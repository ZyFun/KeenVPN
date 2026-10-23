"""Прочитанная конфигурация Xray: части, их ревизии и структурная сводка без секретов.

Это модель чтения существующей установки, а не генератор или валидатор
конфигурации: генерация, проверка установленным Xray и пробы принадлежат
адаптеру движка. Сводка извлекает только теги, протоколы, имена полей и
счётчики, причём строки из файлов выводятся по правилу `xray_identifiers`,
общему с импортом правил: теги и селекторы — после проверки формата,
протоколы, стратегии, `type` правила, имена полей условий и разделов — только
из списков известных значений Xray; скрытое значение заменяется на `None`,
признаки `*_known` сохраняют факт его наличия, а позиция (часть и индекс)
позволяет отличить элементы со скрытыми тегами. Значения `settings`,
`streamSettings`, доменов, адресов, путей, паролей и теги правил `ruleTag` в
сводку не попадают. Семантика объединения нескольких файлов Xray не
моделируется: сводка лишь показывает, какие части содержат каждый раздел.
Значения списков доменов и адресов правил и DNS доступны доверенному коду
отдельно через `rule_list_values`: по ним разбираются ссылки на наборы геобаз,
в сводку они не входят.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from keenvpn.domain.config_document import ConfigDocument, validate_config_document
from keenvpn.domain.routing import ConditionFamily
from keenvpn.domain.xray_identifiers import (
    known_condition_field, known_section, safe_domain_strategy, safe_identifier, safe_inbound_protocol,
    safe_outbound_protocol, safe_rule_type, safe_selector, safe_strategy,
)


XRAY_TAIL_MARKER = "tail"
"""Слово в имени части, при котором `Config.Override` Xray добавляет её новые outbound сразу в конец, а не в начало.

Новые outbound обычной части откладываются и ставятся в начало только после
всей части, поэтому повтор нового тега в ней сохраняется; в части с этим
словом повтор заменяет только что добавленный. Регистр не учитывается.
"""

_RULE_SERVICE_KEYS = frozenset({"type", "ruleTag", "inboundTag", "outboundTag", "balancerTag"})
_OBSERVATORY_SECTIONS = ("observatory", "burstObservatory")
_RULE_DOMAIN_LIST_KEYS = ("domain", "domains")
"""Поля правила со списками доменов: `StringList` Xray, разбираются `parseDomainRule`."""
_RULE_IP_LIST_KEYS = ("ip", "source", "sourceIP", "localIP")
"""Поля правила со списками адресов: `StringList` Xray, разбираются `ToCidrList`."""
_DNS_IP_LIST_KEYS = ("expectIPs", "expectedIPs", "unexpectedIPs")
"""Поля сервера DNS со списками адресов: `StringList` Xray, разбираются `ToCidrList`."""
_READ_SECTIONS = frozenset({"inbounds", "outbounds", "dns", "routing", *_OBSERVATORY_SECTIONS})
_ENDPOINT_FIELDS = frozenset({"tag", "protocol"})
_DNS_FIELDS = frozenset({"tag", "servers", "hosts"})
_DNS_SERVER_FIELDS = frozenset({"tag", "domains", *_DNS_IP_LIST_KEYS})
_ROUTING_FIELDS = frozenset({"domainStrategy", "rules", "balancers"})
_RULE_READ_FIELDS = _RULE_SERVICE_KEYS | frozenset(_RULE_DOMAIN_LIST_KEYS) | frozenset(_RULE_IP_LIST_KEYS)
_BALANCER_READ_FIELDS = frozenset({"tag", "selector", "fallbackTag", "strategy"})
_STRATEGY_READ_FIELDS = frozenset({"type"})
_OBSERVATORY_FIELDS = frozenset({"subjectSelector"})
"""Поля, которые читает структурная сводка, по объектам; варианты их регистра сводка не читает."""


def _absent(item: dict[str, object], key: str) -> bool:
    """Поле отсутствует либо `null`: указательное поле Xray остаётся `nil`."""
    return item.get(key) is None


def _alias_ignored(item: dict[str, object], key: str) -> bool:
    """Значение поля-алиаса не действует, как в декодере Xray v26.3.27.

    `source` правила используется, только если `sourceIP` отсутствует или `null`
    (пустой массив уже не `nil`). `expectIPs` сервера DNS используется, только
    если `expectedIPs` отсутствует, `null` или пустой массив (`len == 0`).
    """
    if key == "source":
        return not _absent(item, "sourceIP")
    if key == "expectIPs":
        return not _absent(item, "expectedIPs") and item["expectedIPs"] != []
    return False


def _selector_null(item: dict[str, object], key: str) -> bool:
    """`null` в выбирающем поле Xray считает отсутствием, а не неподдержанной структурой."""
    return key in ("sourceIP", "expectedIPs") and key in item and item[key] is None


class XrayConfigErrorCode(StrEnum):
    """Причины отказа без имён файлов и содержимого частей."""

    PARTS = "invalid_xray_parts"
    CONFIG = "invalid_xray_config"


_MESSAGES = {
    XrayConfigErrorCode.PARTS: "Части конфигурации Xray должны быть кортежем документов с уникальными именами.",
    XrayConfigErrorCode.CONFIG: "Набор частей конфигурации Xray повреждён или имеет неверный тип.",
}


class XrayConfigError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: XrayConfigErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: XrayConfigErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise XrayConfigError(code) from None
    except XrayConfigError as error:
        error.__context__ = None
        raise


class RuleTargetKind(StrEnum):
    """Куда правило направляет трафик; `both` и `none` не разрешаются выбором одного."""

    OUTBOUND = "outbound"
    BALANCER = "balancer"
    BOTH = "both"
    NONE = "none"


def _text(value: object) -> str | None:
    return value if type(value) is str else None


def has_case_variant(item: dict[str, object], names: frozenset[str]) -> bool:
    """Есть ли ключ, совпадающий с полем Xray только без учёта регистра.

    JSON-декодер Go, которым Xray читает конфигурацию, принимает такой ключ
    вместо точного имени, а при нескольких вариантах применяет последний.
    `casefold` шире складывания Go: лишнее совпадение только переводит
    объект в режим просмотра.
    """
    folded = {name.casefold() for name in names}
    return any(key not in names and key.casefold() in folded for key in item)


def decode_string_list(value: object) -> tuple[str, ...] | None:
    """Разобрать `StringList` Xray: массив строк либо строка с разделением по запятым.

    Строка делится без удаления пробелов и пустых элементов, элементы массива
    повторно не делятся; `None` означает значение, которое декодер Xray отклонит.
    """
    if type(value) is str:
        return tuple(value.split(","))
    if type(value) is list and all(type(item) is str for item in value):
        return tuple(value)
    return None


@dataclass(frozen=True, slots=True, repr=False)
class RuleListValue:
    """Одно значение списка доменов или адресов правила маршрутизации либо DNS.

    Значение — домен, адрес, ключ `dns.hosts` или ссылка на набор геобазы;
    оно приватно и в сводку не входит. `qualified` показывает, принимает ли
    поле у Xray префиксы `ext-domain:`/`ext-ip:` наряду с `ext:`: правила и
    серверы DNS — да, ключи `dns.hosts` — нет. Путь ключа `dns.hosts` содержит
    порядковый номер ключа, а не сам ключ.
    """

    part: str
    path: str
    family: ConditionFamily
    qualified: bool
    value: str

    def __repr__(self) -> str:
        return f"RuleListValue(part={self.part!r}, path={self.path!r}, family={self.family.value})"


def _duplicates(values: list[str]) -> list[str]:
    """Повторяющиеся значения в порядке второго появления; стоимость линейна."""
    seen: set[str] = set()
    reported: set[str] = set()
    found: list[str] = []
    for value in values:
        if value in seen and value not in reported:
            reported.add(value)
            found.append(value)
        seen.add(value)
    return found


def _prefix_matches(selectors: list[str], tags: list[str]) -> int:
    """Число тегов, совпадающих хотя бы с одним префиксом селектора, как в балансировщиках Xray."""
    return sum(any(tag.startswith(selector) for selector in selectors) for tag in tags)


class _Summary:
    """Один проход по частям: заполняет сводку и перечисляет неподдержанные места."""

    def __init__(self) -> None:
        self.parts: list[dict[str, object]] = []
        self.sections: dict[str, list[str]] = {}
        self.inbounds: list[dict[str, object]] = []
        self.outbounds: list[dict[str, object]] = []
        self.dns_tags: list[str] = []
        self.dns_server_tags: list[str] = []
        self.domain_strategies: list[str] = []
        self.rules: list[dict[str, object]] = []
        self.balancers: list[dict[str, object]] = []
        self.observatory: list[dict[str, object]] = []
        self.unsupported: list[dict[str, str]] = []
        self.rule_values: list[RuleListValue] = []
        self.case_variant = False

    def unsupported_path(self, part: str, path: str) -> None:
        self.unsupported.append({"part": part, "path": path})

    def note_case_variants(self, item: dict[str, object], names: frozenset[str]) -> None:
        """Отметить ключ, который Xray прочтёт как поле `names`, а сводка пропустит из-за регистра."""
        self.case_variant = self.case_variant or has_case_variant(item, names)

    def string_field(self, part: str, path: str, item: dict[str, object], key: str) -> str | None:
        """Строковое поле либо None; поле другого типа отмечается как неподдержанное."""
        if key not in item:
            return None
        value = item[key]
        if type(value) is not str:
            self.unsupported_path(part, f"{path}.{key}")
            return None
        return value

    def indexed_strings(
        self, part: str, path: str, item: dict[str, object], key: str, *, allow_string: bool = False,
    ) -> list[tuple[int, str]]:
        """Строки поля с исходными индексами; для StringList строка делится по запятым без очистки."""
        if key not in item:
            return []
        value = item[key]
        if allow_string and type(value) is str:
            return list(enumerate(value.split(",")))
        if type(value) is not list:
            self.unsupported_path(part, f"{path}.{key}")
            return []
        strings = []
        for index, element in enumerate(value):
            if type(element) is str:
                strings.append((index, element))
            else:
                self.unsupported_path(part, f"{path}.{key}[{index}]")
        return strings

    def string_list(
        self, part: str, path: str, item: dict[str, object], key: str, *, allow_string: bool = False,
    ) -> list[str]:
        """Массив строк; для StringList допустима строка с запятыми без удаления пробелов и пустых элементов."""
        return [element for _index, element in self.indexed_strings(part, path, item, key, allow_string=allow_string)]

    def objects(self, part: str, path: str, value: object) -> Iterator[tuple[int, str, dict[str, object]]]:
        """Элементы-объекты списка с индексами и путями в порядке файла; остальное отмечается как неподдержанное."""
        if type(value) is not list:
            self.unsupported_path(part, path)
            return
        for index, item in enumerate(value):
            if type(item) is dict:
                yield index, f"{path}[{index}]", item
            else:
                self.unsupported_path(part, f"{path}[{index}]")

    def add_list_values(
        self, part: str, path: str, item: dict[str, object], key: str, family: ConditionFamily,
        *, allow_string: bool = True, qualified: bool = True,
    ) -> None:
        """Сохранить значения списка поля с исходными индексами для доверенного разбора ссылок на геобазы."""
        for index, value in self.indexed_strings(part, path, item, key, allow_string=allow_string):
            self.rule_values.append(RuleListValue(part, f"{path}.{key}[{index}]", family, qualified, value))

    def add_part(self, part: ConfigDocument) -> None:
        """Пройти разделы части в порядке документа; неизвестные разделы только учитываются."""
        document = part.export()
        name = part.name
        self.note_case_variants(document, _READ_SECTIONS)
        known = [section for section in document if known_section(section)]
        self.parts.append({"name": name, "sections": known, "unknown_section_count": len(document) - len(known)})
        for section, value in document.items():
            if known_section(section):
                self.sections.setdefault(section, []).append(name)
            if section in ("inbounds", "outbounds"):
                target = self.inbounds if section == "inbounds" else self.outbounds
                for index, path, item in self.objects(name, section, value):
                    self.note_case_variants(item, _ENDPOINT_FIELDS)
                    target.append({
                        "part": name,
                        "index": index,
                        "tag": self.string_field(name, path, item, "tag"),
                        "protocol": self.string_field(name, path, item, "protocol"),
                    })
            elif section == "dns":
                self.add_dns(name, value)
            elif section == "routing":
                self.add_routing(name, value)
            elif section in _OBSERVATORY_SECTIONS:
                if type(value) is not dict:
                    self.unsupported_path(name, section)
                    continue
                self.note_case_variants(value, _OBSERVATORY_FIELDS)
                for selector in self.string_list(name, section, value, "subjectSelector"):
                    self.observatory.append({"part": name, "section": section, "selector": selector})

    def add_dns(self, name: str, dns: object) -> None:
        """Учесть тег DNS, теги отдельных серверов и значения списков серверов и `hosts`; адреса серверов не читаются.

        Непустой тег сервера Xray v26.3.27 использует вместо общего `dns.tag` как
        inbound-тег своих запросов, поэтому ссылка `inboundTag` на него разрешима;
        пустой тег равен отсутствующему. В сводку теги серверов не входят.
        """
        if type(dns) is not dict:
            self.unsupported_path(name, "dns")
            return
        self.note_case_variants(dns, _DNS_FIELDS)
        tag = self.string_field(name, "dns", dns, "tag")
        if tag is not None:
            self.dns_tags.append(tag)
        if "servers" in dns:
            servers = dns["servers"]
            if type(servers) is not list:
                self.unsupported_path(name, "dns.servers")
            else:
                for index, server in enumerate(servers):
                    path = f"dns.servers[{index}]"
                    if type(server) is dict:
                        self.note_case_variants(server, _DNS_SERVER_FIELDS)
                        # Пустой тег сервера Xray не использует: запросы получают общий тег `dns.tag`.
                        server_tag = self.string_field(name, path, server, "tag")
                        if server_tag:
                            self.dns_server_tags.append(server_tag)
                        for key in server:
                            if _alias_ignored(server, key) or _selector_null(server, key):
                                continue
                            if key == "domains":
                                # `domains` у Xray — обычный массив строк: строковая форма не делится.
                                self.add_list_values(name, path, server, key, ConditionFamily.DOMAIN, allow_string=False)
                            elif key in _DNS_IP_LIST_KEYS:
                                self.add_list_values(name, path, server, key, ConditionFamily.IP)
                    elif type(server) is not str:
                        # Строка — сокращённая форма сервера только с адресом.
                        self.unsupported_path(name, path)
        if "hosts" in dns:
            hosts = dns["hosts"]
            if type(hosts) is not dict:
                self.unsupported_path(name, "dns.hosts")
            else:
                for index, key in enumerate(hosts):
                    self.rule_values.append(
                        RuleListValue(name, f"dns.hosts[{index}]", ConditionFamily.DOMAIN, False, key),
                    )

    def add_routing(self, name: str, routing: object) -> None:
        if type(routing) is not dict:
            self.unsupported_path(name, "routing")
            return
        self.note_case_variants(routing, _ROUTING_FIELDS)
        strategy = self.string_field(name, "routing", routing, "domainStrategy")
        if strategy is not None:
            self.domain_strategies.append(strategy)
        if "rules" in routing:
            for index, path, rule in self.objects(name, "routing.rules", routing["rules"]):
                self.add_rule(name, index, path, rule)
        if "balancers" in routing:
            for index, path, balancer in self.objects(name, "routing.balancers", routing["balancers"]):
                self.note_case_variants(balancer, _BALANCER_READ_FIELDS)
                entry = {
                    "part": name,
                    "index": index,
                    "tag": self.string_field(name, path, balancer, "tag"),
                    "selector": self.string_list(name, path, balancer, "selector", allow_string=True),
                    # Пустой `fallbackTag` балансировщик Xray не применяет: резерва нет.
                    "fallback_tag": self.string_field(name, path, balancer, "fallbackTag") or None,
                    "strategy": None,
                }
                if "strategy" in balancer:
                    if type(balancer["strategy"]) is dict:
                        self.note_case_variants(balancer["strategy"], _STRATEGY_READ_FIELDS)
                        entry["strategy"] = self.string_field(name, f"{path}.strategy", balancer["strategy"], "type")
                    else:
                        self.unsupported_path(name, f"{path}.strategy")
                self.balancers.append(entry)

    def add_rule(self, name: str, index: int, path: str, rule: dict[str, object]) -> None:
        self.note_case_variants(rule, _RULE_READ_FIELDS)
        # Пустой тег назначения `parseFieldRule` Xray v26.3.27 считает отсутствующим, как и импорт правил.
        outbound_tag = self.string_field(name, path, rule, "outboundTag") or None
        balancer_tag = self.string_field(name, path, rule, "balancerTag") or None
        if outbound_tag is not None and balancer_tag is not None:
            kind, target = RuleTargetKind.BOTH, None
        elif outbound_tag is not None:
            kind, target = RuleTargetKind.OUTBOUND, outbound_tag
        elif balancer_tag is not None:
            kind, target = RuleTargetKind.BALANCER, balancer_tag
        else:
            kind, target = RuleTargetKind.NONE, None
        conditions = {}
        for key, value in rule.items():
            if key not in _RULE_SERVICE_KEYS:
                conditions[key] = len(value) if type(value) is list else 1
        for key in rule:
            if _alias_ignored(rule, key) or _selector_null(rule, key):
                continue
            if key in _RULE_DOMAIN_LIST_KEYS:
                self.add_list_values(name, path, rule, key, ConditionFamily.DOMAIN)
            elif key in _RULE_IP_LIST_KEYS:
                self.add_list_values(name, path, rule, key, ConditionFamily.IP)
        self.rules.append({
            "part": name,
            "index": index,
            "type": self.string_field(name, path, rule, "type"),
            "inbound_tags": self.string_list(name, path, rule, "inboundTag", allow_string=True),
            "target_kind": kind,
            "target_tag": target,
            "has_rule_tag": "ruleTag" in rule,
            "conditions": conditions,
        })

    def resolve(self) -> dict[str, object]:
        """Сопоставить ссылки между тегами по исходным значениям и собрать безопасную JSON-совместимую сводку.

        Разрешимость ссылок, совпадения селекторов и повторы считаются по
        исходным тегам; в вывод теги попадают только после проверки формата,
        а протоколы, стратегии и `type` — только из списков известных значений.
        Позиция цели ссылки указывается, только если среди всех частей ровно
        один outbound или балансировщик носит этот тег.
        """
        inbound_tags = [item["tag"] for item in self.inbounds if item["tag"] is not None]
        outbound_tags = [item["tag"] for item in self.outbounds if item["tag"] is not None]
        balancer_tags = [item["tag"] for item in self.balancers if item["tag"] is not None]
        # Запросы DNS несут общий тег или тег своего сервера как inbound-тег: оба разрешают ссылку правила.
        known_inbound = set(inbound_tags) | set(self.dns_tags) | set(self.dns_server_tags)
        outbound_positions = _unique_positions(self.outbounds)
        balancer_positions = _unique_positions(self.balancers)
        rules = []
        for rule in self.rules:
            kind = rule["target_kind"]
            tag = rule["target_tag"]
            if kind is RuleTargetKind.OUTBOUND:
                resolved = tag in outbound_positions
                position = outbound_positions.get(tag)
            elif kind is RuleTargetKind.BALANCER:
                resolved = tag in balancer_positions
                position = balancer_positions.get(tag)
            else:
                resolved, position = False, None
            conditions = rule["conditions"]
            rules.append({
                "part": rule["part"],
                "index": rule["index"],
                "type_known": rule["type"] is not None,
                "type": safe_rule_type(rule["type"]),
                "inbound_tags": [safe_identifier(item) for item in rule["inbound_tags"]],
                "inbound_tags_resolved": all(item in known_inbound for item in rule["inbound_tags"]),
                "target_kind": kind.value,
                "target_tag_known": tag is not None,
                "target_tag": safe_identifier(tag),
                "target_resolved": resolved,
                "target_position": position,
                "has_rule_tag": rule["has_rule_tag"],
                "conditions": {key: count for key, count in conditions.items() if known_condition_field(key)},
                "unknown_condition_count": sum(not known_condition_field(key) for key in conditions),
            })
        balancers = [
            {
                "part": balancer["part"],
                "index": balancer["index"],
                "tag_known": balancer["tag"] is not None,
                "tag": safe_identifier(balancer["tag"]),
                "selector": [safe_selector(item) for item in balancer["selector"]],
                "selector_match_count": _prefix_matches(balancer["selector"], outbound_tags),
                "fallback_known": balancer["fallback_tag"] is not None,
                "fallback_tag": safe_identifier(balancer["fallback_tag"]),
                "fallback_resolved": (
                    None if balancer["fallback_tag"] is None else balancer["fallback_tag"] in outbound_positions
                ),
                "fallback_position": outbound_positions.get(balancer["fallback_tag"]),
                "strategy_known": balancer["strategy"] is not None,
                "strategy": safe_strategy(balancer["strategy"]),
            }
            for balancer in self.balancers
        ]
        observatory = [
            {
                **subject,
                "selector": safe_selector(subject["selector"]),
                "match_count": _prefix_matches([subject["selector"]], outbound_tags),
            }
            for subject in self.observatory
        ]
        return {
            "parts": [dict(item) for item in self.parts],
            "sections": {name: list(parts) for name, parts in self.sections.items()},
            "duplicate_sections": [name for name, parts in self.sections.items() if len(parts) > 1],
            "dns_tags": [safe_identifier(tag) for tag in self.dns_tags],
            "domain_strategies": [safe_domain_strategy(strategy) for strategy in self.domain_strategies],
            "inbounds": [_endpoint(item, safe_inbound_protocol) for item in self.inbounds],
            "outbounds": [_endpoint(item, safe_outbound_protocol) for item in self.outbounds],
            "duplicate_inbound_tags": [safe_identifier(tag) for tag in _duplicates(inbound_tags)],
            "duplicate_outbound_tags": [safe_identifier(tag) for tag in _duplicates(outbound_tags)],
            "duplicate_balancer_tags": [safe_identifier(tag) for tag in _duplicates(balancer_tags)],
            "rule_count": len(rules),
            "rules": rules,
            "balancers": balancers,
            "observatory_subjects": observatory,
            "unsupported_paths": [dict(item) for item in self.unsupported],
        }


def _unique_positions(items: list[dict[str, object]]) -> dict[object, dict[str, object] | None]:
    """Позиция `{part, index}` для тега, который носит ровно один элемент; повтор тега даёт `None`.

    Ключи словаря — все исходные теги, поэтому проверка разрешимости ссылки
    по-прежнему считается по исходным значениям.
    """
    positions: dict[object, dict[str, object] | None] = {}
    for item in items:
        tag = item["tag"]
        if tag is None:
            continue
        positions[tag] = None if tag in positions else {"part": item["part"], "index": item["index"]}
    return positions


def _endpoint(item: dict[str, object], safe_protocol: Callable[[object], str | None]) -> dict[str, object]:
    """Inbound или outbound в безопасной форме: позиция, признаки наличия, тег и известный протокол."""
    return {
        "part": item["part"],
        "index": item["index"],
        "tag_known": item["tag"] is not None,
        "tag": safe_identifier(item["tag"]),
        "protocol_known": item["protocol"] is not None,
        "protocol": safe_protocol(item["protocol"]),
    }


def summarize_xray_config(parts: tuple[ConfigDocument, ...]) -> dict[str, object]:
    """Структурная сводка частей в их порядке без значений полей конфигурации.

    `parts` содержит имя, известные разделы и число неизвестных разделов каждой
    части; ревизии частей добавляет `XrayConfigSet.to_diagnostic()`.
    """
    summary = _Summary()
    for part in parts:
        summary.add_part(part)
    return summary.resolve()


def rule_list_values(parts: tuple[ConfigDocument, ...]) -> tuple[RuleListValue, ...]:
    """Значения списков доменов и адресов правил и DNS в порядке частей; для доверенного кода.

    Учитываются поля `domain`, `domains`, `ip`, `source`, `sourceIP` и `localIP`
    правил, `domains`, `expectIPs`, `expectedIPs` и `unexpectedIPs` серверов DNS
    и ключи `dns.hosts`. Поля `StringList` принимают массив строк либо строку
    с разделением по запятым, как декодер Xray. Алиасы выбираются как в Xray:
    `source` — только без `sourceIP`, `expectIPs` — только при пустом
    `expectedIPs`; недействующий алиас не учитывается. Это не безопасный вывод.
    """
    summary = _Summary()
    for part in parts:
        summary.add_part(part)
    return tuple(summary.rule_values)


def config_case_variants(parts: tuple[ConfigDocument, ...]) -> bool:
    """Есть ли в объектах, которые читает сводка, ключ, отличающийся от поля Xray только регистром.

    Xray применит такой ключ, а сводка его не читает: её выводы о тегах,
    ссылках и значениях списков для такой конфигурации недостоверны.
    Безопасная сводка этот признак не содержит; это данные для доверенного кода.
    """
    summary = _Summary()
    for part in parts:
        summary.add_part(part)
    return summary.case_variant


@dataclass(frozen=True, slots=True, repr=False)
class TagRepeat:
    """Тег, повторённый в секции `inbounds`, `outbounds` или `balancers`; части — в порядке появления, с повторами.

    Значение тега приватно и в сводку не входит: это данные для доверенного кода.
    """

    section: str
    tag: str
    parts: tuple[str, ...]

    def __repr__(self) -> str:
        return f"TagRepeat(section={self.section!r}, parts={len(self.parts)})"


@dataclass(frozen=True, slots=True)
class TagRepeats:
    """Повторы тегов внутри одной части и между частями, раздельно.

    Повтор внутри части — конфликт: Xray v26.3.27 отклоняет повтор тега
    в одном наборе inbound, outbound или балансировщиков. Повтор между частями
    — переопределение `Config.Override`: inbound и outbound с тем же тегом из
    следующей части заменяет предыдущий, а раздел `routing` переписывается
    целиком; какое определение действует, структурная сводка не моделирует.
    """

    within_parts: tuple[TagRepeat, ...]
    between_parts: tuple[TagRepeat, ...]


def tag_repeats(parts: tuple[ConfigDocument, ...]) -> TagRepeats:
    """Найти повторы строковых тегов inbound, outbound и балансировщиков по исходным значениям; для доверенного кода.

    Тег, повторённый в одной части, попадает в `within_parts`; встреченный
    в двух и более частях — в `between_parts`; один тег может попасть в оба
    списка. Теги не строкой не учитываются; пустая строка — не тег: Xray
    проверяет уникальность только непустых тегов, а обработчики без имени
    собирает отдельным списком. Это не безопасный вывод.
    """
    summary = _Summary()
    for part in parts:
        summary.add_part(part)
    within: list[TagRepeat] = []
    between: list[TagRepeat] = []
    for section, entries in (("inbounds", summary.inbounds), ("outbounds", summary.outbounds),
                             ("balancers", summary.balancers)):
        owners: dict[str, list[str]] = {}
        for entry in entries:
            if type(entry["tag"]) is str and entry["tag"]:
                owners.setdefault(entry["tag"], []).append(entry["part"])
        for tag, names in owners.items():
            if len(names) != len(set(names)):
                within.append(TagRepeat(section, tag, tuple(names)))
            if len(set(names)) > 1:
                between.append(TagRepeat(section, tag, tuple(names)))
    return TagRepeats(tuple(within), tuple(between))


@dataclass(frozen=True, slots=True, repr=False)
class XrayConfigSet:
    """Части конфигурации Xray в порядке источника с уникальными именами.

    Порядок задаёт источник: обычно это лексический порядок файлов каталога,
    как при загрузке `-confdir`. Набор без частей допустим и означает, что
    источник ничего не вернул. Объединение разделов между частями и проверка
    конфигурации установленным Xray здесь не выполняются.
    """

    parts: tuple[ConfigDocument, ...]

    def __post_init__(self) -> None:
        _check_parts(self.parts)

    def __repr__(self) -> str:
        return f"XrayConfigSet(parts={len(self.parts)})"

    @property
    def part_names(self) -> tuple[str, ...]:
        """Имена частей в порядке источника."""
        return tuple(part.name for part in self.parts)

    def to_diagnostic(self) -> dict[str, object]:
        """Ревизии частей и структурная сводка без доменов, адресов, путей и паролей.

        Имена разделов части берутся из сводки: показываются только известные
        разделы Xray, остальные учитываются числом.
        """
        summary = summarize_xray_config(self.parts)
        parts = [{**part.to_diagnostic(), **entry} for part, entry in zip(self.parts, summary.pop("parts"))]
        return {"part_count": len(self.parts), "parts": parts, **summary}

    def rule_list_values(self) -> tuple[RuleListValue, ...]:
        """Значения списков доменов и адресов для доверенного кода, не для вывода."""
        return rule_list_values(self.parts)


def _check_parts(parts: object) -> None:
    if type(parts) is not tuple or any(type(part) is not ConfigDocument for part in parts):
        _raise_detached(XrayConfigErrorCode.PARTS)
    names = [part.name for part in parts]
    if len(set(names)) != len(names):
        _raise_detached(XrayConfigErrorCode.PARTS)


def validate_xray_config_set(config: XrayConfigSet) -> None:
    """Проверить готовую модель заново, включая каждую часть по её байтам."""
    if type(config) is not XrayConfigSet:
        _raise_detached(XrayConfigErrorCode.CONFIG)
    _check_parts(config.parts)
    for part in config.parts:
        validate_config_document(part)
