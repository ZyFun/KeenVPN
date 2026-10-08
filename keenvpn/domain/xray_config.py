"""Прочитанная конфигурация Xray: части, их ревизии и структурная сводка без секретов.

Это модель чтения существующей установки, а не генератор или валидатор
конфигурации: генерация, проверка установленным Xray и пробы принадлежат
адаптеру движка. Сводка извлекает только теги, протоколы, имена полей и
счётчики. Значения `settings`, `streamSettings`, доменов, адресов, путей,
паролей и теги правил `ruleTag` в неё не попадают. Семантика объединения
нескольких файлов Xray не моделируется: сводка лишь показывает, какие части
содержат каждый раздел. Значения списков доменов и адресов правил и DNS
доступны доверенному коду отдельно через `rule_list_values`: по ним
разбираются ссылки на наборы геобаз, в сводку они не входят.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from keenvpn.domain.config_document import ConfigDocument, validate_config_document
from keenvpn.domain.routing import ConditionFamily


_RULE_SERVICE_KEYS = frozenset({"type", "ruleTag", "inboundTag", "outboundTag", "balancerTag"})
_OBSERVATORY_SECTIONS = ("observatory", "burstObservatory")
_RULE_DOMAIN_LIST_KEYS = ("domain", "domains")
"""Поля правила со списками доменов: `StringList` Xray, разбираются `parseDomainRule`."""
_RULE_IP_LIST_KEYS = ("ip", "source", "sourceIP", "localIP")
"""Поля правила со списками адресов: `StringList` Xray, разбираются `ToCidrList`."""
_DNS_IP_LIST_KEYS = ("expectIPs", "expectedIPs", "unexpectedIPs")
"""Поля сервера DNS со списками адресов: `StringList` Xray, разбираются `ToCidrList`."""


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
        self.sections: dict[str, list[str]] = {}
        self.inbounds: list[dict[str, object]] = []
        self.outbounds: list[dict[str, object]] = []
        self.dns_tags: list[str] = []
        self.domain_strategies: list[str] = []
        self.rules: list[dict[str, object]] = []
        self.balancers: list[dict[str, object]] = []
        self.observatory: list[dict[str, object]] = []
        self.unsupported: list[dict[str, str]] = []
        self.rule_values: list[RuleListValue] = []

    def unsupported_path(self, part: str, path: str) -> None:
        self.unsupported.append({"part": part, "path": path})

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
        for section, value in document.items():
            self.sections.setdefault(section, []).append(name)
            if section in ("inbounds", "outbounds"):
                target = self.inbounds if section == "inbounds" else self.outbounds
                for _index, path, item in self.objects(name, section, value):
                    target.append({
                        "part": name,
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
                for selector in self.string_list(name, section, value, "subjectSelector"):
                    self.observatory.append({"part": name, "section": section, "selector": selector})

    def add_dns(self, name: str, dns: object) -> None:
        """Учесть тег DNS и значения списков серверов и `hosts`; адреса серверов не читаются."""
        if type(dns) is not dict:
            self.unsupported_path(name, "dns")
            return
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
        strategy = self.string_field(name, "routing", routing, "domainStrategy")
        if strategy is not None:
            self.domain_strategies.append(strategy)
        if "rules" in routing:
            for index, path, rule in self.objects(name, "routing.rules", routing["rules"]):
                self.add_rule(name, index, path, rule)
        if "balancers" in routing:
            for _index, path, balancer in self.objects(name, "routing.balancers", routing["balancers"]):
                entry = {
                    "part": name,
                    "tag": self.string_field(name, path, balancer, "tag"),
                    "selector": self.string_list(name, path, balancer, "selector", allow_string=True),
                    "fallback_tag": self.string_field(name, path, balancer, "fallbackTag"),
                    "strategy": None,
                }
                if "strategy" in balancer:
                    if type(balancer["strategy"]) is dict:
                        entry["strategy"] = self.string_field(name, f"{path}.strategy", balancer["strategy"], "type")
                    else:
                        self.unsupported_path(name, f"{path}.strategy")
                self.balancers.append(entry)

    def add_rule(self, name: str, index: int, path: str, rule: dict[str, object]) -> None:
        outbound_tag = self.string_field(name, path, rule, "outboundTag")
        balancer_tag = self.string_field(name, path, rule, "balancerTag")
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
        """Сопоставить ссылки между тегами и собрать JSON-совместимую сводку."""
        inbound_tags = [item["tag"] for item in self.inbounds if item["tag"] is not None]
        outbound_tags = [item["tag"] for item in self.outbounds if item["tag"] is not None]
        balancer_tags = [item["tag"] for item in self.balancers if item["tag"] is not None]
        known_inbound = set(inbound_tags) | set(self.dns_tags)
        known_outbound = set(outbound_tags)
        known_balancer = set(balancer_tags)
        rules = []
        for rule in self.rules:
            kind = rule["target_kind"]
            if kind is RuleTargetKind.OUTBOUND:
                resolved = rule["target_tag"] in known_outbound
            elif kind is RuleTargetKind.BALANCER:
                resolved = rule["target_tag"] in known_balancer
            else:
                resolved = False
            rules.append({
                **rule,
                "target_kind": kind.value,
                "inbound_tags_resolved": all(tag in known_inbound for tag in rule["inbound_tags"]),
                "target_resolved": resolved,
            })
        balancers = [
            {
                **balancer,
                "selector_match_count": _prefix_matches(balancer["selector"], outbound_tags),
                "fallback_resolved": (
                    None if balancer["fallback_tag"] is None else balancer["fallback_tag"] in known_outbound
                ),
            }
            for balancer in self.balancers
        ]
        observatory = [
            {**subject, "match_count": _prefix_matches([subject["selector"]], outbound_tags)}
            for subject in self.observatory
        ]
        return {
            "sections": {name: list(parts) for name, parts in self.sections.items()},
            "duplicate_sections": [name for name, parts in self.sections.items() if len(parts) > 1],
            "dns_tags": list(self.dns_tags),
            "domain_strategies": list(self.domain_strategies),
            "inbounds": [dict(item) for item in self.inbounds],
            "outbounds": [dict(item) for item in self.outbounds],
            "duplicate_inbound_tags": _duplicates(inbound_tags),
            "duplicate_outbound_tags": _duplicates(outbound_tags),
            "duplicate_balancer_tags": _duplicates(balancer_tags),
            "rule_count": len(rules),
            "rules": rules,
            "balancers": balancers,
            "observatory_subjects": observatory,
            "unsupported_paths": [dict(item) for item in self.unsupported],
        }


def summarize_xray_config(parts: tuple[ConfigDocument, ...]) -> dict[str, object]:
    """Структурная сводка частей в их порядке без значений полей конфигурации."""
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
        """Ревизии частей и структурная сводка без доменов, адресов, путей и паролей."""
        return {
            "part_count": len(self.parts),
            "parts": [part.to_diagnostic() for part in self.parts],
            **summarize_xray_config(self.parts),
        }

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
