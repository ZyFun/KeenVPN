"""Прочитанная конфигурация Xray: части, их ревизии и структурная сводка без секретов.

Это модель чтения существующей установки, а не генератор или валидатор
конфигурации: генерация, проверка установленным Xray и пробы принадлежат
адаптеру движка. Сводка извлекает только теги, протоколы, имена полей и
счётчики. Значения `settings`, `streamSettings`, доменов, адресов, путей,
паролей и теги правил `ruleTag` в неё не попадают. Семантика объединения
нескольких файлов Xray не моделируется: сводка лишь показывает, какие части
содержат каждый раздел.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from keenvpn.domain.config_document import ConfigDocument, validate_config_document


_RULE_SERVICE_KEYS = frozenset({"type", "ruleTag", "inboundTag", "outboundTag", "balancerTag"})
_OBSERVATORY_SECTIONS = ("observatory", "burstObservatory")


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

    def string_list(self, part: str, path: str, item: dict[str, object], key: str) -> list[str]:
        """Список строк либо пустой список; иной тип или элемент отмечается как неподдержанный."""
        if key not in item:
            return []
        value = item[key]
        if type(value) is not list:
            self.unsupported_path(part, f"{path}.{key}")
            return []
        strings = []
        for index, element in enumerate(value):
            if type(element) is str:
                strings.append(element)
            else:
                self.unsupported_path(part, f"{path}.{key}[{index}]")
        return strings

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
                if type(value) is not dict:
                    self.unsupported_path(name, section)
                else:
                    tag = self.string_field(name, section, value, "tag")
                    if tag is not None:
                        self.dns_tags.append(tag)
            elif section == "routing":
                self.add_routing(name, value)
            elif section in _OBSERVATORY_SECTIONS:
                if type(value) is not dict:
                    self.unsupported_path(name, section)
                    continue
                for selector in self.string_list(name, section, value, "subjectSelector"):
                    self.observatory.append({"part": name, "section": section, "selector": selector})

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
                    "selector": self.string_list(name, path, balancer, "selector"),
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
        self.rules.append({
            "part": name,
            "index": index,
            "type": self.string_field(name, path, rule, "type"),
            "inbound_tags": self.string_list(name, path, rule, "inboundTag"),
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
