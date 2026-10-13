"""Перевод действующих правил Xray в модель маршрутизации без изменения их смысла.

Импорт читает набор частей `XrayConfigSet` по правилам декодера Xray
v26.3.27 и собирает группы правил в исходном порядке. Правило со списком
доменов или адресов становится группой условий с одним действием: значения
группы не дробятся, не сливаются с соседними и не переупорядочиваются.
Условия, которые модель понимает (`domain:`, `full:`, IP/CIDR, `geoip:`,
`geosite:`, `ext:`), переводятся в существующие условия; остальные значения
и поля сохраняются в исходном виде и делают правило или группу доступными
только для просмотра с машинной причиной. Действие DIRECT, VPN или BLOCK
определяется только по явному соответствию outbound или балансировщика;
неоднозначность не угадывается, группа резервирования и её `fallbackTag`
сохраняются как назначение. Финальное правило берётся из конфигурации только
в поддержанной форме и не выдумывается. Байты частей не меняются: неизвестные
поля остаются в исходном документе. Ничего не записывается и не применяется.
"""

from dataclasses import dataclass
from enum import StrEnum
import ipaddress
import json
import re
from typing import NoReturn

from keenvpn.domain.config_document import valid_document_name
from keenvpn.domain.geodata import GeoReference, UnsupportedGeoReference, parse_geo_reference
from keenvpn.domain.routing import (
    ConditionFamily, DomainCondition, DomainMatch, GeoDatabase, GeoDatabaseKind, GeoIPCondition,
    GeoSiteCondition, IPCondition, RoutingAction, RoutingCondition, RoutingErrorCode, RoutingRule,
    RoutingValidationError, UnknownCondition, UnsupportedRuleCondition, _PrivateRepresentation,
)
from keenvpn.domain.routing_policy import FinalRoutingRule, RoutingPolicy
from keenvpn.domain.xray_config import RuleListValue, RuleTargetKind, XrayConfigSet, decode_string_list


XRAY_RULE_CONDITION_FIELDS = frozenset({
    "domain", "domains", "ip", "port", "network", "sourceIP", "source", "sourcePort", "user", "vlessRoute",
    "inboundTag", "protocol", "attrs", "localIP", "localPort", "process", "webhook",
})
"""Поля условий правила, которые читает `parseFieldRule` Xray v26.3.27; регистр имён учитывается."""
DIRECT_OUTBOUND_PROTOCOLS = frozenset({"freedom"})
"""Протоколы outbound, означающие прямой выход."""
BLOCK_OUTBOUND_PROTOCOLS = frozenset({"blackhole"})
"""Протоколы outbound, означающие блокировку."""
VPN_OUTBOUND_PROTOCOLS = frozenset({"trojan", "vless", "vmess", "shadowsocks", "socks", "http", "wireguard"})
"""Протоколы outbound, означающие направление через прокси или туннель; профиль не выбирается."""
_SERVICE_FIELDS = frozenset({"type", "ruleTag", "outboundTag", "balancerTag"})
"""`type` декодер v26.3.27 не читает; остальные поля задают назначение и тег правила."""
_MODEL_FIELDS = frozenset({"domain", "domains", "ip"})
_FINAL_NETWORKS = frozenset({"tcp", "udp"})
_TAIL_MARKER = "tail"
"""Часть с этим словом в имени добавляет новые outbound в конец, остальные — в начало."""
_DOCUMENT_FIELDS = frozenset({"routing", "outbounds"})
_ROUTING_FIELDS = frozenset({"rules", "balancers"})
_OUTBOUND_FIELDS = frozenset({"tag", "protocol", "proxySettings", "streamSettings"})
_PROXY_SETTINGS_FIELDS = frozenset({"tag", "transportLayer"})
_STREAM_SETTINGS_FIELDS = frozenset({"sockopt"})
_SOCKOPT_FIELDS = frozenset({"dialerProxy"})
_BALANCER_FIELDS = frozenset({"tag", "selector", "fallbackTag", "strategy"})
_RULE_FIELDS = XRAY_RULE_CONDITION_FIELDS | _SERVICE_FIELDS
BALANCER_STRATEGIES = frozenset({"random", "leastping", "roundrobin", "leastload"})
"""Стратегии балансировщика Xray v26.3.27; тип сравнивается без учёта регистра, как в загрузчике."""
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,127}")
"""Технический идентификатор в безопасном выводе: без `.`, `/`, `:`, `@`, пробелов и управляющих символов.

Без точки и двоеточия в вывод не попадают IPv4- и IPv6-адреса и имена,
похожие на домен.
"""


def _case_variants(item: dict[str, object], names: frozenset[str]) -> bool:
    """Есть ли ключ, совпадающий с полем Xray только без учёта регистра.

    JSON-декодер Go, которым Xray читает конфигурацию, принимает такой ключ
    вместо точного имени, а при нескольких вариантах применяет последний.
    `casefold` шире складывания Go: лишнее совпадение только переводит
    объект в режим просмотра.
    """
    folded = {name.casefold() for name in names}
    return any(key not in names and key.casefold() in folded for key in item)


def safe_identifier(value: object) -> str | None:
    """Тег outbound или балансировщика для вывода, если он похож на технический идентификатор.

    Теги задаёт пользователь: значение с разделителями URL, пути, адреса,
    домена или учётных данных скрывается и заменяется на `None`; отдельно
    скрывается всё, что разбирается как IP-адрес. Проверка формата не
    отличает секрет из букв, цифр, `_`, `+` и `-` от обычного тега: такие
    теги выводятся так же, как в сводке конфигурации прокси.
    """
    if type(value) is not str or not _SAFE_IDENTIFIER.fullmatch(value):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return None


def safe_strategy(value: object) -> str | None:
    """Тип стратегии для вывода, только если это известная стратегия Xray."""
    return value if type(value) is str and value.lower() in BALANCER_STRATEGIES else None


class RoutingImportErrorCode(StrEnum):
    """Причины отказа без значений правил, тегов и содержимого частей."""

    CONFIG = "invalid_routing_import_config"
    TARGET = "invalid_rule_target"
    GROUP = "invalid_rule_group"
    SCHEME = "invalid_routing_scheme"


_MESSAGES = {
    RoutingImportErrorCode.CONFIG: "Импорт правил принимает набор частей конфигурации Xray.",
    RoutingImportErrorCode.TARGET: "Назначение правила должно содержать согласованные вид, теги, действие и причины.",
    RoutingImportErrorCode.GROUP: "Группа правил должна содержать согласованные условия, назначение, поля и причины.",
    RoutingImportErrorCode.SCHEME: "Импортированная схема должна содержать согласованные группы, политику и причины.",
}


class RoutingImportError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: RoutingImportErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: RoutingImportErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise RoutingImportError(code) from None
    except RoutingImportError as error:
        error.__context__ = None
        raise


class ImportReason(StrEnum):
    """Машинные причины режима только для просмотра и отсутствия политики."""

    ROUTING_MISSING = "routing_missing"
    """Ни одна часть не содержит раздел `routing`."""
    ROUTING_UNSUPPORTED = "routing_unsupported"
    """Действующий раздел `routing` не объект."""
    RULES_UNSUPPORTED = "rules_unsupported"
    """`routing.rules` не список."""
    BALANCERS_UNSUPPORTED = "balancers_unsupported"
    """`routing.balancers` не список либо содержит элемент не объект или без строкового тега."""
    OUTBOUNDS_UNSUPPORTED = "outbounds_unsupported"
    """Раздел `outbounds` части не список либо содержит элемент не объект."""
    FIELD_CASE_VARIANT = "field_case_variant"
    """Ключ отличается от поля Xray только регистром: декодер Xray принял бы его, импорт не выбирает."""
    FINAL_RULE_MISSING = "final_rule_missing"
    """Последнее правило не является правилом для остатка трафика в поддержанной форме."""
    FINAL_RULE_UNRESOLVED = "final_rule_unresolved"
    """Последнее правило подходит под финальное, но его действие не определено."""
    RULE_ACTION_UNRESOLVED = "rule_action_unresolved"
    """Действие хотя бы одного правила не определено, поэтому политика не собрана."""
    RULE_NOT_OBJECT = "rule_not_object"
    """Элемент `routing.rules` не объект."""
    TARGET_MISSING = "target_missing"
    """Нет непустого `outboundTag` и `balancerTag`."""
    TARGET_AMBIGUOUS = "target_ambiguous"
    """Заданы оба тега; Xray выбрал бы outbound, импорт не выбирает."""
    TARGET_INVALID = "target_invalid"
    """`outboundTag` или `balancerTag` не строка и не `null`."""
    TARGET_UNRESOLVED = "target_unresolved"
    """Тега нет среди действующих outbound или балансировщиков."""
    TARGET_DUPLICATE = "target_duplicate"
    """Тег определён более одного раза; ничего не выбирается по первому."""
    OUTBOUND_PROTOCOL_UNSUPPORTED = "outbound_protocol_unsupported"
    """Протокол outbound не сопоставлен с DIRECT, VPN или BLOCK."""
    OUTBOUND_CHAINED = "outbound_chained"
    """Outbound передаёт соединение другому через `proxySettings.tag` или `sockopt.dialerProxy`."""
    BALANCER_INVALID = "balancer_invalid"
    """Селектор, `fallbackTag` или `strategy` балансировщика имеют неподдержанную структуру."""
    BALANCER_EMPTY = "balancer_empty"
    """Селектор балансировщика не выбирает ни одного outbound."""
    BALANCER_MIXED = "balancer_mixed"
    """Выбранные outbound дают разные действия."""
    FALLBACK_UNRESOLVED = "fallback_unresolved"
    """`fallbackTag` балансировщика не соответствует outbound."""
    UNSUPPORTED_CONDITIONS = "unsupported_conditions"
    """Поля условий Xray вне модели: `port`, `network`, `inboundTag`, `protocol` и другие."""
    UNKNOWN_FIELDS = "unknown_fields"
    """Поля, которые декодер Xray v26.3.27 не читает под таким именем."""
    CONDITIONS_COMBINED = "conditions_combined"
    """Домены и адреса в одном правиле: логическое И модель не представляет."""
    VALUES_INVALID = "values_invalid"
    """Список доменов или адресов не массив строк и не строка, либо `null`."""
    VALUES_EMPTY = "values_empty"
    """Пустой список или пустое значение: Xray считает условие отсутствующим либо совпадающим со всем."""
    RULE_WITHOUT_CONDITIONS = "rule_without_conditions"
    """Правило без полей условий: Xray v26.3.27 отклоняет его при загрузке (`no effective fields`)."""
    CATCH_ALL_NOT_LAST = "catch_all_not_last"
    """Правило только с `network` из `tcp` и `udp` стоит не последним; следующие за ним недостижимы."""
    DOMAIN_PLAIN = "domain_plain"
    """Домен без префикса: в Xray это подстрочное совпадение."""
    DOMAIN_REGEXP = "domain_regexp"
    DOMAIN_KEYWORD = "domain_keyword"
    DOMAIN_DOTLESS = "domain_dotless"
    DOMAIN_UNSUPPORTED = "domain_unsupported"
    """Значение после `domain:` или `full:` модель не принимает."""
    DOMAIN_NOT_CANONICAL = "domain_not_canonical"
    """Каноническая форма модели отличается от текста: Xray сравнивал бы текст как есть."""
    GEOSITE_ATTRIBUTES = "geosite_attributes"
    """Атрибуты `@` набора GeoSite модель не представляет."""
    GEOIP_NEGATED = "geoip_negated"
    """Отрицание `!` набора GeoIP модель не представляет."""
    GEO_REFERENCE_UNSUPPORTED = "geo_reference_unsupported"
    """Ссылку на набор геобазы загрузчик Xray отклонил бы либо модель не принимает её файл."""
    SET_NAME_UNSUPPORTED = "set_name_unsupported"
    """Код набора не проходит проверку формы имени набора."""
    IP_IPV4_MAPPED = "ip_ipv4_mapped"
    """IPv4-mapped IPv6 (`::ffff:a.b.c.d`): Xray сводит его к IPv4 с маской IPv4, модель хранит IPv6."""
    IP_UNSUPPORTED = "ip_unsupported"
    """Адрес или сеть модель не принимает: биты хоста, маска, зона, имя вместо адреса."""


class RuleGroupKind(StrEnum):
    """Группа обычных условий либо финальное правило для остатка трафика."""

    RULES = "rules"
    FINAL = "final"


def _unique_reasons(reasons: object) -> bool:
    return (
        type(reasons) is tuple
        and all(isinstance(reason, ImportReason) for reason in reasons)
        and len(set(reasons)) == len(reasons)
    )


def _names(values: object) -> bool:
    return type(values) is tuple and all(type(value) is str and bool(value) for value in values)


def _keys(values: object) -> bool:
    """Исходные ключи JSON: любые строки, включая пустую, как их принимает документ."""
    return type(values) is tuple and all(type(value) is str for value in values)


@dataclass(frozen=True, slots=True)
class ValueReason:
    """Путь значения списка правила и причина, по которой оно сохранено как неизвестное."""

    path: str
    reason: ImportReason

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str or not self.path or not self.path.isprintable()
            or not isinstance(self.reason, ImportReason)
        ):
            _raise_detached(RoutingImportErrorCode.GROUP)


@dataclass(frozen=True, slots=True, repr=False)
class RuleTarget:
    """Назначение правила: вид, тег, outbound, по которым определено действие, и причины.

    Для балансировщика `outbound_tags` — outbound, выбранные селектором по
    префиксу, `fallback_tag` и `strategy` — как в конфигурации; группа
    резервирования не сводится к одному профилю. `action` равно `None`, когда
    соответствие неоднозначно или отсутствует; причины объясняют почему.
    Теги и стратегия хранятся как написаны для доверенного кода; в вывод
    они попадают только после проверки формата.
    """

    kind: RuleTargetKind
    tag: str | None
    outbound_tags: tuple[str, ...]
    fallback_tag: str | None
    strategy: str | None
    action: RoutingAction | None
    reasons: tuple[ImportReason, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.kind, RuleTargetKind)
            or (self.tag is not None and (type(self.tag) is not str or not self.tag))
            or not _names(self.outbound_tags)
            or (self.fallback_tag is not None and (type(self.fallback_tag) is not str or not self.fallback_tag))
            or (self.strategy is not None and type(self.strategy) is not str)
            or (self.action is not None and not isinstance(self.action, RoutingAction))
            or not _unique_reasons(self.reasons)
            or (self.action is None and not self.reasons)
            or (self.kind is RuleTargetKind.OUTBOUND and (
                self.outbound_tags not in ((), (self.tag,))
                or self.fallback_tag is not None or self.strategy is not None
            ))
            or (self.kind in (RuleTargetKind.BOTH, RuleTargetKind.NONE) and (
                self.tag is not None or self.outbound_tags or self.fallback_tag is not None
                or self.strategy is not None or self.action is not None
            ))
            or (self.kind is RuleTargetKind.BALANCER and self.tag is None)
        ):
            _raise_detached(RoutingImportErrorCode.TARGET)

    def __repr__(self) -> str:
        action = None if self.action is None else self.action.value
        return f"RuleTarget(kind={self.kind.value}, action={action})"

    def to_diagnostic(self) -> dict[str, object]:
        """Вид, теги и стратегия в безопасной форме, действие и причины.

        Тег, не прошедший `safe_identifier`, и неизвестная стратегия заменяются
        на `None`; признаки `*_known` сохраняют факт наличия значения.
        """
        return {
            "kind": self.kind.value,
            "tag_known": self.tag is not None,
            "tag": safe_identifier(self.tag),
            "outbound_tags": [safe_identifier(tag) for tag in self.outbound_tags],
            "fallback_known": self.fallback_tag is not None,
            "fallback_tag": safe_identifier(self.fallback_tag),
            "strategy_known": self.strategy is not None,
            "strategy": safe_strategy(self.strategy),
            "action": None if self.action is None else self.action.value,
            "reasons": [reason.value for reason in self.reasons],
        }


def _is_condition(value: object) -> bool:
    return isinstance(value, RoutingCondition)


@dataclass(frozen=True, slots=True, repr=False)
class ImportedRuleGroup(_PrivateRepresentation):
    """Одно правило Xray: условия в порядке значений, назначение, поля и причины.

    Условия группы делят одно действие и соседние позиции в политике.
    Правило, которое модель не переводит, содержит одно
    `UnsupportedRuleCondition` и остаётся только для просмотра; финальное
    правило условий не имеет. `rules` строятся из условий и действия, пока
    действие определено.
    """

    part: str
    index: int
    kind: RuleGroupKind
    conditions: tuple[RoutingCondition, ...]
    target: RuleTarget
    fields: tuple[str, ...]
    unsupported_fields: tuple[str, ...]
    unknown_fields: tuple[str, ...]
    value_count: int
    has_rule_tag: bool
    reasons: tuple[ImportReason, ...]
    value_reasons: tuple[ValueReason, ...]

    def __post_init__(self) -> None:
        if (
            not valid_document_name(self.part)
            or type(self.index) is not int or self.index < 0
            or not isinstance(self.kind, RuleGroupKind)
            or type(self.conditions) is not tuple or not all(_is_condition(item) for item in self.conditions)
            or type(self.target) is not RuleTarget
            or not _keys(self.fields) or len(set(self.fields)) != len(self.fields)
            or not _names(self.unsupported_fields) or not set(self.unsupported_fields) <= set(self.fields)
            or not set(self.unsupported_fields) <= XRAY_RULE_CONDITION_FIELDS
            or not _keys(self.unknown_fields) or not set(self.unknown_fields) <= set(self.fields)
            or type(self.value_count) is not int or self.value_count < 0
            or type(self.has_rule_tag) is not bool
            or not _unique_reasons(self.reasons)
            or type(self.value_reasons) is not tuple
            or not all(type(item) is ValueReason for item in self.value_reasons)
            or (self.kind is RuleGroupKind.FINAL and (self.conditions or self.value_reasons))
            or (self.kind is RuleGroupKind.RULES and not self.conditions)
        ):
            _raise_detached(RoutingImportErrorCode.GROUP)

    def __repr__(self) -> str:
        return f"ImportedRuleGroup(part={self.part!r}, index={self.index}, kind={self.kind.value})"

    @property
    def action(self) -> RoutingAction | None:
        """Действие группы, определённое по назначению; `None` — не определено."""
        return self.target.action

    @property
    def read_only(self) -> bool:
        """Группу нельзя безопасно редактировать как обычное правило."""
        return bool(self.reasons) or bool(self.target.reasons) or any(
            isinstance(item, (UnknownCondition, UnsupportedRuleCondition)) for item in self.conditions
        )

    @property
    def rules(self) -> tuple[RoutingRule, ...]:
        """Правила модели для условий группы; без действия правил нет."""
        if self.action is None:
            return ()
        return tuple(RoutingRule(item, self.action) for item in self.conditions)

    def to_diagnostic(self) -> dict[str, object]:
        """Структура, назначение и причины без доменов, адресов, кодов наборов и тегов правил.

        Имена полей выводятся только из списка полей Xray; неизвестные ключи
        задаёт пользователь, поэтому показывается лишь их число.
        """
        condition_types: dict[str, int] = {}
        for item in self.conditions:
            name = type(item).__name__
            condition_types[name] = condition_types.get(name, 0) + 1
        return {
            "part": self.part,
            "index": self.index,
            "kind": self.kind.value,
            "condition_count": len(self.conditions),
            "condition_types": condition_types,
            "value_count": self.value_count,
            "fields": [name for name in self.fields if name in XRAY_RULE_CONDITION_FIELDS],
            "unsupported_fields": list(self.unsupported_fields),
            "unknown_field_count": len(self.unknown_fields),
            "has_rule_tag": self.has_rule_tag,
            "action": None if self.action is None else self.action.value,
            "read_only": self.read_only,
            "reasons": [reason.value for reason in self.reasons],
            "value_reasons": [{"path": item.path, "reason": item.reason.value} for item in self.value_reasons],
            "target": self.target.to_diagnostic(),
        }


def _rebuild_condition(item: RoutingCondition) -> RoutingCondition:
    """Пересобрать условие его конструктором, чтобы повторно проверить поля."""
    if type(item) is DomainCondition:
        return DomainCondition(item.value, item.mode)
    if type(item) is IPCondition:
        return IPCondition(item.value)
    if type(item) in (GeoIPCondition, GeoSiteCondition):
        base = item.database
        if type(base) is not GeoDatabase:
            _raise_detached(RoutingImportErrorCode.GROUP)
        database = GeoDatabase(base.kind, base.reference, base.source, base.version, base.sha256)
        return type(item)(database, item.set_name)
    if type(item) is UnknownCondition:
        return UnknownCondition(item.family, item.reference)
    if type(item) is UnsupportedRuleCondition:
        return UnsupportedRuleCondition(item.fields, item.snapshot)
    _raise_detached(RoutingImportErrorCode.GROUP)


def _rebuild_target(target: RuleTarget) -> RuleTarget:
    if type(target) is not RuleTarget:
        _raise_detached(RoutingImportErrorCode.GROUP)
    return RuleTarget(
        target.kind, target.tag, target.outbound_tags, target.fallback_tag, target.strategy, target.action,
        target.reasons,
    )


def _rebuild_group(group: ImportedRuleGroup) -> ImportedRuleGroup:
    if (
        type(group) is not ImportedRuleGroup or type(group.conditions) is not tuple
        or type(group.value_reasons) is not tuple
    ):
        _raise_detached(RoutingImportErrorCode.SCHEME)
    try:
        return ImportedRuleGroup(
            group.part, group.index, group.kind, tuple(_rebuild_condition(item) for item in group.conditions),
            _rebuild_target(group.target), group.fields, group.unsupported_fields, group.unknown_fields,
            group.value_count, group.has_rule_tag, group.reasons,
            tuple(ValueReason(item.path, item.reason) for item in group.value_reasons),
        )
    except RoutingValidationError:
        # Повреждённое условие — ошибка группы; отказ назначения и группы проходит своим кодом.
        _raise_detached(RoutingImportErrorCode.GROUP)
    except (AttributeError, TypeError):
        _raise_detached(RoutingImportErrorCode.SCHEME)


def _check_scheme(scheme: "RoutingScheme") -> None:
    if (
        (scheme.routing_part is not None and not valid_document_name(scheme.routing_part))
        or type(scheme.routing_parts) is not tuple
        or not all(valid_document_name(name) for name in scheme.routing_parts)
        or len(set(scheme.routing_parts)) != len(scheme.routing_parts)
        or (scheme.routing_part is None) != (not scheme.routing_parts)
        or (scheme.routing_part is not None and scheme.routing_parts[-1] != scheme.routing_part)
        or type(scheme.groups) is not tuple
        or not _unique_reasons(scheme.reasons)
    ):
        _raise_detached(RoutingImportErrorCode.SCHEME)
    for group in scheme.groups:
        if _rebuild_group(group) != group:
            _raise_detached(RoutingImportErrorCode.SCHEME)
    if any(group.part != scheme.routing_part for group in scheme.groups):
        _raise_detached(RoutingImportErrorCode.SCHEME)
    if scheme.policy is None:
        return
    final = scheme.groups[-1] if scheme.groups else None
    if (
        type(scheme.policy) is not RoutingPolicy
        or final is None or final.kind is not RuleGroupKind.FINAL or final.action is None
        or any(group.kind is RuleGroupKind.FINAL or group.action is None for group in scheme.groups[:-1])
    ):
        _raise_detached(RoutingImportErrorCode.SCHEME)
    try:
        expected = RoutingPolicy(
            tuple(rule for group in scheme.groups[:-1] for rule in group.rules), FinalRoutingRule(final.action),
        )
    except RoutingValidationError:
        _raise_detached(RoutingImportErrorCode.SCHEME)
    if _rebuild_policy(scheme.policy) != expected:
        _raise_detached(RoutingImportErrorCode.SCHEME)


def _rebuild_policy(policy: RoutingPolicy) -> RoutingPolicy:
    """Пересобрать входную политику конструкторами из её собственных полей.

    `==` не отличает строку от `RoutingAction` (str-Enum) и `1`/`0` от `bool`:
    сравнение с ожидаемой политикой выполняется только после того, как
    конструкторы заново проверили типы каждого правила и условия.
    """
    rules = policy.rules
    final = policy.final_rule
    if (
        type(rules) is not tuple
        or any(type(rule) is not RoutingRule for rule in rules)
        or type(final) is not FinalRoutingRule
    ):
        _raise_detached(RoutingImportErrorCode.SCHEME)
    try:
        return RoutingPolicy(
            tuple(
                RoutingRule(_rebuild_condition(rule.condition), rule.action, enabled=rule.enabled, protected=rule.protected)
                for rule in rules
            ),
            FinalRoutingRule(final.action),
        )
    except (RoutingValidationError, RoutingImportError):
        _raise_detached(RoutingImportErrorCode.SCHEME)


@dataclass(frozen=True, slots=True, repr=False)
class RoutingScheme(_PrivateRepresentation):
    """Импортированные группы правил в порядке файла и политика, если её удалось собрать.

    `routing_part` — часть, чей раздел `routing` действует: при загрузке
    нескольких частей Xray v26.3.27 берёт раздел последней части, в которой
    он есть. `policy` собирается только когда каждое правило получило
    однозначное действие, а последнее правило — финальное в поддержанной
    форме; иначе `policy` равна `None`, а причины перечислены в `reasons`.
    Группы сохраняются всегда, включая доступные только для просмотра.
    """

    routing_part: str | None
    routing_parts: tuple[str, ...]
    groups: tuple[ImportedRuleGroup, ...]
    policy: RoutingPolicy | None
    reasons: tuple[ImportReason, ...]

    def __post_init__(self) -> None:
        _check_scheme(self)

    def __repr__(self) -> str:
        return f"RoutingScheme(groups={len(self.groups)}, policy={self.policy is not None})"

    @property
    def final_group(self) -> ImportedRuleGroup | None:
        """Финальная группа, если последнее правило распознано как правило для остатка трафика."""
        if self.groups and self.groups[-1].kind is RuleGroupKind.FINAL:
            return self.groups[-1]
        return None

    @property
    def final_action(self) -> RoutingAction | None:
        """Действие финального правила, если оно распознано и определено."""
        final = self.final_group
        return None if final is None else final.action

    @property
    def read_only(self) -> bool:
        """Схема только для просмотра: есть причина уровня схемы либо группа только для просмотра."""
        return self.policy is None or bool(self.reasons) or any(group.read_only for group in self.groups)

    def to_diagnostic(self) -> dict[str, object]:
        """Группы, политика и причины без доменов, адресов, кодов наборов и тегов правил."""
        return {
            "routing_part": self.routing_part,
            "routing_parts": list(self.routing_parts),
            "group_count": len(self.groups),
            "rule_count": sum(len(group.rules) for group in self.groups),
            "final_action": None if self.final_action is None else self.final_action.value,
            "read_only": self.read_only,
            "reasons": [reason.value for reason in self.reasons],
            "policy": None if self.policy is None else self.policy.to_diagnostic(),
            "groups": [group.to_diagnostic() for group in self.groups],
        }


def validate_routing_scheme(scheme: RoutingScheme) -> None:
    """Проверить готовую модель заново, включая каждую группу, условие и политику."""
    if type(scheme) is not RoutingScheme:
        _raise_detached(RoutingImportErrorCode.SCHEME)
    _check_scheme(scheme)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def _outbound_action(protocol: object) -> RoutingAction | None:
    """Действие по протоколу outbound; загрузчик Xray сравнивает идентификатор без учёта регистра."""
    if type(protocol) is not str:
        return None
    name = protocol.lower()
    if name in DIRECT_OUTBOUND_PROTOCOLS:
        return RoutingAction.DIRECT
    if name in BLOCK_OUTBOUND_PROTOCOLS:
        return RoutingAction.BLOCK
    if name in VPN_OUTBOUND_PROTOCOLS:
        return RoutingAction.VPN
    return None


@dataclass(frozen=True, slots=True)
class _Outbound:
    tag: str | None
    action: RoutingAction | None
    reason: ImportReason | None = None


def _chained(item: dict[str, object]) -> bool:
    """Передаёт ли outbound соединение другому outbound, как `Handler.Dial` Xray v26.3.27.

    Цепочку задают непустой `proxySettings.tag` и `streamSettings.sockopt.dialerProxy`
    (в него `proxySettings` с `transportLayer` превращается при загрузке).
    Неподдержанная структура этих разделов и варианты регистра их ключей
    считаются возможной цепочкой: выход по протоколу тогда не определяется.
    """
    proxy = item.get("proxySettings")
    if proxy is not None:
        if type(proxy) is not dict or _case_variants(proxy, _PROXY_SETTINGS_FIELDS):
            return True
        tag = proxy.get("tag")
        if tag is not None and (type(tag) is not str or tag):
            return True
    stream = item.get("streamSettings")
    if stream is None:
        return False
    if type(stream) is not dict or _case_variants(stream, _STREAM_SETTINGS_FIELDS):
        return True
    sockopt = stream.get("sockopt")
    if sockopt is None:
        return False
    if type(sockopt) is not dict or _case_variants(sockopt, _SOCKOPT_FIELDS):
        return True
    dialer = sockopt.get("dialerProxy")
    return dialer is not None and (type(dialer) is not str or bool(dialer))


def _outbound_entries(value: object) -> tuple[list[_Outbound], bool, bool]:
    """Записи раздела `outbounds`, признак поддержанной структуры и признак вариантов регистра ключей.

    `null` означает отсутствие раздела, иная структура — неподдержанную.
    """
    if value is None:
        return [], True, False
    if type(value) is not list:
        return [], False, False
    entries = []
    supported = True
    variant = False
    for item in value:
        if type(item) is not dict:
            entries.append(_Outbound(None, None))
            supported = False
            continue
        variant = variant or _case_variants(item, _OUTBOUND_FIELDS)
        tag = item.get("tag", "")
        tag = tag if type(tag) is str else None
        if _chained(item):
            entries.append(_Outbound(tag, None, ImportReason.OUTBOUND_CHAINED))
            continue
        action = _outbound_action(item.get("protocol"))
        entries.append(_Outbound(tag, action, None if action is not None else ImportReason.OUTBOUND_PROTOCOL_UNSUPPORTED))
    return entries, supported, variant


def _effective_outbounds(documents: list[tuple[str, dict[str, object]]]) -> tuple[list[_Outbound], bool, bool]:
    """Собрать outbound как `Config.Override` Xray v26.3.27 за линейное время.

    Первая часть берётся целиком, включая повторы тегов. Из каждой следующей
    части outbound с уже известным тегом заменяет первый outbound с этим тегом
    на месте. Новые для обычной части собираются и после неё ставятся в начало
    списка, поэтому повторы внутри части сохраняются все; для части со словом
    `tail` в имени новые сразу добавляются в конец, и повтор в той же части
    заменяет только что добавленный. Порядок важен только Xray для неявного
    первого outbound; модель требует явного финального.

    Позиции хранятся ячейками: индекс «тег → ячейка первого вхождения»
    заменяет поиск по списку, блоки начала собираются отдельно и соединяются
    один раз в конце.
    """
    body: list[list[_Outbound]] = []
    chunks: list[list[list[_Outbound]]] = []
    first: dict[str | None, list[_Outbound]] = {}
    supported = True
    variant = False
    for position, (name, document) in enumerate(documents):
        if "outbounds" not in document:
            continue
        entries, entries_supported, entries_variant = _outbound_entries(document["outbounds"])
        supported = supported and entries_supported
        variant = variant or entries_variant
        if position == 0:
            body = [[entry] for entry in entries]
            for cell in body:
                if cell[0].tag is not None:
                    first.setdefault(cell[0].tag, cell)
            continue
        if not entries:
            continue
        tail = _TAIL_MARKER in name.lower()
        prepends: list[list[_Outbound]] = []
        for entry in entries:
            cell = first.get(entry.tag) if entry.tag is not None else None
            if cell is not None:
                cell[0] = entry
            elif tail:
                cell = [entry]
                body.append(cell)
                if entry.tag is not None:
                    first[entry.tag] = cell
            else:
                prepends.append([entry])
        if prepends:
            # Блок встаёт перед всем прежним списком: его первое вхождение тега — первое во всём списке.
            for cell in prepends:
                if cell[0].tag is not None and cell[0].tag not in first:
                    first[cell[0].tag] = cell
            chunks.append(prepends)
    ordered = [cell[0] for chunk in reversed(chunks) for cell in chunk]
    ordered.extend(cell[0] for cell in body)
    return ordered, supported, variant


def _target(kind: RuleTargetKind, tag: str | None, *reasons: ImportReason) -> RuleTarget:
    return RuleTarget(kind, tag, (), None, None, None, tuple(reasons))


def _select_outbounds(selectors: tuple[str, ...], tags: tuple[str, ...]) -> tuple[str, ...]:
    """Outbound, тег которых начинается с одного из селекторов, в порядке outbound; пустой селектор выбирает все."""
    return tuple(tag for tag in tags if any(tag.startswith(selector) for selector in selectors))


class _TargetResolver:
    """Сопоставление тегов правил с действующими outbound и балансировщиками за линейное время."""

    def __init__(self, outbounds: list[_Outbound], balancers: object) -> None:
        self._by_tag: dict[str, list[_Outbound]] = {}
        tags: list[str] = []
        for entry in outbounds:
            # Outbound без тега Xray не регистрирует по тегу: правило и селектор его не достигают.
            if not entry.tag:
                continue
            if entry.tag not in self._by_tag:
                tags.append(entry.tag)
            self._by_tag.setdefault(entry.tag, []).append(entry)
        self._tags = tuple(tags)
        self._balancers: dict[str, list[dict[str, object]]] = {}
        self._resolved_balancers: dict[str, RuleTarget] = {}
        self.balancers_supported = True
        self.case_variant = False
        if balancers is None:
            return
        if type(balancers) is not list:
            self.balancers_supported = False
            return
        for item in balancers:
            if type(item) is dict and _case_variants(item, _BALANCER_FIELDS):
                self.case_variant = True
            if type(item) is dict and type(item.get("tag")) is str and item["tag"]:
                self._balancers.setdefault(item["tag"], []).append(item)
            else:
                self.balancers_supported = False

    def resolve(self, rule: dict[str, object]) -> RuleTarget:
        """Определить назначение по `outboundTag` и `balancerTag`, как их читает `parseFieldRule`."""
        outbound = rule.get("outboundTag")
        balancer = rule.get("balancerTag")
        if _case_variants(rule, frozenset({"outboundTag", "balancerTag"})):
            return _target(RuleTargetKind.NONE, None, ImportReason.FIELD_CASE_VARIANT)
        if any(value is not None and type(value) is not str for value in (outbound, balancer)):
            return _target(RuleTargetKind.NONE, None, ImportReason.TARGET_INVALID)
        if outbound and balancer:
            return _target(RuleTargetKind.BOTH, None, ImportReason.TARGET_AMBIGUOUS)
        if outbound:
            return self._outbound_target(outbound)
        if balancer:
            if balancer not in self._resolved_balancers:
                self._resolved_balancers[balancer] = self._balancer_target(balancer)
            return self._resolved_balancers[balancer]
        return _target(RuleTargetKind.NONE, None, ImportReason.TARGET_MISSING)

    def _outbound_target(self, tag: str) -> RuleTarget:
        entries = self._by_tag.get(tag)
        if entries is None:
            return _target(RuleTargetKind.OUTBOUND, tag, ImportReason.TARGET_UNRESOLVED)
        if len(entries) > 1:
            return _target(RuleTargetKind.OUTBOUND, tag, ImportReason.TARGET_DUPLICATE)
        if entries[0].action is None:
            return _target(RuleTargetKind.OUTBOUND, tag, entries[0].reason or ImportReason.OUTBOUND_PROTOCOL_UNSUPPORTED)
        return RuleTarget(RuleTargetKind.OUTBOUND, tag, (tag,), None, None, entries[0].action, ())

    def _balancer_target(self, tag: str) -> RuleTarget:
        items = self._balancers.get(tag)
        if items is None:
            return _target(RuleTargetKind.BALANCER, tag, ImportReason.TARGET_UNRESOLVED)
        if len(items) > 1:
            return _target(RuleTargetKind.BALANCER, tag, ImportReason.TARGET_DUPLICATE)
        item = items[0]
        reasons: list[ImportReason] = []
        if _case_variants(item, _BALANCER_FIELDS):
            reasons.append(ImportReason.FIELD_CASE_VARIANT)
        selectors = decode_string_list(item["selector"]) if item.get("selector") is not None else ()
        fallback = item.get("fallbackTag")
        strategy = item.get("strategy")
        strategy_type = None
        if selectors is None or (fallback is not None and type(fallback) is not str) or (
            strategy is not None and type(strategy) is not dict
        ):
            reasons.append(ImportReason.BALANCER_INVALID)
            selectors = () if selectors is None else selectors
        elif type(strategy) is dict and type(strategy.get("type")) is str:
            strategy_type = strategy["type"]
        fallback = fallback if type(fallback) is str and fallback else None
        selected = _select_outbounds(selectors, self._tags)
        actions: list[RoutingAction] = []
        for name in selected:
            entries = self._by_tag[name]
            if len(entries) > 1:
                reasons.append(ImportReason.TARGET_DUPLICATE)
            elif entries[0].action is None:
                reasons.append(entries[0].reason or ImportReason.OUTBOUND_PROTOCOL_UNSUPPORTED)
            elif entries[0].action not in actions:
                actions.append(entries[0].action)
        if not selected:
            reasons.append(ImportReason.BALANCER_EMPTY)
        if len(actions) > 1:
            reasons.append(ImportReason.BALANCER_MIXED)
        blocking = bool(reasons)
        if fallback is not None:
            if fallback not in self._by_tag:
                reasons.append(ImportReason.FALLBACK_UNRESOLVED)
            elif len(self._by_tag[fallback]) > 1:
                reasons.append(ImportReason.TARGET_DUPLICATE)
                blocking = True
        unique: list[ImportReason] = []
        for reason in reasons:
            if reason not in unique:
                unique.append(reason)
        action = None if blocking or len(actions) != 1 else actions[0]
        return RuleTarget(RuleTargetKind.BALANCER, tag, selected, fallback, strategy_type, action, tuple(unique))


def _is_catch_all(fields: tuple[str, ...], rule: dict[str, object]) -> bool:
    """Правило только с `network` из `tcp` и `udp` совпадает со всем трафиком TCP и UDP.

    Правило без полей условий сюда не относится: `BuildCondition` Xray
    v26.3.27 отклоняет его, и маршрутизатор не запускается.
    """
    if fields != ("network",):
        return False
    networks = decode_string_list(rule["network"])
    return networks is not None and {network.lower() for network in networks} == _FINAL_NETWORKS


def _domain(name: str, mode: DomainMatch, text: str) -> tuple[RoutingCondition, ImportReason | None]:
    try:
        condition = DomainCondition(name, mode)
    except RoutingValidationError:
        return UnknownCondition(ConditionFamily.DOMAIN, text), ImportReason.DOMAIN_UNSUPPORTED
    if condition.value != name:
        return UnknownCondition(ConditionFamily.DOMAIN, text), ImportReason.DOMAIN_NOT_CANONICAL
    return condition, None


def _geo_condition(
    family: ConditionFamily, reference: GeoReference, text: str,
) -> tuple[RoutingCondition, ImportReason | None]:
    unknown = UnknownCondition(family, text)
    if reference.negated:
        return unknown, ImportReason.GEOIP_NEGATED
    if reference.attributes:
        return unknown, ImportReason.GEOSITE_ATTRIBUTES
    try:
        if family is ConditionFamily.DOMAIN:
            database = GeoDatabase(GeoDatabaseKind.GEOSITE, reference.file_name)
            return GeoSiteCondition(database, reference.set_name), None
        database = GeoDatabase(GeoDatabaseKind.GEOIP, reference.file_name)
        return GeoIPCondition(database, reference.set_name), None
    except RoutingValidationError as error:
        if error.code is RoutingErrorCode.SET_NAME:
            return unknown, ImportReason.SET_NAME_UNSUPPORTED
        return unknown, ImportReason.GEO_REFERENCE_UNSUPPORTED


_IPV4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def _ipv4_mapped(value: str) -> bool:
    """Адрес сети в `::ffff:0:0/96`: `IPAddress` Xray v26.3.27 сводит его к IPv4."""
    network = ipaddress.ip_network(value)
    return network.version == 6 and network.network_address in _IPV4_MAPPED


_DOMAIN_PREFIXES = (
    ("regexp:", ImportReason.DOMAIN_REGEXP),
    ("domain:", None),
    ("full:", None),
    ("keyword:", ImportReason.DOMAIN_KEYWORD),
    ("dotless:", ImportReason.DOMAIN_DOTLESS),
)
"""Префиксы `parseDomainRule` после `geosite:` и `ext:` в порядке проверки Xray."""


def _translate(
    part: str, path: str, family: ConditionFamily, text: str,
) -> tuple[RoutingCondition, ImportReason | None]:
    """Перевести одно значение списка по правилам декодера; непереводимое сохраняется как неизвестное."""
    reference = parse_geo_reference(RuleListValue(part, path, family, True, text))
    if type(reference) is UnsupportedGeoReference:
        return UnknownCondition(family, text), ImportReason.GEO_REFERENCE_UNSUPPORTED
    if type(reference) is GeoReference:
        return _geo_condition(family, reference, text)
    if family is ConditionFamily.IP:
        try:
            condition = IPCondition(text)
        except RoutingValidationError:
            return UnknownCondition(family, text), ImportReason.IP_UNSUPPORTED
        if _ipv4_mapped(condition.value):
            return UnknownCondition(family, text), ImportReason.IP_IPV4_MAPPED
        return condition, None
    for prefix, reason in _DOMAIN_PREFIXES:
        if text.startswith(prefix):
            if reason is not None:
                return UnknownCondition(family, text), reason
            mode = DomainMatch.SUBDOMAINS if prefix == "domain:" else DomainMatch.EXACT
            return _domain(text[len(prefix):], mode, text)
    return UnknownCondition(family, text), ImportReason.DOMAIN_PLAIN


def _import_rule(part: str, index: int, rule: object, resolver: _TargetResolver, last: bool) -> ImportedRuleGroup:
    path = f"routing.rules[{index}]"
    if type(rule) is not dict:
        reason = ImportReason.RULE_NOT_OBJECT
        return ImportedRuleGroup(
            part, index, RuleGroupKind.RULES, (UnsupportedRuleCondition((), _canonical(rule)),),
            _target(RuleTargetKind.NONE, None, reason), (), (), (), 0, False, (reason,), (),
        )
    target = resolver.resolve(rule)
    fields = tuple(key for key in rule if key not in _SERVICE_FIELDS)
    unsupported = tuple(key for key in fields if key in XRAY_RULE_CONDITION_FIELDS and key not in _MODEL_FIELDS)
    unknown = tuple(key for key in fields if key not in XRAY_RULE_CONDITION_FIELDS)
    has_rule_tag = "ruleTag" in rule

    def group(kind: RuleGroupKind, conditions: tuple[RoutingCondition, ...], reasons: tuple[ImportReason, ...],
              value_count: int = 0, value_reasons: tuple[ValueReason, ...] = ()) -> ImportedRuleGroup:
        return ImportedRuleGroup(
            part, index, kind, conditions, target, fields, unsupported, unknown, value_count, has_rule_tag,
            reasons, value_reasons,
        )

    def placeholder() -> tuple[UnsupportedRuleCondition]:
        return (UnsupportedRuleCondition(fields, _canonical({key: rule[key] for key in fields})),)

    if not fields:
        return group(RuleGroupKind.RULES, placeholder(), (ImportReason.RULE_WITHOUT_CONDITIONS,))
    if _is_catch_all(fields, rule):
        # `network` из `tcp` и `udp` здесь понято как форма правила для остатка трафика.
        unsupported = ()
        if last:
            return group(RuleGroupKind.FINAL, (), ())
        return group(RuleGroupKind.RULES, placeholder(), (ImportReason.CATCH_ALL_NOT_LAST,))
    reasons: list[ImportReason] = []
    if unsupported:
        reasons.append(ImportReason.UNSUPPORTED_CONDITIONS)
    if unknown:
        reasons.append(ImportReason.UNKNOWN_FIELDS)
    if _case_variants({key: None for key in unknown}, _RULE_FIELDS):
        reasons.append(ImportReason.FIELD_CASE_VARIANT)
    values: list[tuple[str, ConditionFamily, str]] = []
    families: list[ConditionFamily] = []
    invalid = empty = False
    for key in fields:
        if key not in _MODEL_FIELDS:
            continue
        decoded = decode_string_list(rule[key])
        if decoded is None:
            invalid = True
            continue
        family = ConditionFamily.IP if key == "ip" else ConditionFamily.DOMAIN
        if family not in families:
            families.append(family)
        if not decoded or any(not text for text in decoded):
            empty = True
        values.extend((f"{path}.{key}[{position}]", family, text) for position, text in enumerate(decoded))
    if invalid:
        reasons.append(ImportReason.VALUES_INVALID)
    if empty:
        reasons.append(ImportReason.VALUES_EMPTY)
    if len(families) > 1:
        reasons.append(ImportReason.CONDITIONS_COMBINED)
    if reasons:
        return group(RuleGroupKind.RULES, placeholder(), tuple(reasons), len(values))
    conditions: list[RoutingCondition] = []
    value_reasons: list[ValueReason] = []
    for value_path, family, text in values:
        condition, reason = _translate(part, value_path, family, text)
        conditions.append(condition)
        if reason is not None:
            value_reasons.append(ValueReason(value_path, reason))
    return group(RuleGroupKind.RULES, tuple(conditions), (), len(values), tuple(value_reasons))


def import_routing_scheme(config: XrayConfigSet) -> RoutingScheme:
    """Перевести правила действующего раздела `routing` в группы и, если возможно, политику.

    Части экспортируются по одному разу; их байты, хеши и неизвестные поля
    не меняются. Каждое правило становится группой в порядке файла:
    переводимые значения — условиями модели, непереводимые — неизвестными
    ссылками, а правило с полями вне модели — одним неподдержанным условием.
    Политика собирается только при однозначных действиях всех правил и
    финальном правиле в поддержанной форме; импортированные правила не
    помечаются служебными и не отключаются.
    """
    if type(config) is not XrayConfigSet:
        _raise_detached(RoutingImportErrorCode.CONFIG)
    documents = [(part.name, part.export()) for part in config.parts]
    outbounds, outbounds_supported, case_variant = _effective_outbounds(documents)
    case_variant = case_variant or any(_case_variants(document, _DOCUMENT_FIELDS) for _name, document in documents)
    routing_part = None
    routing: object = None
    routing_parts: list[str] = []
    for name, document in documents:
        if document.get("routing") is not None:
            routing_parts.append(name)
            routing_part, routing = name, document["routing"]
    reasons: list[ImportReason] = []
    if not outbounds_supported:
        reasons.append(ImportReason.OUTBOUNDS_UNSUPPORTED)
    if type(routing) is dict and _case_variants(routing, _ROUTING_FIELDS):
        case_variant = True
    groups: tuple[ImportedRuleGroup, ...] = ()
    rules_readable = False
    if routing is None:
        reasons.append(ImportReason.ROUTING_MISSING)
    elif type(routing) is not dict:
        reasons.append(ImportReason.ROUTING_UNSUPPORTED)
    else:
        resolver = _TargetResolver(outbounds, routing.get("balancers"))
        if not resolver.balancers_supported:
            reasons.append(ImportReason.BALANCERS_UNSUPPORTED)
        case_variant = case_variant or resolver.case_variant
        rules = routing.get("rules")
        if rules is None:
            rules = []
        if type(rules) is not list:
            reasons.append(ImportReason.RULES_UNSUPPORTED)
        else:
            rules_readable = True
            groups = tuple(
                _import_rule(routing_part, index, rule, resolver, index == len(rules) - 1)
                for index, rule in enumerate(rules)
            )
    if case_variant:
        reasons.append(ImportReason.FIELD_CASE_VARIANT)
    policy = None
    final = groups[-1] if groups and groups[-1].kind is RuleGroupKind.FINAL else None
    if final is None:
        if rules_readable:
            reasons.append(ImportReason.FINAL_RULE_MISSING)
    elif final.action is None:
        reasons.append(ImportReason.FINAL_RULE_UNRESOLVED)
    elif any(group.action is None for group in groups[:-1]):
        reasons.append(ImportReason.RULE_ACTION_UNRESOLVED)
    elif not case_variant:
        # При вариантах регистра Xray мог выбрать другой раздел, outbound или поле: политика не собирается.
        rules = tuple(rule for group in groups[:-1] for rule in group.rules)
        policy = RoutingPolicy(rules, FinalRoutingRule(final.action))
    return RoutingScheme(routing_part, tuple(routing_parts), groups, policy, tuple(reasons))
