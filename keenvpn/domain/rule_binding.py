"""Семантический ключ правила и привязка записей метаданных к правилам при повторном импорте.

Запись раздела `rules` метаданных менеджера находит своё правило по
семантическому ключу: тип условия, каноническое значение модели и действие.
Позиция правила, его группа, `ruleTag` и теги outbound в ключ не входят,
поэтому привязка переживает перемещение, вставку и удаление соседних правил
и перенос значения между группами с тем же действием, а ручная правка
значения или действия вне менеджера отвязывает только это правило.
Привязка линейна по числу правил и записей и ничего не выбирает по первому:
ключ, встречающийся больше одного раза среди правил или среди записей,
оставляет все его правила и записи без привязки с машинной причиной.
Записи без правила сохраняются и считаются отдельно. Модуль работает в памяти:
здесь нет чтения файлов, Xray и роутера, а идентификаторы не генерируются.
"""

from dataclasses import dataclass, replace
from enum import StrEnum
import json
from typing import NoReturn

from keenvpn.domain.manager_metadata import ManagerMetadataError, RuleKey, RuleRecord
from keenvpn.domain.routing import (
    DomainCondition, GeoIPCondition, GeoSiteCondition, IPCondition, RoutingRule, RoutingValidationError,
    UnknownCondition, UnsupportedRuleCondition, _PrivateRepresentation,
)
from keenvpn.domain.routing_import import RoutingScheme
from keenvpn.domain.routing_policy import RoutingPolicy


class RuleBindingErrorCode(StrEnum):
    """Причины отказа без значений условий, названий и ключей."""

    RULES = "invalid_binding_rules"
    RECORDS = "invalid_binding_records"
    SCHEME = "invalid_binding_scheme"
    BINDING = "invalid_rule_binding"


_MESSAGES = {
    RuleBindingErrorCode.RULES: "Привязка принимает правила модели маршрутизации без идентификаторов и названий.",
    RuleBindingErrorCode.RECORDS: "Привязка принимает записи правил с уникальными идентификаторами.",
    RuleBindingErrorCode.SCHEME: "Привязка по схеме принимает импортированную схему маршрутизации.",
    RuleBindingErrorCode.BINDING: "Результат привязки должен содержать согласованные правила, записи и политику.",
}


class RuleBindingError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: RuleBindingErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: RuleBindingErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise RuleBindingError(code) from None
    except RuleBindingError as error:
        error.__context__ = None
        raise


class BindingReason(StrEnum):
    """Машинные причины, по которым правило или запись остались без привязки."""

    RULE_DUPLICATE = "rule_duplicate"
    """Ключ встречается среди правил больше одного раза: неоднозначно, ничего не выбирается."""
    RECORD_DUPLICATE = "record_duplicate"
    """Ключ встречается среди записей больше одного раза: неоднозначно, ничего не выбирается."""
    RECORD_MISSING = "record_missing"
    """У правила нет записи с его ключом: идентификатор ещё не присвоен."""
    RULE_MISSING = "rule_missing"
    """У записи нет правила с её ключом: правило удалено или изменено вне менеджера; запись сохраняется."""


_BOUND = "bound"
_RULE_REASONS = frozenset({BindingReason.RULE_DUPLICATE, BindingReason.RECORD_DUPLICATE, BindingReason.RECORD_MISSING})
_RECORD_REASONS = frozenset({BindingReason.RULE_DUPLICATE, BindingReason.RECORD_DUPLICATE, BindingReason.RULE_MISSING})


def rule_key(rule: RoutingRule) -> RuleKey:
    """Семантический ключ правила: тип условия, каноническое значение модели и действие.

    Значения уже нормализованы конструкторами условий: домен — IDNA в нижнем
    регистре с режимом (`subdomains:` или `exact:`), адрес — стандартная запись,
    набор геобазы — имя файла и код набора без версии и хеша базы, неизвестная
    ссылка — семейство и исходный текст, неподдержанное правило — JSON-снимок
    его полей с отсортированными ключами объектов на всех уровнях: порядок
    ключей в файле Xray смысл правила не меняет, порядок массивов и типы
    значений сохраняются. Идентификатор, название, состояние и защита
    правила в ключ не входят.
    """
    if type(rule) is not RoutingRule:
        _raise_detached(RuleBindingErrorCode.RULES)
    condition = rule.condition
    if type(condition) is DomainCondition:
        kind, value = "domain", f"{condition.mode.value}:{condition.value}"
    elif type(condition) is IPCondition:
        kind, value = "ip", condition.value
    elif type(condition) is GeoIPCondition:
        kind, value = "geoip", f"{condition.database.reference}:{condition.set_name}"
    elif type(condition) is GeoSiteCondition:
        kind, value = "geosite", f"{condition.database.reference}:{condition.set_name}"
    elif type(condition) is UnknownCondition:
        kind, value = "unknown", f"{condition.family.value}:{condition.reference}"
    elif type(condition) is UnsupportedRuleCondition:
        kind, value = "unsupported", _sorted_snapshot(condition.snapshot)
    else:
        _raise_detached(RuleBindingErrorCode.RULES)
    try:
        return RuleKey(kind, value, rule.action)
    except ManagerMetadataError:
        _raise_detached(RuleBindingErrorCode.RULES)


def _sorted_snapshot(snapshot: str) -> str:
    """Снимок полей неподдержанного правила с отсортированными ключами объектов на всех уровнях.

    Текст, который не является JSON или не кодируется обратно (например,
    `NaN`, `Infinity` и число вне диапазона в значении записи метаданных),
    возвращается как есть: такой ключ всё равно не совпадёт со снимком
    импорта, где строгий разбор частей Xray этих значений не допускает.
    """
    try:
        document = json.loads(snapshot)
        return json.dumps(document, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (ValueError, TypeError, RecursionError):
        return snapshot


def _match_key(key: RuleKey) -> tuple[str, str, str]:
    """Сопоставление идёт по известным полям ключа; неизвестные поля записи на него не влияют.

    Значение ключа `unsupported` нормализуется и у записи: порядок ключей
    объектов в сохранённом снимке не влияет на совпадение.
    """
    value = _sorted_snapshot(key.value) if key.condition == "unsupported" else key.value
    return key.condition, value, key.action.value


@dataclass(frozen=True, slots=True, repr=False)
class BoundRule(_PrivateRepresentation):
    """Правило в порядке схемы с записью, если она найдена однозначно.

    Привязанное правило несёт идентификатор и название записи; правило без
    записи остаётся без них, а `reason` объясняет почему.
    """

    index: int
    rule: RoutingRule
    record: RuleRecord | None
    reason: BindingReason | None

    def __post_init__(self) -> None:
        if (
            type(self.index) is not int or self.index < 0
            or type(self.rule) is not RoutingRule
            or (self.record is None) != (self.reason is not None)
            or (self.record is not None and (
                type(self.record) is not RuleRecord
                or self.rule.rule_id != self.record.rule_id or self.rule.name != self.record.name
            ))
            or (self.reason is not None and (
                self.reason not in _RULE_REASONS or self.rule.rule_id is not None or self.rule.name is not None
            ))
        ):
            _raise_detached(RuleBindingErrorCode.BINDING)

    @property
    def bound(self) -> bool:
        """Найдена ли запись для правила."""
        return self.record is not None

    def to_diagnostic(self) -> dict[str, object]:
        """Позиция, итог привязки и диагностика правила без значений условия и названия."""
        return {
            "index": self.index,
            "binding": _BOUND if self.reason is None else self.reason.value,
            **self.rule.to_diagnostic(),
        }


@dataclass(frozen=True, slots=True, repr=False)
class UnboundRecord(_PrivateRepresentation):
    """Запись метаданных, не привязанная ни к одному правилу, с причиной."""

    record: RuleRecord
    reason: BindingReason

    def __post_init__(self) -> None:
        if type(self.record) is not RuleRecord or self.reason not in _RECORD_REASONS:
            _raise_detached(RuleBindingErrorCode.BINDING)

    def to_diagnostic(self) -> dict[str, object]:
        """Идентификатор, признак и длина названия и причина без названия и ключа."""
        return {
            "rule_id": self.record.rule_id,
            "has_name": self.record.name is not None,
            "name_length": None if self.record.name is None else len(self.record.name),
            "reason": self.reason.value,
        }


@dataclass(frozen=True, slots=True, repr=False)
class RuleBinding(_PrivateRepresentation):
    """Итог привязки: правила в порядке схемы, записи без правила и политика с идентичностью.

    `policy` собирается только когда у схемы есть политика: те же правила
    с идентификаторами и названиями записей и то же финальное правило.
    """

    rules: tuple[BoundRule, ...]
    unbound_records: tuple[UnboundRecord, ...]
    policy: RoutingPolicy | None

    def __post_init__(self) -> None:
        if (
            type(self.rules) is not tuple or any(type(item) is not BoundRule for item in self.rules)
            or [item.index for item in self.rules] != list(range(len(self.rules)))
            or type(self.unbound_records) is not tuple
            or any(type(item) is not UnboundRecord for item in self.unbound_records)
            or (self.policy is not None and (
                type(self.policy) is not RoutingPolicy or self.policy.rules != self.bound_rules
            ))
        ):
            _raise_detached(RuleBindingErrorCode.BINDING)
        ids = [item.record.rule_id for item in self.rules if item.record is not None]
        ids.extend(item.record.rule_id for item in self.unbound_records)
        if len(set(ids)) != len(ids):
            _raise_detached(RuleBindingErrorCode.BINDING)

    def __repr__(self) -> str:
        return f"RuleBinding(rules={len(self.rules)}, bound={self.bound_rule_count}, unbound_records={len(self.unbound_records)})"

    @property
    def bound_rules(self) -> tuple[RoutingRule, ...]:
        """Правила в порядке схемы с применёнными идентификаторами и названиями."""
        return tuple(item.rule for item in self.rules)

    @property
    def bound_rule_count(self) -> int:
        """Число правил, получивших запись."""
        return sum(item.bound for item in self.rules)

    @property
    def record_count(self) -> int:
        """Число записей, участвовавших в привязке: привязанные и без правила."""
        return self.bound_rule_count + len(self.unbound_records)

    def to_diagnostic(self) -> dict[str, object]:
        """Счётчики, итог по каждому правилу и записи без правила; названия и ключи не выводятся."""
        return {
            "rule_count": len(self.rules),
            "bound_rule_count": self.bound_rule_count,
            "named_rule_count": sum(item.rule.name is not None for item in self.rules),
            "unbound_rule_count": len(self.rules) - self.bound_rule_count,
            "record_count": self.record_count,
            "unbound_record_count": len(self.unbound_records),
            "policy": None if self.policy is None else self.policy.to_diagnostic(),
            "rules": [item.to_diagnostic() for item in self.rules],
            "unbound_records": [item.to_diagnostic() for item in self.unbound_records],
        }


def _check_records(records: object) -> tuple[RuleRecord, ...]:
    if type(records) not in (tuple, list) or any(type(record) is not RuleRecord for record in records):
        _raise_detached(RuleBindingErrorCode.RECORDS)
    ids = {record.rule_id for record in records}
    if len(ids) != len(records):
        _raise_detached(RuleBindingErrorCode.RECORDS)
    return tuple(records)


def _check_rules(rules: object) -> tuple[RoutingRule, ...]:
    if type(rules) not in (tuple, list) or any(
        type(rule) is not RoutingRule or rule.rule_id is not None or rule.name is not None for rule in rules
    ):
        _raise_detached(RuleBindingErrorCode.RULES)
    return tuple(rules)


def bind_rule_records(
    rules: tuple[RoutingRule, ...], records: tuple[RuleRecord, ...], policy: RoutingPolicy | None = None,
) -> RuleBinding:
    """Привязать записи к правилам по семантическому ключу за линейное время.

    `rules` — правила в порядке схемы без идентификаторов и названий;
    `records` — записи раздела `rules` с уникальными идентификаторами;
    `policy` — политика из тех же правил, если она есть: тогда результат
    содержит политику с применённой идентичностью. Правило привязывается
    к записи, только когда их ключ единственный с обеих сторон.
    """
    rules = _check_rules(rules)
    records = _check_records(records)
    if policy is not None and (type(policy) is not RoutingPolicy or policy.rules != rules):
        _raise_detached(RuleBindingErrorCode.RULES)
    keys = [_match_key(rule_key(rule)) for rule in rules]
    rule_counts: dict[tuple[str, str, str], int] = {}
    for key in keys:
        rule_counts[key] = rule_counts.get(key, 0) + 1
    record_counts: dict[tuple[str, str, str], int] = {}
    record_keys = [_match_key(record.key) for record in records]
    for key in record_keys:
        record_counts[key] = record_counts.get(key, 0) + 1
    by_key = {key: record for key, record in zip(record_keys, records) if record_counts[key] == 1}
    bound: list[BoundRule] = []
    for index, (rule, key) in enumerate(zip(rules, keys)):
        if rule_counts[key] > 1:
            bound.append(BoundRule(index, rule, None, BindingReason.RULE_DUPLICATE))
        elif record_counts.get(key, 0) == 0:
            bound.append(BoundRule(index, rule, None, BindingReason.RECORD_MISSING))
        elif record_counts[key] > 1:
            bound.append(BoundRule(index, rule, None, BindingReason.RECORD_DUPLICATE))
        else:
            record = by_key[key]
            bound.append(BoundRule(index, replace(rule, rule_id=record.rule_id, name=record.name), record, None))
    unbound: list[UnboundRecord] = []
    for record, key in zip(records, record_keys):
        if record_counts[key] > 1:
            unbound.append(UnboundRecord(record, BindingReason.RECORD_DUPLICATE))
        elif rule_counts.get(key, 0) == 0:
            unbound.append(UnboundRecord(record, BindingReason.RULE_MISSING))
        elif rule_counts[key] > 1:
            unbound.append(UnboundRecord(record, BindingReason.RULE_DUPLICATE))
    bound_policy = None
    if policy is not None:
        try:
            bound_policy = RoutingPolicy(tuple(item.rule for item in bound), policy.final_rule)
        except RoutingValidationError:
            _raise_detached(RuleBindingErrorCode.BINDING)
    return RuleBinding(tuple(bound), tuple(unbound), bound_policy)


def scheme_rules(scheme: RoutingScheme) -> tuple[RoutingRule, ...]:
    """Правила модели всех групп схемы в порядке файла.

    Группа без определённого действия правил не даёт. При наличии политики
    это ровно её правила; политика может отсутствовать, например из-за
    неоднозначного резерва балансировщика, а правила групп остаются.
    """
    if type(scheme) is not RoutingScheme:
        _raise_detached(RuleBindingErrorCode.SCHEME)
    return tuple(rule for group in scheme.groups for rule in group.rules)


def bind_routing_scheme(scheme: RoutingScheme, records: tuple[RuleRecord, ...]) -> RuleBinding:
    """Привязать записи к правилам импортированной схемы в порядке файла."""
    return bind_rule_records(scheme_rules(scheme), records, scheme.policy)
