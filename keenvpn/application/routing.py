"""Сценарий статического объяснения маршрута по действующим правилам.

Политика берётся либо из порта `RoutingPolicySource`, либо из импортированной
схемы действующей конфигурации Xray через обработчик импорта — тем же чтением
моделей, сводкой и привязкой метаданных, что у списка правил. Во втором случае
представление дополняется позицией группы, названием и идентификатором правила
из метаданных и назначением по позиции; несобранная политика — отдельное
состояние результата, а не выдуманный маршрут. Введённые домен и адреса,
значения условий и коды наборов в представление не входят.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import GeoDataSource, ManagerMetadataStore, RoutingPolicySource
from keenvpn.application.proxy_config import XrayPositionView
from keenvpn.application.routing_import import ImportRoutingSchemeHandler, RoutingSchemeView, RuleTargetView
from keenvpn.application.routing_rules import (
    MetadataState, SchemeReading, TargetPositionState, read_scheme_identity, resolve_target_position,
)
from keenvpn.application.views import view_dict
from keenvpn.domain.routing import RoutingErrorCode, RoutingValidationError, valid_rule_id, valid_rule_name
from keenvpn.domain.routing_explanation import (
    DomainSource, IPSource, RouteExplanation, RoutingContext, context_assumptions, destination_context,
    explain_route,
)
from keenvpn.domain.routing_import import RoutingScheme
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class ExplainRoute:
    """Предположения о назначении; значения считаются приватными данными.

    `destination` — строка назначения из общего ввода меню: домен, отдельный
    адрес или домен с адресами через пробел; её разбирает домен. Она
    взаимоисключающа с типизированными `domain`, `domain_source`, `ips`
    и `ip_source`.
    """

    name: ClassVar[str] = "explain_route"

    destination: str | None = None
    domain: str | None = None
    domain_source: DomainSource = DomainSource.UNKNOWN
    ips: tuple[str, ...] | None = None
    ip_source: IPSource = IPSource.UNKNOWN
    contract_version: int = CONTRACT_VERSION

    def __repr__(self) -> str:
        return "ExplainRoute(<скрытые параметры>)"


class RouteOutcome(StrEnum):
    """Итог расчёта: четыре раздельных состояния, ни одно не выводится из другого."""

    RULE = "rule"
    """Совпало обычное правило: выбраны его позиция и действие."""
    FINAL = "final"
    """Ни одно включённое правило не совпало: действует финальное правило."""
    UNKNOWN = "unknown"
    """Первое неизвестное условие остановило расчёт: правило не выбрано, маршрут не определён."""
    POLICY_ABSENT = "policy_absent"
    """Политика импортированной схемы не собрана: правила не проверялись."""


OUTCOME_LABELS: Mapping[str, str] = MappingProxyType({
    RouteOutcome.RULE.value: "выбрано правило",
    RouteOutcome.FINAL.value: "ни одно правило не выбрано, действует финальное правило",
    RouteOutcome.UNKNOWN.value: "правило не выбрано: условие неизвестно, маршрут не определён",
    RouteOutcome.POLICY_ABSENT.value: "расчёт не выполнен: политика действующей схемы не собрана",
})
"""Русские подписи итогов расчёта. Таблица только для чтения."""
STEP_RESULT_LABELS: Mapping[str, str] = MappingProxyType({
    MatchResult.MATCH.value: "совпало",
    MatchResult.NO_MATCH.value: "не совпало",
    MatchResult.UNKNOWN.value: "неизвестно",
})
"""Русские подписи результата шага. Таблица только для чтения."""
STEP_SKIPPED_LABEL = "пропущено"
"""Подпись шага без результата: правило выключено."""

INCONSISTENT = "route_explanation_inconsistent"
"""Код отказа, когда расчёт не удалось согласовать со схемой и сводкой тех же моделей."""
_INCONSISTENT = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, INCONSISTENT,
    "Объяснение маршрута не удалось согласовать с импортированной схемой.",
)


@dataclass(frozen=True, slots=True)
class RouteSchemeView:
    """Импортированная схема, по политике которой выполнен расчёт: часть, режим, причины и счётчики."""

    routing_part: str | None
    read_only: bool
    reasons: tuple[str, ...]
    group_count: int
    rule_count: int
    policy_present: bool

    def __post_init__(self) -> None:
        if (
            not (self.routing_part is None or type(self.routing_part) is str)
            or type(self.read_only) is not bool or type(self.policy_present) is not bool
            or type(self.reasons) is not tuple or any(type(item) is not str for item in self.reasons)
            or type(self.group_count) is not int or self.group_count < 0
            or type(self.rule_count) is not int or self.rule_count < 0
        ):
            raise TypeError("Некорректное описание схемы в объяснении маршрута.")

    @classmethod
    def from_scheme(cls, scheme: RoutingScheme) -> "RouteSchemeView":
        """Построить представление из безопасной диагностики схемы."""
        diagnostic = scheme.to_diagnostic()
        return cls(
            routing_part=diagnostic["routing_part"], read_only=diagnostic["read_only"],
            reasons=tuple(diagnostic["reasons"]), group_count=diagnostic["group_count"],
            rule_count=diagnostic["rule_count"], policy_present=diagnostic["policy"] is not None,
        )


def _identity_consistent(has_id: object, rule_id: object, has_name: object, name: object) -> bool:
    return (
        type(has_id) is bool and has_id == (rule_id is not None) and (rule_id is None or valid_rule_id(rule_id))
        and type(has_name) is bool and has_name == (name is not None) and (name is None or valid_rule_name(name))
    )


def _position_consistent(group_index: object, offset: object) -> bool:
    return (
        (group_index is None or (type(group_index) is int and group_index >= 0))
        and (offset is None or (type(offset) is int and offset >= 0))
        and not (group_index is None and offset is not None)
    )


@dataclass(frozen=True, slots=True)
class RouteStepView:
    """Шаг объяснения без значений условий, ссылок и версий баз.

    `index` — позиция правила в политике (счёт с нуля), `group_index` — индекс
    правила Xray в действующей части и `offset` — позиция внутри его группы,
    когда политика взята из импортированной схемы; у финального правила
    `offset` пуст. Название — пользовательский текст после проверки
    `valid_rule_name`: интерфейс выводит его только через свой фильтр.
    """

    index: int
    condition_type: str | None
    enabled: bool | None
    protected: bool | None
    action: str
    result: str | None
    reason_code: str
    reason: str
    database_kind: str | None
    database_version_known: bool
    group_index: int | None = None
    offset: int | None = None
    has_id: bool = False
    rule_id: str | None = None
    has_name: bool = False
    name: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.index) is not int or self.index < 0
            or not _position_consistent(self.group_index, self.offset)
            or not _identity_consistent(self.has_id, self.rule_id, self.has_name, self.name)
        ):
            raise TypeError("Некорректное описание шага объяснения маршрута.")


@dataclass(frozen=True, slots=True)
class RouteSelectionView:
    """Выбранная позиция, действие, идентичность правила и назначение по позиции.

    `target`, `target_position_state` и `target_position` заполняются только
    по импортированной схеме: назначение группы из её представления и позиция
    по структурной сводке тех же моделей; скрытый тег позицию не теряет.
    """

    index: int
    action: str
    is_final: bool
    group_index: int | None = None
    offset: int | None = None
    has_id: bool = False
    rule_id: str | None = None
    has_name: bool = False
    name: str | None = None
    target: RuleTargetView | None = None
    target_position_state: TargetPositionState | None = None
    target_position: XrayPositionView | None = None

    def __post_init__(self) -> None:
        if (
            type(self.index) is not int or self.index < 0 or type(self.action) is not str
            or type(self.is_final) is not bool
            or not _position_consistent(self.group_index, self.offset)
            or (self.is_final and self.offset is not None)
            or not _identity_consistent(self.has_id, self.rule_id, self.has_name, self.name)
            or not (self.target is None or type(self.target) is RuleTargetView)
            or (self.target is None) != (self.target_position_state is None)
            or not (self.target_position_state is None or type(self.target_position_state) is TargetPositionState)
            or not (self.target_position is None or type(self.target_position) is XrayPositionView)
            or (self.target_position is not None) != (self.target_position_state is TargetPositionState.RESOLVED)
        ):
            raise TypeError("Некорректное описание выбора в объяснении маршрута.")


@dataclass(frozen=True, slots=True)
class RouteExplanationView:
    """Безопасная трасса предварительного расчёта.

    `outcome` различает четыре состояния. `selection=None` при `unknown`
    означает, что первое неизвестное условие не позволило выбрать действие;
    это не отказ сценария и не выбор BLOCK. При `policy_absent` шагов нет:
    схема прочитана, но её политика не собрана, и правила не проверялись.
    `scheme`, `metadata_state` и `metadata_error` есть только для политики
    из импортированной схемы.
    """

    preliminary: bool
    domain_source: str
    ip_source: str
    ip_count: int | None
    assumptions: tuple[str, ...]
    steps: tuple[RouteStepView, ...]
    selection: RouteSelectionView | None
    outcome: RouteOutcome
    scheme: RouteSchemeView | None = None
    metadata_state: MetadataState | None = None
    metadata_error: ErrorDetail | None = None

    def __post_init__(self) -> None:
        selection = self.selection
        expected = (
            RouteOutcome.POLICY_ABSENT if self.scheme is not None and not self.scheme.policy_present
            else RouteOutcome.UNKNOWN if selection is None
            else RouteOutcome.FINAL if selection.is_final else RouteOutcome.RULE
        )
        if (
            self.preliminary is not True or type(self.domain_source) is not str or type(self.ip_source) is not str
            or not (self.ip_count is None or (type(self.ip_count) is int and self.ip_count >= 0))
            or type(self.assumptions) is not tuple or any(type(item) is not str for item in self.assumptions)
            or type(self.steps) is not tuple or any(type(item) is not RouteStepView for item in self.steps)
            or not (selection is None or type(selection) is RouteSelectionView)
            or type(self.outcome) is not RouteOutcome or self.outcome is not expected
            or (self.outcome is RouteOutcome.POLICY_ABSENT) != (not self.steps)
            or (self.outcome is RouteOutcome.POLICY_ABSENT and selection is not None)
            or not (self.scheme is None or type(self.scheme) is RouteSchemeView)
            or (self.scheme is None) != (self.metadata_state is None)
            or not (self.metadata_state is None or type(self.metadata_state) is MetadataState)
            or (self.metadata_error is not None) != (self.metadata_state is MetadataState.FAILED)
            or not (self.metadata_error is None or type(self.metadata_error) is ErrorDetail)
        ):
            raise TypeError("Объяснение маршрута не согласовано со своим итогом.")

    @classmethod
    def from_explanation(
        cls, explanation: RouteExplanation, reading: SchemeReading | None = None,
    ) -> "RouteExplanationView":
        """Построить представление из безопасной диагностики расчёта и, при наличии, схемы импорта."""
        diagnostic = explanation.to_diagnostic()
        positions = None if reading is None else _rule_positions(reading)
        steps = tuple(
            RouteStepView(
                reason_code=step.reason.name.lower(), **fields, **_identity(step.rule),
                **_position(positions, step.index, isinstance(step.rule, FinalRoutingRule)),
            )
            for step, fields in zip(explanation.steps, diagnostic["steps"], strict=True)
        )
        selection = explanation.selection
        selected = None
        if selection is not None:
            selected = RouteSelectionView(
                **diagnostic["selection"], **_identity(selection.rule),
                **_position(positions, selection.index, selection.is_final),
                **({} if reading is None else _target(reading, positions, selection.index, selection.is_final)),
            )
        return cls(
            preliminary=diagnostic["preliminary"],
            domain_source=diagnostic["context"]["domain_source"],
            ip_source=diagnostic["context"]["ip_source"],
            ip_count=diagnostic["context"]["ip_count"],
            assumptions=tuple(diagnostic["assumptions"]),
            steps=steps,
            selection=selected,
            outcome=(
                RouteOutcome.UNKNOWN if selection is None
                else RouteOutcome.FINAL if selection.is_final else RouteOutcome.RULE
            ),
            **_scheme_fields(reading),
        )

    @classmethod
    def policy_absent(cls, context: RoutingContext, reading: SchemeReading) -> "RouteExplanationView":
        """Описать прочитанную схему без собранной политики: правила не проверялись."""
        diagnostic = context.to_diagnostic()
        return cls(
            preliminary=True,
            domain_source=diagnostic["domain_source"],
            ip_source=diagnostic["ip_source"],
            ip_count=diagnostic["ip_count"],
            assumptions=context_assumptions(context),
            steps=(),
            selection=None,
            outcome=RouteOutcome.POLICY_ABSENT,
            **_scheme_fields(reading),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        selection = self.selection
        return {
            "preliminary": self.preliminary,
            "domain_source": self.domain_source,
            "ip_source": self.ip_source,
            "ip_count": self.ip_count,
            "assumptions": list(self.assumptions),
            "steps": [view_dict(step) for step in self.steps],
            "selection": None if selection is None else {
                **view_dict(selection),
                "target": None if selection.target is None else {
                    **view_dict(selection.target),
                    "outbound_tags": list(selection.target.outbound_tags),
                    "reasons": list(selection.target.reasons),
                },
                "target_position_state": (
                    None if selection.target_position_state is None else selection.target_position_state.value
                ),
                "target_position": None if selection.target_position is None else view_dict(selection.target_position),
            },
            "outcome": self.outcome.value,
            "scheme": None if self.scheme is None else {**view_dict(self.scheme), "reasons": list(self.scheme.reasons)},
            "metadata_state": None if self.metadata_state is None else self.metadata_state.value,
            "metadata_error": None if self.metadata_error is None else self.metadata_error.to_dict(),
        }


def _identity(rule: object) -> dict[str, object]:
    """Идентификатор и название правила модели; у финального правила их нет."""
    rule_id = getattr(rule, "rule_id", None)
    name = getattr(rule, "name", None)
    return {"has_id": rule_id is not None, "rule_id": rule_id, "has_name": name is not None, "name": name}


def _rule_positions(reading: SchemeReading) -> tuple[tuple[int, int, int | None], ...]:
    """Для каждой позиции политики — порядковый номер группы, индекс правила Xray и позиция в группе.

    Правила политики — правила групп схемы в порядке файла; финальное
    правило занимает позицию после них и относится к финальной группе.
    """
    positions = [
        (number, group.index, offset)
        for number, group in enumerate(reading.scheme.groups) for offset in range(len(group.rules))
    ]
    final = reading.scheme.final_group
    policy = reading.policy
    if policy is None or final is None or len(positions) != len(policy.rules):
        raise TypeError("Политика не соответствует группам схемы.")
    positions.append((len(reading.scheme.groups) - 1, final.index, None))
    return tuple(positions)


def _position(positions: tuple[tuple[int, int, int | None], ...] | None, index: int, final: bool) -> dict[str, object]:
    if positions is None:
        return {}
    _number, group_index, offset = positions[index]
    if final != (offset is None):
        raise TypeError("Финальное правило не совпало с финальной группой схемы.")
    return {"group_index": group_index, "offset": offset}


def _target(
    reading: SchemeReading, positions: tuple[tuple[int, int, int | None], ...], index: int, final: bool,
) -> dict[str, object]:
    """Назначение выбранной группы из представления схемы и его позиция из сводки тех же моделей."""
    number, _group_index, _offset = positions[index]
    group = reading.scheme.groups[number]
    target = RoutingSchemeView.from_scheme(reading.scheme).groups[number].target
    summary_rules = {(rule.part, rule.index): rule for rule in reading.summary.rules}
    state, position = resolve_target_position(summary_rules.get((group.part, group.index)))
    return {"target": target, "target_position_state": state, "target_position": position}


def _scheme_fields(reading: SchemeReading | None) -> dict[str, object]:
    if reading is None:
        return {}
    return {
        "scheme": RouteSchemeView.from_scheme(reading.scheme),
        "metadata_state": reading.metadata_state,
        "metadata_error": reading.metadata_error,
    }


def _well_typed(command: object) -> bool:
    """Проверить типы полей: аннотации dataclass при создании не проверяются.

    Смысл значений (формат домена и IP, сочетание источников, разбор строки
    назначения) проверяет домен, и его отказ относится к invalid_input.
    Строка назначения не сочетается с типизированными предположениями.
    """
    if type(command) is not ExplainRoute:
        return False
    typed = (
        (command.domain is None or isinstance(command.domain, str))
        and isinstance(command.domain_source, DomainSource)
        and (command.ips is None or (
            type(command.ips) is tuple and all(isinstance(value, str) for value in command.ips)
        ))
        and isinstance(command.ip_source, IPSource)
    )
    if command.destination is None:
        return typed
    return (
        type(command.destination) is str and typed
        and command.domain is None and command.domain_source is DomainSource.UNKNOWN
        and command.ips is None and command.ip_source is IPSource.UNKNOWN
    )


class _PortPolicyReader:
    """Политика из порта `RoutingPolicySource`: отказ и неподдерживаемый формат — прежние коды."""

    def __init__(self, policies: RoutingPolicySource) -> None:
        self._policies = policies

    def read(self) -> RoutingPolicy | ErrorDetail:
        try:
            policy = self._policies.current_routing_policy()
        except Exception:
            # Текст и цепочка исключения адаптера могут содержать приватные данные.
            return ErrorDetail(
                ErrorCategory.SOURCE_FAILED, "routing_policy_unavailable",
                "Не удалось получить текущие правила маршрутизации.",
            )
        if not isinstance(policy, RoutingPolicy):
            return ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, "invalid_routing_policy",
                "Источник вернул правила маршрутизации в неподдерживаемом формате.",
            )
        return policy


class _ImportedPolicyReader:
    """Политика импортированной схемы с идентичностью из метаданных тем же чтением, что у списка правил."""

    def __init__(self, routing: ImportRoutingSchemeHandler, store: ManagerMetadataStore | None) -> None:
        if type(routing) is not ImportRoutingSchemeHandler:
            raise TypeError("Объяснение по импорту принимает обработчик импорта схемы.")
        self._routing = routing
        self._store = store

    def read(self) -> SchemeReading | ErrorDetail:
        return read_scheme_identity(self._routing, self._store)


class ExplainRouteHandler:
    """Объяснить маршрут по правилам источника без DNS, Xray и изменений.

    Результат предварительный и не подтверждает реальный путь трафика.
    Конструктор принимает порт правил; `from_import` строит обработчик
    поверх импорта действующей схемы с необязательным хранилищем метаданных.
    """

    def __init__(
        self,
        policies: RoutingPolicySource,
        geodata: GeoDataSource | None = None,
        *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._setup(_PortPolicyReader(policies), geodata, operation_ids)

    @classmethod
    def from_import(
        cls,
        routing: ImportRoutingSchemeHandler,
        store: ManagerMetadataStore | None = None,
        geodata: GeoDataSource | None = None,
        *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> "ExplainRouteHandler":
        """Объяснять маршрут по политике импортированной схемы действующей конфигурации Xray.

        Источники читаются обработчиком конфигурации прокси в его порядке
        и с его кодами, схема строится переводом импорта, названия
        и идентификаторы берутся из хранилища метаданных, если оно передано;
        его отсутствие и отказ — состояния результата. Ничего не записывается.
        """
        handler = cls.__new__(cls)
        handler._setup(_ImportedPolicyReader(routing, store), geodata, operation_ids)
        return handler

    def _setup(self, reader: object, geodata: GeoDataSource | None, operation_ids: OperationIdFactory) -> None:
        self._reader = reader
        self._geodata = geodata
        self._operation_ids = operation_ids

    def execute(self, command: ExplainRoute) -> Result[RouteExplanationView]:
        """Выполнить команду и вернуть результат, не вызывая исключений отказа."""
        operation_id = self._operation_ids()
        name = ExplainRoute.name
        if not _well_typed(command):
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        try:
            if command.destination is not None:
                context = destination_context(command.destination)
            else:
                context = RoutingContext(
                    domain=command.domain, domain_source=command.domain_source,
                    ips=command.ips, ip_source=command.ip_source,
                )
        except RoutingValidationError as invalid:
            return failed(operation_id, name, ErrorDetail(ErrorCategory.INVALID_INPUT, invalid.code.value, str(invalid)))

        # Источник вызывается только для корректного запроса.
        reading = self._reader.read()
        if isinstance(reading, ErrorDetail):
            return failed(operation_id, name, reading)
        scheme_reading = reading if type(reading) is SchemeReading else None
        policy = reading if scheme_reading is None else scheme_reading.policy
        if policy is None:
            try:
                view = RouteExplanationView.policy_absent(context, scheme_reading)
            except TypeError:
                return failed(operation_id, name, _INCONSISTENT)
            return succeeded(operation_id, name, view)

        matcher = None if self._geodata is None else self._geodata.match
        try:
            explanation = explain_route(policy, context, geo_matcher=matcher)
        except RoutingValidationError as invalid:
            category = (
                ErrorCategory.SOURCE_FAILED if invalid.code is RoutingErrorCode.MATCHER
                else ErrorCategory.INVALID_SOURCE_DATA
            )
            return failed(operation_id, name, ErrorDetail(category, invalid.code.value, str(invalid)))
        try:
            view = RouteExplanationView.from_explanation(explanation, scheme_reading)
        except TypeError:
            return failed(operation_id, name, _INCONSISTENT)
        return succeeded(operation_id, name, view)
