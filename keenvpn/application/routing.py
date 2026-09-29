"""Сценарий статического объяснения маршрута по действующим правилам."""

from dataclasses import dataclass
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import GeoDataSource, RoutingPolicySource
from keenvpn.domain.routing import RoutingErrorCode, RoutingValidationError
from keenvpn.domain.routing_explanation import (
    DomainSource, IPSource, RouteExplanation, RoutingContext, explain_route,
)
from keenvpn.domain.routing_policy import RoutingPolicy


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class ExplainRoute:
    """Предположения о назначении; значения считаются приватными данными."""

    name: ClassVar[str] = "explain_route"

    domain: str | None = None
    domain_source: DomainSource = DomainSource.UNKNOWN
    ips: tuple[str, ...] | None = None
    ip_source: IPSource = IPSource.UNKNOWN
    contract_version: int = CONTRACT_VERSION

    def __repr__(self) -> str:
        return "ExplainRoute(<скрытые параметры>)"


@dataclass(frozen=True, slots=True)
class RouteStepView:
    """Шаг объяснения без значений условий, ссылок и версий баз."""

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


@dataclass(frozen=True, slots=True)
class RouteSelectionView:
    """Выбранная позиция и действие."""

    index: int
    action: str
    is_final: bool


@dataclass(frozen=True, slots=True)
class RouteExplanationView:
    """Безопасная трасса предварительного расчёта.

    selection=None означает, что первое неизвестное условие не позволило
    выбрать действие; это не отказ сценария и не выбор BLOCK.
    """

    preliminary: bool
    domain_source: str
    ip_source: str
    ip_count: int | None
    assumptions: tuple[str, ...]
    steps: tuple[RouteStepView, ...]
    selection: RouteSelectionView | None

    @classmethod
    def from_explanation(cls, explanation: RouteExplanation) -> "RouteExplanationView":
        """Построить представление из безопасной диагностики расчёта."""
        diagnostic = explanation.to_diagnostic()
        steps = tuple(
            RouteStepView(reason_code=step.reason.name.lower(), **fields)
            for step, fields in zip(explanation.steps, diagnostic["steps"], strict=True)
        )
        selection = diagnostic["selection"]
        return cls(
            preliminary=diagnostic["preliminary"],
            domain_source=diagnostic["context"]["domain_source"],
            ip_source=diagnostic["context"]["ip_source"],
            ip_count=diagnostic["context"]["ip_count"],
            assumptions=tuple(diagnostic["assumptions"]),
            steps=steps,
            selection=None if selection is None else RouteSelectionView(**selection),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "preliminary": self.preliminary,
            "domain_source": self.domain_source,
            "ip_source": self.ip_source,
            "ip_count": self.ip_count,
            "assumptions": list(self.assumptions),
            "steps": [
                {name: getattr(step, name) for name in RouteStepView.__dataclass_fields__}
                for step in self.steps
            ],
            "selection": None if self.selection is None else {
                name: getattr(self.selection, name) for name in RouteSelectionView.__dataclass_fields__
            },
        }


class ExplainRouteHandler:
    """Объяснить маршрут по правилам источника без DNS, Xray и изменений.

    Результат предварительный и не подтверждает реальный путь трафика.
    """

    def __init__(
        self,
        policies: RoutingPolicySource,
        geodata: GeoDataSource | None = None,
        *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._policies = policies
        self._geodata = geodata
        self._operation_ids = operation_ids

    def execute(self, command: ExplainRoute) -> Result[RouteExplanationView]:
        """Выполнить команду и вернуть результат, не вызывая исключений отказа."""
        operation_id = self._operation_ids()
        name = ExplainRoute.name
        if type(command) is not ExplainRoute:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        try:
            context = RoutingContext(
                domain=command.domain, domain_source=command.domain_source,
                ips=command.ips, ip_source=command.ip_source,
            )
        except RoutingValidationError as invalid:
            return failed(operation_id, name, ErrorDetail(ErrorCategory.INVALID_INPUT, invalid.code.value, str(invalid)))

        # Источник вызывается только для корректного запроса.
        try:
            policy = self._policies.current_routing_policy()
        except Exception:
            # Текст и цепочка исключения адаптера могут содержать приватные данные.
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.SOURCE_FAILED, "routing_policy_unavailable",
                "Не удалось получить текущие правила маршрутизации.",
            ))
        if not isinstance(policy, RoutingPolicy):
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, "invalid_routing_policy",
                "Источник вернул правила маршрутизации в неподдерживаемом формате.",
            ))

        matcher = None if self._geodata is None else self._geodata.match
        try:
            explanation = explain_route(policy, context, geo_matcher=matcher)
        except RoutingValidationError as invalid:
            category = (
                ErrorCategory.SOURCE_FAILED if invalid.code is RoutingErrorCode.MATCHER
                else ErrorCategory.INVALID_SOURCE_DATA
            )
            return failed(operation_id, name, ErrorDetail(category, invalid.code.value, str(invalid)))
        return succeeded(operation_id, name, RouteExplanationView.from_explanation(explanation))
