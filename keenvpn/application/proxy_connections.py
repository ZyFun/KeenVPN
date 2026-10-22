"""Список подключений: outbound и балансировщики Xray из безопасной сводки конфигурации прокси.

Сценарий читает источники обработчиком `InspectProxyConfig` в его порядке
и с его кодами отказов и собирает один список: все outbound в порядке частей
и индексов структурной сводки, затем все балансировщики. Элемент описан
позицией, тегом после проверки формата и известным протоколом либо полями
балансировщика: селекторами, числом совпадений, `fallbackTag` с позицией
цели и стратегией. Адреса серверов, порты, идентификаторы, пароли, SNI,
пути и ссылки не читаются, разбор ссылок не выполняется, поля настроек
outbound не учитываются даже по именам. Вид действия outbound (прямой выход,
блокировка, VPN) не выводится: по одному протоколу без разрешателя импорта
правил его нельзя определить безопасно. Список не подтверждает доступность
подключений: это снимок конфигурации на момент чтения.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorDetail, OperationIdFactory, Result, check_contract_version, failed, invalid_command,
    new_operation_id, succeeded,
)
from keenvpn.application.proxy_config import (
    InspectProxyConfigHandler, XrayBalancerView, XrayConfigView, XrayEndpointView, XrayPositionView,
)
from keenvpn.application.views import view_dict


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectConnections:
    """Показать outbound и балансировщики Xray списком без секретов и без разбора ссылок."""

    name: ClassVar[str] = "inspect_connections"

    contract_version: int = CONTRACT_VERSION


class ConnectionKind(StrEnum):
    """Вид элемента списка подключений."""

    OUTBOUND = "outbound"
    BALANCER = "balancer"


def _optional_str(value: object) -> bool:
    return value is None or type(value) is str


def _known_pair(known: object, value: object) -> bool:
    """Признак и значение согласованы: без признака значения нет; со признаком оно строка либо скрыто."""
    return type(known) is bool and _optional_str(value) and (known or value is None)


def _position_dict(value: XrayPositionView | None) -> dict[str, object] | None:
    return None if value is None else view_dict(value)


@dataclass(frozen=True, slots=True)
class OutboundConnectionView:
    """Outbound: позиция, тег после проверки формата и известный протокол.

    `tag` и `protocol` — `None`, если поля нет или значение скрыто как
    небезопасное либо неизвестное; `tag_known` и `protocol_known` различают
    эти случаи. Два outbound со скрытыми тегами различаются только позицией.
    """

    kind: ClassVar[ConnectionKind] = ConnectionKind.OUTBOUND

    position: XrayPositionView
    tag_known: bool
    tag: str | None
    protocol_known: bool
    protocol: str | None

    def __post_init__(self) -> None:
        if (
            type(self.position) is not XrayPositionView
            or not _known_pair(self.tag_known, self.tag)
            or not _known_pair(self.protocol_known, self.protocol)
        ):
            raise TypeError("Некорректное описание outbound в списке подключений.")

    @classmethod
    def from_endpoint(cls, item: XrayEndpointView) -> "OutboundConnectionView":
        """Построить элемент из outbound структурной сводки."""
        if type(item) is not XrayEndpointView:
            raise TypeError("Ожидается XrayEndpointView.")
        return cls(XrayPositionView(item.part, item.index), item.tag_known, item.tag, item.protocol_known, item.protocol)

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление с видом элемента."""
        return {**view_dict(self), "kind": self.kind.value, "position": view_dict(self.position)}


@dataclass(frozen=True, slots=True)
class BalancerConnectionView:
    """Балансировщик: позиция, тег, селекторы, `fallbackTag` с позицией цели и известная стратегия.

    Скрытый селектор — `None` на своей позиции, пустой остаётся `""`.
    `fallback_position` указан, только если цель однозначна среди всех частей.
    """

    kind: ClassVar[ConnectionKind] = ConnectionKind.BALANCER

    position: XrayPositionView
    tag_known: bool
    tag: str | None
    selector: tuple[str | None, ...]
    selector_match_count: int
    fallback_known: bool
    fallback_tag: str | None
    fallback_resolved: bool | None
    fallback_position: XrayPositionView | None
    strategy_known: bool
    strategy: str | None

    def __post_init__(self) -> None:
        if (
            type(self.position) is not XrayPositionView
            or not _known_pair(self.tag_known, self.tag)
            or type(self.selector) is not tuple or not all(_optional_str(item) for item in self.selector)
            or type(self.selector_match_count) is not int or self.selector_match_count < 0
            or not _known_pair(self.fallback_known, self.fallback_tag)
            or not (self.fallback_resolved is None or type(self.fallback_resolved) is bool)
            or (self.fallback_resolved is None) != (not self.fallback_known)
            or not (self.fallback_position is None or type(self.fallback_position) is XrayPositionView)
            or (self.fallback_position is not None and self.fallback_resolved is not True)
            or not _known_pair(self.strategy_known, self.strategy)
        ):
            raise TypeError("Некорректное описание балансировщика в списке подключений.")

    @classmethod
    def from_balancer(cls, item: XrayBalancerView) -> "BalancerConnectionView":
        """Построить элемент из балансировщика структурной сводки."""
        if type(item) is not XrayBalancerView:
            raise TypeError("Ожидается XrayBalancerView.")
        return cls(
            XrayPositionView(item.part, item.index), item.tag_known, item.tag, item.selector, item.selector_match_count,
            item.fallback_known, item.fallback_tag, item.fallback_resolved, item.fallback_position,
            item.strategy_known, item.strategy,
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление с видом элемента."""
        return {
            **view_dict(self),
            "kind": self.kind.value,
            "position": view_dict(self.position),
            "selector": list(self.selector),
            "fallback_position": _position_dict(self.fallback_position),
        }


ConnectionView = OutboundConnectionView | BalancerConnectionView
"""Элемент списка подключений."""


def _hidden(item: ConnectionView) -> bool:
    return item.tag_known and item.tag is None


@dataclass(frozen=True, slots=True)
class ConnectionsView:
    """Список подключений и счётчики без доменов, адресов, портов, путей и паролей.

    `connections` — все outbound в порядке частей и индексов сводки, затем все
    балансировщики; номер элемента в интерфейсе — его позиция в этом кортеже.
    `hidden_tag_count` — число элементов, чей тег задан, но скрыт как
    небезопасный; повторы тегов считаются по исходным значениям в сводке.
    """

    part_count: int
    outbound_count: int
    balancer_count: int
    duplicate_outbound_tag_count: int
    duplicate_balancer_tag_count: int
    hidden_tag_count: int
    connections: tuple[ConnectionView, ...]

    def __post_init__(self) -> None:
        counts = (
            self.part_count, self.outbound_count, self.balancer_count, self.duplicate_outbound_tag_count,
            self.duplicate_balancer_tag_count, self.hidden_tag_count,
        )
        if any(type(value) is not int or value < 0 for value in counts) or type(self.connections) is not tuple:
            raise TypeError("Некорректные счётчики списка подключений.")
        kinds = [type(item) for item in self.connections]
        expected = [OutboundConnectionView] * self.outbound_count + [BalancerConnectionView] * self.balancer_count
        if kinds != expected or sum(_hidden(item) for item in self.connections) != self.hidden_tag_count:
            raise TypeError("Список подключений не согласован со счётчиками: сначала outbound, затем балансировщики.")

    @classmethod
    def from_config(cls, view: XrayConfigView) -> "ConnectionsView":
        """Построить список из безопасной сводки конфигурации Xray."""
        if type(view) is not XrayConfigView:
            raise TypeError("Ожидается XrayConfigView.")
        connections: tuple[ConnectionView, ...] = (
            *(OutboundConnectionView.from_endpoint(item) for item in view.outbounds),
            *(BalancerConnectionView.from_balancer(item) for item in view.balancers),
        )
        return cls(
            part_count=view.part_count,
            outbound_count=len(view.outbounds),
            balancer_count=len(view.balancers),
            duplicate_outbound_tag_count=len(view.duplicate_outbound_tags),
            duplicate_balancer_tag_count=len(view.duplicate_balancer_tags),
            hidden_tag_count=sum(_hidden(item) for item in connections),
            connections=connections,
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {**view_dict(self), "connections": [item.to_dict() for item in self.connections]}


class InspectConnectionsHandler:
    """Прочитать конфигурацию прокси её обработчиком и показать outbound и балансировщики списком.

    Источники читаются обработчиком `InspectProxyConfig` в его порядке и с его
    кодами отказов; отказ любого источника завершает сценарий без частичного
    результата. Ничего не записывается; успех не подтверждает доступность
    подключений, работу Xray, XKeen или VPN.
    """

    def __init__(
        self, proxy: InspectProxyConfigHandler, *, operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._proxy = proxy
        self._operation_ids = operation_ids

    def execute(self, command: InspectConnections) -> Result[ConnectionsView]:
        """Выполнить чтение; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = InspectConnections.name
        if type(command) is not InspectConnections:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        models = self._proxy.read()
        if isinstance(models, ErrorDetail):
            return failed(operation_id, name, models)
        return succeeded(operation_id, name, ConnectionsView.from_config(XrayConfigView.from_config(models.xray)))
