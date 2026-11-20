"""Список VPN-подключений и их карточки."""

from keenvpn.application.contract import OperationIdFactory
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.proxy_connections import (
    BalancerConnectionView, ConnectionsView, InspectConnections, InspectConnectionsHandler,
    OutboundConnectionView,
)
from keenvpn.interfaces.cli.bindings import SectionActions
from keenvpn.interfaces.cli.menu import ListEntry, MAX_ITEM_NUMBER, MenuList
from keenvpn.interfaces.cli.presentation import (
    INDENT, xray_position, count, HIDDEN, identifier, known_value, present_result,
)

ACTION_CAPTIONS = {
    "connections.list": "Выходы и балансировщики из конфигурации Xray. Доступны поиск и карточки.",
}


CONNECTIONS_LIST_TITLE = "Подключения"

CONNECTIONS_ITEM_NAME = "Подключение"

SELECTORS_PER_LINE = 10
"""Сколько селекторов балансировщика в строке карточки; селектор после фильтра не длиннее 64 символов."""

CONNECTIONS_NOTE = (
    "Адреса серверов, порты, идентификаторы, пароли, SNI, пути и ссылки не читаются и не показываются; "
    "разбор ссылок не выполняется."
)

CONNECTIONS_HEALTH_NOTE = "Список не подтверждает доступность подключений: это снимок конфигурации на момент чтения."


def _selector(value: object) -> str:
    return "пустой" if value == "" else identifier(value)


def _connection_label(item: object) -> str:
    if type(item) is OutboundConnectionView:
        return (
            f"outbound: тег {known_value(item.tag_known, item.tag, identifier, 'без тега')}, "
            f"протокол {known_value(item.protocol_known, item.protocol, identifier, 'не задан')}, {xray_position(item.position)}"
        )
    if type(item) is BalancerConnectionView:
        return (
            f"балансировщик: тег {known_value(item.tag_known, item.tag, identifier, 'без тега')}, "
            f"селекторов {count(len(item.selector))}, совпадений {count(item.selector_match_count)}, "
            f"fallback {known_value(item.fallback_known, item.fallback_tag, identifier, 'не задан')}, "
            f"стратегия {known_value(item.strategy_known, item.strategy, identifier, 'не задана')}, {xray_position(item.position)}"
        )
    return HIDDEN


def _fallback_position(item: BalancerConnectionView) -> str:
    if item.fallback_known is not True:
        return "не задан"
    if item.fallback_resolved is not True:
        return "не найден"
    return "не определена однозначно" if item.fallback_position is None else xray_position(item.fallback_position)


def _connection_card(item: object) -> tuple[str, ...]:
    if type(item) is OutboundConnectionView:
        return (
            "Вид: outbound",
            f"Позиция: {xray_position(item.position)}",
            f"Тег: {known_value(item.tag_known, item.tag, identifier, 'без тега')}",
            f"Протокол: {known_value(item.protocol_known, item.protocol, identifier, 'не задан')}",
            CONNECTIONS_NOTE,
        )
    if type(item) is BalancerConnectionView:
        selectors = [f"Селекторов: {count(len(item.selector))}; совпадений outbound: {count(item.selector_match_count)}"]
        for start in range(0, len(item.selector), SELECTORS_PER_LINE):
            selectors.append(INDENT + ", ".join(_selector(value) for value in item.selector[start:start + SELECTORS_PER_LINE]))
        return (
            "Вид: балансировщик",
            f"Позиция: {xray_position(item.position)}",
            f"Тег: {known_value(item.tag_known, item.tag, identifier, 'без тега')}",
            *selectors,
            f"Fallback: {known_value(item.fallback_known, item.fallback_tag, identifier, 'не задан')}; "
            f"позиция цели: {_fallback_position(item)}",
            f"Стратегия: {known_value(item.strategy_known, item.strategy, identifier, 'не задана')}",
            CONNECTIONS_NOTE,
        )
    return (HIDDEN,)


def _connection_entry(number: int, item: OutboundConnectionView | BalancerConnectionView) -> ListEntry:
    tag = known_value(item.tag_known, item.tag, identifier, "без тега")
    if type(item) is OutboundConnectionView:
        protocol = known_value(item.protocol_known, item.protocol, identifier, "не задан")
        brief = f"{tag} · {protocol}"
        preview = ("Выход Xray", f"Тег: {tag}", f"Протокол: {protocol}")
    else:
        brief = f"{tag} · балансировщик"
        fallback = known_value(item.fallback_known, item.fallback_tag, identifier, "не задан")
        strategy = known_value(item.strategy_known, item.strategy, identifier, "не задана")
        preview = ("Балансировщик Xray", f"Тег: {tag}", f"Выходов по селекторам: {count(item.selector_match_count)}",
                   f"Запасной выход: {fallback}", f"Стратегия: {strategy}")
    return ListEntry(number, _connection_label(item), _connection_card(item), brief=brief, preview=preview)


def present_connections(view: ConnectionsView) -> MenuList:
    """Показать outbound и балансировщики списком: номер — позиция в списке сценария, начиная с 1.

    Строка списка и карточка собраны из одних отфильтрованных значений;
    адреса, порты, пароли и ссылки в представление не входят.
    """
    if type(view) is not ConnectionsView:
        raise TypeError("Ожидается ConnectionsView.")
    header = [
        "Подключения по конфигурации Xray",
        f"Частей: {count(view.part_count)}; outbound: {count(view.outbound_count)}; "
        f"балансировщиков: {count(view.balancer_count)}",
        f"Повторов тегов outbound: {count(view.duplicate_outbound_tag_count)}; "
        f"повторов тегов балансировщиков: {count(view.duplicate_balancer_tag_count)}; "
        f"скрытых тегов: {count(view.hidden_tag_count)}",
        CONNECTIONS_NOTE,
        CONNECTIONS_HEALTH_NOTE,
    ]
    summary = [f"Выходов: {count(view.outbound_count)} · Балансировщиков: {count(view.balancer_count)}",
               "Доступность по сети не проверялась."]
    items = view.connections[:MAX_ITEM_NUMBER]
    if len(view.connections) > MAX_ITEM_NUMBER:
        header.append(f"Подключений больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.")
        summary.append(header[-1])
    entries = tuple(_connection_entry(number, item) for number, item in enumerate(items, start=1))
    return MenuList(CONNECTIONS_LIST_TITLE, CONNECTIONS_ITEM_NAME, tuple(header), entries,
                    summary=tuple(summary), split_preview=False)


def bind_actions(bindings: SectionActions, proxy: InspectProxyConfigHandler, operation_ids: OperationIdFactory) -> None:
    """Подключить просмотр подключений из действующей конфигурации."""
    connections = InspectConnectionsHandler(proxy, operation_ids=operation_ids)
    bindings["connections.list"] = lambda: present_result(connections.execute(InspectConnections()), present_connections)
