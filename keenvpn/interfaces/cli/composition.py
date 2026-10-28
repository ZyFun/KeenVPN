"""Сборка меню: подключение источников к сценариям application и действиям пунктов.

Единственный модуль интерфейса, которому разрешён импорт конкретных адаптеров.
Сборка по умолчанию не подключает ни одного источника: пункты, сценарию
которых нужен источник, показываются недоступными. Чтение роутера включается
явно (`vpn-menu --read-router`): тогда подключаются источники файлов Xray,
XKeen и геобаз Entware, наблюдения процесса Xray и состояния Keenetic через
локальный RCI. Хранилище метаданных и членство в наборах геобаз в этой версии
не подключаются ни в одном режиме. Объяснение маршрута открывает запрос значения
и передаёт введённую строку сценарию без разбора. Сводка состояния и быстрая проверка допускают
неподключённые источники, поэтому пункты «Сводка» и «Быстрая проверка без изменений» и шапка
главного меню доступны всегда и показывают такие области и проверки «не проверено». Каждое действие выполняет сценарий
заново при каждом выборе пункта и не хранит результаты между выборами: список,
который вернуло действие, существует, пока он открыт, а возврат из карточки
или поиска источники не читает. Шапка выполняет тот же сценарий сводки при
входе в корень главного меню.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from keenvpn.adapters.router_sources import (
    GeoDatabaseFiles, KeeneticHotspotRuntimeRci, KeeneticHotspotSettingsRci, KeeneticPoliciesRci,
    KeeneticRegistrationsRci, XKeenInitFile, XKeenListFiles, XKeenSettingsFile, XrayConfigFiles, XrayProcessObserver,
)
from keenvpn.application.contract import OperationIdFactory, new_operation_id
from keenvpn.application.keenetic_devices import ListKeeneticDevices, ListKeeneticDevicesHandler
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler
from keenvpn.application.manager_metadata import InspectManagerMetadata, InspectManagerMetadataHandler
from keenvpn.application.ports import (
    GeoDatabaseSource, GeoDataSource, KeeneticHotspotRuntimeSource, KeeneticHotspotSettingsSource,
    KeeneticPolicySource, KeeneticRegistrationSource, ManagerMetadataStore, XKeenInitSource, XKeenListSource,
    XKeenSettingsSource, XrayConfigSource, XrayProcessSource,
)
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler
from keenvpn.application.proxy_connections import InspectConnections, InspectConnectionsHandler
from keenvpn.application.quick_check import QuickCheck, QuickCheckHandler
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler
from keenvpn.application.routing_import import ImportRoutingSchemeHandler
from keenvpn.application.routing_rules import ListRoutingRules, ListRoutingRulesHandler
from keenvpn.application.status_summary import InspectStatusSummary, InspectStatusSummaryHandler
from keenvpn.interfaces.cli.menu import Menu, MenuError, UnavailableReason, ValueRequest
from keenvpn.interfaces.cli.presenters import (
    ROUTE_PROMPT, present_about, present_connections, present_device_list, present_manager_metadata, present_port53,
    present_quick_check, present_result, present_route_explanation, present_rule_list, present_status_header,
    present_status_summary,
)
from keenvpn.interfaces.cli.terminal import Action, Header
from keenvpn.interfaces.cli.tree import (
    BOUND_SCENARIOS, BUILTIN_ACTIONS, ActionStates, build_main_menu, build_setup_menu,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class MenuSources:
    """Порты чтения, доступные меню; `None` — источник не подключён.

    Источники только читают. Их подключение не включает запись, установку
    или команды XKeen: меню показывает результат сценария и ничего не меняет.
    """

    policies: KeeneticPolicySource | None = None
    hotspot: KeeneticHotspotSettingsSource | None = None
    registrations: KeeneticRegistrationSource | None = None
    runtime: KeeneticHotspotRuntimeSource | None = None
    xray: XrayConfigSource | None = None
    xkeen_settings: XKeenSettingsSource | None = None
    xkeen_init: XKeenInitSource | None = None
    xkeen_lists: XKeenListSource | None = None
    geodata: GeoDatabaseSource | None = None
    process: XrayProcessSource | None = None
    metadata: ManagerMetadataStore | None = None
    geo_match: GeoDataSource | None = None
    """Источник членства в наборах GeoIP и GeoSite для объяснения маршрута; без него условия геобаз «неизвестны»."""

    @property
    def keenetic_connected(self) -> bool:
        """Подключены ли все четыре источника состояния Keenetic."""
        return None not in (self.policies, self.hotspot, self.registrations, self.runtime)

    @property
    def proxy_connected(self) -> bool:
        """Подключены ли все четыре источника конфигурации Xray и XKeen."""
        return None not in (self.xray, self.xkeen_settings, self.xkeen_init, self.xkeen_lists)


@dataclass(frozen=True, slots=True)
class MenuAssembly:
    """Собранное меню, обработчики его доступных действий и шапка корня; у меню мастера шапки нет."""

    menu: Menu
    actions: Mapping[str, Action]
    header: Header | None = None


def default_sources() -> MenuSources:
    """Источники запуска без явного включения чтения роутера: ничего не подключено ни на какой платформе."""
    return MenuSources()


def router_sources() -> MenuSources:
    """Источники запуска с флагом `--read-router`: файлы Entware, процесс Xray и локальный RCI проверенной платформы.

    Источники только читают. Хранилище метаданных и членство в наборах геобаз
    не подключаются: зависящие от них пункты остаются с пометкой, а правила
    показываются без названий и идентификаторов. Создание источников ничего
    не читает: файлы, процесс и RCI читаются при выполнении сценария.
    """
    return MenuSources(
        policies=KeeneticPoliciesRci(), hotspot=KeeneticHotspotSettingsRci(), registrations=KeeneticRegistrationsRci(),
        runtime=KeeneticHotspotRuntimeRci(), xray=XrayConfigFiles(), xkeen_settings=XKeenSettingsFile(),
        xkeen_init=XKeenInitFile(), xkeen_lists=XKeenListFiles(), geodata=GeoDatabaseFiles(),
        process=XrayProcessObserver(),
    )


def _bindings(
    sources: MenuSources, operation_ids: OperationIdFactory,
) -> tuple[ActionStates, dict[str, Action], Header]:
    """Решить для каждой привязки, доступна ли она, и собрать её действие и шапку корня."""
    if type(sources) is not MenuSources:
        raise MenuError("Источники меню задаются объектом MenuSources.")
    keenetic = None
    if sources.keenetic_connected:
        keenetic = InspectKeeneticStateHandler(
            sources.policies, sources.hotspot, sources.registrations, sources.runtime, operation_ids=operation_ids,
        )
    proxy = None
    if sources.proxy_connected:
        proxy = InspectProxyConfigHandler(
            sources.xray, sources.xkeen_settings, sources.xkeen_init, sources.xkeen_lists, operation_ids=operation_ids,
        )

    states: dict[str, UnavailableReason | None] = {
        action_id: UnavailableReason.SOURCE_NOT_CONNECTED for action_id in BOUND_SCENARIOS
    }
    actions: dict[str, Action] = {}

    def bind(action_id: str, action: Action) -> None:
        states[action_id] = None
        actions[action_id] = action

    # Сводка допускает неподключённые источники: пункт и шапка — один сценарий, который читает то, что подключено.
    summary = InspectStatusSummaryHandler(proxy, sources.process, operation_ids=operation_ids)
    bind("status.summary", lambda: present_result(summary.execute(InspectStatusSummary()), present_status_summary))

    def header() -> list[str]:
        return present_result(summary.execute(InspectStatusSummary()), present_status_header)

    # Быстрая проверка читает те же источники теми же функциями, что сводка, и дополнительно инвентарь геобаз.
    quick_check = QuickCheckHandler(proxy, sources.process, sources.geodata, operation_ids=operation_ids)
    bind("status.quick_check", lambda: present_result(quick_check.execute(QuickCheck()), present_quick_check))

    if proxy is not None:
        connections = InspectConnectionsHandler(proxy, operation_ids=operation_ids)
        bind("connections.list", lambda: present_result(connections.execute(InspectConnections()), present_connections))
        # Список правил и объяснение маршрута допускают неподключённое хранилище метаданных: тогда они показываются
        # без названий и идентификаторов. Объяснение читает ту же схему тем же обработчиком импорта.
        routing = ImportRoutingSchemeHandler(proxy, operation_ids=operation_ids)
        rules = ListRoutingRulesHandler(routing, sources.metadata, operation_ids=operation_ids)
        bind("routing.list", lambda: present_result(rules.execute(ListRoutingRules()), present_rule_list))
        explain = ExplainRouteHandler.from_import(routing, sources.metadata, sources.geo_match, operation_ids=operation_ids)

        def explain_route(value: str) -> list[str]:
            # Строка передаётся сценарию как есть: домен, адрес и их сочетание разбирает домен, меню не разбирает.
            return present_result(explain.execute(ExplainRoute(destination=value)), present_route_explanation)

        bind("routing.explain", lambda: ValueRequest(ROUTE_PROMPT, explain_route))
        bind("failsafe.port53_check", lambda: present_result(proxy.execute(InspectProxyConfig()), present_port53))
    if keenetic is not None:
        # Список устройств читает те же четыре источника тем же обработчиком состояния Keenetic.
        devices = ListKeeneticDevicesHandler(keenetic, operation_ids=operation_ids)
        bind("devices.list", lambda: present_result(devices.execute(ListKeeneticDevices()), present_device_list))
    if sources.metadata is not None:
        metadata = InspectManagerMetadataHandler(sources.metadata, operation_ids=operation_ids)
        bind(
            "settings.storage",
            lambda: present_result(metadata.execute(InspectManagerMetadata()), present_manager_metadata),
        )
    for action_id in BUILTIN_ACTIONS:
        bind(action_id, present_about)
    return states, actions, header


def assemble_main_menu(
    sources: MenuSources | None = None, *, operation_ids: OperationIdFactory = new_operation_id,
) -> MenuAssembly:
    """Собрать главное меню `vpn-menu` с шапкой сводки состояния для переданных источников."""
    states, actions, header = _bindings(default_sources() if sources is None else sources, operation_ids)
    return MenuAssembly(build_main_menu(states), MappingProxyType(actions), header)


def assemble_setup_menu(
    sources: MenuSources | None = None, *, operation_ids: OperationIdFactory = new_operation_id,
) -> MenuAssembly:
    """Собрать корневое меню `vpn-setup`: пункты мастера без шапки; действий мастера в этой версии нет."""
    states, actions, _header = _bindings(default_sources() if sources is None else sources, operation_ids)
    return MenuAssembly(build_setup_menu(states), MappingProxyType(actions))
