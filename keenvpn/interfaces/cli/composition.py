"""Сборка меню: подключение источников к сценариям application и действиям пунктов.

Единственный модуль интерфейса, которому разрешён импорт конкретных адаптеров.
Транспорта чтения роутера в этой версии нет, поэтому сборка по умолчанию
не подключает ни одного источника: пункты с привязанным сценарием показываются
недоступными, доступна только справка. Каждое действие выполняет сценарий
заново при каждом выборе пункта и не хранит результаты между выборами: список,
который вернуло действие, существует, пока он открыт, а возврат из карточки
или поиска источники не читает.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from keenvpn.application.contract import OperationIdFactory, new_operation_id
from keenvpn.application.installation import InspectInstallation, InspectInstallationHandler
from keenvpn.application.keenetic_state import InspectKeeneticState, InspectKeeneticStateHandler
from keenvpn.application.manager_metadata import InspectManagerMetadata, InspectManagerMetadataHandler
from keenvpn.application.ports import (
    GeoDatabaseSource, KeeneticHotspotRuntimeSource, KeeneticHotspotSettingsSource, KeeneticPolicySource,
    KeeneticRegistrationSource, ManagerMetadataStore, XKeenInitSource, XKeenListSource, XKeenSettingsSource,
    XrayConfigSource, XrayProcessSource,
)
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler
from keenvpn.application.routing_import import ImportRoutingScheme, ImportRoutingSchemeHandler
from keenvpn.interfaces.cli.menu import Menu, MenuError, UnavailableReason
from keenvpn.interfaces.cli.presenters import (
    present_about, present_installation, present_keenetic_state, present_manager_metadata, present_port53,
    present_result, present_routing_scheme,
)
from keenvpn.interfaces.cli.terminal import Action
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
    """Собранное меню и обработчики его доступных действий."""

    menu: Menu
    actions: Mapping[str, Action]


def default_sources() -> MenuSources:
    """Источники запуска на этой версии: транспорта чтения роутера нет, ничего не подключено."""
    return MenuSources()


def _bindings(sources: MenuSources, operation_ids: OperationIdFactory) -> tuple[ActionStates, dict[str, Action]]:
    """Решить для каждой привязки, доступна ли она, и собрать её действие."""
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

    if keenetic is not None and proxy is not None and sources.geodata is not None and sources.process is not None:
        installation = InspectInstallationHandler(
            keenetic, proxy, sources.geodata, sources.process, operation_ids=operation_ids,
        )
        bind("status.summary", lambda: present_result(installation.execute(InspectInstallation()), present_installation))
    if proxy is not None:
        routing = ImportRoutingSchemeHandler(proxy, operation_ids=operation_ids)
        bind("routing.list", lambda: present_result(routing.execute(ImportRoutingScheme()), present_routing_scheme))
        bind("failsafe.port53_check", lambda: present_result(proxy.execute(InspectProxyConfig()), present_port53))
    if keenetic is not None:
        bind("devices.list", lambda: present_result(keenetic.execute(InspectKeeneticState()), present_keenetic_state))
    if sources.metadata is not None:
        metadata = InspectManagerMetadataHandler(sources.metadata, operation_ids=operation_ids)
        bind(
            "settings.storage",
            lambda: present_result(metadata.execute(InspectManagerMetadata()), present_manager_metadata),
        )
    # Объяснение маршрута требует ввода домена или адреса, которого это меню не принимает.
    states["routing.explain"] = UnavailableReason.INPUT_REQUIRED
    for action_id in BUILTIN_ACTIONS:
        bind(action_id, present_about)
    return states, actions


def assemble_main_menu(
    sources: MenuSources | None = None, *, operation_ids: OperationIdFactory = new_operation_id,
) -> MenuAssembly:
    """Собрать главное меню `vpn-menu` для переданных источников."""
    states, actions = _bindings(default_sources() if sources is None else sources, operation_ids)
    return MenuAssembly(build_main_menu(states), MappingProxyType(actions))


def assemble_setup_menu(
    sources: MenuSources | None = None, *, operation_ids: OperationIdFactory = new_operation_id,
) -> MenuAssembly:
    """Собрать корневое меню `vpn-setup`: пункты мастера; действий мастера в этой версии нет."""
    states, actions = _bindings(default_sources() if sources is None else sources, operation_ids)
    return MenuAssembly(build_setup_menu(states), MappingProxyType(actions))
