"""Сборка меню: подключение источников к сценариям application и действиям пунктов.

Единственный модуль интерфейса, которому разрешён импорт конкретных адаптеров.
Сборка по умолчанию не подключает ни одного источника: пункты, сценарию
которых нужен источник, показываются недоступными. Чтение роутера включается
при запуске `vpn-menu --read-router`, `vpn-menu --apply-draft` или `vpn-setup`: подключаются источники файлов Xray,
XKeen и геобаз Entware, наблюдения процесса Xray и состояния Keenetic через
локальный RCI. Черновик и метаданные подключаются только по подтверждённой
роли data; отказ подключения показывается без путей и UUID. Отмена требует явно
подключённого порта удаления, которого нет в режиме чтения. Членство в наборах
геобаз не подключается. Объяснение маршрута открывает запрос значения
и передаёт введённую строку сценарию без разбора. Сводка состояния и быстрая проверка допускают
неподключённые источники, поэтому пункты «Сводка» и «Быстрая проверка без изменений» и шапка
главного меню доступны всегда и показывают такие области и проверки «не проверено». Каждое действие выполняет сценарий
заново при каждом выборе пункта и не хранит результаты между выборами: список,
который вернуло действие, существует, пока он открыт, а возврат из карточки
или поиска источники не читает. Шапка выполняет тот же сценарий сводки при
входе в корень главного меню. Выход из корня обоих меню, пункт 7 → 4 и конец ввода
выполняют сценарий решения о выходе: при неприменённом черновике или отказе
его хранилища меню спрашивает, остаться ли или выйти, сохранив черновик.
"""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType

from keenvpn.adapters.geo_category_files import GeoCategoryFiles
from keenvpn.adapters.router_sources import (
    GeoCandidateFiles, GeoDatabaseFiles, KeeneticHotspotRuntimeRci, KeeneticHotspotSettingsRci, KeeneticPoliciesRci,
    KeeneticRegistrationsRci, XKeenInitFile, XKeenListFiles, XKeenSettingsFile, XrayConfigFiles, XrayProcessObserver,
    SourceFingerprints,
)
from keenvpn.adapters.router_manager_files import connect_router_draft_apply, connect_router_manager_files
from keenvpn.adapters.storage_placement_files import StoragePlacementFiles
from keenvpn.application.contract import ErrorDetail, OperationIdFactory, new_operation_id
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.saved_draft_apply import ApplySavedDraftHandler
from keenvpn.interfaces.cli.bindings import MenuSources, SectionActions
from keenvpn.interfaces.cli.menu import Menu, MenuError, UnavailableReason
from keenvpn.interfaces.cli.sections import connections, devices, draft, failsafe, routing, settings, status
from keenvpn.interfaces.cli.terminal import Action, ExitCheck, Header
from keenvpn.interfaces.cli.tree import BOUND_SCENARIOS, ActionStates, build_main_menu, build_setup_menu


@dataclass(frozen=True, slots=True)
class MenuAssembly:
    """Собранное меню, обработчики его доступных действий, шапка корня и проверка выхода; у меню мастера шапки нет."""

    menu: Menu
    actions: Mapping[str, Action]
    header: Header | None = None
    exit_check: ExitCheck | None = None


def default_sources() -> MenuSources:
    """Источники запуска без явного включения чтения роутера: ничего не подключено ни на какой платформе."""
    return MenuSources()


def router_sources(*, apply_draft: bool = False) -> MenuSources:
    """Источники роутера. Запись подключается только для явно запрошенного режима.

    Подключаются файлы Entware, процесс Xray и локальный RCI.
    При сборке читается размещение DATA для подключения приватных файлов.
    При отказе оба хранилища остаются неподключёнными с безопасной причиной.
    Остальные источники читаются при выполнении сценария. Членство в наборах
    геобаз не подключается. При сборке записей, создания каталогов и импорта
    нет. Проверочный процесс запускается при проверке кандидата из 7 → 2 или 7 → 3.
    """
    placement = StoragePlacementFiles()
    stores = connect_router_manager_files(placement)
    # Необязательные зависимости runner не должны ломать остальные пункты
    # меню. Проверки платформы и полномочий выполняет сам порт перед запуском.
    try:
        from keenvpn.adapters.xray_isolated_port import IsolatedInstalledXray
    except ImportError:
        tester = None
    else:
        tester = IsolatedInstalledXray()
    sources = MenuSources(
        policies=KeeneticPoliciesRci(), hotspot=KeeneticHotspotSettingsRci(), registrations=KeeneticRegistrationsRci(),
        runtime=KeeneticHotspotRuntimeRci(), xray=XrayConfigFiles(), xkeen_settings=XKeenSettingsFile(),
        xkeen_init=XKeenInitFile(), xkeen_lists=XKeenListFiles(), geodata=GeoDatabaseFiles(),
        process=XrayProcessObserver(),
        drafts=stores.drafts, metadata=stores.metadata, storage_error=stores.error,
        fingerprints=SourceFingerprints(), candidate_assets=GeoCandidateFiles(), installed_xray=tester,
    )
    if not apply_draft or stores.error is not None:
        return sources
    if tester is None or not tester.coordinator_available():
        return replace(sources, draft_apply_unavailable=UnavailableReason.DRAFT_APPLY_XRAY_UNAVAILABLE)
    ports = connect_router_draft_apply(placement)
    if isinstance(ports, ErrorDetail):
        reason = (UnavailableReason.DRAFT_APPLY_PERMISSIONS if ports.code == "draft_apply_permissions"
                  else UnavailableReason.STORAGE_NOT_CONFIRMED)
        return replace(sources, draft_apply_unavailable=reason)
    catalogs = GeoCategoryFiles(sources.candidate_assets)
    apply = ApplySavedDraftHandler(
        ports.drafts, ports.drafts, ports.files, ports.backup, ports.journal, tester=tester,
        readiness=ports.readiness, geodata=sources.geodata, assets=sources.candidate_assets, catalogs=catalogs,
    )
    return replace(sources, drafts=ports.drafts, draft_apply=apply, geo_catalogs=catalogs)


def _bindings(
    sources: MenuSources, operation_ids: OperationIdFactory,
) -> tuple[ActionStates, dict[str, Action], Header, ExitCheck]:
    """Решить для каждой привязки, доступна ли она, и собрать её действие, шапку корня и проверку выхода."""
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

    bindings: SectionActions = dict.fromkeys(BOUND_SCENARIOS, UnavailableReason.SOURCE_NOT_CONNECTED)
    storage_notice = [] if sources.storage_error is None else [
        "Хранилища не подключены: " + sources.storage_error.message,
    ]
    header = status.bind_actions(bindings, proxy, sources, operation_ids, storage_notice)
    if proxy is not None:
        connections.bind_actions(bindings, proxy, operation_ids)
        routing.bind_actions(bindings, proxy, sources.metadata, sources.geo_match, operation_ids)
        failsafe.bind_actions(bindings, proxy)
    if keenetic is not None:
        devices.bind_actions(bindings, keenetic, operation_ids)
    exit_check = draft.bind_actions(bindings, sources, operation_ids, storage_notice)
    settings.bind_actions(bindings, sources, operation_ids)

    states = {key: value if isinstance(value, UnavailableReason) else None for key, value in bindings.items()}
    actions = {key: value for key, value in bindings.items() if callable(value)}
    return states, actions, header, exit_check


def assemble_main_menu(
    sources: MenuSources | None = None, *, operation_ids: OperationIdFactory = new_operation_id,
) -> MenuAssembly:
    """Собрать главное меню `vpn-menu` с шапкой сводки состояния и проверкой выхода для переданных источников."""
    states, actions, header, exit_check = _bindings(default_sources() if sources is None else sources, operation_ids)
    return MenuAssembly(build_main_menu(states), MappingProxyType(actions), header, exit_check)


def assemble_setup_menu(
    sources: MenuSources | None = None, *, operation_ids: OperationIdFactory = new_operation_id,
) -> MenuAssembly:
    """Собрать корневое меню `vpn-setup`: пункты мастера без шапки и проверка выхода; действий мастера нет."""
    states, actions, _header, exit_check = _bindings(
        default_sources() if sources is None else sources, operation_ids,
    )
    return MenuAssembly(build_setup_menu(states), MappingProxyType(actions), exit_check=exit_check)
