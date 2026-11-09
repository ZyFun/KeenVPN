"""Сборка меню: подключение источников к сценариям application и действиям пунктов.

Единственный модуль интерфейса, которому разрешён импорт конкретных адаптеров.
Сборка по умолчанию не подключает ни одного источника: пункты, сценарию
которых нужен источник, показываются недоступными. Чтение роутера включается
при запуске `vpn-menu --read-router` или `vpn-setup`: подключаются источники файлов Xray,
XKeen и геобаз Entware, наблюдения процесса Xray и состояния Keenetic через
локальный RCI. Черновик и метаданные подключаются только по подтверждённой
роли data; отказ подключения показывается без путей и UUID. Членство в наборах
геобаз не подключается. Объяснение маршрута открывает запрос значения
и передаёт введённую строку сценарию без разбора. Сводка состояния и быстрая проверка допускают
неподключённые источники, поэтому пункты «Сводка» и «Быстрая проверка без изменений» и шапка
главного меню доступны всегда и показывают такие области и проверки «не проверено». Каждое действие выполняет сценарий
заново при каждом выборе пункта и не хранит результаты между выборами: список,
который вернуло действие, существует, пока он открыт, а возврат из карточки
или поиска источники не читает. Шапка выполняет тот же сценарий сводки при
входе в корень главного меню. Выход из корня обоих меню и конец ввода
выполняют сценарий решения о выходе: при неприменённом черновике или отказе
его хранилища меню спрашивает, остаться ли или выйти, сохранив черновик.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from keenvpn.adapters.router_sources import (
    GeoCandidateFiles, GeoDatabaseFiles, KeeneticHotspotRuntimeRci, KeeneticHotspotSettingsRci, KeeneticPoliciesRci,
    KeeneticRegistrationsRci, XKeenInitFile, XKeenListFiles, XKeenSettingsFile, XrayConfigFiles, XrayProcessObserver,
    SourceFingerprints,
)
from keenvpn.adapters.router_manager_files import connect_router_manager_files
from keenvpn.adapters.storage_placement_files import StoragePlacementFiles
from keenvpn.application.contract import ErrorDetail, OperationIdFactory, new_operation_id
from keenvpn.application.draft_session import InspectDraft, InspectDraftHandler
from keenvpn.application.keenetic_devices import ListKeeneticDevices, ListKeeneticDevicesHandler
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler
from keenvpn.application.manager_metadata import InspectManagerMetadata, InspectManagerMetadataHandler
from keenvpn.application.menu_exit import InspectMenuExit, InspectMenuExitHandler
from keenvpn.application.ports import (
    DraftSessionStore, GeoDatabaseSource, GeoDataSource, KeeneticHotspotRuntimeSource, KeeneticHotspotSettingsSource,
    KeeneticPolicySource, KeeneticRegistrationSource, ManagerMetadataStore, XKeenInitSource, XKeenListSource,
    XKeenSettingsSource, XrayConfigSource, XrayProcessSource, SourceFingerprintSource,
)
from keenvpn.application.saved_draft import (
    CandidateAssetSource, GeoCategorySource, CompareSavedDraft, CompareSavedDraftHandler,
    CheckSavedDraft, CheckSavedDraftHandler,
)
from keenvpn.application.xray_candidate import InstalledXrayPort
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler
from keenvpn.application.proxy_connections import InspectConnections, InspectConnectionsHandler
from keenvpn.application.quick_check import QuickCheck, QuickCheckHandler
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler
from keenvpn.application.routing_import import ImportRoutingSchemeHandler
from keenvpn.application.routing_rules import ListRoutingRules, ListRoutingRulesHandler
from keenvpn.application.status_summary import InspectStatusSummary, InspectStatusSummaryHandler
from keenvpn.interfaces.cli.menu import ExitNotice, Menu, MenuError, UnavailableReason, ValueRequest
from keenvpn.interfaces.cli.presenters import (
    ROUTE_PROMPT, present_about, present_connections, present_device_list, present_manager_metadata, present_port53,
    present_menu_exit, present_quick_check, present_result, present_route_explanation, present_rule_list,
    present_status_header, present_status_summary,
)
from keenvpn.interfaces.cli.draft_presenters import present_draft_diff, present_saved_draft_check
from keenvpn.interfaces.cli.terminal import Action, ExitCheck, Header
from keenvpn.interfaces.cli.tree import (
    BOUND_SCENARIOS, BUILTIN_ACTIONS, ActionStates, build_main_menu, build_setup_menu,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class MenuSources:
    """Порты чтения, доступные меню; `None` — источник не подключён.

    Источники конфигурации и хранилища только читают. Отдельный порт проверки
    Xray создаёт временную область и запускает изолированный config test
    лишь при выборе проверки черновика. Рабочие настройки не меняются.
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
    drafts: DraftSessionStore | None = None
    """Хранилище черновика для области «Черновик» и решения о выходе; сценарии его только читают."""
    storage_error: ErrorDetail | None = None
    """Безопасная причина неподключённых хранилищ при неподтверждённом размещении DATA."""
    fingerprints: SourceFingerprintSource | None = None
    """Текущие отпечатки всех управляемых источников для проверки сохранённой сессии."""
    candidate_assets: CandidateAssetSource | None = None
    """Полные байты геобаз; ожидаемые ревизии всегда берутся из кандидата."""
    geo_catalogs: GeoCategorySource | None = None
    """Доверенные свидетельства категорий; отсутствие не подменяется именем или SHA."""
    installed_xray: InstalledXrayPort | None = None
    """Изолированный исполнитель; его отсутствие не блокирует статический отчёт."""

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
    """Собранное меню, обработчики его доступных действий, шапка корня и проверка выхода; у меню мастера шапки нет."""

    menu: Menu
    actions: Mapping[str, Action]
    header: Header | None = None
    exit_check: ExitCheck | None = None


def default_sources() -> MenuSources:
    """Источники запуска без явного включения чтения роутера: ничего не подключено ни на какой платформе."""
    return MenuSources()


def router_sources() -> MenuSources:
    """Источники `vpn-menu --read-router` и `vpn-setup` для чтения проверенной платформы.

    Подключаются файлы Entware, процесс Xray и локальный RCI.
    При сборке читается размещение DATA для подключения приватных файлов.
    При отказе оба хранилища остаются неподключёнными с безопасной причиной.
    Остальные источники читаются при выполнении сценария. Членство в наборах
    геобаз не подключается. При сборке записей, создания каталогов и импорта
    нет; проверочный процесс и временные файлы возможны только в пункте 7 → 2.
    """
    stores = connect_router_manager_files(StoragePlacementFiles())
    # Необязательные зависимости runner не должны ломать остальные пункты
    # меню. Проверки платформы и полномочий выполняет сам порт перед запуском.
    try:
        from keenvpn.adapters.xray_isolated_port import IsolatedInstalledXray
    except ImportError:
        tester = None
    else:
        tester = IsolatedInstalledXray()
    return MenuSources(
        policies=KeeneticPoliciesRci(), hotspot=KeeneticHotspotSettingsRci(), registrations=KeeneticRegistrationsRci(),
        runtime=KeeneticHotspotRuntimeRci(), xray=XrayConfigFiles(), xkeen_settings=XKeenSettingsFile(),
        xkeen_init=XKeenInitFile(), xkeen_lists=XKeenListFiles(), geodata=GeoDatabaseFiles(),
        process=XrayProcessObserver(),
        drafts=stores.drafts, metadata=stores.metadata, storage_error=stores.error,
        fingerprints=SourceFingerprints(), candidate_assets=GeoCandidateFiles(), installed_xray=tester,
    )


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

    states: dict[str, UnavailableReason | None] = {
        action_id: UnavailableReason.SOURCE_NOT_CONNECTED for action_id in BOUND_SCENARIOS
    }
    actions: dict[str, Action] = {}
    storage_notice = [] if sources.storage_error is None else [
        "Хранилища не подключены: " + sources.storage_error.message,
    ]
    if storage_notice:
        for action_id in ("settings.storage", "draft.diff", "draft.check"):
            states[action_id] = UnavailableReason.STORAGE_NOT_CONFIRMED

    def bind(action_id: str, action: Action) -> None:
        states[action_id] = None
        actions[action_id] = action

    # Сводка допускает неподключённые источники: пункт и шапка — один сценарий, который читает то, что подключено.
    summary = InspectStatusSummaryHandler(proxy, sources.process, drafts=sources.drafts, operation_ids=operation_ids)
    bind("status.summary", lambda: [
        *present_result(summary.execute(InspectStatusSummary()), present_status_summary), *storage_notice,
    ])

    def header() -> list[str]:
        return [*present_result(summary.execute(InspectStatusSummary()), present_status_header), *storage_notice]

    # Решение о выходе принимает сценарий; меню только показывает его строки и задаёт вопрос, если он нужен.
    menu_exit = InspectMenuExitHandler(sources.drafts, operation_ids=operation_ids)

    def exit_check() -> ExitNotice:
        notice = present_menu_exit(menu_exit.execute(InspectMenuExit()))
        return ExitNotice((*notice.lines, *storage_notice), notice.confirm)

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
    if sources.drafts is not None and sources.fingerprints is not None:
        inspect_draft = InspectDraftHandler(sources.drafts, operation_ids=operation_ids)
        compare = CompareSavedDraftHandler(sources.drafts, sources.fingerprints, operation_ids=operation_ids)
        check = CheckSavedDraftHandler(sources.drafts, sources.fingerprints, sources.geodata,
            sources.candidate_assets, sources.geo_catalogs, sources.installed_xray, operation_ids=operation_ids)

        def saved_action(handler, command_type, presenter):
            def action():
                inspected = inspect_draft.execute(InspectDraft())
                if not inspected.succeeded:
                    return present_result(inspected, presenter)
                view = inspected.data.draft
                if view is None:
                    return ["Сохранённого черновика нет."]
                # ID и токен остаются в состоянии вызова и не выводятся.
                return present_result(handler.execute(command_type(draft_id=view.draft_id,
                    expected_revision=view.revision)), presenter)
            return action

        bind("draft.diff", saved_action(compare, CompareSavedDraft, present_draft_diff))
        bind("draft.check", saved_action(check, CheckSavedDraft, present_saved_draft_check))
    for action_id in BUILTIN_ACTIONS:
        bind(action_id, present_about)
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
