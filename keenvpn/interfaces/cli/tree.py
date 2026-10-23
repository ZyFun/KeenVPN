"""Дерево меню первой версии: стабильные номера, заголовки и идентификаторы действий.

Разделы 1–10 и порядок пунктов повторяют утверждённое дерево меню; подпункты
нумеруются по порядку перечисления с 1. Номера не зависят от того, какие
действия реализованы: состояние пункта задаёт сборка через отображение
«идентификатор действия → причина недоступности», а действие без состояния
считается нереализованным. Все пункты дерева видны; недоступные помечаются.
"""

from collections.abc import Mapping

from keenvpn.interfaces.cli.menu import Menu, MenuAction, MenuError, MenuItem, UnavailableReason, valid_action_id


ActionStates = Mapping[str, UnavailableReason | None]
"""Состояния действий: `None` — доступно, причина — показано как недоступное."""

MAIN_MENU_TITLE = "Главное меню KeenVPN"
SETUP_MENU_TITLE = "Мастер установки и настройки KeenVPN"
STATISTICS_TITLE = "Статистика проверок"

BOUND_SCENARIOS: Mapping[str, str] = {
    "status.summary": "inspect_status_summary",
    "status.quick_check": "quick_check",
    "connections.list": "inspect_connections",
    "routing.list": "list_routing_rules",
    "routing.explain": "explain_route",
    "devices.list": "list_keenetic_devices",
    "failsafe.port53_check": "inspect_proxy_config",
    "settings.storage": "inspect_manager_metadata",
}
"""Пункты, за которыми закреплён существующий сценарий application: действие → имя команды."""

BUILTIN_ACTIONS = frozenset({"settings.about"})
"""Действия самого интерфейса без сценария application."""

# Лист: (номер, заголовок, идентификатор действия). Раздел: (номер, заголовок, заголовок подменю, пункты).
_STATISTICS_ITEMS = (
    (1, "Выбрать период", "statistics.period"),
    (2, "Сводка по каналам", "statistics.channels"),
    (3, "Эпизоды ошибок — список и подробности", "statistics.episodes"),
    (4, "История переключений", "statistics.switches"),
    (5, "Прямые проверки интернета", "statistics.direct_checks"),
    (6, "Экспорт отчёта", "statistics.export"),
)

WIZARD_ITEMS = (
    (1, "Новая установка", "wizard.new_install"),
    (2, "Подключить меню к существующей системе", "wizard.attach_existing"),
    (3, "Повторно пройти настройки в черновике", "wizard.reconfigure"),
    (4, "Восстановить настройку из резервной копии", "wizard.restore"),
    (5, "Проверить / продолжить незавершённую операцию", "wizard.resume"),
)

MAIN_SECTIONS = (
    (1, "Состояние и быстрые действия", "Состояние и быстрые действия", (
        (1, "Сводка: ядро, перехват, VPN, DNS, автозапуск, черновик", "status.summary"),
        (2, "Открыть статистику проверок — переход в раздел 9", STATISTICS_TITLE, _STATISTICS_ITEMS),
        (3, "Включить XKeen сейчас", "status.start_xkeen"),
        (4, "Остановить XKeen — прямой доступ сейчас", "status.stop_xkeen"),
        (5, "Прямой доступ и отключить автозапуск", "status.direct_and_disable_autostart"),
        (6, "Перезапустить текущую конфигурацию", "status.restart"),
        (7, "Быстрая проверка без изменений", "status.quick_check"),
    )),
    (2, "Мастер установки и настройки", "Мастер установки и настройки", WIZARD_ITEMS),
    (3, "VPN-подключения", "VPN-подключения", (
        (1, "Список и карточка подключения", "connections.list"),
        (2, "Добавить из ссылки", "connections.add_link"),
        (3, "Изменить параметры / переименовать", "connections.edit"),
        (4, "Проверить подключение отдельно", "connections.check"),
        (5, "Выбрать одиночный профиль либо основной и до трёх резервов", "connections.select_group"),
        (6, "Изменить приоритеты, пороги и безопасный режим автоматики", "connections.failover_settings"),
        (7, "Здоровье всех каналов, выбранный выход и причина переключения", "connections.health"),
        (8, "Найти правила, использующие подключение", "connections.find_rules"),
        (9, "Удалить неиспользуемое подключение", "connections.delete"),
    )),
    (4, "Правила маршрутизации", "Правила маршрутизации", (
        (1, "Все правила по порядку / поиск", "routing.list"),
        (2, "Добавить: домен / IP и подсеть / GeoIP / GeoSite", "routing.add"),
        (3, "Настроить GeoIP RU / зоны .ru, .su, .рф / наборы GeoSite", "routing.geo_settings"),
        (4, "Изменить условие или направление", "routing.edit"),
        (5, "Переместить выше / ниже / перед выбранным правилом", "routing.move"),
        (6, "Выделить одно исключение из группы", "routing.split_exception"),
        (7, "Включить / выключить / удалить правило", "routing.toggle_or_delete"),
        (8, "Проверить пересечения и порядок", "routing.check_order"),
        (9, "Объяснить выбор правила для домена/IP", "routing.explain"),
        (10, "Выбрать общий режим маршрутизации", "routing.mode"),
    )),
    (5, "Устройства и политики", "Устройства и политики", (
        (1, "Список, поиск, текущие назначения", "devices.list"),
        (2, "Назначить устройству VPN или прямой режим", "devices.assign"),
        (3, "Вернуть наследование политики сегмента", "devices.inherit"),
        (4, "Выбрать несколько устройств", "devices.select_many"),
        (5, "Настроить: только выбранные / весь сегмент / все кроме", "devices.segment_mode"),
        (6, "Показать новые и изменившиеся MAC", "devices.changes"),
    )),
    (6, "Автозапуск, DNS и поведение при сбое", "Автозапуск, DNS и поведение при сбое", (
        (1, "Автозапуск при загрузке: включить / выключить", "failsafe.autostart"),
        (2, "Прямой резерв при отказе VPN: разрешить / запретить", "failsafe.direct_fallback"),
        (3, "Аварийная блокировка: режим и ограничения", "failsafe.killswitch"),
        (4, "DNS Keenetic / DoH: состояние и поддерживаемые настройки", "failsafe.dns_state"),
        (5, "Исключать DNS (TCP/UDP 53) из перехвата: включить / выключить", "failsafe.port53_toggle"),
        (6, "Подсказка: исключение DNS и совместимость с Pritunl", "failsafe.port53_hint"),
        (7, "Проверить выбранный и фактический режим порта 53", "failsafe.port53_check"),
        (8, "IPv6: состояние роутера и возможности VPN-выхода", "failsafe.ipv6"),
    )),
    (7, "Черновик и применение", "Черновик и применение", (
        (1, "Посмотреть изменения без секретов", "draft.diff"),
        (2, "Проверить черновик", "draft.check"),
        (3, "Применить с подтверждением", "draft.apply"),
        (4, "Сохранить черновик и выйти", "draft.save_and_exit"),
        (5, "Отменить черновик", "draft.discard"),
    )),
    (8, "Резервные копии и восстановление", "Резервные копии и восстановление", (
        (1, "Создать копию", "backup.create"),
        (2, "Скачать проверенный архив и SHA-256 на компьютер", "backup.download"),
        (3, "Расписание копий: включить / выключить, время и часовой пояс", "backup.schedule"),
        (4, "Список, дата, состав и совместимость", "backup.list"),
        (5, "Проверить архив без восстановления", "backup.verify"),
        (6, "Восстановить с просмотром изменений", "backup.restore"),
        (7, "Подготовить копию для переноса", "backup.export"),
        (8, "Удалить выбранную копию с подтверждением", "backup.delete"),
    )),
    (9, "Обслуживание и диагностика", "Обслуживание и диагностика", (
        (1, STATISTICS_TITLE, STATISTICS_TITLE, _STATISTICS_ITEMS),
        (2, "Проверить версии и совместимость", "maintenance.versions"),
        (3, "Проверить обновления без установки", "maintenance.check_updates"),
        (4, "Обновить менеджер / Xray / XKeen / GeoIP / GeoSite отдельно", "maintenance.update"),
        (5, "Настроить автообновление GeoIP / GeoSite: базы, время, периодичность", "maintenance.geo_schedule"),
        (6, "Приостановить / выключить расписание; посмотреть результат и следующий запуск",
         "maintenance.geo_schedule_state"),
        (7, "Проверить сохранность доработок XKeen", "maintenance.xkeen_patches"),
        (8, "Посмотреть ошибки / создать отчёт без секретов", "maintenance.report"),
        (9, "Удалить только меню управления", "maintenance.uninstall"),
    )),
    (10, "Настройки меню", "Настройки меню", (
        (1, "Хранилища: простой / расширенный вариант, размещение собственных данных", "settings.storage"),
        (2, "История: размер, срок хранения и состояние выбранного хранилища", "settings.history"),
        (3, "Каталог и число успешных копий; переход к расписанию и результату запуска", "settings.backups"),
        (4, "Вывод: обычный текст / цвет", "settings.output"),
        (5, "Сведения о версии и справка", "settings.about"),
    )),
)


def _collect(items: tuple, found: list[str]) -> None:
    for entry in items:
        if len(entry) == 3:
            found.append(entry[2])
        else:
            _collect(entry[3], found)


def _all_action_ids() -> frozenset[str]:
    found: list[str] = []
    _collect(MAIN_SECTIONS, found)
    # Статистика встречается дважды как общий переход; это одни и те же пункты.
    distinct = frozenset(found)
    expected = len(found) - len(_STATISTICS_ITEMS)
    if len(distinct) != expected or not all(valid_action_id(action_id) for action_id in distinct):
        raise MenuError("Идентификаторы действий дерева меню должны быть уникальными и корректными.")
    return distinct


ALL_ACTION_IDS = _all_action_ids()
"""Все идентификаторы действий дерева; привязки и встроенные действия входят в него."""

if not (set(BOUND_SCENARIOS) | BUILTIN_ACTIONS) <= ALL_ACTION_IDS:
    raise MenuError("Привязанные и встроенные действия должны входить в дерево меню.")


def _check_states(states: ActionStates) -> None:
    unknown = set(states) - ALL_ACTION_IDS
    if unknown:
        raise MenuError("Состояние задано для действия, которого нет в дереве меню.")
    if any(reason is not None and type(reason) is not UnavailableReason for reason in states.values()):
        raise MenuError("Состояние действия — None или UnavailableReason.")


def _build(title: str, items: tuple, states: ActionStates, memo: dict[int, Menu]) -> Menu:
    key = id(items)
    if key in memo:
        return memo[key]
    built = []
    for entry in items:
        if len(entry) == 3:
            number, item_title, action_id = entry
            reason = states.get(action_id, UnavailableReason.NOT_IMPLEMENTED)
            built.append(MenuItem(number, item_title, action=MenuAction(action_id, reason)))
        else:
            number, item_title, submenu_title, children = entry
            built.append(MenuItem(number, item_title, submenu=_build(submenu_title, children, states, memo)))
    menu = Menu(title, tuple(built))
    memo[key] = menu
    return menu


def build_main_menu(states: ActionStates) -> Menu:
    """Собрать главное меню со всеми разделами и заданными состояниями действий."""
    _check_states(states)
    return _build(MAIN_MENU_TITLE, MAIN_SECTIONS, states, {})


def build_setup_menu(states: ActionStates) -> Menu:
    """Собрать корневое меню `vpn-setup`: пункты мастера под собственным заголовком."""
    _check_states(states)
    return _build(SETUP_MENU_TITLE, WIZARD_ITEMS, states, {})
