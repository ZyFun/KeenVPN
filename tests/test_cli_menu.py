"""Модель меню, навигация и дерево плана без терминала, файлов, сети и процессов."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.status_summary import InspectStatusSummary
from keenvpn.application.keenetic_devices import ListKeeneticDevices
from keenvpn.application.manager_metadata import InspectManagerMetadata
from keenvpn.application.proxy_config import InspectProxyConfig
from keenvpn.application.proxy_connections import InspectConnections
from keenvpn.application.quick_check import QuickCheck
from keenvpn.application.routing import ExplainRoute
from keenvpn.application.routing_rules import ListRoutingRules
from keenvpn.interfaces.cli.menu import (
    BACK_NUMBER, MAX_ITEM_NUMBER, MAX_TITLE_LENGTH, REASON_MESSAGES, Menu, MenuAction, MenuError, MenuItem,
    MenuNavigator, Selection, SelectionKind, UnavailableReason, valid_action_id, valid_title,
)
from keenvpn.interfaces.cli.tree import (
    ALL_ACTION_IDS, BOUND_SCENARIOS, BUILTIN_ACTIONS, MAIN_MENU_TITLE, MAIN_SECTIONS, SETUP_MENU_TITLE,
    STATISTICS_TITLE, WIZARD_ITEMS, build_main_menu, build_setup_menu,
)
from tests.support.isolation import forbid_external_effects


def leaf(number: int, title: str = "Пункт", action_id: str = "section.item", reason=None) -> MenuItem:
    return MenuItem(number, title, action=MenuAction(action_id, reason))


def sample_root() -> Menu:
    """Корень с двумя уровнями подменю, доступными и недоступными действиями."""
    inner = Menu("Вложенное", (leaf(1, "Глубокий пункт", "inner.item"),))
    section = Menu("Раздел", (
        leaf(1, "Доступное действие", "section.available"),
        leaf(2, "Нереализованное действие", "section.missing", UnavailableReason.NOT_IMPLEMENTED),
        MenuItem(3, "Вложенный раздел", submenu=inner),
    ))
    return Menu("Корень", (
        MenuItem(1, "Раздел", submenu=section),
        leaf(2, "Корневое действие", "root.available"),
        leaf(3, "Без источника", "root.detached", UnavailableReason.SOURCE_NOT_CONNECTED),
    ))


def structure(menu: Menu, seen: set[int] | None = None) -> list:
    """Номера и заголовки дерева без состояний; общее подменю обходится один раз."""
    seen = set() if seen is None else seen
    seen.add(id(menu))
    result = []
    for item in menu.items:
        if item.submenu is None:
            result.append((item.number, item.title, item.action.action_id))
        elif id(item.submenu) in seen:
            result.append((item.number, item.title, "shared"))
        else:
            result.append((item.number, item.title, structure(item.submenu, seen)))
    return result


def leaves(menu: Menu, seen: set[int] | None = None) -> list[MenuItem]:
    seen = set() if seen is None else seen
    seen.add(id(menu))
    found = []
    for item in menu.items:
        if item.submenu is None:
            found.append(item)
        elif id(item.submenu) not in seen:
            found.extend(leaves(item.submenu, seen))
    return found


def submenus(menu: Menu, seen: set[int] | None = None) -> list[Menu]:
    seen = set() if seen is None else seen
    seen.add(id(menu))
    found = [menu]
    for item in menu.items:
        if item.submenu is not None and id(item.submenu) not in seen:
            found.extend(submenus(item.submenu, seen))
    return found


class MenuModelTests(unittest.TestCase):
    def test_item_requires_exactly_one_of_submenu_or_action(self):
        inner = Menu("Вложенное", ())
        with self.assertRaises(MenuError):
            MenuItem(1, "Пункт")
        with self.assertRaises(MenuError):
            MenuItem(1, "Пункт", submenu=inner, action=MenuAction("a.b"))
        self.assertTrue(MenuItem(1, "Пункт", submenu=inner).available)
        self.assertTrue(leaf(1).available)

    def test_item_number_bounds_and_types(self):
        for number in (0, -1, MAX_ITEM_NUMBER + 1, True, "1", 1.0, None):
            with self.subTest(number=number), self.assertRaises(MenuError):
                leaf(number)
        self.assertEqual(leaf(1).number, 1)
        self.assertEqual(leaf(MAX_ITEM_NUMBER).number, MAX_ITEM_NUMBER)
        self.assertEqual(BACK_NUMBER, 0)

    def test_titles_reject_control_characters_and_padding(self):
        for title in ("", " Пункт", "Пункт ", "Пункт\x1b[0m", "Пункт\nещё", "Пункт\tещё", "П" * (MAX_TITLE_LENGTH + 1), 5):
            with self.subTest(title=title):
                self.assertFalse(valid_title(title))
                with self.assertRaises(MenuError):
                    leaf(1, title)
                with self.assertRaises(MenuError):
                    Menu(title, ())
        self.assertTrue(valid_title("Пункт — текст / значение: .ru, .su, .рф"))
        self.assertTrue(valid_title("П" * MAX_TITLE_LENGTH))

    def test_action_id_format(self):
        for action_id in ("status.summary", "a1.b_2", "statistics.direct_checks", "x"):
            with self.subTest(action_id=action_id):
                self.assertTrue(valid_action_id(action_id))
        for action_id in ("Status", "1a", "a..b", ".a", "a.", "a-b", "", "a" * 65, "а.б", b"a.b", None, 7):
            with self.subTest(action_id=action_id):
                self.assertFalse(valid_action_id(action_id))
                with self.assertRaises(MenuError):
                    MenuAction(action_id)

    def test_reason_must_be_enum_or_none(self):
        for reason in ("not_implemented", 0, False, object()):
            with self.subTest(reason=reason), self.assertRaises(MenuError):
                MenuAction("a.b", reason)
        self.assertTrue(MenuAction("a.b").available)
        for reason in UnavailableReason:
            action = MenuAction("a.b", reason)
            self.assertFalse(action.available)
            self.assertIs(leaf(1, reason=reason).reason, reason)

    def test_menu_rejects_duplicate_numbers_and_wrong_item_types(self):
        with self.assertRaises(MenuError):
            Menu("Меню", (leaf(1), leaf(1, "Другой", "a.c")))
        with self.assertRaises(MenuError):
            Menu("Меню", [leaf(1)])
        with self.assertRaises(MenuError):
            Menu("Меню", (leaf(1), "пункт"))
        with self.assertRaises(MenuError):
            MenuItem(1, "Пункт", submenu="меню")
        with self.assertRaises(MenuError):
            MenuItem(1, "Пункт", action="a.b")

    def test_item_lookup_ignores_wrong_types_and_unknown_numbers(self):
        menu = Menu("Меню", (leaf(1), leaf(2, "Второй", "a.c")))
        self.assertEqual(menu.item(2).title, "Второй")
        for number in (0, 3, True, "1", 1.0, None):
            with self.subTest(number=number):
                self.assertIsNone(menu.item(number))

    def test_reason_messages_cover_every_reason_without_control_characters(self):
        self.assertEqual(set(REASON_MESSAGES), set(UnavailableReason))
        for message in REASON_MESSAGES.values():
            self.assertTrue(message.isprintable())
            # Каждая причина говорит, что действие не выполнено или настройки не изменились.
            self.assertTrue("не меняются" in message or "не выполняется" in message)

    def test_reason_messages_are_read_only(self):
        # Таблица текстов только для чтения, как таблицы шагов контракта: правка из процесса не меняет показ причин.
        with self.assertRaises(TypeError):
            REASON_MESSAGES[UnavailableReason.NOT_IMPLEMENTED] = "другой текст"
        with self.assertRaises(TypeError):
            del REASON_MESSAGES[UnavailableReason.NOT_IMPLEMENTED]


class NavigatorTests(unittest.TestCase):
    def setUp(self):
        self.root = sample_root()
        self.navigator = MenuNavigator(self.root)

    def test_root_requires_menu(self):
        with self.assertRaises(MenuError):
            MenuNavigator("Меню")

    def test_zero_at_root_exits_and_keeps_root(self):
        self.assertEqual(self.navigator.select(0), Selection(SelectionKind.EXIT))
        self.assertEqual(self.navigator.back(), Selection(SelectionKind.EXIT))
        self.assertIs(self.navigator.current, self.root)
        self.assertEqual(self.navigator.depth, 0)

    def test_zero_on_each_level_returns_exactly_one_level(self):
        self.assertIs(self.navigator.select(1).kind, SelectionKind.ENTERED)
        self.assertIs(self.navigator.select(3).kind, SelectionKind.ENTERED)
        self.assertEqual(self.navigator.titles, ("Корень", "Раздел", "Вложенное"))
        self.assertEqual(self.navigator.depth, 2)
        self.assertIs(self.navigator.select(0).kind, SelectionKind.BACK)
        self.assertEqual(self.navigator.titles, ("Корень", "Раздел"))
        self.assertIs(self.navigator.back().kind, SelectionKind.BACK)
        self.assertEqual(self.navigator.titles, ("Корень",))
        self.assertIs(self.navigator.back().kind, SelectionKind.EXIT)
        self.assertEqual(self.navigator.titles, ("Корень",))

    def test_unknown_numbers_do_not_change_position(self):
        self.navigator.select(1)
        for number in (99, 4, -5, True, "1", 1.5, None):
            with self.subTest(number=number):
                self.assertEqual(self.navigator.select(number), Selection(SelectionKind.UNKNOWN))
                self.assertEqual(self.navigator.depth, 1)

    def test_available_action_reports_identifier_without_moving(self):
        selection = self.navigator.select(2)
        self.assertIs(selection.kind, SelectionKind.ACTION)
        self.assertEqual(selection.action_id, "root.available")
        self.assertIsNone(selection.reason)
        self.assertEqual(self.navigator.depth, 0)
        self.navigator.select(1)
        self.assertEqual(self.navigator.select(1).action_id, "section.available")
        self.assertEqual(self.navigator.depth, 1)

    def test_unavailable_reports_reason_without_moving(self):
        selection = self.navigator.select(3)
        self.assertIs(selection.kind, SelectionKind.UNAVAILABLE)
        self.assertIs(selection.reason, UnavailableReason.SOURCE_NOT_CONNECTED)
        self.assertEqual(selection.action_id, "root.detached")
        self.navigator.select(1)
        self.assertIs(self.navigator.select(2).reason, UnavailableReason.NOT_IMPLEMENTED)
        self.assertEqual(self.navigator.depth, 1)

    def test_entered_selection_names_item_and_submenu_becomes_current(self):
        selection = self.navigator.select(1)
        self.assertEqual(selection.item.title, "Раздел")
        self.assertIs(self.navigator.current, selection.item.submenu)
        self.assertIsNone(selection.action_id)

    def test_navigation_has_no_external_effects(self):
        with forbid_external_effects():
            navigator = MenuNavigator(self.root)
            for number in (1, 3, 1, 0, 2, 0, 0, 2, 3, 99, 0):
                navigator.select(number)
            self.assertEqual(navigator.depth, 0)


class TreeTests(unittest.TestCase):
    def test_main_sections_keep_plan_numbers_and_titles(self):
        menu = build_main_menu({})
        self.assertEqual(menu.title, MAIN_MENU_TITLE)
        self.assertEqual([item.number for item in menu.items], list(range(1, 11)))
        self.assertEqual([item.title for item in menu.items], [
            "Состояние и быстрые действия", "Мастер установки и настройки", "VPN-подключения",
            "Правила маршрутизации", "Устройства и политики", "Автозапуск, DNS и поведение при сбое",
            "Черновик и применение", "Резервные копии и восстановление", "Обслуживание и диагностика",
            "Настройки меню",
        ])
        self.assertTrue(all(item.submenu is not None for item in menu.items))

    def test_subitems_are_numbered_consecutively_from_one(self):
        for submenu in submenus(build_main_menu({}))[1:]:
            with self.subTest(menu=submenu.title):
                self.assertEqual([item.number for item in submenu.items], list(range(1, len(submenu.items) + 1)))
                self.assertGreater(len(submenu.items), 0)

    def test_numbers_and_titles_do_not_depend_on_availability(self):
        plain = build_main_menu({})
        everything = build_main_menu({action_id: None for action_id in ALL_ACTION_IDS})
        mixed = build_main_menu({
            "status.summary": UnavailableReason.SOURCE_NOT_CONNECTED,
            "routing.explain": UnavailableReason.INPUT_REQUIRED,
            "settings.about": None,
        })
        self.assertEqual(structure(plain), structure(everything))
        self.assertEqual(structure(plain), structure(mixed))
        self.assertTrue(all(not item.available for item in leaves(plain)))
        self.assertTrue(all(item.available for item in leaves(everything)))
        states = {item.action.action_id: item.reason for item in leaves(mixed)}
        self.assertIs(states["status.summary"], UnavailableReason.SOURCE_NOT_CONNECTED)
        self.assertIs(states["routing.explain"], UnavailableReason.INPUT_REQUIRED)
        self.assertIsNone(states["settings.about"])
        self.assertIs(states["routing.list"], UnavailableReason.NOT_IMPLEMENTED)

    def test_every_action_is_visible_and_unimplemented_by_default(self):
        found = leaves(build_main_menu({}))
        self.assertEqual({item.action.action_id for item in found}, set(ALL_ACTION_IDS))
        self.assertEqual(len(found), len(ALL_ACTION_IDS))
        self.assertTrue(all(item.reason is UnavailableReason.NOT_IMPLEMENTED for item in found))

    def test_statistics_submenu_is_shared_between_sections_one_and_nine(self):
        menu = build_main_menu({})
        from_status = menu.item(1).submenu.item(2)
        from_maintenance = menu.item(9).submenu.item(1)
        self.assertIs(from_status.submenu, from_maintenance.submenu)
        self.assertEqual(from_status.submenu.title, STATISTICS_TITLE)
        self.assertEqual(from_maintenance.title, STATISTICS_TITLE)
        self.assertEqual(len(from_status.submenu.items), 6)
        navigator = MenuNavigator(menu)
        navigator.select(1)
        navigator.select(2)
        self.assertEqual(navigator.titles[1:], ("Состояние и быстрые действия", STATISTICS_TITLE))
        navigator.back()
        self.assertEqual(navigator.titles[-1], "Состояние и быстрые действия")

    def test_bound_scenarios_match_existing_commands_and_tree(self):
        self.assertEqual(BOUND_SCENARIOS, {
            "status.summary": InspectStatusSummary.name,
            "status.quick_check": QuickCheck.name,
            "connections.list": InspectConnections.name,
            "routing.list": ListRoutingRules.name,
            "routing.explain": ExplainRoute.name,
            "devices.list": ListKeeneticDevices.name,
            "failsafe.port53_check": InspectProxyConfig.name,
            "settings.storage": InspectManagerMetadata.name,
        })
        self.assertLessEqual(set(BOUND_SCENARIOS) | BUILTIN_ACTIONS, ALL_ACTION_IDS)
        self.assertEqual(BUILTIN_ACTIONS, {"settings.about"})
        menu = build_main_menu({})
        self.assertEqual(menu.item(1).submenu.item(1).action.action_id, "status.summary")
        self.assertEqual(menu.item(1).submenu.item(7).action.action_id, "status.quick_check")
        self.assertEqual(menu.item(3).submenu.item(1).action.action_id, "connections.list")
        self.assertEqual(menu.item(4).submenu.item(1).action.action_id, "routing.list")
        self.assertEqual(menu.item(4).submenu.item(9).action.action_id, "routing.explain")
        self.assertEqual(menu.item(5).submenu.item(1).action.action_id, "devices.list")
        self.assertEqual(menu.item(6).submenu.item(7).action.action_id, "failsafe.port53_check")
        self.assertEqual(menu.item(10).submenu.item(1).action.action_id, "settings.storage")
        self.assertEqual(menu.item(10).submenu.item(5).action.action_id, "settings.about")

    def test_unknown_state_or_wrong_reason_is_rejected(self):
        with self.assertRaises(MenuError):
            build_main_menu({"nope.item": None})
        with self.assertRaises(MenuError):
            build_main_menu({"status.summary": "source_not_connected"})
        with self.assertRaises(MenuError):
            build_setup_menu({"status.summary": False})

    def test_setup_menu_is_the_wizard_section(self):
        setup = build_setup_menu({})
        wizard = build_main_menu({}).item(2).submenu
        self.assertEqual(setup.title, SETUP_MENU_TITLE)
        self.assertEqual(structure(setup), structure(wizard))
        self.assertEqual(len(setup.items), len(WIZARD_ITEMS))
        self.assertTrue(all(item.reason is UnavailableReason.NOT_IMPLEMENTED for item in setup.items))
        self.assertIs(MenuNavigator(setup).back().kind, SelectionKind.EXIT)

    def test_action_ids_are_unique_valid_and_counted(self):
        self.assertTrue(all(valid_action_id(action_id) for action_id in ALL_ACTION_IDS))
        self.assertEqual(len(ALL_ACTION_IDS), len(leaves(build_main_menu({}))))
        self.assertEqual(len(MAIN_SECTIONS), 10)

    def test_building_has_no_external_effects(self):
        with forbid_external_effects():
            menu = build_main_menu({"settings.about": None})
            setup = build_setup_menu({})
        self.assertTrue(menu.item(10).submenu.item(5).available)
        self.assertEqual(len(setup.items), 5)


if __name__ == "__main__":
    unittest.main()
