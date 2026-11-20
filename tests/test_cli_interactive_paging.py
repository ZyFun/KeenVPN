"""Постраничный выбор в интерактивном меню и списках."""

from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.interfaces.cli.interactive import InteractiveMenu
from keenvpn.interfaces.cli.menu import (
    CardLevel, ListEntry, Menu, MenuAction, MenuItem, MenuList, MenuNavigator, UnavailableReason,
)


class PagingTests(unittest.TestCase):
    def screen(self, disabled=(), title="Пункт"):
        calls = []
        items = []
        actions = {}
        for number in range(1, 25):
            action_id = f"sample.row_{number}"
            reason = UnavailableReason.NOT_IMPLEMENTED if number in disabled else None
            items.append(MenuItem(number, title, action=MenuAction(action_id, reason)))
            if reason is None:
                actions[action_id] = lambda number=number: calls.append(number) or ["Открыто"]
        return InteractiveMenu(MenuNavigator(Menu("Меню", tuple(items))), actions), calls

    def selected(self, screen):
        result = re.search(r"^› (\d+)\.", screen, re.M)
        return int(result[1]) if result else None

    def test_page_down_up_select_only_a_visible_number(self):
        menu, calls = self.screen()
        menu.render(80, 10, False)
        menu.key("page_down")
        self.assertEqual(self.selected(menu.render(80, 10, False)), 7)
        menu.key("enter")
        self.assertEqual(calls, [7])
        menu.key("back")
        menu.render(80, 10, False)
        menu.key("page_down")
        menu.render(80, 10, False)
        menu.key("page_up")
        selected = self.selected(menu.render(80, 10, False))
        self.assertIsNotNone(selected)
        menu.key("enter")
        self.assertEqual(calls, [7, selected])

    def test_page_of_closed_rows_rejects_enter_and_arrows_or_number_can_leave(self):
        for key, target in (("down", 21), ("up", 3), ("2", 2)):
            with self.subTest(key=key):
                menu, calls = self.screen(disabled=range(4, 21))
                menu.render(80, 10, False)
                menu.key("page_down")
                page = menu.render(80, 10, False)
                self.assertIsNone(self.selected(page))
                menu.key("enter")
                self.assertEqual(calls, [])
                self.assertEqual(menu.render(80, 10, False), page)
                menu.key(key)
                menu.key("enter")
                self.assertEqual(calls, [target])

    def test_width_change_reselects_a_visible_row_after_wrap(self):
        menu, calls = self.screen(title="Длинное название пункта для проверки переноса между строками")
        menu.render(80, 10, False)
        menu.key("page_down")
        old = self.selected(menu.render(80, 10, False))
        new = self.selected(menu.render(31, 10, False))
        self.assertIsNotNone(new)
        self.assertNotEqual(new, old)
        menu.key("enter")
        self.assertEqual(calls, [new])

    def test_paged_list_opens_the_card_shown_in_the_preview(self):
        menu, _ = self.screen()
        entries = tuple(ListEntry(i, f"Устройство {i}", (f"Карточка устройства {i}",)) for i in range(1, 30))
        menu.navigator.open_list(MenuList("Устройства", "Устройство", (), entries))
        menu.render(100, 11, False)
        menu.key("page_down")
        page = menu.render(100, 11, False)
        selected = self.selected(page)
        self.assertIsNotNone(selected)
        self.assertGreater(selected, 1)
        self.assertIn(f"Карточка устройства {selected}", page)
        menu.key("enter")
        self.assertIsInstance(menu.navigator.current, CardLevel)
        self.assertEqual(menu.navigator.current.entry.number, selected)
