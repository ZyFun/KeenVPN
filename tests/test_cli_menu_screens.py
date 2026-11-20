"""Полноэкранное меню на обезличенном снимке роутера в широком и узком терминалах."""

from dataclasses import replace
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.interfaces.cli.composition import assemble_main_menu
from keenvpn.interfaces.cli.interactive import InteractiveMenu
from keenvpn.interfaces.cli.menu import CardLevel, InputLevel, ListLevel, MenuNavigator
from tests.support.in_memory import InMemoryDraftSessionStore, InMemoryManagerMetadataStore, InMemorySourceFingerprints
from tests.support.isolation import forbid_external_effects
from tests.test_cli_menu_exit import DRAFT_ID, content
from tests.test_cli_terminal import snapshot_menu_sources


SIZES = ((123, 31), (70, 26))


class RouterMenuScreensTests(unittest.TestCase):
    def setUp(self):
        self.metadata = InMemoryManagerMetadataStore()
        self.fixture, sources = snapshot_menu_sources(self.metadata)
        self.drafts = InMemoryDraftSessionStore()
        self.sources = replace(sources, drafts=self.drafts, fingerprints=InMemorySourceFingerprints())

    def menu(self, **changes):
        assembly = assemble_main_menu(replace(self.sources, **changes))
        return InteractiveMenu(MenuNavigator(assembly.menu), assembly.actions, assembly.header, assembly.exit_check)

    def submit(self, menu, value):
        for character in str(value):
            menu.key(character)
        menu.key("enter")

    def frame(self, menu, size):
        frame = menu.render(*size, color=False)
        self.assertEqual(len(frame.splitlines()), size[1])
        self.assertTrue(all(len(line) < size[0] for line in frame.splitlines()))
        for marker in ("\x1b", "fixture-password", "/fixture/ws", "02:00:00:54", "192.0.2.", DRAFT_ID,
                       "TEST_secret-extra", "TEST_private-note"):
            self.assertNotIn(marker, frame)
        return frame

    def test_available_and_closed_sections_and_actions_on_router_snapshot(self):
        # При подключённых источниках и черновиках только для чтения доступны эти двенадцать действий.
        screens = {
            1: {1: "Ядро Xray", 7: "Итог:"},
            2: {},
            3: {1: "Балансировщиков: 1"},
            4: {1: "Правил модели: 40", 9: "Домен"},
            5: {1: "Записей устройств: 19"},
            6: {7: "proxy_dns"},
            7: {1: "Сохранённого черновика нет", 2: "Сохранённого черновика нет", 4: None},
            8: {},
            9: {},
            10: {1: "Метаданны", 5: "Enter"},
        }
        for size in SIZES:
            with self.subTest(size=size), forbid_external_effects():
                menu = self.menu()
                root = menu.navigator.current
                for number, actions in screens.items():
                    self.submit(menu, number)
                    if not actions:
                        self.assertIs(menu.navigator.current, root)
                        self.assertIn("ещё не реализовано", self.frame(menu, size))
                        continue
                    section = menu.navigator.current
                    self.assertIs(section, root.item(number).submenu)
                    self.assertEqual({item.number for item in section.items if item.available}, set(actions))
                    if number == 7:
                        self.submit(menu, 5)
                        self.assertIs(menu.navigator.current, section)
                        self.assertIn("только чтение", self.frame(menu, size))
                    for action, marker in actions.items():
                        with self.subTest(section=number, action=action):
                            # Выход отрабатывает в отдельной сессии, чтобы продолжить обход разделов.
                            visit = menu
                            if marker is None:
                                visit = self.menu()
                                self.submit(visit, number)
                            self.submit(visit, action)
                            if marker is None:
                                self.assertTrue(visit.finished)
                                continue
                            self.assertIn(marker, self.frame(visit, size))
                            visit.key("back")
                            self.assertIs(visit.navigator.current, section)
                    menu.key("back")
                    self.assertIs(menu.navigator.current, root)
        self.assertFalse(self.drafts.remove_calls)
        self.assertFalse(self.metadata.write_calls)

    def test_rule_list_uses_actual_rows_and_opens_original_number_after_search(self):
        for size in SIZES:
            with self.subTest(size=size), forbid_external_effects():
                menu = self.menu(metadata=None)
                self.submit(menu, 4)
                self.submit(menu, 1)
                reads = self.fixture.proxy.calls
                first = self.frame(menu, size)
                self.assertIn("хранилище не подключено", first)
                self.assertIn("1. Входящий тег Xray", first)
                self.assertIn("8. Остальной трафик", first)
                self.assertNotIn("UnsupportedRuleCondition", first)
                menu.key("i")
                self.assertIn("Часть с маршрутизацией", self.frame(menu, size))
                menu.key("back")
                menu.key("/")
                self.submit(menu, "fallback_mixed")
                self.assertIn("Совпадений нет", self.frame(menu, size))
                menu.key("back")
                menu.key("/")
                self.submit(menu, "GeoIP")
                self.assertIn("7. GeoIP", self.frame(menu, size))
                menu.key("enter")
                self.assertIsInstance(menu.navigator.current, CardLevel)
                self.assertEqual(menu.navigator.current.entry.number, 7)
                self.assertIn("Действие: DIRECT", self.frame(menu, size))
                menu.key("back")
                self.assertTrue(menu.navigator.current.filtered)
                menu.key("tab")
                self.assertFalse(menu.navigator.current.filtered)
                menu.key("/")
                self.submit(menu, "fallback_mixed")
                self.assertEqual([entry.number for entry in menu.navigator.current.entries], [3, 4, 8])
                self.submit(menu, 8)
                self.assertEqual(menu.navigator.current.entry.number, 8)
                menu.key("home")
                self.assertEqual(menu.navigator.depth, 0)
                self.assertEqual(self.fixture.proxy.calls, reads)

    def test_paging_long_device_list_opens_highlighted_card_after_resize(self):
        with forbid_external_effects():
            menu = self.menu()
            self.submit(menu, 5)
            self.submit(menu, 1)
            self.frame(menu, SIZES[1])
            menu.key("page_down")
            self.frame(menu, SIZES[1])
            shown = self.frame(menu, SIZES[0])
            selected = re.search(r"› (\d+)\.", shown)
            self.assertIsNotNone(selected, shown)
            picked = int(selected[1])
            self.assertGreater(picked, 1)
            menu.key("enter")
            self.assertEqual(menu.navigator.current.entry.number, picked)
            card = self.frame(menu, SIZES[0])
            self.assertIn("Наблюдаемый интерфейс", card)
            self.assertIn("5 → 2", card)
            menu.key("back")
            self.assertIn(f"› {picked}.", self.frame(menu, SIZES[0]))

    def test_failure_and_route_retry_hide_private_values(self):
        with forbid_external_effects():
            menu = self.menu()
            self.submit(menu, 4)
            self.submit(menu, 9)
            self.assertIsInstance(menu.navigator.current, InputLevel)
            menu.key("enter")
            self.assertIsInstance(menu.navigator.current, InputLevel)
            self.submit(menu, "http://secret.example")
            error = self.frame(menu, SIZES[1])
            self.assertNotIn("secret.example", error)
            self.assertIn("Следующий шаг", error)
            menu.key("r")
            self.assertIsInstance(menu.navigator.current, InputLevel)
            self.submit(menu, "retry.example")
            answer = self.frame(menu, SIZES[0])
            self.assertNotIn("retry.example", answer)
            self.assertIn("Итог", answer)
            menu.key("back")
            self.fixture.proxy.xray.outcome = OSError("/opt/etc/fixture-password")
            self.submit(menu, 1)
            failure = self.frame(menu, SIZES[1])
            self.assertNotIsInstance(menu.navigator.current, ListLevel)
            self.assertIn("Не удалось прочитать", failure)
            self.assertIn("Следующий шаг", failure)

    def test_draft_exit_confirmation_preserves_stored_bytes(self):
        raw = content()
        store = InMemoryDraftSessionStore(raw)
        with forbid_external_effects():
            menu = self.menu(drafts=store)
            self.submit(menu, 7)
            self.submit(menu, 4)
            self.assertIn("Черновик изменений создан", self.frame(menu, SIZES[1]))
            menu.key("enter")
            self.assertFalse(menu.finished)
            self.submit(menu, 4)
            self.submit(menu, 2)
            self.assertTrue(menu.finished)
        self.assertEqual(store.content, raw)
        self.assertFalse(store.remove_calls)
