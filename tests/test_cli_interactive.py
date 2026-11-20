"""Проверки двух компоновок, навигации и ввода через интерактивный адаптер."""

from io import StringIO
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.interfaces.cli.interactive import InteractiveMenu, can_use_terminal
from keenvpn.interfaces.cli.menu import (
    ConfirmationRequest, ExitNotice, ListEntry, MenuList, MenuNavigator, UnavailableReason, ValueRequest,
)
from keenvpn.interfaces.cli.tree import build_main_menu


class InteractiveMenuTests(unittest.TestCase):
    def screen(self, actions, reasons=None, **kwargs):
        states = {action_id: None for action_id in actions}
        states.update(reasons or {})
        nav = MenuNavigator(build_main_menu(states))
        return InteractiveMenu(nav, actions, **kwargs)

    def choose(self, menu, value):
        for char in str(value):
            menu.key(char)
        menu.key("enter")

    def test_nested_availability_and_two_layouts_use_same_live_tree(self):
        menu = self.screen({"status.summary": lambda: ["Сводка"], "settings.about": lambda: ["Справка"]},
                           {"draft.discard": UnavailableReason.DRAFT_DISCARD_NOT_CONNECTED})
        wide = menu.render(150, 60)
        self.assertIn("Обзор роутера", wide)
        self.assertIn("Мастер установки и настройки (ещё не реализовано)", wide)
        self.assertIn("только чтение", wide)
        self.assertIn("Компактный SSH", menu.render(95, 40, False))
        self.choose(menu, 2)
        self.assertEqual(menu.navigator.depth, 0)
        menu.key("down")
        menu.key("enter")
        self.assertEqual(menu.navigator.current.title, "Настройки меню")
        self.choose(menu, 5)
        self.assertIn("Справка", menu.render(52, 15, False))
        menu.key("back")
        menu.key("back")
        self.choose(menu, 10)
        self.assertEqual(menu.navigator.current.title, "Настройки меню")

    def test_closed_statistics_opens_through_both_paths_when_first_action_is_bound(self):
        for section, number in ((1, 2), (9, 1)):
            with self.subTest(section=section):
                menu = self.screen({"statistics.period": lambda: ["Период"]})
                self.choose(menu, section)
                self.choose(menu, number)
                self.assertEqual(menu.navigator.current.title, "Статистика проверок")
                self.choose(menu, 1)
                self.assertIn("Период", menu.render(120, 40, False))

    def test_lists_search_card_and_return_to_selection(self):
        rows = (ListEntry(1, "Ноутбук", ("Карточка ноутбука",)), ListEntry(2, "Телевизор", ("Карточка телевизора",)))
        menu = self.screen({"devices.list": lambda: MenuList("Устройства", "Устройство", (), rows)})
        self.choose(menu, 5)
        self.choose(menu, 1)
        menu.key("/")
        for ch in "телев":
            menu.key(ch)
        menu.key("enter")
        self.assertEqual([it.number for it in menu.navigator.current.entries], [2])
        menu.key("enter")
        self.assertIn("Карточка телевизора", menu.render(60, 24, False))
        menu.key("back")
        self.assertTrue(menu.navigator.current.filtered)
        menu.key("/")
        for char in "камера":
            menu.key(char)
        menu.key("enter")
        self.assertEqual(menu.navigator.current.entries, ())
        self.assertIn("Устройства не найдены", menu.render(52, 24))
        self.choose(menu, 2)
        self.assertEqual(menu.navigator.current.entries, ())
        menu.key("back")
        self.assertEqual(menu.navigator.current.entries, rows)

    def test_confirmation_is_exact_and_does_not_accept_arbitrary_input(self):
        accepted = []
        def accept():
            accepted.append(True)
            return ["Завершено"]
        menu = self.screen({"draft.discard": lambda: ConfirmationRequest(("Подтвердите действие",), accept)})
        self.choose(menu, 7)
        self.choose(menu, 5)
        self.choose(menu, "2x")
        self.assertFalse(accepted)
        menu.key("back")
        self.choose(menu, 5)
        self.choose(menu, 2)
        self.assertEqual(accepted, [True])

    def test_eof_and_default_exit_response_preserve_draft(self):
        menu = self.screen({}, exit_check=lambda: ExitNotice(("Найден черновик",), True))
        self.choose(menu, 0)
        self.assertIn("Найден черновик", menu.render(80, 24))
        menu.key("enter")
        self.assertFalse(menu.finished)
        menu.key("eof")
        self.assertTrue(menu.finished)
        self.assertIn("Найден черновик", menu.exit_lines)

    def test_private_input_and_controls_in_results(self):
        values = []
        def submit(value):
            values.append(value)
            return ["Учебный ответ\x1b[31m"]
        menu = self.screen({"routing.explain": lambda: ValueRequest(("Введите домен",), submit)})
        self.choose(menu, 4)
        self.choose(menu, 9)
        for char in "host.example":
            menu.key(char)
        self.assertNotIn("host.example", menu.render(120, 35))
        menu.key("enter")
        self.assertEqual(values, ["host.example"])
        self.assertNotIn("\x1b", menu.render(120, 35, False))
        self.assertTrue(all(len(line) < 120 for line in menu.render(120, 35, False).splitlines()))

    def test_mono_keeps_labels_and_cannot_enable_controls(self):
        menu = self.screen({"status.summary": lambda: ["Сводка"]})
        color = menu.render(120, 60)
        plain = menu.render(120, 60, False)
        self.assertIn("\x1b[", color)
        self.assertEqual(re.sub(r"\x1b\[[\d;]*m", "", color), plain)
        self.assertFalse(can_use_terminal(StringIO(), StringIO()))

    def test_backgrounds_fill_rows_and_separate_the_preview(self):
        menu = self.screen({"status.summary": lambda: [], "connections.list": lambda: []})
        menu.key("down")
        for term, colors, background in (("xterm", "", "0"), ("xterm-256color", "", "15"),
                                         ("xterm", "truecolor", "0"), ("vt100", "", "0")):
            with self.subTest(term=term, colors=colors, background=background):
                with patch.dict(os.environ, {"TERM": term, "COLORTERM": colors, "COLORFGBG": background}):
                    frame = menu.render(124, 35)
                rows = [self.line_backgrounds(line) for line in frame.splitlines()]
                picked, locked, normal = (
                    next(row for row in rows if label in row[0])
                    for label in ("› 3.", "2. Мастер установки", "1. Состояние и быстрые")
                )
                split = picked[0].index("│", 2)
                tones = []
                for text, backgrounds in (picked, locked, normal):
                    tone = backgrounds[4]
                    self.assertIsNotNone(tone)
                    self.assertEqual(tone, backgrounds[split-2], text)
                    tones.append(tone)
                self.assertEqual(len(set(tones)), 3)
                detail, backgrounds = next(row for row in rows if "2. Добавить из ссылки" in row[0])
                self.assertEqual(backgrounds[detail.index("Добавить")], tones[2])
                self.assertNotEqual(rows[1][1][4], tones[2])
                self.assertEqual(len(rows), 35)
                self.assertIn("Выход", rows[-2][0])
                self.assertTrue(rows[-3][0].startswith("├──"))
                self.assertTrue(rows[-1][0].startswith("└──"))

    @staticmethod
    def line_backgrounds(line):
        """Воспроизвести действие SGR на фон каждой печатной ячейки проверяемой строки."""
        characters, backgrounds, active = [], [], None
        for part in re.split(r"(\x1b\[[0-9;]*m)", line):
            if not part.startswith("\x1b["):
                characters.append(part)
                backgrounds.extend([active] * len(part))
                continue
            codes = iter(int(value) for value in part[2:-1].split(";"))
            for code in codes:
                if code in (0, 49):
                    active = None
                elif 40 <= code <= 47 or 100 <= code <= 107:
                    active = code
                elif code in (38, 48):
                    count = 3 if next(codes) == 2 else 1
                    value = tuple(next(codes) for _ in range(count))
                    if code == 48:
                        active = value
        return "".join(characters), backgrounds

    def test_compact_monochrome_keeps_dividers_and_locked_reason(self):
        menu = self.screen({"status.summary": lambda: []})
        rows = menu.render(70, 26, False).splitlines()
        self.assertEqual(len(rows), 26)
        self.assertIn("Компактный SSH", rows[1])
        self.assertTrue(all(len(row) < 70 for row in rows))
        self.assertIn("› 1.", "\n".join(rows))
        self.assertIn("(ещё не реализовано)", "\n".join(rows))
        self.assertNotIn("Обзор раздела", "\n".join(rows))
        self.assertTrue(rows[-3].startswith("├──"))
        self.assertTrue(rows[-1].startswith("└──"))


@unittest.skipUnless(os.name == "posix", "Требуется POSIX PTY.")
class InteractiveTerminalTests(unittest.TestCase):
    def test_signals_leave_canonical_mode_and_echo_intact(self):
        import pty
        import termios

        script = Path(__file__).resolve().parents[1] / "scripts/vpn_menu.py"
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signum=signum):
                master, slave = pty.openpty()
                try:
                    flags = termios.ECHO | termios.ICANON
                    before = termios.tcgetattr(slave)[3] & flags
                    with subprocess.Popen(
                        [sys.executable, "-I", "-S", "-B", str(script)],
                        stdin=slave, stdout=slave, stderr=slave, env={**os.environ, "TERM": "xterm"},
                    ) as process:
                        try:
                            output = b""
                            deadline = time.monotonic() + 10
                            while b"?1049h" not in output:
                                remaining = max(0, deadline - time.monotonic())
                                self.assertTrue(select.select([master], [], [], remaining)[0], "Меню не открылось")
                                output += os.read(master, 8192)
                            self.assertEqual(termios.tcgetattr(slave)[3] & flags, 0)
                            process.send_signal(signum)
                            self.assertEqual(process.wait(timeout=5), 128 + signum)
                            self.assertEqual(termios.tcgetattr(slave)[3] & flags, before)
                        finally:
                            if process.poll() is None:
                                process.kill()
                finally:
                    os.close(master)
                    os.close(slave)
