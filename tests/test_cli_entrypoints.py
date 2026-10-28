"""Точки входа vpn-menu и vpn-setup: коды завершения, прерывание, аргументы и запуск скриптов."""

import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from keenvpn.interfaces.cli.composition import MenuSources
from keenvpn.interfaces.cli.entrypoints import (
    EXIT_FAILURE, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, FAILURE_MESSAGE, INTERRUPTED_MESSAGE, READ_ROUTER_FLAG,
    vpn_menu, vpn_setup,
)
from keenvpn.interfaces.cli.terminal import UNAVAILABLE_MARK
from keenvpn.interfaces.cli.tree import MAIN_MENU_TITLE, SETUP_MENU_TITLE
from tests.support.in_memory import InMemoryXrayProcessSource
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import synthetic_xray_process


class Interrupting:
    def readline(self, size=-1):
        raise KeyboardInterrupt


def call(entry, argv, text):
    stdout, stderr = io.StringIO(), io.StringIO()
    with forbid_external_effects():
        code = entry(argv, io.StringIO(text), stdout, stderr)
    return code, stdout.getvalue(), stderr.getvalue()


class EntrypointTests(unittest.TestCase):
    def test_menu_exits_on_zero_and_eof(self):
        for text in ("0\n", "", "4\n0\n0\n", "10\n5\n0\n0\n"):
            with self.subTest(text=text):
                code, out, err = call(vpn_menu, [], text)
                self.assertEqual(code, EXIT_OK)
                self.assertTrue(out.startswith(MAIN_MENU_TITLE + "\n"))
                self.assertEqual(err, "")
                self.assertNotIn("\x1b", out)
        # Источники роутера не подключены: шапка показывает области «не проверено», а не исправность.
        code, out, _ = call(vpn_menu, [], "0\n")
        self.assertTrue(out.startswith(
            f"{MAIN_MENU_TITLE}\nСостояние по источникам, активная сетевая проверка не выполнялась:\n"
            "  Ядро Xray: не проверено\n  Перехват: не поддерживается\n",
        ))

    def test_setup_shows_wizard_items_as_unavailable(self):
        code, out, err = call(vpn_setup, [], "1\n0\n")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(out.startswith(SETUP_MENU_TITLE + "\n"))
        self.assertEqual(out.count(UNAVAILABLE_MARK), 10)
        self.assertIn("Пункт не реализован в этой версии меню", out)
        self.assertEqual(err, "")

    def test_arguments_are_rejected_without_opening_the_menu(self):
        expected = {"vpn-menu": "vpn-menu принимает только флаг --read-router.\n", "vpn-setup": "vpn-setup не принимает аргументов.\n"}
        for entry, command in ((vpn_menu, "vpn-menu"), (vpn_setup, "vpn-setup")):
            for argv in (
                ["--help"], ["0"], ["a", "b"], ("x",), ["--read-router", "--read-router"], ["--read-router=1"],
                ["--READ-ROUTER"], ["TEST_secret_argument"], ["--read-router", "TEST_secret_argument"],
            ):
                with self.subTest(command=command, argv=argv), \
                        patch("keenvpn.interfaces.cli.entrypoints.router_sources") as sources:
                    code, out, err = call(entry, argv, "0\n")
                    self.assertEqual(code, EXIT_USAGE)
                    self.assertEqual(out, "")
                    self.assertEqual(err, expected[command])
                    sources.assert_not_called()
        code, out, err = call(vpn_setup, [READ_ROUTER_FLAG], "0\n")
        self.assertEqual((code, out, err), (EXIT_USAGE, "", "vpn-setup не принимает аргументов.\n"))

    def test_read_router_flag_connects_router_sources_and_default_does_not(self):
        connected = MenuSources(process=InMemoryXrayProcessSource(synthetic_xray_process()))
        with patch("keenvpn.interfaces.cli.entrypoints.router_sources", return_value=connected) as sources:
            code, out, err = call(vpn_menu, [READ_ROUTER_FLAG], "0\n")
            self.assertEqual((code, err), (EXIT_OK, ""))
            sources.assert_called_once_with()
            self.assertIn("  Ядро Xray: работает\n", out)
            sources.reset_mock()
            code, out, err = call(vpn_menu, [], "0\n")
            self.assertEqual((code, err), (EXIT_OK, ""))
            sources.assert_not_called()
            self.assertIn("  Ядро Xray: не проверено\n", out)

    def test_keyboard_interrupt_gives_fixed_message_and_130(self):
        for entry in (vpn_menu, vpn_setup):
            stdout, stderr = io.StringIO(), io.StringIO()
            with forbid_external_effects():
                code = entry([], Interrupting(), stdout, stderr)
            self.assertEqual(code, EXIT_INTERRUPTED)
            self.assertEqual(stderr.getvalue(), INTERRUPTED_MESSAGE + "\n")
            self.assertNotIn("Traceback", stdout.getvalue() + stderr.getvalue())

    def test_unexpected_exception_gives_fixed_message_without_details(self):
        for name in ("assemble_main_menu", "assemble_setup_menu"):
            entry = vpn_menu if name == "assemble_main_menu" else vpn_setup
            with self.subTest(entry=name), patch(
                f"keenvpn.interfaces.cli.entrypoints.{name}", side_effect=ValueError("/private/path TEST_ONLY_SECRET"),
            ):
                code, out, err = call(entry, [], "0\n")
            self.assertEqual(code, EXIT_FAILURE)
            self.assertEqual(err, FAILURE_MESSAGE + "\n")
            self.assertEqual(out, "")
            self.assertNotIn("TEST_ONLY_SECRET", out + err)


class ScriptTests(unittest.TestCase):
    """Запуск тонких скриптов настоящим интерпретатором; роутер и сеть не нужны."""

    def run_script(self, name: str, argv=(), text: str = "") -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(ROOT / "scripts" / name), *argv],
            input=text, capture_output=True, text=True, timeout=120, cwd=ROOT,
        )

    def test_vpn_menu_script_exits_on_zero(self):
        completed = self.run_script("vpn_menu.py", text="0\n")
        self.assertEqual(completed.returncode, EXIT_OK, completed.stderr)
        self.assertTrue(completed.stdout.startswith(MAIN_MENU_TITLE + "\n"))
        self.assertEqual(completed.stderr, "")
        self.assertNotIn("\x1b", completed.stdout)

    def test_vpn_setup_script_exits_on_eof(self):
        completed = self.run_script("vpn_setup.py")
        self.assertEqual(completed.returncode, EXIT_OK, completed.stderr)
        self.assertIn(SETUP_MENU_TITLE, completed.stdout)
        self.assertEqual(completed.stderr, "")

    def test_scripts_reject_arguments(self):
        completed = self.run_script("vpn_menu.py", argv=["--version"], text="0\n")
        self.assertEqual(completed.returncode, EXIT_USAGE)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "vpn-menu принимает только флаг --read-router.\n")


if __name__ == "__main__":
    unittest.main()
