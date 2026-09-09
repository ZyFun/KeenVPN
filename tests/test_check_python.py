"""Проверки диагностики Python без роутера, сети и установленного менеджера."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_python.py"
SPEC = importlib.util.spec_from_file_location("check_python", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
SUPPORTED_VERSION = (3, 12, 0, "final", 0)


class VersionTests(unittest.TestCase):
    def test_version_boundaries_and_release_level(self):
        """Нижняя граница, другая реализация и prerelease различаются."""
        cases = (
            ((3, 11, 99, "final", 0), "cpython", False),
            (SUPPORTED_VERSION, "cpython", True),
            ((3, 13, 9, "final", 0), "cpython", True),
            ((3, 14, 0, "candidate", 1), "cpython", False),
            ((4, 0, 0, "final", 0), "cpython", False),
            (SUPPORTED_VERSION, "pypy", False),
        )
        for version, implementation, expected in cases:
            with self.subTest(version=version, implementation=implementation):
                self.assertEqual(checker.version_is_eligible(version, implementation), expected)

    def test_unsupported_version_does_not_import_optional_parts(self):
        """В старой среде причина отказа видна даже без остальных модулей."""
        def forbidden_import(name):
            raise AssertionError("Импорт не должен вызываться")

        results = checker.check_python((3, 9, 6, "final", 0), "cpython", forbidden_import)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0][1])


class RequirementTests(unittest.TestCase):
    def check_with(self, replacements):
        """Подменить только выбранные модули, остальные загрузить штатно."""
        def importer(name):
            if name in replacements:
                value = replacements[name]
                if isinstance(value, Exception):
                    raise value
                return value
            return checker.import_module(name)

        return dict(checker.check_python(SUPPORTED_VERSION, "cpython", importer))

    def test_missing_module_and_transitive_import_failure_are_reported(self):
        """Сбой зависимости не теряется и не мешает сообщить о других модулях."""
        for error in (ModuleNotFoundError("TEST_SECRET"), ImportError("TEST_SECRET"), OSError("TEST_SECRET")):
            with self.subTest(error=type(error).__name__):
                report = self.check_with({"ssl": error})
                self.assertFalse(report["Импорт ssl"])
                self.assertTrue(report["Импорт json"])
                self.assertNotIn("Контекст TLS с проверкой имени и сертификата", report)
                self.assertNotIn("TEST_SECRET", repr(report))

    def test_successful_import_does_not_hide_missing_api(self):
        """Облегчённый модуль может импортироваться, но не содержать нужное API."""
        for name, label in (("fcntl", "API блокировки flock"), ("tarfile", "Фильтр tarfile.data_filter"), ("os", "API файловых операций POSIX")):
            with self.subTest(module=name):
                report = self.check_with({name: types.SimpleNamespace()})
                self.assertTrue(report["Импорт " + name])
                self.assertFalse(report[label])

    def test_tls_failure_is_reported_without_exception_text(self):
        """Недоступная криптобиблиотека не становится успешной проверкой HTTPS."""
        with patch.object(ssl, "SSLContext", side_effect=OSError("TEST_SECRET")):
            report = self.check_with({})
        self.assertFalse(report["Контекст TLS с проверкой имени и сертификата"])
        self.assertNotIn("TEST_SECRET", repr(report))

    def test_unverified_tls_context_is_rejected(self):
        """Наличие SSL не оправдывает отключённую проверку сертификатов."""
        for hostname, verify_mode in ((False, ssl.CERT_REQUIRED), (True, ssl.CERT_NONE)):
            context = types.SimpleNamespace(check_hostname=hostname, verify_mode=verify_mode)
            with patch.object(ssl, "SSLContext", return_value=context):
                report = self.check_with({})
            self.assertFalse(report["Контекст TLS с проверкой имени и сертификата"])

    def test_memory_probe_does_not_connect_spawn_or_write_keylog(self):
        """Проверка не использует сеть, процессы, замену файлов и TLS key log."""
        with tempfile.TemporaryDirectory() as directory:
            keylog = Path(directory) / "tls-keys.log"
            with (
                patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}),
                patch.object(socket, "create_connection", side_effect=AssertionError("Сеть запрещена")),
                patch.object(socket, "socket", side_effect=AssertionError("Сокеты запрещены")),
                patch.object(subprocess, "Popen", side_effect=AssertionError("Процессы запрещены")),
                patch.object(os, "replace", side_effect=AssertionError("Запись запрещена")),
            ):
                report = self.check_with({})
            self.assertTrue(all(report.values()), report)
            self.assertFalse(keylog.exists())


class CommandTests(unittest.TestCase):
    def test_command_exit_code_and_safe_output(self):
        """Отрицательный отчёт даёт ненулевой код, положительный не обещает работу VPN."""
        for passed, expected_code in ((True, 0), (False, 1)):
            with patch.object(checker, "check_python", return_value=[("Импорт ssl", passed)]):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(checker.main([]), expected_code)
                self.assertIn("Не проверены:", output.getvalue())
                self.assertNotIn("Traceback", output.getvalue())

    def test_arguments_are_not_echoed(self):
        """Ошибочно переданный секрет не попадает в сообщение об использовании."""
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(checker.main(["TEST_SECRET"]), 2)
        self.assertNotIn("TEST_SECRET", output.getvalue())

    def test_real_isolated_interpreter(self):
        """Проверить настоящий запуск, а не только подменённый номер версии."""
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(SCRIPT)],
            capture_output=True, text=True, timeout=20, check=False,
        )
        eligible = checker.version_is_eligible(sys.version_info, sys.implementation.name)
        self.assertEqual(result.returncode, 0 if eligible else 1, result.stdout + result.stderr)
        self.assertIn("Не проверены:", result.stdout)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
