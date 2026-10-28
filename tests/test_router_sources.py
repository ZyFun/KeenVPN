"""Источники чтения роутера поверх файлов Entware и `pidof`: модели, отказы и коды сценариев."""

import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import router_sources
from keenvpn.adapters.geodata_files import geo_inventory_from_files
from keenvpn.adapters.router_sources import (
    GEO_DATABASE_COUNT_LIMIT, PIDOF_OUTPUT_LIMIT, PIDOF_PATH, PIDOF_TIMEOUT, XKEEN_INIT_LIMIT, XKEEN_LIST_LIMIT,
    XKEEN_SETTINGS_LIMIT, XRAY_PART_COUNT_LIMIT, XRAY_PART_LIMIT, XRAY_PARTS_TOTAL_LIMIT, GeoDatabaseFiles,
    XKeenInitFile, XKeenListFiles, XKeenSettingsFile, XrayConfigFiles, XrayProcessObserver, run_read_command,
)
from keenvpn.adapters.xkeen_files import xkeen_init_from_bytes
from keenvpn.application.contract import ErrorCategory
from keenvpn.application.installation import read_geo_databases, read_xray_process
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler
from keenvpn.domain.config_document import ConfigDocumentError
from keenvpn.domain.xkeen_config import XKeenConfigError, XKeenListName
from keenvpn.domain.xray_process import XrayProcessError, XrayProcessObservation
from tests.support.isolation import forbid_external_effects
from tests.support.router_files import (
    GEODATA, INIT, READY, SYNTHETIC_GEOIP, SYNTHETIC_INIT, XKEEN, XRAY_CONFIGS, ScriptedCommand, write_router_snapshot,
)
from tests.support.snapshot import snapshot_xkeen_list, snapshot_xkeen_settings, snapshot_xray_config


Failure = RouterReadFailure
# Имена частей Xray и списков XKeen показываются представлением по контракту; пути и секреты — нет.
PRIVATE_MARKERS = ("fixture-password", "/fixture/ws", "192.0.2.", "2001:db8", "/opt/etc", "S05xkeen", "tmp/.xkeen")


class RouterFilesCase(unittest.TestCase):
    def setUp(self):
        # Реальный путь: на macOS временный каталог находится за ссылкой /var.
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-router-")))
        self.addCleanup(self._cleanup)
        write_router_snapshot(self.root)
        self.base = str(self.root)

    def _cleanup(self):
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        shutil.rmtree(self.root)

    def assert_failure(self, call, failure):
        with self.assertRaises(RouterReadError) as caught:
            call()
        self.assertIs(caught.exception.failure, failure)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(self.base, str(caught.exception) + repr(caught.exception))
        return caught.exception

    def assert_private(self, value):
        text = repr(value) + str(value)
        if hasattr(value, "to_dict"):
            text += json.dumps(value.to_dict(), ensure_ascii=False)
        self.assertNotIn(self.base, text)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)


class FileSourcesTests(RouterFilesCase):
    def test_sources_read_snapshot_files_into_the_same_models(self):
        self.assertEqual(XrayConfigFiles(root=self.base).current_xray_config(), snapshot_xray_config())
        self.assertEqual(XKeenSettingsFile(root=self.base).current_xkeen_settings(), snapshot_xkeen_settings())
        self.assertEqual(XKeenInitFile(root=self.base).current_xkeen_init(), xkeen_init_from_bytes(SYNTHETIC_INIT))
        lists = XKeenListFiles(root=self.base)
        for name in XKeenListName:
            with self.subTest(name=name):
                self.assertEqual(lists.current_xkeen_list(name), snapshot_xkeen_list(name))
        self.assertEqual(
            GeoDatabaseFiles(root=self.base).current_geo_databases(), geo_inventory_from_files({"geoip.dat": SYNTHETIC_GEOIP}),
        )

    def test_constructing_sources_touches_nothing(self):
        with forbid_external_effects():
            for source in (
                XrayConfigFiles(), XKeenSettingsFile(), XKeenInitFile(), XKeenListFiles(), GeoDatabaseFiles(),
                XrayProcessObserver(run=ScriptedCommand()),
            ):
                self.assertIsNotNone(source)

    def test_invalid_root_or_list_name_is_a_programming_error(self):
        for root in ("relative", "/tmp/", "/a/../b", "", None):
            with self.subTest(root=root), self.assertRaises(ValueError):
                XKeenSettingsFile(root=root)
        with self.assertRaises(TypeError):
            XKeenListFiles(root=self.base).current_xkeen_list("port_exclude.lst")
        with self.assertRaises(TypeError):
            XrayProcessObserver(run="pidof")

    def test_limits_match_the_verified_platform_with_margin(self):
        self.assertEqual(
            (XRAY_PART_LIMIT, XRAY_PART_COUNT_LIMIT, XRAY_PARTS_TOTAL_LIMIT, XKEEN_SETTINGS_LIMIT, XKEEN_INIT_LIMIT,
             XKEEN_LIST_LIMIT, GEO_DATABASE_COUNT_LIMIT, PIDOF_OUTPUT_LIMIT, PIDOF_PATH, PIDOF_TIMEOUT),
            (1024 * 1024, 64, 8 * 1024 * 1024, 256 * 1024, 1024 * 1024, 256 * 1024, 32, 64 * 1024, "/opt/bin/pidof", 3.0),
        )

    def test_missing_files_and_directories(self):
        for relative, read, failure in (
            (f"{XKEEN}/xkeen.json", lambda: XKeenSettingsFile(root=self.base).current_xkeen_settings(), Failure.MISSING),
            (INIT, lambda: XKeenInitFile(root=self.base).current_xkeen_init(), Failure.MISSING),
            (f"{XKEEN}/port_proxying.lst",
             lambda: XKeenListFiles(root=self.base).current_xkeen_list(XKeenListName.PORT_PROXYING), Failure.MISSING),
            (XRAY_CONFIGS, lambda: XrayConfigFiles(root=self.base).current_xray_config(), Failure.MISSING),
            (GEODATA, lambda: GeoDatabaseFiles(root=self.base).current_geo_databases(), Failure.MISSING),
        ):
            with self.subTest(path=relative):
                target = self.root / relative
                moved = target.with_name(target.name + ".moved")
                target.rename(moved)
                self.assert_failure(read, failure)
                moved.rename(target)

    def test_symlinked_or_oversized_files_are_rejected(self):
        settings = self.root / XKEEN / "xkeen.json"
        real = self.root / "real-xkeen.json"
        settings.rename(real)
        settings.symlink_to(real)
        self.assert_failure(lambda: XKeenSettingsFile(root=self.base).current_xkeen_settings(), Failure.UNSAFE)
        settings.unlink()
        real.rename(settings)
        (self.root / INIT).write_bytes(b"#" * (XKEEN_INIT_LIMIT + 1))
        self.assert_failure(lambda: XKeenInitFile(root=self.base).current_xkeen_init(), Failure.TOO_LARGE)
        (self.root / XRAY_CONFIGS / "09_link.json").symlink_to(settings)
        self.assert_failure(lambda: XrayConfigFiles(root=self.base).current_xray_config(), Failure.UNSAFE)

    def test_corrupt_content_raises_domain_errors_for_the_scenario(self):
        (self.root / XRAY_CONFIGS / "02_dns.json").write_bytes(b'{"dns": ')
        with self.assertRaises(ConfigDocumentError):
            XrayConfigFiles(root=self.base).current_xray_config()
        (self.root / XKEEN / "ip_exclude.lst").write_bytes(b"\xff\xfe")
        with self.assertRaises(XKeenConfigError):
            XKeenListFiles(root=self.base).current_xkeen_list(XKeenListName.IP_EXCLUDE)


class ProcessObserverTests(RouterFilesCase):
    def observe(self, outcome):
        command = ScriptedCommand(outcome)
        result = XrayProcessObserver(root=self.base, run=command).current_xray_process()
        self.assertEqual(command.calls, [((PIDOF_PATH, "xray"), PIDOF_TIMEOUT, PIDOF_OUTPUT_LIMIT)])
        return result

    def test_running_stopped_and_marker_states(self):
        self.assertEqual(self.observe((0, b"4242\n")), XrayProcessObservation((4242,), True))
        self.assertEqual(self.observe((0, b"4242 4343\n")), XrayProcessObservation((4242, 4343), True))
        (self.root / READY).unlink()
        self.assertEqual(self.observe((1, b"")), XrayProcessObservation((), False))
        self.assertEqual(self.observe((0, b"4242\n")).state.value, "process_without_marker")
        shutil.rmtree(self.root / "tmp/.xkeen")
        self.assertEqual(self.observe((1, b"")).state.value, "stopped")

    def test_unexpected_exit_status_or_marker_type_is_a_failure(self):
        for outcome in ((1, b"4242\n"), (2, b""), (0, b""), (0, b" \n"), (-9, b""), (127, b"")):
            with self.subTest(outcome=outcome):
                self.assert_failure(lambda: self.observe(outcome), Failure.EXIT_STATUS)
        for failure in (Failure.TIMEOUT, Failure.MISSING, Failure.TOO_LARGE, Failure.IO_ERROR):
            with self.subTest(failure=failure):
                self.assert_failure(lambda: self.observe(RouterReadError(failure)), failure)
        (self.root / READY).unlink()
        (self.root / READY).symlink_to(self.root / INIT)
        self.assert_failure(lambda: self.observe((0, b"4242\n")), Failure.UNSAFE)

    def test_wrong_runner_result_and_bad_output(self):
        for outcome in ((0, "4242"), ("0", b"4242"), (True, b"4242")):
            with self.subTest(outcome=outcome), self.assertRaises(TypeError):
                self.observe(outcome)
        for output in (b"abc\n", b"0\n", b"042\n", b"4242 4242\n", "٤".encode("utf-8") + b"\n"):
            with self.subTest(output=output), self.assertRaises(XrayProcessError):
                self.observe((0, output))


class RunReadCommandTests(unittest.TestCase):
    def assert_failure(self, call, failure):
        try:
            raise ValueError("fixture-private-context")
        except ValueError:
            with self.assertRaises(RouterReadError) as caught:
                call()
        self.assertIs(caught.exception.failure, failure)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("fixture-private", str(caught.exception) + repr(caught.exception))

    def test_runs_argument_list_without_shell_with_closed_stdin_empty_env(self):
        with patch.object(router_sources.subprocess, "Popen", side_effect=OSError(errno.E2BIG, "сбой", "/fixture-private")) as popen:
            self.assert_failure(lambda: run_read_command(("/opt/bin/pidof", "xray"), 3.0, 64), Failure.IO_ERROR)
        popen.assert_called_once_with(
            ["/opt/bin/pidof", "xray"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={}, close_fds=True,
        )
        self.assertNotIn("shell", popen.call_args.kwargs)

    def test_launch_failures(self):
        for error, failure in (
            (FileNotFoundError(errno.ENOENT, "нет", "/fixture-private"), Failure.MISSING),
            (PermissionError(errno.EACCES, "нет", "/fixture-private"), Failure.PERMISSION_DENIED),
            (OSError(errno.E2BIG, "сбой", "/fixture-private"), Failure.IO_ERROR),
            (subprocess.SubprocessError("fixture-private"), Failure.IO_ERROR),
        ):
            with self.subTest(error=type(error).__name__), patch.object(router_sources.subprocess, "Popen", side_effect=error):
                self.assert_failure(lambda: run_read_command(("/opt/bin/pidof", "xray"), 3.0, 64), failure)

    def test_real_output_up_to_the_limit_and_one_byte_over(self):
        exact = "import sys; sys.stdout.write('7' * 64)"
        self.assertEqual(run_read_command((sys.executable, "-I", "-S", "-B", "-c", exact), 30.0, 64), (0, b"7" * 64))
        over = "import sys; sys.stdout.write('7' * 65)"
        self.assert_failure(lambda: run_read_command((sys.executable, "-I", "-S", "-B", "-c", over), 30.0, 64), Failure.TOO_LARGE)

    def test_real_output_over_limit_fails_before_the_command_ends(self):
        # Команда выводит больше предела и продолжает работать: отказ — too_large сразу, а не timeout по сроку.
        script = "import sys, time; sys.stdout.write('x' * 70000); sys.stdout.flush(); time.sleep(30)"
        started = time.monotonic()
        self.assert_failure(
            lambda: run_read_command((sys.executable, "-I", "-S", "-B", "-c", script), 10.0, 64 * 1024), Failure.TOO_LARGE,
        )
        self.assertLess(time.monotonic() - started, 8.0)

    def test_real_interpreter_exit_status_output_and_timeout(self):
        # Настоящий запуск: команда задана массивом, без shell и с пустым окружением.
        script = "import os, sys; sys.stdout.write(os.environ.get('KEENVPN_TEST_MARKER', 'absent')); sys.exit(3)"
        with patch.dict(os.environ, {"KEENVPN_TEST_MARKER": "fixture-private"}):
            status, output = run_read_command((sys.executable, "-I", "-S", "-B", "-c", script), 30.0, 64)
        self.assertEqual((status, output), (3, b"absent"))
        started = time.monotonic()
        self.assert_failure(
            lambda: run_read_command((sys.executable, "-I", "-S", "-B", "-c", "import time; time.sleep(30)"), 0.5, 64),
            Failure.TIMEOUT,
        )
        self.assertLess(time.monotonic() - started, 8.0)
        # Вывод без завершения тоже упирается в общий срок.
        chatty = "import sys, time; sys.stdout.write('1'); sys.stdout.flush(); time.sleep(30)"
        self.assert_failure(lambda: run_read_command((sys.executable, "-I", "-S", "-B", "-c", chatty), 0.5, 64), Failure.TIMEOUT)
        self.assert_failure(lambda: run_read_command(("/nonexistent/keenvpn-pidof",), 5.0, 64), Failure.MISSING)


class ScenarioTests(RouterFilesCase):
    def handler(self):
        base = self.base
        return InspectProxyConfigHandler(
            XrayConfigFiles(root=base), XKeenSettingsFile(root=base), XKeenInitFile(root=base), XKeenListFiles(root=base),
            operation_ids=lambda: "op-1",
        )

    def assert_failed(self, result, category, code, reason):
        self.assertFalse(result.succeeded)
        self.assertIs(result.error.category, category)
        self.assertEqual((result.error.code, result.error.reason), (code, reason))
        self.assert_private(result)

    def test_proxy_config_is_read_from_files_without_private_values(self):
        result = self.handler().execute(InspectProxyConfig())
        self.assertTrue(result.succeeded)
        self.assert_private(result)

    def test_scenario_codes_for_file_failures_and_corrupt_data(self):
        cases = (
            (lambda: (self.root / XKEEN / "xkeen.json").unlink(),
             ErrorCategory.SOURCE_FAILED, "xkeen_settings_unavailable", "missing"),
            (lambda: (self.root / INIT).write_bytes(b"#" * (XKEEN_INIT_LIMIT + 1)),
             ErrorCategory.SOURCE_FAILED, "xkeen_init_unavailable", "too_large"),
            (lambda: (self.root / XRAY_CONFIGS / "05_routing.json").write_bytes(b"{"),
             ErrorCategory.INVALID_SOURCE_DATA, "invalid_xray_config", "invalid_document_json"),
            (lambda: (self.root / XKEEN / "port_exclude.lst").write_bytes(b"\xff"),
             ErrorCategory.INVALID_SOURCE_DATA, "invalid_xkeen_port_exclude", "invalid_xkeen_list"),
            (lambda: os.mkfifo(self.root / XRAY_CONFIGS / "08_fifo.json"),
             ErrorCategory.SOURCE_FAILED, "xray_config_unavailable", "unsafe"),
        )
        for index, (damage, category, code, reason) in enumerate(cases):
            with self.subTest(code=code):
                self._cleanup()
                self.root.mkdir()
                write_router_snapshot(self.root)
                damage()
                self.assert_failed(self.handler().execute(InspectProxyConfig()), category, code, reason)

    def test_geodata_and_process_readers_keep_reasons(self):
        self.assertEqual(read_geo_databases(GeoDatabaseFiles(root=self.base)).files[0].name, "geoip.dat")
        shutil.rmtree(self.root / GEODATA)
        error = read_geo_databases(GeoDatabaseFiles(root=self.base))
        self.assertEqual((error.code, error.reason), ("geo_databases_unavailable", "missing"))
        error = read_xray_process(XrayProcessObserver(root=self.base, run=ScriptedCommand(RouterReadError(Failure.TIMEOUT))))
        self.assertEqual((error.code, error.reason), ("xray_process_unavailable", "timeout"))
        error = read_xray_process(XrayProcessObserver(root=self.base, run=ScriptedCommand((0, b"abc\n"))))
        self.assertEqual((error.category, error.code, error.reason), (
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_xray_process", "invalid_xray_process_observation",
        ))
        self.assert_private(error)


if __name__ == "__main__":
    unittest.main()
