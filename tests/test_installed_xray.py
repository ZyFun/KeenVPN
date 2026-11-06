"""Проверка прикладной команды и временной подготовки без настоящего Xray и бинарных баз."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_candidate_test as adapter
from keenvpn.application.xray_candidate import (
    CandidateAsset, CheckInstalledXray, CheckInstalledXrayHandler, XrayTestInput, XrayTestOutcome as Outcome,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.routing import GeoDatabaseKind as Kind
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.in_memory import InMemoryDraftSessionStore
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_MARKERS, reachable
from tests.test_application_draft_baseline_check import FIRST_ID, OPERATION, Source, current_fingerprints, draft_bytes, token


IP = b"TEST_IP\nTEST_PRIVATE"
SITE = b"TEST_SITE\nTEST_ADS"
BANNER = b"Xray 26.3.27 (TEST_build)\nConfiguration OK.\n"
RULE = {"outboundTag": "TEST_out", "ip": ["geoip:!TEST_IP"], "domain": ["geosite:TEST_SITE@test"]}


def asset(kind, name, data):
    return CandidateAsset(kind, name, hashlib.sha256(data).hexdigest(), data)


def config(rules=(RULE,), **extra):
    raw = {"routing": {"rules": list(rules)}, "outbounds": [{"protocol": "freedom", "tag": "TEST_out"}], **extra}
    first = ConfigDocument("TEST_z.json", b'/* TEST_secret */ {"TEST_unknown":null}')
    second = ConfigDocument("TEST_a_tail.json", json.dumps(raw).encode())
    return XrayConfigSet((first, second))


def command(**changes):
    args = dict(draft_id=FIRST_ID, expected_revision=token(draft_bytes()), xray=config(),
                assets=(asset(Kind.GEOIP, "geoip.dat", IP), asset(Kind.GEOSITE, "geosite.dat", SITE)))
    return CheckInstalledXray(**(args | changes))


class Tester:
    def __init__(self):
        self.outcome = Outcome.PASSED
        self.calls = []
        self.hook = lambda: None

    def test(self, candidate):
        self.calls.append(candidate)
        self.hook()
        return self.outcome


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.port = Tester()
        self.store = InMemoryDraftSessionStore(draft_bytes())
        self.sources = current_fingerprints()
        self.handler = CheckInstalledXrayHandler(self.store, self.sources, self.port, operation_ids=lambda: OPERATION)

    def execute(self, cmd):
        with forbid_external_effects():
            result = self.handler.execute(cmd)
        public = repr(result) + json.dumps(result.to_dict()) + repr(cmd)
        for value in (*UNSAFE_MARKERS, "TEST_", FIRST_ID, token(draft_bytes()), hashlib.sha256(IP).hexdigest()):
            self.assertNotIn(value, public)
        self.assertFalse(any(isinstance(x, (BaseException, bytes, ConfigDocument, CandidateAsset)) for x in reachable(result)))
        self.assertFalse(self.store.create_calls or self.store.remove_calls or self.store.confirm_calls)
        return result

    def test_input_is_detached_and_ordered_and_binds_both_kinds(self):
        cmd = command()
        result = self.execute(cmd)
        self.assertEqual(result.data.to_dict(), dict(code="installed_xray_candidate", status="passed", network=False, reason=None))
        request, = self.port.calls
        self.assertEqual(request.parts, tuple((p.name, p.content) for p in cmd.xray.parts))
        self.assertEqual(set(request.categories), {(Kind.GEOIP, "geoip.dat", "TEST_IP"), (Kind.GEOSITE, "geosite.dat", "TEST_SITE")})
        self.assertIsNot(request.assets[0], cmd.assets[0])
        self.assertNotIn("TEST_", repr(request) + repr(request.assets))

    def test_only_effective_references_count_and_no_success_without_both(self):
        for rule in ({"ip": ["geoip:TEST_IP"]}, {"domain": ["geosite:TEST_SITE"]}, {}):
            replaced = ConfigDocument("TEST_end.json", json.dumps({"routing": {"rules": [dict(rule, outboundTag="TEST_out")]}}).encode())
            candidate = XrayConfigSet((*config().parts, replaced))
            self.assertEqual(self.execute(command(xray=candidate)).data.reason, "both_geo_references_required")
        self.assertFalse(self.port.calls)

    def test_handler_without_tester_reports_unavailable(self):
        self.handler = CheckInstalledXrayHandler(self.store, self.sources, operation_ids=lambda: OPERATION)
        result = self.execute(command())
        self.assertIsNone(result.data)
        self.assertEqual((result.error.code, result.error.reason), ("xray_test_unavailable", "xray_isolation_unavailable"))

    def test_dns_and_custom_resource_bindings(self):
        dns = {"servers": [{"address": "198.51.100.2", "domains": ["geosite:TEST_SITE", "ext:TEST_extra.dat:TEST_ADS"],
                            "expectedIPs": ["geoip:TEST_IP"], "expectIPs": ["ext:TEST_ignored.dat:TEST_unused"]}]}
        cmd = command(xray=config((), dns=dns))
        self.assertEqual(self.execute(cmd).data.reason, "candidate_assets_mismatch")
        complete = replace(cmd, assets=(*cmd.assets, asset(Kind.GEOSITE, "TEST_extra.dat", SITE)))
        self.assertEqual(self.execute(complete).data.status.value, "passed")
        self.assertIn((Kind.GEOSITE, "TEST_extra.dat", "TEST_ADS"), self.port.calls[0].categories)

    def test_mismatch_missing_empty_duplicate_and_invalid_reference(self):
        cmd = command()
        ip, site = cmd.assets
        for items, expected in (((), "candidate_assets_mismatch"), ((site,), "candidate_assets_mismatch"),
                                ((ip, replace(site, kind=Kind.GEOIP)), "candidate_assets_mismatch"),
                                ((ip, replace(site, sha256="0" * 64)), "candidate_asset_digest"),
                                ((ip, replace(site, content=b"")), "candidate_asset_size")):
            self.assertEqual(self.execute(replace(cmd, assets=items)).data.reason, expected)
        self.assertIsNotNone(self.execute(replace(cmd, assets=(ip, site, site))).error)
        invalid = config((dict(RULE, domain=["ext:../TEST_private:TEST_site"]),))
        self.assertEqual(self.execute(replace(cmd, xray=invalid)).data.reason, "candidate_references_incomplete")
        self.assertFalse(self.port.calls)

    def test_closed_outcomes_and_exception_privacy(self):
        forged = object.__new__(Outcome)
        object.__setattr__(forged, "_value_", "TEST_rogue")
        for bad in (forged, "passed", object()):
            self.port.outcome = bad
            self.assertEqual(self.execute(command()).error.reason, "invalid_port_response")
        self.port.hook = lambda: (_ for _ in ()).throw(OSError("TEST_secret"))
        self.assertEqual(self.execute(command()).error.reason, "xray_execution_failed")

    def test_invalid_type_damaged_command_and_version(self):
        cmd = command()
        for item in (replace(cmd, expected_revision=42), replace(cmd, contract_version=True), replace(cmd, xray=None)):
            self.assertIsNotNone(self.execute(item).error)
        object.__delattr__(cmd, "assets")
        self.assertIsNotNone(self.execute(cmd).error)
        self.assertFalse(self.port.calls)

    def test_conflicts_before_and_during_execution(self):
        self.assertIsNotNone(self.execute(command(expected_revision=token(b"TEST_other"))).error)
        self.assertFalse(self.port.calls)
        self.port.hook = lambda: self.sources.set_response(Source.XRAY_CONFIGS, RuntimeError("TEST_read"))
        self.assertIsNotNone(self.execute(command()).error)
        self.assertEqual(len(self.port.calls), 1)


    def test_complexity_is_bounded_before_decoding_and_string_list_expansion(self):
        cases = (b'{"routing":{"rules":[{"domain":"geosite:X' + b',' * 65 + b'"}]}}',
                 b'{"routing":{"rules":[{"domain":"geosite:X' + br"\u002C" * 65 + b'"}]}}',
                 b'{"TEST_extra":[' + b"0," * 65 + b'0]}')
        for raw in cases:
            cmd = command(xray=XrayConfigSet((ConfigDocument("TEST_many.json", raw),)))
            with patch("keenvpn.application.xray_candidate.MAX_CONFIG_SEPARATORS", 64):
                self.assertEqual(self.execute(cmd).error.code, "invalid_command")
        self.assertFalse(self.port.calls)

    def test_unicode_category_cannot_attest_to_another_xray_code(self):
        candidate = config((dict(RULE, domain=["geosite:straße"]),))
        self.assertEqual(self.execute(command(xray=candidate)).data.reason, "candidate_references_incomplete")
        self.assertFalse(self.port.calls)

    def test_preparation_interrupt_is_structured_and_revision_has_priority(self):
        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt("TEST_interrupted")
        with patch("keenvpn.application.xray_candidate._parts", side_effect=interrupt):
            self.assertEqual(self.execute(command()).error.reason, "xray_test_interrupted")
        def changed(*args, **kwargs):
            self.sources.set_response(Source.XRAY_CONFIGS, RuntimeError("TEST_changed"))
            raise KeyboardInterrupt
        with patch("keenvpn.application.xray_candidate._parts", side_effect=changed):
            self.assertNotEqual(self.execute(command()).error.reason, "xray_test_interrupted")
        self.assertFalse(self.port.calls)


class ManagedRunner:
    """Модель отдельно работающей группы. Категории кодируются строками только в этом двойнике."""

    def __init__(self):
        self.on_start = lambda invocation: None
        self.reply = adapter.XrayTestExit(0, BANNER, b"", False)
        self.calls = 0
        self.reaped = False
        self.request = None
        self.job = None
        self.group = None
        self.snapshot = {}

    def reserve_staging(self, job, parent_fd):
        self.job = job
        return True

    def release_staging(self, job):
        if self.job == job:
            self.job = None

    def start(self, invocation):
        self.request = invocation
        self.calls += 1
        assert invocation.job == self.job
        self.group = invocation.job
        self.snapshot = {}
        for entry in invocation.files:
            data = os.pread(entry.descriptor, entry.size + 1, 0)
            if len(data) != entry.size or hashlib.sha256(data).digest() != entry.sha256:
                raise adapter.IsolationUnavailable
            self.snapshot[entry.name] = data
        self.on_start(invocation)

    def collect(self, job):
        assert self.group == job
        if isinstance(self.reply, BaseException):
            raise self.reply
        return self.reply

    def terminate_and_wait(self, job):
        if self.group == job:
            self.group = None
        self.reaped = True


class StagingTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.parent = Path(tmp.name).resolve()
        self.runner = ManagedRunner()
        self.staged = adapter.StagedXrayTest(str(self.parent), self.runner)
        self.store = InMemoryDraftSessionStore(draft_bytes())
        self.handler = CheckInstalledXrayHandler(self.store, current_fingerprints(), self.staged, operation_ids=lambda: OPERATION)

    def execute(self, cmd=None):
        with patch("subprocess.Popen", side_effect=AssertionError), patch("socket.socket", side_effect=AssertionError):
            result = self.handler.execute(cmd or command())
        self.assertEqual(list(self.parent.iterdir()), [])
        self.assertNotIn("TEST_", repr(result) + json.dumps(result.to_dict()))
        return result

    def test_workspace_protocol_and_original_bytes(self):
        cmd = command()
        def inspect(req):
            root, = self.parent.iterdir()
            self.assertEqual(self.runner.snapshot["assets/geoip.dat"], IP)
            self.assertEqual(req.argv, (adapter.XRAY_BINARY, "run", "-test", "-format", "json", "-c", "parts/000.json",
                                        "-c", "parts/001-tail.json"))
            self.assertEqual(req.environment, (("XRAY_LOCATION_ASSET", "assets"),))
            self.assertEqual(req.required_version, "26.3.27")
            self.assertEqual(req.memory_limit, 256 * 1024 * 1024)
            self.assertEqual(req.output_limit, 65536)
            self.assertEqual([p.read_bytes() for p in sorted((root / "parts").iterdir())],
                             [p.content for p in cmd.xray.parts])
            for path in (root, *root.rglob("*")):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
            for resource in cmd.assets:
                data = (root / "assets" / resource.name).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), resource.sha256)
            self.assertNotIn("TEST_", repr(req) + repr(req.argv))
        self.runner.on_start = inspect
        self.assertEqual(self.execute(cmd).data.status.value, "passed")
        self.assertTrue(self.runner.reaped)

    def test_explicit_lower_memory_limit_reaches_the_runner_unchanged(self):
        staged = adapter.StagedXrayTest(str(self.parent), self.runner, memory_limit=128 * 1024 * 1024)
        self.handler = CheckInstalledXrayHandler(self.store, current_fingerprints(), staged)
        self.assertEqual(self.execute().data.status.value, 'passed')
        self.assertEqual(self.runner.request.memory_limit, 128 * 1024 * 1024)

    def test_invalid_or_increased_memory_limit_has_no_staging_effects(self):
        for limit in (True, 0, -1, 268435457, 128.0, None):
            staged = adapter.StagedXrayTest(str(self.parent), self.runner, memory_limit=limit)
            self.assertIs(staged.test(None), Outcome.ISOLATION)
        self.assertEqual(list(self.parent.iterdir()), [])
        self.assertEqual(self.runner.calls, 0)

    def test_fake_loader_rejects_missing_category_and_corrupt_candidate(self):
        def inspect(req):
            for _, name, code in req.categories:
                if code.encode() not in self.runner.snapshot["assets/" + name].splitlines():
                    self.runner.reply = adapter.XrayTestExit(23, b"TEST_path", b"TEST_password", False)
        self.runner.on_start = inspect
        for kind, name, data in ((Kind.GEOIP, "geoip.dat", b"TEST_wrong"), (Kind.GEOSITE, "geosite.dat", b"\xff")):
            cmd = command()
            items = tuple(asset(kind, name, data) if a.kind is kind else a for a in cmd.assets)
            self.assertEqual(self.execute(replace(cmd, assets=items)).data.reason, "xray_candidate_rejected")
            self.assertTrue(self.runner.reaped)

    def test_absent_binary_unsupported_version_and_isolation(self):
        for error, reason in ((FileNotFoundError(), "xray_binary_missing"), (adapter.UnsupportedXrayVersion(), "xray_version_unsupported"),
                              (adapter.IsolationUnavailable(), "xray_isolation_unavailable"), (PermissionError(), "xray_execution_failed")):
            self.runner.on_start = lambda req: (_ for _ in ()).throw(error)
            result = self.execute()
            self.assertEqual((result.error or result.data).reason, reason)
        absent = adapter.StagedXrayTest(str(self.parent))
        self.assertIs(absent.test(None), Outcome.ISOLATION)

    def test_timeout_cancel_and_output_errors_terminate_group(self):
        for reply, reason in ((TimeoutError(), "xray_test_timeout"), (KeyboardInterrupt(), "xray_test_interrupted"),
                              (adapter.OutputLimitExceeded(), "xray_output_limit"), (object(), "xray_output_invalid"),
                              (adapter.XrayTestExit(0, b"x", b"x" * 65536, False), "xray_output_limit"),
                              (adapter.XrayTestExit(0, BANNER, b"\xff", False), "xray_output_invalid"),
                              (adapter.XrayTestExit(0, b"Configuration OK.\n", b"", False), "xray_output_invalid"),
                              (adapter.XrayTestExit(1, BANNER, b"", False), "xray_execution_failed")):
            self.runner.reaped = False
            self.runner.reply = reply
            self.assertEqual(self.execute().error.reason, reason)
            self.assertTrue(self.runner.reaped)
        self.runner.reply = adapter.XrayTestExit(0, BANNER, b"", False)
        with patch.object(adapter, "monotonic", side_effect=(20, 50)):
            self.assertEqual(self.execute().error.reason, "xray_test_timeout")

    def test_changes_group_cleanup_and_no_space(self):
        def tamper(req):
            root, = self.parent.iterdir()
            (root / "assets" / "geoip.dat").write_bytes(b"TEST_altered")
        self.runner.on_start = tamper
        self.assertEqual(self.execute().error.reason, "xray_staging_changed")
        self.runner.on_start = lambda req: None
        with patch.object(self.runner, "terminate_and_wait", side_effect=OSError("TEST_failed")):
            self.assertEqual(self.execute().error.reason, "xray_cleanup_failed")
        with patch.object(adapter.os, "mkdir", side_effect=OSError(28, "TEST_full")):
            self.assertEqual(self.execute().error.reason, "xray_staging_failed")

    def test_unsafe_parent_is_not_used(self):
        self.parent.chmod(0o755)
        self.assertEqual(self.execute().error.reason, "xray_staging_failed")
        self.assertEqual(self.runner.calls, 0)
        self.assertIs(adapter.StagedXrayTest("/opt/etc/xray/configs", self.runner).test(None), Outcome.FILES)

    def test_direct_port_input_rechecked_before_file_creation(self):
        empty = XrayTestInput((("TEST_x.json", b"{}"),), (), ())
        captured = Tester()
        CheckInstalledXrayHandler(self.store, current_fingerprints(), captured, operation_ids=lambda: OPERATION).execute(command())
        good, = captured.calls
        with patch.object(adapter.os, "mkdir", side_effect=AssertionError):
            for bad in (empty, replace(good, categories=()), replace(good, categories=(("geoip", "geoip.dat", "TEST_IP"),)),
                        replace(good, assets=good.assets[:1]), replace(good, parts=good.parts * 65)):
                self.assertIs(self.staged.test(bad), Outcome.CHANGED)
        self.assertEqual(self.runner.calls, 0)

    def test_staged_bytes_rechecked_even_when_initial_stat_already_sees_substitution(self):
        original = adapter.os.fstat
        for payload in (IP, command().xray.parts[0].content):
            changed = []
            def corrupt(fd):
                info = original(fd)
                if not changed and stat.S_ISREG(info.st_mode) and info.st_size == len(payload):
                    os.pwrite(fd, b"?" * len(payload), 0)
                    changed.append(True)
                    info = original(fd)
                return info
            with patch.object(adapter.os, "fstat", side_effect=corrupt):
                self.assertEqual(self.execute().error.reason, "xray_staging_changed")
            self.assertEqual(changed, [True])
        self.assertEqual(self.runner.calls, 0)

    def test_simple_go_lowercase_preserves_tail_marker_for_unicode_filename(self):
        doc = config().parts[1].export()
        doc["outbounds"][0]["tag"] = "TEST_last"
        first = ConfigDocument("TEST_first.json", b'{"outbounds":[{"protocol":"freedom","tag":"TEST_first"}]}')
        last = ConfigDocument("TEST_TAİL.json", json.dumps(doc).encode())
        self.assertEqual(self.execute(command(xray=XrayConfigSet((first, last)))).data.status.value, "passed")
        self.assertEqual(self.runner.request.argv[-1], "parts/001-tail.json")

    def test_first_stat_failures_cleanup_and_close_pinned_descriptors(self):
        original = adapter.os.fstat
        for file_type in (stat.S_ISREG, stat.S_ISDIR):
            broken = []
            def fail(fd):
                info = original(fd)
                # Сбой после mkdir или создания файла, а не на исходном родителе.
                if file_type(info.st_mode) and not broken and not os.path.samestat(info, self.parent.stat()):
                    broken.append(fd)
                    raise OSError("TEST_io")
                return info
            with patch.object(adapter.os, "fstat", side_effect=fail):
                self.assertEqual(self.execute().error.reason, "xray_staging_failed")
            self.assertEqual(len(broken), 1)
            with self.assertRaises(OSError):
                original(broken[0])
        self.assertEqual(self.runner.calls, 0)

    def test_invalid_group_is_not_invoked_as_process(self):
        called = []
        class ForeignGroup:
            def __getattr__(self, name):
                called.append(name)
                raise AssertionError
        def broken_start(request):
            self.runner.group = request.job
            return ForeignGroup()
        with patch.object(self.runner, "start", side_effect=broken_start):
            self.assertEqual(self.execute().error.reason, "xray_execution_failed")
        self.assertEqual(called, [])
        self.assertTrue(self.runner.reaped)
        self.assertIsNone(self.runner.group)

    def test_transient_directory_replacement_cannot_supply_other_bytes(self):
        def swap(req):
            root, = self.parent.iterdir()
            (root / "assets").rename(root / "saved")
            (root / "assets").mkdir(mode=0o700)
            foreign = root / "assets" / "geoip.dat"
            foreign.write_bytes(b"TEST_foreign")
            pinned = next(entry for entry in req.files if entry.name == "assets/geoip.dat")
            self.assertEqual(os.pread(pinned.descriptor, pinned.size, 0), IP)
            self.assertEqual(self.runner.snapshot["assets/geoip.dat"], IP)
            foreign.unlink()
            (root / "assets").rmdir()
            (root / "saved").rename(root / "assets")
        self.runner.on_start = swap
        self.assertEqual(self.execute().error.reason, "xray_staging_changed")

    def test_substituted_root_is_neither_used_nor_removed(self):
        foreign = self.parent / "TEST_foreign"
        foreign.mkdir(mode=0o700)
        identity = foreign.stat()
        open_directory = adapter.os.open
        def swap(name, flags, *args, **kwargs):
            if name.startswith(".xray-test-"):
                (self.parent / name).rename(self.parent / "TEST_owned")
                foreign.rename(self.parent / name)
            return open_directory(name, flags, *args, **kwargs)
        with patch.object(adapter.os, "open", side_effect=swap):
            result = self.handler.execute(command())
        self.assertEqual(result.error.reason, "xray_cleanup_failed")
        replacements = list(self.parent.glob(".xray-test-*"))
        self.assertEqual(len(replacements), 1)
        self.assertTrue(os.path.samestat(identity, replacements[0].stat()))
        self.assertEqual(self.runner.calls, 0)
        self.assertIsNone(self.runner.job)

    def test_exclusive_workspace_required_before_mkdir(self):
        with patch.object(self.runner, "reserve_staging", return_value=False), patch.object(adapter.os, "mkdir", side_effect=AssertionError):
            self.assertEqual(self.execute().error.reason, "xray_isolation_unavailable")
        self.assertEqual(self.runner.calls, 0)

    def test_partial_reservation_is_released_before_any_directory_or_process(self):
        def partial_reservation(job, parent_fd):
            self.runner.job = job
            raise OSError("TEST_partial")

        with (patch.object(self.runner, "reserve_staging", side_effect=partial_reservation) as reserve,
              patch.object(self.runner, "release_staging", wraps=self.runner.release_staging) as release,
              patch.object(adapter.os, "mkdir") as mkdir):
            self.assertEqual(self.execute().error.reason, "xray_isolation_unavailable")
        reserve.assert_called_once()
        release.assert_called_once_with(reserve.call_args.args[0])
        mkdir.assert_not_called()
        self.assertIsNone(self.runner.job)
        self.assertEqual(self.runner.calls, 0)

    def test_release_exception_reports_cleanup_failure_after_successful_run(self):
        with patch.object(self.runner, "release_staging", side_effect=OSError("TEST_release")) as release:
            self.assertEqual(self.execute().error.reason, "xray_cleanup_failed")
        release.assert_called_once_with(self.runner.request.job)
        self.assertTrue(self.runner.reaped)

    def test_invalid_release_response_reports_cleanup_failure_after_successful_run(self):
        with patch.object(self.runner, "release_staging", return_value=False) as release:
            self.assertEqual(self.execute().error.reason, "xray_cleanup_failed")
        release.assert_called_once_with(self.runner.request.job)
        self.assertTrue(self.runner.reaped)

    def test_group_cleanup_error_wins_over_changed_contents(self):
        def mutate(req):
            root, = self.parent.iterdir()
            (root / "assets" / "geosite.dat").write_bytes(b"TEST_changed")
        self.runner.on_start = mutate
        with patch.object(self.runner, "terminate_and_wait", side_effect=OSError("TEST_group_alive")):
            self.assertEqual(self.execute().error.reason, "xray_cleanup_failed")

    def test_initial_directory_stat_failure_only_uses_retry_for_cleanup(self):
        original = adapter.os.stat
        failed = []
        def fail(path, *args, **kwargs):
            if not failed and type(path) is str and path.startswith(".xray-test-"):
                failed.append(True)
                raise OSError("TEST_stat")
            return original(path, *args, **kwargs)
        with patch.object(adapter.os, "stat", side_effect=fail):
            self.assertEqual(self.execute().error.reason, "xray_staging_failed")
        self.assertEqual(failed, [True])
        self.assertEqual(self.runner.calls, 0)

    def test_file_logger_denial_is_environment_failure_for_unchanged_candidate(self):
        raw = b'{"log":{"access":"none","error":"/opt/var/log/TEST_error.log","dnsLog":false}}'
        part = ConfigDocument("TEST_log.json", raw)
        cmd = command(xray=XrayConfigSet((part, *config().parts)))
        def check_original(req):
            self.assertEqual(self.runner.snapshot["parts/000.json"], raw)
            self.assertEqual(len(req.argv[5:]), 2 * len(cmd.xray.parts))
        self.runner.on_start = check_original
        for code in (0, 23):
            self.runner.reply = adapter.XrayTestExit(code, BANNER, b"TEST_denial", True)
            result = self.execute(cmd)
            self.assertEqual((result.error.code, result.error.reason), ("xray_test_unavailable", "xray_file_access_denied"))
        self.runner.reply = adapter.XrayTestExit(23, b"TEST_error", b"TEST_output", False)
        self.assertEqual(self.execute(cmd).data.reason, "xray_candidate_rejected")
        self.runner.reply = adapter.XrayTestExit(0, BANNER, b"", None)
        self.assertEqual(self.execute(cmd).error.reason, "xray_output_invalid")

    def test_async_console_line_after_exact_success_marker(self):
        self.runner.reply = adapter.XrayTestExit(0, BANNER + b"TEST_console\n", b"", False)
        self.assertEqual(self.execute().data.status.value, "passed")
        self.runner.reply = adapter.XrayTestExit(0, BANNER.replace(b"Configuration OK.", b"TEST_log: Configuration OK."), b"", False)
        self.assertEqual(self.execute().error.reason, "xray_output_invalid")

    def test_file_denial_precedes_decoding_within_output_limit(self):
        for stdout, stderr in ((BANNER, b"\xff"), (b"\xff", b"")):
            self.runner.reply = adapter.XrayTestExit(23, stdout, stderr, True)
            self.assertEqual(self.execute().error.reason, "xray_file_access_denied")
        self.runner.reply = adapter.XrayTestExit(23, b"\xff", b"x" * adapter.OUTPUT_LIMIT, True)
        self.assertEqual(self.execute().error.reason, "xray_output_limit")
