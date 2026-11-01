"""Исходные отпечатки управляемых источников роутера, их фиксация при создании черновика и проверка его актуальности.

Файлы читаются из обезличенного снимка во временном корне, RCI — через
подставное соединение. Роутер, сеть и процессы не используются.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.adapters.keenetic_rci_http import RciResource
from keenvpn.adapters.router_sources import XKEEN_INIT_LIMIT, XRAY_PART_COUNT_LIMIT, XRAY_PART_LIMIT, SourceFingerprints
from keenvpn.application.contract import ErrorCategory, NextStepCode
from keenvpn.application.draft_session import CheckDraftBaseline, CheckDraftBaselineHandler, CreateDraft, CreateDraftHandler
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.domain.draft_session import decode_draft_session
from keenvpn.domain.source_baseline import (
    MAX_BASELINE_PARTS, BaselineSource, FingerprintState, SourceBaselineError, SourceBaselineErrorCode,
    SourceFingerprint, native_fingerprint,
)
from tests.support.isolation import forbid_external_effects
from tests.support.rci import RciReply, ScriptedRci
from tests.support.router_files import INIT, SYNTHETIC_INIT, XKEEN, XRAY_CONFIGS, write_router_snapshot
from tests.support.snapshot import (
    load_keenetic_snapshot, load_xkeen_snapshot, load_xray_snapshot_files, snapshot_xkeen_settings_bytes,
)


Failure = RouterReadFailure
PRESENT = FingerprintState.PRESENT
ABSENT = FingerprintState.ABSENT
LISTS = {
    BaselineSource.XKEEN_PORT_EXCLUDE: "port_exclude.lst",
    BaselineSource.XKEEN_PORT_PROXYING: "port_proxying.lst",
    BaselineSource.XKEEN_IP_EXCLUDE: "ip_exclude.lst",
}
FINGERPRINT_PATHS = (RciResource.POLICIES.path, RciResource.HOTSPOT_SETTINGS.path)


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def snapshot_fingerprints() -> dict[BaselineSource, SourceFingerprint]:
    """Ожидаемые отпечатки снимка, посчитанные независимо от адаптера."""
    keenetic = load_keenetic_snapshot()
    lists = load_xkeen_snapshot()["lists"]
    parts = tuple(sorted((name, sha256(content)) for name, content in load_xray_snapshot_files().items()))
    expected = {
        BaselineSource.XRAY_CONFIGS: SourceFingerprint(BaselineSource.XRAY_CONFIGS, PRESENT, parts=parts),
        BaselineSource.XKEEN_SETTINGS: SourceFingerprint(
            BaselineSource.XKEEN_SETTINGS, PRESENT, sha256=sha256(snapshot_xkeen_settings_bytes()),
        ),
        BaselineSource.XKEEN_INIT: SourceFingerprint(BaselineSource.XKEEN_INIT, PRESENT, sha256=sha256(SYNTHETIC_INIT)),
        BaselineSource.KEENETIC_POLICIES: SourceFingerprint(
            BaselineSource.KEENETIC_POLICIES, PRESENT, sha256=native_fingerprint(keenetic["ip/policy"]),
        ),
        BaselineSource.KEENETIC_HOTSPOT_SETTINGS: SourceFingerprint(
            BaselineSource.KEENETIC_HOTSPOT_SETTINGS, PRESENT, sha256=native_fingerprint(keenetic["ip/hotspot"]),
        ),
    }
    for source, name in LISTS.items():
        expected[source] = SourceFingerprint(source, PRESENT, sha256=sha256(lists[name].encode("utf-8")))
    return expected


class FingerprintsCase(unittest.TestCase):
    def setUp(self):
        # Реальный путь: на macOS временный каталог находится за ссылкой /var.
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-baseline-")))
        self.addCleanup(self._cleanup)
        write_router_snapshot(self.root)
        self.base = str(self.root)
        self.script = ScriptedRci()
        self.reader = SourceFingerprints(root=self.base, read=self.script.read)

    def _cleanup(self):
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        shutil.rmtree(self.root)

    def assert_failure(self, source, failure):
        with self.assertRaises(RouterReadError) as caught:
            self.reader.current_fingerprint(source)
        self.assertIs(caught.exception.failure, failure)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(self.base, str(caught.exception) + repr(caught.exception))

    def files(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in sorted(self.root.rglob("*")) if path.is_file() and not path.is_symlink()
        }


class SourceFingerprintsTests(FingerprintsCase):
    def test_snapshot_fingerprints_are_bytes_and_canonical_json_hashes(self):
        expected = snapshot_fingerprints()
        before = self.files()
        for source in BaselineSource:
            with self.subTest(source=source.value):
                self.assertEqual(self.reader.current_fingerprint(source), expected[source])
                self.assertEqual(self.reader.current_fingerprint(source), expected[source])
        # Один запрос на вызов; реестр регистраций и runtime не читаются.
        self.assertEqual(self.script.paths, tuple(path for path in FINGERPRINT_PATHS for _ in range(2)))
        self.assertEqual(self.files(), before)

    def test_absent_differs_from_empty_file_and_empty_directory(self):
        (self.root / INIT).write_bytes(b"")
        self.assertEqual(self.reader.current_fingerprint(BaselineSource.XKEEN_INIT).sha256, sha256(b""))
        (self.root / INIT).unlink()
        self.assertEqual(
            self.reader.current_fingerprint(BaselineSource.XKEEN_INIT),
            SourceFingerprint(BaselineSource.XKEEN_INIT, ABSENT),
        )
        for path in (self.root / XRAY_CONFIGS).iterdir():
            path.unlink()
        self.assertEqual(self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS).parts, ())
        (self.root / XRAY_CONFIGS).rmdir()
        self.assertIs(self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS).state, ABSENT)
        shutil.rmtree(self.root / "opt/etc/xray")
        self.assertIs(self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS).state, ABSENT)
        shutil.rmtree(self.root / XKEEN)
        for source in (BaselineSource.XKEEN_SETTINGS, *LISTS):
            with self.subTest(source=source.value):
                self.assertEqual(self.reader.current_fingerprint(source), SourceFingerprint(source, ABSENT))

    def test_part_set_changes_change_the_fingerprint(self):
        configs = self.root / XRAY_CONFIGS
        original = self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS)
        (configs / "README").write_bytes(b"not a part")
        (configs / "10_dir.json").mkdir()
        self.assertEqual(self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS), original)
        (configs / "08_failover_api.json").write_bytes(b'{"api": {"tag": "TEST_api"}}')
        added = self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS)
        self.assertEqual(added.parts[:-1], original.parts)
        self.assertEqual(added.parts[-1][0], "08_failover_api.json")
        (configs / "08_failover_api.json").unlink()
        (configs / "07_observatory.json").rename(configs / "07_renamed.json")
        renamed = self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS)
        self.assertNotEqual(renamed, original)
        self.assertEqual([digest for _name, digest in renamed.parts], [digest for _name, digest in original.parts])
        (configs / "07_renamed.json").unlink()
        self.assertEqual(self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS).parts, original.parts[:-1])
        (configs / "01_log.json").write_bytes((configs / "01_log.json").read_bytes() + b" ")
        changed = self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS)
        self.assertNotEqual(changed.parts[0], original.parts[0])
        self.assertEqual(changed.parts[1:], original.parts[1:-1])

    def test_rci_key_order_does_not_matter_but_permit_order_does(self):
        policies = load_keenetic_snapshot()["ip/policy"]
        expected = native_fingerprint(policies)
        reordered = {key: dict(reversed(list(value.items()))) for key, value in reversed(list(policies.items()))}
        self.script.replies[RciResource.POLICIES.path] = RciReply(body=json.dumps(reordered).encode("utf-8"))
        self.assertEqual(self.reader.current_fingerprint(BaselineSource.KEENETIC_POLICIES).sha256, expected)
        swapped = json.loads(json.dumps(policies))
        swapped["Policy20"]["permit"].reverse()
        self.script.replies[RciResource.POLICIES.path] = RciReply(body=json.dumps(swapped).encode("utf-8"))
        self.assertNotEqual(self.reader.current_fingerprint(BaselineSource.KEENETIC_POLICIES).sha256, expected)

    def test_unsafe_large_changed_and_unreadable_sources_are_failures(self):
        settings = self.root / XKEEN / "xkeen.json"
        real = self.root / "real-xkeen.json"
        settings.rename(real)
        settings.symlink_to(real)
        self.assert_failure(BaselineSource.XKEEN_SETTINGS, Failure.UNSAFE)
        settings.unlink()
        real.rename(settings)
        (self.root / XRAY_CONFIGS / "09_link.json").symlink_to(settings)
        self.assert_failure(BaselineSource.XRAY_CONFIGS, Failure.UNSAFE)
        (self.root / XRAY_CONFIGS / "09_link.json").unlink()
        (self.root / INIT).write_bytes(b"#" * (XKEEN_INIT_LIMIT + 1))
        self.assert_failure(BaselineSource.XKEEN_INIT, Failure.TOO_LARGE)
        (self.root / XRAY_CONFIGS / "09_large.json").write_bytes(b" " * (XRAY_PART_LIMIT + 1))
        self.assert_failure(BaselineSource.XRAY_CONFIGS, Failure.TOO_LARGE)
        (self.root / XRAY_CONFIGS / "09_large.json").unlink()
        (self.root / XKEEN / "ip_exclude.lst").chmod(0)
        if os.geteuid() != 0:
            self.assert_failure(BaselineSource.XKEEN_IP_EXCLUDE, Failure.PERMISSION_DENIED)
        original = os.read

        def rewrite(descriptor, size):
            chunk = original(descriptor, size)
            if chunk:
                os.utime(settings, ns=(1, 1))
            return chunk

        with patch.object(os, "read", rewrite):
            self.assert_failure(BaselineSource.XKEEN_SETTINGS, Failure.CHANGED)

    def replace_before_open(self, name: str, relative: str, *files: str):
        """Заменить каталог по пути непосредственно перед открытием `name` в удерживаемом прежнем каталоге."""
        original = os.open
        done = []

        def opening(path, flags, *args, **kwargs):
            if path == name and kwargs.get("dir_fd") is not None and not done:
                done.append(1)
                directory = self.root / relative
                directory.rename(directory.with_name(directory.name + ".old"))
                directory.mkdir()
                for file_name in files:
                    (directory / file_name).write_bytes(b"{}")
            return original(path, flags, *args, **kwargs)

        return patch.object(os, "open", opening), done

    def test_absence_seen_in_a_replaced_directory_is_not_recorded_as_absent(self):
        (self.root / INIT).unlink()
        patcher, done = self.replace_before_open("S05xkeen", "opt/etc/init.d", "S05xkeen")
        with patcher:
            self.assert_failure(BaselineSource.XKEEN_INIT, Failure.CHANGED)
        self.assertEqual(done, [1])
        shutil.rmtree(self.root / "opt/etc/xray")
        (self.root / "opt/etc/xray").mkdir()
        patcher, done = self.replace_before_open("configs", "opt/etc/xray")
        with patcher:
            self.assert_failure(BaselineSource.XRAY_CONFIGS, Failure.CHANGED)
        self.assertEqual(done, [1])

    def test_too_many_parts_is_a_failure_within_the_model_limit(self):
        self.assertEqual(XRAY_PART_COUNT_LIMIT, MAX_BASELINE_PARTS)
        for index in range(XRAY_PART_COUNT_LIMIT):
            (self.root / XRAY_CONFIGS / f"50_{index:02d}.json").write_bytes(b"{}")
        self.assert_failure(BaselineSource.XRAY_CONFIGS, Failure.TOO_LARGE)

    def test_rci_failures_pass_through(self):
        self.script.failures["connect"] = ConnectionRefusedError("TEST_private")
        self.assert_failure(BaselineSource.KEENETIC_POLICIES, Failure.CONNECTION_FAILED)
        self.script.failures.clear()
        self.script.replies[RciResource.HOTSPOT_SETTINGS.path] = RciReply(status=500)
        self.assert_failure(BaselineSource.KEENETIC_HOTSPOT_SETTINGS, Failure.HTTP_STATUS)
        self.script.replies[RciResource.HOTSPOT_SETTINGS.path] = RciReply(body=b'{"status": "error"}')
        self.assert_failure(BaselineSource.KEENETIC_HOTSPOT_SETTINGS, Failure.RCI_ERROR)

    def test_hidden_part_name_is_a_model_error(self):
        (self.root / XRAY_CONFIGS / ".hidden.json").write_bytes(b"{}")
        with self.assertRaises(SourceBaselineError) as caught:
            self.reader.current_fingerprint(BaselineSource.XRAY_CONFIGS)
        self.assertIs(caught.exception.code, SourceBaselineErrorCode.PARTS)
        self.assertIsNone(caught.exception.__context__)

    def test_wrong_source_reader_or_root_is_a_programming_error(self):
        with self.assertRaises(TypeError):
            self.reader.current_fingerprint("xkeen_init")
        with self.assertRaises(TypeError):
            SourceFingerprints(read=None)
        with self.assertRaises(TypeError):
            SourceFingerprints(root=self.base, read=lambda _resource: []).current_fingerprint(
                BaselineSource.KEENETIC_POLICIES,
            )
        for root in ("relative", "/tmp/", "/a/../b"):
            with self.subTest(root=root), self.assertRaises(ValueError):
                SourceFingerprints(root=root)

    def test_constructing_the_reader_touches_nothing(self):
        with forbid_external_effects():
            self.assertIsNotNone(SourceFingerprints())
            self.assertIsNotNone(SourceFingerprints(root=self.base, read=self.script.read))
        self.assertEqual(self.script.connections, [])


class CreateDraftOverRouterSourcesTests(FingerprintsCase):
    def setUp(self):
        super().setUp()
        self.data = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-baseline-data-")))
        self.addCleanup(shutil.rmtree, self.data)
        self.directory = self.data / "draft"
        self.handler = CreateDraftHandler(
            DraftSessionFiles(str(self.directory)), self.reader, operation_ids=lambda: "test-operation",
        )

    def test_draft_file_keeps_baseline_and_router_files_are_unchanged(self):
        before = self.files()
        result = self.handler.execute(CreateDraft())
        self.assertTrue(result.succeeded)
        self.assertEqual(self.files(), before)
        stored = decode_draft_session((self.directory / DRAFT_FILE_NAME).read_bytes()).session.baseline
        expected = snapshot_fingerprints()
        self.assertEqual(stored.fingerprints, tuple(expected[source] for source in BaselineSource))
        self.assertEqual(stat_mode(self.directory / DRAFT_FILE_NAME), 0o600)
        text = json.dumps(result.to_dict(), ensure_ascii=False)
        for value in (self.base, str(self.data), "01_log.json", *(item.sha256 or "" for item in stored.fingerprints[1:])):
            self.assertNotIn(value, text)
        self.assertEqual(
            [item["state"] for item in result.to_dict()["data"]["baseline"]["sources"]], ["present"] * len(BaselineSource),
        )

    def test_unavailable_source_leaves_no_draft(self):
        self.script.failures["connect"] = ConnectionRefusedError("TEST_private")
        result = self.handler.execute(CreateDraft())
        self.assertEqual(
            (result.error.category, result.error.code, result.error.reason, result.error.next_step.code),
            (ErrorCategory.SOURCE_FAILED, "draft_baseline_unavailable", "connection_failed", NextStepCode.CHECK_SOURCE),
        )
        self.assertFalse(self.directory.exists())
        self.assertNotIn("TEST_private", json.dumps(result.to_dict(), ensure_ascii=False))

    def test_init_replaced_while_checking_absence_leaves_no_draft(self):
        (self.root / INIT).unlink()
        original = os.open
        done = []

        def opening(path, flags, *args, **kwargs):
            if path == "S05xkeen" and kwargs.get("dir_fd") is not None and not done:
                done.append(1)
                (self.root / "opt/etc/init.d").rename(self.root / "opt/etc/init.d.old")
                (self.root / INIT).parent.mkdir()
                (self.root / INIT).write_bytes(SYNTHETIC_INIT)
            return original(path, flags, *args, **kwargs)

        with patch.object(os, "open", opening):
            result = self.handler.execute(CreateDraft())
        self.assertEqual(done, [1])
        self.assertEqual((result.error.code, result.error.reason), ("draft_baseline_unavailable", "changed"))
        self.assertFalse(self.directory.exists())

    def test_absent_init_is_recorded_and_hidden_part_blocks_creation(self):
        (self.root / INIT).unlink()
        self.assertTrue(self.handler.execute(CreateDraft()).succeeded)
        stored = decode_draft_session((self.directory / DRAFT_FILE_NAME).read_bytes()).session.baseline
        self.assertIs(stored.fingerprint(BaselineSource.XKEEN_INIT).state, ABSENT)
        (self.directory / DRAFT_FILE_NAME).unlink()
        (self.root / XRAY_CONFIGS / ".hidden.json").write_bytes(b"{}")
        result = self.handler.execute(CreateDraft())
        self.assertEqual((result.error.code, result.error.reason), ("invalid_draft_baseline_source", "invalid_baseline_parts"))
        self.assertFalse((self.directory / DRAFT_FILE_NAME).exists())


class CheckDraftOverRouterSourcesTests(FingerprintsCase):
    """Черновик, созданный по файлам снимка, проверяется на актуальность после внешних правок тех же файлов."""

    def setUp(self):
        super().setUp()
        self.data = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-baseline-data-")))
        self.addCleanup(shutil.rmtree, self.data)
        self.directory = self.data / "draft"
        create = CreateDraftHandler(DraftSessionFiles(str(self.directory)), self.reader, operation_ids=lambda: "test-operation")
        created = create.execute(CreateDraft())
        self.assertTrue(created.succeeded)
        self.command = CheckDraftBaseline(draft_id=created.data.draft_id, expected_revision=created.data.revision)
        self.check = CheckDraftBaselineHandler(
            DraftSessionFiles(str(self.directory)), self.reader, operation_ids=lambda: "test-operation",
        )
        self.draft = (self.directory / DRAFT_FILE_NAME).read_bytes()

    def run_check(self):
        before = self.files()
        result = self.check.execute(self.command)
        # Проверка ничего не пишет: ни файлы роутера, ни файл черновика не меняются.
        self.assertEqual(self.files(), before)
        self.assertEqual((self.directory / DRAFT_FILE_NAME).read_bytes(), self.draft)
        text = json.dumps(result.to_dict(), ensure_ascii=False)
        for value in (self.base, str(self.data), "01_log.json", self.command.expected_revision):
            self.assertNotIn(value, text)
        return result

    def conflicts(self, result):
        return [(item["source"], item["expected"], item["found"]) for item in result.to_dict()["error"]["conflicts"]]

    def test_unchanged_files_and_settings_keep_the_draft_current(self):
        result = self.run_check()
        self.assertEqual(result.to_dict()["data"], {"outcome": "current", "draft_id": self.command.draft_id})
        # Два ресурса RCI на создание и два на проверку: реестр регистраций и runtime не читаются.
        self.assertEqual(self.script.paths, FINGERPRINT_PATHS * 2)

    def test_external_file_edits_make_the_draft_stale(self):
        (self.root / XKEEN / "port_exclude.lst").write_bytes(b"TEST_port\n")
        (self.root / XRAY_CONFIGS / "99_TEST_extra.json").write_bytes(b"{}")
        (self.root / INIT).unlink()
        result = self.run_check()
        self.assertEqual((result.error.code, result.error.next_step.code), ("draft_baseline_changed", NextStepCode.RECREATE_DRAFT))
        self.assertEqual(self.conflicts(result), [
            ("xray_configs", "present", "changed"), ("xkeen_init", "present", "absent"),
            ("xkeen_port_exclude", "present", "changed"),
        ])
        self.assertNotIn("99_TEST_extra.json", json.dumps(result.to_dict(), ensure_ascii=False))

    def test_changed_native_setting_makes_the_draft_stale(self):
        policies = load_keenetic_snapshot()["ip/policy"]
        policies["TEST_policy"] = {"description": "TEST_private"}
        self.script.replies[RciResource.POLICIES.path] = RciReply(body=json.dumps(policies).encode("utf-8"))
        result = self.run_check()
        self.assertEqual(result.error.code, "draft_baseline_changed")
        self.assertEqual(self.conflicts(result), [("keenetic_policies", "present", "changed")])
        self.assertNotIn("TEST_private", json.dumps(result.to_dict(), ensure_ascii=False))

    def test_unreachable_rci_is_not_a_match(self):
        self.script.failures["connect"] = ConnectionRefusedError("TEST_private")
        result = self.run_check()
        self.assertEqual(
            (result.error.code, result.error.reason, result.error.next_step.code),
            ("draft_baseline_unavailable", "connection_failed", NextStepCode.CHECK_SOURCE),
        )
        self.assertEqual(self.conflicts(result), [
            ("keenetic_policies", "present", "unknown"), ("keenetic_hotspot_settings", "present", "unknown"),
        ])
        self.assertNotIn("TEST_private", json.dumps(result.to_dict(), ensure_ascii=False))


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
