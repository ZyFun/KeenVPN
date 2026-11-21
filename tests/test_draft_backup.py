"""Копирование перед применением на временных файлах и подставном RCI."""

import base64
from dataclasses import replace
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_backup_files import DraftBackupFiles
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.adapters.keenetic_rci_http import RciResource
from keenvpn.adapters.router_sources import SourceFingerprints
from keenvpn.application.draft_apply import run_draft_apply_with_backup
from keenvpn.application.draft_backup import BackupFile, BackupXrayDirectory, DraftBackupStorageError, FileMetadata
from keenvpn.application.draft_session import draft_revision_token
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure
from keenvpn.application.source_baseline import capture_baseline
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.draft_candidate_state import build_draft_candidate
from keenvpn.domain.draft_session import DraftSession, encode_draft_session
from keenvpn.domain.draft_snapshot import DraftDiffSnapshot
from keenvpn.domain.keenetic_native import KeeneticHotspotSettings
from keenvpn.domain.source_baseline import BaselineSource
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.router_files import INIT, XRAY_CONFIGS


DRAFT_ID = "0000abcd-0000-4000-8000-000000000091"
PRIVATE_VALUE = "synthetic-private-value"
POLICIES = {"Policy1": {"permit": ["Example"], "unknown": PRIVATE_VALUE}}
HOTSPOT = {"host": []}


def parts(*names):
    return XrayConfigSet(tuple(ConfigDocument(name, b"{}") for name in names))


class DraftBackupTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.apply = Mock(return_value="результат исполнителя")
        self.backups = self.root / "backups"
        info = self.root.stat()
        self.storage = DraftBackupFiles(str(self.backups), parent_identity=(info.st_dev, info.st_ino))
        self.drafts = self.root / "draft"
        self.store = DraftSessionFiles(str(self.drafts))
        self.init = self.root / INIT
        self.init.parent.mkdir(parents=True)
        self.init.write_bytes(b"")
        self.init.chmod(0o751)
        self.xray = self.root / XRAY_CONFIGS
        self.xray.mkdir(parents=True)
        (self.xray / "remove.json").write_bytes(b"{}")
        (self.xray / "same.json").write_bytes(b"{}")
        (self.xray / "other.txt").write_bytes(b"unmanaged")
        payloads = {RciResource.POLICIES: POLICIES, RciResource.HOTSPOT_SETTINGS: HOTSPOT}
        self.rci = Mock(side_effect=payloads.__getitem__)
        self.reader = SourceFingerprints(root=str(self.root), read=self.rci)
        self.original = DraftDiffSnapshot(
            xray_configs=parts("remove.json", "same.json"), xkeen_settings=None, xkeen_init=b"",
            xkeen_port_exclude=None, xkeen_port_proxying=None, xkeen_ip_exclude=None,
            keenetic_policies=POLICIES, keenetic_hotspot_settings=KeeneticHotspotSettings(HOTSPOT),
        )
        self.candidate = replace(self.original, xray_configs=parts("add.json", "same.json"), xkeen_init=None,
                                 keenetic_policies={"Policy1": {"permit": []}})
        self.baseline = capture_baseline(self.reader)

    def create(self, *, original=None, candidate=None, include_candidate=True):
        state = None
        if include_candidate:
            state = build_draft_candidate(original or self.original, candidate or self.candidate, ())
        self.session = DraftSession(DRAFT_ID, datetime(2026, 11, 21, tzinfo=timezone.utc),
                                    baseline=self.baseline, candidate=state)
        self.revision = self.store.create_draft(self.session)
        self.token = draft_revision_token(self.revision)

    def run_apply(self, *, source=None, storage=None, token=None):
        return run_draft_apply_with_backup(
            self.store, self.reader, DRAFT_ID, token or self.token,
            source or self.reader, storage or self.storage, self.apply,
        )

    def assert_error(self, result, code):
        self.assertEqual(result.code, code)
        self.apply.assert_not_called()
        rendered = repr(result) + repr(result.to_dict())
        for private in (str(self.root), PRIVATE_VALUE, "remove.json", self.revision):
            self.assertNotIn(private, rendered)

    def test_fresh_scoped_backup_is_readable_before_executor_under_the_same_lock(self):
        self.create()
        peer = DraftSessionFiles(str(self.drafts))
        read = Mock(wraps=self.reader.read_backup_source)

        def apply(stored, backup):
            self.assertEqual(stored.revision, self.revision)
            self.assertEqual(backup.draft_revision, self.revision)
            with self.assertRaises(DraftSessionStoreError) as caught:
                peer.remove_draft(self.revision)
            self.assertIs(caught.exception.failure, DraftStoreFailure.BUSY)
            path = self.backups / f"apply-{backup.backup_id}.json"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.backups.stat().st_mode), 0o700)
            content = path.read_bytes()
            self.assertEqual(backup.sha256, hashlib.sha256(content).hexdigest())
            document = json.loads(content)
            self.assertEqual(document["schema_version"], 1)
            self.assertEqual(document["draft_id"], DRAFT_ID)
            self.assertEqual(document["draft_revision"], self.revision)
            self.assertEqual(document["backup_id"], backup.backup_id)
            sources = document["sources"]
            self.assertEqual(set(sources), {"xray_configs", "xkeen_init", "keenetic_policies"})
            files = sources["xray_configs"]
            self.assertEqual(files["state"], "present")
            self.assertEqual(files["metadata"]["mode"], stat.S_IMODE(self.xray.stat().st_mode))
            self.assertEqual(set(files["parts"]), {"add.json", "remove.json"})
            self.assertIsNone(files["parts"]["add.json"])
            self.assertEqual(self.check_entry(files["parts"]["remove.json"]), b"{}")
            self.assertEqual(self.check_entry(sources["xkeen_init"]), b"")
            self.assertEqual(sources["xkeen_init"]["metadata"], {
                "mode": 0o751, "uid": self.init.stat().st_uid, "gid": self.init.stat().st_gid,
            })
            self.assertEqual(json.loads(self.check_entry(sources["keenetic_policies"])), POLICIES)
            self.assertNotIn(self.revision, repr(backup))
            self.assertEqual(self.init.read_bytes(), b"")
            self.assertEqual((self.xray / "same.json").read_bytes(), b"{}")
            return "после проверки"

        self.apply.side_effect = apply
        with patch.object(self.reader, "read_backup_source", read):
            self.assertEqual(self.run_apply(), "после проверки")
        self.assertEqual([call.args[0] for call in read.call_args_list],
                         [BaselineSource.XRAY_CONFIGS, BaselineSource.XKEEN_INIT, BaselineSource.KEENETIC_POLICIES] * 2)
        self.assertEqual(self.store.read_draft().revision, self.revision)

    def check_entry(self, entry):
        content = base64.b64decode(entry["base64"], validate=True)
        self.assertEqual(entry["size"], len(content))
        self.assertEqual(entry["sha256"], hashlib.sha256(content).hexdigest())
        return content

    def test_absent_sources_and_empty_xray_directory_are_distinct(self):
        for item in self.xray.iterdir():
            item.unlink()
        self.original = replace(self.original, xray_configs=parts())
        self.baseline = capture_baseline(self.reader)
        self.create(candidate=replace(self.original, xray_configs=None, xkeen_port_exclude=b"53\n"))
        self.run_apply()
        sources = json.loads(next(self.backups.iterdir()).read_bytes())["sources"]
        self.assertEqual(sources["xray_configs"]["state"], "present")
        self.assertEqual(sources["xray_configs"]["parts"], {})
        self.assertIsNone(sources["xkeen_port_exclude"])

    def test_bad_revision_or_inconsistent_original_skips_backup(self):
        self.create(original=replace(self.original, xkeen_init=b"mismatch"))
        source, storage = Mock(), Mock()
        self.assert_error(self.run_apply(source=source, storage=storage, token="0" * 32), "draft_revision_conflict")
        self.assert_error(self.run_apply(source=source, storage=storage), "draft_baseline_changed")
        source.read_backup_source.assert_not_called()
        storage.save.assert_not_called()

    def test_missing_candidate_rejects_backup(self):
        self.create(include_candidate=False)
        self.assert_error(self.run_apply(), "draft_backup_invalid_candidate")
        self.assertFalse(self.backups.exists())

    def test_no_changes_rejects_execution_without_creating_backup(self):
        self.create(candidate=self.original)
        self.assert_error(self.run_apply(), "draft_backup_no_changes")
        self.assertFalse(self.backups.exists())

    def test_incomplete_live_snapshot_and_read_error_do_not_reach_storage(self):
        self.create()
        source = Mock()
        metadata = FileMetadata(0o644, 1, 1)
        file = BackupFile(b"{}", metadata)
        for result in (None, {}, BackupXrayDirectory({"remove.json": file}, metadata),
                       BackupXrayDirectory({"remove.json": file, "same.json": BackupFile(b"{}", None)}, metadata)):
            with self.subTest(result=type(result)):
                source.read_backup_source.return_value = result
                self.assert_error(self.run_apply(source=source), "draft_backup_source_changed")
        source.read_backup_source.side_effect = RuntimeError(PRIVATE_VALUE)
        self.assert_error(self.run_apply(source=source), "draft_backup_source_unavailable")
        self.assertFalse(self.backups.exists())

    def test_revision_is_rechecked_after_saving_before_executor(self):
        self.create()

        def save(backup_id, content):
            checksum = self.storage.save(backup_id, content)
            path = self.drafts / DRAFT_FILE_NAME
            path.write_bytes(encode_draft_session(self.session) + b" ")
            return checksum

        self.assert_error(self.run_apply(storage=Mock(save=save)), "draft_revision_conflict")
        self.assertEqual(len(list(self.backups.iterdir())), 1)

    def test_revision_is_rechecked_after_reading_source_metadata_again(self):
        self.create()
        read = self.reader.read_backup_source

        def read_backup_source(source):
            if source is BaselineSource.XRAY_CONFIGS and self.backups.exists():
                path = self.drafts / DRAFT_FILE_NAME
                path.write_bytes(encode_draft_session(self.session) + b" ")
            return read(source)

        with patch.object(self.reader, "read_backup_source", side_effect=read_backup_source):
            self.assert_error(self.run_apply(), "draft_revision_conflict")

    def test_source_revision_is_rechecked_after_saving_before_executor(self):
        self.create()

        def save(backup_id, content):
            checksum = self.storage.save(backup_id, content)
            self.init.write_bytes(b"external edit")
            return checksum

        self.assert_error(self.run_apply(storage=Mock(save=save)), "draft_baseline_changed")
        self.assertEqual(self.init.read_bytes(), b"external edit")

    def test_source_permissions_are_rechecked_after_backup(self):
        self.create()

        def save(backup_id, content):
            checksum = self.storage.save(backup_id, content)
            self.init.chmod(0o600)
            return checksum

        self.assert_error(self.run_apply(storage=Mock(save=save)), "draft_backup_source_changed")

    def test_source_permissions_are_rechecked_after_final_fingerprint_read(self):
        self.create()
        read = self.reader.current_fingerprint

        def current_fingerprint(source):
            if source is BaselineSource.KEENETIC_HOTSPOT_SETTINGS and self.backups.exists():
                self.init.chmod(0o600)
            return read(source)

        with patch.object(self.reader, "current_fingerprint", side_effect=current_fingerprint):
            self.assert_error(self.run_apply(), "draft_backup_source_changed")

    def test_backup_is_confirmed_after_final_fingerprint_read(self):
        self.create()
        read = self.reader.current_fingerprint
        for remove_or_change in (Path.unlink, lambda path: path.write_bytes(b"tampered")):
            with self.subTest(action=remove_or_change):
                def current_fingerprint(source):
                    if source is BaselineSource.XRAY_CONFIGS and self.backups.exists():
                        for path in self.backups.iterdir():
                            remove_or_change(path)
                    return read(source)

                with patch.object(self.reader, "current_fingerprint", side_effect=current_fingerprint):
                    self.assert_error(self.run_apply(), "draft_backup_unverified")

    def test_replaced_storage_parent_is_rejected_before_creating_backup_directory(self):
        self.create()
        selected = self.root / "selected"
        selected.mkdir()
        original = selected.stat()
        target = selected / "backups"
        storage = DraftBackupFiles(str(target), parent_identity=(original.st_dev, original.st_ino))
        selected.rename(self.root / "moved")
        selected.mkdir()
        result = self.run_apply(storage=storage)
        self.assert_error(result, "draft_backup_storage_failed")
        self.assertEqual(result.reason, "replaced")
        self.assertFalse(target.exists())

    def test_no_space_keeps_previous_copy_and_allows_retry(self):
        self.create()
        self.assertEqual(self.run_apply(), self.apply.return_value)
        first = next(self.backups.iterdir())
        previous = first.read_bytes()
        self.apply.reset_mock()
        with patch("keenvpn.adapters.private_files.os.write", side_effect=OSError(errno.ENOSPC, PRIVATE_VALUE)):
            result = self.run_apply()
        self.assert_error(result, "draft_backup_storage_failed")
        self.assertEqual(result.reason, "no_space")
        self.assertEqual(list(self.backups.iterdir()), [first])
        self.assertEqual(first.read_bytes(), previous)
        self.assertEqual(self.run_apply(), self.apply.return_value)
        self.assertEqual(len(list(self.backups.iterdir())), 2)

    def test_corrupted_persisted_bytes_fail_actual_post_fsync_read(self):
        self.create()
        real_write = os.write

        def corrupt(descriptor, content):
            return real_write(descriptor, b"!" + bytes(content)[1:])

        with patch("keenvpn.adapters.private_files.os.write", side_effect=corrupt):
            self.assert_error(self.run_apply(), "draft_backup_storage_failed")

    def test_unverified_storage_reply_does_not_reach_executor(self):
        self.create()
        self.assert_error(self.run_apply(storage=Mock(save=Mock(return_value="0" * 64))), "draft_backup_unverified")
        storage = Mock(save=Mock(side_effect=DraftBackupStorageError(reason=PRIVATE_VALUE)))
        result = self.run_apply(storage=storage)
        self.assert_error(result, "draft_backup_storage_failed")
        self.assertIsNone(result.reason)

    def test_storage_refuses_symbolic_link_without_writing_elsewhere(self):
        self.create()
        target = self.root / "other"
        target.mkdir(mode=0o700)
        self.backups.symlink_to(target, target_is_directory=True)
        self.assert_error(self.run_apply(), "draft_backup_storage_failed")
        self.assertEqual(list(target.iterdir()), [])
