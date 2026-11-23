"""Проверки журналируемого применения на временных файлах и управляемых портах."""

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import draft_config_files
from keenvpn.adapters.draft_backup_files import DraftBackupFiles
from keenvpn.adapters.draft_config_files import DraftConfigFiles
from keenvpn.adapters.draft_journal_files import DraftJournalFiles
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.adapters.keenetic_rci_http import RciResource
from keenvpn.application.draft_file_apply import FileStepFailure, FileStepResult
from keenvpn.application.draft_journal import DraftJournalStatus
from keenvpn.application.draft_journal_apply import ProcessChange, ProcessSnapshot, ProcessState, run_draft_journal_apply
from keenvpn.application.draft_session import draft_revision_token
from keenvpn.application.source_baseline import capture_baseline
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.draft_candidate_state import build_draft_candidate
from keenvpn.domain.draft_session import DraftSession
from keenvpn.domain.draft_snapshot import DraftDiffSnapshot
from keenvpn.domain.keenetic_native import KeeneticHotspotSettings
from keenvpn.domain.manager_metadata import metadata_revision
from keenvpn.domain.source_baseline import BaselineSource
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.router_files import INIT, XRAY_CONFIGS


DRAFT_ID = "0000abcd-0000-4000-8000-000000000087"
ORIGINAL = b'{"setting": 1}\n'
CANDIDATE = b'{"synthetic-private-value": 2}\n'


def parts(**values):
    return XrayConfigSet(tuple(ConfigDocument(name + ".json", values[name]) for name in sorted(values)))


class _Native:
    def __init__(self, resources, observe):
        self.resources = resources
        self.observe = observe
        self.calls = []

    def supports(self, change):
        return change.source is BaselineSource.KEENETIC_HOTSPOT_SETTINGS

    def change(self, change, check_current):
        self.observe()
        failure = check_current()
        if failure is not None:
            return failure
        self.calls.append(change)
        self.resources[RciResource.HOTSPOT_SETTINGS] = json.loads(change.after)


class _Process:
    def __init__(self, state, observe):
        self.snapshot = ProcessSnapshot(state, metadata_revision(b"initial process state"))
        self.calls = []
        self.observe = observe

    def supports(self, _change, changed_sources):
        return BaselineSource.XKEEN_INIT not in changed_sources

    def read(self):
        return self.snapshot

    def change(self, change, check_current):
        self.observe()
        failure = check_current()
        if failure is not None:
            return failure
        if self.snapshot != change.before:
            return FileStepFailure.CONFLICT
        self.calls.append(change)
        revision = metadata_revision(str(len(self.calls)).encode("ascii"))
        self.snapshot = ProcessSnapshot(change.after, revision)
        return self.snapshot


class DraftJournalApplyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        info = self.root.stat()
        identity = info.st_dev, info.st_ino
        self.backups = self.root / "backups"
        self.journals = self.root / "journals"
        self.storage = DraftBackupFiles(str(self.backups), parent_identity=identity)
        self.journal = DraftJournalFiles(str(self.journals), parent_identity=identity)
        self.drafts = DraftSessionFiles(str(self.root / "draft"))
        self.xray = self.root / XRAY_CONFIGS
        self.xray.mkdir(parents=True)
        self.first = self.xray / "first.json"
        self.second = self.xray / "second.json"
        self.first.write_bytes(ORIGINAL)
        self.first.chmod(0o640)
        self.second.write_bytes(ORIGINAL)
        self.init = self.root / INIT
        self.init.parent.mkdir(parents=True)
        self.init.write_bytes(b'proxy_router="on"\n')
        self.resources = {RciResource.POLICIES: {}, RciResource.HOTSPOT_SETTINGS: {"host": [], "mode": "original"}}
        self.files = DraftConfigFiles(root=str(self.root), read=self.resources.__getitem__)
        self.original = DraftDiffSnapshot(
            xray_configs=parts(first=ORIGINAL, second=ORIGINAL), xkeen_settings=None,
            xkeen_init=self.init.read_bytes(), xkeen_port_exclude=None, xkeen_port_proxying=None, xkeen_ip_exclude=None,
            keenetic_policies={}, keenetic_hotspot_settings=KeeneticHotspotSettings(
                self.resources[RciResource.HOTSPOT_SETTINGS]),
        )
        self.native = _Native(self.resources, lambda: self.assert_intent("native"))
        self.process = _Process(ProcessState(True, False), lambda: self.assert_intent("process"))
        self.target = ProcessChange(self.process.snapshot, ProcessState(True, True), reload=True)
        self.file_candidate = replace(self.original, xray_configs=parts(first=CANDIDATE, second=CANDIDATE))
        self.mixed_candidate = replace(self.file_candidate,
                                       keenetic_hotspot_settings=KeeneticHotspotSettings({"host": [], "mode": "next"}))

    def save(self, candidate):
        session = DraftSession(
            DRAFT_ID, datetime(2026, 11, 22, tzinfo=timezone.utc), baseline=capture_baseline(self.files),
            candidate=build_draft_candidate(self.original, candidate, ()),
        )
        self.revision = self.drafts.create_draft(session)
        self.token = draft_revision_token(self.revision)

    def apply(self, *, verify=lambda: True, mixed=False, lock=None,
              requires_network_verification=False, verify_restored=None):
        return run_draft_journal_apply(
            self.drafts if lock is None else lock, self.files, DRAFT_ID, self.token, self.storage,
            self.journal, verify=verify, native=self.native if mixed else None,
            process=self.process if mixed else None, process_change=self.target if mixed else None,
            requires_network_verification=requires_network_verification, verify_restored=verify_restored,
        )

    def read_journal(self):
        path, = self.journals.glob("journal-*.json")
        return json.loads(path.read_bytes())

    def assert_intent(self, stage, part=None):
        last = self.read_journal()["events"][-1]
        index = None if part is None else self.backup_part_names().index(part)
        self.assertEqual((last["stage"], last["part_index"], last["phase"]), (stage, index, "started"))

    def backup_part_names(self):
        path, = self.backups.glob("*.json")
        return sorted(json.loads(path.read_bytes())["sources"]["xray_configs"]["parts"])

    def assert_status(self, result, status):
        self.assertIs(result.status, DraftJournalStatus(status))
        document = self.read_journal()
        self.assertEqual(document["status"], status)
        self.assertEqual(result.confirmed_events, len(result.events))
        self.assertEqual(len(document["events"]), len(result.events))
        self.assertEqual(document["operation_id"], result.backup.backup_id)
        return document

    def test_intent_and_result_for_every_stage_are_durable_under_common_lock(self):
        self.save(self.mixed_candidate)
        write = self.files.write_draft_file

        def observed_file(change, check):
            self.assert_intent("file", change.target.part)
            return write(change, check)

        def verify():
            self.assert_intent("verify")
            with self.assertRaises(Exception):
                with self.drafts.lock_for_apply():
                    self.fail("Проверка выполняется вне исходной блокировки.")
            return True

        with patch.object(self.files, "write_draft_file", side_effect=observed_file):
            result = self.apply(mixed=True, verify=verify)
        document = self.assert_status(result, "applied")
        self.assertEqual([(e["stage"], e["phase"]) for e in document["events"]],
                         [(stage, phase) for stage in ("file", "file", "native", "process", "verify", "verify_backup")
                          for phase in ("started", "finished")])
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.process.snapshot.state, ProcessState(True, True))
        self.assertEqual(document["process"]["before"]["autostart"], False)
        process_result = next(event for event in document["events"]
                              if event["stage"] == "process" and event["phase"] == "finished")
        self.assertEqual(process_result["process_revision"], self.process.snapshot.revision)
        self.assertEqual(document["draft_revision"], self.revision)
        backup, = self.backups.glob("*.json")
        self.assertEqual(document["backup_sha256"], metadata_revision(backup.read_bytes()))
        journal_path, = self.journals.glob("*.json")
        self.assertEqual(stat.S_IMODE(journal_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.journals.stat().st_mode), 0o700)
        encoded = journal_path.read_text()
        self.assertNotIn("synthetic-private-value", encoded)
        self.assertNotIn('"mode":"next"', encoded)
        first_intent, first_outcome = document["events"][:2]
        self.assertEqual(first_intent["before_sha256"], metadata_revision(ORIGINAL))
        self.assertEqual(first_intent["after_sha256"], metadata_revision(CANDIDATE))
        self.assertIsNone(first_intent["publication"])
        self.assertEqual(first_outcome["publication"]["metadata"]["mode"], 0o640)
        safe = repr(result) + repr(result.events) + repr(result.backup)
        for private in (self.revision, str(self.root), self.first.name, result.backup.backup_id):
            self.assertNotIn(private, safe)

    def test_missing_native_port_refuses_before_any_file_or_backup_write(self):
        self.save(self.mixed_candidate)
        result = self.apply()
        self.assertEqual(result.code, "draft_native_apply_unavailable")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertFalse(self.backups.exists())
        self.assertFalse(self.journals.exists())

    def test_native_only_candidate_uses_same_backup_and_journal(self):
        self.save(replace(self.mixed_candidate, xray_configs=self.original.xray_configs))
        result = run_draft_journal_apply(
            self.drafts, self.files, DRAFT_ID, self.token, self.storage, self.journal,
            native=self.native, verify=lambda: True,
        )
        self.assert_status(result, "applied")
        self.assertEqual(len(self.native.calls), 1)
        self.assertEqual(self.resources[RciResource.HOTSPOT_SETTINGS]["mode"], "next")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)

    def test_process_conflict_refuses_before_any_file_write(self):
        self.save(self.mixed_candidate)
        self.process.snapshot = replace(self.process.snapshot, revision="b" * 64)
        result = self.apply(mixed=True)
        self.assertEqual(result.code, "draft_process_changed")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertFalse(self.backups.exists())

    def test_no_process_transition_runs_for_file_only_change(self):
        self.save(self.file_candidate)
        with patch.object(self.process, "change") as change:
            result = self.apply()
        self.assert_status(result, "applied")
        change.assert_not_called()

    def test_autostart_only_transition_has_verified_backup_and_no_file_or_native_write(self):
        self.save(self.original)
        self.target = replace(self.target, reload=False)
        previous = self.process.snapshot

        result = self.apply(mixed=True)

        document = self.assert_status(result, "applied")
        backup, = self.backups.glob("*.json")
        payload = json.loads(backup.read_bytes())
        self.assertEqual(payload["sources"], {})
        self.assertEqual(payload["process_before"], document["process"]["before"])
        self.assertEqual(payload["process_before"],
                         {"running": True, "autostart": False, "revision": previous.revision})
        self.assertEqual(metadata_revision(backup.read_bytes()), document["backup_sha256"])
        self.assertEqual(self.process.snapshot.state, ProcessState(True, True))
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.native.calls, [])
        self.assertFalse(any(event.stage == "file" for event in result.events))

    def test_autostart_only_transition_compensates_to_previous_state_without_reload(self):
        self.save(self.original)
        self.target = replace(self.target, reload=False)

        result = self.apply(mixed=True, verify=lambda: False)

        self.assert_status(result, "compensated")
        self.assertEqual(self.process.snapshot.state, ProcessState(True, False))
        self.assertEqual([request.reload for request in self.process.calls], [False, False])

    def test_unchanged_draft_without_process_transition_still_rejects_no_changes(self):
        self.save(self.original)

        result = self.apply()

        self.assertEqual(result.code, "draft_backup_no_changes")
        self.assertFalse(self.backups.exists())
        self.assertFalse(self.journals.exists())

    def test_process_cannot_change_xkeen_autostart_stored_in_unchanged_init(self):
        initial = b'start_auto="off"\nproxy_router="on"\n'
        self.init.write_bytes(initial)
        self.original = replace(self.original, xkeen_init=initial)
        self.save(replace(self.file_candidate, xkeen_init=initial))

        result = self.apply(mixed=True)

        self.assertEqual(result.code, "draft_process_autostart_in_init")
        self.assertEqual(self.init.read_bytes(), initial)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.process.calls, [])
        self.assertFalse(self.backups.exists())

    def test_xkeen_autostart_edit_cannot_invalidate_process_snapshot_mid_apply(self):
        initial = b'start_auto="off"\nproxy_router="on"\n'
        desired = b'start_auto="on"\nproxy_router="on"\n'
        self.init.write_bytes(initial)
        self.original = replace(self.original, xkeen_init=initial)
        self.save(replace(self.original, xkeen_init=desired))
        self.target = ProcessChange(self.process.snapshot, self.process.snapshot.state, reload=True)

        with patch.object(self.process, "supports", return_value=True):
            result = self.apply(mixed=True)

        self.assertEqual(result.code, "draft_process_autostart_in_init")
        self.assertEqual(self.init.read_bytes(), initial)
        self.assertEqual(self.process.calls, [])
        self.assertFalse(self.backups.exists())

    def test_xkeen_autostart_in_init_is_compensated_as_a_file(self):
        initial = b'start_auto="off"\nproxy_router="on"\n'
        desired = b'start_auto="on"\nproxy_router="on"\n'
        self.init.write_bytes(initial)
        self.original = replace(self.original, xkeen_init=initial)
        self.save(replace(self.original, xkeen_init=desired))

        def reject():
            self.assertEqual(self.init.read_bytes(), desired)
            return False

        result = self.apply(verify=reject)

        document = self.assert_status(result, "compensated")
        file_events = [event for event in document["events"] if event["stage"] == "file"]
        self.assertEqual([event["source"] for event in file_events], ["xkeen_init"] * 4)
        self.assertEqual(self.init.read_bytes(), initial)
        self.assertEqual(self.process.calls, [])

    def test_verified_compensation_restores_files_native_autostart_and_loaded_config_in_order(self):
        self.save(self.mixed_candidate)
        change = self.process.change

        def process(request, check_current):
            if self.process.calls:
                self.assertEqual(self.first.read_bytes(), ORIGINAL)
                self.assertEqual(self.resources[RciResource.HOTSPOT_SETTINGS]["mode"], "original")
                self.assertTrue(request.reload)
            return change(request, check_current)

        with patch.object(self.process, "change", side_effect=process):
            result = self.apply(mixed=True, verify=lambda: False)
        document = self.assert_status(result, "compensated")
        reverse = [(e["stage"], e["part_index"]) for e in document["events"]
                   if e["direction"] == "compensate" and e["phase"] == "finished"]
        self.assertEqual(reverse, [("verify", None), ("native", None), ("file", 1), ("file", 0),
                                   ("process", None), ("verify", None)])
        self.assertEqual(self.process.snapshot.state, ProcessState(True, False))
        self.assertEqual(stat.S_IMODE(self.first.stat().st_mode), 0o640)
        self.assertTrue(any(e.failure is FileStepFailure.CONFLICT for e in result.events))

    def test_network_apply_requires_callback_for_original_route_before_writing(self):
        self.save(self.file_candidate)

        result = self.apply(requires_network_verification=True)

        self.assertEqual(result.code, "invalid_command")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertFalse(self.backups.exists())

    def test_failed_original_route_probe_requires_recovery_after_files_are_restored(self):
        self.save(self.file_candidate)
        calls = []

        def check_original_route():
            self.assert_intent("verify_restored_route")
            calls.append(self.first.read_bytes())
            return False

        result = self.apply(verify=lambda: False, requires_network_verification=True,
                            verify_restored=check_original_route)

        self.assert_status(result, "recovery_required")
        self.assertEqual(calls, [ORIGINAL])
        self.assertEqual(result.events[-1].stage, "verify_restored_route")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)

    def test_probe_can_confirm_original_stopped_service_after_compensation(self):
        self.save(self.mixed_candidate)
        self.process.snapshot = replace(self.process.snapshot, state=ProcessState(False, False))
        self.target = ProcessChange(self.process.snapshot, ProcessState(True, False))
        observations = []

        def check_original_mode():
            observations.append((self.process.snapshot.state, self.first.read_bytes(),
                                 self.resources[RciResource.HOTSPOT_SETTINGS]["mode"]))
            return True

        result = self.apply(mixed=True, verify=lambda: False, requires_network_verification=True,
                            verify_restored=check_original_mode)

        self.assert_status(result, "compensated")
        self.assertEqual(observations, [(ProcessState(False, False), ORIGINAL, "original")])
        event = result.events[-3]
        self.assertEqual(event.stage, "verify_restored_route")
        self.assertIsNone(event.failure)

    def test_explicit_start_can_be_compensated_back_to_stopped(self):
        self.save(self.mixed_candidate)
        self.process.snapshot = replace(self.process.snapshot, state=ProcessState(False, False))
        self.target = ProcessChange(self.process.snapshot, ProcessState(True, False))
        result = self.apply(mixed=True, verify=lambda: False)
        document = self.assert_status(result, "compensated")
        reverse = [e["stage"] for e in document["events"]
                   if e["direction"] == "compensate" and e["phase"] == "started"]
        self.assertEqual(reverse, ["verify", "process", "native", "file", "file", "verify"])
        self.assertEqual(self.process.snapshot.state, ProcessState(False, False))
        self.assertFalse(self.process.calls[-1].reload)

    def test_compensating_only_autostart_does_not_reload_a_running_service(self):
        self.save(self.mixed_candidate)
        self.target = replace(self.target, reload=False)
        result = self.apply(mixed=True, verify=lambda: False)
        self.assert_status(result, "compensated")
        self.assertEqual([request.reload for request in self.process.calls], [False, False])
        self.assertEqual(self.process.snapshot.state, ProcessState(True, False))

    def test_recreates_only_deleted_file_with_original_metadata(self):
        self.save(replace(self.original, xray_configs=parts(added=CANDIDATE, second=ORIGINAL)))
        result = self.apply(verify=lambda: False)
        self.assert_status(result, "compensated")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(stat.S_IMODE(self.first.stat().st_mode), 0o640)
        self.assertFalse((self.xray / "added.json").exists())
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_refuses_delete_when_staging_cannot_restore_owner(self):
        self.save(replace(self.original, xray_configs=parts(second=CANDIDATE)))
        read_metadata = draft_config_files._metadata

        def different_owner(info):
            metadata = read_metadata(info)
            return replace(metadata, uid=metadata.uid + 1)

        # Имитируем другой UID временного файла без смены владельца на хосте.
        with (patch.object(draft_config_files, "_metadata", side_effect=different_owner),
              patch.object(os, "fchown", side_effect=PermissionError(errno.EPERM, "Синтетический отказ")) as chown,
              patch.object(self.files, "write_draft_file", wraps=self.files.write_draft_file) as write):
            result = self.apply()
        self.assertEqual(getattr(result, "code", None), "draft_file_restore_unavailable")
        chown.assert_called_once()
        self.assertEqual(chown.call_args.args[1:], (self.first.stat().st_uid, self.first.stat().st_gid))
        write.assert_not_called()
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        self.assertEqual(list(self.xray.glob(".keenvpn-write-*")), [])

    def test_journal_refs_to_backup_hide_names_even_on_compensation(self):
        name = "contact@example.test.json"
        configurations = XrayConfigSet((
            ConfigDocument(name, CANDIDATE),
            ConfigDocument(self.second.name, ORIGINAL),
        ))
        self.save(replace(self.original, xray_configs=configurations))
        result = self.apply(verify=lambda: False)
        document = self.assert_status(result, "compensated")
        backup_names = self.backup_part_names()
        file_events = [event for event in document["events"] if event["stage"] == "file"]
        self.assertEqual([backup_names[event["part_index"]] for event in file_events],
                         [self.first.name, self.first.name, name, name, name, name, self.first.name, self.first.name])
        journal_path, = self.journals.glob("*.json")
        self.assertNotIn(name, journal_path.read_text())
        self.assertTrue(self.first.exists())
        self.assertFalse((self.xray / name).exists())

    def test_definite_file_refusal_reverts_prefix_and_skips_following_steps(self):
        self.save(self.mixed_candidate)
        write = self.files.write_draft_file

        def refuse_second(change, check):
            if change.target.part == self.second.name:
                return FileStepResult(FileStepFailure.WRITE_FAILED, False)
            return write(change, check)

        with patch.object(self.files, "write_draft_file", side_effect=refuse_second):
            result = self.apply(mixed=True)
        self.assert_status(result, "compensated")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.process.calls, [])

    def test_indeterminate_file_publication_leaves_prefix_and_requires_recovery(self):
        self.save(self.mixed_candidate)
        replace_file = os.replace

        def lose_result(source, target, **kwargs):
            replace_file(source, target, **kwargs)
            if source == "candidate" and target == self.second.name:
                raise OSError(errno.EIO, "synthetic secret exception")

        with patch("os.replace", side_effect=lose_result):
            result = self.apply(mixed=True)
        self.assert_status(result, "recovery_required")
        self.assertIs(result.events[-1].failure, FileStepFailure.UNCONFIRMED)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), CANDIDATE)
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.process.calls, [])

    def test_native_lost_response_does_not_trigger_blind_compensation(self):
        self.save(self.mixed_candidate)

        def uncertain(change, check_current):
            self.assertIsNone(check_current())
            self.resources[RciResource.HOTSPOT_SETTINGS] = json.loads(change.after)
            raise OSError("synthetic private data")

        with patch.object(self.native, "change", side_effect=uncertain):
            result = self.apply(mixed=True)
        self.assert_status(result, "recovery_required")
        self.assertIs(result.events[-1].failure, FileStepFailure.UNCONFIRMED)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.resources[RciResource.HOTSPOT_SETTINGS]["mode"], "next")
        self.assertNotIn("synthetic private data", json.dumps(self.read_journal()))

    def test_process_partial_failure_leaves_configuration_for_explicit_recovery(self):
        self.save(self.mixed_candidate)
        change = self.process.change

        def switch_then_lose_response(request, check_current):
            change(request, check_current)
            return FileStepFailure.UNCONFIRMED

        with patch.object(self.process, "change", side_effect=switch_then_lose_response):
            result = self.apply(mixed=True)
        self.assert_status(result, "recovery_required")
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.process.snapshot.state, ProcessState(True, True))
        self.assertEqual(len(self.process.calls), 1)

    def test_external_native_change_refuses_compensation_without_overwrite(self):
        self.save(self.mixed_candidate)

        def external():
            self.resources[RciResource.HOTSPOT_SETTINGS] = {"host": [], "mode": "external"}
            return False

        result = self.apply(mixed=True, verify=external)
        self.assert_status(result, "recovery_required")
        self.assertEqual(self.resources[RciResource.HOTSPOT_SETTINGS]["mode"], "external")
        self.assertEqual(len(self.native.calls), 1)
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)

    def test_external_file_replacement_with_same_bytes_refuses_compensation(self):
        self.save(self.file_candidate)

        def external():
            other = self.xray / "external.tmp"
            other.write_bytes(CANDIDATE)
            other.replace(self.second)
            return False

        result = self.apply(verify=external)
        self.assert_status(result, "recovery_required")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.second.read_bytes(), CANDIDATE)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)

    def test_successful_probe_cannot_hide_externally_changed_file_permissions(self):
        self.save(self.file_candidate)

        def external():
            self.second.chmod(0o666)
            return True

        result = self.apply(verify=external)
        self.assert_status(result, "recovery_required")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(stat.S_IMODE(self.second.stat().st_mode), 0o666)
        self.assertEqual(self.second.read_bytes(), CANDIDATE)

    def test_external_file_change_prevents_process_reload(self):
        self.save(self.mixed_candidate)
        change_native = self.native.change

        def change_then_edit(request, check_current):
            failure = change_native(request, check_current)
            self.second.chmod(0o666)
            return failure

        with patch.object(self.native, "change", side_effect=change_then_edit):
            result = self.apply(mixed=True)
        self.assert_status(result, "recovery_required")
        self.assertEqual(self.process.calls, [])
        process = [e for e in result.events if e.stage == "process" and e.phase == "finished"]
        self.assertIs(process[0].failure, FileStepFailure.CONFLICT)

    def test_external_directory_replacement_does_not_receive_restored_file(self):
        self.save(replace(self.original, xray_configs=parts(second=ORIGINAL)))

        def external():
            self.xray.rename(self.xray.with_name("unmanaged"))
            self.xray.mkdir()
            self.second.write_bytes(ORIGINAL)
            return False

        result = self.apply(verify=external)
        self.assert_status(result, "recovery_required")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertFalse(self.first.exists())

    def test_external_process_revision_refuses_compensation_before_touching_files(self):
        self.save(self.mixed_candidate)

        def external():
            self.process.snapshot = replace(self.process.snapshot, revision="a" * 64)
            return True

        result = self.apply(mixed=True, verify=external)
        self.assert_status(result, "recovery_required")
        self.assertEqual(len(self.process.calls), 1)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)

    def test_external_restart_while_staging_prevents_first_publication(self):
        self.save(self.file_candidate)
        stage = draft_config_files._stage

        @contextmanager
        def external_restart(parent, content, metadata, cleanup):
            with stage(parent, content, metadata, cleanup) as prepared:
                if content == CANDIDATE:
                    self.process.snapshot = replace(self.process.snapshot, revision="b" * 64)
                yield prepared

        with patch.object(draft_config_files, "_stage", external_restart):
            result = self.apply(mixed=True)

        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        self.assertEqual(self.process.calls, [])
        self.assertEqual(list(self.xray.glob(".keenvpn-write-*")), [])

    def test_external_restart_while_staging_prevents_compensating_publication(self):
        self.save(self.file_candidate)
        stage = draft_config_files._stage

        @contextmanager
        def external_restart(parent, content, metadata, cleanup):
            with stage(parent, content, metadata, cleanup) as prepared:
                if content == ORIGINAL:
                    self.process.snapshot = replace(self.process.snapshot, revision="b" * 64)
                yield prepared

        with patch.object(draft_config_files, "_stage", external_restart):
            result = self.apply(mixed=True, verify=lambda: False)

        self.assert_status(result, "recovery_required")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(result.events[-1].direction, "compensate")
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), CANDIDATE)
        self.assertEqual(len(self.process.calls), 1)
        self.assertEqual(list(self.xray.glob(".keenvpn-write-*")), [])

    def test_restart_during_native_fingerprint_read_prevents_native_write(self):
        self.save(self.mixed_candidate)
        fingerprint = self.files.current_fingerprint

        def read_with_restart(source):
            result = fingerprint(source)
            if source is BaselineSource.KEENETIC_HOTSPOT_SETTINGS and self.journals.exists():
                events = self.read_journal()["events"]
                if events and (events[-1]["direction"], events[-1]["stage"], events[-1]["phase"]) == (
                    "apply", "native", "started",
                ):
                    self.process.snapshot = replace(self.process.snapshot, revision="b" * 64)
            return result

        with patch.object(self.files, "current_fingerprint", side_effect=read_with_restart):
            result = self.apply(mixed=True)

        self.assert_status(result, "recovery_required")
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.resources[RciResource.HOTSPOT_SETTINGS]["mode"], "original")
        outcome = next(event for event in result.events if event.stage == "native" and event.phase == "finished")
        self.assertIs(outcome.failure, FileStepFailure.CONFLICT)

    def test_restart_during_native_port_preparation_prevents_compensating_write(self):
        self.save(self.mixed_candidate)
        change = self.native.change

        def prepare_then_change(request, check_current):
            if self.native.calls:
                self.process.snapshot = replace(self.process.snapshot, revision="b" * 64)
            return change(request, check_current)

        with patch.object(self.native, "change", side_effect=prepare_then_change):
            result = self.apply(mixed=True, verify=lambda: False)

        self.assert_status(result, "recovery_required")
        self.assertEqual(len(self.native.calls), 1)
        self.assertEqual(self.resources[RciResource.HOTSPOT_SETTINGS]["mode"], "next")
        self.assertEqual((result.events[-1].stage, result.events[-1].direction), ("native", "compensate"))
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)

    def test_external_restart_during_compensation_prevents_later_compensations(self):
        self.save(self.mixed_candidate)
        self.process.snapshot = replace(self.process.snapshot, state=ProcessState(False, False))
        self.target = ProcessChange(self.process.snapshot, ProcessState(True, False))
        save = self.journal.save

        def restart(operation_id, content, expected):
            digest = save(operation_id, content, expected)
            events = json.loads(content)["events"]
            if events and (events[-1]["direction"], events[-1]["stage"], events[-1]["phase"]) == (
                "compensate", "native", "started",
            ):
                self.process.snapshot = ProcessSnapshot(ProcessState(True, False), "a" * 64)
            return digest

        with patch.object(self.journal, "save", side_effect=restart):
            result = self.apply(mixed=True, verify=lambda: False)
        self.assert_status(result, "recovery_required")
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(len(self.native.calls), 1)
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)

    def test_backup_loss_after_first_intent_blocks_publication(self):
        self.save(self.file_candidate)
        save = self.journal.save

        def remove_backup(operation_id, content, expected):
            digest = save(operation_id, content, expected)
            if len(json.loads(content)["events"]) == 1:
                backup, = self.backups.glob("*.json")
                backup.unlink()
            return digest

        with (patch.object(self.journal, "save", side_effect=remove_backup),
              patch.object(self.files, "write_draft_file", wraps=self.files.write_draft_file) as write):
            result = self.apply()
        self.assert_status(result, "rejected")
        write.assert_not_called()
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertIs(result.events[-1].failure, FileStepFailure.READ_FAILED)

    def test_backup_loss_during_first_staging_prevents_publication(self):
        self.save(self.file_candidate)
        stage = draft_config_files._stage

        @contextmanager
        def stage_then_remove_backup(parent, content, metadata, cleanup):
            with stage(parent, content, metadata, cleanup) as prepared:
                for backup in self.backups.glob("*.json"):
                    backup.unlink()
                yield prepared

        with patch.object(draft_config_files, "_stage", stage_then_remove_backup):
            result = self.apply()

        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.READ_FAILED)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        self.assertEqual(list(self.xray.glob(".keenvpn-write-*")), [])

    def test_backup_loss_after_publication_prevents_process_transition(self):
        self.save(self.file_candidate)
        write = self.files.write_draft_file

        def publish_then_remove_backup(change, check):
            result = write(change, check)
            if change.target.part == self.first.name:
                backup, = self.backups.glob("*.json")
                backup.unlink()
            return result

        with patch.object(self.files, "write_draft_file", side_effect=publish_then_remove_backup):
            result = self.apply(mixed=True)

        self.assert_status(result, "recovery_required")
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.process.calls, [])
        outcome = next(event for event in result.events if event.stage == "process" and event.phase == "finished")
        self.assertIs(outcome.failure, FileStepFailure.READ_FAILED)

    def test_backup_loss_after_result_verification_prevents_applied_status(self):
        self.save(self.file_candidate)
        save = self.journal.save

        def remove_backup_after_verify(operation_id, content, expected):
            digest = save(operation_id, content, expected)
            events = json.loads(content)["events"]
            if events and (events[-1]["direction"], events[-1]["stage"], events[-1]["phase"]) == (
                "apply", "verify", "finished",
            ):
                backup, = self.backups.glob("*.json")
                backup.unlink()
            return digest

        with patch.object(self.journal, "save", side_effect=remove_backup_after_verify):
            result = self.apply()

        self.assert_status(result, "recovery_required")
        outcome = next(event for event in result.events if event.stage == "verify_backup" and event.phase == "finished")
        self.assertIs(outcome.failure, FileStepFailure.READ_FAILED)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)

    def apply_with_backup_confirmation_change(self, stage, change, *, mixed):
        self.save(self.file_candidate)
        confirm = self.storage.confirm

        def confirm_with_change(backup_id, sha256):
            if self.journals.exists():
                events = self.read_journal()["events"]
                if events and (events[-1]["direction"], events[-1]["stage"], events[-1]["phase"]) == (
                    "apply", stage, "started",
                ):
                    change()
            return confirm(backup_id, sha256)

        with patch.object(self.storage, "confirm", side_effect=confirm_with_change):
            return self.apply(mixed=mixed)

    def test_permissions_changed_during_backup_confirmation_stop_process_transition(self):
        result = self.apply_with_backup_confirmation_change(
            "process", lambda: self.second.chmod(0o666), mixed=True,
        )

        self.assert_status(result, "recovery_required")
        outcome = next(event for event in result.events if event.stage == "process" and event.phase == "finished")
        self.assertIs(outcome.failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.process.calls, [])
        self.assertEqual(stat.S_IMODE(self.second.stat().st_mode), 0o666)

    def test_permissions_changed_during_final_backup_confirmation_prevent_applied_status(self):
        result = self.apply_with_backup_confirmation_change(
            "verify_backup", lambda: self.second.chmod(0o666), mixed=False,
        )

        self.assert_status(result, "recovery_required")
        outcome = next(event for event in result.events if event.stage == "verify_backup" and event.phase == "finished")
        self.assertIs(outcome.failure, FileStepFailure.CONFLICT)
        self.assertEqual(stat.S_IMODE(self.second.stat().st_mode), 0o666)

    def test_process_revision_changed_during_final_backup_confirmation_prevents_applied_status(self):
        def external_restart():
            self.process.snapshot = replace(self.process.snapshot, revision="a" * 64)

        result = self.apply_with_backup_confirmation_change("verify_backup", external_restart, mixed=True)

        self.assert_status(result, "recovery_required")
        outcome = next(event for event in result.events if event.stage == "verify_backup" and event.phase == "finished")
        self.assertIs(outcome.failure, FileStepFailure.CONFLICT)
        self.assertEqual(len(self.process.calls), 1)

    def test_draft_removed_after_first_intent_blocks_native_write(self):
        self.save(replace(self.mixed_candidate, xray_configs=self.original.xray_configs))
        save = self.journal.save

        def remove_draft(operation_id, content, expected):
            digest = save(operation_id, content, expected)
            if len(json.loads(content)["events"]) == 1:
                (self.root / "draft" / DRAFT_FILE_NAME).unlink()
            return digest

        with patch.object(self.journal, "save", side_effect=remove_draft):
            result = self.apply(mixed=True)
        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.process.calls, [])

    def test_unrelated_source_changed_after_first_intent_blocks_native_write(self):
        self.save(replace(self.mixed_candidate, xray_configs=self.original.xray_configs))
        save = self.journal.save

        def change_source(operation_id, content, expected):
            digest = save(operation_id, content, expected)
            if len(json.loads(content)["events"]) == 1:
                self.first.write_bytes(CANDIDATE)
            return digest

        with patch.object(self.journal, "save", side_effect=change_source):
            result = self.apply(mixed=True)
        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.first.read_bytes(), CANDIDATE)

    def assert_draft_conflict_after_staging(self, edit_draft):
        self.save(self.file_candidate)
        stage = draft_config_files._stage
        path = self.root / "draft" / DRAFT_FILE_NAME

        @contextmanager
        def stage_then_edit(parent, content, metadata, cleanup):
            with stage(parent, content, metadata, cleanup) as prepared:
                edit_draft(path)
                yield prepared

        with patch.object(draft_config_files, "_stage", stage_then_edit):
            result = self.apply()

        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        self.assertEqual(list(self.xray.glob(".keenvpn-write-*")), [])

    def test_draft_removed_during_staging_blocks_first_publication(self):
        self.assert_draft_conflict_after_staging(lambda path: path.unlink())

    def test_draft_replaced_during_staging_blocks_first_publication(self):
        def replace_draft(path):
            changed = json.loads(path.read_bytes())
            changed["external_test"] = True
            new = path.with_name("external-test.tmp")
            new.write_text(json.dumps(changed))
            new.chmod(0o600)
            new.replace(path)

        self.assert_draft_conflict_after_staging(replace_draft)
        self.assertNotEqual(self.drafts.read_draft().revision, self.revision)

    def test_draft_removed_during_last_file_fingerprint_read_blocks_first_publication(self):
        self.save(self.file_candidate)
        fingerprint = self.files.current_fingerprint
        reads_during_first_intent = 0

        def read_then_remove(source):
            nonlocal reads_during_first_intent
            current = fingerprint(source)
            if source is BaselineSource.XRAY_CONFIGS and self.journals.exists():
                events = self.read_journal()["events"]
                if len(events) == 1 and events[-1]["stage"] == "file":
                    reads_during_first_intent += 1
                    if reads_during_first_intent == 3:
                        (self.root / "draft" / DRAFT_FILE_NAME).unlink()
            return current

        with patch.object(self.files, "current_fingerprint", side_effect=read_then_remove):
            result = self.apply()

        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(reads_during_first_intent, 3)

    def test_draft_removed_during_native_port_preparation_blocks_first_write(self):
        self.save(replace(self.mixed_candidate, xray_configs=self.original.xray_configs))
        change = self.native.change

        def remove_then_change(request, check_current):
            (self.root / "draft" / DRAFT_FILE_NAME).unlink()
            return change(request, check_current)

        with patch.object(self.native, "change", side_effect=remove_then_change):
            result = self.apply(mixed=True)

        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.process.calls, [])

    def test_backup_removed_during_native_port_preparation_blocks_first_write(self):
        self.save(replace(self.mixed_candidate, xray_configs=self.original.xray_configs))
        change = self.native.change

        def remove_backup_then_change(request, check_current):
            backup, = self.backups.glob("*.json")
            backup.unlink()
            return change(request, check_current)

        with patch.object(self.native, "change", side_effect=remove_backup_then_change):
            result = self.apply(mixed=True)

        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.READ_FAILED)
        self.assertEqual(self.resources[RciResource.HOTSPOT_SETTINGS]["mode"], "original")
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.process.calls, [])

    def test_draft_removed_during_backup_recheck_blocks_process_only_transition(self):
        self.save(self.original)
        self.target = replace(self.target, reload=False)
        confirm = self.storage.confirm
        confirms_during_intent = 0

        def confirm_then_remove(backup_id, sha256):
            nonlocal confirms_during_intent
            confirmed = confirm(backup_id, sha256)
            if self.journals.exists():
                events = self.read_journal()["events"]
                if len(events) == 1 and events[-1]["stage"] == "process":
                    confirms_during_intent += 1
                    if confirms_during_intent == 2:
                        (self.root / "draft" / DRAFT_FILE_NAME).unlink()
            return confirmed

        with patch.object(self.storage, "confirm", side_effect=confirm_then_remove):
            result = self.apply(mixed=True)

        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.process.calls, [])
        self.assertEqual(confirms_during_intent, 2)

    def test_draft_removed_during_process_port_preparation_blocks_process_only_transition(self):
        self.save(self.original)
        self.target = replace(self.target, reload=False)
        change = self.process.change

        def remove_then_change(request, check_current):
            (self.root / "draft" / DRAFT_FILE_NAME).unlink()
            return change(request, check_current)

        with patch.object(self.process, "change", side_effect=remove_then_change):
            result = self.apply(mixed=True)

        self.assert_status(result, "rejected")
        self.assertIs(result.events[-1].failure, FileStepFailure.CONFLICT)
        self.assertEqual(self.process.calls, [])

    def test_backup_cannot_be_used_for_compensation_after_damage(self):
        self.save(self.file_candidate)

        def damage():
            backup, = self.backups.glob("*.json")
            backup.write_bytes(b"corrupt")
            return False

        result = self.apply(verify=damage)
        self.assert_status(result, "recovery_required")
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertIs(result.events[-1].failure, FileStepFailure.READ_FAILED)

    def test_journal_start_failure_prevents_mutation(self):
        self.save(self.file_candidate)
        with patch.object(self.journal, "save", side_effect=OSError(errno.ENOSPC, "synthetic private data")):
            result = self.apply()
        self.assertIs(result.status, DraftJournalStatus.REJECTED)
        self.assertTrue(result.journal_failed)
        self.assertEqual(result.events, ())
        self.assertEqual(self.first.read_bytes(), ORIGINAL)

    def test_first_intent_failure_prevents_mutation(self):
        self.save(self.file_candidate)
        save = self.journal.save

        def refuse_intent(operation_id, content, expected):
            if json.loads(content)["events"]:
                raise OSError(errno.ENOSPC, "synthetic private data")
            return save(operation_id, content, expected)

        with patch.object(self.journal, "save", side_effect=refuse_intent):
            result = self.apply()
        self.assertIs(result.status, DraftJournalStatus.REJECTED)
        self.assertTrue(result.journal_failed)
        self.assertEqual(result.confirmed_events, 0)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.read_journal()["status"], "in_progress")

    def test_journal_outcome_failure_after_write_stops_before_next_action(self):
        self.save(self.file_candidate)
        save = self.journal.save

        def refuse_outcome(operation_id, content, expected):
            if len(json.loads(content)["events"]) == 2:
                raise OSError(errno.ENOSPC, "synthetic private data")
            return save(operation_id, content, expected)

        with patch.object(self.journal, "save", side_effect=refuse_outcome):
            result = self.apply()
        self.assertIs(result.status, DraftJournalStatus.RECOVERY_REQUIRED)
        self.assertTrue(result.journal_failed)
        self.assertEqual(result.confirmed_events, 1)
        self.assertIsNone(result.events[-1].failure)
        self.assert_intent("file", self.first.name)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_journal_outcome_failure_before_any_write_retains_rejected_status(self):
        self.save(self.file_candidate)
        save = self.journal.save

        def fail_after_rejected_step(operation_id, content, expected):
            events = json.loads(content)["events"]
            if len(events) == 2:
                raise OSError(errno.ENOSPC, "Синтетический отказ записи журнала")
            digest = save(operation_id, content, expected)
            if len(events) == 1:
                backup, = self.backups.glob("*.json")
                backup.unlink()
            return digest

        with (patch.object(self.journal, "save", side_effect=fail_after_rejected_step),
              patch.object(self.files, "write_draft_file", wraps=self.files.write_draft_file) as write):
            result = self.apply()

        self.assertIs(result.status, DraftJournalStatus.REJECTED)
        self.assertTrue(result.journal_failed)
        self.assertEqual(result.confirmed_events, 1)
        self.assertIs(result.events[-1].failure, FileStepFailure.READ_FAILED)
        intent, = self.read_journal()["events"]
        self.assertEqual((intent["stage"], intent["part_index"], intent["phase"]), ("file", 0, "started"))
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        write.assert_not_called()

    def test_interruption_after_publication_leaves_only_confirmed_intent(self):
        self.save(self.file_candidate)
        write = self.files.write_draft_file

        def interrupt(change, check):
            result = write(change, check)
            self.assertIsNone(result.code)
            raise KeyboardInterrupt

        with patch.object(self.files, "write_draft_file", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.apply()
        self.assertEqual(self.read_journal()["status"], "in_progress")
        self.assert_intent("file", self.first.name)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        with self.drafts.lock_for_apply() as reader:
            self.assertIsNotNone(reader)

    def test_recovery_if_compensation_itself_fails(self):
        self.save(self.file_candidate)
        write = self.files.write_draft_file

        def fail_restore(change, check):
            if change.restore_metadata is not None:
                return FileStepResult(FileStepFailure.WRITE_FAILED, False)
            return write(change, check)

        with patch.object(self.files, "write_draft_file", side_effect=fail_restore):
            result = self.apply(verify=lambda: False)
        self.assert_status(result, "recovery_required")
        self.assertEqual(self.second.read_bytes(), CANDIDATE)
        self.assertIs(result.events[-1].failure, FileStepFailure.WRITE_FAILED)

    def test_unlock_failure_retains_journal_and_result(self):
        self.save(self.file_candidate)

        class FailingUnlock:
            @contextmanager
            def lock_for_apply(other):
                with self.drafts.lock_for_apply() as reader:
                    yield reader
                raise OSError("synthetic lock error")

        result = self.apply(lock=FailingUnlock())
        self.assert_status(result, "applied")
        self.assertTrue(result.lock_release_failed)

    def test_journal_store_checks_expected_revision_and_refuses_link(self):
        first = b'{"events":[]}'
        previous = self.journal.save(DRAFT_ID, first, None)
        path, = self.journals.glob("*.json")
        self.assertEqual(previous, metadata_revision(first))
        with self.assertRaises(Exception):
            self.journal.save(DRAFT_ID, b"{}", "0" * 64)
        self.assertEqual(path.read_bytes(), first)
        path.unlink()
        target = self.root / "unrelated"
        target.write_bytes(first)
        path.symlink_to(target)
        with self.assertRaises(Exception):
            self.journal.save(DRAFT_ID, b"{}", previous)
        self.assertEqual(target.read_bytes(), first)
