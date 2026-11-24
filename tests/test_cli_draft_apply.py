"""Сверка, подтверждение и журналируемая запись через обычный вход vpn-menu."""

from contextlib import contextmanager
from dataclasses import replace
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_backup_files import DraftBackupFiles
from keenvpn.adapters.draft_config_files import DraftConfigFiles
from keenvpn.adapters.draft_journal_files import DraftJournalFiles
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.adapters.geodata_files import XRAY_ASSET_DIRECTORY
from keenvpn.adapters.router_sources import GeoCandidateFiles, GeoDatabaseFiles
from keenvpn.adapters.xray_configs import XRAY_CONFIG_DIRECTORY
from keenvpn.application.contract import ErrorCategory, ErrorDetail
from keenvpn.application.draft_journal import DRAFT_JOURNAL_SCHEMA_VERSION
from keenvpn.application.draft_session import CreateDraft, CreateDraftHandler, draft_revision_token
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure
from keenvpn.application.saved_draft_apply import ApplySavedDraftHandler
from keenvpn.application.draft_file_apply import FileStepFailure, FileStepResult
from keenvpn.application.xray_candidate import XrayTestOutcome
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.draft_candidate_state import DraftCandidateState
from keenvpn.domain.draft_session import encode_draft_session
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation
from keenvpn.interfaces.cli import composition, entrypoints
from keenvpn.interfaces.cli.composition import assemble_main_menu
from keenvpn.interfaces.cli.interactive import InteractiveMenu
from keenvpn.interfaces.cli.menu import MenuNavigator
from tests import test_cli_saved_draft
from tests.support import saved_draft as fixture


class ApplyDraftMenuTests(unittest.TestCase):
    def setUp(self):
        router = test_cli_saved_draft.SavedDraftMenuTests()
        router.setUp()
        self.addCleanup(router.doCleanups)
        self.router = router
        self.original = router.session.candidate.original
        self.part = self.original.xray_configs.parts[-1]
        formatted = ConfigDocument(self.part.name, b"\n" + self.part.content.replace(b'": ', b'" : ', 1) + b"\n")
        self.candidate = replace(self.original, xray_configs=XrayConfigSet(
            (*self.original.xray_configs.parts[:-1], formatted),
        ))
        self.target = router.root / XRAY_CONFIG_DIRECTORY.lstrip("/") / self.part.name
        self.store = DraftSessionFiles(str(router.directory))
        self.backups, self.journals = router.root / "apply-backups", router.root / "apply-journals"
        root = router.root.stat()
        identity = root.st_dev, root.st_ino
        self.storage = DraftBackupFiles(str(self.backups), parent_identity=identity)
        self.journal = DraftJournalFiles(str(self.journals), parent_identity=identity)
        self.files = DraftConfigFiles(root=str(router.root), read=router.rci)
        self.handler = ApplySavedDraftHandler(
            self.store, self.store, self.files, self.storage, self.journal, tester=router.tester,
            readiness=lambda: None, geodata=router.sources.geodata,
            assets=router.sources.candidate_assets, catalogs=router.catalogs,
        )
        self.sources = replace(router.sources, drafts=self.store, draft_apply=self.handler)
        self.save(self.candidate)

    def save(self, candidate):
        session = fixture.session(original=self.original, candidate=candidate)
        (self.router.directory / DRAFT_FILE_NAME).write_bytes(encode_draft_session(session))

    def flow(self, choices):
        output, error = io.StringIO(), io.StringIO()
        with patch.object(entrypoints, "router_sources", return_value=self.sources) as sources:
            code = entrypoints.vpn_menu(["--apply-draft"], io.StringIO(choices) if isinstance(choices, str)
                                        else choices, output, error)
        sources.assert_called_once_with(apply_draft=True)
        self.assertEqual((code, error.getvalue()), (0, ""))
        self.router.assert_private(output.getvalue())
        return output.getvalue()

    def assert_original(self):
        self.assertEqual(self.target.read_bytes(), self.part.content)
        self.assertFalse(self.backups.exists())
        self.assertFalse(self.journals.exists())

    def _save_two_file_draft(self):
        first = self.original.xray_configs.parts[0]
        original_first = ConfigDocument(first.name, b'{"log":{}}')
        candidate_first = ConfigDocument(first.name, b'{"log": {}}\n')
        self.original = replace(self.original, xray_configs=XrayConfigSet((original_first, self.part)))
        candidate = replace(self.candidate, xray_configs=XrayConfigSet(
            (candidate_first, self.candidate.xray_configs.parts[-1]),
        ))
        self.save(candidate)
        first_path = self.router.put(f"{XRAY_CONFIG_DIRECTORY}/{first.name}", original_first.content)
        return first_path, candidate

    def test_cancellation_and_eof_keep_original(self):
        for answer in ("1\n", "0\n", "\n", ""):
            with self.subTest(answer=answer):
                output = self.flow("7\n3\n" + answer)
                self.assertIn("Исходная ревизия подтверждена.", output)
                self.assertIn("installed_xray_candidate: успешно", output)
                self.assertIn("representation: изменено", output)
                self.assertIn("Применить показанные изменения?", output)
                self.assert_original()

    def test_confirm_runs_xray_again_before_backup_and_journal(self):
        tester = self.router.tester
        original_test = tester.test

        def observe(candidate):
            self.assert_original()
            return original_test(candidate)

        with patch.object(tester, "test", side_effect=observe):
            output = self.flow("7\n3\n2\n1\n")
        self.assertIn("Изменения записаны.", output)
        self.assertIn("Посмотреть изменения без секретов", output)
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)
        self.assertEqual(len(tester.calls), 2)
        for checked in tester.calls:
            self.assertEqual(checked.parts, tuple((p.name, p.content) for p in self.candidate.xray_configs.parts))
            self.assertEqual({asset.name: asset.content for asset in checked.assets}, fixture.DATA)
        self.assertEqual(len(list(self.backups.glob("*.json"))), 1)
        self.assertEqual(len(list(self.journals.glob("*.json"))), 1)
        self.assertTrue(self.journal.is_clear())

    def test_success_reports_file_write_even_if_xray_stops_during_publication(self):
        process = XrayProcessObservation((123,), True)
        stopped = XrayProcessObservation((), False)
        self.sources = replace(self.sources, process=SimpleNamespace(current_xray_process=lambda: process))
        write = self.files.write_draft_file

        def stop_after_write(change, check):
            nonlocal process
            result = write(change, check)
            self.assertIsNone(result.code)
            process = stopped
            return result

        with patch.object(self.files, "write_draft_file", side_effect=stop_after_write):
            output = self.flow("7\n3\n2\n")
        self.assertIs(process, stopped)
        self.assertIn("Изменения записаны. Команды управления службой не выполнялись.", output)
        self.assertNotIn("Служба и сетевые настройки сохранены.", output)
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)
        journal, = self.journals.glob("*.json")
        self.assertIsNone(json.loads(journal.read_bytes())["process"])

    def test_success_closes_applied_revision_and_preserves_diff_after_menu_restart(self):
        first_path, candidate = self._save_two_file_draft()
        self.save(replace(candidate, xray_configs=XrayConfigSet(
            (self.original.xray_configs.parts[0], candidate.xray_configs.parts[-1]),
        )))
        saved = (self.router.directory / DRAFT_FILE_NAME).read_bytes()
        first = self.flow("7\n3\n2\n")
        self.assertIn("Изменения записаны.", first)
        self.assertIsNone(self.store.read_draft())
        path, = self.journals.glob("*.json")
        record = json.loads(path.read_bytes())
        self.assertEqual(record["status"], "applied")
        retained = self.router.directory / f"draft-close-{record['operation_id']}.json"
        self.assertEqual(retained.read_bytes(), saved)
        self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record["diff_parts"], [1])
        self.assertEqual(first_path.read_bytes(), self.original.xray_configs.parts[0].content)
        self.assertEqual([(event["stage"], event["phase"]) for event in record["events"][-2:]],
                         [("close_draft", "started"), ("close_draft", "finished")])

        reopened = self.flow("7\n1\n0\n0\n")
        self.assertIn("Последняя подтверждённая операция.", reopened)
        expected_report = [line for line in first.splitlines() if "representation: изменено" in line]
        self.assertTrue(expected_report)
        self.assertEqual([line for line in reopened.splitlines() if "representation: изменено" in line],
                         expected_report)
        self.assertNotIn("draft_baseline_changed", reopened)
        self.assertNotIn("не применён", reopened)
        self.assertTrue(CreateDraftHandler(self.store, self.files).execute(CreateDraft()).succeeded)
        self.assertEqual(retained.read_bytes(), saved)

    def test_completed_diff_uses_apply_order_even_when_clock_moves_back(self):
        _, candidate = self._save_two_file_draft()
        intermediate = replace(self.original, xray_configs=XrayConfigSet(
            (candidate.xray_configs.parts[0], self.original.xray_configs.parts[-1]),
        ))
        self.save(intermediate)
        self.assertIn("Изменения записаны.", self.flow("7\n3\n2\n"))
        first, = self.journals.glob("*.json")
        self.store.create_draft(fixture.session(original=intermediate, candidate=candidate))
        self.assertIn("Изменения записаны.", self.flow("7\n3\n2\n"))
        second, = set(self.journals.glob("*.json")) - {first}
        os.utime(first, (200, 200))
        os.utime(second, (100, 100))

        report = self.flow("7\n1\n")
        self.assertIn("representation: изменено; часть 2", report)
        self.assertNotIn("representation: изменено; часть 1", report)

        # Один порядковый номер не может описывать две успешные операции.
        document = json.loads(second.read_bytes())
        document["sequence"] = json.loads(first.read_bytes())["sequence"]
        second.write_text(json.dumps(document), encoding="ascii")
        self.assertFalse(self.journal.is_clear())
        self.assertIn("draft_apply_recovery_required", self.flow("7\n1\n"))

    def test_close_preserves_replaced_revision_and_requires_recovery(self):
        pending = self.store.read_draft()
        replacement = replace(pending.session, draft_id="1111abcd-0000-4000-8000-000000000020")
        close = self.store._close_applied_draft

        def replace_before_close(directory, expected_revision, operation_id):
            # Внешний писатель обошёл общую блокировку.
            (self.router.directory / DRAFT_FILE_NAME).write_bytes(encode_draft_session(replacement))
            with self.assertRaises(DraftSessionStoreError):
                with self.store.lock_for_apply():
                    self.fail("Завершение должно выполняться под общей блокировкой.")
            close(directory, expected_revision, operation_id)

        with patch.object(self.store, "_close_applied_draft", side_effect=replace_before_close):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление.", output)
        self.assertEqual(self.store.read_draft().session, replacement)
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)
        self.assertFalse(self.journal.is_clear())

    def test_close_preserves_in_place_revision_change_at_boundary(self):
        active = self.router.directory / DRAFT_FILE_NAME
        inode = active.stat().st_ino
        stored = self.store.read_draft()
        revised = replace(stored.session, draft_id="1111abcd-0000-4000-8000-000000000020")
        revised_content = encode_draft_session(revised)
        check_identity = self.store._check_file_identity
        close = self.store._close_applied_draft

        def update_saved_bytes(directory, descriptor):
            active.write_bytes(revised_content)
            self.assertEqual(active.stat().st_ino, inode)
            check_identity(directory, descriptor)

        def close_with_edit(directory, revision, operation_id):
            with patch.object(self.store, "_check_file_identity", side_effect=update_saved_bytes):
                close(directory, revision, operation_id)

        with patch.object(self.store, "_close_applied_draft", side_effect=close_with_edit):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление.", output)
        self.assertNotIn("Изменения записаны.", output)
        self.assertFalse(active.exists())
        path, = self.journals.glob("*.json")
        record = json.loads(path.read_bytes())
        retained = self.router.directory / f"draft-close-{record['operation_id']}.json"
        self.assertEqual(retained.read_bytes(), revised_content)
        self.assertEqual(retained.stat().st_ino, inode)
        self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record["status"], "recovery_required")
        self.assertFalse(self.journal.is_clear())
        self.assertIn("draft_apply_recovery_required", self.flow("7\n3\n"))

    def test_close_does_not_overwrite_existing_destination(self):
        active = self.router.directory / DRAFT_FILE_NAME
        saved = active.read_bytes()
        close = self.store._close_applied_draft

        def put_existing_file(directory, revision, operation_id):
            retained = self.router.directory / f"draft-close-{operation_id}.json"
            retained.write_bytes(b"TEST_recovery_file")
            close(directory, revision, operation_id)

        with patch.object(self.store, "_close_applied_draft", side_effect=put_existing_file):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление.", output)
        self.assertEqual(active.read_bytes(), saved)
        retained, = self.router.directory.glob("draft-close-*.json")
        self.assertEqual(retained.read_bytes(), b"TEST_recovery_file")
        self.assertFalse(self.journal.is_clear())

    def test_known_close_blockers_refuse_before_backup_and_publication(self):
        active = self.router.directory / DRAFT_FILE_NAME
        saved = active.read_bytes()
        for path, flag in ((active, 0x10), (self.router.directory, 0x20)):
            with self.subTest(flag=flag):
                blocked = path.stat()

                def flags(descriptor, _architecture):
                    return flag if os.path.samestat(os.fstat(descriptor), blocked) else 0

                with patch("keenvpn.adapters.draft_session_files.read_linux_inode_flags", side_effect=flags):
                    output = self.flow("7\n3\n2\n")
                self.assertIn("draft_write_failed", output)
                self.assertIn("permission_denied", output)
                self.assertNotIn("Изменения записаны.", output)
                self.assertEqual(active.read_bytes(), saved)
                self.assert_original()

        directory = self.router.directory.stat()
        actual_access = os.access

        def access(path, mode, *, dir_fd, effective_ids=False):
            if os.path.samestat(os.fstat(dir_fd), directory):
                return False
            return actual_access(path, mode, dir_fd=dir_fd, effective_ids=effective_ids)

        with patch("keenvpn.adapters.draft_session_files.os.access", side_effect=access):
            output = self.flow("7\n3\n2\n")
        self.assertIn("draft_write_failed", output)
        self.assertIn("permission_denied", output)
        self.assertEqual(active.read_bytes(), saved)
        self.assert_original()

    def test_unavailable_exclusive_rename_refuses_before_active_write(self):
        with patch("keenvpn.adapters.draft_session_files.rename_new_file",
                   side_effect=OSError(errno.ENOSYS, "TEST_private_errno")) as move:
            output = self.flow("7\n3\n2\n")
        self.assertIn("draft_write_failed", output)
        move.assert_called_once_with("source", "target", src_dir_fd=-1, dst_dir_fd=-1)
        self.assertIsNotNone(self.store.read_draft())
        self.assert_original()

    def test_close_blocker_appearing_during_staging_prevents_first_publication(self):
        active = self.router.directory / DRAFT_FILE_NAME
        saved = active.read_bytes()
        write = self.files.write_draft_file
        exact_file = active.stat()

        def flags(descriptor, _architecture):
            return 0x10 if os.path.samestat(os.fstat(descriptor), exact_file) else 0

        def restrict_before_publication(change, check):
            with patch("keenvpn.adapters.draft_session_files.read_linux_inode_flags", side_effect=flags):
                return write(change, check)

        with patch.object(self.files, "write_draft_file", side_effect=restrict_before_publication):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Применение отклонено до записи", output)
        self.assertIn("file / read_failed", output)
        self.assertEqual(active.read_bytes(), saved)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        path, = self.journals.glob("*.json")
        record = json.loads(path.read_bytes())
        self.assertEqual(record["status"], "rejected")
        self.assertEqual([event["stage"] for event in record["events"]], ["file", "file"])
        self.assertTrue(self.journal.is_clear())

    def test_close_blocker_after_first_publication_restores_first_and_keeps_second(self):
        first, candidate = self._save_two_file_draft()
        active = self.router.directory / DRAFT_FILE_NAME
        saved, identity = active.read_bytes(), active.stat()
        second_inode = self.target.stat().st_ino
        write = self.files.write_draft_file
        blocked = False

        def flags(descriptor, _architecture):
            return 0x10 if blocked and os.path.samestat(os.fstat(descriptor), identity) else 0

        def block_after_first_write(change, check):
            nonlocal blocked
            result = write(change, check)
            if change.target.part == first.name and change.content == candidate.xray_configs.parts[0].content:
                self.assertIsNone(result.code)
                self.assertEqual(first.read_bytes(), change.content)
                blocked = True
            return result

        with patch.object(self.files, "write_draft_file", side_effect=block_after_first_write), \
                patch("keenvpn.adapters.draft_session_files.read_linux_inode_flags", side_effect=flags), \
                patch.object(self.store, "_close_applied_draft",
                             side_effect=DraftSessionStoreError(DraftStoreFailure.WRITE_FAILED)) as close:
            output = self.flow("7\n3\n2\n")

        self.assertTrue(blocked)
        self.assertIn("Предыдущее состояние восстановлено.", output)
        close.assert_not_called()
        self.assertEqual(first.read_bytes(), self.original.xray_configs.parts[0].content)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        self.assertEqual(self.target.stat().st_ino, second_inode)
        self.assertEqual(active.read_bytes(), saved)
        self.assertFalse(list(self.router.directory.glob("draft-close-*.json")))
        path, = self.journals.glob("*.json")
        record = json.loads(path.read_bytes())
        self.assertEqual(record["status"], "compensated")
        files = [event for event in record["events"] if event["stage"] == "file" and event["phase"] == "finished"]
        self.assertEqual([(event["direction"], event["part_index"], event["failure"]) for event in files],
                         [("apply", 0, None), ("apply", 1, "read_failed"), ("compensate", 0, None)])
        self.assertTrue(self.journal.is_clear())

    def test_close_requires_persisted_start_event_before_removal(self):
        saved = self.store.read_draft()
        persist = self.journal.save

        def fail_close_start(operation, content, expected_revision):
            events = json.loads(content)["events"]
            if events and events[-1]["stage"] == "close_draft":
                raise OSError("Журнал недоступен.")
            return persist(operation, content, expected_revision)

        with patch.object(self.journal, "save", side_effect=fail_close_start):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление.", output)
        self.assertEqual(self.store.read_draft(), saved)
        path, = self.journals.glob("*.json")
        self.assertEqual(json.loads(path.read_bytes())["status"], "in_progress")
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)
        self.assertFalse(self.journal.is_clear())

    def test_close_failure_requires_recovery_even_after_draft_was_moved(self):
        saved = (self.router.directory / DRAFT_FILE_NAME).read_bytes()

        def unconfirmed_move(_directory):
            raise DraftSessionStoreError(DraftStoreFailure.WRITE_UNCONFIRMED)

        with patch.object(self.store, "_sync_absent", side_effect=unconfirmed_move):
            first = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление.", first)
        self.assertIn("Отказ применения на этапе close_draft / unconfirmed.", first)
        self.assertIn("Сверьте журнал применения и фактическое состояние", first)
        self.assertIsNone(self.store.read_draft())
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)
        path, = self.journals.glob("*.json")
        record = json.loads(path.read_bytes())
        self.assertEqual(record["status"], "recovery_required")
        self.assertEqual(record["events"][-1]["stage"], "close_draft")
        self.assertEqual(record["events"][-1]["failure"], "unconfirmed")
        retained = self.router.directory / f"draft-close-{record['operation_id']}.json"
        self.assertEqual(retained.read_bytes(), saved)
        self.assertFalse(self.journal.is_clear())
        reopened = self.flow("7\n1\n3\n")
        self.assertEqual(reopened.count("draft_apply_recovery_required"), 2)
        self.assertNotIn("Последняя подтверждённая операция.", reopened)
        self.assertNotIn("Применить показанные изменения?", reopened)

    def _assert_disruption_at_close_requires_recovery(self, disrupt, failure):
        close = self.store._close_applied_draft

        def close_and_disrupt(directory, revision, operation_id):
            close(directory, revision, operation_id)
            disrupt()

        with patch.object(self.store, "_close_applied_draft", side_effect=close_and_disrupt):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление.", output)
        self.assertNotIn("Изменения записаны.", output)
        self.assertIsNone(self.store.read_draft())
        path, = self.journals.glob("*.json")
        journal = json.loads(path.read_bytes())
        self.assertEqual(journal["status"], "recovery_required")
        last = journal["events"][-1]
        self.assertEqual((last["stage"], last["phase"], last["failure"]), ("close_draft", "finished", failure))
        self.assertFalse(self.journal.is_clear())

        reopened = self.flow("7\n1\n3\n")
        self.assertEqual(reopened.count("draft_apply_recovery_required"), 2)
        self.assertNotIn("Применить показанные изменения?", reopened)
        self.assertEqual(list(self.journals.glob("*.json")), [path])

    def test_backup_loss_while_closing_draft_requires_recovery(self):
        def remove_backup():
            backup, = self.backups.glob("*.json")
            backup.unlink()

        self._assert_disruption_at_close_requires_recovery(remove_backup, "read_failed")
        self.assertFalse(list(self.backups.glob("*.json")))
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)

    def test_external_file_change_while_closing_draft_requires_recovery(self):
        external = b"{}\n"
        self._assert_disruption_at_close_requires_recovery(lambda: self.target.write_bytes(external), "conflict")
        self.assertEqual(self.target.read_bytes(), external)

    def test_backup_loss_after_first_publication_keeps_second_file(self):
        first_path, candidate = self._save_two_file_draft()
        second_inode = self.target.stat().st_ino
        write = self.files.write_draft_file

        def lose_backup_after_first(change, check):
            result = write(change, check)
            if change.target.part == first_path.name and result.code is None:
                backup, = self.backups.glob("*.json")
                backup.unlink()
            return result

        with patch.object(self.files, "write_draft_file", side_effect=lose_backup_after_first):
            output = self.flow("7\n3\n2\n")

        self.assertEqual(first_path.read_bytes(), candidate.xray_configs.parts[0].content)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        self.assertEqual(self.target.stat().st_ino, second_inode)
        self.assertIn("Требуется явное восстановление.", output)
        journal, = self.journals.glob("*.json")
        record = json.loads(journal.read_bytes())
        self.assertEqual(record["status"], "recovery_required")
        files = [event for event in record["events"]
                 if event["stage"] == "file" and event["phase"] == "finished"]
        self.assertEqual([(event["part_index"], event["failure"]) for event in files], [(0, None), (1, "read_failed")])

    def test_write_mode_builds_catalogs_only_for_referenced_geo_revisions(self):
        def bytes_field(number, content):
            return bytes((number << 3 | 2, len(content))) + content

        def database(code, child):
            return bytes_field(1, bytes_field(1, code) + bytes_field(2, child))

        ip = database(b"TEST_IP", bytes_field(1, b"\xc0\x00\x02\x00") + b"\x10\x18")
        site = database(b"TEST_SITE", b"\x08\x02" + bytes_field(2, b"example.test"))
        actual = {"geoip.dat": ip, "geosite.dat": site}
        for name, data in actual.items():
            self.router.put(XRAY_ASSET_DIRECTORY + "/" + name, data)
        revisions = tuple(replace(item, sha256=hashlib.sha256(actual[item.reference]).hexdigest())
                          for item in fixture.REVISIONS)
        unused = tuple(replace(revisions[0], reference=f"unused-{index}.dat") for index in range(31))
        session = fixture.session(original=self.original, candidate=self.candidate, revisions=(*revisions, *unused))
        (self.router.directory / DRAFT_FILE_NAME).write_bytes(encode_draft_session(session))
        root = str(self.router.root)
        ports = SimpleNamespace(drafts=self.store, files=self.files, backup=self.storage, journal=self.journal,
                                readiness=lambda: None)
        tester = self.router.tester
        with patch.object(tester, "coordinator_available", return_value=True, create=True), \
                patch.object(composition, "connect_router_manager_files", return_value=self.router.stores), \
                patch.object(composition, "connect_router_draft_apply", return_value=ports), \
                patch.object(composition, "GeoCandidateFiles", return_value=GeoCandidateFiles(root=root)), \
                patch.object(composition, "GeoDatabaseFiles", return_value=GeoDatabaseFiles(root=root)), \
                patch("keenvpn.adapters.xray_isolated_port.IsolatedInstalledXray", return_value=tester):
            sources = composition.router_sources(apply_draft=True)
        catalogs = sources.geo_catalogs.read_catalogs(revisions)
        self.assertEqual([item.categories for item in catalogs], [frozenset({"TEST_IP"}), frozenset({"TEST_SITE"})])
        self.sources = replace(self.router.sources, draft_apply=sources.draft_apply, geo_catalogs=sources.geo_catalogs)

        missing = self.router.root / XRAY_ASSET_DIRECTORY.lstrip("/") / "geosite.dat"
        missing.unlink()
        output = self.flow("7\n3\n")
        self.assertIn("missing_geo_file", output)
        self.assertNotIn("Применить показанные изменения?", output)
        self.assertFalse(tester.calls)
        self.assert_original()
        self.router.put(XRAY_ASSET_DIRECTORY + "/geosite.dat", actual["geosite.dat"])

        with patch.object(sources.geo_catalogs, "read_catalogs", wraps=sources.geo_catalogs.read_catalogs) as read:
            self.assertIn("Изменения записаны.", self.flow("7\n3\n2\n"))
        self.assertEqual([call.args[0] for call in read.call_args_list], [revisions, revisions])
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)
        self.assertEqual(len(tester.calls), 2)
        self.assertTrue(all({asset.name: asset.content for asset in item.assets} == actual for item in tester.calls))

    def test_unsupported_binary_and_incomplete_static_refuse_confirmation(self):
        self.router.tester.outcome = XrayTestOutcome.ISOLATION
        self.router.catalogs.values = ()
        output = self.flow("7\n3\n")
        self.assertIn("draft_apply_check_required", output)
        self.assertNotIn("Применить показанные изменения?", output)
        self.assert_original()

    def test_changed_draft_after_preview_refuses_before_backup(self):
        original_read = io.StringIO.readline
        case = self

        class ChangedInput(io.StringIO):
            calls = 0

            def readline(self, size=-1):
                self.calls += 1
                if self.calls == 3:
                    case.save(case.original)
                return original_read(self, size)

        output = self.flow(ChangedInput("7\n3\n2\n"))
        self.assertIn("draft_revision_conflict", output)
        self.assert_original()
        self.assertEqual(len(self.router.tester.calls), 1)

    def test_geodata_changed_before_publication_blocks_write(self):
        write = self.files.write_draft_file

        def change_assets(change, check):
            self.router.put(XRAY_ASSET_DIRECTORY + "/geoip.dat", b"new database")
            return write(change, check)

        with patch.object(self.files, "write_draft_file", side_effect=change_assets):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Применение отклонено до записи", output)
        self.assertIn("Отказ применения на этапе file / conflict.", output)
        self.assertIn("Сверьте текущие файлы, геобазы и черновик", output)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        self.assertTrue(self.journal.is_clear())

    def test_temporary_file_write_failure_has_distinct_code_and_next_step(self):
        write = self.files.write_draft_file

        def fail_staging(change, check):
            error = OSError(errno.ENOSPC, "TEST_private_error")
            with patch("keenvpn.adapters.draft_config_files.os.write", side_effect=error):
                return write(change, check)

        with patch.object(self.files, "write_draft_file", side_effect=fail_staging):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Применение отклонено до записи", output)
        self.assertIn("Отказ применения на этапе file / write_failed.", output)
        self.assertIn("Проверьте права записи и свободное место", output)
        self.assertNotIn("Сверьте текущие файлы, геобазы и черновик", output)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        self.assertTrue(self.journal.is_clear())

    def test_failed_staging_cleanup_reports_step_even_after_files_are_restored(self):
        write = self.files.write_draft_file

        def fail_first_cleanup(change, check):
            if change.content != self.part.content:
                with patch("keenvpn.adapters.draft_config_files.os.rmdir",
                           side_effect=OSError(errno.EIO, "TEST_private_cleanup")):
                    return write(change, check)
            return write(change, check)

        with patch.object(self.files, "write_draft_file", side_effect=fail_first_cleanup):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление.", output)
        self.assertIn("Сбой очистки на этапе применения file / cleanup_failed.", output)
        self.assertIn("Сверьте журнал применения и фактическое состояние", output)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        path, = self.journals.glob("*.json")
        record = json.loads(path.read_bytes())
        step, = [event for event in record["events"] if event["cleanup_failed"]]
        self.assertIsNone(step["failure"])
        self.assertEqual(step["direction"], "apply")

    def test_failed_binary_recheck_before_backup_blocks_write(self):
        tester = self.router.tester

        def fail_second_test():
            if len(tester.calls) == 2:
                tester.outcome = XrayTestOutcome.REJECTED

        tester.hook = fail_second_test
        output = self.flow("7\n3\n2\n")
        self.assertIn("draft_apply_check_required", output)
        self.assert_original()

    def test_recovery_required_prevents_a_second_attempt_even_with_original_files(self):
        with patch.object(self.files, "write_draft_file",
                          return_value=FileStepResult(FileStepFailure.UNCONFIRMED, False)):
            first = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление", first)
        second = self.flow("7\n3\n2\n")
        self.assertIn("draft_apply_recovery_required", second)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        self.assertEqual(len(list(self.journals.glob("*.json"))), 1)

    def test_unconfirmed_publication_prioritizes_recovery_on_reentry_and_confirmation(self):
        stored = self.store.read_draft()
        preview = self.handler.prepare(stored.session.draft_id, draft_revision_token(stored.revision))
        write = self.files.write_draft_file

        def lose_confirmation(change, check):
            self.assertIsNone(write(change, check).code)
            return FileStepResult(FileStepFailure.UNCONFIRMED, False)

        with patch.object(self.files, "write_draft_file", side_effect=lose_confirmation):
            first = self.flow("7\n3\n2\n")
        self.assertIn("Требуется явное восстановление", first)
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)
        journal, = self.journals.glob("*.json")
        content = journal.read_bytes()
        self.assertEqual(json.loads(content)["status"], "recovery_required")

        is_clear = self.journal.is_clear

        def check_under_lock():
            with self.assertRaises(DraftSessionStoreError):
                with self.store.lock_for_apply():
                    self.fail("Проверка журнала должна выполняться под общей блокировкой.")
            return is_clear()

        with patch.object(self.journal, "is_clear", side_effect=check_under_lock) as guard, \
                patch.object(self.files, "current_fingerprint", wraps=self.files.current_fingerprint) as fingerprint:
            reopened = self.flow("7\n3\n")
            self.assertIn("draft_apply_recovery_required", reopened)
            self.assertNotIn("draft_baseline_changed", reopened)
            retry = self.handler.apply(preview)
            self.assertEqual(retry.code, "draft_apply_recovery_required")
            self.assertEqual(guard.call_count, 2)
            fingerprint.assert_not_called()
        self.assertEqual(list(self.journals.glob("*.json")), [journal])
        self.assertEqual(journal.read_bytes(), content)

    def test_prepare_reports_pending_recovery_even_when_lock_release_fails(self):
        lock = self.store.lock_for_apply

        @contextmanager
        def unconfirmed_release():
            with lock() as reader:
                yield reader
            raise OSError("Блокировка освобождена без подтверждения.")

        with patch.object(self.store, "lock_for_apply", side_effect=unconfirmed_release):
            for journal_clear, code in ((False, "draft_apply_recovery_required"), (True, "draft_apply_unavailable")):
                with self.subTest(journal_clear=journal_clear), \
                        patch.object(self.journal, "is_clear", return_value=journal_clear):
                    output = self.flow("7\n3\n2\n")
                    self.assertIn(code, output)
                    self.assertIn("Не удалось подтвердить освобождение блокировки.", output)
                    self.assertNotIn("Применить показанные изменения?", output)

        self.assert_original()

    def test_malformed_terminal_journal_blocks_attempt(self):
        operation = "1111abcd-0000-4000-8000-000000000020"
        self.journal.save(operation, json.dumps({
            "format": "keenvpn-draft-journal", "schema_version": DRAFT_JOURNAL_SCHEMA_VERSION, "operation_id": operation,
            "status": "applied", "events": [{"stage": "file", "phase": "started"}],
        }).encode(), None)
        output = self.flow("7\n3\n")
        self.assertIn("draft_apply_recovery_required", output)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        self.assertFalse(self.backups.exists())

    def test_applied_journal_requires_files_checks_and_publications(self):
        self.flow("7\n3\n2\n")
        path, = self.journals.glob("*.json")
        content = path.read_bytes()
        for defect in ("only_backup_check", "missing_publication", "missing_check", "missing_close"):
            with self.subTest(defect=defect):
                document = json.loads(content)
                events = document["events"]
                if defect == "only_backup_check":
                    document["events"] = events[-2:]
                elif defect == "missing_check":
                    document["events"] = events[:2] + events[-2:]
                elif defect == "missing_close":
                    document["events"] = events[:-2]
                else:
                    events[1]["publication"] = None
                path.write_text(json.dumps(document), encoding="ascii")
                self.assertFalse(self.journal.is_clear())

    def test_applied_journal_refuses_missing_first_or_last_file_events(self):
        first_path, candidate = self._save_two_file_draft()
        with patch.object(self.journal, "save", wraps=self.journal.save) as save:
            self.assertIn("Изменения записаны.", self.flow("7\n3\n2\n"))
        initial = json.loads(save.call_args_list[0].args[1])
        self.assertEqual(initial["status"], "in_progress")
        self.assertEqual(initial["events"], [])
        expected_plan = [
            {"source": "xray_configs", "part_index": index, "before_sha256": before.sha256, "after_sha256": after.sha256}
            for index, (before, after) in enumerate(zip(self.original.xray_configs.parts, candidate.xray_configs.parts,
                                                       strict=True))
        ]
        self.assertEqual(initial["file_plan"], expected_plan)
        self.assertTrue(self.journal.is_clear())
        path, = self.journals.glob("*.json")
        content = path.read_bytes()
        self.assertEqual(json.loads(content)["file_plan"], expected_plan)
        reverse = fixture.session(original=candidate, candidate=self.original)
        self.store.create_draft(reverse)

        for missing in (0, 1):
            with self.subTest(missing_part_index=missing):
                document = json.loads(content)
                document["events"] = [
                    event for event in document["events"]
                    if event["stage"] != "file" or event["part_index"] != missing
                ]
                path.write_text(json.dumps(document), encoding="ascii")
                self.assertFalse(self.journal.is_clear())
                self.assertIn("draft_apply_recovery_required", self.flow("7\n3\n2\n"))
                self.assertEqual(first_path.read_bytes(), candidate.xray_configs.parts[0].content)
                self.assertEqual(self.target.read_bytes(), candidate.xray_configs.parts[1].content)
                self.assertEqual(list(self.journals.glob("*.json")), [path])

    def test_legacy_terminal_journal_without_plan_blocks_attempt(self):
        self.assertIn("Изменения записаны.", self.flow("7\n3\n2\n"))
        self.assertTrue(self.journal.is_clear())
        path, = self.journals.glob("*.json")
        document = json.loads(path.read_bytes())
        document["schema_version"] = 1
        del document["file_plan"]
        path.write_text(json.dumps(document), encoding="ascii")
        self.assertFalse(self.journal.is_clear())

    def test_compensated_journal_requires_matching_reverse_write(self):
        with patch.object(self.handler, "_verify_assets", side_effect=(True, True, False)):
            output = self.flow("7\n3\n2\n")
        self.assertIn("Предыдущее состояние восстановлено.", output)
        self.assertIn("Отказ применения на этапе verify / conflict.", output)
        self.assertEqual(self.target.read_bytes(), self.part.content)
        self.assertTrue(self.journal.is_clear())
        path, = self.journals.glob("*.json")
        document = json.loads(path.read_bytes())
        document["events"] = [
            event for event in document["events"]
            if (event["direction"], event["stage"]) != ("compensate", "file")
        ]
        path.write_text(json.dumps(document), encoding="ascii")
        self.assertFalse(self.journal.is_clear())

    def test_terminal_journal_must_be_synced_before_reuse(self):
        self.flow("7\n3\n2\n")
        session = fixture.session(original=self.candidate, candidate=self.original)
        self.store.create_draft(session)
        with patch("keenvpn.adapters.private_files.os.fsync", side_effect=OSError):
            output = self.flow("7\n3\n")
        self.assertIn("draft_apply_recovery_required", output)
        self.assertEqual(len(list(self.journals.glob("*.json"))), 1)

    def test_number_selection_explains_specific_unavailable_port(self):
        from keenvpn.adapters.xray_isolated_port import IsolatedInstalledXray

        denied = ErrorDetail(ErrorCategory.SOURCE_FAILED, "draft_apply_permissions", "Недоступно.")
        for coordinator, expected in (
            (False, "изолированный исполнитель проверки Xray недоступен"),
            (True, "не подтверждён доступ на запись"),
        ):
            with self.subTest(coordinator=coordinator), \
                    patch.object(composition, "connect_router_manager_files", return_value=self.router.stores), \
                    patch.object(composition, "connect_router_draft_apply", return_value=denied), \
                    patch.object(IsolatedInstalledXray, "coordinator_available", return_value=coordinator):
                sources = composition.router_sources(apply_draft=True)
                isolated_sources = replace(self.router.sources, draft_apply_unavailable=sources.draft_apply_unavailable)
                output = self.router.run_menu("7\n3\n", sources=isolated_sources)
                self.assertIn(expected, output)
                self.assert_original()

    def test_network_changes_are_blocked_even_after_both_checks_pass(self):
        for candidate in (fixture.snapshot(fixture.SECRET + " "),
                          replace(self.candidate, xkeen_ip_exclude=b"192.0.2.1\n")):
            with self.subTest():
                self.save(candidate)
                output = self.flow("7\n3\n")
                self.assertIn("draft_network_apply_blocked", output)
                self.assertNotIn("Применить показанные изменения?", output)
                self.assert_original()

    def _save_unknown_sources(self, before, after):
        stored = self.store.read_draft()
        document = stored.session.candidate.export()
        document["original"].update(before)
        document["snapshot"].update(after)
        session = replace(stored.session, candidate=DraftCandidateState(document))
        return self.store.replace_draft(session, stored.revision)

    def test_unknown_source_changes_show_masked_diff_and_block_both_apply_stages(self):
        key = "TEST_private_unknown_source"
        value = {key: {"TEST_private_value": [True]}}
        for before, after in (({}, value), (value, {}), (value, {key: {"TEST_private_value": [1]}})):
            with self.subTest(added=not before, removed=not after):
                self.save(self.candidate)
                revision = self._save_unknown_sources(before, after)
                output = self.flow("7\n1\n3\n")
                self.assertEqual(output.count("Изменились неизвестные источники."), 2)
                self.assertIn("representation: изменено", output)
                self.assertIn("installed_xray_candidate: успешно", output)
                self.assertIn("draft_unknown_source_changes", output)
                self.assertNotIn("Применить показанные изменения?", output)

                session = self.store.read_draft().session
                preview = self.handler.prepare(session.draft_id, draft_revision_token(revision))
                report = preview.diff.to_dict()
                self.assertIs(report["unknown_sources_changed"], True)
                self.router.assert_private(str(report))
                result = self.handler.apply(replace(preview, rejection=None))
                self.assertEqual(result.code, "draft_unknown_source_changes")
                self.assertEqual(self.store.read_draft().revision, revision)
                self.assert_original()

    def test_unknown_only_change_has_masked_diff_without_false_equality(self):
        self.save(self.original)
        self._save_unknown_sources({}, {"TEST_private_unknown_source": None})
        output = self.flow("7\n1\n3\n")
        self.assertEqual(output.count("Изменились неизвестные источники."), 2)
        self.assertNotIn("полные снимки совпадают", output)
        self.assertIn("draft_unknown_source_changes", output)
        self.assert_original()

    def test_identical_unknown_sources_do_not_block_proven_whitespace_change(self):
        value = {"TEST_private_unknown_source": {"TEST_private_value": [True, 1, None]}}
        self._save_unknown_sources(value, value)
        output = self.flow("7\n3\n2\n")
        self.assertIn("Изменения записаны.", output)
        self.assertNotIn("Изменились неизвестные источники.", output)
        self.assertEqual(self.target.read_bytes(), self.candidate.xray_configs.parts[-1].content)

    def test_both_layouts_show_preview_cancel_and_return_to_diff(self):
        assembly = assemble_main_menu(self.sources)
        for size in ((123, 31), (70, 26)):
            with self.subTest(size=size):
                menu = InteractiveMenu(MenuNavigator(assembly.menu), assembly.actions,
                                       assembly.header, assembly.exit_check)
                for action in ("7", "3"):
                    menu.key(action)
                    menu.key("enter")
                frame = menu.render(*size, color=False)
                self.assertIn("Исходная ревизия подтверждена.", frame)
                self.assertIn("Бинарная проверка", frame)
                menu.key("page_down")
                self.assertIn("Применить показанные изменения?", menu.render(*size, color=False))
                menu.key("back")
                menu.key("1")
                menu.key("enter")
                self.assertIn("representation:", menu.render(*size, color=False))
                menu.key("back")
                self.assertIn("Черновик и применение", menu.render(*size, color=False))
                self.assert_original()
