"""Координация применения с другими операциями во временном хранилище."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import tempfile
from threading import Event
import unittest
from unittest.mock import Mock, patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.application.draft_apply import run_draft_apply
from keenvpn.application.draft_session import DRAFT_GONE, DiscardDraft, DiscardDraftHandler, draft_revision_token
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure
from keenvpn.domain.draft_session import DraftSession, encode_draft_session
from keenvpn.domain.source_baseline import BaselineSource, FingerprintState, SourceBaseline, SourceFingerprint
from tests.support.in_memory import InMemoryDraftSessionStore, InMemorySourceFingerprints


DRAFT_ID = "0000abcd-0000-4000-8000-00000000000d"
OTHER_ID = "0000abcd-0000-4000-8000-00000000000e"
FINGERPRINTS = tuple(SourceFingerprint(source, FingerprintState.ABSENT) for source in BaselineSource)
SESSION = DraftSession(DRAFT_ID, datetime(2026, 11, 1, tzinfo=timezone.utc), baseline=SourceBaseline(FINGERPRINTS))


def current_fingerprints():
    source = InMemorySourceFingerprints()
    for fingerprint in FINGERPRINTS:
        source.set_response(fingerprint.source, fingerprint)
    return source


class ApplyOrderTests(unittest.TestCase):
    def test_invalid_draft_id_or_token_is_rejected_before_locking(self):
        lock = Mock()
        apply = Mock()
        source = current_fingerprints()
        for draft_id, token in (("invalid", "0" * 32), (DRAFT_ID, "0" * 64)):
            with self.subTest(draft_id=draft_id, token=token):
                result = run_draft_apply(lock, source, draft_id, token, apply)
                self.assertEqual(result.code, "invalid_command")
                lock.lock_for_apply.assert_not_called()
        self.assertEqual(source.calls, ())
        apply.assert_not_called()

    def test_checks_and_operation_use_the_same_lock_and_read_revision(self):
        store = InMemoryDraftSessionStore(encode_draft_session(SESSION))
        expected = store.read_draft()
        source = current_fingerprints()
        events = []
        result = object()

        @contextmanager
        def locked():
            events.append("lock")
            try:
                yield reader
            finally:
                events.append("release")

        def read():
            events.append("read")
            return store.read_draft()

        def apply(stored):
            self.assertEqual(stored, expected)
            self.assertEqual(source.calls, tuple(BaselineSource))
            events.append("apply")
            return result

        reader = Mock(read_draft=read)
        lock = Mock(lock_for_apply=locked)
        token = draft_revision_token(expected.revision)
        self.assertIs(run_draft_apply(lock, source, DRAFT_ID, token, apply), result)
        self.assertEqual(events, ["lock", "read", "read", "apply", "release"])


class ApplyFileLockTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.directory = root / "draft"
        self.file = self.directory / DRAFT_FILE_NAME
        self.store = DraftSessionFiles(str(self.directory))
        self.peer = DraftSessionFiles(str(self.directory))
        self.source = current_fingerprints()

    def run_apply(self, apply, *, token=None, draft_id=DRAFT_ID):
        if token is None:
            token = self.token
        return run_draft_apply(self.store, self.source, draft_id, token, apply)

    def create(self):
        revision = self.store.create_draft(SESSION)
        self.token = draft_revision_token(revision)
        return revision

    def test_apply_excludes_other_apply_and_every_storage_mutation(self):
        revision = self.create()
        entered = Event()
        finish = Event()
        rival = Mock()

        def apply(stored):
            entered.set()
            self.assertTrue(finish.wait(5))
            return stored.revision

        with ThreadPoolExecutor(max_workers=1) as executor:
            running = executor.submit(self.run_apply, apply)
            try:
                self.assertTrue(entered.wait(5))
                source = current_fingerprints()
                failure = run_draft_apply(self.peer, source, DRAFT_ID, self.token, rival)
                self.assertEqual(failure.code, "draft_store_busy")
                self.assertEqual(source.calls, ())
                rival.assert_not_called()
                for change in (
                    lambda: self.peer.create_draft(SESSION),
                    lambda: self.peer.replace_draft(replace(SESSION, draft_id=OTHER_ID), revision),
                    lambda: self.peer.remove_draft(revision),
                    self.peer.confirm_draft_absent,
                ):
                    with self.subTest(change=change), self.assertRaises(DraftSessionStoreError) as caught:
                        change()
                    self.assertIs(caught.exception.failure, DraftStoreFailure.BUSY)
                command = DiscardDraft(draft_id=DRAFT_ID, expected_revision=self.token)
                cancelled = DiscardDraftHandler(self.peer).execute(command)
                self.assertEqual(cancelled.error.code, "draft_store_busy")
                self.assertEqual(self.file.read_bytes(), encode_draft_session(SESSION))
            finally:
                finish.set()
            self.assertEqual(running.result(5), revision)
        self.assertEqual(DiscardDraftHandler(self.peer).execute(command).data.outcome, "discarded")

    def test_write_lock_also_refuses_apply_before_checking_sources(self):
        revision = self.create()
        apply = Mock()
        original_check = self.peer._check_revision

        def check_revision(directory, expected_revision):
            self.assertEqual(self.run_apply(apply).code, "draft_store_busy")
            return original_check(directory, expected_revision)

        with patch.object(self.peer, "_check_revision", side_effect=check_revision):
            self.peer.replace_draft(SESSION, revision)
        self.assertEqual(self.source.calls, ())
        apply.assert_not_called()

    def test_operation_exception_releases_lock(self):
        revision = self.create()
        for error in (RuntimeError("отказ исполнителя"), KeyboardInterrupt()):
            with self.subTest(error=type(error)), self.assertRaises(type(error)) as caught:
                self.run_apply(Mock(side_effect=error))
            self.assertIs(caught.exception, error)
            self.assertEqual(self.peer.replace_draft(SESSION, revision), revision)
        self.assertEqual(self.run_apply(lambda stored: stored.revision), revision)

    def test_operation_exception_releases_lock_with_live_forked_child(self):
        revision = self.create()
        read_fd, write_fd = os.pipe()
        child = None

        def apply(stored):
            nonlocal child
            child = os.fork()
            if child == 0:
                try:
                    os.close(write_fd)
                    os.read(read_fd, 1)
                finally:
                    os._exit(0)
            raise RuntimeError("отказ исполнителя")

        try:
            with self.assertRaises(RuntimeError):
                self.run_apply(apply)
            # У дочернего процесса открыт унаследованный дескриптор каталога.
            self.assertEqual(self.run_apply(lambda stored: stored.revision), revision)
        finally:
            os.close(read_fd)
            os.close(write_fd)
            if child is not None:
                os.waitpid(child, 0)

    def test_missing_store_returns_conflict_without_creating_directory(self):
        apply = Mock()
        self.assertEqual(self.run_apply(apply, token="0" * 32), DRAFT_GONE)
        self.assertFalse(self.directory.exists())
        self.assertEqual(self.source.calls, ())
        apply.assert_not_called()

    def test_conflicts_skip_operation_and_leave_session_unchanged(self):
        revision = self.create()
        apply = Mock()
        self.assertEqual(self.run_apply(apply, draft_id=OTHER_ID).code, "draft_mismatch")
        self.assertEqual(self.run_apply(apply, token="0" * 32).code, "draft_revision_conflict")
        self.assertEqual(self.source.calls, ())
        source = BaselineSource.XKEEN_INIT
        self.source.set_response(source, SourceFingerprint(source, FingerprintState.PRESENT, sha256="1" * 64))
        self.assertEqual(self.run_apply(apply).code, "draft_baseline_changed")
        apply.assert_not_called()
        self.assertEqual(self.file.read_bytes(), encode_draft_session(SESSION))
        self.assertEqual(self.peer.replace_draft(SESSION, revision), revision)

    def test_external_edit_during_fingerprint_check_is_still_detected(self):
        self.create()
        changed = encode_draft_session(replace(SESSION, draft_id=OTHER_ID))
        apply = Mock()
        original_read = self.source.current_fingerprint

        def read(source):
            self.file.write_bytes(changed)
            return original_read(source)

        with patch.object(self.source, "current_fingerprint", side_effect=read):
            self.assertEqual(self.run_apply(apply).code, "draft_revision_conflict")
        apply.assert_not_called()
        self.assertEqual(self.file.read_bytes(), changed)

    def test_external_directory_replacement_during_check_is_rejected(self):
        self.create()
        saved = self.directory.with_name("saved")
        apply = Mock()
        original_read = self.source.current_fingerprint

        def read(source):
            if not saved.exists():
                self.directory.rename(saved)
                self.peer.create_draft(SESSION)
            return original_read(source)

        with patch.object(self.source, "current_fingerprint", side_effect=read):
            failure = self.run_apply(apply)
        self.assertEqual((failure.code, failure.reason), ("draft_store_unsafe", "replaced"))
        apply.assert_not_called()
