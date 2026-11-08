"""Замена приватной сессии: гонки, сбои записи, fsync и прерывания."""

from dataclasses import replace
import errno
import fcntl
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.ports import DraftStoreFailure as Failure, StoreReason as Reason
from keenvpn.domain.draft_candidate_state import build_draft_candidate
from keenvpn.domain.draft_session import DraftSessionError, draft_revision, encode_draft_session
from tests import test_draft_candidate_state as candidate_fixture
from tests import test_draft_session_files as fixture


class ReplaceTests(fixture.StoreCase):
    def setUp(self):
        super().setUp()
        self.old = candidate_fixture.session()
        original = candidate_fixture.snapshot()
        state = build_draft_candidate(original, replace(original, xkeen_init=b'new\n'), candidate_fixture.GEO)
        self.new = replace(self.old, candidate=state)
        self.revision = self.store.create_draft(self.old)
        self.before = self.file.read_bytes()

    def change(self):
        return self.store.replace_draft(self.new, self.revision)

    def assert_old(self):
        self.assertEqual(self.file.read_bytes(), self.before)
        self.assertEqual(self.leftovers(), [])

    def test_replace_returns_revision_and_private_file_with_full_candidate(self):
        revision = self.change()
        self.assertEqual(revision, draft_revision(self.file.read_bytes()))
        self.assertEqual(self.file.read_bytes(), encode_draft_session(self.new))
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        self.assertEqual(self.store.read_draft().session.baseline, self.old.baseline)
        self.assertEqual(self.leftovers(), [])

    def test_stale_revision_is_conflict_before_any_write(self):
        info = self.file.stat()
        with patch.object(os, 'write', side_effect=AssertionError('запись')), \
             patch.object(os, 'replace', side_effect=AssertionError('замена')):
            self.assert_failure(lambda: self.store.replace_draft(self.new, 'a'*64), Failure.CONFLICT)
        self.assertEqual(self.file.stat().st_ino, info.st_ino)
        self.assert_old()

    def test_missing_file_and_directory_are_conflict_without_creation(self):
        self.file.unlink()
        self.assert_failure(self.change, Failure.CONFLICT)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.directory.rmdir()
        self.assert_failure(self.change, Failure.CONFLICT)
        self.assertFalse(self.directory.exists())

    def test_corrupt_file_is_preserved(self):
        for content in (b'{', b'{"format":"keenvpn-draft-session","schema_version":2}',
                        self.before.replace(b'"baseline"', b'"candidate"')):
            self.file.write_bytes(content)
            self.assert_failure(lambda: self.store.replace_draft(self.new, draft_revision(content)), Failure.INVALID,
                                self._invalid_reason(content))
            self.assertEqual(self.file.read_bytes(), content)

    def _invalid_reason(self, content):
        from keenvpn.domain.draft_session import decode_draft_session
        try:
            decode_draft_session(content)
        except DraftSessionError as error:
            return error.code.value
        self.fail('Ожидался повреждённый файл.')

    def test_invalid_revision_and_model_do_not_access_files(self):
        for revision in (None, 'A'*64, 'a'*32):
            with patch.object(os, 'open', side_effect=AssertionError('файлы')), self.assertRaises(DraftSessionError):
                self.store.replace_draft(self.new, revision)
        with patch.object(os, 'open', side_effect=AssertionError('файлы')), self.assertRaises(DraftSessionError):
            self.store.replace_draft(None, self.revision)

    def test_same_directory_lock_prevents_replace(self):
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        self.assert_failure(self.change, Failure.BUSY)
        self.assert_old()

    def test_write_and_no_space_failures_keep_old_file(self):
        for code, reason in ((errno.EIO, Reason.IO_ERROR), (errno.ENOSPC, Reason.NO_SPACE)):
            with self.subTest(code=code), patch.object(os, 'write', side_effect=OSError(code, candidate_fixture.SECRET)):
                self.assert_failure(self.change, Failure.WRITE_FAILED, reason)
            self.assert_old()

    def test_partial_writes_complete_before_publication(self):
        write = os.write
        with patch.object(os, 'write', side_effect=lambda fd, data: write(fd, data[:7])):
            self.change()
        self.assertEqual(self.file.read_bytes(), encode_draft_session(self.new))

    def test_zero_write_and_rename_failure_keep_old_file(self):
        with patch.object(os, 'write', return_value=0):
            self.assert_failure(self.change, Failure.WRITE_FAILED, Reason.IO_ERROR)
        self.assert_old()
        with patch.object(os, 'replace', side_effect=OSError(errno.EIO, candidate_fixture.SECRET)):
            self.assert_failure(self.change, Failure.WRITE_FAILED, Reason.IO_ERROR)
        self.assert_old()

    def test_temporary_file_fsync_failure_keeps_old_file(self):
        real = os.fsync
        def fsync(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, candidate_fixture.SECRET)
            return real(fd)
        with patch.object(os, 'fsync', side_effect=fsync):
            self.assert_failure(self.change, Failure.WRITE_FAILED, Reason.IO_ERROR)
        self.assert_old()

    def test_directory_fsync_is_unconfirmed_and_retry_confirms_without_rename(self):
        real = os.fsync
        def fsync(fd):
            if os.path.samestat(os.fstat(fd), self.directory.stat()):
                raise OSError(errno.EIO, candidate_fixture.SECRET)
            return real(fd)
        with patch.object(os, 'fsync', side_effect=fsync):
            self.assert_failure(self.change, Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
        new_revision = self.store.read_draft().revision
        self.assertEqual(self.file.read_bytes(), encode_draft_session(self.new))
        self.assert_failure(self.change, Failure.CONFLICT)
        with patch.object(os, 'replace', side_effect=AssertionError('лишнее переименование')), \
             patch.object(os, 'fsync', wraps=real) as calls:
            self.assertEqual(self.store.replace_draft(self.new, new_revision), new_revision)
            self.assertGreaterEqual(calls.call_count, 2)
        with patch.object(os, 'fsync', side_effect=fsync):
            self.assert_failure(lambda: self.store.replace_draft(self.new, new_revision),
                                Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)

    def test_external_change_during_temporary_fsync_is_not_overwritten(self):
        real = os.fsync
        external = self.before + b'\n'
        def fsync(fd):
            result = real(fd)
            if stat.S_ISREG(os.fstat(fd).st_mode):
                self.file.write_bytes(external)
            return result
        with patch.object(os, 'fsync', side_effect=fsync):
            self.assert_failure(self.change, Failure.CONFLICT)
        self.assertEqual(self.file.read_bytes(), external)
        self.assertEqual(self.leftovers(), [])

    def test_symlink_and_directory_substitution_are_rejected(self):
        saved = self.root / 'saved.json'
        self.file.rename(saved)
        self.file.symlink_to(saved)
        self.assert_failure(self.change, Failure.UNSAFE, Reason.SYMLINK)
        self.assertEqual(saved.read_bytes(), self.before)
        self.file.unlink(); saved.rename(self.file)
        real = os.fsync
        moved = self.root / 'moved'
        def fsync(fd):
            result = real(fd)
            if stat.S_ISREG(os.fstat(fd).st_mode) and not moved.exists():
                self.directory.rename(moved)
                self.directory.mkdir(mode=0o700)
            return result
        with patch.object(os, 'fsync', side_effect=fsync):
            self.assert_failure(self.change, Failure.UNSAFE, Reason.REPLACED)
        self.assertEqual((moved / self.file.name).read_bytes(), self.before)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_interrupted_before_publication_keeps_old_file_and_cleans_temporary(self):
        with patch.object(os, 'replace', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.change()
        self.assert_old()

    def test_interrupted_after_publication_leaves_complete_readable_new_file(self):
        real = os.fsync
        def fsync(fd):
            if os.path.samestat(os.fstat(fd), self.directory.stat()):
                raise KeyboardInterrupt
            return real(fd)
        with patch.object(os, 'fsync', side_effect=fsync), self.assertRaises(KeyboardInterrupt):
            self.change()
        current = self.store.read_draft()
        self.assertEqual(self.file.read_bytes(), encode_draft_session(self.new))
        self.assertEqual(self.store.replace_draft(self.new, current.revision), current.revision)
        self.assertEqual(self.leftovers(), [])

    def test_parent_sync_is_required_before_replacement_and_confirmation(self):
        real = os.fsync
        def fsync(fd):
            if os.path.samestat(os.fstat(fd), self.directory.parent.stat()):
                raise OSError(errno.EIO, candidate_fixture.SECRET)
            return real(fd)
        for model in (self.old, self.new):
            with patch.object(os, 'fsync', side_effect=fsync):
                self.assert_failure(lambda: self.store.replace_draft(model, self.revision),
                                    Failure.UNAVAILABLE, Reason.IO_ERROR)
            self.assert_old()

    def test_stale_temporary_file_is_removed_but_foreign_files_survive(self):
        (self.directory / fixture.TEMPORARY).write_bytes(b'{partial')
        foreign = self.directory / 'foreign'; foreign.write_bytes(b'kept')
        self.change()
        self.assertFalse((self.directory / fixture.TEMPORARY).exists())
        self.assertEqual(foreign.read_bytes(), b'kept')
