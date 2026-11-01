"""Файловое хранилище сессии черновика во временных каталогах; отказы — внедрением, без заполнения диска."""

from datetime import datetime, timezone
import errno
import fcntl
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.adapters.manager_metadata_files import METADATA_FILE_NAME, ManagerMetadataFiles
from keenvpn.adapters.private_files import PROTECTED_DIRECTORIES
from keenvpn.application.ports import (
    DraftSessionStore, DraftSessionStoreError, DraftStoreFailure as Failure, StoreReason as Reason,
)
from keenvpn.domain.draft_session import (
    MAX_DRAFT_SIZE, DraftSession, DraftSessionError, DraftSessionErrorCode, draft_revision, encode_draft_session,
)
from keenvpn.domain.manager_metadata import ManagerMetadata, UnknownFields, encode_manager_metadata


FIRST_ID = "0000abcd-0000-4000-8000-00000000000d"
SECOND_ID = "0000abcd-0000-4000-8000-00000000000e"
TEMPORARY = "." + DRAFT_FILE_NAME + ".tmp-0123456789abcdef"


def session(draft_id: str = FIRST_ID, note: str | None = None) -> DraftSession:
    extra = UnknownFields(None if note is None else {"note": note})
    return DraftSession(draft_id, datetime(2026, 11, 1, 2, 14, 16, tzinfo=timezone.utc), extra)


def directory_sync(directory_info):
    """Отличить fsync собственного каталога от файла и родителя по inode."""
    def kind(descriptor):
        info = os.fstat(descriptor)
        if stat.S_ISREG(info.st_mode):
            return "file"
        return "directory" if os.path.samestat(info, directory_info) else "parent"
    return kind


class StoreCase(unittest.TestCase):
    def setUp(self):
        # Реальный путь: на macOS временный каталог находится за ссылкой /var.
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-draft-")))
        self.addCleanup(self._cleanup)
        self.directory = self.root / "parent" / "draft"
        self.directory.parent.mkdir()
        self.store = DraftSessionFiles(str(self.directory))
        self.file = self.directory / DRAFT_FILE_NAME

    def _cleanup(self):
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        shutil.rmtree(self.root)

    def assert_failure(self, call, failure, reason=None):
        with self.assertRaises(DraftSessionStoreError) as caught:
            call()
        error = caught.exception
        self.assertIs(error.failure, failure)
        self.assertEqual(error.reason, None if reason is None else reason.value if isinstance(reason, Reason) else reason)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn(str(self.root), str(error) + repr(error.args))
        return error

    def create_initial(self) -> tuple[bytes, str]:
        revision = self.store.create_draft(session())
        return self.file.read_bytes(), revision

    def leftovers(self, directory: Path | None = None) -> list[str]:
        return sorted(name for name in os.listdir(directory or self.directory) if name != DRAFT_FILE_NAME)


class CreateReadTests(StoreCase):
    def test_store_implements_port(self):
        store: DraftSessionStore = self.store
        self.assertIsNone(store.read_draft())
        self.assertFalse(self.directory.exists())

    def test_create_makes_private_directory_and_file(self):
        revision = self.store.create_draft(session())
        content = self.file.read_bytes()
        self.assertEqual(content, encode_draft_session(session()))
        self.assertEqual(revision, draft_revision(content))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        stored = self.store.read_draft()
        self.assertEqual((stored.session, stored.revision), (session(), revision))
        self.assertEqual(self.leftovers(), [])

    def test_restrictive_umask_still_gives_exact_permissions(self):
        previous = os.umask(0o277)
        try:
            self.store.create_draft(session())
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)

    def test_existing_draft_is_never_overwritten(self):
        content, _revision = self.create_initial()
        before = self.file.stat()
        with patch.object(os, "replace", side_effect=AssertionError("перезапись")), \
                patch.object(os, "write", side_effect=AssertionError("перезапись")):
            for label, candidate in (("same", session()), ("other", session(SECOND_ID, "вторая"))):
                with self.subTest(case=label):
                    self.assert_failure(lambda: self.store.create_draft(candidate), Failure.CONFLICT)
        after = self.file.stat()
        self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))
        self.assertEqual(self.file.read_bytes(), content)
        self.assertEqual(self.leftovers(), [])

    def test_draft_created_bypassing_lock_during_write_is_kept(self):
        external = encode_draft_session(session(SECOND_ID, "внешний"))
        original = os.fsync
        state = {"done": False}

        def fsync(descriptor):
            result = original(descriptor)
            # Черновик появился в обход блокировки после записи временного файла и до переименования.
            if not state["done"] and stat.S_ISREG(os.fstat(descriptor).st_mode):
                state["done"] = True
                self.file.write_bytes(external)
                self.file.chmod(0o600)
            return result

        with patch.object(os, "fsync", fsync):
            self.assert_failure(lambda: self.store.create_draft(session()), Failure.CONFLICT)
        self.assertTrue(state["done"])
        self.assertEqual(self.file.read_bytes(), external)
        self.assertEqual(self.leftovers(), [])

    def test_concurrent_operation_holding_the_lock_is_busy(self):
        self.directory.mkdir(mode=0o700)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        self.assert_failure(lambda: self.store.create_draft(session()), Failure.BUSY)
        self.assertFalse(self.file.exists())
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        revision = self.store.create_draft(session())
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        self.assert_failure(lambda: self.store.remove_draft(revision), Failure.BUSY)
        self.assertEqual(self.store.read_draft().revision, revision)
        self.file.unlink()
        self.assert_failure(self.store.confirm_draft_absent, Failure.BUSY)

    def test_invalid_model_is_rejected_before_file_access(self):
        broken = session()
        object.__setattr__(broken, "draft_id", FIRST_ID.upper())
        with patch.object(os, "open", side_effect=AssertionError("обращение к файлам")), \
                self.assertRaises(DraftSessionError) as caught:
            self.store.create_draft(broken)
        self.assertIs(caught.exception.code, DraftSessionErrorCode.DRAFT_ID)
        for revision in ("A" * 64, "a" * 63, None):
            with self.subTest(revision=revision), \
                    patch.object(os, "open", side_effect=AssertionError("обращение к файлам")), \
                    self.assertRaises(DraftSessionError) as caught:
                self.store.remove_draft(revision)
            self.assertIs(caught.exception.code, DraftSessionErrorCode.REVISION)

    def test_damaged_or_foreign_file_is_not_overwritten_or_removed(self):
        self.directory.mkdir(mode=0o700)
        metadata = encode_manager_metadata(ManagerMetadata())
        for label, content, reason in (
            ("json", b'{"format": "keenvpn-draft-session",', "invalid_draft_json"),
            ("newer", b'{"format": "keenvpn-draft-session", "schema_version": 2}', "unsupported_draft_schema_version"),
            ("metadata", metadata, "invalid_draft_format"),
            ("large", b" " * (MAX_DRAFT_SIZE + 1), "invalid_draft_content"),
        ):
            self.file.write_bytes(content)
            self.file.chmod(0o600)
            with self.subTest(case=label):
                self.assert_failure(self.store.read_draft, Failure.INVALID, reason)
                self.assert_failure(lambda: self.store.create_draft(session()), Failure.INVALID, reason)
                self.assert_failure(lambda: self.store.remove_draft(draft_revision(content)), Failure.INVALID, reason)
                self.assertEqual(self.file.read_bytes(), content)

    def test_killed_writer_leaves_only_ignored_temporary_file(self):
        self.directory.mkdir(mode=0o700)
        (self.directory / TEMPORARY).write_bytes(encode_draft_session(session())[:20])
        (self.directory / "foreign.txt").write_text("чужой файл")
        (self.directory / (TEMPORARY[:-1] + "x")).write_text("похожее имя")
        self.assertIsNone(self.store.read_draft())
        revision = self.store.create_draft(session())
        self.assertEqual(self.leftovers(), sorted(["foreign.txt", TEMPORARY[:-1] + "x"]))
        (self.directory / TEMPORARY).write_bytes(b"{")
        self.store.remove_draft(revision)
        self.assertEqual(self.leftovers(), sorted(["foreign.txt", TEMPORARY[:-1] + "x"]))

    def test_metadata_and_draft_in_one_directory_do_not_touch_each_other(self):
        metadata_store = ManagerMetadataFiles(str(self.directory))
        metadata_revision = metadata_store.write_metadata(ManagerMetadata(), None)
        metadata = (self.directory / METADATA_FILE_NAME).read_bytes()
        revision = self.store.create_draft(session())
        self.store.remove_draft(revision)
        self.assertEqual((self.directory / METADATA_FILE_NAME).read_bytes(), metadata)
        self.assertEqual(metadata_store.read_metadata().revision, metadata_revision)
        self.assertNotEqual(DRAFT_FILE_NAME, METADATA_FILE_NAME)


class CreateFailureTests(StoreCase):
    def check_failed_create(self, target, error, reason):
        original = getattr(os, target)
        calls = {"count": 0}

        def failing(*args, **kwargs):
            if target == "fsync" and not stat.S_ISREG(os.fstat(args[0]).st_mode):
                return original(*args, **kwargs)
            calls["count"] += 1
            raise error

        with patch.object(os, target, failing):
            self.assert_failure(lambda: self.store.create_draft(session()), Failure.WRITE_FAILED, reason)
        self.assertEqual(calls["count"], 1)
        self.assertFalse(self.file.exists())
        self.assertIsNone(self.store.read_draft())
        self.assertEqual(self.leftovers(), [])

    def test_no_space_and_quota_during_write(self):
        for code in (errno.ENOSPC, errno.EDQUOT):
            with self.subTest(code=code):
                self.check_failed_create("write", OSError(code, "test"), Reason.NO_SPACE)

    def test_io_error_during_write_and_file_fsync(self):
        self.check_failed_create("write", OSError(errno.EIO, "test"), Reason.IO_ERROR)
        self.check_failed_create("fsync", OSError(errno.EIO, "test"), Reason.IO_ERROR)

    def test_rename_failure(self):
        self.check_failed_create("replace", OSError(errno.EACCES, "test"), Reason.PERMISSION_DENIED)

    def test_short_write_is_completed_and_zero_write_fails(self):
        original = os.write
        with patch.object(os, "write", lambda fd, data: original(fd, bytes(data[:7]))):
            revision = self.store.create_draft(session())
        self.assertEqual(self.file.read_bytes(), encode_draft_session(session()))
        self.store.remove_draft(revision)
        with patch.object(os, "write", lambda _fd, _data: 0):
            self.assert_failure(lambda: self.store.create_draft(session()), Failure.WRITE_FAILED, Reason.IO_ERROR)
        self.assertFalse(self.file.exists())
        self.assertEqual(self.leftovers(), [])

    def test_read_only_file_system_at_temporary_file(self):
        original = os.open

        def open_(path, flags, *args, **kwargs):
            if flags & os.O_CREAT:
                raise OSError(errno.EROFS, "test")
            return original(path, flags, *args, **kwargs)

        with patch.object(os, "open", open_):
            self.assert_failure(lambda: self.store.create_draft(session()), Failure.WRITE_FAILED, Reason.READ_ONLY)
        self.assertFalse(self.file.exists())
        self.assertEqual(self.leftovers(), [])

    def test_interruption_before_rename_leaves_no_draft(self):
        with patch.object(os, "replace", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                self.store.create_draft(session())
        self.assertFalse(self.file.exists())
        self.assertEqual(self.leftovers(), [])
        self.store.create_draft(session())

    def test_directory_creation_failures(self):
        for error, reason in (
            (OSError(errno.EROFS, "test"), Reason.READ_ONLY), (OSError(errno.ENOSPC, "test"), Reason.NO_SPACE),
            (OSError(errno.EACCES, "test"), Reason.PERMISSION_DENIED),
        ):
            with self.subTest(reason=reason.value), patch.object(os, "mkdir", side_effect=error):
                self.assert_failure(lambda: self.store.create_draft(session()), Failure.WRITE_FAILED, reason)
            self.assertFalse(self.directory.exists())

    def test_missing_parent_is_unavailable_and_not_created(self):
        store = DraftSessionFiles(str(self.root / "missing" / "draft"))
        self.assert_failure(store.read_draft, Failure.UNAVAILABLE, Reason.MISSING)
        self.assert_failure(lambda: store.create_draft(session()), Failure.UNAVAILABLE, Reason.MISSING)
        self.assertFalse((self.root / "missing").exists())

    def test_directory_fsync_failure_after_rename_is_unconfirmed(self):
        self.directory.mkdir(mode=0o700)
        kind = directory_sync(self.directory.stat())
        original = os.fsync

        def fsync(descriptor):
            if kind(descriptor) == "directory":
                raise OSError(errno.EIO, "test")
            return original(descriptor)

        with patch.object(os, "fsync", fsync):
            self.assert_failure(lambda: self.store.create_draft(session()), Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
        # Черновик уже виден: вызывающий код перечитывает состояние, повтор создания — конфликт.
        self.assertEqual(self.store.read_draft().session, session())
        self.assert_failure(lambda: self.store.create_draft(session()), Failure.CONFLICT)

    def test_directory_replaced_during_create(self):
        moved = self.root / "moved"
        self.directory.mkdir(mode=0o700)
        original = os.fsync
        swapped = {"done": False}

        def fsync(descriptor):
            result = original(descriptor)
            if not swapped["done"] and stat.S_ISREG(os.fstat(descriptor).st_mode):
                # Подмена после записи временного файла и до переименования.
                swapped["done"] = True
                os.rename(self.directory, moved)
                self.directory.mkdir(mode=0o700)
            return result

        with patch.object(os, "fsync", fsync):
            self.assert_failure(lambda: self.store.create_draft(session()), Failure.UNSAFE, Reason.REPLACED)
        self.assertTrue(swapped["done"])
        self.assertEqual(os.listdir(moved), [])
        self.assertEqual(os.listdir(self.directory), [])


class RemoveTests(StoreCase):
    def test_remove_deletes_only_the_session_file(self):
        _content, revision = self.create_initial()
        (self.directory / "foreign.txt").write_text("чужой файл")
        self.assertIsNone(self.store.remove_draft(revision))
        self.assertFalse(self.file.exists())
        self.assertIsNone(self.store.read_draft())
        self.assertEqual(self.leftovers(), ["foreign.txt"])
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        # Повторная отмена с той же ревизией: черновика уже нет — конфликт без изменений.
        self.assert_failure(lambda: self.store.remove_draft(revision), Failure.CONFLICT)
        self.assertEqual(self.leftovers(), ["foreign.txt"])
        shutil.rmtree(self.directory)
        self.assert_failure(lambda: self.store.remove_draft(revision), Failure.CONFLICT)
        self.assertFalse(self.directory.exists())

    def test_other_revision_is_a_conflict_without_removal(self):
        content, revision = self.create_initial()
        self.assert_failure(lambda: self.store.remove_draft(draft_revision(b"other")), Failure.CONFLICT)
        self.assertEqual(self.file.read_bytes(), content)
        self.store.remove_draft(revision)

    def test_change_or_replacement_after_lock_is_not_removed(self):
        content, revision = self.create_initial()
        external = encode_draft_session(session(SECOND_ID, "внешний"))
        cases = (
            ("changed", external, Failure.CONFLICT, None),
            # Те же байты в другом inode: сверка ревизии проходит, удержанный дескриптор — нет.
            ("same bytes", content, Failure.UNSAFE, Reason.REPLACED),
        )
        for label, replacement, failure, reason in cases:
            with self.subTest(case=label):
                read = self.store._read

                def swap_then_read(directory, replacement=replacement):
                    # Замена файла в обход блокировки после открытия удаляемого файла.
                    spare = self.directory / "spare"
                    spare.write_bytes(replacement)
                    spare.chmod(0o600)
                    os.replace(spare, self.file)
                    return read(directory)

                with patch.object(self.store, "_read", swap_then_read):
                    self.assert_failure(lambda: self.store.remove_draft(revision), failure, reason)
                self.assertEqual(self.file.read_bytes(), replacement)
                self.file.write_bytes(content)
                revision = draft_revision(content)

    def test_unlink_failures_keep_the_draft(self):
        content, revision = self.create_initial()
        for error, reason in (
            (OSError(errno.EACCES, "test"), Reason.PERMISSION_DENIED), (OSError(errno.EROFS, "test"), Reason.READ_ONLY),
            (OSError(errno.EIO, "test"), Reason.IO_ERROR),
        ):
            with self.subTest(reason=reason.value), patch.object(os, "unlink", side_effect=error):
                self.assert_failure(lambda: self.store.remove_draft(revision), Failure.WRITE_FAILED, reason)
            self.assertEqual(self.file.read_bytes(), content)
        with patch.object(os, "unlink", side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.store.remove_draft(revision)
        self.assertEqual(self.file.read_bytes(), content)

    def test_directory_fsync_failure_after_unlink_is_unconfirmed(self):
        _content, revision = self.create_initial()
        kind = directory_sync(self.directory.stat())
        original = os.fsync

        def fsync(descriptor):
            if kind(descriptor) == "directory":
                raise OSError(errno.EIO, "test")
            return original(descriptor)

        with patch.object(os, "fsync", fsync):
            self.assert_failure(lambda: self.store.remove_draft(revision), Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
        self.assertIsNone(self.store.read_draft())

    def test_draft_restored_bypassing_lock_during_directory_fsync_is_kept(self):
        _content, revision = self.create_initial()
        external = encode_draft_session(session(SECOND_ID, "внешний"))
        kind = directory_sync(self.directory.stat())
        original = os.fsync
        state = {"done": False}

        def fsync(descriptor):
            # Черновик появился в обход блокировки после удаления, до закрепления каталога.
            if not state["done"] and kind(descriptor) == "directory":
                state["done"] = True
                self.file.write_bytes(external)
                self.file.chmod(0o600)
            return original(descriptor)

        with patch.object(os, "fsync", fsync):
            self.assert_failure(lambda: self.store.remove_draft(revision), Failure.CONFLICT)
        self.assertTrue(state["done"])
        self.assertEqual(self.file.read_bytes(), external)
        self.assertEqual(self.leftovers(), [])

    def test_directory_replaced_during_remove_is_not_reported_as_success(self):
        content, revision = self.create_initial()
        moved = self.root / "moved"
        read = self.store._read

        def swap_then_read(directory):
            # Каталог подменён после открытия: файл по настроенному пути остаётся.
            os.rename(self.directory, moved)
            self.directory.mkdir(mode=0o700)
            shutil.copy2(moved / DRAFT_FILE_NAME, self.file)
            return read(directory)

        with patch.object(self.store, "_read", swap_then_read):
            self.assert_failure(lambda: self.store.remove_draft(revision), Failure.UNSAFE, Reason.REPLACED)
        self.assertEqual(self.file.read_bytes(), content)

    def test_symlink_instead_of_file_is_not_followed_or_removed(self):
        _content, revision = self.create_initial()
        target = self.root / "target.json"
        os.replace(self.file, target)
        os.symlink(target, self.file)
        self.assert_failure(self.store.read_draft, Failure.UNSAFE, Reason.SYMLINK)
        self.assert_failure(lambda: self.store.remove_draft(revision), Failure.UNSAFE, Reason.SYMLINK)
        self.assertTrue(self.file.is_symlink())
        self.assertTrue(target.exists())


class ConfirmAbsentTests(StoreCase):
    def sync_kinds(self, failing: bool = False, restore: bytes | None = None) -> tuple[list[str], object]:
        """Подменённый fsync: виды синхронизируемых объектов, отказ каталога и восстановление файла в обход блокировки."""
        kind = directory_sync(self.directory.stat())
        original = os.fsync
        kinds = []

        def fsync(descriptor):
            kinds.append(kind(descriptor))
            if kinds[-1] == "directory":
                if restore is not None:
                    self.file.write_bytes(restore)
                    self.file.chmod(0o600)
                if failing:
                    raise OSError(errno.EIO, "test")
            return original(descriptor)
        return kinds, patch.object(os, "fsync", fsync)

    def test_missing_directory_needs_no_confirmation_and_is_not_created(self):
        with patch.object(os, "fsync", side_effect=AssertionError("fsync")):
            self.assertIsNone(self.store.confirm_draft_absent())
        self.assertFalse(self.directory.exists())

    def test_absence_is_synced_without_touching_the_directory(self):
        _content, revision = self.create_initial()
        self.store.remove_draft(revision)
        (self.directory / "foreign.txt").write_text("чужой файл")
        (self.directory / TEMPORARY).write_bytes(b"{")
        kinds, patched = self.sync_kinds()
        with patched, patch.object(os, "unlink", side_effect=AssertionError("удаление")):
            self.assertIsNone(self.store.confirm_draft_absent())
        self.assertEqual(kinds, ["directory"])
        self.assertEqual(self.leftovers(), sorted(["foreign.txt", TEMPORARY]))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_present_damaged_or_linked_draft_is_a_conflict_without_removal(self):
        content, _revision = self.create_initial()
        target = self.root / "target.json"
        target.write_bytes(content)
        for label, prepare in (
            ("valid", lambda: None),
            ("damaged", lambda: self.file.write_bytes(b"{")),
            ("symlink", lambda: (self.file.unlink(), os.symlink(target, self.file))),
        ):
            with self.subTest(case=label):
                prepare()
                before = os.lstat(self.file)
                with patch.object(os, "fsync", side_effect=AssertionError("fsync")):
                    self.assert_failure(self.store.confirm_draft_absent, Failure.CONFLICT)
                self.assertEqual(os.lstat(self.file).st_ino, before.st_ino)
        self.assertTrue(self.file.is_symlink())
        self.assertEqual(target.read_bytes(), content)

    def test_repeat_after_unconfirmed_removal_stays_unconfirmed_until_synced(self):
        _content, revision = self.create_initial()
        kinds, patched = self.sync_kinds(failing=True)
        with patched:
            self.assert_failure(lambda: self.store.remove_draft(revision), Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
            self.assert_failure(self.store.confirm_draft_absent, Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
        self.assertEqual(kinds, ["directory", "directory"])
        kinds, patched = self.sync_kinds()
        with patched:
            self.assertIsNone(self.store.confirm_draft_absent())
        self.assertEqual(kinds, ["directory"])
        self.assertFalse(self.file.exists())

    def test_draft_restored_bypassing_lock_during_confirmation_is_kept(self):
        _content, revision = self.create_initial()
        self.store.remove_draft(revision)
        external = encode_draft_session(session(SECOND_ID, "внешний"))
        kinds, patched = self.sync_kinds(restore=external)
        with patched:
            self.assert_failure(self.store.confirm_draft_absent, Failure.CONFLICT)
        self.assertEqual(kinds, ["directory"])
        self.assertEqual(self.file.read_bytes(), external)

    def test_directory_replaced_during_confirmation_is_not_reported_as_success(self):
        _content, revision = self.create_initial()
        self.store.remove_draft(revision)
        moved = self.root / "moved"
        kind = directory_sync(self.directory.stat())
        original = os.fsync

        def fsync(descriptor):
            if kind(descriptor) == "directory" and not moved.exists():
                os.rename(self.directory, moved)
                self.directory.mkdir(mode=0o700)
            return original(descriptor)

        with patch.object(os, "fsync", fsync):
            self.assert_failure(self.store.confirm_draft_absent, Failure.UNSAFE, Reason.REPLACED)


class SafetyTests(StoreCase):
    def test_wrong_permissions_and_owner_are_reported_and_not_fixed(self):
        _content, revision = self.create_initial()
        self.file.chmod(0o644)
        self.assert_failure(self.store.read_draft, Failure.UNSAFE, Reason.PERMISSIONS)
        self.assert_failure(lambda: self.store.remove_draft(revision), Failure.UNSAFE, Reason.PERMISSIONS)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o644)
        self.file.chmod(0o600)
        self.directory.chmod(0o755)
        self.assert_failure(self.store.read_draft, Failure.UNSAFE, Reason.PERMISSIONS)
        self.assert_failure(lambda: self.store.create_draft(session()), Failure.UNSAFE, Reason.PERMISSIONS)
        self.assert_failure(self.store.confirm_draft_absent, Failure.UNSAFE, Reason.PERMISSIONS)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)
        self.directory.chmod(0o700)
        with patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            self.assert_failure(self.store.read_draft, Failure.UNSAFE, Reason.OWNER)
            self.assert_failure(lambda: self.store.remove_draft(revision), Failure.UNSAFE, Reason.OWNER)
        self.assertTrue(self.file.exists())

    def test_links_and_unexpected_objects_are_unsafe(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        os.symlink(real, self.directory)
        self.assert_failure(self.store.read_draft, Failure.UNSAFE, Reason.SYMLINK)
        self.assert_failure(lambda: self.store.create_draft(session()), Failure.UNSAFE, Reason.SYMLINK)
        self.assertEqual(os.listdir(real), [])
        self.directory.unlink()
        linked_parent = self.root / "linked"
        os.symlink(self.directory.parent, linked_parent)
        store = DraftSessionFiles(str(linked_parent / "draft"))
        self.assert_failure(store.read_draft, Failure.UNSAFE, Reason.SYMLINK)
        self.directory.mkdir(mode=0o700)
        os.mkfifo(self.file, 0o600)
        self.assert_failure(self.store.read_draft, Failure.UNSAFE, Reason.NOT_REGULAR_FILE)
        self.file.unlink()
        self.file.mkdir(mode=0o700)
        self.assert_failure(self.store.read_draft, Failure.UNSAFE, Reason.NOT_REGULAR_FILE)
        self.file.rmdir()
        shutil.rmtree(self.directory)
        self.directory.write_text("не каталог")
        self.assert_failure(self.store.read_draft, Failure.UNSAFE, Reason.NOT_DIRECTORY)

    def test_protected_and_invalid_directories_are_rejected_before_file_access(self):
        self.assertEqual(PROTECTED_DIRECTORIES, ("/opt/etc/xray", "/opt/etc/xkeen", "/opt/etc/init.d"))
        cases = [(path, Reason.PROTECTED_DIRECTORY) for path in (
            "/opt/etc/xray", "/opt/etc/xray/configs", "/opt/etc/xray/configs/draft", "/opt/etc/xkeen",
            "/opt/etc/xkeen/draft", "/opt/etc/init.d", "/opt/etc/init.d/draft",
        )]
        cases += [(path, Reason.INVALID_DIRECTORY) for path in (
            "relative/draft", "/", "/opt/draft/", "/opt//draft", "/opt/../draft", "/opt/\ndraft", None,
        )]
        revision = draft_revision(b"x")
        for path, reason in cases:
            store = DraftSessionFiles(path)
            with self.subTest(path=path), patch.object(os, "open", side_effect=AssertionError("обращение к файлам")):
                self.assert_failure(store.read_draft, Failure.UNSAFE, reason)
                self.assert_failure(lambda: store.create_draft(session()), Failure.UNSAFE, reason)
                self.assert_failure(lambda: store.remove_draft(revision), Failure.UNSAFE, reason)
        etc = self.root / "etc"
        etc.mkdir()
        protected = tuple(str(etc / name) for name in ("xray", "xkeen", "init.d"))
        for name in ("xray-draft", "init.draft", "keenvpn"):
            with self.subTest(name=name):
                # Похожие имена рядом с защищёнными каталогами не защищены.
                store = DraftSessionFiles(str(etc / name), protected_directories=protected)
                store.create_draft(session())
                self.assertEqual(store.read_draft().session, session())

    def test_errors_do_not_reveal_paths_or_system_text(self):
        private = self.root / "TEST_secret-owner" / "draft"
        private.parent.mkdir()
        store = DraftSessionFiles(str(private))
        with patch.object(os, "mkdir", side_effect=OSError(errno.EACCES, "TEST_system_text", str(private))):
            error = self.assert_failure(lambda: store.create_draft(session()), Failure.WRITE_FAILED,
                                        Reason.PERMISSION_DENIED)
        self.assertNotIn("TEST_", str(error) + repr(error.args) + repr(vars(error)))


if __name__ == "__main__":
    unittest.main()
