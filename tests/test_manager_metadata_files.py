"""Файловое хранилище метаданных менеджера во временных каталогах; отказы — внедрением, без заполнения диска."""

import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import manager_metadata_files
from keenvpn.adapters.manager_metadata_files import METADATA_FILE_NAME, PROTECTED_DIRECTORIES, ManagerMetadataFiles
from keenvpn.application.ports import (
    ManagerMetadataStore, ManagerMetadataStoreError, MetadataStoreFailure as Failure, MetadataStoreReason as Reason,
)
from keenvpn.domain.manager_metadata import (
    MAX_METADATA_SIZE, METADATA_FORMAT, HistoryLimits, ManagerMetadata, ManagerMetadataError, RoleLocation,
    StorageRoles, StoragePlacement, StorageVariant, TrackedValue, UnknownFields, ValueState,
    encode_manager_metadata, metadata_revision,
)


STORAGE_ID = "0000abcd-0000-4000-8000-00000000000a"
TEMPORARY = "." + METADATA_FILE_NAME + ".tmp-0123456789abcdef"


def metadata(note: str = "первая") -> ManagerMetadata:
    known = lambda value: TrackedValue(ValueState.KNOWN, value)
    data = RoleLocation(ValueState.KNOWN, known(STORAGE_ID), known("/tmp/mnt/test-data/keenvpn"), True)
    roles = StorageRoles(data, RoleLocation(ValueState.UNKNOWN), RoleLocation(ValueState.ABSENT))
    limits = HistoryLimits(TrackedValue(ValueState.UNKNOWN), TrackedValue(ValueState.ABSENT))
    placement = StoragePlacement(known(StorageVariant.SIMPLE), roles, limits)
    return ManagerMetadata(placement, UnknownFields({"note": note}))


def failing(error: BaseException, *, after: int = 0):
    """Обёртка вызова: первые `after` вызовов проходят, следующий отказывает."""
    calls = {"count": 0}

    def wrap(original):
        def call(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] > after:
                raise error
            return original(*args, **kwargs)
        return call
    return wrap


class StoreCase(unittest.TestCase):
    def setUp(self):
        # Реальный путь: на macOS временный каталог находится за ссылкой /var.
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-metadata-")))
        self.addCleanup(self._cleanup)
        self.directory = self.root / "parent" / "keenvpn"
        self.directory.parent.mkdir()
        self.store = ManagerMetadataFiles(str(self.directory))
        self.file = self.directory / METADATA_FILE_NAME

    def _cleanup(self):
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        shutil.rmtree(self.root)

    def assert_failure(self, call, failure, reason=None):
        with self.assertRaises(ManagerMetadataStoreError) as caught:
            call()
        error = caught.exception
        self.assertIs(error.failure, failure)
        self.assertEqual(error.reason, None if reason is None else reason.value if isinstance(reason, Reason) else reason)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn(str(self.root), str(error) + repr(error.args))
        return error

    def write_initial(self) -> tuple[bytes, str]:
        revision = self.store.write_metadata(metadata(), None)
        return self.file.read_bytes(), revision

    def leftovers(self, directory: Path | None = None) -> list[str]:
        return sorted(name for name in os.listdir(directory or self.directory) if name != METADATA_FILE_NAME)

    def initial_store(self, name):
        directory = self.root / name
        store = ManagerMetadataFiles(str(directory))
        revision = store.write_metadata(metadata(), None)
        return store, directory, directory / METADATA_FILE_NAME, revision


class ReadWriteTests(StoreCase):
    def test_store_implements_port(self):
        store: ManagerMetadataStore = self.store
        self.assertIsNone(store.read_metadata())

    def test_first_write_creates_private_directory_and_file(self):
        self.assertIsNone(self.store.read_metadata())
        self.assertFalse(self.directory.exists())
        revision = self.store.write_metadata(metadata(), None)
        content = self.file.read_bytes()
        self.assertEqual(content, encode_manager_metadata(metadata()))
        self.assertEqual(revision, metadata_revision(content))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        stored = self.store.read_metadata()
        self.assertEqual(stored.metadata, metadata())
        self.assertEqual(stored.revision, revision)
        self.assertEqual(self.leftovers(), [])

    def test_private_modes_do_not_depend_on_umask(self):
        previous = os.umask(0o277)
        try:
            self.store.write_metadata(metadata(), None)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)

    def test_write_requires_current_revision(self):
        content, revision = self.write_initial()
        self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), None), Failure.CONFLICT)
        self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), "0" * 64), Failure.CONFLICT)
        self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision.upper()), Failure.CONFLICT)
        self.assertEqual(self.file.read_bytes(), content)
        second = self.store.write_metadata(metadata("вторая"), revision)
        self.assertNotEqual(second, revision)
        self.assertEqual(self.store.read_metadata().metadata, metadata("вторая"))
        self.assert_failure(lambda: self.store.write_metadata(metadata("третья"), revision), Failure.CONFLICT)

    def test_external_change_after_read_is_a_conflict(self):
        _content, revision = self.write_initial()
        external = encode_manager_metadata(metadata("внешняя правка"))
        self.file.write_bytes(external)
        self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision), Failure.CONFLICT)
        self.assertEqual(self.file.read_bytes(), external)

    def test_change_during_write_bypassing_lock_is_a_conflict(self):
        external = encode_manager_metadata(metadata("внешняя правка"))

        def during_temporary_fsync(action):
            original = os.fsync
            state = {"done": False}

            def fsync(descriptor):
                result = original(descriptor)
                # Правка без блокировки после записи временного файла и до переименования.
                if not state["done"] and stat.S_ISREG(os.fstat(descriptor).st_mode):
                    state["done"] = True
                    action()
                return result
            return patch.object(os, "fsync", fsync), state

        def replace_content():
            self.file.write_bytes(external)

        def remove_file():
            self.file.unlink()

        for label, action, expected in (("changed", replace_content, external), ("removed", remove_file, None)):
            with self.subTest(case=label):
                if self.directory.exists():
                    shutil.rmtree(self.directory)
                _content, revision = self.write_initial()
                patcher, state = during_temporary_fsync(action)
                with patcher:
                    self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision), Failure.CONFLICT)
                self.assertTrue(state["done"])
                self.assertEqual(self.file.read_bytes() if self.file.exists() else None, expected)
                self.assertEqual(self.leftovers(), [])
        shutil.rmtree(self.directory)
        self.directory.mkdir(mode=0o700)

        def create_file():
            self.file.write_bytes(external)
            self.file.chmod(0o600)

        patcher, state = during_temporary_fsync(create_file)
        with patcher:
            self.assert_failure(lambda: self.store.write_metadata(metadata("первая"), None), Failure.CONFLICT)
        self.assertTrue(state["done"])
        self.assertEqual(self.file.read_bytes(), external)
        self.assertEqual(self.leftovers(), [])

    def test_unchanged_content_is_not_rewritten(self):
        _content, revision = self.write_initial()
        before = self.file.stat()
        with patch.object(os, "replace", side_effect=AssertionError("повторная запись")), \
                patch.object(os, "write", side_effect=AssertionError("повторная запись")):
            self.assertEqual(self.store.write_metadata(metadata(), revision), revision)
        after = self.file.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))

    def test_parallel_writer_gets_busy_without_change(self):
        content, revision = self.write_initial()
        holder = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision), Failure.BUSY)
            # Чтение не ждёт блокировку: файл публикуется одним переименованием.
            self.assertEqual(self.store.read_metadata().revision, revision)
        finally:
            os.close(holder)
        self.assertEqual(self.file.read_bytes(), content)
        self.store.write_metadata(metadata("вторая"), revision)

    def test_lock_is_released_after_failure(self):
        _content, revision = self.write_initial()
        with patch.object(os, "fsync", side_effect=OSError(errno.EIO, "test")):
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                                Failure.WRITE_FAILED, Reason.IO_ERROR)
        self.store.write_metadata(metadata("вторая"), revision)

    def test_invalid_model_is_rejected_before_any_file_operation(self):
        broken = metadata()
        object.__setattr__(broken.storage.variant, "value", "simple")
        with patch.object(os, "open", side_effect=AssertionError("обращение к файлам")):
            with self.assertRaises(ManagerMetadataError):
                self.store.write_metadata(broken, None)
        self.assertFalse(self.directory.exists())


class ConfirmationTests(StoreCase):
    """Совпадающий файл не подтверждается после внешней правки в обход блокировки."""

    def change_file(self, file, action):
        if action == "delete":
            file.unlink()
        else:
            replacement = file.parent / "external.json"
            replacement.write_bytes(encode_manager_metadata(metadata("внешняя")))
            replacement.chmod(0o600)
            os.replace(replacement, file)

    def test_unchanged_file_changed_after_initial_read_is_not_confirmed(self):
        for action in ("replace", "delete"):
            with self.subTest(action=action):
                store, _directory, file, revision = self.initial_store("before-" + action)
                original = store._read
                changed = False

                def read(descriptor):
                    nonlocal changed
                    current = original(descriptor)
                    if not changed:
                        changed = True
                        self.change_file(file, action)
                    return current

                with patch.object(store, "_read", read), patch.object(os, "fsync", wraps=os.fsync) as sync:
                    self.assert_failure(lambda: store.write_metadata(metadata(), revision), Failure.CONFLICT)
                sync.assert_not_called()
                self.assertTrue(changed)
                if action == "delete":
                    self.assertFalse(file.exists())
                else:
                    self.assertEqual(file.read_bytes(), encode_manager_metadata(metadata("внешняя")))

    def test_unchanged_directory_replaced_after_initial_read_is_not_confirmed(self):
        store, directory, _file, revision = self.initial_store("before-directory")
        old_directory = self.root / "original-directory"
        original = store._read
        changed = False

        def read(descriptor):
            nonlocal changed
            current = original(descriptor)
            if not changed:
                changed = True
                directory.rename(old_directory)
                directory.mkdir(mode=0o700)
            return current

        with patch.object(store, "_read", read), patch.object(os, "fsync", wraps=os.fsync) as sync:
            self.assert_failure(lambda: store.write_metadata(metadata(), revision), Failure.UNSAFE, Reason.REPLACED)
        sync.assert_not_called()
        self.assertTrue(changed)
        self.assertEqual(list(directory.iterdir()), [])
        self.assertEqual((old_directory / METADATA_FILE_NAME).read_bytes(), encode_manager_metadata(metadata()))

    def test_unchanged_file_changed_during_fsync_is_not_confirmed(self):
        for phase in ("file", "directory"):
            for action in ("replace", "delete"):
                with self.subTest(phase=phase, action=action):
                    store, _directory, file, revision = self.initial_store("during-" + phase + "-" + action)
                    original = os.fsync
                    changed = False

                    def sync(descriptor):
                        nonlocal changed
                        original(descriptor)
                        kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
                        if not changed and kind == phase:
                            changed = True
                            self.change_file(file, action)

                    with patch.object(os, "fsync", sync):
                        self.assert_failure(lambda: store.write_metadata(metadata(), revision), Failure.CONFLICT)
                    self.assertTrue(changed)
                    if action == "delete":
                        self.assertFalse(file.exists())
                    else:
                        self.assertEqual(file.read_bytes(), encode_manager_metadata(metadata("внешняя")))

    def test_unchanged_directory_replaced_during_fsync_is_not_confirmed(self):
        for phase in ("file", "directory"):
            with self.subTest(phase=phase):
                store, directory, _file, revision = self.initial_store("during-directory-" + phase)
                old_directory = self.root / ("original-directory-" + phase)
                original = os.fsync
                changed = False

                def sync(descriptor):
                    nonlocal changed
                    original(descriptor)
                    kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
                    if not changed and kind == phase:
                        changed = True
                        directory.rename(old_directory)
                        directory.mkdir(mode=0o700)

                with patch.object(os, "fsync", sync):
                    self.assert_failure(lambda: store.write_metadata(metadata(), revision), Failure.UNSAFE, Reason.REPLACED)
                self.assertTrue(changed)
                self.assertEqual(list(directory.iterdir()), [])
                self.assertEqual((old_directory / METADATA_FILE_NAME).read_bytes(), encode_manager_metadata(metadata()))


class PublicationTests(StoreCase):
    """Опубликованный файл должен оставаться доступным по настроенному пути."""

    def replace_directory(self, directory, moved, foreign):
        directory.rename(moved)
        directory.mkdir(mode=0o700)
        if foreign:
            file = directory / METADATA_FILE_NAME
            file.write_bytes(encode_manager_metadata(metadata("внешняя")))
            file.chmod(0o600)

    def assert_replaced_directory_preserved(self, store, directory, moved, foreign):
        self.assertEqual((moved / METADATA_FILE_NAME).read_bytes(), encode_manager_metadata(metadata("вторая")))
        self.assertEqual(self.leftovers(moved), [])
        if foreign:
            self.assertEqual(store.read_metadata().metadata, metadata("внешняя"))
        else:
            self.assertEqual(list(directory.iterdir()), [])
            self.assertIsNone(store.read_metadata())

    def test_directory_replaced_around_atomic_publication_is_not_confirmed(self):
        for phase in ("before", "after"):
            for foreign in (False, True):
                with self.subTest(phase=phase, foreign=foreign):
                    name = phase + "-" + str(foreign)
                    store, directory, _file, revision = self.initial_store(name)
                    moved = self.root / ("moved-" + name)
                    original = os.replace

                    def replace(*args, **kwargs):
                        if phase == "before":
                            self.replace_directory(directory, moved, foreign)
                        original(*args, **kwargs)
                        if phase == "after":
                            self.replace_directory(directory, moved, foreign)

                    with patch.object(os, "replace", replace):
                        self.assert_failure(lambda: store.write_metadata(metadata("вторая"), revision),
                                            Failure.UNSAFE, Reason.REPLACED)
                    self.assert_replaced_directory_preserved(store, directory, moved, foreign)

    def test_directory_replaced_during_publication_fsync_is_not_confirmed(self):
        for foreign in (False, True):
            with self.subTest(foreign=foreign):
                name = "fsync-" + str(foreign)
                store, directory, _file, revision = self.initial_store(name)
                moved = self.root / ("moved-" + name)
                original = os.fsync
                changed = False

                def sync(descriptor):
                    nonlocal changed
                    original(descriptor)
                    if not changed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        changed = True
                        self.replace_directory(directory, moved, foreign)

                with patch.object(os, "fsync", sync):
                    self.assert_failure(lambda: store.write_metadata(metadata("вторая"), revision),
                                        Failure.UNSAFE, Reason.REPLACED)
                self.assertTrue(changed)
                self.assert_replaced_directory_preserved(store, directory, moved, foreign)

    def test_file_changed_after_publication_is_not_confirmed(self):
        for phase in ("replace", "fsync"):
            for action in ("replace", "delete"):
                with self.subTest(phase=phase, action=action):
                    store, directory, file, revision = self.initial_store("file-" + phase + "-" + action)
                    changed = False

                    def change_file():
                        nonlocal changed
                        changed = True
                        if action == "delete":
                            file.unlink()
                        else:
                            replacement = directory / "external.json"
                            replacement.write_bytes(encode_manager_metadata(metadata("внешняя")))
                            replacement.chmod(0o600)
                            original_replace(replacement, file)

                    original_replace = os.replace
                    original_fsync = os.fsync

                    def replace(*args, **kwargs):
                        original_replace(*args, **kwargs)
                        change_file()

                    def sync(descriptor):
                        original_fsync(descriptor)
                        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                            change_file()

                    target, callback = ("replace", replace) if phase == "replace" else ("fsync", sync)
                    with patch.object(os, target, callback):
                        self.assert_failure(lambda: store.write_metadata(metadata("вторая"), revision), Failure.CONFLICT)
                    self.assertTrue(changed)
                    if action == "delete":
                        self.assertIsNone(store.read_metadata())
                    else:
                        self.assertEqual(store.read_metadata().metadata, metadata("внешняя"))


class DurabilityTests(StoreCase):
    """Подтверждение относится к синхронизированному файлу в приватном каталоге."""

    def test_synced_descriptor_is_held_until_confirmation_and_closed_on_exit(self):
        for changed_content in (False, True):
            for fail_directory_sync in (False, True):
                with self.subTest(changed_content=changed_content, fail_directory_sync=fail_directory_sync):
                    name = "descriptor-" + str(changed_content) + "-" + str(fail_directory_sync)
                    store, _directory, _file, revision = self.initial_store(name)
                    requested = metadata("вторая") if changed_content else metadata()
                    original = os.fsync
                    held_descriptor = None
                    observed = False

                    def sync(descriptor):
                        nonlocal held_descriptor, observed
                        if stat.S_ISREG(os.fstat(descriptor).st_mode):
                            held_descriptor = descriptor
                        else:
                            self.assertTrue(stat.S_ISREG(os.fstat(held_descriptor).st_mode))
                            observed = True
                            if fail_directory_sync:
                                raise OSError(errno.EIO, "test")
                        original(descriptor)

                    with patch.object(os, "fsync", sync):
                        if fail_directory_sync:
                            self.assert_failure(lambda: store.write_metadata(requested, revision),
                                                Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
                        else:
                            self.assertEqual(store.write_metadata(requested, revision),
                                             metadata_revision(encode_manager_metadata(requested)))
                    self.assertTrue(observed)
                    with self.assertRaises(OSError) as caught:
                        os.fstat(held_descriptor)
                    self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_identical_replacement_after_directory_fsync_is_rejected(self):
        for changed_content in (False, True):
            with self.subTest(changed_content=changed_content):
                store, directory, file, revision = self.initial_store("inode-" + str(changed_content))
                requested = metadata("вторая") if changed_content else metadata()
                original = os.fsync
                synced = []
                replaced = False

                def sync(descriptor):
                    nonlocal replaced
                    info = os.fstat(descriptor)
                    original(descriptor)
                    if stat.S_ISREG(info.st_mode):
                        synced.append((info.st_dev, info.st_ino))
                    elif not replaced:
                        replaced = True
                        replacement = directory / "external.json"
                        replacement.write_bytes(file.read_bytes())
                        replacement.chmod(0o600)
                        os.replace(replacement, file)

                with patch.object(os, "fsync", sync):
                    self.assert_failure(lambda: store.write_metadata(requested, revision), Failure.UNSAFE, Reason.REPLACED)
                self.assertTrue(replaced)
                self.assertNotIn((file.stat().st_dev, file.stat().st_ino), synced)
                self.assertEqual(file.read_bytes(), encode_manager_metadata(requested))
                self.assertEqual(self.leftovers(directory), [])

    def test_identical_replacement_after_file_fsync_or_rename_is_rejected(self):
        for changed_content in (False, True):
            with self.subTest(changed_content=changed_content):
                store, directory, file, revision = self.initial_store("early-inode-" + str(changed_content))
                requested = metadata("вторая") if changed_content else metadata()
                original_sync = os.fsync
                original_replace = os.replace
                replaced = False

                def replace_identical():
                    nonlocal replaced
                    replaced = True
                    replacement = directory / "external.json"
                    replacement.write_bytes(file.read_bytes())
                    replacement.chmod(0o600)
                    original_replace(replacement, file)

                def sync(descriptor):
                    original_sync(descriptor)
                    if not replaced and stat.S_ISREG(os.fstat(descriptor).st_mode):
                        replace_identical()

                def replace(*args, **kwargs):
                    original_replace(*args, **kwargs)
                    replace_identical()

                target, callback = ("replace", replace) if changed_content else ("fsync", sync)
                with patch.object(os, target, callback):
                    self.assert_failure(lambda: store.write_metadata(requested, revision), Failure.UNSAFE, Reason.REPLACED)
                self.assertTrue(replaced)
                self.assertEqual(file.read_bytes(), encode_manager_metadata(requested))
                self.assertEqual(self.leftovers(directory), [])

    def test_directory_permissions_changed_after_fsync_are_rejected(self):
        for changed_content in (False, True):
            with self.subTest(changed_content=changed_content):
                store, directory, file, revision = self.initial_store("mode-" + str(changed_content))
                requested = metadata("вторая") if changed_content else metadata()
                original = os.fsync
                changed = False

                def sync(descriptor):
                    nonlocal changed
                    original(descriptor)
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        changed = True
                        directory.chmod(0o777)

                with patch.object(os, "fsync", sync):
                    self.assert_failure(lambda: store.write_metadata(requested, revision), Failure.UNSAFE, Reason.PERMISSIONS)
                self.assertTrue(changed)
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o777)
                self.assertEqual(file.read_bytes(), encode_manager_metadata(requested))

    def test_directory_owner_changed_after_fsync_is_rejected(self):
        for changed_content in (False, True):
            with self.subTest(changed_content=changed_content):
                store, directory, file, revision = self.initial_store("owner-" + str(changed_content))
                requested = metadata("вторая") if changed_content else metadata()
                original_sync, original_stat = os.fsync, os.fstat
                changed = False

                def sync(descriptor):
                    nonlocal changed
                    original_sync(descriptor)
                    if stat.S_ISDIR(original_stat(descriptor).st_mode):
                        changed = True

                def fstat(descriptor):
                    info = original_stat(descriptor)
                    if changed and stat.S_ISDIR(info.st_mode):
                        values = list(info)
                        values[4] = os.geteuid() + 1
                        return os.stat_result(values)
                    return info

                # Владельца меняет управляемый ответ fstat; chown на машине не выполняется.
                with patch.object(os, "fsync", sync), patch.object(os, "fstat", fstat):
                    self.assert_failure(lambda: store.write_metadata(requested, revision), Failure.UNSAFE, Reason.OWNER)
                self.assertTrue(changed)
                self.assertEqual(directory.stat().st_uid, os.geteuid())
                self.assertEqual(file.read_bytes(), encode_manager_metadata(requested))

    def test_directory_permissions_changed_before_publication_are_rejected(self):
        for changed_content in (False, True):
            with self.subTest(changed_content=changed_content):
                store, directory, file, revision = self.initial_store("early-mode-" + str(changed_content))
                requested = metadata("вторая") if changed_content else metadata()
                original = store._read
                changed = False

                def read(descriptor):
                    nonlocal changed
                    current = original(descriptor)
                    if not changed:
                        changed = True
                        directory.chmod(0o777)
                    return current

                with patch.object(store, "_read", read):
                    self.assert_failure(lambda: store.write_metadata(requested, revision), Failure.UNSAFE, Reason.PERMISSIONS)
                self.assertTrue(changed)
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o777)
                self.assertEqual(file.read_bytes(), encode_manager_metadata(metadata()))
                self.assertEqual(self.leftovers(directory), [])


class FailureInjectionTests(StoreCase):
    def check_directory_stat_failure(self, *, after_sync):
        for changed_content in (False, True):
            for stat_call in (1, 2):
                with self.subTest(changed_content=changed_content, stat_call=stat_call):
                    name = "stat-" + str(after_sync) + "-" + str(changed_content) + "-" + str(stat_call)
                    store, directory, file, revision = self.initial_store(name)
                    requested = metadata("вторая") if changed_content else metadata()
                    directory_info = directory.stat()
                    original_read, original_sync, original_stat = store._read, os.fsync, os.fstat
                    armed = False
                    calls = 0
                    failed_descriptor = None

                    def read(descriptor):
                        nonlocal armed
                        current = original_read(descriptor)
                        if not after_sync:
                            armed = True
                        return current

                    def sync(descriptor):
                        nonlocal armed
                        original_sync(descriptor)
                        if after_sync and stat.S_ISDIR(original_stat(descriptor).st_mode):
                            armed = True

                    def fstat(descriptor):
                        nonlocal calls, failed_descriptor
                        info = original_stat(descriptor)
                        if armed and os.path.samestat(info, directory_info):
                            calls += 1
                            if calls == stat_call:
                                failed_descriptor = descriptor
                                raise OSError(errno.EIO, "моделируемый отказ", str(directory))
                        return info

                    with patch.object(store, "_read", read), patch.object(os, "fsync", sync), \
                            patch.object(os, "fstat", fstat):
                        self.assert_failure(lambda: store.write_metadata(requested, revision),
                                            Failure.UNAVAILABLE, Reason.IO_ERROR)
                    self.assertIsNotNone(failed_descriptor)
                    with self.assertRaises(OSError) as caught:
                        original_stat(failed_descriptor)
                    self.assertEqual(caught.exception.errno, errno.EBADF)
                    visible = requested if after_sync else metadata()
                    self.assertEqual(file.read_bytes(), encode_manager_metadata(visible))
                    self.assertEqual(self.leftovers(directory), [])
                    current = store.read_metadata()
                    self.assertEqual(store.write_metadata(requested, current.revision),
                                     metadata_revision(encode_manager_metadata(requested)))

    def test_directory_stat_failure_before_confirmation_is_safe(self):
        self.check_directory_stat_failure(after_sync=False)

    def test_directory_stat_failure_after_fsync_is_safe(self):
        self.check_directory_stat_failure(after_sync=True)

    def check_failed_write(self, target, error, reason, *, after=0):
        content, revision = self.write_initial()
        wrapper = failing(error, after=after)(getattr(os, target))
        with patch.object(os, target, wrapper):
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                                Failure.WRITE_FAILED, reason)
        self.assertEqual(self.file.read_bytes(), content)
        self.assertEqual(self.store.read_metadata().revision, revision)
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)

    def test_no_space_during_write(self):
        self.check_failed_write("write", OSError(errno.ENOSPC, "test"), Reason.NO_SPACE)

    def test_quota_exceeded_during_write(self):
        self.check_failed_write("write", OSError(errno.EDQUOT, "test"), Reason.NO_SPACE)

    def test_short_write_is_completed(self):
        _content, revision = self.write_initial()
        original = os.write
        with patch.object(os, "write", lambda fd, data: original(fd, bytes(data[:7]))):
            second = self.store.write_metadata(metadata("вторая"), revision)
        self.assertEqual(self.file.read_bytes(), encode_manager_metadata(metadata("вторая")))
        self.assertEqual(second, metadata_revision(self.file.read_bytes()))

    def test_zero_length_write_is_an_error(self):
        self.check_failed_write("write", OSError(errno.EIO, "test"), Reason.IO_ERROR)
        _content, revision = self.file.read_bytes(), self.store.read_metadata().revision
        with patch.object(os, "write", lambda _fd, _data: 0):
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                                Failure.WRITE_FAILED, Reason.IO_ERROR)
        self.assertEqual(self.leftovers(), [])

    def test_read_only_file_system_at_temporary_file(self):
        original = os.open

        def open_(path, flags, *args, **kwargs):
            if flags & os.O_CREAT:
                raise OSError(errno.EROFS, "test")
            return original(path, flags, *args, **kwargs)

        content, revision = self.write_initial()
        with patch.object(os, "open", open_):
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                                Failure.WRITE_FAILED, Reason.READ_ONLY)
        self.assertEqual(self.file.read_bytes(), content)
        self.assertEqual(self.leftovers(), [])

    def test_file_fsync_failure(self):
        self.check_failed_write("fsync", OSError(errno.EIO, "test"), Reason.IO_ERROR)

    def test_rename_failure(self):
        self.check_failed_write("replace", OSError(errno.EACCES, "test"), Reason.PERMISSION_DENIED)

    def test_interruption_between_write_and_rename_keeps_previous_file(self):
        content, revision = self.write_initial()
        with patch.object(os, "replace", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                self.store.write_metadata(metadata("вторая"), revision)
        self.assertEqual(self.file.read_bytes(), content)
        self.assertEqual(self.leftovers(), [])
        self.store.write_metadata(metadata("вторая"), revision)

    def test_killed_writer_leaves_only_ignored_temporary_file(self):
        content, revision = self.write_initial()
        # Процесс, убитый до переименования, оставляет полный или обрезанный временный файл.
        (self.directory / TEMPORARY).write_bytes(encode_manager_metadata(metadata("недописанная"))[:20])
        (self.directory / "foreign.txt").write_text("чужой файл")
        (self.directory / (TEMPORARY[:-1] + "x")).write_text("похожее имя")
        os.symlink(self.root, self.directory / (TEMPORARY[:-1] + "e"))
        self.assertEqual(self.store.read_metadata().revision, revision)
        self.assertEqual(self.file.read_bytes(), content)
        self.store.write_metadata(metadata("вторая"), revision)
        self.assertEqual(self.leftovers(), sorted([
            "foreign.txt", TEMPORARY[:-1] + "x", TEMPORARY[:-1] + "e",
        ]))
        self.assertTrue(os.path.islink(self.directory / (TEMPORARY[:-1] + "e")))
        self.assertTrue(self.root.is_dir())

    def test_directory_fsync_failure_after_rename_is_unconfirmed(self):
        _content, revision = self.write_initial()
        directory_fsync = {"count": 0}
        original = os.fsync

        def fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                directory_fsync["count"] += 1
                raise OSError(errno.EIO, "test")
            return original(descriptor)

        with patch.object(os, "fsync", fsync):
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                                Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
        self.assertEqual(directory_fsync["count"], 1)
        # Новый файл уже виден: вызывающий код перечитывает состояние.
        self.assertEqual(self.store.read_metadata().metadata, metadata("вторая"))

    def test_retry_after_unconfirmed_write_confirms_durability(self):
        _content, revision = self.write_initial()
        original = os.fsync
        calls = {"file": 0, "directory": 0}

        def fsync(fail_directory):
            def call(descriptor):
                kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
                calls[kind] += 1
                if kind == "directory" and fail_directory:
                    raise OSError(errno.EIO, "test")
                return original(descriptor)
            return call

        with patch.object(os, "fsync", fsync(True)):
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                                Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
        # Рекомендованный путь восстановления: перечитать и повторить ту же запись.
        visible = self.store.read_metadata()
        self.assertEqual(visible.metadata, metadata("вторая"))
        published = self.file.stat()
        never_rewrite = (patch.object(os, "replace", side_effect=AssertionError("повторная запись")),
                         patch.object(os, "write", side_effect=AssertionError("повторная запись")))
        for fail_directory, label in ((True, "отказ продолжается"), (False, "отказ прошёл")):
            calls.update(file=0, directory=0)
            with self.subTest(case=label), never_rewrite[0], never_rewrite[1], \
                    patch.object(os, "fsync", fsync(fail_directory)):
                if fail_directory:
                    self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), visible.revision),
                                        Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)
                else:
                    self.assertEqual(self.store.write_metadata(metadata("вторая"), visible.revision), visible.revision)
                self.assertEqual(calls, {"file": 1, "directory": 1})
            current = self.file.stat()
            self.assertEqual((current.st_ino, current.st_mtime_ns), (published.st_ino, published.st_mtime_ns))
            self.assertEqual(self.file.read_bytes(), encode_manager_metadata(metadata("вторая")))
        with patch.object(os, "fsync", side_effect=OSError(errno.EIO, "test")):
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), visible.revision),
                                Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR)

    def test_directory_creation_failures(self):
        for error, failure, reason in (
            (OSError(errno.EROFS, "test"), Failure.WRITE_FAILED, Reason.READ_ONLY),
            (OSError(errno.ENOSPC, "test"), Failure.WRITE_FAILED, Reason.NO_SPACE),
            (OSError(errno.EACCES, "test"), Failure.WRITE_FAILED, Reason.PERMISSION_DENIED),
        ):
            with self.subTest(reason=reason.value), patch.object(os, "mkdir", side_effect=error):
                self.assert_failure(lambda: self.store.write_metadata(metadata(), None), failure, reason)
            self.assertFalse(self.directory.exists())

    def test_directory_replaced_during_write(self):
        content, revision = self.write_initial()
        moved = self.root / "moved"
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
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                                Failure.UNSAFE, Reason.REPLACED)
        self.assertTrue(swapped["done"])
        self.assertEqual((moved / METADATA_FILE_NAME).read_bytes(), content)
        self.assertEqual(self.leftovers(moved), [])
        self.assertEqual(os.listdir(self.directory), [])


class SafetyTests(StoreCase):
    def test_missing_parent_is_unavailable_and_nothing_is_created(self):
        store = ManagerMetadataFiles(str(self.root / "absent" / "keenvpn"))
        self.assert_failure(store.read_metadata, Failure.UNAVAILABLE, Reason.MISSING)
        self.assert_failure(lambda: store.write_metadata(metadata(), None), Failure.UNAVAILABLE, Reason.MISSING)
        self.assertFalse((self.root / "absent").exists())

    def test_parent_symlink_and_file_components_are_rejected(self):
        target = self.root / "target"
        target.mkdir()
        os.symlink(target, self.root / "link")
        (self.root / "file").write_text("x")
        for path, reason in (
            (self.root / "link" / "keenvpn", Reason.SYMLINK),
            (self.root / "file" / "keenvpn", Reason.NOT_DIRECTORY),
        ):
            store = ManagerMetadataFiles(str(path))
            with self.subTest(reason=reason.value):
                self.assert_failure(store.read_metadata, Failure.UNSAFE, reason)
                self.assert_failure(lambda: store.write_metadata(metadata(), None), Failure.UNSAFE, reason)
        self.assertEqual(os.listdir(target), [])

    def test_own_directory_must_not_be_a_link_or_file(self):
        target = self.root / "target"
        target.mkdir(mode=0o700)
        os.symlink(target, self.directory)
        self.assert_failure(self.store.read_metadata, Failure.UNSAFE, Reason.SYMLINK)
        self.assert_failure(lambda: self.store.write_metadata(metadata(), None), Failure.UNSAFE, Reason.SYMLINK)
        self.assertEqual(os.listdir(target), [])
        self.directory.unlink()
        self.directory.write_text("x")
        self.assert_failure(lambda: self.store.write_metadata(metadata(), None), Failure.UNSAFE, Reason.NOT_DIRECTORY)

    def test_metadata_file_must_be_a_private_regular_file(self):
        content, _revision = self.write_initial()
        outside = self.root / "outside.json"
        outside.write_bytes(content)
        outside.chmod(0o600)
        self.file.unlink()
        os.symlink(outside, self.file)
        self.assert_failure(self.store.read_metadata, Failure.UNSAFE, Reason.SYMLINK)
        self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), metadata_revision(content)),
                            Failure.UNSAFE, Reason.SYMLINK)
        self.assertEqual(outside.read_bytes(), content)
        self.file.unlink()
        os.mkfifo(self.file, 0o600)
        self.assert_failure(self.store.read_metadata, Failure.UNSAFE, Reason.NOT_REGULAR_FILE)
        self.file.unlink()
        self.file.mkdir(mode=0o700)
        self.assert_failure(self.store.read_metadata, Failure.UNSAFE, Reason.NOT_REGULAR_FILE)

    def test_wrong_modes_are_rejected_without_repair(self):
        content, revision = self.write_initial()
        self.file.chmod(0o644)
        self.assert_failure(self.store.read_metadata, Failure.UNSAFE, Reason.PERMISSIONS)
        self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                            Failure.UNSAFE, Reason.PERMISSIONS)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o644)
        self.assertEqual(self.file.read_bytes(), content)
        self.file.chmod(0o600)
        self.directory.chmod(0o755)
        self.assert_failure(self.store.read_metadata, Failure.UNSAFE, Reason.PERMISSIONS)
        self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                            Failure.UNSAFE, Reason.PERMISSIONS)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)
        self.assertEqual(self.file.read_bytes(), content)

    def test_foreign_owner_is_rejected(self):
        content, revision = self.write_initial()
        with patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            self.assert_failure(self.store.read_metadata, Failure.UNSAFE, Reason.OWNER)
            self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), revision),
                                Failure.UNSAFE, Reason.OWNER)
        self.assertEqual(self.file.read_bytes(), content)

    def test_damaged_or_newer_file_is_not_overwritten(self):
        self.write_initial()
        for label, content, reason in (
            ("json", b'{"format": "keenvpn-manager-metadata", "schema_version": 1,', "invalid_metadata_json"),
            ("newer", json.dumps({"format": METADATA_FORMAT, "schema_version": 2}).encode(),
             "unsupported_metadata_schema_version"),
            ("foreign", b'{"xkeen": true}', "invalid_metadata_format"),
            ("large", b" " * (MAX_METADATA_SIZE + 1), "invalid_metadata_content"),
        ):
            self.file.write_bytes(content)
            with self.subTest(case=label):
                self.assert_failure(self.store.read_metadata, Failure.INVALID, reason)
                self.assert_failure(lambda: self.store.write_metadata(metadata("вторая"), metadata_revision(content)),
                                    Failure.INVALID, reason)
                self.assertEqual(self.file.read_bytes(), content)

    def test_protected_and_invalid_directories_are_rejected_before_file_access(self):
        protected = (str(self.root / "etc" / "xray"), str(self.root / "etc" / "xkeen"))
        allowed = ManagerMetadataFiles(str(self.root / "etc" / "keenvpn"), protected_directories=protected)
        self.assert_failure(allowed.read_metadata, Failure.UNAVAILABLE, Reason.MISSING)
        cases = [(path, Reason.PROTECTED_DIRECTORY) for path in (
            protected[0], protected[0] + "/configs", protected[1], protected[1] + "/keenvpn",
        )]
        cases += [(path, Reason.INVALID_DIRECTORY) for path in (
            "relative/keenvpn", "/", "/opt/keenvpn/", "/opt//keenvpn", "/opt/../keenvpn", "/opt/\nkeenvpn", None,
        )]
        for path, reason in cases:
            store = ManagerMetadataFiles(path, protected_directories=protected)
            with self.subTest(path=path), patch.object(os, "open", side_effect=AssertionError("обращение к файлам")):
                self.assert_failure(store.read_metadata, Failure.UNSAFE, reason)
                self.assert_failure(lambda: store.write_metadata(metadata(), None), Failure.UNSAFE, reason)
        for protected_value in ([str(self.root)], ("relative",)):
            store = ManagerMetadataFiles(str(self.directory), protected_directories=protected_value)
            self.assert_failure(store.read_metadata, Failure.UNSAFE, Reason.INVALID_DIRECTORY)

    def test_default_protection_covers_xray_and_xkeen_directories(self):
        self.assertEqual(PROTECTED_DIRECTORIES, ("/opt/etc/xray", "/opt/etc/xkeen"))
        for path in ("/opt/etc/xray", "/opt/etc/xray/configs", "/opt/etc/xkeen", "/opt/etc/xkeen/keenvpn"):
            with self.subTest(path=path), patch.object(os, "open", side_effect=AssertionError("обращение к файлам")):
                self.assert_failure(ManagerMetadataFiles(path).read_metadata, Failure.UNSAFE,
                                    Reason.PROTECTED_DIRECTORY)
        self.assertEqual(manager_metadata_files.METADATA_FILE_NAME, METADATA_FILE_NAME)
        self.assertFalse(METADATA_FILE_NAME.startswith("."))


if __name__ == "__main__":
    unittest.main()
