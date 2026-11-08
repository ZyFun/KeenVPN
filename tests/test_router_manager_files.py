"""Подключение обоих CLI к приватным файлам DATA без роутера и записей."""

from contextlib import contextmanager, ExitStack
from dataclasses import replace
import errno
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.adapters.manager_metadata_files import METADATA_FILE_NAME, ManagerMetadataFiles
from keenvpn.adapters.private_files import PROTECTED_DIRECTORIES
from keenvpn.adapters.router_manager_files import (
    DRAFT_DIRECTORY, METADATA_DIRECTORY, connect_router_manager_files,
)
from keenvpn.application.ports import DraftSessionStoreError, ManagerMetadataStoreError
from keenvpn.domain.manager_metadata import (
    ManagerMetadata, RoleLocation, TrackedValue, UnknownFields, ValueState, decode_manager_metadata,
)
from keenvpn.interfaces.cli import composition, entrypoints
from tests import test_cli_terminal as cli_fixture
from tests import test_draft_session_files as draft_fixture
from tests import test_storage_placement_files as placement_fixture
from tests.support.in_memory import InMemoryManagerMetadataStore, InMemoryStoragePlacementSource
from tests.support.isolation import forbid_external_effects


@contextmanager
def read_only():
    """Проверить отсутствие попыток записи, изменения прав, fsync и запуска процессов."""
    open_file = os.open

    def checked_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError("Попытка открытия для записи.")
        return open_file(path, flags, *args, **kwargs)

    with ExitStack() as stack:
        mocks = [stack.enter_context(patch(name, side_effect=AssertionError("Попытка записи или запуска.")))
                 for name in ("os.mkdir", "os.write", "os.replace", "os.rename", "os.unlink", "os.chmod",
                              "os.fchmod", "os.fsync", "subprocess.Popen", "os.system", "socket.socket")]
        stack.enter_context(patch("os.open", side_effect=checked_open))
        yield
        for mock in mocks:
            mock.assert_not_called()


class RouterManagerFilesTests(unittest.TestCase):
    def setUp(self):
        # Переиспользуется временная установка тестов реального источника размещения.
        self.fixture = placement_fixture.SourceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source = self.fixture.source
        self.root = self.fixture.root
        self.data = self.fixture.path(placement_fixture.MOUNTS[1])
        self.drafts = self.data / DRAFT_DIRECTORY
        self.metadata = self.data / METADATA_DIRECTORY

    def connect(self, source=None):
        return connect_router_manager_files(self.source if source is None else source, root=str(self.root))

    def populate(self):
        DraftSessionFiles(str(self.drafts)).create_draft(draft_fixture.session(note="TEST_ONLY_SECRET"))
        ManagerMetadataFiles(str(self.metadata)).write_metadata(ManagerMetadata(self.source.current_storage_placement()), None)

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.lstat().st_mode, p.lstat().st_ino,
                p.read_bytes() if p.is_file() and not p.is_symlink() else None)
                for p in self.root.rglob("*")}

    def assert_private(self, value):
        for marker in (*placement_fixture.UUIDS, str(self.root), str(self.data), "TEST_ONLY_SECRET", draft_fixture.FIRST_ID):
            self.assertNotIn(marker, value)

    def test_known_placement_connects_existing_files_without_any_write(self):
        self.populate()
        before = self.snapshot()
        with read_only():
            stores = self.connect()
            self.assertIsNone(stores.error)
            self.assertIsNotNone(stores.drafts.read_draft())
            self.assertIsNotNone(stores.metadata.read_metadata())
        self.assertEqual(self.snapshot(), before)
        self.assert_private(repr(stores))

    def test_missing_own_directories_and_files_are_absent_without_creation(self):
        for directories in (False, True):
            with self.subTest(directories=directories):
                if directories:
                    self.drafts.mkdir(mode=0o700)
                    self.metadata.mkdir(mode=0o700)
                before = self.snapshot()
                with read_only():
                    stores = self.connect()
                    self.assertIsNone(stores.error)
                    self.assertIsNone(stores.drafts.read_draft())
                    self.assertIsNone(stores.metadata.read_metadata())
                self.assertEqual(self.snapshot(), before)

    def test_absent_unknown_and_incomplete_roles_remain_disconnected(self):
        original = self.source.current_storage_placement()
        roles = [RoleLocation(ValueState.ABSENT), RoleLocation(ValueState.UNKNOWN),
                 replace(original.roles.data, verified=False),
                 replace(original.roles.data, path=TrackedValue(ValueState.UNKNOWN), verified=False)]
        for role in roles:
            with self.subTest(state=role.state, verified=role.verified), forbid_external_effects():
                stores = self.connect(InMemoryStoragePlacementSource(replace(
                    original, roles=replace(original.roles, data=role))))
                self.assertIsNone(stores.drafts)
                self.assertIsNone(stores.metadata)
                self.assertIsNotNone(stores.error)

    def test_absent_mount_and_ambiguous_mount_do_not_connect_lower_directory(self):
        rows = self.fixture.rows.copy()
        for changed in ([row for row in rows if placement_fixture.MOUNTS[1] not in row],
                        rows + [rows[3].replace("4 1", "8 1")]):
            with self.subTest(rows=len(changed)):
                self.fixture.rows = changed
                self.fixture.write_mounts()
                before = self.snapshot()
                with read_only():
                    stores = self.connect()
                self.assertIsNone(stores.drafts)
                self.assertIsNone(stores.metadata)
                self.assertEqual(stores.error.code, "data_placement_unverified")
                self.assertEqual(self.snapshot(), before)

    def test_source_failure_and_invalid_model_are_safely_disconnected(self):
        for answer in (None, object(), {"path": "TEST_ONLY_SECRET"}):
            with patch.object(self.source, "current_storage_placement", return_value=answer), read_only():
                stores = self.connect()
            self.assertEqual(stores.error.code, "invalid_storage_placement")
            self.assertIsNone(stores.drafts)
            self.assert_private(repr(stores))
        with patch.object(self.source, "current_storage_placement", side_effect=OSError(str(self.data))), read_only():
            stores = self.connect()
        self.assertEqual(stores.error.code, "storage_placement_unavailable")
        self.assert_private(repr(stores))

    def test_unknown_fields_and_corrupted_nested_types_are_rejected(self):
        original = self.source.current_storage_placement()
        extra = replace(original, extra=UnknownFields({"private": "TEST_ONLY_SECRET"}))
        broken = replace(original)
        object.__setattr__(broken.roles.data, "verified", "yes")
        for value in (extra, broken):
            with patch.object(self.source, "current_storage_placement", return_value=value), read_only():
                stores = self.connect()
            self.assertEqual(stores.error.code, "invalid_storage_placement")
            self.assertIsNone(stores.metadata)
            self.assert_private(repr(stores))

    def test_protected_data_paths_are_rejected_before_filesystem_access(self):
        original = self.source.current_storage_placement()
        for directory in PROTECTED_DIRECTORIES:
            for path in (directory, directory + "/child"):
                role = replace(original.roles.data, path=TrackedValue(ValueState.KNOWN, path))
                source = InMemoryStoragePlacementSource(replace(original, roles=replace(original.roles, data=role)))
                with self.subTest(path=path), forbid_external_effects():
                    stores = self.connect(source)
                self.assertEqual(stores.error.code, "data_directory_unsafe")
                self.assertIsNone(stores.drafts)

    def test_missing_data_after_connection_is_failure_not_absent_draft(self):
        stores = self.connect()
        self.fixture.rows = [row for row in self.fixture.rows if placement_fixture.MOUNTS[1] not in row]
        self.fixture.write_mounts()
        with read_only():
            for callback, error in ((stores.drafts.read_draft, DraftSessionStoreError),
                                    (stores.metadata.read_metadata, ManagerMetadataStoreError)):
                with self.assertRaises(error) as caught:
                    callback()
                self.assertTrue(caught.exception.failure.value.endswith("store_unavailable"))
                self.assert_private(repr(caught.exception))

    def test_changed_data_path_or_uuid_does_not_switch_to_another_store(self):
        original = self.source.current_storage_placement()
        stores = self.connect()
        for role in (replace(original.roles.data, path=TrackedValue(ValueState.KNOWN, "/other-data")),
                     replace(original.roles.data, storage_id=TrackedValue(ValueState.KNOWN, placement_fixture.UUIDS[2]))):
            changed = replace(original, roles=replace(original.roles, data=role))
            with patch.object(self.source, "current_storage_placement", return_value=changed), read_only():
                with self.assertRaises(DraftSessionStoreError) as caught:
                    stores.drafts.read_draft()
            self.assertEqual(caught.exception.reason, "replaced")

    def test_loss_during_file_read_does_not_confirm_absence(self):
        stores = self.connect()
        original = self.source.current_storage_placement()
        lost = replace(original, roles=replace(original.roles, data=replace(original.roles.data, verified=False)))
        with patch.object(self.source, "current_storage_placement", side_effect=[original, lost]), read_only():
            with self.assertRaises(DraftSessionStoreError):
                stores.drafts.read_draft()

    def test_private_directory_permissions_symlink_and_file_type_are_preserved(self):
        self.populate()
        stores = self.connect()
        for directory, callback, error, filename in (
            (self.drafts, stores.drafts.read_draft, DraftSessionStoreError, DRAFT_FILE_NAME),
            (self.metadata, stores.metadata.read_metadata, ManagerMetadataStoreError, METADATA_FILE_NAME),
        ):
            directory.chmod(0o755)
            with read_only(), self.assertRaises(error) as caught:
                callback()
            self.assertEqual(caught.exception.reason, "permissions")
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
            directory.chmod(0o700)
            target = directory / filename
            target.chmod(0o644)
            with read_only(), self.assertRaises(error) as caught:
                callback()
            self.assertEqual(caught.exception.reason, "permissions")
            target.unlink()
            target.symlink_to(self.fixture.path(placement_fixture.files.BACKUP_CONFIG))
            with read_only(), self.assertRaises(error) as caught:
                callback()
            self.assertEqual(caught.exception.reason, "symlink")
            target.unlink()
            target.mkdir()
            with read_only(), self.assertRaises(error) as caught:
                callback()
            self.assertEqual(caught.exception.reason, "not_regular_file")

    def test_private_directory_symlink_and_access_error(self):
        self.drafts.symlink_to(self.data, target_is_directory=True)
        stores = self.connect()
        with read_only(), self.assertRaises(DraftSessionStoreError) as caught:
            stores.drafts.read_draft()
        self.assertEqual(caught.exception.reason, "symlink")
        self.drafts.unlink()
        self.drafts.mkdir(mode=0o700)
        actual_open = os.open

        def denied(path, *args, **kwargs):
            if path == DRAFT_DIRECTORY:
                raise PermissionError(errno.EACCES, "TEST_ONLY_SECRET")
            return actual_open(path, *args, **kwargs)

        with patch("os.open", side_effect=denied), self.assertRaises(DraftSessionStoreError) as caught:
            stores.drafts.read_draft()
        self.assertEqual(caught.exception.reason, "permission_denied")
        self.assert_private(str(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_corrupt_existing_files_are_errors_not_absence(self):
        self.populate()
        (self.drafts / DRAFT_FILE_NAME).write_bytes(b"TEST_ONLY_SECRET")
        (self.metadata / METADATA_FILE_NAME).write_bytes(b"TEST_ONLY_SECRET")
        stores = self.connect()
        before = self.snapshot()
        with read_only():
            for callback, error in ((stores.drafts.read_draft, DraftSessionStoreError),
                                    (stores.metadata.read_metadata, ManagerMetadataStoreError)):
                with self.assertRaises(error) as caught:
                    callback()
                self.assertIn("invalid_stored", caught.exception.failure.value)
                self.assert_private(str(caught.exception))
        self.assertEqual(self.snapshot(), before)

    def test_connected_stores_reject_all_mutating_port_methods(self):
        stores = self.connect()
        revision = "0" * 64
        calls = [(lambda: stores.drafts.create_draft(draft_fixture.session()), DraftSessionStoreError),
                 (lambda: stores.drafts.remove_draft(revision), DraftSessionStoreError),
                 (stores.drafts.confirm_draft_absent, DraftSessionStoreError),
                 (lambda: stores.metadata.write_metadata(ManagerMetadata(), None), ManagerMetadataStoreError)]
        with read_only():
            for callback, error in calls:
                with self.assertRaises(error) as caught:
                    callback()
                self.assertEqual(caught.exception.reason, "read_only")

    def test_both_entrypoints_read_draft_and_preserve_files(self):
        self.populate()
        stores = self.connect()
        # Прочие источники здесь управляемые; файловые хранилища и детектор настоящие.
        _, sources = cli_fixture.snapshot_menu_sources(stores.metadata)
        sources = replace(sources, drafts=stores.drafts)
        before = self.snapshot()
        for entry, argv, text in ((entrypoints.vpn_menu, ["--read-router"], "1\n1\n0\n0\n2\n"),
                                  (entrypoints.vpn_setup, [], "0\n2\n")):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(entrypoints, "router_sources", return_value=sources), read_only():
                code = entry(argv, io.StringIO(text), stdout, stderr)
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertIn("и не применён", stdout.getvalue())
            if entry is entrypoints.vpn_menu:
                self.assertIn("Черновик: есть", stdout.getvalue())
            self.assert_private(stdout.getvalue())
        self.assertEqual(self.snapshot(), before)

    def test_router_composition_attaches_both_stores(self):
        with patch.object(composition, "StoragePlacementFiles", return_value=self.source), \
                patch.object(composition, "connect_router_manager_files", side_effect=lambda source: self.connect(source)), read_only():
            sources = composition.router_sources()
        self.assertIsNotNone(sources.drafts)
        self.assertIsNotNone(sources.metadata)
        self.assertIsNone(sources.storage_error)

    def test_metadata_settings_and_rule_names_read_selected_file(self):
        memory = InMemoryManagerMetadataStore()
        installation, _ = cli_fixture.snapshot_menu_sources(memory)
        cli_fixture.assign_snapshot_ids(installation, memory, ((0, "Проверочное правило"),))
        ManagerMetadataFiles(str(self.metadata)).write_metadata(decode_manager_metadata(memory.content).metadata, None)
        stores = self.connect()
        _, sources = cli_fixture.snapshot_menu_sources(stores.metadata)
        sources = replace(sources, drafts=stores.drafts)
        before = self.snapshot()
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(entrypoints, "router_sources", return_value=sources), read_only():
            code = entrypoints.vpn_menu(["--read-router"], io.StringIO("10\n1\n0\n4\n1\n0\n0\n0\n"), stdout, stderr)
        self.assertEqual((code, stderr.getvalue()), (0, ""))
        self.assertIn("Версия схемы: 1", stdout.getvalue())
        self.assertIn("Проверочное правило", stdout.getvalue())
        self.assert_private(stdout.getvalue())
        self.assertEqual(self.snapshot(), before)

    def test_both_entrypoints_with_absent_files_exit_without_question(self):
        stores = self.connect()
        sources = composition.MenuSources(drafts=stores.drafts, metadata=stores.metadata)
        before = self.snapshot()
        for entry, argv in ((entrypoints.vpn_menu, ["--read-router"]), (entrypoints.vpn_setup, [])):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(entrypoints, "router_sources", return_value=sources), read_only():
                code = entry(argv, io.StringIO("0\n"), stdout, stderr)
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertNotIn("Остаться", stdout.getvalue())
            self.assertNotIn("Черновик не проверялся", stdout.getvalue())
        self.assertEqual(self.snapshot(), before)

    def test_lost_storage_shows_unchecked_draft_and_confirmation(self):
        stores = self.connect()
        self.fixture.rows = [row for row in self.fixture.rows if placement_fixture.MOUNTS[1] not in row]
        self.fixture.write_mounts()
        sources = composition.MenuSources(drafts=stores.drafts, metadata=stores.metadata)
        for entry, argv in ((entrypoints.vpn_menu, ["--read-router"]), (entrypoints.vpn_setup, [])):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(entrypoints, "router_sources", return_value=sources), read_only():
                code = entry(argv, io.StringIO("0\n2\n"), stdout, stderr)
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertIn("Не удалось проверить", stdout.getvalue())
            self.assertIn("Остаться", stdout.getvalue())
            self.assert_private(stdout.getvalue())

    def test_unknown_placement_explains_header_summary_settings_and_both_exits(self):
        original = self.source.current_storage_placement()
        absent = replace(original, roles=replace(original.roles, data=RoleLocation(ValueState.UNKNOWN)))
        stores = self.connect(InMemoryStoragePlacementSource(absent))
        sources = composition.MenuSources(storage_error=stores.error)
        for entry, argv, text in ((entrypoints.vpn_menu, ["--read-router"], "1\n1\n0\n10\n1\n0\n0\n"),
                                  (entrypoints.vpn_setup, [], "0\n")):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(entrypoints, "router_sources", return_value=sources), forbid_external_effects():
                code = entry(argv, io.StringIO(text), stdout, stderr)
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertIn("Хранилища не подключены", stdout.getvalue())
            self.assertIn("Черновик не проверялся", stdout.getvalue())
            if entry is entrypoints.vpn_menu:
                self.assertIn("Черновик: не проверено", stdout.getvalue())
                self.assertIn("размещение роли data или выбранные каталоги не прошли проверку", stdout.getvalue())
            self.assert_private(stdout.getvalue())

    def test_settings_reason_covers_source_failure_and_unsafe_directory(self):
        original = self.source.current_storage_placement()
        role = replace(original.roles.data, path=TrackedValue(ValueState.KNOWN, PROTECTED_DIRECTORIES[0]))
        self.assertTrue(role.verified)
        unsafe = self.connect(InMemoryStoragePlacementSource(replace(original, roles=replace(original.roles, data=role))))
        with patch.object(self.source, "current_storage_placement", side_effect=OSError("TEST_ONLY_SECRET")):
            unavailable = self.connect()
        self.assertEqual(unsafe.error.code, "data_directory_unsafe")
        self.assertEqual(unavailable.error.code, "storage_placement_unavailable")
        for stores in (unsafe, unavailable):
            with self.subTest(code=stores.error.code):
                sources = composition.MenuSources(storage_error=stores.error)
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(entrypoints, "router_sources", return_value=sources), forbid_external_effects():
                    code = entrypoints.vpn_menu(["--read-router"], io.StringIO("10\n1\n0\n0\n"), stdout, stderr)
                self.assertEqual((code, stderr.getvalue()), (0, ""))
                self.assertIn("размещение роли data или выбранные каталоги не прошли проверку", stdout.getvalue())
                self.assertNotIn("размещение роли data не подтверждено;", stdout.getvalue())
                self.assertIn(stores.error.message, stdout.getvalue())
                self.assert_private(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
