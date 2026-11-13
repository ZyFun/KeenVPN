"""Обезличенные форматы и отказы реального источника размещения без роутера."""

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

from keenvpn.adapters import storage_placement_formats as formats
from keenvpn.adapters import storage_placement_files as files
from keenvpn.application.manager_metadata import ImportStoragePlacement, ImportStoragePlacementHandler
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.domain.manager_metadata import ManagerMetadata, StorageVariant, ValueState
from tests.support.in_memory import InMemoryManagerMetadataStore


FIXTURES = Path(__file__).parent / "fixtures/storage_placement"
REPOSITORY = Path(__file__).parent.parent
UUIDS = tuple(f"00000000-0000-0000-0000-{index:012d}" for index in (1, 2, 3))
MOUNTS = tuple("/tmp/mnt/" + value for value in UUIDS)
HISTORY = MOUNTS[1] + "/example/history"


def fixture(name):
    return (FIXTURES / name).read_bytes()


class FailureCase(unittest.TestCase):
    def assert_failure(self, callback, failure=RouterReadFailure.INVALID_RESPONSE):
        with self.assertRaises(RouterReadError) as caught:
            callback()
        error = caught.exception
        self.assertEqual(error.failure, failure)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        for private in (*UUIDS, HISTORY, "private-secret"):
            self.assertNotIn(private, str(error))
            self.assertNotIn(private, repr(error))


class FormatTests(FailureCase):
    def test_v4_preserves_settings_and_accepts_independent_limits(self):
        script, sql = fixture("history-v4.sh"), fixture("history-ingest-v4.sql")
        result = formats.history_placement(script, sql)
        self.assertEqual(result, formats.history_placement(fixture("history.sh"), fixture("history-ingest.sql")))
        changed = formats.history_placement(
            script.replace(b"-le 131072 ]", b"-le 8192 ]"),
            sql.replace(b"-864000;", b"-172800;"),
        )
        self.assertEqual((changed.size_bytes, changed.retention_seconds), (8388608, 172800))

    def test_history_rejects_mixed_versions_and_modified_v4_structure(self):
        script, sql = fixture("history-v4.sh"), fixture("history-ingest-v4.sql")
        cases = (
            (script, fixture("history-ingest.sql")),
            (fixture("history.sh"), sql),
            (script.replace(b"4\\ndelete", b"5\\ndelete"), sql),
            (script.replace(b"4\\ndelete", b"4\\nwal"), sql),
            (script, sql.replace(b"'hysteria' THEN 3", b"'hysteria' THEN 2")),
            (script, sql.replace(b"THEN 3 END", b"THEN 3 ELSE 2 END")),
            (script, sql.replace(b",'hysteria')", b")")),
            (script + b"\nunknown_function\n", sql),
            (script, sql + b"SELECT 'private-secret';\n"),
        )
        for index, (writer, ingest) in enumerate(cases):
            with self.subTest(case=index):
                self.assert_failure(lambda: formats.history_placement(writer, ingest))

    def test_backup_code_fingerprints_match_repository_sources(self):
        sources = (
            ("scripts/router_backup.py", formats.BACKUP_ENTRY_SHA256),
            ("keenvpn/adapters/router_backup.py", formats.BACKUP_ADAPTER_SHA256),
        )
        for relative, expected in sources:
            with self.subTest(source=relative):
                actual = hashlib.sha256((REPOSITORY / relative).read_bytes()).hexdigest()
                self.assertEqual(actual, expected, f"Изменён {relative} — проверьте и согласованно обновите "
                                 "поддерживаемые эталоны источника размещения.")

    def test_known_structure_accepts_independent_settings(self):
        result = formats.history_placement(fixture("history.sh"), fixture("history-ingest.sql"))
        self.assertEqual(result.storage_id, UUIDS[1])
        self.assertEqual(result.path, HISTORY)
        self.assertEqual(result.size_bytes, 128 * 1024 * 1024)
        self.assertEqual(result.retention_seconds, 10 * 86400)
        script = fixture("history.sh").replace(b"-le 131072 ]", b"-le 8192 ]")
        sql = fixture("history-ingest.sql").replace(b"-864000;", b"-172800;")
        changed = formats.history_placement(script, sql)
        self.assertEqual((changed.size_bytes, changed.retention_seconds), (8388608, 172800))
        self.assertNotIn(UUIDS[1], repr(result))
        self.assertNotIn(HISTORY, repr(result))

    def test_history_rejects_incomplete_unknown_duplicate_and_executable_values(self):
        script, sql = fixture("history.sh"), fixture("history-ingest.sql")
        cases = [
            (b"", sql), (script + b"\nunknown_function\n", sql),
            (script + b"history_uuid=" + UUIDS[1].encode() + b"\n", sql),
            (script.replace(UUIDS[1].encode(), b"$(private-secret)"), sql),
            (script.replace(HISTORY.encode(), b"/tmp/../private-secret"), sql),
            (script.replace(b"-le 131072 ]", b"-le 0 ]"), sql),
            (script.replace(b"-le 131072 ]", b"-le 9000000000000000000 ]"), sql),
            (script.replace(b"history_uuid=", b"#history_uuid="), sql),
            (script + b"\xff", sql), (script, b""),
            (script, sql.replace(b"-864000;", b"-0;")),
            (script, sql.replace(b"-864000;", b"-172800;", 1)),
            (script, sql + b"SELECT 'private-secret';\n"),
            (script, sql.replace(b">14336 AS trim", b">16384 AS trim")),
        ]
        for script, sql in cases:
            with self.subTest(lengths=(len(script), len(sql))):
                self.assert_failure(lambda: formats.history_placement(script, sql))

    def test_backup_strict_json_no_defaults_or_coercion(self):
        valid = dict(zip(("entware_uuid", "data_uuid", "backup_uuid"), UUIDS), keep=4)
        result = formats.backup_placement(json.dumps(valid).encode())
        self.assertEqual(result.data_uuid, UUIDS[1])
        self.assertNotIn(UUIDS[1], repr(result))
        documents = [None, [], {}, {**valid, "keep": True}, {**valid, "keep": 0},
                     {**valid, "backup_uuid": UUIDS[1]}, {**valid, "data_uuid": "private-secret"},
                     {**valid, "extra": 1}, {key: value for key, value in valid.items() if key != "keep"}]
        for document in documents:
            self.assert_failure(lambda: formats.backup_placement(json.dumps(document).encode()))
        raw = json.dumps(valid).encode()
        for content in (raw[:-1] + b',"keep":3}', b"/*comment*/" + raw, raw.replace(b"4", b"NaN"), b"\xff"):
            self.assert_failure(lambda: formats.backup_placement(content))

    def test_blkid_full_busybox_output_and_ambiguity(self):
        device = "/dev/sda2"
        valid = f'{device}: LABEL="sample" UUID="{UUIDS[1]}"\n'.encode()
        self.assertEqual(files.uuid_from_blkid(valid, device), UUIDS[1])
        self.assertEqual(files.uuid_from_blkid(valid.rstrip() + b' TYPE="ext4"\n', device), UUIDS[1])
        for output in (b"", valid + valid, valid.replace(b"sda2", b"sda3"),
                       valid.rstrip() + b' UUID="' + UUIDS[1].encode() + b'"\n',
                       valid.rstrip() + b' UNKNOWN="private-secret"\n', valid + b"\xff",
                       valid.replace(UUIDS[1].encode(), b"not-a-uuid"), valid.rstrip() + b' TYPE="xfs"\n'):
            self.assert_failure(lambda: files.uuid_from_blkid(output, device))

    def test_mountinfo_escapes_and_strict_records(self):
        record = b"1 0 8:1 / /sample\\040directory rw shared:3 - ext4 /dev/sda1 rw\n"
        self.assertEqual(files.mounts_from_bytes(record)[0].point, "/sample directory")
        for content in (b"", record.rstrip(), record + record, record.replace(b"8:1", b"no"),
                        record.replace(b"shared:3", b"unknown:3"), record.replace(b"\\040", b"\\777"),
                        record.replace(b" rw ", b" rw,ro "), record.replace(b"/sample", b"/../sample"), b"\xff\n"):
            self.assert_failure(lambda: files.mounts_from_bytes(content))
        self.assert_failure(lambda: files.mounts_from_bytes(b"x" * (files.MOUNTINFO_LIMIT + 1)),
                            RouterReadFailure.TOO_LARGE)

    def test_namespace_root_is_supported_only_for_nsfs(self):
        record = b"6 1 0:5 net:[12345] /run/netns/example rw - nsfs nsfs rw\n"
        mount = files.mounts_from_bytes(record)[0]
        self.assertEqual((mount.root, mount.filesystem), ("net:[12345]", "nsfs"))
        for content in (record.replace(b"net:[12345]", b"net:[bad]"),
                        record.replace(b"net:[12345]", b"net:[12345"),
                        record.replace(b" - nsfs nsfs ", b" - ext4 /dev/sda1 ")):
            self.assert_failure(lambda: files.mounts_from_bytes(content))


class FixtureSource(files.StoragePlacementFiles):
    """Настоящий обход каталогов; только номера устройств подменяются без block-device."""

    def _block_device(self, device):
        return 8, int(device[-1])

    def _directory_identity(self, path):
        actual, inode = super()._directory_identity(path)
        number = (8, 1) if path == "/opt" or path.startswith("/opt/") else actual
        for index, mount in enumerate(MOUNTS, 1):
            if path == mount or path.startswith(mount + "/"):
                number = (8, index)
        return number, inode


class SourceTests(FailureCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keenvpn-storage-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.calls = []
        self.outputs = {f"/dev/sda{index}": f'/dev/sda{index}: LABEL="sample" UUID="{value}"\n'.encode()
                        for index, value in enumerate(UUIDS, 1)}
        self.source = FixtureSource(root=str(self.root), run=self.run_command)
        self.put(files.BACKUP_CONFIG, json.dumps(dict(zip(
            ("entware_uuid", "data_uuid", "backup_uuid"), UUIDS), keep=4)).encode())
        for path, content in ((files.BACKUP_WRAPPER, fixture("backup-wrapper.sh")),
                              (files.BACKUP_ENTRY, (REPOSITORY / "scripts/router_backup.py").read_bytes()),
                              (files.BACKUP_ADAPTER, (REPOSITORY / "keenvpn/adapters/router_backup.py").read_bytes()),
                              (files.HISTORY_SCRIPT, fixture("history.sh")),
                              (files.HISTORY_INIT, fixture("history-init.sh")),
                              (files.HISTORY_INGEST, fixture("history-ingest.sql")),
                              (HISTORY + "/.store-id", (UUIDS[1] + "\n").encode())):
            self.put(path, content)
        for path in (*MOUNTS, MOUNTS[2] + "/keenvpn/daily"):
            self.path(path).mkdir(parents=True, exist_ok=True)
        self.mountinfo = "/proc/" + str(os.getpid()) + "/mountinfo"
        self.rows = ["1 0 0:4 / / rw - tmpfs tmpfs rw", "2 1 8:1 / /opt rw - ext4 /dev/sda1 rw"]
        self.rows += [f"{index+2} 1 8:{index} / {point} rw - ext4 /dev/sda{index} rw"
                      for index, point in enumerate(MOUNTS, 1)]
        self.write_mounts()

    def path(self, path):
        return self.root / path.lstrip("/")

    def put(self, path, content):
        target = self.path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    def write_mounts(self):
        self.put(self.mountinfo, ("\n".join(self.rows) + "\n").encode())

    def run_command(self, args, timeout, limit):
        self.calls.append((args, timeout, limit))
        self.assertEqual((args[0], timeout, limit), (files.BLKID_PATH, 5.0, 32768))
        return 0, self.outputs[args[1]]

    def read(self):
        return self.source.current_storage_placement()

    def test_v4_source_reads_verified_placement_without_writes_or_sqlite(self):
        expected = self.read()
        self.put(files.HISTORY_SCRIPT, fixture("history-v4.sh"))
        self.put(files.HISTORY_INGEST, fixture("history-ingest-v4.sql"))
        # Содержимое БД не требуется для распознавания размещения.
        self.put(HISTORY + "/history.sqlite", b"private-secret-not-a-database")
        def snapshot():
            return {str(path.relative_to(self.root)): (path.stat().st_mode, path.read_bytes())
                    for path in self.root.rglob("*") if path.is_file()}
        before = snapshot()
        self.calls.clear()
        with patch("sqlite3.connect", side_effect=AssertionError("SQLite не должна открываться")):
            self.assertEqual(self.read(), expected)
        self.assertEqual(snapshot(), before)
        self.assertEqual(len(self.calls), 6)

    def test_real_port_preserves_layout_limits_and_import_idempotence(self):
        placement = self.read()
        self.assertEqual(placement.variant.value, StorageVariant.EXTENDED)
        for role, identity, path in ((placement.roles.data, UUIDS[1], MOUNTS[1]),
                                      (placement.roles.history, UUIDS[1], HISTORY),
                                      (placement.roles.backups, UUIDS[2], MOUNTS[2] + "/keenvpn/daily")):
            self.assertEqual(role.state, ValueState.KNOWN)
            self.assertEqual((role.storage_id.value, role.path.value, role.verified), (identity, path, True))
        self.assertEqual(placement.history_limits.size_bytes.value, 128 * 1024 * 1024)
        self.assertEqual(placement.history_limits.retention_seconds.value, 864000)
        self.assertEqual(len(self.calls), 6)
        for private in (*UUIDS, HISTORY):
            self.assertNotIn(private, repr(placement))
            self.assertNotIn(private, repr(self.source))
            self.assertNotIn(private, str(ManagerMetadata(placement).to_diagnostic()))
        store = InMemoryManagerMetadataStore()
        handler = ImportStoragePlacementHandler(self.source, store)
        self.assertTrue(handler.execute(ImportStoragePlacement()).succeeded)
        original = store.content
        result = handler.execute(ImportStoragePlacement())
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.outcome, "unchanged")
        self.assertEqual(store.content, original)

    def test_missing_sources_are_absent_and_data_is_unknown_without_evidence(self):
        for path in (files.BACKUP_CONFIG, files.BACKUP_WRAPPER, files.HISTORY_SCRIPT, files.HISTORY_INIT):
            self.path(path).unlink()
        placement = self.read()
        self.assertEqual(placement.variant.state, ValueState.UNKNOWN)
        self.assertEqual(placement.roles.data.state, ValueState.UNKNOWN)
        self.assertEqual(placement.roles.backups.state, ValueState.ABSENT)
        self.assertEqual(placement.roles.history.state, ValueState.ABSENT)
        self.assertEqual(placement.history_limits.size_bytes.state, ValueState.ABSENT)
        self.assertEqual(self.calls, [])

    def test_history_verification_is_independent_of_backup_entware_bind(self):
        original = self.read().roles.history
        self.rows = [row.replace(" rw ", " ro ") if " /opt " in row else row for row in self.rows]
        self.write_mounts()
        with_backup = self.read()
        self.assertFalse(with_backup.roles.data.verified)
        self.assertFalse(with_backup.roles.backups.verified)
        self.assertTrue(with_backup.roles.history.verified)
        self.assertEqual(with_backup.roles.history, original)

        for path in (files.BACKUP_CONFIG, files.BACKUP_WRAPPER):
            self.path(path).unlink()
        without_backup = self.read()
        self.assertTrue(without_backup.roles.history.verified)
        self.assertEqual(without_backup.roles.history, original)

    def test_unverified_entware_rejects_backup_roles_for_each_mount_failure(self):
        original = self.read()
        rows = self.rows.copy()
        variants = {
            "missing": [row for row in rows if " /opt " not in row],
            "read_only": [row.replace(" rw ", " ro ") if " /opt " in row else row for row in rows],
            "subtree": [row.replace(" / /opt ", " /subtree /opt ") for row in rows],
            "replacement": [row.replace("8:1", "8:3").replace("/dev/sda1", "/dev/sda3")
                            if " /opt " in row else row for row in rows],
        }
        for name, changed in variants.items():
            with self.subTest(mount_failure=name):
                self.rows = changed
                self.write_mounts()
                placement = self.read()
                self.assertFalse(placement.roles.data.verified)
                self.assertFalse(placement.roles.backups.verified)
                for role_name in ("data", "backups"):
                    role, expected = getattr(placement.roles, role_name), getattr(original.roles, role_name)
                    self.assertEqual(role.state, ValueState.KNOWN)
                    self.assertEqual(role.storage_id, expected.storage_id)
                    self.assertEqual(role.path, expected.path)
                self.assertTrue(placement.roles.history.verified)
                self.assertEqual(placement.roles.history, original.roles.history)

    def test_unknown_script_format_is_a_refusal(self):
        self.put(files.HISTORY_SCRIPT, fixture("history.sh") + b"echo private-secret\n")
        self.assert_failure(self.read)
        self.assertEqual(self.calls, [])

    def test_each_partial_source_set_is_rejected(self):
        for path in (files.BACKUP_CONFIG, files.BACKUP_WRAPPER, files.BACKUP_ENTRY, files.BACKUP_ADAPTER,
                     files.HISTORY_SCRIPT, files.HISTORY_INIT, files.HISTORY_INGEST):
            original = self.path(path).read_bytes()
            self.path(path).unlink()
            self.assert_failure(self.read)
            self.put(path, original)

    def test_corrupt_or_unknown_backup_code_is_rejected(self):
        for path in (files.BACKUP_CONFIG, files.BACKUP_WRAPPER, files.BACKUP_ENTRY, files.BACKUP_ADAPTER):
            original = self.path(path).read_bytes()
            self.put(path, b"private-secret")
            self.assert_failure(self.read)
            self.put(path, original)

    def test_absent_mount_does_not_verify_lower_directory(self):
        self.rows = [row for row in self.rows if MOUNTS[1] not in row]
        self.write_mounts()
        placement = self.read()
        self.assertFalse(placement.roles.data.verified)
        self.assertFalse(placement.roles.history.verified)
        self.assertEqual(placement.roles.data.storage_id.value, UUIDS[1])

    def test_ro_replaced_uuid_and_bind_subtree_are_unverified(self):
        original = self.rows.copy()
        for change in (lambda row: row.replace(" rw ", " ro "),
                       lambda row: row.replace(" 8:2 ", " 8:3 ").replace("/dev/sda2", "/dev/sda3"),
                       lambda row: row.replace(" / /tmp/mnt/", " /subtree /tmp/mnt/")):
            self.rows = [change(row) if MOUNTS[1] in row else row for row in original]
            self.write_mounts()
            placement = self.read()
            self.assertFalse(placement.roles.data.verified)
            self.assertFalse(placement.roles.history.verified)

    def test_duplicate_uuid_is_not_selected_by_first_candidate(self):
        self.outputs["/dev/sda3"] = self.outputs["/dev/sda3"].replace(UUIDS[2].encode(), UUIDS[1].encode())
        placement = self.read()
        self.assertFalse(placement.roles.data.verified)
        self.assertFalse(placement.roles.history.verified)
        self.assertFalse(placement.roles.backups.verified)

    def test_nested_and_ambiguous_mounts_do_not_verify(self):
        for row in (f"6 4 8:3 / {HISTORY} rw - ext4 /dev/sda3 rw",
                    f"6 4 8:3 / {HISTORY}/nested rw - ext4 /dev/sda3 rw",
                    f"6 1 8:2 / {MOUNTS[1]} rw - ext4 /dev/sda2 rw"):
            self.rows.append(row)
            self.write_mounts()
            placement = self.read()
            self.assertFalse(placement.roles.data.verified)
            self.assertFalse(placement.roles.history.verified)
            self.rows.pop()

    def test_namespace_mount_outside_roles_does_not_affect_placement(self):
        original = self.read()
        calls = len(self.calls)
        self.rows.append("6 1 0:5 net:[12345] /run/netns/example rw - nsfs nsfs rw")
        self.write_mounts()
        self.assertEqual(self.read(), original)
        self.assertEqual(len(self.calls) - calls, 6)

    def test_namespace_mount_inside_role_does_not_verify_storage(self):
        rows = self.rows.copy()
        for point in (HISTORY, HISTORY + "/namespace"):
            with self.subTest(nested=point != HISTORY):
                self.rows = rows + [f"6 1 0:5 net:[12345] {point} rw - nsfs nsfs rw"]
                self.write_mounts()
                placement = self.read()
                self.assertFalse(placement.roles.data.verified)
                self.assertFalse(placement.roles.history.verified)
                self.assertTrue(placement.roles.backups.verified)

    def test_missing_path_and_marker_mismatch_are_unverified(self):
        self.path(HISTORY + "/.store-id").unlink()
        self.assertFalse(self.read().roles.history.verified)
        self.put(HISTORY + "/.store-id", (UUIDS[2] + "\n").encode())
        self.assertFalse(self.read().roles.history.verified)
        shutil.rmtree(self.path(HISTORY))
        self.assertFalse(self.read().roles.history.verified)

    def test_marker_trailing_newlines_match_writer_without_normalizing_other_bytes(self):
        value = UUIDS[1].encode("ascii")
        cases = (
            ("no_lf", value, True), ("one_lf", value + b"\n", True),
            ("two_lf", value + b"\n\n", True), ("empty", b"", False),
            ("leading_space", b" " + value + b"\n", False),
            ("trailing_space", value + b" \n", False), ("crlf", value + b"\r\n", False),
            ("extra_line", value + b"\nother\n", False),
        )
        for name, content, verified in cases:
            with self.subTest(marker=name):
                self.put(HISTORY + "/.store-id", content)
                self.assertEqual(self.read().roles.history.verified, verified)

    def test_symlink_in_source_role_and_marker_are_refusals(self):
        for path in (files.BACKUP_CONFIG, HISTORY + "/.store-id"):
            target = self.path(path)
            original = target.read_bytes()
            target.unlink()
            target.symlink_to("/private-secret")
            self.assert_failure(self.read, RouterReadFailure.UNSAFE)
            target.unlink()
            target.write_bytes(original)
        directory = self.path(HISTORY)
        directory.rename(directory.with_name("original"))
        directory.symlink_to(directory.with_name("original"))
        self.assert_failure(self.read, RouterReadFailure.UNSAFE)

    def test_selected_path_device_must_match_mountinfo(self):
        original = self.source._directory_identity
        with patch.object(self.source, "_directory_identity", side_effect=lambda path:
                          ((9, 9), original(path)[1]) if path == HISTORY else original(path)):
            self.assertFalse(self.read().roles.history.verified)

    def test_block_device_number_mismatch_only_unverifies_affected_roles(self):
        original = self.read()
        block_device = self.source._block_device
        with patch.object(self.source, "_block_device", side_effect=lambda device:
                          (8, 99) if device == "/dev/sda2" else block_device(device)):
            placement = self.read()
        self.assertFalse(placement.roles.data.verified)
        self.assertFalse(placement.roles.history.verified)
        self.assertTrue(placement.roles.backups.verified)
        for name in ("data", "history", "backups"):
            role, expected = getattr(placement.roles, name), getattr(original.roles, name)
            self.assertEqual(role.state, ValueState.KNOWN)
            self.assertEqual(role.storage_id, expected.storage_id)
            self.assertEqual(role.path, expected.path)

    def test_mismatched_block_device_uuid_still_participates_in_duplicate_detection(self):
        self.outputs["/dev/sda3"] = self.outputs["/dev/sda3"].replace(UUIDS[2].encode(), UUIDS[1].encode())
        block_device = self.source._block_device
        with patch.object(self.source, "_block_device", side_effect=lambda device:
                          (8, 99) if device == "/dev/sda3" else block_device(device)):
            placement = self.read()
        self.assertFalse(placement.roles.data.verified)
        self.assertFalse(placement.roles.history.verified)
        self.assertFalse(placement.roles.backups.verified)

    def test_device_number_change_during_read_is_a_refusal(self):
        block_device = self.source._block_device
        observed = 0
        def changing_device(device):
            nonlocal observed
            if device == "/dev/sda2":
                observed += 1
                if observed == 2:
                    return 8, 99
            return block_device(device)
        with patch.object(self.source, "_block_device", side_effect=changing_device):
            self.assert_failure(self.read, RouterReadFailure.CHANGED)

    def test_command_exit_timeout_size_and_exception_are_safe(self):
        for failure in (RouterReadFailure.TIMEOUT, RouterReadFailure.TOO_LARGE, RouterReadFailure.MISSING):
            with patch.object(self.source, "_run", side_effect=RouterReadError(failure)):
                self.assert_failure(self.read, failure)
        with patch.object(self.source, "_run", return_value=(2, b"private-secret")):
            self.assert_failure(self.read, RouterReadFailure.EXIT_STATUS)
        for outcome in ((True, b""), (0, "private-secret"), (0, b"x" * 32769)):
            with patch.object(self.source, "_run", return_value=outcome):
                self.assert_failure(self.read, RouterReadFailure.TOO_LARGE if type(outcome[1]) is bytes
                                    and len(outcome[1]) > 32768 else RouterReadFailure.INVALID_RESPONSE)
        with patch.object(self.source, "_run", side_effect=OSError("private-secret")):
            self.assert_failure(self.read, RouterReadFailure.IO_ERROR)

    def during_confirmation(self, change):
        original = self.source._optional
        count = 0
        def read(path, limit):
            nonlocal count
            if path == files.BACKUP_CONFIG:
                count += 1
                if count == 2:
                    change()
            return original(path, limit)
        with patch.object(self.source, "_optional", side_effect=read):
            self.assert_failure(self.read, RouterReadFailure.CHANGED)

    def test_mountinfo_change_is_a_refusal(self):
        def change():
            self.rows.append("6 1 0:5 / /new rw - tmpfs tmpfs rw")
            self.write_mounts()
        self.during_confirmation(change)

    def test_configuration_change_is_a_refusal(self):
        self.during_confirmation(lambda: self.put(files.BACKUP_CONFIG, b"{}"))

    def test_uuid_change_is_a_refusal(self):
        self.during_confirmation(lambda: self.outputs.update({
            "/dev/sda2": self.outputs["/dev/sda2"].replace(UUIDS[1].encode(), UUIDS[2].encode())}))

    def test_directory_replacement_is_a_refusal(self):
        def change():
            directory = self.path(HISTORY)
            directory.rename(directory.with_name("original"))
            directory.mkdir()
        self.during_confirmation(change)

    def test_real_block_device_check_rejects_regular_file_and_symlink(self):
        self.put("/dev/sda1", b"private-secret")
        real = files.StoragePlacementFiles(root=str(self.root), run=self.run_command)
        self.assert_failure(lambda: real._block_device("/dev/sda1"), RouterReadFailure.UNSAFE)
        self.path("/dev/sda1").unlink()
        self.path("/dev/sda1").symlink_to("/private-secret")
        self.assert_failure(lambda: real._block_device("/dev/sda1"), RouterReadFailure.UNSAFE)


if __name__ == "__main__":
    unittest.main()
