"""Архивы и отказы на искусственных разделах; без SSH, сети и реального роутера."""

from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.backup import BackupError, create_backup
from keenvpn.adapters.router_backup import (
    BackupConfig, RouterBackupStorage, digest_file, inventory, load_config,
    snapshot_sqlite, sqlite_source_info, verify_archive,
)


UUIDS = tuple(f"00000000-0000-0000-0000-{number:012d}" for number in (1, 2, 3))


class FixtureStorage(RouterBackupStorage):
    """Внешние команды заменены фиксированными безопасными ответами."""

    def command(self, args):
        if args[0].endswith("blkid"):
            return (args[-1] + ': LABEL="fixture" UUID="' + UUIDS[int(args[-1][-1]) - 1] + '"\n').encode()
        if args[-1] == "show running-config":
            return b"! $$$ Agent: fixture\n" + b"!\n" * 40
        return b"fixture-version\n"


class RouterBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = BackupConfig(*UUIDS)
        for uuid in UUIDS:
            (self.root / "tmp/mnt" / uuid).mkdir(parents=True)
        (self.root / "opt/etc").mkdir(parents=True)
        (self.root / "opt/etc/config.json").write_text('{"password": "fixture-secret"}')
        (self.root / "opt/tmp").mkdir()
        (self.root / "opt/tmp/excluded").write_text("temporary")
        (self.root / "opt/etc/link").symlink_to("/opt/etc/config.json")
        self.data = self.root / "tmp/mnt" / UUIDS[1]
        self.database = self.data / "keenvpn/vpn-history/history.sqlite"
        self.database.parent.mkdir(parents=True)
        with sqlite3.connect(self.database) as db:
            db.execute("CREATE TABLE history(value TEXT)")
            db.execute("INSERT INTO history VALUES ('fixture')")
        db.close()
        self.mounts = self.root / "mounts"
        self.mounts.write_text("".join(
            f"/dev/sda{i} {self.root}/tmp/mnt/{uuid} ext4 rw,noatime 0 0\n"
            for i, uuid in enumerate(UUIDS, 1)
        ) + f"/dev/sda1 {self.root}/opt ext4 rw,noatime 0 0\n")
        self.storage = FixtureStorage(self.config, system_root=self.root, mounts_file=self.mounts)
        self.target = self.storage.target

    def make_old(self, count=7):
        self.target.mkdir(parents=True, exist_ok=True)
        for number in range(count):
            name = f"keenvpn-20200101T0000{number:02d}.000000Z.tar.gz"
            (self.target / name).write_bytes(b"old")
            (self.target / (name + ".sha256")).write_text("old")

    def test_complete_archive_snapshot_permissions_and_rotation(self):
        self.make_old()
        result = create_backup(self.storage)
        archives = sorted(self.target.glob("*.tar.gz"))
        self.assertEqual(len(archives), 5)
        self.assertEqual(result.retained, 5)
        archive_path = self.target / result.name
        self.assertEqual(digest_file(archive_path), result.sha256)
        self.assertEqual(archive_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o700)
        with tarfile.open(archive_path) as archive:
            self.assertNotIn("opt/tmp/excluded", archive.getnames())
            self.assertTrue(archive.getmember("opt/etc/link").issym())
            self.assertEqual(archive.getmember("opt/etc/link").linkname, "/opt/etc/config.json")
            manifest = json.load(archive.extractfile("manifest.json"))
            self.assertEqual(manifest["sqlite"]["integrity"], "ok")
            content = archive.extractfile("data/keenvpn/vpn-history/history.sqlite").read()
            restored = self.root / "verify.sqlite"
            restored.write_bytes(content)
            with sqlite3.connect(restored) as db:
                self.assertEqual(db.execute("SELECT * FROM history").fetchall(), [("fixture",)])
            db.close()
        self.assertFalse(list(self.target.glob(".partial-*")))

    def test_missing_mount_never_creates_fallback(self):
        self.mounts.write_text("")
        with self.assertRaises(BackupError):
            create_backup(self.storage)
        self.assertFalse(self.target.exists())

    def test_sqlite_snapshot_preserves_source_metadata_in_archive_and_manifest(self):
        self.database.chmod(0o640)
        source = self.database.stat()
        result = create_backup(self.storage)
        name = "data/keenvpn/vpn-history/history.sqlite"
        with tarfile.open(self.target / result.name) as archive:
            member = archive.getmember(name)
            record = json.load(archive.extractfile("manifest.json"))["files"][name]
        self.assertEqual((member.mode, member.uid, member.gid),
                         (0o640, source.st_uid, source.st_gid))
        self.assertEqual((record["mode"], record["uid"], record["gid"]),
                         (0o640, source.st_uid, source.st_gid))

    def test_sqlite_snapshot_uses_source_service_owner(self):
        self.make_old()
        before = {p.name: p.read_bytes() for p in self.target.iterdir()}
        chown = os.chown
        owners = []

        def source_info(path):
            info = sqlite_source_info(path)
            if path == self.database:
                values = list(info)
                values[4:6] = [12345, 12346]
                return os.stat_result(values)
            return info

        def reject_owner(path, uid, gid, **kwargs):
            if Path(path) == self.storage.work / "history.sqlite":
                owners.append((uid, gid))
                raise PermissionError("fixture")
            return chown(path, uid, gid, **kwargs)

        with patch("keenvpn.adapters.router_backup.sqlite_source_info", side_effect=source_info), \
                patch("keenvpn.adapters.router_backup.os.chown", side_effect=reject_owner):
            with self.assertRaises(PermissionError):
                create_backup(self.storage)
        self.assertEqual(owners, [(12345, 12346)])
        self.assertEqual({p.name: p.read_bytes() for p in self.target.iterdir()}, before)

    def test_sqlite_snapshot_metadata_failure_preserves_old_archives(self):
        self.make_old()
        self.database.chmod(0o640)
        before = {p.name: p.read_bytes() for p in self.target.iterdir()}
        chmod = os.chmod

        def reject_mode(path, mode, **kwargs):
            if self.storage.work is not None and Path(path) == self.storage.work / "history.sqlite" and mode == 0o640:
                raise PermissionError("fixture")
            return chmod(path, mode, **kwargs)

        with patch("keenvpn.adapters.router_backup.os.chmod", side_effect=reject_mode):
            with self.assertRaises(PermissionError):
                create_backup(self.storage)
        self.assertEqual({p.name: p.read_bytes() for p in self.target.iterdir()}, before)

    def test_wrong_uuid_and_read_only_mount(self):
        for changed in (self.mounts.read_text().replace("/dev/sda3", "/dev/sda2"),
                        self.mounts.read_text().replace("ext4 rw", "ext4 ro")):
            self.mounts.write_text(changed)
            with self.assertRaises(BackupError):
                create_backup(self.storage)
            self.assertFalse(self.target.exists())

    def test_failure_preserves_every_old_archive(self):
        self.make_old()
        before = sorted(p.name for p in self.target.iterdir())
        with patch.object(self.storage, "create_and_verify", side_effect=OSError("private-value")):
            with self.assertRaises(OSError):
                create_backup(self.storage)
        self.assertEqual(sorted(p.name for p in self.target.iterdir()), before)

    def test_low_space_preserves_old_archives(self):
        self.make_old()
        with patch("keenvpn.adapters.router_backup.shutil.disk_usage") as usage:
            usage.return_value.free = 0
            with self.assertRaisesRegex(BackupError, "Недостаточно места"):
                create_backup(self.storage)
        self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)

    def test_changed_source_prevents_publication(self):
        original = self.storage.create_and_verify
        def change():
            (self.root / "opt/etc/config.json").write_text("changed")
            original()
        with patch.object(self.storage, "create_and_verify", side_effect=change):
            with self.assertRaisesRegex(BackupError, "Исходные файлы изменились"):
                create_backup(self.storage)
        self.assertFalse(list(self.target.glob("*.tar.gz")))

    def test_changed_native_config_prevents_publication(self):
        original = self.storage.create_and_verify
        command = self.storage.command
        def change():
            with patch.object(self.storage, "command", side_effect=lambda args:
                              b"changed" if args[-1] == "show running-config" else command(args)):
                original()
        with patch.object(self.storage, "create_and_verify", side_effect=change):
            with self.assertRaisesRegex(BackupError, "Конфигурация Keenetic изменилась"):
                create_backup(self.storage)
        self.assertFalse(list(self.target.glob("*.tar.gz")))

    def test_symlink_destination_is_rejected(self):
        other = self.root / "other"
        other.mkdir()
        self.target.parent.mkdir()
        self.target.symlink_to(other)
        with self.assertRaises(BackupError):
            create_backup(self.storage)
        self.assertEqual(list(other.iterdir()), [])

    def test_shared_lock_prevents_parallel_run(self):
        lock = self.root / "tmp/keenvpn-backup.lock"
        with lock.open("w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            with self.assertRaisesRegex(BackupError, "уже выполняется"):
                create_backup(self.storage)
        self.assertFalse(self.target.exists())

    def test_lock_is_released_after_failure(self):
        with patch.object(self.storage, "prepare", side_effect=BackupError("test")):
            with self.assertRaises(BackupError):
                create_backup(self.storage)
        self.storage = FixtureStorage(self.config, system_root=self.root, mounts_file=self.mounts)
        self.assertEqual(create_backup(self.storage).retained, 1)

    def test_stale_workspace_removed_but_unrelated_files_preserved(self):
        self.target.mkdir(parents=True)
        stale = self.target / ".partial-12345678"
        stale.mkdir()
        (stale / "secret").write_text("fixture")
        (self.target / "manual.tar.gz").write_bytes(b"manual")
        create_backup(self.storage)
        self.assertFalse(stale.exists())
        self.assertTrue((self.target / "manual.tar.gz").exists())

    def test_mount_loss_before_publication_keeps_previous(self):
        self.make_old()
        original = self.storage.publish
        def unmount():
            self.mounts.write_text("")
            original()
        with patch.object(self.storage, "publish", side_effect=unmount):
            with self.assertRaises(BackupError):
                create_backup(self.storage)
        self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)

    def test_active_sqlite_wal_is_backed_up_consistently(self):
        destination = self.root / "snapshot.sqlite"
        with sqlite3.connect(self.database) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("INSERT INTO history VALUES ('committed')")
            writer.commit()
            writer.execute("INSERT INTO history VALUES ('not-committed')")
            snapshot_sqlite(self.database, destination)
            writer.rollback()
        writer.close()
        with sqlite3.connect(destination) as db:
            self.assertEqual(db.execute("SELECT * FROM history").fetchall(), [("fixture",), ("committed",)])
        db.close()

    def test_sqlite_parent_links_preserve_other_database_and_old_archives(self):
        for component in ("keenvpn", "keenvpn/vpn-history"):
            for absolute in (False, True):
                with self.subTest(component=component, absolute=absolute):
                    folder = self.data / component
                    original = self.root / "history-original"
                    folder.rename(original)
                    link = original if absolute else Path(os.path.relpath(original, folder.parent))
                    folder.symlink_to(link, target_is_directory=True)
                    self.make_old()
                    before = {p.name: p.read_bytes() for p in self.target.iterdir()}
                    database_before = self.database.read_bytes()
                    try:
                        with self.assertRaises(BackupError):
                            create_backup(self.storage)
                        self.assertEqual(self.database.read_bytes(), database_before)
                        self.assertEqual({p.name: p.read_bytes() for p in self.target.iterdir()}, before)
                    finally:
                        folder.unlink()
                        original.rename(folder)
                        self.storage = FixtureStorage(self.config, system_root=self.root, mounts_file=self.mounts)

    def test_relative_sqlite_parent_link_cannot_overwrite_foreign_database(self):
        original = self.root / "history-other"
        self.database.parent.rename(original)
        self.database.parent.symlink_to("../../../../history-other", target_is_directory=True)
        self.make_old()
        foreign = self.target / "history-other/history.sqlite"
        foreign.parent.mkdir()
        with sqlite3.connect(foreign) as db:
            db.execute("CREATE TABLE protected(value TEXT)")
            db.execute("INSERT INTO protected VALUES ('must-remain')")
        db.close()
        before = foreign.read_bytes()
        with self.assertRaises(BackupError):
            create_backup(self.storage)
        self.assertEqual(foreign.read_bytes(), before)
        self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)
        self.assertFalse(list(self.target.glob(".partial-*")))

    def test_sqlite_snapshot_rejects_destination_parent_link(self):
        outside = self.root / "outside"
        outside.mkdir()
        foreign = outside / "history.sqlite"
        foreign.write_bytes(b"must-remain")
        link = self.root / "snapshot-link"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(BackupError):
            snapshot_sqlite(self.database, link / "history.sqlite")
        self.assertEqual(foreign.read_bytes(), b"must-remain")

    def test_sqlite_snapshot_never_overwrites_existing_destination(self):
        destination = self.root / "protected.sqlite"
        destination.write_bytes(b"must-remain")
        with self.assertRaises(FileExistsError):
            snapshot_sqlite(self.database, destination)
        self.assertEqual(destination.read_bytes(), b"must-remain")

    def test_staged_parent_link_during_snapshot_preserves_foreign_database(self):
        self.make_old()
        outside = self.root / "outside"
        outside.mkdir()
        foreign = outside / "history.sqlite"
        foreign.write_bytes(b"must-remain")
        def replace_parent(source, destination):
            snapshot_sqlite(source, destination)
            folder = self.storage.stage / "data/keenvpn/vpn-history"
            folder.rename(folder.with_name("saved-history"))
            folder.symlink_to(outside, target_is_directory=True)
        with patch("keenvpn.adapters.router_backup.snapshot_sqlite", side_effect=replace_parent):
            with self.assertRaises(BackupError):
                create_backup(self.storage)
        self.assertEqual(foreign.read_bytes(), b"must-remain")
        self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)

    def test_missing_staged_sqlite_snapshot_prevents_publication(self):
        self.make_old()
        original = self.storage.create_and_verify
        def remove_snapshot():
            (self.storage.stage / "data" / "keenvpn/vpn-history/history.sqlite").unlink()
            original()
        with patch.object(self.storage, "create_and_verify", side_effect=remove_snapshot):
            with self.assertRaises(BackupError):
                create_backup(self.storage)
        self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)

    def test_sqlite_source_replaced_on_open_prevents_publication(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                self.make_old()
                other = self.root / "other.sqlite"
                with sqlite3.connect(other) as db:
                    db.execute("CREATE TABLE foreign_data(value TEXT)")
                db.close()
                connect = sqlite3.connect
                replaced = False
                def replace_on_open(path, *args, **kwargs):
                    nonlocal replaced
                    if not replaced and str(path).startswith(self.database.as_uri()):
                        replaced = True
                        self.database.rename(self.root / "original.sqlite")
                        if symlink:
                            self.database.symlink_to(other)
                        else:
                            self.database.write_bytes(other.read_bytes())
                    return connect(path, *args, **kwargs)
                try:
                    with patch("keenvpn.adapters.router_backup.sqlite3.connect", side_effect=replace_on_open):
                        with self.assertRaises(BackupError):
                            create_backup(self.storage)
                    self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)
                    self.assertFalse(list(self.target.glob(".partial-*")))
                finally:
                    self.database.unlink()
                    (self.root / "original.sqlite").rename(self.database)
                    other.unlink()
                    self.storage = FixtureStorage(self.config, system_root=self.root, mounts_file=self.mounts)

    def test_sqlite_source_parent_replaced_on_open_prevents_publication(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                self.make_old()
                folder = self.database.parent
                original = self.root / "original-history"
                connect = sqlite3.connect
                replaced = False
                def replace_on_open(path, *args, **kwargs):
                    nonlocal replaced
                    if not replaced and str(path).startswith(self.database.as_uri()):
                        replaced = True
                        folder.rename(original)
                        if symlink:
                            folder.symlink_to(original, target_is_directory=True)
                        else:
                            folder.mkdir()
                            self.database.hardlink_to(original / "history.sqlite")
                    return connect(path, *args, **kwargs)
                try:
                    with patch("keenvpn.adapters.router_backup.sqlite3.connect", side_effect=replace_on_open):
                        with self.assertRaises(BackupError):
                            create_backup(self.storage)
                    self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)
                finally:
                    if symlink:
                        folder.unlink()
                    else:
                        self.database.unlink()
                        folder.rmdir()
                    original.rename(folder)
                    self.storage = FixtureStorage(self.config, system_root=self.root, mounts_file=self.mounts)

    def test_sqlite_source_replaced_after_verification_preserves_old_archives(self):
        self.make_old()
        original = self.storage.publish
        def replace_before_publication():
            self.database.rename(self.root / "original.sqlite")
            self.database.write_bytes((self.root / "original.sqlite").read_bytes())
            original()
        with patch.object(self.storage, "publish", side_effect=replace_before_publication):
            with self.assertRaises(BackupError):
                create_backup(self.storage)
        self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)

    def test_sqlite_source_replaced_during_backup_prevents_publication(self):
        self.make_old()
        database = self.database
        original = self.root / "original.sqlite"
        connect = sqlite3.connect
        class ReplacingConnection(sqlite3.Connection):
            def backup(self, target, *args, **kwargs):
                super().backup(target, *args, **kwargs)
                database.rename(original)
                database.write_bytes(original.read_bytes())
        def open_source(path, *args, **kwargs):
            if str(path).startswith(database.as_uri()):
                kwargs["factory"] = ReplacingConnection
            return connect(path, *args, **kwargs)
        with patch("keenvpn.adapters.router_backup.sqlite3.connect", side_effect=open_source):
            with self.assertRaises(BackupError):
                create_backup(self.storage)
        self.assertEqual(len(list(self.target.glob("*.tar.gz"))), 7)
        self.assertFalse(list(self.target.glob(".partial-*")))

    def test_committed_wal_write_after_snapshot_does_not_block_archive(self):
        original = self.storage.create_and_verify
        with sqlite3.connect(self.database) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            def write_after_snapshot():
                writer.execute("INSERT INTO history VALUES ('after-snapshot')")
                writer.commit()
                original()
            with patch.object(self.storage, "create_and_verify", side_effect=write_after_snapshot):
                result = create_backup(self.storage)
        writer.close()
        with tarfile.open(self.target / result.name) as archive:
            restored = self.root / "verify.sqlite"
            restored.write_bytes(archive.extractfile("data/keenvpn/vpn-history/history.sqlite").read())
        with sqlite3.connect(restored) as db:
            self.assertEqual(db.execute("SELECT * FROM history").fetchall(), [("fixture",)])
        db.close()

    def test_busybox_blkid_full_output_and_ambiguous_uuid(self):
        self.storage.check_mounts()
        command = self.storage.command
        for suffix in (b' UUID="unexpected"', b'\n/dev/sdz1: UUID="unexpected"'):
            with patch.object(self.storage, "command", side_effect=lambda args:
                              command(args).rstrip() + suffix):
                with self.assertRaises(BackupError):
                    self.storage.check_mounts()

    def test_corrupt_sqlite_is_rejected(self):
        self.database.write_bytes(b"not a database")
        with self.assertRaises(sqlite3.DatabaseError):
            create_backup(self.storage)
        self.assertFalse(list(self.target.glob("*.tar.gz")))

    def test_archive_validation_rejects_corruption_and_traversal(self):
        path = self.root / "bad.tar.gz"
        for name in ("../outside", "/absolute", "file"):
            with tarfile.open(path, "w:gz") as archive:
                entry = tarfile.TarInfo(name)
                entry.size = 1
                archive.addfile(entry, io.BytesIO(b"a"))
            record = {"type": "file", "mode": 0o644, "uid": 0, "gid": 0, "size": 1,
                      "sha256": hashlib.sha256(b"wrong").hexdigest()}
            with self.assertRaises(BackupError):
                verify_archive(path, {name: record})

    def test_invalid_config_and_shell_payload_rejected(self):
        for values in ((UUIDS[0], UUIDS[0], UUIDS[2]), ("$(false)", *UUIDS[1:])):
            with self.assertRaises(BackupError):
                BackupConfig(*values)
        for count in (0, 31, True, "5"):
            with self.assertRaises(BackupError):
                BackupConfig(*UUIDS, keep=count)
        config = self.root / "config.json"
        config.write_text(json.dumps({**self.config.__dict__, "command": "bad"}))
        with self.assertRaises(BackupError):
            load_config(config)

    def test_no_rotation_without_publication(self):
        with self.assertRaises(BackupError):
            self.storage.retain()


class BackupOrderingTests(unittest.TestCase):
    def test_failure_at_each_stage_never_reaches_rotation(self):
        for failed in ("prepare", "create_and_verify", "publish"):
            calls = []
            class Storage:
                @contextmanager
                def session(self):
                    yield
                def __getattr__(self, name):
                    def call():
                        calls.append(name)
                        if name == failed:
                            raise BackupError("fixture")
                    return call
            with self.assertRaises(BackupError):
                create_backup(Storage())
            self.assertNotIn("retain", calls)
