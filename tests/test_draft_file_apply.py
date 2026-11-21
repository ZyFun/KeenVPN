"""Файловый этап под настоящей блокировкой и с проверенной копией во временном корне."""

from dataclasses import replace
from datetime import datetime, timezone
import errno
import fcntl
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import draft_config_files
from keenvpn.adapters.draft_backup_files import DraftBackupFiles
from keenvpn.adapters.draft_config_files import DraftConfigFiles
from keenvpn.adapters.draft_session_files import DraftSessionFiles
from keenvpn.adapters.file_writes import rename_new_file
from keenvpn.adapters.keenetic_rci_http import RciResource
from keenvpn.application.draft_file_apply import FileStepFailure, run_draft_file_apply
from keenvpn.application.draft_session import draft_revision_token
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.application.source_baseline import capture_baseline
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.draft_candidate_state import build_draft_candidate
from keenvpn.domain.draft_session import DraftSession
from keenvpn.domain.draft_snapshot import DraftDiffSnapshot
from keenvpn.domain.keenetic_native import KeeneticHotspotSettings
from keenvpn.domain.source_baseline import BaselineSource
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.router_files import INIT, XRAY_CONFIGS


DRAFT_ID = "0000abcd-0000-4000-8000-000000000094"
ORIGINAL = b'{"setting": 1}\n'
CANDIDATE = b'// synthetic-private-content\n{"setting": 2}\n'


def parts(**contents):
    return XrayConfigSet(tuple(ConfigDocument(name + ".json", contents[name]) for name in sorted(contents)))


class DraftFileApplyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        root = self.root.stat()
        self.backups = self.root / "backups"
        self.storage = DraftBackupFiles(str(self.backups), parent_identity=(root.st_dev, root.st_ino))
        self.drafts = DraftSessionFiles(str(self.root / "draft"))
        self.xray = self.root / XRAY_CONFIGS
        self.xray.mkdir(parents=True)
        self.first = self.xray / "first.json"
        self.second = self.xray / "second.json"
        self.first.write_bytes(ORIGINAL)
        self.second.write_bytes(ORIGINAL)
        self.first.chmod(0o640)
        self.init = self.root / INIT
        self.init.parent.mkdir(parents=True)
        self.init.write_bytes(b'proxy_router="on"\n')
        self.init.chmod(0o751)
        self.lists = self.root / "opt/etc/xkeen"
        self.lists.mkdir()
        hotspot = {"host": []}
        rci = {RciResource.POLICIES: {}, RciResource.HOTSPOT_SETTINGS: hotspot}
        self.files = DraftConfigFiles(root=str(self.root), read=rci.__getitem__)
        self.original = DraftDiffSnapshot(
            xray_configs=parts(first=ORIGINAL, second=ORIGINAL),
            xkeen_settings=None, xkeen_init=self.init.read_bytes(),
            xkeen_port_exclude=None, xkeen_port_proxying=None, xkeen_ip_exclude=None,
            keenetic_policies={}, keenetic_hotspot_settings=KeeneticHotspotSettings(hotspot),
        )
        self.candidate = replace(self.original, xray_configs=parts(first=CANDIDATE, second=CANDIDATE),
                                 xkeen_init=b'# private test\nproxy_router="on"\n')

    def save(self, candidate=None):
        state = build_draft_candidate(self.original, self.candidate if candidate is None else candidate, ())
        session = DraftSession(DRAFT_ID, datetime(2026, 11, 21, tzinfo=timezone.utc),
                               baseline=capture_baseline(self.files), candidate=state)
        self.revision = self.drafts.create_draft(session)
        self.token = draft_revision_token(self.revision)

    def run_apply(self):
        return run_draft_file_apply(self.drafts, self.files, DRAFT_ID, self.token, self.storage)

    def assert_failure(self, result, code, *, completed=(), part="first.json"):
        self.assertIs(result.failure.code, code)
        self.assertEqual(result.failure.target.part, part)
        self.assertEqual(tuple(target.part for target in result.completed), completed)
        for private in (str(self.root), part, self.revision, "synthetic-private-content"):
            if private is not None:
                self.assertNotIn(private, repr(result) + repr(result.failure) + repr(result.failure.target))
        self.assert_no_temporary()

    def assert_no_temporary(self):
        self.assertEqual(list(self.root.rglob(".keenvpn-write-*")), [])

    def test_replaces_each_file_from_private_staging_and_preserves_posix_metadata(self):
        self.save()
        first = self.first.stat()
        init = self.init.stat()
        original_replace = os.replace

        def observe(source, target, *, src_dir_fd, dst_dir_fd):
            if source == "candidate":
                self.assertTrue(any(self.backups.iterdir()))
                self.assertEqual(os.fstat(src_dir_fd).st_dev, os.fstat(dst_dir_fd).st_dev)
                self.assertEqual(stat.S_IMODE(os.fstat(src_dir_fd).st_mode) & 0o777, 0o700)
                current = Path(self.xray / target) if target.endswith(".json") else self.init
                self.assertNotIn(b"private", current.read_bytes())
                self.assertEqual([path.name for path in self.xray.glob("*.json")],
                                 [path.name for path in self.xray.iterdir() if path.is_file()])
            return original_replace(source, target, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

        with patch("os.replace", side_effect=observe):
            result = self.run_apply()
        self.assertIsNone(result.failure)
        self.assertEqual([target.part for target in result.completed], ["first.json", "second.json", None])
        self.assertEqual(result.backup.draft_revision, self.revision)
        self.assertEqual(self.drafts.read_draft().revision, self.revision)
        for target, info, payload in ((self.first, first, CANDIDATE), (self.init, init, self.candidate.xkeen_init)):
            after = target.stat()
            self.assertNotEqual(after.st_ino, info.st_ino)
            self.assertEqual((after.st_mode, after.st_uid, after.st_gid), (info.st_mode, info.st_uid, info.st_gid))
            self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(self.second.read_bytes(), CANDIDATE)
        self.assert_no_temporary()

    def test_xray_add_remove_and_xkeen_empty_file_use_distinct_presence(self):
        self.save(replace(self.original, xray_configs=parts(added=CANDIDATE, second=ORIGINAL),
                          xkeen_port_exclude=b""))
        other = self.xray / "unmanaged.txt"
        other.write_bytes(b"keep")
        (self.xray / "ignored.json").mkdir()
        result = self.run_apply()
        self.assertIsNone(result.failure)
        self.assertEqual([target.part for target in result.completed], ["first.json", "added.json", None])
        self.assertFalse(self.first.exists())
        added = self.xray / "added.json"
        for file, expected in ((added, CANDIDATE), (self.lists / "port_exclude.lst", b"")):
            self.assertEqual(file.read_bytes(), expected)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            self.assertEqual(file.stat().st_nlink, 1)
        self.assertEqual(other.read_bytes(), b"keep")
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        self.assert_no_temporary()

    def test_new_part_keeps_external_file_created_at_publication(self):
        self.save(replace(self.candidate, xray_configs=parts(added=CANDIDATE, first=ORIGINAL, second=ORIGINAL)))
        added = self.xray / "added.json"
        external = b'{"external": true}\n'
        publish = draft_config_files.rename_new_file

        def appears_at_publication(source, target, **kwargs):
            if source == "candidate" and target == added.name:
                added.write_bytes(external)
            return publish(source, target, **kwargs)

        with patch.object(draft_config_files, "rename_new_file", side_effect=appears_at_publication):
            result = self.run_apply()

        self.assert_failure(result, FileStepFailure.CONFLICT, part=added.name)
        self.assertEqual(added.read_bytes(), external)
        self.assertEqual(self.init.read_bytes(), self.original.xkeen_init)

    def test_interruption_after_addition_leaves_one_link_and_allows_later_edit(self):
        with_added = replace(self.original, xray_configs=parts(added=CANDIDATE, first=ORIGINAL, second=ORIGINAL))
        self.save(with_added)
        added = self.xray / "added.json"
        publish = draft_config_files.rename_new_file

        def publish_then_exit(source, target, **kwargs):
            publish(source, target, **kwargs)
            if target == added.name:
                os._exit(0)

        pid = os.fork()
        if pid == 0:
            try:
                with patch.object(draft_config_files, "rename_new_file", side_effect=publish_then_exit):
                    self.run_apply()
            finally:
                os._exit(2)
        _, status = os.waitpid(pid, 0)

        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(added.read_bytes(), CANDIDATE)
        self.assertEqual(added.stat().st_nlink, 1)
        abandoned, = self.xray.glob(".keenvpn-write-*")
        self.assertEqual(list(abandoned.iterdir()), [])
        self.drafts.remove_draft(self.revision)

        self.original = with_added
        self.save(replace(with_added, xray_configs=parts(added=ORIGINAL, first=ORIGINAL, second=ORIGINAL)))
        result = self.run_apply()

        self.assertIsNone(result.failure)
        self.assertEqual([target.part for target in result.completed], [added.name])
        self.assertEqual(added.read_bytes(), ORIGINAL)

    def test_unavailable_exclusive_rename_stops_without_creating_file(self):
        self.save(replace(self.candidate, xray_configs=parts(added=CANDIDATE, first=ORIGINAL, second=ORIGINAL)))

        def fail_publication(_source, _target, *, src_dir_fd, dst_dir_fd):
            if src_dir_fd == dst_dir_fd == -1:
                raise OSError(errno.EBADF, "control descriptors")
            if src_dir_fd == dst_dir_fd:
                return publish(_source, _target, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
            raise OSError(errno.ENOSYS, "unavailable")

        publish = draft_config_files.rename_new_file
        with patch.object(draft_config_files, "rename_new_file", side_effect=fail_publication):
            result = self.run_apply()

        self.assert_failure(result, FileStepFailure.WRITE_FAILED, part="added.json")
        self.assertFalse((self.xray / "added.json").exists())
        self.assertEqual(self.init.read_bytes(), self.original.xkeen_init)

    def test_missing_exclusive_rename_is_rejected_before_backup_and_deletion(self):
        self.save(replace(self.original, xray_configs=parts(added=CANDIDATE, second=ORIGINAL)))
        with patch.object(draft_config_files, "rename_new_file", side_effect=OSError(errno.ENOSYS, "unavailable")):
            result = self.run_apply()

        self.assertEqual(result.code, "draft_files_exclusive_rename_unavailable")
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertFalse((self.xray / "added.json").exists())

    def test_exclusive_rename_probe_rejects_filesystem_before_removing_old_part(self):
        self.save(replace(self.original, xray_configs=parts(added=CANDIDATE, second=ORIGINAL)))

        def unsupported_filesystem(_source, _target, *, src_dir_fd, dst_dir_fd):
            if src_dir_fd == dst_dir_fd == -1:
                raise OSError(errno.EBADF, "control descriptors")
            raise OSError(errno.EINVAL, "filesystem does not support the rename flag")

        with (patch.object(draft_config_files, "rename_new_file", side_effect=unsupported_filesystem),
              patch.object(self.files, "write_draft_file", wraps=self.files.write_draft_file) as write):
            result = self.run_apply()

        write.assert_not_called()
        self.assertEqual(result.code, "draft_files_exclusive_rename_unavailable")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertFalse((self.xray / "added.json").exists())
        self.assertTrue(any(self.backups.iterdir()))
        self.assert_no_temporary()

    def test_exclusive_rename_checks_each_destination_directory_before_writes(self):
        self.save(replace(self.original, xray_configs=parts(a=CANDIDATE, b=CANDIDATE, second=ORIGINAL),
                          xkeen_settings=b"{}", xkeen_port_exclude=b""))
        publish = draft_config_files.rename_new_file
        xray = self.xray.stat()
        xkeen = self.lists.stat()
        observed = []

        def fail_second_probe(source, target, *, src_dir_fd, dst_dir_fd):
            if src_dir_fd >= 0 and src_dir_fd == dst_dir_fd:
                self.assertTrue(any(self.backups.iterdir()))
                directory = os.stat("..", dir_fd=src_dir_fd, follow_symlinks=False)
                if os.path.samestat(directory, xray):
                    observed.append("xray")
                elif os.path.samestat(directory, xkeen):
                    observed.append("xkeen")
                    raise OSError(errno.ENOTSUP, "filesystem does not support the rename flag")
            return publish(source, target, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

        with (patch.object(draft_config_files, "rename_new_file", side_effect=fail_second_probe),
              patch.object(self.files, "write_draft_file", wraps=self.files.write_draft_file) as write):
            result = self.run_apply()

        self.assertEqual(observed, ["xray", "xkeen"])
        write.assert_not_called()
        self.assertEqual(result.code, "draft_files_exclusive_rename_unavailable")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assert_no_temporary()

    def test_linux_aarch64_exclusive_rename_passes_abi_and_preserves_errno(self):
        host = os.uname_result(("Linux", "test", "4.9", "", "aarch64"))
        with (patch("os.uname", return_value=host), patch("ctypes.CDLL") as load,
              patch("ctypes.get_errno", return_value=errno.EEXIST)):
            syscall = load.return_value.syscall
            syscall.return_value = -1
            with self.assertRaises(OSError) as caught:
                rename_new_file("candidate", "часть.json", src_dir_fd=5, dst_dir_fd=7)

        self.assertEqual(caught.exception.errno, errno.EEXIST)
        load.assert_called_once_with(None, use_errno=True)
        number, source_dir, source, target_dir, target, flags = syscall.call_args.args
        self.assertEqual(number, 276)
        self.assertEqual((source_dir.value, source.value), (5, b"candidate"))
        self.assertEqual((target_dir.value, target.value, flags.value), (7, os.fsencode("часть.json"), 1))

    def test_oversized_name_is_rejected_before_removing_old_part(self):
        stem = "я" * 126
        self.assertEqual(len(os.fsencode(stem + ".json")), 257)
        self.save(replace(self.original, xray_configs=parts(**{stem: CANDIDATE, "second": ORIGINAL})))

        with patch.object(self.files, "write_draft_file", wraps=self.files.write_draft_file) as write:
            result = self.run_apply()

        write.assert_not_called()
        self.assertEqual(result.code, "draft_files_invalid_name")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        self.assert_no_temporary()

    def test_part_name_can_take_all_255_bytes(self):
        stem = "я" * 125
        name = stem + ".json"
        self.assertEqual(len(os.fsencode(name)), 255)
        self.save(replace(self.original, xray_configs=parts(**{stem: CANDIDATE, "second": ORIGINAL})))
        result = self.run_apply()
        self.assertIsNone(result.failure)
        self.assertEqual([target.part for target in result.completed], ["first.json", name])
        self.assertEqual((self.xray / name).read_bytes(), CANDIDATE)
        self.assertFalse(self.first.exists())

    def test_init_has_only_read_descriptor_when_published(self):
        self.save(replace(self.original, xkeen_init=b"#!/bin/sh\nexit 0\n"))
        open_entry = os.open
        replace_entry = os.replace
        descriptors = []
        observed = []

        def open_and_track(path, flags, *args, **kwargs):
            descriptor = open_entry(path, flags, *args, **kwargs)
            if path == "candidate":
                descriptors.append(descriptor)
            return descriptor

        def replace_and_check(source, target, **kwargs):
            replace_entry(source, target, **kwargs)
            if source != "candidate" or target != self.init.name:
                return
            current = self.init.stat()
            for descriptor in descriptors:
                try:
                    info = os.fstat(descriptor)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
                    continue
                if os.path.samestat(info, current):
                    observed.append(fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE)

        with (patch("os.open", side_effect=open_and_track), patch("os.replace", side_effect=replace_and_check)):
            result = self.run_apply()

        self.assertIsNone(result.failure)
        self.assertEqual(observed, [os.O_RDONLY])
        self.assert_no_temporary()

    @unittest.skipUnless(sys.platform == "linux", "Прямой запуск с проверкой ETXTBSY относится к Linux.")
    def test_linux_init_can_be_executed_immediately_after_publication(self):
        self.save(replace(self.original, xkeen_init=b"#!/bin/sh\nexit 0\n"))
        replace_entry = os.replace
        started = []

        def replace_and_run(source, target, **kwargs):
            replace_entry(source, target, **kwargs)
            if source == "candidate" and target == self.init.name:
                completed = subprocess.run(
                    [str(self.init)], stdin=subprocess.DEVNULL, capture_output=True,
                    env={}, timeout=3, check=False,
                )
                started.append(completed.returncode)

        with (patch("os.replace", side_effect=replace_and_run),
              patch("keenvpn.adapters.draft_config_files._has_unsupported_linux_flags", return_value=False)):
            result = self.run_apply()

        self.assertIsNone(result.failure)
        self.assertEqual(started, [0])

    def test_external_edit_during_second_staging_stops_remaining_writes(self):
        self.save()
        write = os.write

        def edit(descriptor, content):
            if self.first.read_bytes() == CANDIDATE and bytes(content) == CANDIDATE:
                self.second.write_bytes(b'{"external": true}')
            return write(descriptor, content)

        with patch("keenvpn.adapters.file_writes.os.write", side_effect=edit):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.CONFLICT, completed=("first.json",), part="second.json")
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), b'{"external": true}')
        self.assertEqual(self.init.read_bytes(), self.original.xkeen_init)

    def test_new_xray_part_during_staging_conflicts_even_when_target_is_unchanged(self):
        self.save()
        write = os.write

        def edit(descriptor, content):
            if bytes(content) == CANDIDATE:
                (self.xray / "foreign.json").write_bytes(ORIGINAL)
            return write(descriptor, content)

        with patch("keenvpn.adapters.file_writes.os.write", side_effect=edit):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.CONFLICT)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_read_failure_at_last_xkeen_fingerprint_stops_writes(self):
        self.save()
        real = self.files.current_fingerprint

        def read(source):
            if source is BaselineSource.XKEEN_INIT and self.first.read_bytes() == CANDIDATE:
                raise RouterReadError(RouterReadFailure.IO_ERROR)
            return real(source)

        with patch.object(self.files, "current_fingerprint", side_effect=read):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.READ_FAILED, completed=("first.json", "second.json"), part=None)
        self.assertEqual(self.init.read_bytes(), self.original.xkeen_init)

    def test_write_failure_leaves_original_and_removes_staging(self):
        self.save()
        write = os.write

        def fail(descriptor, content):
            if bytes(content) == CANDIDATE:
                write(descriptor, content[:4])
                raise OSError(errno.ENOSPC, "write failed")
            return write(descriptor, content)

        with patch("keenvpn.adapters.file_writes.os.write", side_effect=fail):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.WRITE_FAILED)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_failed_fsync_after_rename_leaves_unknown_step_and_stops(self):
        self.save()
        sync = os.fsync

        def fail(descriptor):
            if self.first.read_bytes() == CANDIDATE and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "sync failed")
            return sync(descriptor)

        with patch("os.fsync", side_effect=fail):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.UNCONFIRMED)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_rename_io_error_is_unknown_even_if_os_changed_target(self):
        self.save()
        real = os.replace

        def fail(source, target, **kwargs):
            real(source, target, **kwargs)
            if source == "candidate":
                raise OSError(errno.EIO, "rename outcome unknown")

        with patch("os.replace", side_effect=fail):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.UNCONFIRMED)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_close_failure_cannot_hide_uncertain_rename(self):
        self.save()
        real_replace = os.replace
        real_close = os.close
        descriptors = set()

        def rename(source, target, **kwargs):
            real_replace(source, target, **kwargs)
            if source == "candidate":
                descriptors.add(kwargs["src_dir_fd"])
                raise OSError(errno.EIO, "rename outcome unknown")

        def close(descriptor):
            real_close(descriptor)
            if descriptor in descriptors:
                descriptors.remove(descriptor)
                raise OSError(errno.EIO, "staging close failed")

        with patch("os.replace", side_effect=rename), patch("os.close", side_effect=close):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.UNCONFIRMED)
        self.assertTrue(result.failure.cleanup_failed)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_cleanup_io_error_keeps_confirmed_step_and_stops_remaining_writes(self):
        self.save()
        rmdir_entry = os.rmdir

        def fail_cleanup(name, *args, **kwargs):
            if name.startswith(".keenvpn-write-"):
                raise OSError(errno.EIO, "staging cleanup failed")
            return rmdir_entry(name, *args, **kwargs)

        with patch("os.rmdir", side_effect=fail_cleanup):
            result = self.run_apply()

        self.assertEqual([target.part for target in result.completed], ["first.json"])
        self.assertEqual(result.failure.target.part, "first.json")
        self.assertIsNone(result.failure.code)
        self.assertTrue(result.failure.cleanup_failed)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        self.assertEqual(self.init.read_bytes(), self.original.xkeen_init)
        self.assertEqual(len(list(self.xray.glob(".keenvpn-write-*"))), 1)

    def test_moved_staging_directory_is_reported_as_incomplete_cleanup(self):
        self.save()
        fingerprint = self.files.current_fingerprint
        moved = self.xray / "moved-stage"

        def move_staging(source):
            result = fingerprint(source)
            if source is BaselineSource.XRAY_CONFIGS and not moved.exists():
                folders = list(self.xray.glob(".keenvpn-write-*"))
                if folders:
                    folders[0].rename(moved)
            return result

        with patch.object(self.files, "current_fingerprint", side_effect=move_staging):
            result = self.run_apply()

        self.assertEqual([target.part for target in result.completed], ["first.json"])
        self.assertIsNone(result.failure.code)
        self.assertTrue(result.failure.cleanup_failed)
        self.assertEqual(result.failure.target.part, "first.json")
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)
        self.assertEqual(list(moved.iterdir()), [])

    def test_staging_directory_replacement_is_not_written_or_removed(self):
        self.save()
        real_open = os.open
        foreign = []

        def open_entry(path, flags, *args, **kwargs):
            if path.startswith(".keenvpn-write-"):
                (self.xray / path).rename(self.xray / "displaced")
                replacement = self.xray / path
                replacement.mkdir(mode=0o700)
                foreign.append(replacement)
            return real_open(path, flags, *args, **kwargs)

        with patch("os.open", side_effect=open_entry):
            result = self.run_apply()
        self.assertIs(result.failure.code, FileStepFailure.WRITE_FAILED)
        self.assertEqual(result.completed, ())
        self.assertEqual(len(foreign), 1)
        self.assertEqual(list(foreign[0].iterdir()), [])
        self.assertEqual(list((self.xray / "displaced").iterdir()), [])
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_modified_staged_bytes_are_not_published(self):
        self.save()
        real_sync = os.fsync

        def sync(descriptor):
            for staging in self.xray.glob(".keenvpn-write-*/candidate"):
                info = os.fstat(descriptor)
                if os.path.samestat(info, staging.stat()):
                    staging.write_bytes(b"x" * len(CANDIDATE))
            return real_sync(descriptor)

        with patch("os.fsync", side_effect=sync):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.WRITE_FAILED)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_unlock_failure_keeps_completed_steps_and_backup(self):
        self.save()
        real_flock = fcntl.flock

        def flock(descriptor, operation):
            real_flock(descriptor, operation)
            if operation == fcntl.LOCK_UN and self.first.read_bytes() == CANDIDATE:
                raise OSError(errno.EIO, "lock exit failed")

        with patch("fcntl.flock", side_effect=flock):
            result = self.run_apply()
        self.assertTrue(result.lock_release_failed)
        self.assertIsNone(result.failure)
        self.assertEqual([target.part for target in result.completed], ["first.json", "second.json", None])
        self.assertEqual(result.backup.draft_revision, self.revision)
        self.assertEqual(self.init.read_bytes(), self.candidate.xkeen_init)
        self.assert_no_temporary()

    def test_unlock_failure_keeps_structured_rejection_before_backup(self):
        self.save(replace(self.candidate, xkeen_init=None))
        expected = self.run_apply()
        self.assertEqual(expected.code, "draft_files_init_presence_change")
        draft = (self.root / "draft").stat()
        real_flock = fcntl.flock

        def flock(descriptor, operation):
            real_flock(descriptor, operation)
            if operation == fcntl.LOCK_UN and os.path.samestat(os.fstat(descriptor), draft):
                raise OSError(errno.EIO, "lock exit failed")

        with patch("fcntl.flock", side_effect=flock):
            result = self.run_apply()

        self.assertTrue(result.lock_release_failed)
        self.assertEqual(result.error, expected)
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assert_no_temporary()

    def test_metadata_change_after_backup_blocks_write_even_when_hash_matches(self):
        self.save()
        confirm = self.storage.confirm

        def edit(backup_id, digest):
            confirm(backup_id, digest)
            self.first.chmod(0o644)

        with patch.object(self.storage, "confirm", side_effect=edit):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.CONFLICT)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(stat.S_IMODE(self.first.stat().st_mode), 0o644)

    def test_linux_ext4_rejects_nodump_and_accepts_layout_flags(self):
        self.save()
        first = self.first.stat()
        layout_flags = 0x00080000 | 0x10000000
        nodump = 0x00000040

        def ioctl(descriptor, _request, result):
            flags = layout_flags
            if os.path.samestat(os.fstat(descriptor), first):
                flags |= nodump
            struct.pack_into("=I", result, 0, flags)
            return 0

        with (patch("keenvpn.adapters.draft_config_files._LINUX_ARCH", "aarch64"),
              patch("fcntl.ioctl", side_effect=ioctl)):
            result = self.run_apply()
            self.assert_failure(result, FileStepFailure.CONFLICT)
            self.assertEqual(self.first.read_bytes(), ORIGINAL)
            self.assertEqual(self.second.read_bytes(), ORIGINAL)
            nodump = 0
            result = self.run_apply()

        self.assertIsNone(result.failure)
        self.assertEqual(len(result.completed), 3)
        self.assertEqual(self.first.read_bytes(), CANDIDATE)
        self.assert_no_temporary()

    def test_linux_inode_flags_read_failure_prevents_publication(self):
        self.save()
        with (patch("keenvpn.adapters.draft_config_files._LINUX_ARCH", "aarch64"),
              patch("fcntl.ioctl", side_effect=OSError(errno.EIO, "flags read failed"))):
            result = self.run_apply()

        self.assert_failure(result, FileStepFailure.READ_FAILED)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assertEqual(self.second.read_bytes(), ORIGINAL)

    def test_directory_swap_during_last_read_fails_before_rename(self):
        self.save()
        real = self.files.current_fingerprint
        old = self.xray.with_name("original-dir")

        def read(source):
            actual = real(source)
            if source is BaselineSource.XRAY_CONFIGS and list(self.xray.glob(".keenvpn-write-*")):
                self.xray.rename(old)
                self.xray.mkdir()
                self.first.write_bytes(ORIGINAL)
                self.second.write_bytes(ORIGINAL)
            return actual

        with patch.object(self.files, "current_fingerprint", side_effect=read):
            result = self.run_apply()
        self.assert_failure(result, FileStepFailure.CONFLICT)
        self.assertEqual((old / self.first.name).read_bytes(), ORIGINAL)
        self.assertEqual(self.first.read_bytes(), ORIGINAL)

    def test_directory_and_init_presence_change_rejects_whole_file_stage(self):
        self.save(replace(self.candidate, xkeen_init=None))
        result = self.run_apply()
        self.assertEqual(result.code, "draft_files_init_presence_change")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assert_no_temporary()
        self.drafts.remove_draft(self.revision)
        self.save(replace(self.candidate, xray_configs=None))
        result = self.run_apply()
        self.assertEqual(result.code, "draft_files_xray_directory_change")
        self.assertEqual(self.first.read_bytes(), ORIGINAL)
        self.assert_no_temporary()

    def test_invalid_file_plan_rejects_repeated_attempts_before_backup(self):
        self.save(replace(self.candidate, xkeen_init=None))
        with (patch.object(self.storage, "save", wraps=self.storage.save) as save,
              patch.object(self.files, "write_draft_file", wraps=self.files.write_draft_file) as write):
            for _ in range(2):
                self.assertEqual(self.run_apply().code, "draft_files_init_presence_change")

        save.assert_not_called()
        write.assert_not_called()
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.first.read_bytes(), ORIGINAL)

    def test_native_change_uses_backup_without_publishing_files_or_native_data(self):
        self.save(replace(self.original, keenetic_policies={"Policy1": {"permit": []}}))
        result = self.run_apply()
        self.assertIsNone(result.failure)
        self.assertEqual(result.completed, ())
        self.assertTrue(any(self.backups.iterdir()))
        self.assertEqual(self.first.read_bytes(), ORIGINAL)

    def test_unverified_backup_prevents_any_file_step(self):
        self.save()
        with patch.object(self.storage, "confirm", side_effect=OSError), patch.object(self.files, "write_draft_file") as write:
            result = self.run_apply()
        self.assertEqual(result.code, "draft_backup_unverified")
        write.assert_not_called()
        self.assertEqual(self.first.read_bytes(), ORIGINAL)


if __name__ == "__main__":
    unittest.main()
