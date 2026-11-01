"""Чтение файлов Entware: пределы размера, запрет ссылок, неизменность во время чтения и безопасные отказы."""

import errno
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import entware_files
from keenvpn.adapters.entware_files import (
    PathFailure, digest_file, digest_files, read_file, read_files, regular_file_exists, walk_directory,
)
from keenvpn.application.ports import RouterReadError, RouterReadFailure


Failure = RouterReadFailure
LIMITS = dict(file_limit=64, total_limit=128, count_limit=4)


class FilesCase(unittest.TestCase):
    def setUp(self):
        # Реальный путь: на macOS временный каталог находится за ссылкой /var.
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-entware-")))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        shutil.rmtree(self.root)

    def write(self, relative: str, content: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def assert_failure(self, call, failure):
        try:
            raise ValueError(f"fixture-private-context {self.root}")
        except ValueError:
            with self.assertRaises(RouterReadError) as caught:
                call()
        error = caught.exception
        self.assertIs(type(error), RouterReadError)
        self.assertIs(error.failure, failure)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        text = str(error) + repr(error) + repr(error.args)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("fixture-private", text)
        return error


class ReadFileTests(FilesCase):
    def test_reads_regular_file_within_limit(self):
        self.write("etc/xkeen/xkeen.json", b'{"xkeen": {}}')
        self.assertEqual(read_file(str(self.root / "etc/xkeen/xkeen.json"), 13), b'{"xkeen": {}}')
        self.write("etc/empty", b"")
        self.assertEqual(read_file(str(self.root / "etc/empty"), 0), b"")

    def test_missing_file_or_directory(self):
        self.write("etc/xkeen/other", b"x")
        self.assert_failure(lambda: read_file(str(self.root / "etc/xkeen/xkeen.json"), 64), Failure.MISSING)
        self.assert_failure(lambda: read_file(str(self.root / "etc/absent/xkeen.json"), 64), Failure.MISSING)

    def test_too_large_file_is_rejected_before_and_while_reading(self):
        self.write("etc/list", b"x" * 65)
        self.assert_failure(lambda: read_file(str(self.root / "etc/list"), 64), Failure.TOO_LARGE)
        # Файл, выросший после первой проверки размера, отклоняется по числу прочитанных байт.
        self.write("etc/grow", b"x" * 10)
        original = os.read

        def grow(descriptor, size):
            chunk = original(descriptor, size)
            if chunk:
                with open(self.root / "etc/grow", "ab") as handle:
                    handle.write(b"y" * 100)
            return chunk

        with patch.object(os, "read", grow):
            self.assert_failure(lambda: read_file(str(self.root / "etc/grow"), 64), Failure.TOO_LARGE)

    def test_reads_at_most_limit_plus_one_byte(self):
        self.write("etc/list", b"x" * 64)
        requested = []
        original = os.read

        def counting(descriptor, size):
            requested.append(size)
            return original(descriptor, size)

        with patch.object(os, "read", counting):
            self.assertEqual(read_file(str(self.root / "etc/list"), 64), b"x" * 64)
        self.assertLessEqual(sum(requested), 65 + 1)
        self.assertLessEqual(max(requested), 65)

    def test_symlink_in_any_component_is_unsafe(self):
        target = self.write("real/etc/xkeen.json", b"{}")
        (self.root / "link-file").symlink_to(target)
        (self.root / "link-dir").symlink_to(self.root / "real")
        self.assert_failure(lambda: read_file(str(self.root / "link-file"), 64), Failure.UNSAFE)
        self.assert_failure(lambda: read_file(str(self.root / "link-dir/etc/xkeen.json"), 64), Failure.UNSAFE)
        (self.root / "dangling").symlink_to(self.root / "absent")
        self.assert_failure(lambda: read_file(str(self.root / "dangling"), 64), Failure.UNSAFE)

    def test_directory_fifo_and_file_in_path_are_unsafe(self):
        (self.root / "etc/dir").mkdir(parents=True)
        self.assert_failure(lambda: read_file(str(self.root / "etc/dir"), 64), Failure.UNSAFE)
        os.mkfifo(self.root / "etc/fifo")
        # O_NONBLOCK: открытие FIFO без писателя не зависает, тип отклоняется.
        self.assert_failure(lambda: read_file(str(self.root / "etc/fifo"), 64), Failure.UNSAFE)
        self.write("etc/plain", b"x")
        self.assert_failure(lambda: read_file(str(self.root / "etc/plain/inner"), 64), Failure.UNSAFE)

    def test_unreadable_file_and_directory(self):
        self.write("etc/locked/file", b"x")
        for target, code in ((self.root / "etc/locked/file", errno.EACCES), (self.root / "etc/locked/file", errno.EPERM)):
            with self.subTest(code=code):
                original = os.open

                def deny(path, flags, *args, **kwargs):
                    if path == "file":
                        raise OSError(code, "моделируемый отказ", str(target))
                    return original(path, flags, *args, **kwargs)

                with patch.object(os, "open", deny):
                    self.assert_failure(lambda: read_file(str(target), 64), Failure.PERMISSION_DENIED)
        if os.geteuid() != 0:
            (self.root / "etc/locked/file").chmod(0)
            self.assert_failure(lambda: read_file(str(self.root / "etc/locked/file"), 64), Failure.PERMISSION_DENIED)
            (self.root / "etc/locked/file").chmod(0o600)
            (self.root / "etc/locked").chmod(0)
            self.assert_failure(lambda: read_file(str(self.root / "etc/locked/file"), 64), Failure.PERMISSION_DENIED)

    def test_io_errors_are_safe(self):
        self.write("etc/file", b"x")
        for name in ("read", "fstat"):
            with self.subTest(call=name), patch.object(os, name, side_effect=OSError(errno.EIO, "сбой", str(self.root))):
                self.assert_failure(lambda: read_file(str(self.root / "etc/file"), 64), Failure.IO_ERROR)
        with patch.object(os, "open", side_effect=OSError(errno.EMFILE, "сбой", str(self.root))):
            self.assert_failure(lambda: read_file(str(self.root / "etc/file"), 64), Failure.IO_ERROR)

    def test_file_changed_or_replaced_while_reading(self):
        self.write("etc/file", b"0123456789")
        original = os.read

        def rewrite(descriptor, size):
            chunk = original(descriptor, size)
            if chunk:
                os.utime(self.root / "etc/file", ns=(1, 1))
            return chunk

        with patch.object(os, "read", rewrite):
            self.assert_failure(lambda: read_file(str(self.root / "etc/file"), 64), Failure.CHANGED)

        def replace(descriptor, size):
            chunk = original(descriptor, size)
            if chunk:
                self.write("etc/next", b"0123456789")
                os.replace(self.root / "etc/next", self.root / "etc/file")
            return chunk

        with patch.object(os, "read", replace):
            self.assert_failure(lambda: read_file(str(self.root / "etc/file"), 64), Failure.CHANGED)

        def remove(descriptor, size):
            chunk = original(descriptor, size)
            if chunk and (self.root / "etc/file").exists():
                (self.root / "etc/file").unlink()
            return chunk

        with patch.object(os, "read", remove):
            self.assert_failure(lambda: read_file(str(self.root / "etc/file"), 64), Failure.CHANGED)

    def test_relative_or_unnormalized_path_is_rejected_without_access(self):
        for path in ("etc/file", "/etc/../file", "//etc/file", "/etc/file/", "/", 7, None):
            with self.subTest(path=path), patch.object(os, "open") as opened:
                self.assert_failure(lambda: read_file(path, 64), Failure.UNSAFE)
                opened.assert_not_called()

    def test_descriptors_are_closed(self):
        self.write("etc/file", b"x")
        opened, closed = [], []
        original_open, original_close = os.open, os.close

        def tracking_open(*args, **kwargs):
            descriptor = original_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        def tracking_close(descriptor):
            closed.append(descriptor)
            return original_close(descriptor)

        with patch.object(os, "open", tracking_open), patch.object(os, "close", tracking_close):
            read_file(str(self.root / "etc/file"), 64)
            self.assert_failure(lambda: read_file(str(self.root / "etc/file"), 0), Failure.TOO_LARGE)
            self.assert_failure(lambda: read_file(str(self.root / "etc/absent"), 0), Failure.MISSING)
        self.assertEqual(sorted(opened), sorted(closed))


class PathReplacedWhileReadingTests(FilesCase):
    """Каталог или его предок, заменённые по исходному пути во время чтения, — отказ `changed`."""

    def replace_during_read(self, call, replace):
        original = os.read
        done = []

        def replacing(descriptor, size):
            chunk = original(descriptor, size)
            if chunk and not done:
                done.append(1)
                replace()
            return chunk

        with patch.object(os, "read", replacing):
            self.assert_failure(call, Failure.CHANGED)
        self.assertEqual(done, [1])

    def swap(self, relative: str, *, link: bool = False, remove: bool = False):
        """Переименовать каталог и положить по исходному пути копию, ссылку на него или ничего."""
        def run():
            path = self.root / relative
            moved = path.with_name(path.name + ".old")
            path.rename(moved)
            if link:
                path.symlink_to(moved)
            elif not remove:
                shutil.copytree(moved, path)
        return run

    def test_single_file_parent_or_ancestor_replaced(self):
        for relative, options in (
            ("etc/xkeen", {}), ("etc", {}), ("etc/xkeen", {"link": True}), ("etc/xkeen", {"remove": True}),
        ):
            with self.subTest(replaced=relative, **options):
                shutil.rmtree(self.root / "etc", ignore_errors=True)
                for leftover in self.root.glob("**/*.old"):
                    if leftover.is_symlink() or leftover.is_file():
                        leftover.unlink()
                    else:
                        shutil.rmtree(leftover)
                self.write("etc/xkeen/xkeen.json", b'{"xkeen": {}}')
                self.replace_during_read(
                    lambda: read_file(str(self.root / "etc/xkeen/xkeen.json"), 64), self.swap(relative, **options),
                )

    def test_config_set_and_geodata_directory_replaced(self):
        self.write("opt/configs/01.json", b"one")
        self.write("opt/configs/02.json", b"two")
        self.replace_during_read(
            lambda: read_files(str(self.root / "opt/configs"), ".json", **LIMITS), self.swap("opt/configs"),
        )
        self.write("opt/dat/geoip.dat", b"geoip-bytes")
        self.replace_during_read(
            lambda: digest_files(str(self.root / "opt/dat"), ".dat", file_limit=64, count_limit=4), self.swap("opt"),
        )

    def test_unchanged_path_is_read_normally(self):
        self.write("etc/xkeen/xkeen.json", b"{}")
        self.assertEqual(read_file(str(self.root / "etc/xkeen/xkeen.json"), 64), b"{}")


class ReadFilesTests(FilesCase):
    def test_reads_matching_regular_files_in_name_order_and_skips_directories(self):
        self.write("configs/02_b.json", b"two")
        self.write("configs/01_a.json", b"one")
        self.write("configs/notes.txt", b"skip")
        (self.root / "configs/sub.json").mkdir()
        self.assertEqual(
            list(read_files(str(self.root / "configs"), ".json", **LIMITS).items()),
            [("01_a.json", b"one"), ("02_b.json", b"two")],
        )
        (self.root / "empty").mkdir()
        self.assertEqual(read_files(str(self.root / "empty"), ".json", **LIMITS), {})

    def test_symlink_or_special_matching_entry_rejects_the_whole_set(self):
        self.write("configs/01_a.json", b"one")
        target = self.write("real.json", b"two")
        (self.root / "configs/02_link.json").symlink_to(target)
        self.assert_failure(lambda: read_files(str(self.root / "configs"), ".json", **LIMITS), Failure.UNSAFE)
        (self.root / "configs/02_link.json").unlink()
        os.mkfifo(self.root / "configs/03_fifo.json")
        self.assert_failure(lambda: read_files(str(self.root / "configs"), ".json", **LIMITS), Failure.UNSAFE)
        (self.root / "configs/03_fifo.json").unlink()
        (self.root / "configs/other").symlink_to(target)
        self.assertEqual(read_files(str(self.root / "configs"), ".json", **LIMITS), {"01_a.json": b"one"})

    def test_limits_on_file_total_and_count(self):
        self.write("configs/01.json", b"x" * 65)
        self.assert_failure(lambda: read_files(str(self.root / "configs"), ".json", **LIMITS), Failure.TOO_LARGE)
        self.write("configs/01.json", b"x" * 64)
        self.write("configs/02.json", b"x" * 64)
        self.assertEqual(len(read_files(str(self.root / "configs"), ".json", **LIMITS)), 2)
        self.write("configs/03.json", b"x")
        self.assert_failure(lambda: read_files(str(self.root / "configs"), ".json", **LIMITS), Failure.TOO_LARGE)
        for index in range(4, 7):
            self.write(f"configs/0{index}.json", b"")
        self.write("configs/01.json", b"")
        self.write("configs/02.json", b"")
        self.assert_failure(lambda: read_files(str(self.root / "configs"), ".json", **LIMITS), Failure.TOO_LARGE)

    def test_set_changed_while_reading(self):
        self.write("configs/01.json", b"one")
        self.write("configs/02.json", b"two")
        original = os.read
        changes = {
            "added": lambda: self.write("configs/03.json", b"three"),
            "removed": lambda: (self.root / "configs/02.json").unlink(),
            "touched": lambda: os.utime(self.root / "configs/02.json", ns=(1, 1)),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                done = []

                def changing(descriptor, size):
                    chunk = original(descriptor, size)
                    if chunk and not done:
                        done.append(1)
                        change()
                    return chunk

                with patch.object(os, "read", changing):
                    self.assert_failure(lambda: read_files(str(self.root / "configs"), ".json", **LIMITS), Failure.CHANGED)
                self.write("configs/02.json", b"two")
                (self.root / "configs/03.json").unlink(missing_ok=True)

    def test_missing_unsafe_and_unlistable_directory(self):
        self.assert_failure(lambda: read_files(str(self.root / "absent"), ".json", **LIMITS), Failure.MISSING)
        (self.root / "real").mkdir()
        (self.root / "link").symlink_to(self.root / "real")
        self.assert_failure(lambda: read_files(str(self.root / "link"), ".json", **LIMITS), Failure.UNSAFE)
        with patch.object(os, "listdir", side_effect=OSError(errno.EIO, "сбой", str(self.root))):
            self.assert_failure(lambda: read_files(str(self.root / "real"), ".json", **LIMITS), Failure.IO_ERROR)
        self.assert_failure(lambda: read_files("relative", ".json", **LIMITS), Failure.UNSAFE)


class DigestFilesTests(FilesCase):
    def test_digests_without_loading_and_respects_limits(self):
        self.write("dat/geoip.dat", b"geoip-bytes")
        self.write("dat/custom.dat", b"")
        self.write("dat/readme", b"skip")
        digests = digest_files(str(self.root / "dat"), ".dat", file_limit=64, count_limit=4)
        self.assertEqual(digests, {
            "custom.dat": (0, hashlib.sha256(b"").hexdigest()),
            "geoip.dat": (11, hashlib.sha256(b"geoip-bytes").hexdigest()),
        })
        self.assert_failure(lambda: digest_files(str(self.root / "dat"), ".dat", file_limit=10, count_limit=4), Failure.TOO_LARGE)
        self.assert_failure(lambda: digest_files(str(self.root / "dat"), ".dat", file_limit=64, count_limit=1), Failure.TOO_LARGE)
        self.assert_failure(lambda: digest_files(str(self.root / "absent"), ".dat", file_limit=64, count_limit=4), Failure.MISSING)

    def test_streams_in_chunks(self):
        self.write("dat/geoip.dat", b"x" * (3 * 1024 * 1024 + 5))
        sizes = []
        original = os.read

        def counting(descriptor, size):
            chunk = original(descriptor, size)
            sizes.append(len(chunk))
            return chunk

        with patch.object(os, "read", counting):
            digests = digest_files(str(self.root / "dat"), ".dat", file_limit=8 * 1024 * 1024, count_limit=4)
        self.assertEqual(digests["geoip.dat"][0], 3 * 1024 * 1024 + 5)
        self.assertLessEqual(max(sizes), 1024 * 1024)


class DigestFileTests(FilesCase):
    def test_digest_of_regular_file_and_empty_file(self):
        path = self.write("etc/init.d/S05xkeen", b"#!/bin/sh\n")
        self.assertEqual(digest_file(str(path), 64), (10, hashlib.sha256(b"#!/bin/sh\n").hexdigest()))
        self.write("etc/empty", b"")
        self.assertEqual(digest_file(str(self.root / "etc/empty"), 0), (0, hashlib.sha256(b"").hexdigest()))

    def test_same_failures_as_reading_the_file(self):
        target = self.write("real/etc/xkeen.json", b"{}")
        (self.root / "link-file").symlink_to(target)
        (self.root / "link-dir").symlink_to(self.root / "real")
        (self.root / "etc/dir").mkdir(parents=True)
        self.write("etc/large", b"x" * 65)
        for relative, failure in (
            ("etc/absent", Failure.MISSING), ("absent/etc/xkeen.json", Failure.MISSING),
            ("link-file", Failure.UNSAFE), ("link-dir/etc/xkeen.json", Failure.UNSAFE), ("etc/dir", Failure.UNSAFE),
            ("etc/large", Failure.TOO_LARGE),
        ):
            with self.subTest(path=relative):
                self.assert_failure(lambda: digest_file(str(self.root / relative), 64), failure)
        self.assert_failure(lambda: digest_file("etc/xkeen.json", 64), Failure.UNSAFE)
        self.assert_failure(lambda: digest_file(str(self.root) + "/etc/../etc/xkeen.json", 64), Failure.UNSAFE)

    def test_file_or_parent_changed_while_hashing(self):
        path = self.write("etc/xkeen/xkeen.json", b"0123456789")
        original = os.read

        def rewrite(descriptor, size):
            chunk = original(descriptor, size)
            if chunk:
                os.utime(path, ns=(1, 1))
            return chunk

        with patch.object(os, "read", rewrite):
            self.assert_failure(lambda: digest_file(str(path), 64), Failure.CHANGED)

        def swap_parent(descriptor, size):
            chunk = original(descriptor, size)
            if chunk and (self.root / "etc/xkeen").exists() and not (self.root / "etc/xkeen.old").exists():
                (self.root / "etc/xkeen").rename(self.root / "etc/xkeen.old")
                shutil.copytree(self.root / "etc/xkeen.old", self.root / "etc/xkeen")
            return chunk

        with patch.object(os, "read", swap_parent):
            self.assert_failure(lambda: digest_file(str(path), 64), Failure.CHANGED)

    def test_streams_in_chunks_without_loading_the_file(self):
        path = self.write("etc/init.d/S05xkeen", b"x" * (2 * 1024 * 1024 + 3))
        sizes = []
        original = os.read

        def counting(descriptor, size):
            chunk = original(descriptor, size)
            sizes.append(len(chunk))
            return chunk

        with patch.object(os, "read", counting):
            size, digest = digest_file(str(path), 4 * 1024 * 1024)
        self.assertEqual((size, digest), (2 * 1024 * 1024 + 3, hashlib.sha256(b"x" * (2 * 1024 * 1024 + 3)).hexdigest()))
        self.assertLessEqual(max(sizes), 1024 * 1024)


class MissingConfirmedTests(FilesCase):
    """Отсутствие в каталоге, заменённом по пути во время чтения, — `changed`, а не `missing` или `False`."""

    def swap_on_open(self, name: str, replace):
        """Подменить каталог по пути непосредственно перед открытием `name` в удерживаемом каталоге."""
        original = os.open
        done = []

        def opening(path, flags, *args, **kwargs):
            if path == name and kwargs.get("dir_fd") is not None and not done:
                done.append(1)
                replace()
            return original(path, flags, *args, **kwargs)

        return patch.object(os, "open", opening), done

    def replace_with(self, relative: str, *files: str):
        """Переименовать каталог и создать по прежнему пути новый с этими файлами."""
        def run():
            path = self.root / relative
            path.rename(path.with_name(path.name + ".old"))
            path.mkdir()
            for name in files:
                self.write(f"{relative}/{name}", b"{}")
        return run

    def swap_on_stat(self, name: str, replace):
        """То же для проверки наличия файла: подмена перед `stat` имени в удерживаемом каталоге."""
        original = os.stat
        done = []

        def stating(path, *args, **kwargs):
            if path == name and kwargs.get("dir_fd") is not None and not done:
                done.append(1)
                replace()
            return original(path, *args, **kwargs)

        return patch.object(os, "stat", stating), done

    def test_file_missing_in_replaced_parent_is_changed(self):
        path = str(self.root / "etc/xkeen/xkeen.json")
        for title, call, swap in (
            ("read_file", lambda: read_file(path, 64), self.swap_on_open),
            ("digest_file", lambda: digest_file(path, 64), self.swap_on_open),
            ("regular_file_exists", lambda: regular_file_exists(path), self.swap_on_stat),
        ):
            with self.subTest(call=title):
                shutil.rmtree(self.root / "etc", ignore_errors=True)
                self.write("etc/xkeen/other", b"x")
                patcher, done = swap("xkeen.json", self.replace_with("etc/xkeen", "xkeen.json"))
                with patcher:
                    self.assert_failure(call, Failure.CHANGED)
                self.assertEqual(done, [1])

    def test_component_missing_in_replaced_ancestor_is_changed(self):
        for title, call in (
            ("read_file", lambda: read_file(str(self.root / "etc/xkeen/xkeen.json"), 64)),
            ("digest_file", lambda: digest_file(str(self.root / "etc/xkeen/xkeen.json"), 64)),
            ("digest_files", lambda: digest_files(str(self.root / "etc/xkeen"), ".json", file_limit=64, count_limit=4)),
            ("read_files", lambda: read_files(str(self.root / "etc/xkeen"), ".json", **LIMITS)),
            ("regular_file_exists", lambda: regular_file_exists(str(self.root / "etc/xkeen/xkeen.json"))),
        ):
            with self.subTest(call=title):
                shutil.rmtree(self.root / "etc", ignore_errors=True)
                shutil.rmtree(self.root / "etc.old", ignore_errors=True)
                (self.root / "etc").mkdir()

                def replace():
                    (self.root / "etc").rename(self.root / "etc.old")
                    self.write("etc/xkeen/xkeen.json", b"{}")

                patcher, done = self.swap_on_open("xkeen", replace)
                with patcher:
                    self.assert_failure(call, Failure.CHANGED)
                self.assertEqual(done, [1])

    def test_genuine_absence_is_still_missing(self):
        self.write("etc/xkeen/other", b"x")
        for relative in ("etc/xkeen/xkeen.json", "etc/absent/xkeen.json", "absent/etc/xkeen.json"):
            with self.subTest(path=relative):
                path = str(self.root / relative)
                self.assert_failure(lambda: read_file(path, 64), Failure.MISSING)
                self.assert_failure(lambda: digest_file(path, 64), Failure.MISSING)
                self.assertFalse(regular_file_exists(path))
        self.assert_failure(
            lambda: digest_files(str(self.root / "etc/absent"), ".json", file_limit=64, count_limit=4), Failure.MISSING,
        )

    def test_walk_confirms_only_missing_components_with_the_held_directory(self):
        self.write("etc/plain", b"x")
        calls = []

        def confirm(path, descriptor):
            calls.append((path, os.path.samestat(os.fstat(descriptor), os.stat(path))))

        def fail(kind):
            raise RouterReadError(Failure.MISSING if kind is PathFailure.MISSING else Failure.UNSAFE)

        for relative, expected in (("etc/absent/inner", "etc"), ("absent", "")):
            with self.subTest(path=relative), self.assertRaises(RouterReadError):
                with walk_directory(str(self.root / relative), fail, confirm_missing=confirm):
                    pass
            self.assertEqual(calls.pop(), (str(self.root / expected).rstrip("/"), True))
        with self.assertRaises(RouterReadError), walk_directory(str(self.root / "etc/plain/x"), fail, confirm_missing=confirm):
            pass
        self.assertEqual(calls, [])
        with self.assertRaises(RouterReadError), walk_directory(str(self.root / "etc/absent"), fail):
            pass


class RegularFileExistsTests(FilesCase):
    def test_regular_file_missing_file_and_missing_directory(self):
        self.write("tmp/.xkeen/ready", b"")
        self.assertTrue(regular_file_exists(str(self.root / "tmp/.xkeen/ready")))
        self.assertFalse(regular_file_exists(str(self.root / "tmp/.xkeen/other")))
        self.assertFalse(regular_file_exists(str(self.root / "tmp/absent/ready")))

    def test_symlink_directory_or_unreadable_parent_is_a_failure(self):
        target = self.write("tmp/real", b"")
        (self.root / "tmp/.xkeen").mkdir()
        (self.root / "tmp/.xkeen/ready").symlink_to(target)
        self.assert_failure(lambda: regular_file_exists(str(self.root / "tmp/.xkeen/ready")), Failure.UNSAFE)
        (self.root / "tmp/.xkeen/ready").unlink()
        (self.root / "tmp/.xkeen/ready").mkdir()
        self.assert_failure(lambda: regular_file_exists(str(self.root / "tmp/.xkeen/ready")), Failure.UNSAFE)
        (self.root / "tmp/link").symlink_to(self.root / "tmp/.xkeen")
        self.assert_failure(lambda: regular_file_exists(str(self.root / "tmp/link/ready")), Failure.UNSAFE)
        original = os.stat

        def deny(path, *args, **kwargs):
            if path == "ready":
                raise PermissionError(errno.EACCES, "отказ", str(self.root))
            return original(path, *args, **kwargs)

        with patch.object(os, "stat", deny):
            self.assert_failure(lambda: regular_file_exists(str(self.root / "tmp/.xkeen/ready")), Failure.PERMISSION_DENIED)
        with patch.object(os, "stat", side_effect=OSError(errno.EIO, "сбой", str(self.root))):
            self.assert_failure(lambda: regular_file_exists(str(self.root / "tmp/.xkeen/ready")), Failure.IO_ERROR)


class WalkDirectoryTests(FilesCase):
    def test_reports_failure_kind_to_the_caller(self):
        (self.root / "dir").mkdir()
        self.write("file", b"")
        (self.root / "link").symlink_to(self.root / "dir")
        seen = []

        def fail(kind):
            seen.append(kind)
            raise LookupError

        for name, kind in (("absent", PathFailure.MISSING), ("file", PathFailure.NOT_DIRECTORY), ("link", PathFailure.SYMLINK)):
            with self.subTest(name=name), self.assertRaises(LookupError):
                with walk_directory(str(self.root / name), fail):
                    pass
            self.assertIs(seen[-1], kind)
        with walk_directory(str(self.root / "dir"), fail) as descriptor:
            self.assertTrue(os.path.samestat(os.fstat(descriptor), os.stat(self.root / "dir")))

    def test_module_does_not_write_or_execute(self):
        source = Path(entware_files.__file__).read_text(encoding="utf-8")
        for forbidden in ("O_WRONLY", "O_RDWR", "O_CREAT", "os.write", "os.replace", "os.unlink", "os.mkdir", "subprocess"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
