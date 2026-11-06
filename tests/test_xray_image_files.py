"""Копирование проверяет байты, а не pathname/версию из вывода программы."""

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from time import monotonic
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_image_files as files
from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, XrayTestFile, XrayTestInvocation


class ImageFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.write_bytes(b'synthetic input\n')
        self.fd = os.open(self.source, os.O_RDWR)
        self.addCleanup(os.close, self.fd)
        self.data = self.source.read_bytes()
        self.digest = hashlib.sha256(self.data).digest()

    def copy(self, **changes):
        arguments = dict(source=self.fd, destination=str(self.root / 'copied'), size=len(self.data),
                         digest=self.digest, mode=0o444, deadline=monotonic() + 2)
        arguments.update(changes)
        files.copy_verified(**arguments)

    def test_copy_preserves_source_offset_mode_and_bytes(self):
        mode = stat.S_IMODE(os.fstat(self.fd).st_mode)
        os.lseek(self.fd, 3, os.SEEK_SET)
        self.copy()
        self.assertEqual(os.lseek(self.fd, 0, os.SEEK_CUR), 3)
        self.assertEqual(stat.S_IMODE(os.fstat(self.fd).st_mode), mode)
        self.assertEqual((self.root / 'copied').read_bytes(), self.data)
        self.assertEqual(stat.S_IMODE((self.root / 'copied').stat().st_mode), 0o444)

    def test_wrong_digest_and_size_never_produce_trusted_copy(self):
        with self.assertRaises(IsolationUnavailable):
            self.copy(digest=b'x' * 32)
        with self.assertRaises(IsolationUnavailable):
            self.copy(size=len(self.data) + 1)

    def test_existing_file_or_symlink_is_not_overwritten(self):
        destination = self.root / 'copied'
        destination.symlink_to(self.source)
        with self.assertRaises(FileExistsError):
            self.copy()
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_partial_writes_complete_but_zero_write_fails(self):
        real_write = os.write
        with patch.object(files.os, 'write', side_effect=lambda fd, data: real_write(fd, data[:2])):
            self.copy()
        self.assertEqual((self.root / 'copied').read_bytes(), self.data)
        (self.root / 'copied').unlink()
        with patch.object(files.os, 'write', return_value=0):
            with self.assertRaises(IsolationUnavailable):
                self.copy()

    def test_source_replacement_does_not_switch_pinned_descriptor(self):
        new = self.root / 'replacement'
        new.write_bytes(b'unrelated')
        new.replace(self.source)
        self.copy()
        self.assertEqual((self.root / 'copied').read_bytes(), self.data)

    def test_source_mutation_during_copy_is_rejected(self):
        real_write = os.write
        def changed(fd, data):
            os.pwrite(self.fd, b'!', 0)
            return real_write(fd, data)
        with patch.object(files.os, 'write', side_effect=changed):
            with self.assertRaises(IsolationUnavailable):
                self.copy()

    def test_expired_deadline_does_not_copy_data(self):
        with self.assertRaises(TimeoutError):
            self.copy(deadline=monotonic() - 1)

    def test_cage_directories_remain_traversable_after_inherited_umask_077(self):
        previous = os.umask(0o077)
        try:
            for name in ('parts', 'assets'):
                destination = self.root / name
                files._readable_directory(str(destination))
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
        finally:
            os.umask(previous)

    def request(self):
        item = XrayTestFile('parts/000.json', self.fd, len(self.data), self.digest)
        return XrayTestInvocation('a' * 32, (item,),
                                  (files.XRAY_BINARY, 'run', '-test', '-format', 'json', '-c', item.name),
                                  (), monotonic() + 30)

    def test_invocation_rejects_paths_duplicates_alternate_argv_and_environment(self):
        request = self.request()
        files.verify_invocation(request)
        for bad in (replace(request, files=(replace(request.files[0], name='parts/../../outside'),)),
                    replace(request, files=request.files * 2),
                    replace(request, argv=('/bin/sh',)), replace(request, environment=(('HOME', '/'),)),
                    replace(request, memory_limit=256 * 1024 * 1024 + 1),
                    replace(request, deadline=float('nan')), replace(request, deadline=float('inf'))):
            with self.assertRaises(IsolationUnavailable):
                files.verify_invocation(bad)


if __name__ == '__main__':
    unittest.main()
