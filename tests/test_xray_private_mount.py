"""Порядок mount-подготовки и освобождение на двойниках без mount/записи на роутер."""

import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_private_mount as mounts
from keenvpn.adapters.xray_candidate_test import IsolationUnavailable


def info(inode, device=1, mode=0o700):
    return os.stat_result((stat.S_IFDIR | mode, inode, device, 1, 0, 0, 0, 0, 0, 0))


class PrivateMountTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock()
        self.api.prctl.return_value = 0
        self.workspace = mounts.PrivateMounts(self.api, 1024 * 1024, 4 * 1024 * 1024)

    def test_no_mount_or_files_before_distinct_namespace_is_confirmed(self):
        with patch.object(mounts.os, 'lstat', return_value=info(1)), \
                patch.object(mounts.os, 'chdir'), \
                patch.object(mounts, 'namespace_identity', return_value=(1, 1)), \
                patch.object(mounts.os, 'mkdir') as mkdir:
            with self.assertRaises(IsolationUnavailable):
                self.workspace.prepare()
            self.api.mount.assert_not_called()
            mkdir.assert_not_called()

    def test_shared_propagation_prevents_tmpfs_and_file_creation(self):
        with patch.object(mounts.os, 'lstat', return_value=info(1)), \
                patch.object(mounts.os, 'chdir'), \
                patch.object(mounts, 'namespace_identity', side_effect=((1, 1), (1, 2))), \
                patch.object(mounts, '_mount_rows', return_value=[('1:1', '/', ('shared:1',), 'rootfs')]), \
                patch.object(mounts.os, 'mkdir') as mkdir:
            with self.assertRaises(IsolationUnavailable):
                self.workspace.prepare()
            self.assertEqual(self.api.mount.call_count, 1)
            mkdir.assert_not_called()

    def test_failed_post_mount_verification_still_requires_unmount(self):
        with patch.object(mounts.os, 'lstat', return_value=info(1)), \
                patch.object(mounts.os, 'chdir'), \
                patch.object(mounts, 'namespace_identity', side_effect=((1, 1), (1, 2))), \
                patch.object(mounts, '_mount_rows', return_value=[('1:1', '/', (), 'rootfs')]), \
                patch.object(mounts, '_verify_tmpfs', side_effect=IsolationUnavailable):
            with self.assertRaises(IsolationUnavailable):
                self.workspace.prepare()
            self.workspace.close()
        self.api.unmount.assert_called_once_with(b'/tmp')

    def test_busy_cage_is_cleanup_failure_and_is_not_hidden_by_detach(self):
        self.workspace._cage_mounted = True
        self.api.unmount.side_effect = IsolationUnavailable
        with self.assertRaises(mounts.MountCleanupFailed):
            self.workspace.close()
        self.assertTrue(self.workspace._cage_mounted)
        self.api.unmount.assert_called_once_with(b'/tmp/cage')

    def test_readonly_remount_requires_observed_readonly_flag(self):
        self.workspace._cage_mounted = True
        with patch.object(mounts.os, 'statvfs', return_value=SimpleNamespace(f_flag=0)):
            with self.assertRaises(IsolationUnavailable):
                self.workspace.seal_cage()

    def test_staging_owner_requires_namespace_nondumpable_and_same_inode(self):
        self.workspace.stage = info(1, 5)
        self.workspace.namespace = (1, 2)
        self.workspace._stage_mounted = True
        with patch.object(mounts, 'namespace_identity', return_value=(1, 2)), \
                patch.object(mounts.os, 'fstat', return_value=info(1, 5)):
            self.assertTrue(self.workspace.owns_staging(9))
            self.api.prctl.return_value = 1
            self.assertFalse(self.workspace.owns_staging(9))

    def test_preparation_budget_covers_both_copies_and_binary(self):
        stage, cage = mounts.preparation_sizes((1, 4097), 10000)
        self.assertEqual(stage, 12288 + mounts.DIRECTORY_RESERVE)
        self.assertEqual(cage - stage, 12288)
        with self.assertRaises(IsolationUnavailable):
            mounts.preparation_sizes((128 * 1024 * 1024,), 10000)

    def test_private_tmpfs_can_cover_existing_mount_at_same_path(self):
        original, current = info(1, 1), info(2, 2)
        old_device = f'{os.major(original.st_dev)}:{os.minor(original.st_dev)}'
        new_device = f'{os.major(current.st_dev)}:{os.minor(current.st_dev)}'
        rows = [(old_device, '/tmp', (), 'tmpfs'), (new_device, '/tmp', (), 'tmpfs')]
        with patch.object(mounts.os, 'lstat', return_value=current), \
                patch.object(mounts, '_mount_rows', return_value=rows):
            self.assertIs(mounts._verify_tmpfs('/tmp', original), current)

    def test_mount_verification_requires_exact_current_device_and_new_filesystem(self):
        original, current = info(1, 1), info(2, 2)
        device = f'{os.major(current.st_dev)}:{os.minor(current.st_dev)}'
        for rows in ([(device, '/other', (), 'tmpfs')], [(device, '/tmp', (), 'ext4')],
                     [('9:9', '/tmp', (), 'tmpfs')], [(device, '/tmp', (), 'tmpfs')] * 2):
            with patch.object(mounts.os, 'lstat', return_value=current), \
                    patch.object(mounts, '_mount_rows', return_value=rows), self.assertRaises(IsolationUnavailable):
                mounts._verify_tmpfs('/tmp', original)
        unchanged_device = info(3, 1)
        device = f'{os.major(unchanged_device.st_dev)}:{os.minor(unchanged_device.st_dev)}'
        with patch.object(mounts.os, 'lstat', return_value=unchanged_device), \
                patch.object(mounts, '_mount_rows', return_value=[(device, '/tmp', (), 'tmpfs')]), \
                self.assertRaises(IsolationUnavailable):
            mounts._verify_tmpfs('/tmp', original)


if __name__ == '__main__':
    unittest.main()
