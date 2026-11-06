"""Проверки запретов до исполнения syscall и общих бюджетов потоков."""

import errno
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, OutputLimitExceeded
from keenvpn.adapters.xray_memory_budget import MemoryBudgetExceeded, XrayMemoryBudget
from keenvpn.adapters.xray_syscall_policy import (
    AT_FDCWD, GO_CLONE_FLAGS, MAX_THREADS, XraySyscallPolicy,
)


class SyscallPolicyTests(unittest.TestCase):
    def setUp(self):
        self.memory = XrayMemoryBudget(256 * 1024 * 1024, 8 * 1024 * 1024)
        self.memory.set_initial_break(0x10000000)
        self.policy = XraySyscallPolicy(self.memory, 123, 65536, (0x7F800000, 0x80000000))

    def before(self, number, *args):
        return self.policy.before(number, args + (0,) * (6 - len(args)), frozenset((123, 124)))

    def test_socket_exec_namespaces_foreign_memory_and_unaccounted_mapping_are_closed(self):
        for number in (40, 51, 97, 117, 198, 199, 200, 201, 202, 203, 211, 212,
                       216, 219, 221, 270, 271, 281, 282, 435):
            with self.subTest(number=number):
                self.assertNotEqual(self.before(number).error_number, 0)

    def test_unclassified_api_stops_job_instead_of_losing_file_denial(self):
        for number in (425, 437, 999, -1):
            with self.assertRaises(IsolationUnavailable):
                self.before(number)

    def test_uname_query_does_not_abort_job_or_enable_host_identity_changes(self):
        before = self.memory.used
        args = (0x50000000, 0, 0, 0, 0, 0)
        decision = self.before(160, *args)
        self.assertEqual(decision.error_number, 0)
        self.assertFalse(decision.clone)
        for result in (0, (1 << 64) - errno.EFAULT):
            self.policy.after(160, args, result, decision)
        self.assertEqual(self.memory.used, before)
        self.assertEqual(self.policy.output_reserved, 0)
        self.assertFalse(self.policy.file_access_denied)
        # Соседние sethostname/setdomainname не становятся разрешёнными.
        for number in (161, 162):
            with self.assertRaises(IsolationUnavailable):
                self.before(number, 0x50000000, 16)

    def test_vector_io_and_handle_based_access_are_observed_file_denials(self):
        for number in (65, 66, 68, 69, 70, 264, 265, 285, 286, 287):
            with self.subTest(number=number):
                self.policy.file_access_denied = False
                self.assertEqual(self.before(number, 3).error_number, errno.EACCES)
                self.assertTrue(self.policy.file_access_denied)

    def test_all_clone_variants_except_exact_go_threads_are_denied(self):
        for flags in (0, 17, GO_CLONE_FLAGS & ~0x100, GO_CLONE_FLAGS & ~0x10000,
                      GO_CLONE_FLAGS | 0x800000, GO_CLONE_FLAGS | 17,
                      GO_CLONE_FLAGS | (1 << 32)):
            self.assertNotEqual(self.before(220, flags, 0x50000000).error_number, 0)
        self.assertEqual(self.policy.threads_reserved, 1)
        decision = self.before(220, GO_CLONE_FLAGS, 0x50000000)
        self.assertTrue(decision.clone)
        self.assertEqual(decision.error_number, 0)

    def test_thread_budget_counts_failed_and_outstanding_requests(self):
        for _ in range(MAX_THREADS - 1):
            self.assertTrue(self.before(220, GO_CLONE_FLAGS, 0x50000000).clone)
        self.assertEqual(self.before(220, GO_CLONE_FLAGS, 0x50000000).error_number, errno.EAGAIN)

    def test_readonly_open_accepts_both_at_fdcwd_encodings(self):
        for fd in (*AT_FDCWD, 0, 3):
            self.assertEqual(self.before(56, fd, 0x12345678, 0x80000).error_number, 0)
        self.assertFalse(self.policy.file_access_denied)

    def test_open_for_write_or_create_sets_observer_without_executing(self):
        for flags in (1, 2, 0x40, 0x200, 0x410000, 1 << 32):
            self.assertEqual(self.before(56, AT_FDCWD[0], 0x12345678, flags).error_number, errno.EACCES)
            self.assertTrue(self.policy.file_access_denied)

    def test_aarch64_directory_and_largefile_flags_do_not_enable_direct_io(self):
        for flags in (0x4000, 0x8000, 0x20000, 0xAC800):
            self.assertEqual(self.before(56, AT_FDCWD[0], 0x12345678, flags).error_number, 0)
        self.assertFalse(self.policy.file_access_denied)
        self.assertEqual(self.before(56, AT_FDCWD[0], 0x12345678, 0x10000).error_number, errno.EACCES)
        self.assertTrue(self.policy.file_access_denied)

    def test_go_nonblock_preserves_kernel_largefile_and_access_mode_bits(self):
        for fd, previous in ((3, 0x20000), (4, 0x2C000), (1, 1), (5, 2)):
            self.assertEqual(self.before(25, fd, 3).error_number, 0)  # F_GETFL.
            for flags in (previous | 0x800, previous):
                self.assertEqual(self.before(25, fd, 4, flags).error_number, 0)
        self.assertFalse(self.policy.file_access_denied)

    def test_fcntl_cannot_enable_async_append_direct_or_noatime(self):
        for flag in (0x400, 0x2000, 0x10000, 0x40000, 1 << 32):
            self.policy.file_access_denied = False
            self.assertEqual(self.before(25, 3, 4, 0x20800 | flag).error_number, errno.EACCES)
            self.assertTrue(self.policy.file_access_denied)

    def test_descriptors_one_and_two_cannot_be_closed_or_aliased(self):
        for value in (1, 2, 0x100000001, 0x100000002):
            self.policy.file_access_denied = False
            self.assertNotEqual(self.before(57, value).error_number, 0)
            self.assertTrue(self.policy.file_access_denied)
        self.assertNotEqual(self.before(64, 0x100000001, 0, 65537).error_number, 0)
        for number, args in ((23, (3,)), (24, (3, 1)), (25, (3, 0, 1)), (25, (3, 1030, 1))):
            self.assertNotEqual(self.before(number, *args).error_number, 0)

    def test_output_budget_is_shared_and_reserved_before_partial_or_failed_writes(self):
        self.before(64, 1, 0, 32768)
        self.before(64, 2, 0, 32768)
        with self.assertRaises(OutputLimitExceeded):
            self.before(64, 1, 0, 1)
        self.assertEqual(self.policy.output_reserved, 65536)

    def test_private_eventfd_write_does_not_consume_output_budget(self):
        self.assertEqual(self.before(19, 0, 0x80800).error_number, 0)
        self.assertEqual(self.before(64, 3, 0x50000000, 8).error_number, 0)
        self.assertEqual(self.policy.output_reserved, 0)

    def test_memory_growth_is_reserved_before_any_kernel_result(self):
        self.before(222, 0, 16 * 1024 * 1024, 3, 0x22)
        self.before(226, 0x50000000, 16 * 1024 * 1024, 1)
        self.before(215, 0x50000000, 16 * 1024 * 1024)
        self.assertEqual(self.memory.used, 40 * 1024 * 1024)
        with self.assertRaises(MemoryBudgetExceeded):
            self.before(222, 0, 256 * 1024 * 1024, 3, 0x22)

    def test_reservations_without_access_and_new_execute_permissions(self):
        self.assertEqual(self.before(222, 0, 613548032, 0, 0x22).error_number, 0)
        self.assertEqual(self.memory.used, 8 * 1024 * 1024)
        self.assertNotEqual(self.before(222, 0, 4096, 5, 0x22).error_number, 0)
        with self.assertRaises(IsolationUnavailable):
            self.before(226, 0x50000000, 4096, 5)

    def test_initial_growable_stack_cannot_be_split_or_replaced(self):
        for address in (0x7F800000, 0x7FFFF000):
            self.assertNotEqual(self.before(222, address, 4096, 0, 0x32).error_number, 0)
            for number, args in ((226, (address, 4096, 0)), (215, (address, 4096))):
                with self.assertRaises(IsolationUnavailable):
                    self.before(number, *args)
        for address in (0x7F7FF000, 0xFFFFFFFFFFFFF000):
            with self.assertRaises(IsolationUnavailable):
                self.before(215, address, 8192)
        self.assertEqual(self.before(215, 0x7F7FF000, 4096).error_number, 0)

    def test_limit_changes_and_signals_to_other_processes_are_denied(self):
        self.assertEqual(self.before(261, 0, 9, 0, 0x50000000).error_number, 0)
        self.assertNotEqual(self.before(261, 0, 9, 0x50000000, 0).error_number, 0)
        self.assertNotEqual(self.before(261, 456, 9, 0, 0x50000000).error_number, 0)
        self.assertEqual(self.before(131, 123, 124, 23).error_number, 0)
        for args in ((123, 456, 9), (456, 124, 9), (123, 124, (1 << 32) + 9)):
            self.assertNotEqual(self.before(131, *args).error_number, 0)
        self.assertNotEqual(self.before(129, (1 << 64) - 1, 9).error_number, 0)

    def test_file_denial_comes_from_policy_or_kernel_errno(self):
        args = (AT_FDCWD[0], 0x50000000, 0, 0, 0, 0)
        decision = self.before(56, *args)
        self.policy.after(56, args, (1 << 64) - errno.EACCES, decision)
        self.assertTrue(self.policy.file_access_denied)

    def test_missing_optional_path_is_not_permission_denial(self):
        args = (AT_FDCWD[0], 0x50000000, 0, 0, 0, 0)
        decision = self.before(56, *args)
        self.policy.after(56, args, (1 << 64) - errno.ENOENT, decision)
        self.assertFalse(self.policy.file_access_denied)

    def test_file_backed_mapping_denial_is_observed_before_and_after_kernel(self):
        self.assertEqual(self.before(222, 0, 4096, 5, 2, 3).error_number, errno.EACCES)
        self.assertTrue(self.policy.file_access_denied)
        self.policy.file_access_denied = False
        args = (0, 4096, 1, 2, 1, 0)
        decision = self.before(222, *args)
        self.policy.after(222, args, (1 << 64) - errno.EACCES, decision)
        self.assertTrue(self.policy.file_access_denied)

    def test_unclassified_protection_denial_stops_job(self):
        args = (0x50000000, 4096, 1, 0, 0, 0)
        decision = self.before(226, *args)
        with self.assertRaises(IsolationUnavailable):
            self.policy.after(226, args, (1 << 64) - errno.EACCES, decision)

    def test_invalid_register_snapshot_is_rejected(self):
        for args in ((0,), (False,) * 6, (-1,) * 6, ((1 << 64),) * 6):
            with self.assertRaises(IsolationUnavailable):
                self.policy.before(56, args, frozenset((123,)))


if __name__ == '__main__':
    unittest.main()
