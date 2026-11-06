"""Очередность ptrace и cleanup моделируются без fork, сигналов и дочерних процессов."""

import errno
import os
from pathlib import Path
import signal
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_trace_group as tracing
from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, OutputLimitExceeded
from keenvpn.adapters.xray_linux_native import LinuxAarch64, PTRACE_CONT, Registers, SyscallStop
from keenvpn.adapters.xray_memory_budget import MemoryBudgetExceeded, XrayMemoryBudget
from keenvpn.adapters.xray_syscall_policy import GO_CLONE_FLAGS, XraySyscallPolicy


def stopped(sig, event=0):
    return (event << 16) | (sig << 8) | 0x7F


def syscall(number, *args, entering=True, result=0):
    registers = Registers()
    registers.values[0], registers.values[7] = result, 0 if entering else 1
    return SyscallStop(number, args + (0,) * (6 - len(args)), entering, registers)


class TraceGroupTests(unittest.TestCase):
    def setUp(self):
        masks = patch.object(tracing.signal, 'pthread_sigmask', return_value=set())
        masks.start()
        self.addCleanup(masks.stop)
        clock = patch.object(tracing, 'monotonic', return_value=0)
        clock.start()
        self.addCleanup(clock.stop)
        self.reset_group()

    def reset_group(self):
        self.api = Mock()
        self.memory = XrayMemoryBudget(256 * 1024 * 1024, 8 * 1024 * 1024)
        self.memory.set_initial_break(0x10000000)
        self.policy = XraySyscallPolicy(self.memory, 123, 65536, (0x7F800000, 0x80000000))
        self.verify = Mock()
        self.on_exec = Mock(return_value=self.policy)
        self.group = tracing.TraceGroup(self.api, 1000, 65536, self.on_exec, self.verify)
        with patch.object(tracing.os, 'set_blocking'):
            self.group.register(123, 11, 12)

    def boot(self):
        self.group.observe(123, stopped(signal.SIGSTOP))
        self.group.observe(123, stopped(signal.SIGTRAP, 4))
        self.api.resume.reset_mock()

    def call(self, value, tid=123):
        self.api.syscall_stop.return_value = value
        self.group.observe(tid, stopped(signal.SIGTRAP | 0x80))

    def add_thread(self, child, parent=123):
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000), tid=parent)
        self.api.event_child.return_value = child
        self.group.observe(parent, stopped(signal.SIGTRAP, 3))
        self.group.observe(child, stopped(signal.SIGSTOP))
        self.call(syscall(220, entering=False, result=child), tid=parent)
        self.call(syscall(220, entering=False), tid=child)

    def collect_reaped(self):
        # Вывод закрыт ядром; файловые операции в этих тестах не выполняются.
        self.group.streams.clear()
        with patch.object(tracing.os, 'waitpid', side_effect=ChildProcessError):
            return self.group.collect()

    def test_exec_event_is_verified_before_first_user_resume(self):
        self.group.observe(123, stopped(signal.SIGSTOP))
        self.api.resume.assert_called_once_with(123, syscall=False, delivered_signal=0)
        self.api.resume.reset_mock()
        self.on_exec.side_effect = IsolationUnavailable
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(123, stopped(signal.SIGTRAP, 4))
        self.api.resume.assert_not_called()

    def test_native_exec_exit_minus_one_is_accepted_once(self):
        self.boot()
        self.call(syscall(-1, entering=False))
        with self.assertRaises(IsolationUnavailable):
            self.call(syscall(-1, entering=False))

    def test_denial_is_substituted_at_entry_and_verified_at_exit(self):
        self.boot()
        self.call(syscall(198, 2, 1))
        self.assertEqual(self.api.deny_syscall.call_args.args[2], errno.EPERM)
        self.call(syscall(-1, entering=False, result=(1 << 64) - errno.EPERM))
        self.assertIsNone(self.group.threads[123].pending)

    def test_signal_return_accepts_kernel_reset_number_and_restored_nonzero_x0(self):
        self.boot()
        self.call(syscall(139))
        self.call(syscall(-1, entering=False, result=0x12345))
        self.assertIsNone(self.group.threads[123].pending)
        self.call(syscall(63, 3, 0x50000000, 1))
        with self.assertRaises(IsolationUnavailable):
            self.call(syscall(-1, entering=False, result=0x12345))

    def test_missing_skip_or_mismatched_exit_never_resumes(self):
        self.boot()
        self.call(syscall(198, 2, 1))
        self.api.resume.reset_mock()
        with self.assertRaises(IsolationUnavailable):
            self.call(syscall(198, entering=False, result=3))
        self.api.resume.assert_not_called()

    def test_over_budget_entry_never_reaches_kernel(self):
        self.boot()
        with self.assertRaises(MemoryBudgetExceeded):
            self.call(syscall(222, 0, 256 * 1024 * 1024, 3, 0x22))
        self.api.resume.assert_not_called()

    def test_child_stop_before_clone_event_is_held_until_membership_verified(self):
        self.boot()
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.api.resume.reset_mock()
        self.group.observe(124, stopped(signal.SIGSTOP))
        self.api.resume.assert_not_called()
        self.verify.assert_not_called()
        self.api.event_child.return_value = 124
        self.group.observe(123, stopped(signal.SIGTRAP, 3))
        self.verify.assert_called_once_with(124)
        self.assertEqual(self.group.threads[124].phase, 'running')
        self.assertEqual([call.args[0] for call in self.api.resume.call_args_list], [124, 123])
        self.call(syscall(220, entering=False, result=0), tid=124)

    def test_announced_child_is_not_resumed_until_its_own_stop(self):
        self.boot()
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.api.event_child.return_value = 124
        self.group.observe(123, stopped(signal.SIGTRAP, 3))
        self.verify.assert_not_called()
        self.api.resume.reset_mock()
        self.group.observe(124, stopped(signal.SIGSTOP))
        self.verify.assert_called_once_with(124)
        self.api.resume.assert_called_once_with(124, syscall=True, delivered_signal=0)

    def test_reaped_child_before_clone_event_is_never_verified_or_resumed(self):
        self.boot()
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.api.resume.reset_mock()
        self.group.observe(124, 0)
        self.api.event_child.return_value = 124
        self.group.observe(123, stopped(signal.SIGTRAP, 3))
        self.verify.assert_not_called()
        self.api.resume.assert_called_once_with(123, syscall=True, delivered_signal=0)
        self.call(syscall(220, entering=False, result=124))
        self.group.observe(123, 0)
        self.assertEqual(self.collect_reaped().returncode, 0)

    def test_exit_group_accepts_unannounced_terminal_in_either_parent_order(self):
        for early_stop in (False, True):
            for parent_first in (False, True):
                with self.subTest(early_stop=early_stop, parent_first=parent_first):
                    self.reset_group()
                    self.boot()
                    self.add_thread(124)
                    self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000), tid=124)
                    if early_stop:
                        self.group.observe(125, stopped(signal.SIGSTOP))
                    self.call(syscall(94, 0))
                    self.api.resume.reset_mock()
                    self.verify.reset_mock()
                    for tid in ((124, 125) if parent_first else (125, 124)):
                        self.group.observe(tid, 0)
                    self.group.observe(123, 0)
                    self.assertEqual(self.collect_reaped().returncode, 0)
                    self.verify.assert_not_called()
                    self.api.resume.assert_not_called()

    def test_unannounced_stop_after_parent_terminal_stays_held_until_death(self):
        self.boot()
        self.add_thread(124)
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000), tid=124)
        self.group.observe(124, 0)
        self.api.resume.reset_mock()
        self.verify.reset_mock()
        self.group.observe(125, stopped(signal.SIGSTOP))
        self.group.observe(125, signal.SIGKILL)
        self.group.observe(123, 0)
        self.assertEqual(self.collect_reaped().returncode, 0)
        self.verify.assert_not_called()
        self.api.resume.assert_not_called()

    def test_unknown_terminal_without_unannounced_clone_is_rejected(self):
        self.boot()
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(124, 0)
        self.api.resume.assert_not_called()

    def test_announced_clone_does_not_allow_second_unknown_child(self):
        self.boot()
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.api.event_child.return_value = 124
        self.group.observe(123, stopped(signal.SIGTRAP, 3))
        self.api.resume.reset_mock()
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(125, 0)
        self.api.resume.assert_not_called()

    def test_one_pending_clone_cannot_account_for_two_early_children(self):
        self.boot()
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.group.observe(124, stopped(signal.SIGSTOP))
        self.api.resume.reset_mock()
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(125, 0)
        self.api.resume.assert_not_called()

    def test_failed_clone_does_not_leave_permission_for_unknown_terminal(self):
        self.boot()
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.call(syscall(220, entering=False, result=(1 << 64) - errno.EAGAIN))
        self.api.resume.reset_mock()
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(124, 0)
        self.api.resume.assert_not_called()

    def test_repeated_terminal_does_not_consume_another_pending_clone(self):
        self.boot()
        self.add_thread(124)
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000), tid=124)
        self.group.observe(125, 0)
        self.api.resume.reset_mock()
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(125, 0)
        self.api.resume.assert_not_called()

    def test_reaped_children_do_not_refund_lifetime_thread_budget(self):
        self.boot()
        for child in range(124, 124 + 63):
            self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
            self.group.observe(child, 0)
            self.api.event_child.return_value = child
            self.group.observe(123, stopped(signal.SIGTRAP, 3))
            self.call(syscall(220, entering=False, result=child))
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.assertEqual(self.api.deny_syscall.call_args.args[2], errno.EAGAIN)
        self.verify.assert_not_called()
        self.api.resume.reset_mock()
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(200, 0)
        self.api.resume.assert_not_called()

    def test_parallel_clone_events_match_reaped_and_held_children_independently(self):
        self.boot()
        self.add_thread(124)
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000), tid=124)
        self.group.observe(125, 0)
        self.group.observe(126, stopped(signal.SIGSTOP))
        self.api.resume.reset_mock()
        self.verify.reset_mock()
        self.api.event_child.return_value = 126
        self.group.observe(123, stopped(signal.SIGTRAP, 3))
        self.api.event_child.return_value = 125
        self.group.observe(124, stopped(signal.SIGTRAP, 3))
        self.verify.assert_called_once_with(126)
        self.assertEqual([call.args[0] for call in self.api.resume.call_args_list], [126, 123, 124])
        self.call(syscall(220, entering=False, result=126))
        self.call(syscall(220, entering=False, result=125), tid=124)
        for tid in (123, 124, 126):
            self.group.observe(tid, 0)
        self.assertEqual(self.collect_reaped().returncode, 0)

    def test_clone_resolution_cannot_leave_early_child_without_a_reservation(self):
        for reported_child in (None, 125):
            with self.subTest(reported_child=reported_child):
                self.reset_group()
                self.boot()
                self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
                self.group.observe(124, stopped(signal.SIGSTOP))
                self.api.resume.reset_mock()
                with self.assertRaises(IsolationUnavailable):
                    if reported_child is None:
                        self.call(syscall(220, entering=False, result=(1 << 64) - errno.EAGAIN))
                    else:
                        self.api.event_child.return_value = reported_child
                        self.group.observe(123, stopped(signal.SIGTRAP, 3))
                self.verify.assert_not_called()
                self.api.resume.assert_not_called()

    def test_duplicate_clone_event_never_uses_another_parents_reservation(self):
        self.boot()
        self.add_thread(124)
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
        self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000), tid=124)
        self.api.event_child.return_value = 125
        self.group.observe(123, stopped(signal.SIGTRAP, 3))
        self.api.event_child.return_value = 126
        self.api.resume.reset_mock()
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(123, stopped(signal.SIGTRAP, 3))
        self.api.resume.assert_not_called()

    def test_clone_exit_requires_matching_event_or_kernel_error(self):
        for announced, result in ((None, 124), (124, 125), (124, (1 << 64) - errno.EAGAIN)):
            with self.subTest(announced=announced, result=result):
                self.reset_group()
                self.boot()
                self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
                if announced is not None:
                    self.api.event_child.return_value = announced
                    self.group.observe(123, stopped(signal.SIGTRAP, 3))
                self.api.resume.reset_mock()
                with self.assertRaises(IsolationUnavailable):
                    self.call(syscall(220, entering=False, result=result))
                self.api.resume.assert_not_called()

    def test_reused_reaped_tid_never_receives_verification_or_resume(self):
        for via_event in (False, True):
            with self.subTest(via_event=via_event):
                self.reset_group()
                self.boot()
                self.add_thread(124)
                self.group.observe(124, 0)
                self.call(syscall(220, GO_CLONE_FLAGS, 0x50000000))
                self.api.resume.reset_mock()
                self.verify.reset_mock()
                with self.assertRaises(IsolationUnavailable):
                    if via_event:
                        self.api.event_child.return_value = 124
                        self.group.observe(123, stopped(signal.SIGTRAP, 3))
                    else:
                        self.group.observe(124, stopped(signal.SIGSTOP))
                self.verify.assert_not_called()
                self.api.resume.assert_not_called()

    def test_unexpected_child_or_second_exec_is_not_resumed(self):
        self.boot()
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(999, stopped(signal.SIGSTOP))
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(123, stopped(signal.SIGTRAP, 4))
        self.api.resume.assert_not_called()

    def test_early_terminal_wait_is_recorded_before_bootstrap_failure(self):
        with self.assertRaises(IsolationUnavailable):
            self.group.observe(123, 125 << 8)
        self.assertTrue(self.group.leader_reaped)
        with patch.object(tracing.os, 'kill') as kill, \
                patch.object(tracing.os, 'waitpid', side_effect=ChildProcessError), \
                patch.object(tracing.signal, 'pthread_sigmask', return_value=set()):
            self.group.terminate_and_wait()
            kill.assert_not_called()
        self.assertTrue(self.group.all_reaped)

    def test_echild_before_terminal_wait_loses_ownership_and_prevents_pid_reuse_kill(self):
        with patch.object(tracing.os, 'waitpid', side_effect=ChildProcessError):
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group._poll()
        with patch.object(tracing.os, 'kill') as kill:
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group.terminate_and_wait()
            kill.assert_not_called()

    def test_cancellation_after_consuming_terminal_wait_never_kills_reused_pid(self):
        with patch.object(tracing.os, 'waitpid', return_value=(123, 0)), \
                patch.object(self.group, 'observe', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.group._poll()
        self.assertTrue(self.group.leader_reaped)
        with patch.object(tracing.os, 'waitpid', side_effect=ChildProcessError), \
                patch.object(tracing.os, 'kill') as kill:
            self.group.terminate_and_wait()
            kill.assert_not_called()
        self.assertTrue(self.group.all_reaped)

    def test_wait_exception_without_result_forbids_any_saved_pid_signal(self):
        with patch.object(tracing.os, 'waitpid', side_effect=KeyboardInterrupt):
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group._poll()
        self.assertTrue(self.group.ownership_lost)
        with patch.object(tracing.os, 'kill') as kill:
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group.terminate_and_wait()
            kill.assert_not_called()

    def test_unconfirmed_fork_without_known_pid_is_not_confirmed_cleanup(self):
        self.group.leader = None
        self.group.ownership_lost = True
        with patch.object(tracing.os, 'kill') as kill:
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group.terminate_and_wait()
            kill.assert_not_called()

    def test_pending_interrupt_on_signal_unblock_sees_terminal_pid_already_recorded(self):
        def mask(how, values):
            if how == signal.SIG_SETMASK:
                raise KeyboardInterrupt
            return set()
        with patch.object(tracing.os, 'waitpid', return_value=(123, 0)), \
                patch.object(tracing.signal, 'pthread_sigmask', side_effect=mask):
            with self.assertRaises(KeyboardInterrupt):
                self.group._poll()
        self.assertTrue(self.group.leader_reaped)
        self.assertFalse(self.group.wait_uncertain)

    def test_echild_followed_by_pending_interrupt_records_lost_ownership_before_unblock(self):
        def mask(how, values):
            if how == signal.SIG_SETMASK:
                raise KeyboardInterrupt
            return set()
        with patch.object(tracing.os, 'waitpid', side_effect=ChildProcessError), \
                patch.object(tracing.signal, 'pthread_sigmask', side_effect=mask):
            with self.assertRaises(KeyboardInterrupt):
                self.group._poll()
        self.assertTrue(self.group.ownership_lost)
        with patch.object(tracing.os, 'kill') as kill:
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group.terminate_and_wait()
            kill.assert_not_called()

    def test_deadline_is_rechecked_immediately_before_each_resume(self):
        with patch.object(tracing, 'monotonic', return_value=1000):
            with self.assertRaises(TimeoutError):
                self.group._resume(123)
        self.api.resume.assert_not_called()

    def test_cleanup_reaps_even_child_whose_clone_event_was_not_collected(self):
        events = [(124, stopped(signal.SIGSTOP)), (124, 9), (123, 9), ChildProcessError()]
        with patch.object(tracing.os, 'waitpid', side_effect=events), \
                patch.object(tracing.os, 'kill') as kill, \
                patch.object(tracing.signal, 'pthread_sigmask', return_value=set()):
            self.group.terminate_and_wait()
            kill.assert_called_once_with(123, signal.SIGKILL)
        self.api.resume.assert_called_once_with(124, syscall=False, delivered_signal=signal.SIGKILL)
        self.assertTrue(self.group.all_reaped)

    def test_cleanup_timeout_never_claims_success(self):
        with patch.object(tracing.os, 'waitpid', return_value=(0, 0)), \
                patch.object(tracing.os, 'kill'), \
                patch.object(tracing.signal, 'pthread_sigmask', return_value=set()), \
                patch.object(tracing, 'monotonic', side_effect=(0, 3)):
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group.terminate_and_wait()
        self.assertFalse(self.group.all_reaped)

    def test_cleanup_kill_passes_strict_native_resume_for_unannounced_stopped_thread(self):
        native = object.__new__(LinuxAarch64)
        native._ptrace = Mock(return_value=0)
        self.group.native = native
        events = ((124, stopped(signal.SIGSTOP)), (123, 0), (124, 0), ChildProcessError())
        with patch.object(tracing.os, 'waitpid', side_effect=events), \
                patch.object(tracing.os, 'kill') as kill:
            self.group.terminate_and_wait()
            kill.assert_called_once_with(123, signal.SIGKILL)
        self.assertTrue(self.group.all_reaped)
        native._ptrace.assert_called_once()
        request, tid, address, data = native._ptrace.call_args.args
        self.assertEqual((request, tid, address.value, data.value), (PTRACE_CONT, 124, None, 9))

    def test_output_is_bounded_in_total_and_never_exposed_by_group_repr(self):
        self.group._stdout.extend(b'x' * 65536)
        with patch.object(tracing.os, 'read', return_value=b'!'):
            with self.assertRaises(OutputLimitExceeded):
                self.group._drain()
        self.assertNotIn('xxx', repr(self.group))

    def test_close_failure_does_not_skip_other_fd_and_is_not_retried(self):
        with patch.object(tracing.os, 'close', side_effect=(OSError(), None)) as close:
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group.close_streams()
            self.assertEqual([call.args[0] for call in close.call_args_list], [11, 12])
            with self.assertRaises(tracing.ProcessCleanupFailed):
                self.group.close_streams()
            self.assertEqual(close.call_count, 2)


if __name__ == '__main__':
    unittest.main()
