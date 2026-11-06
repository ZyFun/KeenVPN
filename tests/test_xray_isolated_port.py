"""Протокол отдельного координатора: только фиксированный Outcome после cleanup/reap."""

from contextlib import ExitStack
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_isolated_port as port
from keenvpn.adapters.xray_linux_native import LinuxAarch64
from keenvpn.adapters.xray_owned_wait import ProcessCleanupFailed, WorkerOwnership, wait_owned
from keenvpn.application.xray_candidate import XrayTestInput, XrayTestOutcome as Outcome


class IsolatedPortTests(unittest.TestCase):
    def setUp(self):
        self.scope = ExitStack()
        self.addCleanup(self.scope.close)
        self.native = self.scope.enter_context(patch.object(port, 'LinuxAarch64'))
        self.scope.enter_context(patch.object(port, 'namespace_identity', return_value=(1, 2)))
        self.candidate = XrayTestInput(parts=(('part.json', b'{}'),), assets=(), categories=())
        self.checked = self.scope.enter_context(patch.object(port, 'checked_port_input', return_value=self.candidate))
        self.scope.enter_context(patch.object(port, 'private_pipe', return_value=(10, 11)))
        self.scope.enter_context(patch.object(port.os, 'set_blocking'))
        self.scope.enter_context(patch.object(port.signal, 'pthread_sigmask', return_value=set()))
        self.scope.enter_context(patch.object(port.select, 'select', return_value=((), (), ())))
        self.clock = self.scope.enter_context(patch.object(port, 'monotonic', return_value=0))
        self.fork = self.scope.enter_context(patch.object(port.os, 'fork', return_value=123))
        self.wait = self.scope.enter_context(patch.object(port.os, 'waitpid', return_value=(123, 0)))
        self.kill = self.scope.enter_context(patch.object(port.os, 'kill'))
        self.close = self.scope.enter_context(patch.object(port.os, 'close'))
        self.read = self.scope.enter_context(patch.object(port.os, 'read'))
        self.response(b'passed\n')

    def response(self, value):
        chunks = iter((value, b''))
        self.read.side_effect = lambda fd, limit: next(chunks, b'')

    def execute(self):
        return port.IsolatedInstalledXray().test(self.candidate)

    def test_success_requires_fixed_report_and_reap_of_exact_worker(self):
        self.assertIs(self.execute(), Outcome.PASSED)
        self.wait.assert_called_once_with(123, port.os.WNOHANG)
        self.kill.assert_not_called()
        self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [10, 11])

    def test_invalid_or_increased_memory_limit_is_rejected_before_native_guard(self):
        for limit in (True, 0, -1, 268435457, 128.0, None):
            self.assertIs(port.IsolatedInstalledXray(memory_limit=limit).test(self.candidate), Outcome.ISOLATION)
        self.native.assert_not_called()
        self.fork.assert_not_called()

    def test_worker_passes_explicit_lower_memory_limit_to_staging(self):
        with patch.object(port, 'PrivateMounts'), \
                patch.object(port, 'close_other_fds'), patch.object(port.signal, 'signal'), \
                patch.object(port.os, 'getppid', return_value=123), \
                patch.object(port.os, 'write', side_effect=lambda fd, value: len(value)), \
                patch.object(port.os, '_exit', side_effect=SystemExit), \
                patch.object(port, 'StagedXrayTest') as staged:
            staged.return_value.test.return_value = Outcome.PASSED
            with self.assertRaises(SystemExit):
                port._worker(self.native(), self.candidate, 30, 11, 123, (4096, 4096), 128 * 1024 * 1024)
            self.assertEqual(staged.call_args.kwargs, {'memory_limit': 128 * 1024 * 1024})

    def test_worker_parent_death_signal_passes_strict_native_prctl_before_mounts(self):
        api = object.__new__(LinuxAarch64)
        api._prctl = Mock(return_value=0)
        api.require_coordinator = Mock()
        with patch.object(port, 'PrivateMounts') as mounts, \
                patch.object(port, 'close_other_fds'), patch.object(port.signal, 'signal'), \
                patch.object(port.os, 'getppid', return_value=123), \
                patch.object(port.os, 'write', side_effect=lambda fd, value: len(value)) as write, \
                patch.object(port.os, '_exit', side_effect=SystemExit), \
                patch.object(port, 'StagedXrayTest') as staged:
            staged.return_value.test.return_value = Outcome.PASSED
            with self.assertRaises(SystemExit):
                port._worker(api, self.candidate, 30, 11, 123, (4096, 4096))
            write.assert_called_once_with(11, b'passed\n')
            mounts.return_value.prepare.assert_called_once()
        api._prctl.assert_called_once_with(1, 9, 0, 0, 0)

    def test_unsupported_native_guard_and_invalid_candidate_prevent_fork(self):
        self.native.side_effect = port.IsolationUnavailable
        self.assertIs(self.execute(), Outcome.ISOLATION)
        self.fork.assert_not_called()
        self.native.side_effect = None
        self.candidate = SimpleNamespace(parts=(), assets=(), categories=())
        self.assertIs(self.execute(), Outcome.CHANGED)
        self.fork.assert_not_called()

    def test_full_validation_never_runs_in_unsupervised_calling_process(self):
        self.assertIs(self.execute(), Outcome.PASSED)
        self.checked.assert_not_called()

    def test_shallow_input_guard_rejects_active_types_and_excessive_count_without_fork(self):
        class ActiveBytes(bytes):
            def __len__(self):
                raise AssertionError('Не вызывать пользовательский len до fork.')
        for parts in ((('part.json', ActiveBytes(b'{}')),), (('part.json', b'{}'),) * 65):
            self.candidate = XrayTestInput(parts, (), ())
            self.assertIs(self.execute(), Outcome.CHANGED)
        self.checked.assert_not_called()
        self.fork.assert_not_called()

    def test_preparation_cap_is_checked_without_parsing_or_fork(self):
        with patch.object(port, 'preparation_sizes', side_effect=port.IsolationUnavailable):
            self.assertIs(self.execute(), Outcome.ISOLATION)
        self.checked.assert_not_called()
        self.fork.assert_not_called()

    def test_full_validation_in_worker_precedes_mounts_and_reports_changed(self):
        self.checked.return_value = None
        with patch.object(port, 'PrivateMounts') as mounts, \
                patch.object(port, 'close_other_fds'), patch.object(port.signal, 'signal'), \
                patch.object(port.os, 'getppid', return_value=123), \
                patch.object(port.os, 'write', side_effect=lambda fd, value: len(value)) as write, \
                patch.object(port.os, '_exit', side_effect=SystemExit), \
                patch.object(port, 'StagedXrayTest') as staged:
            staged.return_value.test.return_value = Outcome.PASSED
            with self.assertRaises(SystemExit):
                port._worker(self.native(), self.candidate, 30, 11, 123, (4096, 4096))
            self.checked.assert_called_once_with(self.candidate)
            mounts.assert_not_called()
            write.assert_called_once_with(11, b'xray_staging_changed\n')

    def test_worker_checks_expired_deadline_after_validation_before_files(self):
        def verified(value):
            self.clock.return_value = 31
            return value
        self.checked.side_effect = verified
        with patch.object(port, 'PrivateMounts') as mounts, \
                patch.object(port, 'close_other_fds'), patch.object(port.signal, 'signal'), \
                patch.object(port.os, 'getppid', return_value=123), \
                patch.object(port.os, 'write', side_effect=lambda fd, value: len(value)) as write, \
                patch.object(port.os, '_exit', side_effect=SystemExit), \
                patch.object(port, 'StagedXrayTest') as staged:
            staged.return_value.test.return_value = Outcome.PASSED
            with self.assertRaises(SystemExit):
                port._worker(self.native(), self.candidate, 30, 11, 123, (4096, 4096))
            mounts.assert_not_called()
            write.assert_called_once_with(11, b'xray_test_timeout\n')

    def test_unknown_truncated_or_oversized_response_never_reaches_result(self):
        for value in (b'private path /secret\n', b'passed', b'passed\npassed\n', b'x' * 128, b'\xff\n'):
            self.response(value)
            self.assertIs(self.execute(), Outcome.CLEANUP)

    def test_worker_signal_exit_does_not_accept_even_well_formed_success(self):
        self.wait.return_value = (123, 9)
        self.assertIs(self.execute(), Outcome.CLEANUP)
        self.kill.assert_not_called()

    def test_cancel_after_terminal_wait_never_signals_released_worker_pid(self):
        def interrupted(owner, flags):
            wait_owned(owner, flags)
            raise KeyboardInterrupt
        with patch.object(port, 'wait_owned', side_effect=interrupted):
            self.assertIs(self.execute(), Outcome.INTERRUPTED)
        self.kill.assert_not_called()

    def test_wait_with_lost_ownership_never_kills_saved_worker_pid(self):
        self.wait.side_effect = ChildProcessError
        self.assertIs(self.execute(), Outcome.CLEANUP)
        self.kill.assert_not_called()

    def test_fork_without_returned_pid_is_unconfirmed_cleanup_not_absent_worker(self):
        self.fork.side_effect = MemoryError
        self.assertIs(self.execute(), Outcome.CLEANUP)
        self.kill.assert_not_called()

    def test_cleanup_report_overrides_timeout(self):
        moments = iter((0, 0, 31, 31, 31))
        self.clock.side_effect = lambda: next(moments, 31)
        self.response(b'xray_cleanup_failed\n')
        self.assertIs(self.execute(), Outcome.CLEANUP)
        self.kill.assert_called_once_with(123, signal.SIGINT)

    def test_pending_second_cancel_waits_for_all_cleanup_and_preserves_failure(self):
        for reported, expected in ((b'xray_cleanup_failed\n', Outcome.CLEANUP),
                                   (b'xray_test_interrupted\n', Outcome.TIMEOUT)):
            with self.subTest(reported=reported):
                self.close.reset_mock()
                self.response(reported)
                state = {'mask': set(), 'pending': False, 'delivered': False}
                def masking(how, values):
                    previous = state['mask']
                    state['mask'] = previous | set(values) if how == signal.SIG_BLOCK else set(values)
                    if state['pending'] and signal.SIGINT not in state['mask']:
                        state['pending'], state['delivered'] = False, True
                        raise KeyboardInterrupt
                    return previous
                def timeout(*args):
                    state['pending'] = True
                    raise TimeoutError
                with patch.object(port.signal, 'pthread_sigmask', side_effect=masking), \
                        patch.object(port, '_wait_worker', side_effect=timeout):
                    self.assertIs(self.execute(), expected)
                self.assertTrue(state['delivered'])
                self.assertEqual(state['mask'], set())
                self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [10, 11])

    def test_confirmed_cleanup_preserves_timeout_reason(self):
        moments = iter((0, 0, 31, 31, 31))
        self.clock.side_effect = lambda: next(moments, 31)
        self.response(b'xray_test_interrupted\n')
        self.assertIs(self.execute(), Outcome.TIMEOUT)

    def test_late_cancel_after_success_closes_fds_before_delivery_and_restores_previous_mask(self):
        state = {'mask': {signal.SIGUSR1}, 'pending': False}
        def masking(how, values):
            previous = state['mask']
            state['mask'] = previous | set(values) if how == signal.SIG_BLOCK else set(values)
            if state['pending'] and signal.SIGINT not in state['mask']:
                state['pending'] = False
                raise KeyboardInterrupt
            return previous
        def closed(fd):
            if fd == 10:
                state['pending'] = True
        self.close.side_effect = closed
        with patch.object(port.signal, 'pthread_sigmask', side_effect=masking):
            self.assertIs(self.execute(), Outcome.INTERRUPTED)
        self.assertEqual(state['mask'], {signal.SIGUSR1})
        self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [10, 11])

    def test_cleanup_helper_exception_still_closes_all_descriptors(self):
        with patch.object(port, '_cleanup_worker', side_effect=OSError):
            self.assertIs(self.execute(), Outcome.CLEANUP)
        self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [10, 11])

    def test_cleanup_never_uses_pid_zero_negative_or_unconfirmed(self):
        for owner in (WorkerOwnership(0), WorkerOwnership(-1), WorkerOwnership(True),
                      WorkerOwnership(123, ownership_lost=True), WorkerOwnership(123, wait_uncertain=True)):
            self.assertFalse(port._cleanup_worker(owner))
        self.kill.assert_not_called()

    def test_forced_worker_kill_remains_cleanup_failure(self):
        owner = WorkerOwnership(123)
        self.wait.return_value = (123, 9)
        self.clock.side_effect = (0, 3, 3, 3.1)
        self.assertFalse(port._cleanup_worker(owner))
        self.assertEqual([call.args for call in self.kill.call_args_list],
                         [(123, signal.SIGINT), (123, signal.SIGKILL)])

    def test_descriptor_close_error_is_not_hidden_by_successful_worker(self):
        self.close.side_effect = (OSError(), None)
        self.assertIs(self.execute(), Outcome.CLEANUP)

    def test_remaining_writer_after_worker_exit_is_not_confirmed_cleanup(self):
        chunks = iter((b'passed\n', BlockingIOError()))
        def read(fd, limit):
            value = next(chunks, BlockingIOError())
            if isinstance(value, BaseException):
                raise value
            return value
        self.read.side_effect = read
        self.assertIs(self.execute(), Outcome.CLEANUP)


if __name__ == '__main__':
    unittest.main()
