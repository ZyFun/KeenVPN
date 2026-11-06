"""Связь подготовки, бюджета и группы проверяется без fork/ptrace/mount."""

from contextlib import ExitStack, nullcontext
from dataclasses import replace
from pathlib import Path
import sys
import resource
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_linux_runner as runner_module
from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, XrayTestFile, XrayTestInvocation
from keenvpn.adapters.xray_memory_budget import MemoryBudgetExceeded
from keenvpn.adapters.xray_owned_wait import ProcessCleanupFailed


REAL_CLOSE = runner_module.os.close
REAL_FSTAT = runner_module.os.fstat


class LinuxRunnerTests(unittest.TestCase):
    def setUp(self):
        self.scope = ExitStack()
        self.addCleanup(self.scope.close)
        self.api = Mock()
        self.mounts = Mock()
        self.mounts.owns_staging.return_value = True
        self.mounts.create_cage.return_value = '/tmp/cage'
        self.begin_cleanup = Mock()
        self.runner = runner_module.LinuxXrayRunner(self.api, self.mounts, 30,
                                                   begin_cleanup=self.begin_cleanup)
        self.scope.enter_context(patch.object(runner_module.signal, 'pthread_sigmask', return_value=set()))
        self.scope.enter_context(patch.object(runner_module, 'monotonic', return_value=0))
        self.scope.enter_context(patch.object(runner_module, 'require_empty_child_scope'))
        self.scope.enter_context(patch.object(runner_module, 'installed_binary', return_value=nullcontext(71)))
        self.scope.enter_context(patch.object(runner_module, 'populate_cage', return_value=((0x10000, 0x12000),)))
        self.scope.enter_context(patch.object(runner_module, 'bounded_read', side_effect=lambda path, _: (
            b'0\n' if path.endswith('suid_dumpable') else b'80000000-80002000 r-xp 0 0:0 0 [vdso]\n')))
        self.pipes = self.scope.enter_context(patch.object(runner_module, 'private_pipe',
                                                         side_effect=((10, 11), (12, 13), (14, 15))))
        self.fstat = self.scope.enter_context(patch.object(runner_module.os, 'fstat', return_value=object()))
        self.fork = self.scope.enter_context(patch.object(runner_module.os, 'fork', return_value=123))
        self.close = self.scope.enter_context(patch.object(runner_module.os, 'close'))
        self.group = Mock(leader=None, all_reaped=False, streams={})
        def register(pid, stdout, stderr):
            self.group.leader = pid
            self.group.streams = {stdout: bytearray(), stderr: bytearray()}
        self.group.register.side_effect = register
        self.scope.enter_context(patch.object(runner_module, 'TraceGroup', return_value=self.group))
        item = XrayTestFile('parts/000.json', 50, 2, b'x' * 32)
        self.request = XrayTestInvocation('a' * 32, (item,),
                                         ('/opt/sbin/xray', 'run', '-test', '-format', 'json', '-c', item.name), (), 50)

    def reserve(self):
        self.assertTrue(self.runner.reserve_staging(self.request.job, 9))

    def test_reservation_requires_confirmed_private_parent(self):
        self.mounts.owns_staging.return_value = False
        self.assertFalse(self.runner.reserve_staging(self.request.job, 9))
        self.api.require_coordinator.assert_not_called()
        self.fork.assert_not_called()

    def test_start_requires_its_own_reservation(self):
        with self.assertRaises(IsolationUnavailable):
            self.runner.start(self.request)
        self.mounts.create_cage.assert_not_called()
        self.fork.assert_not_called()

    def test_initial_budget_and_readonly_cage_precede_fork(self):
        self.reserve()
        def fork():
            self.assertEqual(self.runner._memory.used, 8 * 1024 * 1024 + 16384)
            self.mounts.seal_cage.assert_called_once()
            return 123
        self.fork.side_effect = fork
        self.runner.start(self.request)
        self.assertEqual(self.runner.deadline, 30)
        self.group.register.assert_called_once_with(123, 10, 12)
        self.group.wait_exec.assert_called_once()
        self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [11, 13, 14, 15])

    def test_initial_memory_over_budget_prevents_fork(self):
        self.reserve()
        with self.assertRaises(MemoryBudgetExceeded):
            self.runner.start(replace(self.request, memory_limit=4096))
        self.fork.assert_not_called()
        self.runner.terminate_and_wait(self.request.job)
        self.runner.release_staging(self.request.job)
        self.mounts.release_cage.assert_called_once()

    def test_start_error_survives_cancel_at_cleanup_callback_entry_without_repeating_release(self):
        self.reserve()
        self.begin_cleanup.side_effect = (KeyboardInterrupt(), None, None)
        with patch.object(runner_module, 'populate_cage', side_effect=OSError('TEST_prepare_failed')):
            with self.assertRaises(OSError):
                self.runner.start(self.request)
        self.runner.terminate_and_wait(self.request.job)
        self.mounts.release_cage.assert_called_once()
        self.fork.assert_not_called()

    def test_collect_timeout_survives_cancel_at_cleanup_callback_entry_without_repeating_reap(self):
        self.reserve()
        self.runner.start(self.request)
        self.begin_cleanup.side_effect = (KeyboardInterrupt(), None, None)
        self.group.collect.side_effect = TimeoutError
        self.group.terminate_and_wait.side_effect = lambda: setattr(self.group, 'all_reaped', True)
        with self.assertRaises(TimeoutError):
            self.runner.collect(self.request.job)
        self.runner.terminate_and_wait(self.request.job)
        self.group.terminate_and_wait.assert_called_once()
        self.group.close_streams.assert_called_once()
        self.mounts.release_cage.assert_called_once()

    def test_stdin_is_readonly_eof_before_fork_and_parent_releases_its_copy(self):
        # Настоящие локальные pipe, без fork, mount, prctl или изменения stdin теста.
        import fcntl
        opened = set()
        pipes = []
        observations = {}
        def pipe():
            pair = runner_module.os.pipe()
            opened.update(pair)
            pipes.append(pair)
            return pair
        def close(fd):
            opened.remove(fd)
            REAL_CLOSE(fd)
        def fork():
            observations['pipe_count'] = len(pipes)
            if len(pipes) != 3:
                return 123
            reader, writer = pipes[2]
            self.assertNotIn(writer, opened)
            self.assertEqual(fcntl.fcntl(reader, fcntl.F_GETFL) & runner_module.os.O_ACCMODE,
                             runner_module.os.O_RDONLY)
            runner_module.os.set_blocking(reader, False)
            self.assertEqual(runner_module.os.read(reader, 1), b'')
            self.assertTrue(runner_module.os.path.samestat(self.runner._stdin, REAL_FSTAT(reader)))
            return 123
        self.reserve()
        self.pipes.side_effect = pipe
        self.fstat.side_effect = REAL_FSTAT
        self.close.side_effect = close
        self.fork.side_effect = fork
        try:
            self.runner.start(self.request)
            self.assertEqual(observations['pipe_count'], 3)
            self.assertEqual(opened, {pipes[0][0], pipes[1][0]})
        finally:
            for fd in tuple(opened):
                close(fd)

    def test_partial_pipe_creation_failure_closes_acquired_descriptors_and_cage(self):
        self.reserve()
        self.pipes.side_effect = ((10, 11), OSError())
        with self.assertRaises(OSError):
            self.runner.start(self.request)
        self.runner.terminate_and_wait(self.request.job)
        self.runner.release_staging(self.request.job)
        self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [10, 11])
        self.fork.assert_not_called()
        self.mounts.release_cage.assert_called_once()

    def test_stdin_pipe_creation_failure_closes_both_output_pipes(self):
        self.reserve()
        self.pipes.side_effect = ((10, 11), (12, 13), OSError())
        with self.assertRaises(OSError):
            self.runner.start(self.request)
        self.runner.terminate_and_wait(self.request.job)
        self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [10, 11, 12, 13])
        self.fork.assert_not_called()

    def test_stdin_metadata_failure_closes_all_six_pipe_descriptors(self):
        self.reserve()
        self.fstat.side_effect = OSError()
        with self.assertRaises(OSError):
            self.runner.start(self.request)
        self.runner.terminate_and_wait(self.request.job)
        self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [10, 11, 12, 13, 14, 15])
        self.fork.assert_not_called()

    def test_stdin_writer_close_failure_prevents_fork_and_is_not_retried(self):
        self.reserve()
        self.close.side_effect = lambda fd: (_ for _ in ()).throw(OSError()) if fd == 15 else None
        with self.assertRaises(ProcessCleanupFailed):
            self.runner.start(self.request)
        with self.assertRaises(ProcessCleanupFailed):
            self.runner.terminate_and_wait(self.request.job)
        self.assertEqual(sorted(call.args[0] for call in self.close.call_args_list), [10, 11, 12, 13, 14, 15])
        self.fork.assert_not_called()

    def test_child_receives_read_end_of_stdin_and_only_output_write_ends(self):
        class ChildExit(BaseException):
            pass
        self.reserve()
        self.fork.return_value = 0
        with patch.object(runner_module, 'exec_tracee') as execute, \
                patch.object(runner_module.os, '_exit', side_effect=ChildExit), \
                self.assertRaises(ChildExit):
            self.runner.start(self.request)
        execute.assert_called_once_with(self.api, '/tmp/cage', self.request, 14, 11, 13,
                                        runner_module.os.getpid())
        self.group.register.assert_not_called()

    def test_cleanup_failure_does_not_skip_stream_closure_or_release_live_cage(self):
        self.reserve()
        self.runner.start(self.request)
        self.group.terminate_and_wait.side_effect = ProcessCleanupFailed
        with self.assertRaises(ProcessCleanupFailed):
            self.runner.terminate_and_wait(self.request.job)
        self.group.close_streams.assert_called_once()
        self.mounts.release_cage.assert_not_called()
        with self.assertRaises(ProcessCleanupFailed):
            self.runner.release_staging(self.request.job)

    def test_successful_reap_precedes_release_and_borrowed_staging_fd_is_not_closed(self):
        self.reserve()
        self.runner.start(self.request)
        self.group.terminate_and_wait.side_effect = lambda: setattr(self.group, 'all_reaped', True)
        self.runner.terminate_and_wait(self.request.job)
        self.runner.release_staging(self.request.job)
        self.mounts.release_cage.assert_called_once()
        self.assertNotIn(9, [call.args[0] for call in self.close.call_args_list])
        self.assertNotIn(50, [call.args[0] for call in self.close.call_args_list])

    def test_other_job_cleanup_cannot_target_existing_group(self):
        self.reserve()
        self.runner.start(self.request)
        with self.assertRaises(ProcessCleanupFailed):
            self.runner.terminate_and_wait('b' * 32)
        self.group.terminate_and_wait.assert_not_called()

    def test_exec_checks_limits_maps_and_initial_break_before_constructing_policy(self):
        self.reserve()
        self.runner.start(self.request)
        maps = (b'10000-12000 r-xp 0 0:1 1 /xray\n'
                b'7fffe000-80000000 rw-p 0 0:0 0 [stack]\n'
                b'80002000-80004000 r-xp 0 0:0 0 [vdso]\n')
        proc_stat = b'123 (xray) ' + b' '.join([b'S'] + [b'0'] * 43 + [b'268435456'])
        def read(path, limit):
            if path.endswith('/maps'):
                return maps
            if path.endswith('/stat'):
                return proc_stat
            return b'0\n'
        limits = {resource.RLIMIT_STACK: 8 * 1024 * 1024, resource.RLIMIT_NOFILE: 64,
                  resource.RLIMIT_CORE: 0, resource.RLIMIT_FSIZE: 0}
        with patch.object(runner_module, 'verify_tracee') as verify, \
                patch.object(runner_module, 'verify_initial_fds') as fds, \
                patch.object(runner_module, 'bounded_read', side_effect=read), \
                patch.object(runner_module.resource, 'prlimit',
                             side_effect=lambda pid, kind: (limits[kind],) * 2, create=True):
            policy = self.runner._after_exec()
        verify.assert_called_once()
        fds.assert_called_once_with(123, self.runner._stdin, 10, 12)
        before = policy.memory.used
        policy.memory.before_brk(268435457)
        self.assertEqual(policy.memory.used, before + 4096)

    def test_unconfirmed_stack_limit_after_exec_prevents_policy(self):
        self.reserve()
        self.runner.start(self.request)
        with patch.object(runner_module, 'verify_tracee'), \
                patch.object(runner_module, 'verify_initial_fds'), \
                patch.object(runner_module.resource, 'prlimit', return_value=(-1, -1), create=True):
            with self.assertRaises(IsolationUnavailable):
                self.runner._after_exec()


if __name__ == '__main__':
    unittest.main()
