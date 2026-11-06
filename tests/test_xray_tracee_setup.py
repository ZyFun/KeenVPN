"""Все UID, resource, fd, fork/exec и сигнальные операции заменены двойниками."""

from contextlib import ExitStack
import errno
from pathlib import Path
import resource
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_tracee_setup as setup
from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, XrayTestInvocation


class Executed(BaseException):
    pass


class TraceeSetupTests(unittest.TestCase):
    def test_pipe_keeps_standard_descriptor_numbers_free(self):
        with patch.object(setup.os, 'pipe2', return_value=(0, 1), create=True), \
                patch.object(setup.fcntl, 'fcntl', side_effect=(3, 4)), \
                patch.object(setup.os, 'close') as close:
            self.assertEqual(setup.private_pipe(), (3, 4))
            self.assertEqual(sorted(call.args[0] for call in close.call_args_list), [0, 1])

    def test_partial_pipe_setup_closes_every_obtained_fd(self):
        with patch.object(setup.os, 'pipe2', return_value=(0, 1), create=True), \
                patch.object(setup.fcntl, 'fcntl', side_effect=(3, OSError())), \
                patch.object(setup.os, 'close') as close:
            with self.assertRaises(OSError):
                setup.private_pipe()
            self.assertEqual(sorted(call.args[0] for call in close.call_args_list), [0, 1, 3])

    def test_pipe_close_failure_does_not_skip_remaining_cleanup(self):
        with patch.object(setup.os, 'pipe2', return_value=(0, 1), create=True), \
                patch.object(setup.fcntl, 'fcntl', side_effect=(3, 4)), \
                patch.object(setup.os, 'close', side_effect=(OSError(), None, None, None)) as close:
            with self.assertRaises(OSError):
                setup.private_pipe()
            self.assertEqual(sorted(call.args[0] for call in close.call_args_list), [0, 1, 3, 4])

    def test_fd_cleanup_closes_stdin_but_ignores_already_closed_listdir_fd(self):
        with patch.object(setup.os, 'listdir', return_value=['0', '1', '2', '9']), \
                patch.object(setup.os, 'close', side_effect=(None, OSError(errno.EBADF, ''))) as close:
            setup.close_other_fds(frozenset((1, 2)))
        self.assertEqual([call.args[0] for call in close.call_args_list], [0, 9])

    def test_nonempty_child_scope_prevents_exclusive_wait_usage(self):
        with patch.object(setup.os, 'waitid', return_value=None, create=True):
            with self.assertRaises(IsolationUnavailable):
                setup.require_empty_child_scope()

    def test_empty_child_scope_uses_nonconsuming_wait_without_proc_children(self):
        with patch.object(setup, 'bounded_read', side_effect=FileNotFoundError), \
                patch.object(setup.os, 'waitid', side_effect=ChildProcessError(errno.ECHILD, ''), create=True) as wait, \
                patch.object(setup.os, 'waitpid', side_effect=AssertionError):
            setup.require_empty_child_scope()
        flags = setup.os.WEXITED | setup.os.WSTOPPED | setup.os.WCONTINUED | setup.os.WNOHANG | setup.os.WNOWAIT | 0x40000000
        wait.assert_called_once_with(setup.os.P_ALL, 0, flags)

    def test_waitable_child_state_is_not_consumed_or_mistaken_for_empty_scope(self):
        with patch.object(setup.os, 'waitid', return_value=SimpleNamespace(si_pid=456), create=True), \
                patch.object(setup.os, 'waitpid', side_effect=AssertionError):
            with self.assertRaises(IsolationUnavailable):
                setup.require_empty_child_scope()

    def test_unavailable_waitid_or_unexpected_errors_fail_closed(self):
        for effect in (OSError(errno.EINVAL, ''), OSError(errno.EACCES, ''), ChildProcessError(), AttributeError()):
            with patch.object(setup.os, 'waitid', side_effect=effect, create=True), self.assertRaises(IsolationUnavailable):
                setup.require_empty_child_scope()
        with patch.object(setup.os, 'waitid', None, create=True), self.assertRaises(IsolationUnavailable):
            setup.require_empty_child_scope()

    def run_setup(self, *, dumpable=0, parent=123, readonly=True, strict_native=False):
        api = Mock()
        api.prctl.side_effect = lambda option, *args: 1 if option == 39 else dumpable if option == 3 else 0
        if strict_native:
            native = object.__new__(setup.LinuxAarch64)
            native._prctl = Mock(side_effect=api.prctl.side_effect)
            api.prctl.side_effect = native.prctl
        request = XrayTestInvocation('a' * 32, (), ('/opt/sbin/xray', 'run', '-test'), (), 1000)
        with ExitStack() as stack:
            patches = {
                'getppid': Mock(return_value=parent), 'getpid': Mock(return_value=124),
                'dup2': Mock(), 'chroot': Mock(), 'chdir': Mock(),
                'listdir': Mock(return_value=['parts', 'assets', 'xray']),
                'statvfs': Mock(return_value=SimpleNamespace(f_flag=setup.os.ST_RDONLY if readonly else 0)),
                'setgroups': Mock(), 'setresgid': Mock(), 'setresuid': Mock(),
                'getresuid': Mock(return_value=(65534,) * 3), 'getresgid': Mock(return_value=(65534,) * 3),
                'getgroups': Mock(return_value=[]), 'kill': Mock(), 'execve': Mock(side_effect=Executed),
            }
            for name, mock in patches.items():
                stack.enter_context(patch.object(setup.os, name, mock, create=True))
            patches['close_other_fds'] = stack.enter_context(patch.object(setup, 'close_other_fds'))
            limit = stack.enter_context(patch.object(setup, '_limit'))
            stack.enter_context(patch.object(setup.resource, 'getrlimit', return_value=(resource.RLIM_INFINITY,) * 2))
            stack.enter_context(patch.object(setup.signal, 'signal'))
            stack.enter_context(patch.object(setup.signal, 'pthread_sigmask'))
            try:
                setup.exec_tracee(api, '/tmp/cage', request, 14, 11, 13, 123)
            except BaseException as error:
                return api, patches, limit, error
        self.fail('Ожидался exec либо закрытый отказ')

    def test_child_exec_has_only_fixed_argv_environment_and_closed_privileges(self):
        api, effects, limit, error = self.run_setup()
        self.assertIsInstance(error, Executed)
        effects['setresuid'].assert_called_once_with(65534, 65534, 65534)
        effects['setresgid'].assert_called_once_with(65534, 65534, 65534)
        effects['setgroups'].assert_called_once_with([])
        api.clear_capabilities.assert_called_once()
        api.trace_me.assert_called_once()
        self.assertEqual(sum(call.args[0] == 1 for call in api.prctl.call_args_list), 2)
        effects['execve'].assert_called_once_with('/xray', ('/xray', 'run', '-test'), {'XRAY_LOCATION_ASSET': 'assets'})
        self.assertIn((resource.RLIMIT_CORE, 0), [call.args for call in limit.call_args_list])

    def test_tracee_parent_death_signal_passes_strict_native_prctl_twice(self):
        api, effects, _, error = self.run_setup(strict_native=True)
        self.assertIsInstance(error, Executed)
        effects['execve'].assert_called_once()
        self.assertEqual(sum(call.args[0] == 1 for call in api.prctl.call_args_list), 2)

    def test_exec_keeps_own_eof_stdin_for_go_standard_descriptor_check(self):
        _, effects, _, error = self.run_setup()
        self.assertIsInstance(error, Executed)
        self.assertEqual([call.args for call in effects['dup2'].call_args_list],
                         [(14, 0), (11, 1), (13, 2)])
        effects['close_other_fds'].assert_called_once_with(frozenset((0, 1, 2)))

    def test_dumpable_changed_parent_or_writable_cage_never_reaches_traceme_exec(self):
        for changes in ({'dumpable': 1}, {'parent': 1}, {'readonly': False}):
            api, effects, _, error = self.run_setup(**changes)
            self.assertIsInstance(error, IsolationUnavailable)
            api.trace_me.assert_not_called()
            effects['execve'].assert_not_called()

    def test_limit_cannot_silently_remain_above_requested_value(self):
        with patch.object(setup.resource, 'getrlimit', side_effect=((100, 100), (100, 100))), \
                patch.object(setup.resource, 'setrlimit'):
            with self.assertRaises(IsolationUnavailable):
                setup._limit(resource.RLIMIT_NOFILE, 64)

    def status(self, **changes):
        fields = dict(Pid='124', Tgid='123', TracerPid='999', Uid='65534 65534 65534 65534',
                      Gid='65534 65534 65534 65534', Groups='', CapInh='0', CapPrm='0', CapEff='0', CapAmb='0')
        fields.update(changes)
        return ''.join(f'{key}:\t{value}\n' for key, value in fields.items()).encode()

    def test_exec_status_requires_zero_caps_nonroot_saved_ids_and_own_tracer(self):
        with patch.object(setup.os, 'stat', return_value=SimpleNamespace(st_uid=0)), \
                patch.object(setup, 'bounded_read', return_value=self.status()):
            setup.verify_tracee(124, 123, 999)
        for changes in ({'CapEff': '1'}, {'Uid': '65534 65534 0 65534'}, {'TracerPid': '0'},
                        {'Tgid': '456'}, {'Groups': '0'}, {'NoNewPrivs': '0'}):
            with patch.object(setup.os, 'stat', return_value=SimpleNamespace(st_uid=0)), \
                    patch.object(setup, 'bounded_read', return_value=self.status(**changes)):
                with self.assertRaises(IsolationUnavailable):
                    setup.verify_tracee(124, 123, 999)

    def test_dumpable_proc_owner_is_rejected_even_with_other_valid_status_fields(self):
        with patch.object(setup.os, 'stat', return_value=SimpleNamespace(st_uid=65534)), \
                patch.object(setup, 'bounded_read', return_value=self.status()):
            with self.assertRaises(IsolationUnavailable):
                setup.verify_tracee(124, 123, 999)

    def test_nondumpable_check_uses_status_owner_not_world_readable_proc_directory(self):
        # Linux 4.9 сохраняет euid у каталога /proc/PID 0555 даже при dumpable=0.
        def metadata(path):
            return SimpleNamespace(st_uid=65534 if path == '/proc/124' else 0)
        with patch.object(setup.os, 'stat', side_effect=metadata) as stat, \
                patch.object(setup, 'bounded_read', return_value=self.status()):
            setup.verify_tracee(124, 123, 999)
        stat.assert_called_once_with('/proc/124/status')

    def pipe_metadata(self, number, mode=stat.S_IFIFO | 0o600):
        return setup.os.stat_result((mode, number, 7, 1, 0, 0, 0, 0, 0, 0))

    def test_exec_fd_verification_accepts_only_three_own_pipes(self):
        metadata = {i: self.pipe_metadata(i + 100) for i in range(3)}
        with patch.object(setup.os, 'listdir', return_value=['0', '1', '2']), \
                patch.object(setup.os, 'fstat', side_effect=lambda fd: metadata[{10: 1, 12: 2}[fd]]), \
                patch.object(setup.os, 'stat', side_effect=lambda path: metadata[int(path.rsplit('/', 1)[1])]):
            setup.verify_initial_fds(124, metadata[0], 10, 12)

    def test_exec_fd_verification_rejects_missing_extra_or_replaced_stdin(self):
        expected = self.pipe_metadata(100)
        for names, actual in ((['1', '2'], expected), (['0', '1', '2', '3'], expected),
                              (['0', '1', '2'], self.pipe_metadata(200)),
                              (['0', '1', '2'], self.pipe_metadata(100, stat.S_IFCHR | 0o600))):
            with self.subTest(names=names, mode=actual.st_mode, inode=actual.st_ino), \
                    patch.object(setup.os, 'listdir', return_value=names), \
                    patch.object(setup.os, 'fstat', return_value=expected), \
                    patch.object(setup.os, 'stat', return_value=actual), \
                    self.assertRaises(IsolationUnavailable):
                setup.verify_initial_fds(124, expected, 10, 12)


if __name__ == '__main__':
    unittest.main()
