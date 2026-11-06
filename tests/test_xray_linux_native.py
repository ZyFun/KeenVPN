"""Проверки границы native ABI на двойниках, без системных вызовов Linux."""

import ctypes
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_linux_native as native
from keenvpn.adapters.xray_candidate_test import IsolationUnavailable


class LinuxNativeTests(unittest.TestCase):
    def setUp(self):
        self.libc = SimpleNamespace(**{name: Mock(return_value=0) for name in
                                      ('ptrace', 'syscall', 'prctl', 'mount', 'unshare', 'umount2')})
        with patch.object(native, '_supported_platform', return_value=True), \
                patch.object(native.ctypes, 'CDLL', return_value=self.libc):
            self.api = native.LinuxAarch64()

    def test_unsupported_abi_never_loads_libc(self):
        with patch.object(native, '_supported_platform', return_value=False), \
                patch.object(native.ctypes, 'CDLL') as loader:
            with self.assertRaises(IsolationUnavailable):
                native.LinuxAarch64()
            loader.assert_not_called()

    def test_varargs_preserve_native_pointer_width(self):
        self.api._call(134, 17, 0, 0xFEDCBA9876543210, 8)
        args = self.libc.syscall.call_args.args
        self.assertEqual(args[3].value, 0xFEDCBA9876543210)
        self.assertIs(type(args[3]), ctypes.c_ulong)

    def test_syscall_failure_and_invalid_arguments_fail_closed(self):
        self.libc.syscall.return_value = -1
        with self.assertRaises(IsolationUnavailable):
            self.api._call(90, 0, 0)
        self.libc.syscall.reset_mock()
        for value in (True, -1, 1 << 64, '0'):
            with self.assertRaises(IsolationUnavailable):
                self.api._call(90, value)
        self.libc.syscall.assert_not_called()

    def test_incomplete_regset_is_rejected(self):
        def truncated(_request, _tid, _kind, address):
            vector = ctypes.cast(address, ctypes.POINTER(native._Iovec)).contents
            vector.length -= 1
            return 0
        self.libc.ptrace.side_effect = truncated
        with self.assertRaises(IsolationUnavailable):
            self.api.registers(123)

    def test_compat_abi_and_unknown_stop_direction_are_rejected(self):
        for pstate, direction in ((0x10, 0), (1, 0), (0, 2)):
            registers = native.Registers()
            registers.pstate, registers.values[7] = pstate, direction
            def get_registers(_request, _tid, _kind, value):
                ctypes.memmove(ctypes.addressof(value), ctypes.addressof(registers), 272)
            with patch.object(self.api, '_regset', side_effect=get_registers):
                with self.assertRaises(IsolationUnavailable):
                    self.api.syscall_stop(123)

    def test_deny_changes_syscall_number_and_result_without_tracee_memory_write(self):
        registers = native.Registers()
        stop = native.SyscallStop(172, (0,) * 6, True, registers)
        with patch.object(self.api, '_regset') as regset, \
                patch.object(self.api, 'syscall_number', return_value=-1), \
                patch.object(self.api, 'registers', return_value=registers):
            self.api.deny_syscall(123, stop, 13)
        self.assertEqual(regset.call_args_list[0].args[:3], (native.PTRACE_SETREGSET, 123, 0x404))
        self.assertEqual(regset.call_args_list[0].args[3].value, -1)
        self.assertEqual(regset.call_args_list[1].args[:3], (native.PTRACE_SETREGSET, 123, 1))
        self.assertEqual(registers.values[0], (1 << 64) - 13)
        self.libc.ptrace.assert_not_called()

    def test_deny_requires_entry_stop_and_confirmed_skip(self):
        registers = native.Registers()
        with self.assertRaises(IsolationUnavailable):
            self.api.deny_syscall(123, native.SyscallStop(172, (), False, registers), 13)
        with patch.object(self.api, '_regset') as regset, \
                patch.object(self.api, 'syscall_number', return_value=172):
            with self.assertRaises(IsolationUnavailable):
                self.api.deny_syscall(123, native.SyscallStop(172, (), True, registers), 13)
            self.assertEqual(regset.call_count, 1)

    def test_coordinator_rejects_autoreap_or_nondefault_handler_before_fork(self):
        def sigaction(_number, _sig, _new, address, _size):
            action = native._KernelSigaction.from_address(address)
            action.handler, action.flags = configured
        for configured in ((1, 0), (2, 0), (0, 2)):
            with patch.object(self.api, 'capabilities', return_value=(native.REQUIRED_CAPABILITIES, 0, 0)), \
                    patch.object(native.os, 'listdir', return_value=['123']), \
                    patch.object(self.api, '_call', side_effect=sigaction):
                with self.assertRaises(IsolationUnavailable):
                    self.api.require_coordinator()

    def test_coordinator_requires_single_thread_and_capabilities(self):
        for capabilities, tids in ((0, ['123']), (native.REQUIRED_CAPABILITIES, ['123', '124'])):
            with patch.object(self.api, 'capabilities', return_value=(capabilities, 0, 0)), \
                    patch.object(native.os, 'listdir', return_value=tids), \
                    patch.object(self.api, '_call') as syscall:
                with self.assertRaises(IsolationUnavailable):
                    self.api.require_coordinator()
                syscall.assert_not_called()

    def test_coordinator_without_cap_kill_is_rejected_before_child_creation(self):
        without_kill = native.REQUIRED_CAPABILITIES & ~(1 << 5)
        with patch.object(self.api, 'capabilities', return_value=(without_kill, 0, 0)), \
                patch.object(native.os, 'listdir', return_value=['123']), \
                patch.object(self.api, '_call') as syscall:
            with self.assertRaises(IsolationUnavailable):
                self.api.require_coordinator()
            syscall.assert_not_called()

    def test_coordinator_requires_effective_cap_sys_resource_before_preparation(self):
        without_resource = native.REQUIRED_CAPABILITIES & ~(1 << 24)
        with patch.object(self.api, 'capabilities', return_value=(without_resource, 1 << 24, 0)), \
                patch.object(native.os, 'listdir', return_value=['123']) as listdir, \
                patch.object(native.signal, 'valid_signals', return_value=set()), \
                patch.object(self.api, '_call') as syscall:
            with self.assertRaises(IsolationUnavailable):
                self.api.require_coordinator()
            listdir.assert_not_called()
            syscall.assert_not_called()

    def test_uncovered_python_signal_handler_is_rejected_before_fork(self):
        with patch.object(self.api, 'capabilities', return_value=(native.REQUIRED_CAPABILITIES, 0, 0)), \
                patch.object(native.os, 'listdir', return_value=['123']), \
                patch.object(native.signal, 'valid_signals', return_value={native.signal.SIGALRM}), \
                patch.object(native.signal, 'getsignal', return_value=lambda *_: None), \
                patch.object(self.api, '_call') as syscall:
            with self.assertRaises(IsolationUnavailable):
                self.api.require_coordinator()
            syscall.assert_not_called()

    def test_no_pid_or_signal_wildcards(self):
        for tid in (0, -1, True, 1 << 31):
            with self.assertRaises(IsolationUnavailable):
                self.api.resume(tid, syscall=True)
        for value in (-1, 65, True):
            with self.assertRaises(IsolationUnavailable):
                self.api.resume(123, syscall=True, delivered_signal=value)
        self.libc.ptrace.assert_not_called()


if __name__ == '__main__':
    unittest.main()
