"""Native Linux AArch64 ABI проверенного исполнителя; импорт не вызывает ОС-операций."""

import ctypes
from dataclasses import dataclass
import os
import signal

from keenvpn.adapters.xray_candidate_test import IsolationUnavailable


PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
NT_PRSTATUS = 1
NT_ARM_SYSTEM_CALL = 0x404
TRACE_OPTIONS = 0x100019  # TRACESYSGOOD | TRACECLONE | TRACEEXEC | EXITKILL.
UINT64_MAX = (1 << 64) - 1
# CAP_SYS_RESOURCE (24) нужен также для чтения prlimit процесса другого UID.
REQUIRED_CAPABILITIES = sum(1 << bit for bit in (1, 5, 6, 7, 18, 19, 21, 24))


class Registers(ctypes.Structure):
    _fields_ = [('values', ctypes.c_uint64 * 31), ('sp', ctypes.c_uint64),
                ('pc', ctypes.c_uint64), ('pstate', ctypes.c_uint64)]


class _Iovec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]


class _CapHeader(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                ('inheritable', ctypes.c_uint32)]


class _KernelSigaction(ctypes.Structure):
    # Linux AArch64 UAPI, не libc sigaction с расширенным sigset_t.
    _fields_ = [('handler', ctypes.c_uint64), ('flags', ctypes.c_uint64),
                ('restorer', ctypes.c_uint64), ('mask', ctypes.c_uint64)]


@dataclass(frozen=True, slots=True, repr=False)
class SyscallStop:
    """Приватный снимок остановленного TID; аргументы и адреса не выводятся."""

    number: int
    arguments: tuple[int, ...]
    entering: bool
    registers: Registers


def _supported_platform() -> bool:
    return (os.uname().sysname == 'Linux' and os.uname().machine == 'aarch64'
            and os.uname().release == '4.9-ndm-5' and os.geteuid() == 0
            and os.sysconf('SC_PAGESIZE') == 4096 and ctypes.sizeof(ctypes.c_void_p) == 8
            and ctypes.sizeof(ctypes.c_long) == 8 and ctypes.sizeof(Registers) == 272
            and ctypes.sizeof(_KernelSigaction) == 32)


def _tid(value: int) -> int:
    if type(value) is not int or not 0 < value < 1 << 31:
        raise IsolationUnavailable
    return value


class LinuxAarch64:
    """Вызовы только для собственного процесса и TID, которыми владеет координатор.

Владение и состояние остановки проверяет координатор. Этот слой не ищет PID,
не управляет службами и не принимает строки shell. Другие ABI и ядра отклоняются.
"""

    def __init__(self) -> None:
        if not _supported_platform():
            raise IsolationUnavailable
        libc = ctypes.CDLL(None, use_errno=True)
        self._ptrace = libc.ptrace
        self._ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self._ptrace.restype = ctypes.c_long
        self._syscall = libc.syscall
        self._syscall.argtypes = [ctypes.c_long]
        self._syscall.restype = ctypes.c_long
        self._prctl = libc.prctl
        self._prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.c_ulong, ctypes.c_ulong]
        self._prctl.restype = ctypes.c_int
        self._mount = libc.mount
        self._mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                               ctypes.c_ulong, ctypes.c_char_p]
        self._mount.restype = ctypes.c_int
        self._unshare = libc.unshare
        self._unshare.argtypes = [ctypes.c_int]
        self._unshare.restype = ctypes.c_int
        self._umount = libc.umount2
        self._umount.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self._umount.restype = ctypes.c_int

    def _call(self, number: int, *arguments: int) -> int:
        if any(type(value) is not int or not 0 <= value <= UINT64_MAX for value in arguments):
            raise IsolationUnavailable
        result = self._syscall(ctypes.c_long(number), *(ctypes.c_ulong(value) for value in arguments))
        if result == -1:
            raise IsolationUnavailable
        return result

    def prctl(self, option: int, value: int = 0) -> int:
        if type(option) is not int or type(value) is not int or not 0 <= value <= UINT64_MAX:
            raise IsolationUnavailable
        result = self._prctl(option, value, 0, 0, 0)
        if result == -1:
            raise IsolationUnavailable
        return result

    def capabilities(self) -> tuple[int, int, int]:
        header, data = _CapHeader(0x20080522, 0), (_CapData * 2)()
        self._call(90, ctypes.addressof(header), ctypes.addressof(data))
        return tuple(getattr(data[0], field) | getattr(data[1], field) << 32
                     for field in ('effective', 'permitted', 'inheritable'))

    def require_coordinator(self) -> None:
        """Проверить полномочия и отсутствие других потоков до создания ребёнка."""
        effective, _, _ = self.capabilities()
        if effective & REQUIRED_CAPABILITIES != REQUIRED_CAPABILITIES:
            raise IsolationUnavailable
        if len(os.listdir('/proc/self/task')) != 1:
            raise IsolationUnavailable
        # На критических участках fork/передачи fd блокируются именно эти сигналы.
        # Другой Python-обработчик мог бы бросить исключение до учёта нового PID/fd.
        for number in signal.valid_signals():
            if number not in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP) and callable(signal.getsignal(number)):
                raise IsolationUnavailable
        action = _KernelSigaction()
        self._call(134, 17, 0, ctypes.addressof(action), 8)
        if action.handler != 0 or action.flags & 2:  # SIG_DFL; без SA_NOCLDWAIT.
            raise IsolationUnavailable

    def clear_capabilities(self) -> None:
        header, data = _CapHeader(0x20080522, 0), (_CapData * 2)()
        self._call(91, ctypes.addressof(header), ctypes.addressof(data))
        if self.capabilities() != (0, 0, 0):
            raise IsolationUnavailable

    def unshare_mounts(self) -> None:
        if self._unshare(0x20000) != 0:
            raise IsolationUnavailable

    def mount(self, source: bytes | None, target: bytes, kind: bytes | None,
              flags: int, data: bytes | None = None) -> None:
        if self._mount(source, target, kind, flags, data) != 0:
            raise IsolationUnavailable

    def unmount(self, target: bytes) -> None:
        """Обычный umount без lazy detach: занятые ресурсы должны дать отказ cleanup."""
        if self._umount(target, 0) != 0:
            raise IsolationUnavailable

    def _trace(self, request: int, tid: int, address: int = 0, data: int = 0) -> None:
        if self._ptrace(request, tid, ctypes.c_void_p(address), ctypes.c_void_p(data)) == -1:
            raise IsolationUnavailable

    def _regset(self, request: int, tid: int, kind: int, value: object) -> object:
        vector = _Iovec(ctypes.addressof(value), ctypes.sizeof(value))
        self._trace(request, _tid(tid), kind, ctypes.addressof(vector))
        if vector.length != ctypes.sizeof(value):
            raise IsolationUnavailable
        return value

    def trace_me(self) -> None:
        self._trace(PTRACE_TRACEME, 0)

    def set_options(self, tid: int) -> None:
        self._trace(PTRACE_SETOPTIONS, _tid(tid), data=TRACE_OPTIONS)

    def resume(self, tid: int, *, syscall: bool, delivered_signal: int = 0) -> None:
        if type(delivered_signal) is not int or not 0 <= delivered_signal <= 64:
            raise IsolationUnavailable
        self._trace(PTRACE_SYSCALL if syscall else PTRACE_CONT, _tid(tid), data=delivered_signal)

    def event_child(self, tid: int) -> int:
        value = ctypes.c_ulong()
        self._trace(PTRACE_GETEVENTMSG, _tid(tid), data=ctypes.addressof(value))
        return _tid(value.value)

    def registers(self, tid: int) -> Registers:
        value = Registers()
        self._regset(PTRACE_GETREGSET, tid, NT_PRSTATUS, value)
        # Включая nRW bit4: разрешён только AArch64 EL0t, а не compat AArch32.
        if value.pstate & 0x1F:
            raise IsolationUnavailable
        return value

    def syscall_number(self, tid: int) -> int:
        value = ctypes.c_int()
        self._regset(PTRACE_GETREGSET, tid, NT_ARM_SYSTEM_CALL, value)
        return value.value

    def syscall_stop(self, tid: int) -> SyscallStop:
        registers = self.registers(tid)
        direction = registers.values[7]
        if direction not in (0, 1):
            raise IsolationUnavailable
        return SyscallStop(self.syscall_number(tid), tuple(registers.values[:6]), direction == 0, registers)

    def deny_syscall(self, tid: int, stop: SyscallStop, error_number: int) -> None:
        """Пропустить вызов на входе и вернуть errno без записи в память tracee."""
        if not stop.entering or type(error_number) is not int or not 1 <= error_number <= 4095:
            raise IsolationUnavailable
        self._regset(PTRACE_SETREGSET, tid, NT_ARM_SYSTEM_CALL, ctypes.c_int(-1))
        if self.syscall_number(tid) != -1:
            raise IsolationUnavailable
        stop.registers.values[0] = (-error_number) & UINT64_MAX
        self._regset(PTRACE_SETREGSET, tid, NT_PRSTATUS, stop.registers)
        if self.registers(tid).values[0] != ((-error_number) & UINT64_MAX):
            raise IsolationUnavailable
