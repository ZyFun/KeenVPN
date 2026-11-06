"""Конкретный runner внутри выделенного private mount координатора."""

import os
import resource
import signal
from collections.abc import Callable
from time import monotonic

from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, XrayTestExit, XrayTestInvocation
from keenvpn.adapters.xray_image_files import installed_binary, populate_cage, verify_invocation
from keenvpn.adapters.xray_initial_memory import InitialMemory, STACK_LIMIT, auxiliary_sizes, initial_break, parse_maps
from keenvpn.adapters.xray_linux_native import LinuxAarch64
from keenvpn.adapters.xray_memory_budget import XrayMemoryBudget
from keenvpn.adapters.xray_private_mount import PrivateMounts, bounded_read
from keenvpn.adapters.xray_syscall_policy import MAX_DESCRIPTORS, XraySyscallPolicy
from keenvpn.adapters.xray_trace_group import ProcessCleanupFailed, TraceGroup
from keenvpn.adapters.xray_tracee_setup import (
    exec_tracee, private_pipe, require_empty_child_scope, verify_initial_fds, verify_tracee,
)


class LinuxXrayRunner:
    """Одна резервация и одна группа; создание снаружи private worker не даёт запуска."""

    def __init__(self, native: LinuxAarch64, mounts: PrivateMounts, deadline: float, *,
                 begin_cleanup: Callable[[], None]) -> None:
        self.native, self.mounts, self.deadline = native, mounts, deadline
        self._begin_cleanup = begin_cleanup
        self._reservation: str | None = None
        self._request: XrayTestInvocation | None = None
        self._group: TraceGroup | None = None
        self._image: InitialMemory | None = None
        self._memory: XrayMemoryBudget | None = None
        self._startup_fds: set[int] = set()
        self._descriptor_failure = False
        self._stdin: os.stat_result | None = None
        self._stdout: int | None = None
        self._stderr: int | None = None

    def reserve_staging(self, job: str, parent_fd: int) -> bool:
        if self._reservation is not None or self._request is not None or not self.mounts.owns_staging(parent_fd):
            return False
        self.native.require_coordinator()
        require_empty_child_scope()
        self._reservation = job
        return True

    def _check_time(self) -> None:
        if monotonic() >= self.deadline:
            raise TimeoutError

    def _verify_thread(self, tid: int) -> None:
        verify_tracee(tid, self._group.leader, os.getpid())

    def _after_exec(self) -> XraySyscallPolicy:
        pid = self._group.leader
        self._verify_thread(pid)
        verify_initial_fds(pid, self._stdin, self._stdout, self._stderr)
        if bounded_read('/proc/sys/fs/suid_dumpable', 16).strip() != b'0':
            raise IsolationUnavailable
        for kind, value in ((resource.RLIMIT_STACK, STACK_LIMIT), (resource.RLIMIT_NOFILE, MAX_DESCRIPTORS),
                            (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
            if resource.prlimit(pid, kind) != (value, value):
                raise IsolationUnavailable
        stack = self._image.verify_exec(parse_maps(bounded_read(f'/proc/{pid}/maps', 256 * 1024)))
        self._memory.set_initial_break(initial_break(bounded_read(f'/proc/{pid}/stat', 65536), pid))
        self._check_time()
        return XraySyscallPolicy(self._memory, pid, self._request.output_limit, stack)

    def _close_startup(self) -> None:
        # Принятые TraceGroup fd теперь закрывает только TraceGroup.
        if self._group is not None:
            self._startup_fds.difference_update(self._group.streams)
        for fd in tuple(self._startup_fds):
            self._startup_fds.remove(fd)
            try:
                os.close(fd)
            except OSError:
                self._descriptor_failure = True
        if self._descriptor_failure:
            raise ProcessCleanupFailed

    def start(self, request: XrayTestInvocation) -> None:
        try:
            self._start(request)
        except BaseException:
            try:
                self._begin_cleanup()
            except KeyboardInterrupt:
                # Повторяется только идемпотентный переход worker, а не операции с ресурсами.
                self._begin_cleanup()
            raise

    def _start(self, request: XrayTestInvocation) -> None:
        verify_invocation(request)
        if self._reservation != request.job or self._request is not None:
            raise IsolationUnavailable
        self._request = request
        self.deadline = min(self.deadline, request.deadline)
        self._check_time()
        self.native.require_coordinator()
        require_empty_child_scope()
        if bounded_read('/proc/sys/fs/suid_dumpable', 16).strip() != b'0':
            raise IsolationUnavailable
        cage = self.mounts.create_cage()
        with installed_binary() as binary:
            loads = populate_cage(cage, request, binary, self.deadline)
        auxiliary = auxiliary_sizes(parse_maps(bounded_read('/proc/self/maps', 256 * 1024)))
        self._image = InitialMemory(loads, auxiliary)
        self._memory = XrayMemoryBudget(request.memory_limit, self._image.bytes)
        self.mounts.seal_cage()
        self._group = TraceGroup(self.native, self.deadline, request.output_limit,
                                 self._after_exec, self._verify_thread)
        self._check_time()
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
        try:
            stdout = private_pipe()
            self._startup_fds.update(stdout)
            stderr = private_pipe()
            self._startup_fds.update(stderr)
            stdin = private_pipe()
            self._startup_fds.update(stdin)
            self._stdin = os.fstat(stdin[0])
            # Go требует открытый fd0. Собственная пустая pipe даёт только EOF,
            # без /dev/null и внешнего ввода. Писатель не должен попасть в fork.
            self._startup_fds.remove(stdin[1])
            try:
                os.close(stdin[1])
            except OSError:
                self._descriptor_failure = True
                raise ProcessCleanupFailed from None
            self._stdout, self._stderr = stdout[0], stderr[0]
            parent_pid = os.getpid()
            try:
                pid = os.fork()
            except OSError:
                raise
            except BaseException:
                # fork мог создать ребёнка, не отдав PID в Python. Не выдавать
                # отсутствие зарегистрированного PID за подтверждённую очистку.
                self._group.ownership_lost = True
                raise ProcessCleanupFailed from None
            if pid == 0:
                try:
                    exec_tracee(self.native, cage, request, stdin[0], stdout[1], stderr[1], parent_pid)
                except BaseException:
                    pass
                os._exit(125)  # Никаких traceback, путей или потоков исключения.
            self._group.register(pid, stdout[0], stderr[0])
            self._close_startup()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        self._group.wait_exec()

    def collect(self, job: str) -> XrayTestExit:
        try:
            if self._reservation != job or self._group is None:
                raise IsolationUnavailable
            return self._group.collect()
        finally:
            # Переход до _run.finally закрывает доставку сигнала при входе в terminate_and_wait.
            try:
                self._begin_cleanup()
            except KeyboardInterrupt:
                self._begin_cleanup()

    def terminate_and_wait(self, job: str) -> None:
        if self._reservation is not None and job != self._reservation:
            raise ProcessCleanupFailed
        try:
            self._begin_cleanup()
        except KeyboardInterrupt:
            self._begin_cleanup()
        failed = False
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
        try:
            if self._group is not None:
                try:
                    self._group.terminate_and_wait()
                except (Exception, KeyboardInterrupt):
                    failed = True
                # Убрать переданные fd до их close, чтобы ошибка close не приводила к повтору.
                self._startup_fds.difference_update(self._group.streams)
                try:
                    self._group.close_streams()
                except (Exception, KeyboardInterrupt):
                    failed = True
            try:
                self._close_startup()
            except (Exception, KeyboardInterrupt):
                failed = True
            if self._group is None or self._group.leader is None or self._group.all_reaped:
                try:
                    self.mounts.release_cage()
                except (Exception, KeyboardInterrupt):
                    failed = True
            else:
                failed = True
            if failed:
                raise ProcessCleanupFailed
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def release_staging(self, job: str) -> None:
        if self._reservation is None:
            return
        if (job != self._reservation or self._group is not None
                and self._group.leader is not None and not self._group.all_reaped):
            raise ProcessCleanupFailed
        self._reservation = None
