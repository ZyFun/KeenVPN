"""Жизненный цикл единственной группы в выделенном доверенном координаторе.

waitpid(-1, __WALL) допустим только в этом отдельном однопоточном процессе:
до fork у него нет детей, а все последующие дети принадлежат одному заданию.
Это позволяет забрать и поток, погибший до получения события TRACECLONE.
Сигналы по отрицательным PID не используются; после terminal wait PID не трогается.
"""

from collections.abc import Callable
from dataclasses import dataclass
import os
import select
import signal
from time import monotonic

from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, OutputLimitExceeded, XrayTestExit
from keenvpn.adapters.xray_linux_native import LinuxAarch64, SyscallStop, UINT64_MAX
from keenvpn.adapters.xray_owned_wait import ProcessCleanupFailed, wait_owned
from keenvpn.adapters.xray_syscall_policy import Decision, MAX_THREADS, XraySyscallPolicy


WAIT_FLAGS = os.WNOHANG | 0x40000000  # __WALL: включая auto-attached CLONE_THREAD.
CLEANUP_SECONDS = 2.0


@dataclass(slots=True, repr=False)
class _Thread:
    phase: str
    pending: tuple[SyscallStop, Decision] | None = None
    optional_exit: int | None = None
    clone_child: int | None = None


class TraceGroup:
    """Один наблюдатель всех TID, два приватных потока и один абсолютный deadline."""

    def __init__(self, native: LinuxAarch64, deadline: float, output_limit: int,
                 on_exec: Callable[[], XraySyscallPolicy], verify_thread: Callable[[int], None]) -> None:
        self.native, self.deadline, self.output_limit = native, deadline, output_limit
        self.on_exec, self.verify_thread = on_exec, verify_thread
        self.leader: int | None = None
        self.leader_reaped = False
        self.returncode: int | None = None
        self.policy: XraySyscallPolicy | None = None
        self.threads: dict[int, _Thread] = {}
        self.early_stops: set[int] = set()
        self.early_terminals: set[int] = set()
        self.reaped_tids: set[int] = set()
        # Это несопоставленные результаты уже оплаченных policy.before clone.
        # Смерть родителя не отменяет возможное рождение ребёнка. Число
        # разрешённых clone за всё задание ограничено политикой до MAX_THREADS.
        self.unannounced_clones = 0
        self.held: set[int] = set()
        self.all_reaped = False
        self.ownership_lost = False
        self.wait_uncertain = False
        self.terminal_status: int | None = None
        self.streams: dict[int, bytearray] = {}
        self._stdout: bytearray = bytearray()
        self._stderr: bytearray = bytearray()
        self.stream_close_failed = False

    def register(self, pid: int, stdout: int, stderr: int) -> None:
        """Вызывается сразу после собственного fork, пока отмена ещё заблокирована."""
        if self.leader is not None or not 0 < pid < 1 << 31:
            raise IsolationUnavailable
        self.leader = pid
        self.threads[pid] = _Thread('bootstrap')
        self.streams = {stdout: self._stdout, stderr: self._stderr}
        for fd in self.streams:
            os.set_blocking(fd, False)

    def _resume(self, tid: int, *, syscall: bool = True, delivered_signal: int = 0) -> None:
        if monotonic() >= self.deadline:
            raise TimeoutError
        self.native.resume(tid, syscall=syscall, delivered_signal=delivered_signal)
        self.held.discard(tid)

    def _new_thread(self, tid: int) -> None:
        self.verify_thread(tid)
        self.native.set_options(tid)
        state = self.threads[tid]
        state.phase, state.optional_exit = 'running', 220
        self._resume(tid)

    def _clone(self, tid: int, state: _Thread) -> None:
        if state.pending is None or not state.pending[1].clone or state.clone_child is not None:
            raise IsolationUnavailable
        child = self.native.event_child(tid)
        if (child in self.threads or len(self.threads) >= MAX_THREADS
                or child in self.reaped_tids and child not in self.early_terminals):
            raise IsolationUnavailable
        matched = child in self.early_stops or child in self.early_terminals
        self._resolve_clone(int(matched))
        state.clone_child = child
        if child in self.early_terminals:
            # Consuming wait уже освободил TID: даже проверять его через proc
            # нельзя, поскольку номер мог достаться постороннему процессу.
            self.early_terminals.remove(child)
        else:
            self.threads[child] = _Thread('new')
            if child in self.early_stops:
                self.early_stops.remove(child)
                self._new_thread(child)
        self._resume(tid)

    def _resolve_clone(self, matched: int = 0) -> None:
        remaining = self.unannounced_clones - 1
        if remaining < 0 or len(self.early_stops) + len(self.early_terminals) - matched > remaining:
            raise IsolationUnavailable
        self.unannounced_clones = remaining

    def _early_child(self, tid: int) -> None:
        if (tid in self.reaped_tids or tid not in self.early_stops
                and len(self.early_stops) + len(self.early_terminals) >= self.unannounced_clones):
            raise IsolationUnavailable

    def _syscall(self, tid: int, state: _Thread) -> None:
        stop = self.native.syscall_stop(tid)
        if stop.entering:
            if state.pending is not None:
                raise IsolationUnavailable
            state.optional_exit = None
            decision = self.policy.before(stop.number, stop.arguments, frozenset(self.threads))
            state.pending = stop, decision
            state.clone_child = None
            if decision.clone:
                self.unannounced_clones += 1
            if decision.error_number:
                self.native.deny_syscall(tid, stop, decision.error_number)
        elif state.pending is None:
            # start_thread_common сбрасывает syscallno в -1 при успешном exec.
            # Новый поток может сначала получить exit родительского clone либо следующий entry.
            if state.optional_exit != stop.number or stop.registers.values[0] != 0:
                raise IsolationUnavailable
            state.optional_exit = None
        else:
            before, decision = state.pending
            # restore_sigframe сбрасывает syscallno и восстанавливает сохранённый
            # x0. Это специальная семантика только разрешённого rt_sigreturn.
            expected = -1 if decision.error_number or before.number == 139 else before.number
            if stop.number != expected:
                raise IsolationUnavailable
            result = stop.registers.values[0]
            if decision.error_number and result != (-decision.error_number & UINT64_MAX):
                raise IsolationUnavailable
            if decision.clone:
                if state.clone_child is None:
                    if not UINT64_MAX - 4094 <= result <= UINT64_MAX:
                        raise IsolationUnavailable
                    self._resolve_clone()
                elif result != state.clone_child:
                    raise IsolationUnavailable
            self.policy.after(before.number, before.arguments, result, decision)
            state.pending = None
        self._resume(tid)

    def _terminal(self, tid: int, status: int) -> None:
        if tid in self.reaped_tids:
            raise IsolationUnavailable
        self.held.discard(tid)
        previous = self.threads.pop(tid, None)
        if tid == self.leader:
            self.leader_reaped = True
            self.returncode = os.waitstatus_to_exitcode(status)
        if previous is None:
            self._early_child(tid)
            self.early_stops.discard(tid)
            self.early_terminals.add(tid)
        self.reaped_tids.add(tid)
        if previous is not None and previous.phase in ('bootstrap', 'exec'):
            raise IsolationUnavailable

    def observe(self, tid: int, status: int) -> None:
        """Ни один неподтверждённый новый TID не получает возобновление."""
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            self._terminal(tid, status)
            return
        if not os.WIFSTOPPED(status):
            raise IsolationUnavailable
        self.held.add(tid)
        stopped, event = (status >> 8) & 0xFF, status >> 16
        state = self.threads.get(tid)
        if state is None:
            # Linux может отдать SIGSTOP ребёнка раньше TRACECLONE родителя
            # или уже после terminal родителя. Без события ребёнок не идёт дальше.
            if stopped != signal.SIGSTOP or event != 0 or tid in self.early_stops:
                raise IsolationUnavailable
            self._early_child(tid)
            self.early_stops.add(tid)
            return
        if state.phase == 'bootstrap':
            if stopped != signal.SIGSTOP or event != 0 or tid != self.leader:
                raise IsolationUnavailable
            self.native.set_options(tid)
            state.phase = 'exec'
            self._resume(tid, syscall=False)
        elif state.phase == 'exec':
            if stopped != signal.SIGTRAP or event != 4 or tid != self.leader:
                raise IsolationUnavailable
            self.native.registers(tid)  # Подтвердить native EL0t после загрузки ELF.
            self.policy = self.on_exec()
            state.phase, state.optional_exit = 'running', -1
            self._resume(tid)
        elif state.phase == 'new':
            if stopped != signal.SIGSTOP or event != 0:
                raise IsolationUnavailable
            self._new_thread(tid)
        elif event:
            if stopped != signal.SIGTRAP or event != 3:
                raise IsolationUnavailable
            self._clone(tid, state)
        elif stopped == signal.SIGTRAP | 0x80:
            self._syscall(tid, state)
        else:
            # SIGSTOP не может превратить loop в непрерывные group-stop. Прочие
            # сигналы доставляются tracee; SIGKILL ядро обрабатывает самостоятельно.
            self._resume(tid, delivered_signal=0 if stopped == signal.SIGSTOP else stopped)

    def _drain(self) -> None:
        for fd, buffer in tuple(self.streams.items()):
            while True:
                try:
                    data = os.read(fd, 4096)
                except BlockingIOError:
                    break
                if not data:
                    del self.streams[fd]
                    try:
                        os.close(fd)
                    except OSError:
                        self.stream_close_failed = True
                        raise ProcessCleanupFailed from None
                    break
                if len(self._stdout) + len(self._stderr) + len(data) > self.output_limit:
                    raise OutputLimitExceeded
                buffer.extend(data)

    def _wait(self) -> tuple[int, int]:
        return wait_owned(self, WAIT_FLAGS, all_children=True)

    def _poll(self) -> bool:
        try:
            tid, status = self._wait()
        except ChildProcessError:
            if not self.leader_reaped or self.threads or self.early_stops:
                self.ownership_lost = True
                raise ProcessCleanupFailed from None
            self.all_reaped = True
            self.early_terminals.clear()
            self.unannounced_clones = 0
            return False
        if tid == 0:
            return False
        self.observe(tid, status)
        return True

    def _step(self) -> None:
        if monotonic() >= self.deadline:
            raise TimeoutError
        self._drain()
        if not self._poll() and not self.all_reaped:
            select.select(tuple(self.streams), (), (), min(0.002, max(0, self.deadline - monotonic())))

    def wait_exec(self) -> None:
        while self.policy is None:
            self._step()

    def collect(self) -> XrayTestExit:
        while not self.all_reaped:
            self._step()
        self._drain()
        if self.streams or self.policy is None or self.returncode is None:
            raise ProcessCleanupFailed
        return XrayTestExit(self.returncode, bytes(self._stdout), bytes(self._stderr), self.policy.file_access_denied)

    def terminate_and_wait(self) -> None:
        """При любом отказе не продолжать syscall; завершить и забрать только свою группу."""
        if self.ownership_lost or self.wait_uncertain:
            raise ProcessCleanupFailed
        if self.leader is None or self.all_reaped:
            return
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
        try:
            if not self.leader_reaped:
                try:
                    os.kill(self.leader, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # Проверить terminal wait; отсутствие PID ещё не подтверждает reap.
            deadline = monotonic() + CLEANUP_SECONDS
            while monotonic() < deadline:
                try:
                    tid, status = self._wait()
                except ChildProcessError:
                    if not self.leader_reaped:
                        self.ownership_lost = True
                        raise ProcessCleanupFailed from None
                    self.threads.clear()
                    self.early_stops.clear()
                    self.early_terminals.clear()
                    self.unannounced_clones = 0
                    self.held.clear()
                    self.all_reaped = True
                    return
                if tid == 0:
                    select.select((), (), (), 0.002)
                elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    self.threads.pop(tid, None)
                    self.early_stops.discard(tid)
                    self.held.discard(tid)
                    if tid == self.leader:
                        self.leader_reaped = True
                elif os.WIFSTOPPED(status):
                    # Даже ещё не объявленный TRACECLONE поток принадлежит
                    # единственному job выделенного координатора. Только SIGKILL.
                    self.native.resume(tid, syscall=False, delivered_signal=int(signal.SIGKILL))
                else:
                    raise ProcessCleanupFailed
            raise ProcessCleanupFailed
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def close_streams(self) -> None:
        failed = self.stream_close_failed
        for fd in tuple(self.streams):
            del self.streams[fd]
            try:
                os.close(fd)
            except OSError:
                failed = True
                self.stream_close_failed = True
        if failed:
            raise ProcessCleanupFailed
