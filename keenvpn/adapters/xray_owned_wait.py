"""Consuming wait с защитой от повторного использования уже освобождённого PID."""

from dataclasses import dataclass
import os
import signal
from typing import Protocol


class ProcessCleanupFailed(Exception):
    """Владение процессом или завершение очистки не подтверждено."""


class WaitOwner(Protocol):
    leader: int | None
    leader_reaped: bool
    ownership_lost: bool
    wait_uncertain: bool
    terminal_status: int | None


@dataclass(slots=True, repr=False)
class WorkerOwnership:
    """Единственный прямой ребёнок вызывающего CLI; остальные дети CLI не затрагиваются."""

    leader: int | None = None
    leader_reaped: bool = False
    ownership_lost: bool = False
    wait_uncertain: bool = False
    terminal_status: int | None = None


def wait_owned(owner: WaitOwner, flags: int, *, all_children: bool = False) -> tuple[int, int]:
    """all_children разрешён только выделенному координатору без посторонних детей.

Даже невозвращённый Python результат может означать уже выполненный reap.
Неопределённость запрещает последующий kill по сохранённому PID. Фиксация
terminal/ECHILD предшествует восстановлению маски и доставке ожидающей отмены.
"""
    if owner.leader is None or type(owner.leader) is not int or not 0 < owner.leader < 1 << 31:
        raise ProcessCleanupFailed
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
    try:
        owner.wait_uncertain = True
        try:
            tid, status = os.waitpid(-1 if all_children else owner.leader, flags)
        except ChildProcessError:
            if not owner.leader_reaped:
                owner.ownership_lost = True
            owner.wait_uncertain = False
            raise
        except BaseException:
            owner.ownership_lost = True
            raise ProcessCleanupFailed from None
        if tid == owner.leader and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            owner.leader_reaped = True
            owner.terminal_status = status
        owner.wait_uncertain = False
        return tid, status
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
