"""Закрытый профиль syscall для одного изолированного native AArch64 mm.

Предпосылки: неизменяемый chroot без устройств/proc/ссылок, только файлы манифеста
и execute-only ELF; при exec открыты только собственные stdin/stdout/stderr (0–2).
Stdin — читающий конец пустой pipe; все писатели закрыты до fork.
Координатор проверяет все TID и вызывает before до допуска каждого syscall.
Проверка указателей по содержимому не применяется: другие потоки могут менять их.
"""

from dataclasses import dataclass
import errno

from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, OutputLimitExceeded
from keenvpn.adapters.xray_memory_budget import (
    MAP_ANONYMOUS, MAP_FIXED, PROT_EXEC, UINT64_MAX, UnsupportedMemoryOperation, XrayMemoryBudget,
)


GO_CLONE_FLAGS = 0x50F00  # VM | FS | FILES | SIGHAND | THREAD | SYSVSEM; Go без cgo.
MAX_THREADS = 64
MAX_DESCRIPTORS = 64
AT_FDCWD = (UINT64_MAX - 99, 0xFFFFFF9C)
# Это native AArch64 Linux UAPI, а не os.O_* машины, где запущен локальный тест.
O_DIRECTORY = 0x4000
O_NOFOLLOW = 0x8000
O_LARGEFILE = 0x20000
O_NONBLOCK = 0x800
O_CLOEXEC = 0x80000
READ_OPEN_FLAGS = O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE | O_NONBLOCK
# Go передаёт F_GETFL целиком. Неизменяемые этим API биты не добавляют права;
# из изменяемых разрешён только NONBLOCK, без ASYNC/APPEND/DIRECT/NOATIME.
SETFL_FLAGS = O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE | O_NONBLOCK | 3
_DENIED_FILE_APIS = frozenset((*range(0, 17), 18, 23, 24, 26, 27, 28, 29,
                             *range(32, 48), *range(49, 56), 58, 59, 60,
                             65, 66, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77,
                             *range(81, 90), 221, 262, 263, 264, 265, 267, 276,
                             279, 281, 285, 286, 287))
_FILE_READS = frozenset((17, 25, 48, 56, 57, 61, 62, 63, 67, 78, 79, 80))
_DENIED_PROCESS_APIS = frozenset((97, 117, 167, 216, 219, 268, 270, 271, 280, 282,
                                283, 284, 288, 289, 290, 293, 435))
_DENIED_NETWORK_APIS = frozenset((*range(198, 213), 242, 243, 269))
_SCALAR_FREE = frozenset((17, 93, 94, 101, 113, 115, 124, 128, 132, 134, 135, 139, 160,
                          163, 169, 172, 173, 174, 175, 176, 177, 178, 232))
# Выход, ожидание/часы, сигналы своего процесса, чтение rlimit/идентичности,
# uname и mincore в уже доступный оплаченный буфер. Uname только копирует
# фиксированную UTS-структуру, без файлов, новых fd и изменения настроек ОС.
# Всё прочее закрыто.


@dataclass(frozen=True, slots=True)
class Decision:
    """errno=0 разрешает вызов; остальное требует реального пропуска ядром."""

    error_number: int = 0
    clone: bool = False


def _fd(value: int) -> bool:
    # int-параметры ядра усекаются до 32 бит: алиасы вида 2**32+1 недопустимы.
    return 0 <= value < MAX_DESCRIPTORS


def _directory_fd(value: int) -> bool:
    return _fd(value) or value in AT_FDCWD


class XraySyscallPolicy:
    """Общие счётчики всех потоков; резервирование не зависит от результата syscall."""

    def __init__(self, memory: XrayMemoryBudget, tgid: int, output_limit: int,
                 stack_range: tuple[int, int]) -> None:
        if (type(tgid) is not int or not 0 < tgid < 1 << 31
                or type(output_limit) is not int or not 0 < output_limit <= 65536):
            raise IsolationUnavailable
        if (type(stack_range) is not tuple or len(stack_range) != 2
                or any(type(v) is not int or not 0 < v <= UINT64_MAX or v % 4096 for v in stack_range)
                or not stack_range[0] < stack_range[1]):
            raise IsolationUnavailable
        self.memory = memory
        self.tgid = tgid
        self.output_limit = output_limit
        self.output_reserved = 0
        self.threads_reserved = 1
        self.file_access_denied = False
        self._stack_range = stack_range

    def _touches_stack(self, address: int, length: int) -> bool:
        # Защищаем весь заранее оплаченный возможный рост, не только текущий VMA.
        # Разбиение VM_GROWSDOWN могло бы создать несколько независимо растущих VMA.
        end = address + ((length + 4095) & -4096)
        return end > UINT64_MAX or address < self._stack_range[1] and end > self._stack_range[0]

    def _file_denial(self) -> Decision:
        self.file_access_denied = True
        return Decision(errno.EACCES)

    def before(self, number: int, args: tuple[int, ...], tids: frozenset[int]) -> Decision:
        """Проверить скалярные аргументы, оплачивая рост до возобновления TID."""
        if (type(number) is not int or type(args) is not tuple or len(args) != 6
                or any(type(v) is not int or not 0 <= v <= UINT64_MAX for v in args)):
            raise IsolationUnavailable
        a, b, c, d, _, _ = args
        if number in _DENIED_FILE_APIS:
            return self._file_denial()
        if number == 56:  # openat: путь всегда разрешается внутри неизменяемого chroot.
            if not _directory_fd(a) or c & ~READ_OPEN_FLAGS:
                return self._file_denial()
            return Decision()
        if number == 57:  # Не позволять заменить stdout/stderr через повторное использование fd.
            return Decision() if _fd(a) and a not in (1, 2) else self._file_denial()
        if number == 64:
            if not _fd(a):
                return self._file_denial()
            if a in (1, 2):
                if c > self.output_limit - self.output_reserved:
                    raise OutputLimitExceeded
                self.output_reserved += c
            # Другие fd — stdin только для чтения, readonly файлы либо собственные eventfd.
            # В частности, здесь нет чужой консоли/сокета/pipe с выходом за клетку.
            return Decision()
        if number in (61, 62, 63, 67, 80):
            return Decision() if _fd(a) else self._file_denial()
        if number in (48, 78, 79):
            return Decision() if _directory_fd(a) else self._file_denial()
        if number == 25:  # fcntl: без дублирования fd и асинхронных сигналов чужому PID.
            if not _fd(a):
                return self._file_denial()
            if b in (1, 3) or b == 2 and c <= 1 or b == 4 and c & ~SETFL_FLAGS == 0:
                return Decision()
            return self._file_denial()
        if number == 222:
            if c & PROT_EXEC or d & MAP_FIXED and self._touches_stack(a, b):
                return Decision(errno.EPERM) if d & MAP_ANONYMOUS else self._file_denial()
            try:
                self.memory.before_mmap(a, b, c, d)
            except UnsupportedMemoryOperation:
                raise IsolationUnavailable from None
            return Decision()
        if number == 226:
            if c & PROT_EXEC or self._touches_stack(a, b):
                # Адрес может относиться к файлу: без безопасной классификации
                # такого отказа нельзя продолжать и впоследствии вернуть PASSED.
                raise IsolationUnavailable
            try:
                self.memory.before_mprotect(a, b, c)
            except UnsupportedMemoryOperation:
                raise IsolationUnavailable from None
            return Decision()
        if number == 215:
            if self._touches_stack(a, b):
                raise IsolationUnavailable
            return Decision()
        if number == 214:
            self.memory.before_brk(a)
            return Decision()
        if number == 233:  # Только освобождение; не разрешать populate/foreign-memory API.
            return Decision() if c in (4, 8) else Decision(errno.EINVAL)
        if number == 220:
            if a != GO_CLONE_FLAGS or b == 0 or self.threads_reserved >= MAX_THREADS:
                return Decision(errno.EAGAIN)
            self.threads_reserved += 1
            return Decision(clone=True)
        if number == 98:  # FUTEX_WAIT_PRIVATE / FUTEX_WAKE_PRIVATE, только в собственном mm.
            return Decision() if b in (128, 129) else Decision(errno.ENOSYS)
        if number == 131:
            return Decision() if a == self.tgid and b in tids and 0 <= c <= 64 else Decision(errno.EPERM)
        if number == 129:
            return Decision() if a == self.tgid and 0 <= b <= 64 else Decision(errno.EPERM)
        if number == 123:
            return Decision() if a == 0 or a in tids else Decision(errno.EPERM)
        if number == 261:  # prlimit64 только GET для текущего процесса.
            return Decision() if a in (0, self.tgid) and c == 0 else Decision(errno.EPERM)
        if number == 278:  # getrandom, без дескрипторов и сети.
            return Decision() if c & ~3 == 0 else Decision(errno.EINVAL)
        if number == 19:  # eventfd2 для внутреннего Go netpoller, не сеть.
            return Decision() if a <= 0xFFFFFFFF and b & ~(0x80000 | 0x800 | 1) == 0 else Decision(errno.EINVAL)
        if number == 20:  # epoll_create1.
            return Decision() if a & ~0x80000 == 0 else Decision(errno.EINVAL)
        if number == 21:  # epoll_ctl, объекты всех доступных fd принадлежат клетке.
            return Decision() if _fd(a) and _fd(c) else Decision(errno.EBADF)
        if number == 22:  # epoll_pwait.
            return Decision() if _fd(a) else Decision(errno.EBADF)
        if number in _SCALAR_FREE:
            return Decision()
        if number in _DENIED_NETWORK_APIS:
            return Decision(errno.EPERM)
        if number in _DENIED_PROCESS_APIS:
            return Decision(errno.ENOSYS)
        # Неизвестный API нельзя молча считать нефайловым: иначе файловый запрет
        # мог бы потеряться в общей ветке ENOSYS и привести к ложному PASSED.
        raise IsolationUnavailable

    def after(self, number: int, args: tuple[int, ...], result: int, decision: Decision) -> None:
        """Наблюдать отказ файлового API по ядру, не по stderr или exit code Xray."""
        if decision.error_number:
            return
        error_number = (1 << 64) - result if (1 << 64) - 4095 <= result <= UINT64_MAX else 0
        if number in _FILE_READS and error_number in (errno.EACCES, errno.EPERM, errno.EROFS):
            self.file_access_denied = True
        if number in (222, 226) and error_number in (errno.EACCES, errno.EPERM, errno.EROFS):
            if number == 222 and not args[3] & MAP_ANONYMOUS:
                self.file_access_denied = True
            else:
                raise IsolationUnavailable
        if number == 64 and args[0] not in (1, 2) and error_number in (
                errno.EBADF, errno.EACCES, errno.EPERM, errno.EROFS):
            self.file_access_denied = True
