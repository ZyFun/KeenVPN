"""Подготовка собственного ребёнка перед единственным разрешённым exec Xray."""

import errno
from contextlib import ExitStack
import fcntl
import os
import resource
import signal
import stat
from typing import NoReturn

from keenvpn.adapters.xray_candidate_test import IsolationUnavailable, XrayTestInvocation
from keenvpn.adapters.xray_initial_memory import STACK_LIMIT
from keenvpn.adapters.xray_linux_native import LinuxAarch64
from keenvpn.adapters.xray_private_mount import bounded_read
from keenvpn.adapters.xray_syscall_policy import MAX_DESCRIPTORS


UNPRIVILEGED_ID = 65534


def private_pipe() -> tuple[int, int]:
    """Собственная CLOEXEC pipe; оба конца выше stdin/stdout/stderr даже если те закрыты."""
    # Вызывающий блокирует обычную отмену на время создания/передачи владения fd.
    with ExitStack() as copies_scope:
        copies = []
        with ExitStack() as originals_scope:
            original = os.pipe2(os.O_CLOEXEC)
            for fd in original:
                originals_scope.callback(os.close, fd)
            for fd in original:
                duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
                copies_scope.callback(os.close, duplicate)
                copies.append(duplicate)
        result = copies[0], copies[1]
        copies_scope.pop_all()
        return result


def close_other_fds(keep: frozenset[int]) -> None:
    """Закрыть у своего процесса все fd, кроме keep; не повторять close после EINTR."""
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd in keep:
            continue
        try:
            os.close(fd)
        except OSError as error:
            if error.errno != errno.EBADF:  # Временный fd самого listdir уже закрыт.
                raise


def require_empty_child_scope() -> None:
    """Непотребляющая проверка после native guard однопоточного координатора.

    Файл proc/children необязателен в этом ядре. Только ECHILD доказывает пустоту;
    None означает возможного работающего ребёнка без готового события. WNOWAIT
    не забирает статусы, а Linux __WALL включает также clone-детей без SIGCHLD.
    """
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WSTOPPED | os.WCONTINUED
                  | os.WNOHANG | os.WNOWAIT | 0x40000000)
    except OSError as error:
        if error.errno == errno.ECHILD:
            return
        raise IsolationUnavailable from None
    except (AttributeError, TypeError, ValueError):
        raise IsolationUnavailable from None
    raise IsolationUnavailable


def _limit(kind: int, value: int) -> None:
    _, hard = resource.getrlimit(kind)
    if hard != resource.RLIM_INFINITY and hard < value:
        raise IsolationUnavailable
    resource.setrlimit(kind, (value, value))
    if resource.getrlimit(kind) != (value, value):
        raise IsolationUnavailable


def _parent_death(native: LinuxAarch64, parent_pid: int) -> None:
    native.prctl(1, int(signal.SIGKILL))
    if os.getppid() != parent_pid:
        raise IsolationUnavailable


def exec_tracee(native: LinuxAarch64, cage: str, request: XrayTestInvocation,
                stdin: int, stdout: int, stderr: int, parent_pid: int) -> NoReturn:
    """Вызывается только после собственного fork; исключения ловит child-ветка без вывода."""
    _parent_death(native, parent_pid)
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGCHLD):
        signal.signal(number, signal.SIG_DFL)
    os.dup2(stdin, 0, inheritable=True)
    os.dup2(stdout, 1, inheritable=True)
    os.dup2(stderr, 2, inheritable=True)
    close_other_fds(frozenset((0, 1, 2)))
    _limit(resource.RLIMIT_CORE, 0)
    _limit(resource.RLIMIT_FSIZE, 0)
    _limit(resource.RLIMIT_NOFILE, MAX_DESCRIPTORS)
    _limit(resource.RLIMIT_STACK, STACK_LIMIT)
    # Go резервирует большое виртуальное пространство. RSS ограничивает ledger,
    # а не RLIMIT_AS; иной унаследованный предел здесь не выдаётся за поддержку.
    if resource.getrlimit(resource.RLIMIT_AS) != (resource.RLIM_INFINITY, resource.RLIM_INFINITY):
        raise IsolationUnavailable
    os.chroot(cage)
    os.chdir('/')
    if set(os.listdir('/')) != {'parts', 'assets', 'xray'} or not os.statvfs('/').f_flag & os.ST_RDONLY:
        raise IsolationUnavailable
    os.setgroups([])
    os.setresgid(UNPRIVILEGED_ID, UNPRIVILEGED_ID, UNPRIVILEGED_ID)
    os.setresuid(UNPRIVILEGED_ID, UNPRIVILEGED_ID, UNPRIVILEGED_ID)
    native.clear_capabilities()
    native.prctl(47, 4)  # PR_CAP_AMBIENT_CLEAR_ALL.
    native.prctl(38, 1)  # PR_SET_NO_NEW_PRIVS.
    native.prctl(4, 0)  # PR_SET_DUMPABLE; exec execute-only ELF сохранит nondumpable.
    if (native.prctl(39) != 1 or native.prctl(3) != 0 or os.getresuid() != (UNPRIVILEGED_ID,) * 3
            or os.getresgid() != (UNPRIVILEGED_ID,) * 3 or os.getgroups()):
        raise IsolationUnavailable
    _parent_death(native, parent_pid)  # setresuid сбрасывает PDEATHSIG.
    native.trace_me()
    signal.pthread_sigmask(signal.SIG_SETMASK, set())
    os.kill(os.getpid(), signal.SIGSTOP)
    os.execve('/xray', ('/xray',) + request.argv[1:], dict(request.environment))
    raise IsolationUnavailable


def verify_tracee(pid: int, tgid: int, tracer: int) -> None:
    """Только собственный остановленный TID; прочитать полномочия независимо от его вывода."""
    try:
        fields = {}
        for line in bounded_read(f'/proc/{pid}/status', 65536).decode('ascii').splitlines():
            key, separator, value = line.partition(':')
            if separator:
                fields[key] = value.strip()
        if (int(fields['Pid']) != pid or int(fields['Tgid']) != tgid or int(fields['TracerPid']) != tracer
                or tuple(map(int, fields['Uid'].split())) != (UNPRIVILEGED_ID,) * 4
                or tuple(map(int, fields['Gid'].split())) != (UNPRIVILEGED_ID,) * 4 or fields['Groups']
                or any(int(fields[key], 16) for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))
                or 'NoNewPrivs' in fields and fields['NoNewPrivs'] != '1'):
            raise IsolationUnavailable
    except (ValueError, KeyError, UnicodeError):
        raise IsolationUnavailable from None
    # В Linux 4.9 каталог /proc/PID 0555 всегда показывает euid процесса.
    # У обычного файла status для UID65534 dumpable=1 дал бы владельца UID65534.
    # Значение0 обеспечивают execute-only образ, suid_dumpable=0 и запрет prctl/exec.
    if os.stat(f'/proc/{pid}/status').st_uid != 0:
        raise IsolationUnavailable


def verify_initial_fds(pid: int, stdin: os.stat_result, stdout: int, stderr: int) -> None:
    """Сверить три собственных канала; у stdin все писатели закрыты ещё до fork."""
    if set(os.listdir(f'/proc/{pid}/fd')) != {'0', '1', '2'}:
        raise IsolationUnavailable
    for number, expected in ((0, stdin), (1, os.fstat(stdout)), (2, os.fstat(stderr))):
        actual = os.stat(f'/proc/{pid}/fd/{number}')
        if not stat.S_ISFIFO(actual.st_mode) or not os.path.samestat(actual, expected):
            raise IsolationUnavailable
