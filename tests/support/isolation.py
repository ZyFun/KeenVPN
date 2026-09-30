"""Запрет терминала, файлов, сети и процессов на время проверяемого сценария."""

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import io
from pkgutil import resolve_name
from unittest.mock import patch


FORBIDDEN_CALLS = (
    "builtins.open", "builtins.input", "builtins.print", "builtins.eval", "builtins.exec",
    "getpass.getpass", "os.get_terminal_size", "shutil.get_terminal_size", "os.isatty",
    "io.open", "io.FileIO",
    "os.open", "os.read", "os.write", "os.stat", "os.lstat", "os.listdir", "os.scandir",
    "os.replace", "os.rename", "os.remove", "os.unlink", "os.mkdir",
    "os.system", "os.popen", "os.posix_spawn", "os.posix_spawnp", "os.fork", "os.execv", "os.execve",
    "subprocess.Popen",
    "socket.socket", "socket.create_connection", "socket.getaddrinfo",
    "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo",
)
# Цели импортируются один раз при загрузке модуля, до запрета exec/open: иначе
# первая загрузка getpass внутри patch сама нарушила бы изоляцию.
_TARGETS = tuple(
    (name, resolve_name(owner), attribute)
    for name in FORBIDDEN_CALLS
    for owner, _, attribute in (name.rpartition("."),)
)


class _TerminalProbe(io.StringIO):
    """Поток, который фиксирует проверку терминала даже при перехваченном отказе."""

    def __init__(self) -> None:
        super().__init__()
        self.probed = False

    def isatty(self) -> bool:
        self.probed = True
        raise AssertionError("Сценарий проверял терминал.")


class _ForbiddenStdin(_TerminalProbe):
    def __init__(self) -> None:
        super().__init__()
        self.attempted = False

    def read(self, *args: object) -> str:
        self.attempted = True
        raise AssertionError("Сценарий читал stdin.")

    readline = read
    readlines = read
    __next__ = read

    @property
    def buffer(self):
        # Бинарное чтение запрещено так же, как текстовое.
        self.attempted = True
        raise AssertionError("Сценарий обращался к бинарному stdin.")


@contextmanager
def forbid_external_effects() -> Iterator[None]:
    """Подменить опасные вызовы отказом и проверить, что их не было.

    Проверка при выходе, в том числе по исключению блока, ловит и вызов, чей
    AssertionError сценарий перехватил через `except Exception`. Нарушение
    заменяет исключение блока, которое остаётся в `__context__`. Вывод
    в stdout/stderr тоже запрещён.
    """
    output = _TerminalProbe()
    stdin = _ForbiddenStdin()
    with ExitStack() as stack:
        calls = {
            name: stack.enter_context(patch.object(target, attribute, side_effect=AssertionError(f"Запрещён вызов {name}.")))
            for name, target, attribute in _TARGETS
        }
        stack.enter_context(patch("sys.stdin", stdin))
        stack.enter_context(patch("sys.__stdin__", stdin))
        stack.enter_context(patch("sys.__stdout__", output))
        stack.enter_context(patch("sys.__stderr__", output))
        stack.enter_context(redirect_stdout(output))
        stack.enter_context(redirect_stderr(output))
        try:
            yield
        finally:
            # Проверка выполняется и при исключении блока: иначе внешний
            # assertRaises прошёл бы, хотя сценарий перехватил запрещённый вызов.
            used = [name for name, mock in calls.items() if mock.called]
            if used:
                raise AssertionError(f"Сценарий обращался к запрещённым вызовам: {', '.join(used)}.")
            if stdin.attempted:
                raise AssertionError("Сценарий читал stdin.")
            if stdin.probed or output.probed:
                raise AssertionError("Сценарий проверял терминал.")
            if output.getvalue():
                raise AssertionError("Сценарий писал в терминал.")
