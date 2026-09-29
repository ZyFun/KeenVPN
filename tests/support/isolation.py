"""Запрет терминала, файлов, сети и процессов на время проверяемого сценария."""

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import io
from unittest.mock import patch


FORBIDDEN_CALLS = (
    "builtins.open", "builtins.input", "builtins.print", "builtins.eval", "builtins.exec",
    "io.open", "io.FileIO",
    "os.open", "os.stat", "os.lstat", "os.listdir", "os.scandir",
    "os.replace", "os.rename", "os.remove", "os.unlink", "os.mkdir",
    "os.system", "os.popen", "os.posix_spawn", "os.posix_spawnp", "os.fork", "os.execv", "os.execve",
    "subprocess.Popen",
    "socket.socket", "socket.create_connection", "socket.getaddrinfo",
    "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo",
)


class _ForbiddenStdin(io.StringIO):
    def read(self, *args: object) -> str:
        raise AssertionError("Сценарий читал stdin.")

    readline = read


@contextmanager
def forbid_external_effects() -> Iterator[None]:
    """Подменить опасные вызовы отказом и проверить, что их не было.

    Проверка при выходе, в том числе по исключению блока, ловит и вызов, чей
    AssertionError сценарий перехватил через `except Exception`. Нарушение
    заменяет исключение блока, которое остаётся в `__context__`. Вывод
    в stdout/stderr тоже запрещён.
    """
    output = io.StringIO()
    with ExitStack() as stack:
        calls = {
            name: stack.enter_context(patch(name, side_effect=AssertionError(f"Запрещён вызов {name}.")))
            for name in FORBIDDEN_CALLS
        }
        stack.enter_context(patch("sys.stdin", _ForbiddenStdin()))
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
            if output.getvalue():
                raise AssertionError("Сценарий писал в терминал.")
