"""Точки входа `vpn-menu` и `vpn-setup` с внедряемыми потоками.

Функции возвращают код завершения; потоки и аргументы процесса передаёт
тонкий скрипт. Прерывание и непредвиденная ошибка завершаются фиксированным
текстом без traceback: в нём могли бы оказаться пути и содержимое источников.
"""

from collections.abc import Callable, Sequence

from keenvpn.interfaces.cli.composition import MenuAssembly, assemble_main_menu, assemble_setup_menu, default_sources
from keenvpn.interfaces.cli.menu import MenuNavigator
from keenvpn.interfaces.cli.terminal import TextInput, TextOutput, run_menu


EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130
"""Код завершения после Ctrl+C: 128 плюс номер сигнала SIGINT."""

INTERRUPTED_MESSAGE = "Прервано."
FAILURE_MESSAGE = "Меню завершилось с внутренней ошибкой; настройки не менялись."

Assembler = Callable[[], MenuAssembly]


def _run(command: str, assemble: Assembler, argv: Sequence[str], stdin: TextInput, stdout: TextOutput,
         stderr: TextOutput) -> int:
    if len(argv):
        stderr.write(f"{command} не принимает аргументов.\n")
        return EXIT_USAGE
    try:
        assembly = assemble()
        return run_menu(MenuNavigator(assembly.menu), assembly.actions, stdin, stdout)
    except KeyboardInterrupt:
        stderr.write(INTERRUPTED_MESSAGE + "\n")
        return EXIT_INTERRUPTED
    except Exception:
        # Текст исключения мог бы содержать пути, содержимое источников и введённые строки.
        stderr.write(FAILURE_MESSAGE + "\n")
        return EXIT_FAILURE


def vpn_menu(argv: Sequence[str], stdin: TextInput, stdout: TextOutput, stderr: TextOutput) -> int:
    """Открыть главное меню и вернуть код завершения."""
    return _run("vpn-menu", lambda: assemble_main_menu(default_sources()), argv, stdin, stdout, stderr)


def vpn_setup(argv: Sequence[str], stdin: TextInput, stdout: TextOutput, stderr: TextOutput) -> int:
    """Открыть меню мастера и вернуть код завершения."""
    return _run("vpn-setup", lambda: assemble_setup_menu(default_sources()), argv, stdin, stdout, stderr)
