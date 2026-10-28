"""Точки входа `vpn-menu` и `vpn-setup` с внедряемыми потоками.

Функции возвращают код завершения; потоки и аргументы процесса передаёт
тонкий скрипт. `vpn-menu` принимает единственный флаг `--read-router`,
который явно включает чтение роутера; `vpn-setup` аргументов не принимает.
Неверные аргументы не повторяются в сообщении. Прерывание и непредвиденная
ошибка завершаются фиксированным текстом без traceback: в нём могли бы
оказаться пути и содержимое источников.
"""

from collections.abc import Callable, Sequence

from keenvpn.interfaces.cli.composition import (
    MenuAssembly, assemble_main_menu, assemble_setup_menu, default_sources, router_sources,
)
from keenvpn.interfaces.cli.menu import MenuNavigator
from keenvpn.interfaces.cli.terminal import TextInput, TextOutput, run_menu


EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130
"""Код завершения после Ctrl+C: 128 плюс номер сигнала SIGINT."""

INTERRUPTED_MESSAGE = "Прервано."
FAILURE_MESSAGE = "Меню завершилось с внутренней ошибкой; настройки не менялись."
READ_ROUTER_FLAG = "--read-router"
"""Флаг `vpn-menu`: подключить источники чтения роутера. Без него ничего не подключается."""

Assembler = Callable[[], MenuAssembly]


def _run(assemble: Assembler, stdin: TextInput, stdout: TextOutput, stderr: TextOutput) -> int:
    try:
        assembly = assemble()
        return run_menu(MenuNavigator(assembly.menu), assembly.actions, stdin, stdout, assembly.header)
    except KeyboardInterrupt:
        stderr.write(INTERRUPTED_MESSAGE + "\n")
        return EXIT_INTERRUPTED
    except Exception:
        # Текст исключения мог бы содержать пути, содержимое источников и введённые строки.
        stderr.write(FAILURE_MESSAGE + "\n")
        return EXIT_FAILURE


def vpn_menu(argv: Sequence[str], stdin: TextInput, stdout: TextOutput, stderr: TextOutput) -> int:
    """Открыть главное меню и вернуть код завершения; `--read-router` подключает источники чтения роутера."""
    arguments = tuple(argv)
    if arguments == (READ_ROUTER_FLAG,):
        sources = router_sources
    elif not arguments:
        sources = default_sources
    else:
        stderr.write(f"vpn-menu принимает только флаг {READ_ROUTER_FLAG}.\n")
        return EXIT_USAGE
    return _run(lambda: assemble_main_menu(sources()), stdin, stdout, stderr)


def vpn_setup(argv: Sequence[str], stdin: TextInput, stdout: TextOutput, stderr: TextOutput) -> int:
    """Открыть меню мастера и вернуть код завершения."""
    if len(argv):
        stderr.write("vpn-setup не принимает аргументов.\n")
        return EXIT_USAGE
    return _run(lambda: assemble_setup_menu(default_sources()), stdin, stdout, stderr)
