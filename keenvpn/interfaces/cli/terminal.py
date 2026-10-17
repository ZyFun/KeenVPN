"""Терминальный цикл меню: чтение строк, показ пунктов и вызов доступных действий.

Потоки ввода и вывода внедряются, поэтому цикл одинаково работает с терминалом
и тестовыми потоками. В вывод попадают только фиксированные тексты, заголовки
дерева и строки, которые вернуло действие; введённые строки не повторяются.
Цвет, поиск, выбор в списках и запросы значений здесь отсутствуют.
"""

from collections.abc import Callable, Mapping
import re
from typing import Protocol

from keenvpn.interfaces.cli.menu import REASON_MESSAGES, MenuError, MenuNavigator, SelectionKind


Action = Callable[[], list[str]]
"""Доступное действие пункта: возвращает строки для вывода, ничего не печатает само."""

UNAVAILABLE_MARK = "[недоступно]"
"""Пометка пункта, который показан, но не выполняется."""
PROMPT = "> "
HINT = "Введите номер пункта из списка или 0."
BACK_LABEL = "Назад"
EXIT_LABEL = "Выход"
EXIT_OK = 0

_CHOICE = re.compile(r"\A(0|[1-9][0-9]{0,2})\Z")


class TextInput(Protocol):
    """Источник строк ввода: пустая строка означает конец ввода."""

    def readline(self) -> str: ...


class TextOutput(Protocol):
    """Приёмник текста."""

    def write(self, text: str) -> int: ...


def parse_choice(line: str) -> int | None:
    """Распознать номер пункта: `0` или 1–999 ASCII-цифрами без ведущих нулей; иначе None."""
    if type(line) is not str:
        return None
    text = line.strip()
    if _CHOICE.fullmatch(text) is None:
        return None
    return int(text)


def render_menu(navigator: MenuNavigator) -> list[str]:
    """Собрать строки текущего уровня: путь, все пункты с пометками и `0`."""
    lines = [" / ".join(navigator.titles)]
    for item in navigator.current.items:
        mark = "" if item.available else f" {UNAVAILABLE_MARK}"
        lines.append(f"{item.number:>3}. {item.title}{mark}")
    lines.append(f"  0. {BACK_LABEL if navigator.depth else EXIT_LABEL}")
    return lines


def _flush(stream: TextOutput) -> None:
    flush = getattr(stream, "flush", None)
    if callable(flush):
        flush()


def run_menu(navigator: MenuNavigator, actions: Mapping[str, Action], stdin: TextInput, stdout: TextOutput) -> int:
    """Выполнять цикл до `0` в корне или конца ввода; вернуть код завершения.

    Нераспознанная строка, включая пустую, и неизвестный номер дают подсказку
    и повторный показ меню без смены состояния. Недоступный пункт показывает
    заранее заданную причину. `KeyboardInterrupt` не перехватывается: его
    обрабатывает точка входа.
    """
    def show(lines: list[str]) -> None:
        stdout.write("\n".join(lines) + "\n")
        _flush(stdout)

    show(render_menu(navigator))
    while True:
        stdout.write(PROMPT)
        _flush(stdout)
        line = stdin.readline()
        if type(line) is not str:
            raise TypeError("Поток ввода меню должен возвращать строки.")
        if line == "":
            stdout.write("\n")
            _flush(stdout)
            return EXIT_OK
        choice = parse_choice(line)
        if choice is None:
            show([HINT, "", *render_menu(navigator)])
            continue
        selection = navigator.select(choice)
        if selection.kind is SelectionKind.EXIT:
            return EXIT_OK
        if selection.kind is SelectionKind.UNKNOWN:
            show([HINT, "", *render_menu(navigator)])
        elif selection.kind is SelectionKind.UNAVAILABLE:
            show([REASON_MESSAGES[selection.reason], "", *render_menu(navigator)])
        elif selection.kind is SelectionKind.ACTION:
            action = actions.get(selection.action_id)
            if action is None:
                raise MenuError("Для доступного действия не задан обработчик.")
            show(["", *action(), "", *render_menu(navigator)])
        else:
            show(render_menu(navigator))
