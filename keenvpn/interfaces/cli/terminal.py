"""Терминальный цикл меню: чтение строк, показ уровней и вызов доступных действий.

Потоки ввода и вывода внедряются, поэтому цикл одинаково работает с терминалом
и тестовыми потоками. В вывод попадают только фиксированные тексты, заголовки
дерева, строки шапки корня и строки, которые вернуло действие; введённые строки,
в том числе запросы поиска и введённые значения, не повторяются. Один цикл
обслуживает все уровни: подменю, список, результаты поиска, карточку элемента
и запрос значения. Запрос значения передаёт строку действию без разбора:
проверку выполняет сценарий. Цвет и скрытый ввод здесь отсутствуют.
"""

from collections.abc import Callable, Mapping, Sequence
import re
from typing import Protocol

from keenvpn.interfaces.cli.menu import (
    REASON_MESSAGES, CardLevel, InputLevel, ListLevel, MenuError, MenuList, MenuNavigator, SelectionKind,
    ValueRequest,
)
from keenvpn.interfaces.cli.search import MAX_QUERY_CHARS, MAX_QUERY_WORDS, is_number_like, parse_query


Action = Callable[[], list[str] | MenuList | ValueRequest]
"""Доступное действие пункта: возвращает строки для вывода, список элементов или запрос значения, ничего не печатает само."""
Header = Callable[[], list[str]]
"""Шапка корня: возвращает строки под заголовком корневого меню, ничего не печатает сама."""

UNAVAILABLE_MARK = "[недоступно]"
"""Пометка пункта, который показан, но не выполняется."""
PROMPT = "> "
HINT = "Введите номер пункта из списка или 0."
LIST_HINT = "Введите номер элемента из списка, текст для поиска или 0."
QUERY_HINT = (
    f"Запрос для поиска — до {MAX_QUERY_CHARS} символов и {MAX_QUERY_WORDS} слов из печатных символов и пробелов."
)
NO_MATCHES = "Совпадений нет: показанный список не изменился."
CARD_HINT = "Введите 0, чтобы вернуться к списку."
INPUT_HINT = "Введите значение или 0, чтобы вернуться в меню."
LIST_USAGE = "Номер — карточка элемента, текст — поиск по показанным строкам, 0 — назад."
EMPTY_LIST = "Список пуст."
BACK_LABEL = "Назад"
EXIT_LABEL = "Выход"
EXIT_OK = 0

MAX_INPUT_LENGTH = 1024
"""Предел строки ввода в символах без перевода строки; более длинная строка отбрасывается целиком."""
LINE_TOO_LONG = f"Строка длиннее {MAX_INPUT_LENGTH} символов не обработана."
MAX_SHOWN = 50
"""Сколько элементов списка показывается за раз; остальные выбираются по номеру или поиском."""

_CHOICE = re.compile(r"\A(0|[1-9][0-9]{0,2})\Z")


class TextInput(Protocol):
    """Источник строк ввода: не больше `size` символов за вызов, пустая строка означает конец ввода."""

    def readline(self, size: int = -1, /) -> str: ...


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


def _chunk(stdin: TextInput) -> str:
    chunk = stdin.readline(MAX_INPUT_LENGTH + 1)
    if type(chunk) is not str:
        raise TypeError("Поток ввода меню должен возвращать строки.")
    return chunk


def read_line(stdin: TextInput) -> tuple[str | None, bool]:
    """Прочитать строку; вернуть её и признак превышения предела, а в конце ввода — None.

    Строка длиннее предела дочитывается до перевода строки и отбрасывается,
    чтобы её хвост не был принят за следующую команду; память при этом
    ограничена пределом.
    """
    chunk = _chunk(stdin)
    if chunk == "":
        return None, False
    if chunk.endswith("\n") or len(chunk) <= MAX_INPUT_LENGTH:
        return chunk, False
    while chunk != "" and not chunk.endswith("\n"):
        chunk = _chunk(stdin)
    return "", True


def render_menu(navigator: MenuNavigator, header: Sequence[str] = ()) -> list[str]:
    """Собрать строки текущего уровня: путь, шапку в корне, все пункты с пометками и `0`."""
    lines = [" / ".join(navigator.titles)]
    if navigator.depth == 0:
        lines.extend(header)
    for item in navigator.current.items:
        mark = "" if item.available else f" {UNAVAILABLE_MARK}"
        lines.append(f"{item.number:>3}. {item.title}{mark}")
    lines.append(f"  0. {BACK_LABEL if navigator.depth else EXIT_LABEL}")
    return lines


def render_list(navigator: MenuNavigator) -> list[str]:
    """Собрать строки открытого списка или результатов поиска: не больше `MAX_SHOWN` элементов."""
    level = navigator.current
    if type(level) is not ListLevel:
        raise MenuError("Открытый уровень — не список.")
    lines = [" / ".join(navigator.titles)]
    if level.filtered:
        lines.append(f"Найдено: {len(level.entries)} из {len(level.source.entries)}.")
    else:
        lines.extend(level.source.header)
    entries = level.entries
    if not entries:
        lines.append(EMPTY_LIST)
    for entry in entries[:MAX_SHOWN]:
        lines.append(f"{entry.number:>3}. {entry.label}")
    if len(entries) > MAX_SHOWN:
        lines.append(f"Показаны первые {MAX_SHOWN} из {len(entries)}: уточните поиск или введите номер.")
    lines += [LIST_USAGE, f"  0. {BACK_LABEL}"]
    return lines


def render_card(navigator: MenuNavigator) -> list[str]:
    """Собрать строки карточки элемента и `0`."""
    level = navigator.current
    if type(level) is not CardLevel:
        raise MenuError("Открытый уровень — не карточка.")
    return [" / ".join(navigator.titles), *level.entry.card, f"  0. {BACK_LABEL}"]


def render_input(navigator: MenuNavigator) -> list[str]:
    """Собрать строки запроса значения: путь, подсказку запроса и `0`; введённое значение не выводится."""
    level = navigator.current
    if type(level) is not InputLevel:
        raise MenuError("Открытый уровень — не запрос значения.")
    return [" / ".join(navigator.titles), *level.request.prompt, f"  0. {BACK_LABEL}"]


def render_level(navigator: MenuNavigator, header: Sequence[str] = ()) -> list[str]:
    """Собрать строки открытого уровня любого вида; шапка показывается только в корневом меню."""
    level = navigator.current
    if type(level) is ListLevel:
        return render_list(navigator)
    if type(level) is CardLevel:
        return render_card(navigator)
    if type(level) is InputLevel:
        return render_input(navigator)
    return render_menu(navigator, header)


class _RootHeader:
    """Строки шапки корня: выполняются при входе в корень и повторяются без вызова, пока корень открыт."""

    def __init__(self, header: Header | None) -> None:
        self._header = header
        self._lines: list[str] | None = None

    def lines(self, navigator: MenuNavigator) -> list[str]:
        """Строки для текущего уровня; вне корня шапки нет и она не выполняется."""
        if self._header is None or navigator.depth != 0:
            return []
        if self._lines is None:
            self._lines = list(self._header())
        return self._lines

    def track(self, navigator: MenuNavigator) -> None:
        """Забыть строки после выхода из корня: следующий вход в корень выполнит шапку заново."""
        if navigator.depth != 0:
            self._lines = None


def _flush(stream: TextOutput) -> None:
    flush = getattr(stream, "flush", None)
    if callable(flush):
        flush()


def _menu_step(
    navigator: MenuNavigator, actions: Mapping[str, Action], line: str, root: _RootHeader,
) -> list[str] | None:
    choice = parse_choice(line)
    if choice is None:
        return [HINT, "", *render_menu(navigator, root.lines(navigator))]
    selection = navigator.select(choice)
    if selection.kind is SelectionKind.EXIT:
        return None
    if selection.kind is SelectionKind.UNKNOWN:
        return [HINT, "", *render_menu(navigator, root.lines(navigator))]
    if selection.kind is SelectionKind.UNAVAILABLE:
        return [REASON_MESSAGES[selection.reason], "", *render_menu(navigator, root.lines(navigator))]
    if selection.kind is SelectionKind.ACTION:
        action = actions.get(selection.action_id)
        if action is None:
            raise MenuError("Для доступного действия не задан обработчик.")
        result = action()
        if type(result) is MenuList:
            navigator.open_list(result)
            return ["", *render_list(navigator)]
        if type(result) is ValueRequest:
            navigator.open_input(selection.item.title, result)
            return ["", *render_input(navigator)]
        return ["", *result, "", *render_menu(navigator, root.lines(navigator))]
    return render_level(navigator, root.lines(navigator))


def _list_step(navigator: MenuNavigator, line: str, root: _RootHeader) -> list[str]:
    choice = parse_choice(line)
    if choice is not None:
        selection = navigator.select(choice)
        if selection.kind is SelectionKind.UNKNOWN:
            return [LIST_HINT, "", *render_list(navigator)]
        return render_level(navigator, root.lines(navigator))
    text = line.strip()
    if not text or is_number_like(text):
        return [LIST_HINT, "", *render_list(navigator)]
    query = parse_query(text)
    if query is None:
        return [QUERY_HINT, "", *render_list(navigator)]
    if navigator.search(query).kind is SelectionKind.NO_MATCHES:
        return [NO_MATCHES, "", *render_list(navigator)]
    return render_list(navigator)


def _card_step(navigator: MenuNavigator, line: str, root: _RootHeader) -> list[str]:
    if parse_choice(line) == 0:
        navigator.back()
        return render_level(navigator, root.lines(navigator))
    return [CARD_HINT, "", *render_card(navigator)]


def _input_step(navigator: MenuNavigator, line: str, root: _RootHeader) -> list[str]:
    """Принять значение: `0` — возврат без выполнения, пустая строка — подсказка, иначе строка передаётся действию.

    Уровень закрывается до вызова действия, поэтому результат или отказ
    показывается перед подменю, из которого открыт запрос; введённая строка
    без перевода строки передаётся как есть и в вывод не попадает.
    """
    if parse_choice(line) == 0:
        navigator.back()
        return render_level(navigator, root.lines(navigator))
    value = line.rstrip("\r\n")
    if not value.strip():
        return [INPUT_HINT, "", *render_input(navigator)]
    request = navigator.current.request
    navigator.back()
    result = request.submit(value)
    if type(result) is not list or any(type(item) is not str for item in result):
        raise MenuError("Приём значения возвращает список строк.")
    return ["", *result, "", *render_menu(navigator, root.lines(navigator))]


def run_menu(
    navigator: MenuNavigator, actions: Mapping[str, Action], stdin: TextInput, stdout: TextOutput,
    header: Header | None = None,
) -> int:
    """Выполнять цикл до `0` в корне или конца ввода; вернуть код завершения.

    В подменю нераспознанная строка, включая пустую, и неизвестный номер дают
    подсказку и повторный показ без смены состояния; недоступный пункт
    показывает заранее заданную причину. В списке номер открывает карточку,
    другой текст — поиск по показанным строкам, `0` возвращает на один уровень;
    пустая строка и ошибочный ввод ничего не меняют. В запросе значения `0`
    возвращает в подменю без выполнения, пустая строка повторяет подсказку,
    любая другая строка передаётся действию и закрывает запрос. Строка длиннее
    предела отбрасывается на любом уровне. Шапка корня выполняется при старте и при
    каждом возврате в корень; повторный показ корня после подсказки или
    действия в нём выводит те же строки без нового вызова. `KeyboardInterrupt`
    не перехватывается: его обрабатывает точка входа.
    """
    def show(lines: list[str]) -> None:
        stdout.write("\n".join(lines) + "\n")
        _flush(stdout)

    root = _RootHeader(header)
    show(render_level(navigator, root.lines(navigator)))
    while True:
        stdout.write(PROMPT)
        _flush(stdout)
        line, too_long = read_line(stdin)
        if line is None:
            stdout.write("\n")
            _flush(stdout)
            return EXIT_OK
        if too_long:
            show([LINE_TOO_LONG, "", *render_level(navigator, root.lines(navigator))])
            continue
        level = navigator.current
        if type(level) is ListLevel:
            show(_list_step(navigator, line, root))
        elif type(level) is CardLevel:
            show(_card_step(navigator, line, root))
        elif type(level) is InputLevel:
            show(_input_step(navigator, line, root))
        else:
            lines = _menu_step(navigator, actions, line, root)
            if lines is None:
                return EXIT_OK
            show(lines)
        root.track(navigator)
