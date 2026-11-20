"""Интерактивный терминал KeenVPN. Данные и разрешения действий приходят из сборки меню."""

from collections.abc import Mapping, Sequence
from contextlib import contextmanager, ExitStack
import codecs
import os
import select
import signal
import threading
import unicodedata

from keenvpn.interfaces.cli.menu import (
    CardLevel, ConfirmationRequest, ExitNotice, InputLevel, ListLevel, Menu,
    MenuError, MenuItem, MenuList, MenuNavigator, SelectionKind, UnavailableReason, ValueRequest,
)
from keenvpn.interfaces.cli.search import parse_query
from keenvpn.interfaces.cli.report_layout import report_layout
from keenvpn.interfaces.cli.terminal import (
    CONFIRMATION_HINT, EMPTY_LIST, EXIT_OK, INPUT_ENDED, INPUT_HINT, LINE_TOO_LONG, MAX_INPUT_LENGTH,
    QUERY_HINT, Action, ExitCheck, Header, TextInput, TextOutput, parse_choice,
    render_exit_question,
)


WIDE_COLUMNS = 96
_MARK = {
    UnavailableReason.NOT_IMPLEMENTED: "ещё не реализовано",
    UnavailableReason.SOURCE_NOT_CONNECTED: "источник не подключён",
    UnavailableReason.STORAGE_NOT_CONFIRMED: "DATA не подтверждён",
    UnavailableReason.DRAFT_STORE_NOT_CONNECTED: "хранилище не подключено",
    UnavailableReason.DRAFT_DISCARD_NOT_CONNECTED: "только чтение",
    UnavailableReason.INPUT_REQUIRED: "нужен ввод",
    UnavailableReason.NO_AVAILABLE_ACTIONS: "нет доступных пунктов",
}
_RESET = "\x1b[0m"
Cell = tuple[str, str]
Palette = Mapping[str, str]

# Тона макета, ближайшие цвета xterm-256 и базовые цвета ANSI.
_DARK = {
    "paper": ("11161d", 233, 0), "strip": ("1a222d", 235, 0),
    "text": ("e0e9f5", 254, 7), "muted": ("a4b3c6", 146, 7),
    "line": ("3a4758", 60, 7), "mint": ("7be0cb", 116, 6),
    "picked": ("183630", 23, 0), "good": ("8adeab", 115, 2),
    "amber": ("ffca7a", 222, 3), "coral": ("db9697", 174, 1),
    "locked": ("261e25", 235, 0),
}
_LIGHT = {
    "paper": ("f6f8fc", 255, 7), "strip": ("eaf0f7", 254, 7),
    "text": ("192533", 235, 0), "muted": ("536277", 60, 0),
    "line": ("b8c4d3", 249, 0), "mint": ("006254", 23, 6),
    "picked": ("d7eee7", 194, 7), "good": ("24623c", 22, 2),
    "amber": ("81510f", 94, 3), "coral": ("884045", 95, 1),
    "locked": ("f4e9ea", 224, 7),
}
_SURFACES = {
    "": ("text", "paper"), "muted": ("muted", "paper"), "line": ("line", "paper"),
    "accent": ("mint", "paper"), "brand": ("mint", "strip"), "bar": ("muted", "strip"),
    "bar_text": ("text", "strip"),
    "picked": ("text", "picked"), "indicator": ("mint", "picked"),
    "locked": ("coral", "locked"), "warning": ("coral", "paper"),
    "good": ("good", "paper"), "amber": ("amber", "paper"),
}
_SECTION_CAPTIONS = {
    "Состояние и быстрые действия": "Сводка, состояние перехвата и управление работающей конфигурацией.",
    "Мастер установки и настройки": "Установка, первое подключение меню, перенастройка и восстановление.",
    "VPN-подключения": "Профили, резервные подключения, проверка и выбор пути.",
    "Правила маршрутизации": "Правила Xray, их порядок и объяснение выбора маршрута.",
    "Устройства и политики": "Устройства сети, индивидуальные назначения и режимы сегментов.",
    "Автозапуск, DNS и поведение при сбое": "Поведение после загрузки, при отказе VPN и при обработке DNS.",
    "Черновик и применение": "Проверка, просмотр изменений и подтверждение черновика.",
    "Резервные копии и восстановление": "Архивы настроек, расписание, проверка и восстановление.",
    "Обслуживание и диагностика": "Статистика, диагностика, версии компонентов и обновления.",
    "Настройки меню": "Размещение данных, лимиты истории, параметры вывода и справка.",
}
_ACTION_CAPTIONS = {
    "status.summary": "Состояние семи областей роутера. У непрочитанных источников показан статус проверки.",
    "status.quick_check": "Статическая сверка источников и проверок без активной сетевой пробы.",
    "connections.list": "Выходы и балансировщики из конфигурации Xray. Доступны поиск и карточки.",
    "routing.list": "Группы правил Xray в порядке конфигурации. Названия и ID зависят от метаданных.",
    "routing.explain": "Предварительный расчёт по импортированной схеме без DNS-запросов и отправки трафика.",
    "devices.list": "Снимок устройств Keenetic, их присутствия и назначенных политик.",
    "failsafe.port53_check": "Сверка списков портов и флагов XKeen. Фактический путь DNS проверяется отдельно.",
    "draft.diff": "Сравнение сохранённого черновика с исходной ревизией. Значения замаскированы.",
    "draft.check": "Проверка сохранённого черновика. Запуск Xray зависит от кандидата и условий проверки.",
    "draft.save_and_exit": "Выход с проверкой сохранённого черновика.",
    "settings.storage": "Сохранённые сведения о размещении данных и лимитах истории.",
    "settings.about": "Управление меню и версия контракта результатов.",
}


def _palette(color: bool) -> Palette:
    if not color:
        return {}
    term = os.environ.get("TERM", "").lower()
    truecolor = os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit") or "direct" in term
    indexed = "256" in term or term.startswith(("xterm", "screen", "tmux", "rxvt"))
    background = os.environ.get("COLORFGBG", "").split(";")[-1]
    tones = _LIGHT if background in ("7", "15") else _DARK

    def sgr(name: str, foreground: bool) -> str:
        rgb, index, basic = tones[name]
        code = 38 if foreground else 48
        if truecolor:
            red, green, blue = bytes.fromhex(rgb)
            return f"{code};2;{red};{green};{blue}"
        if indexed:
            return f"{code};5;{index}"
        return str((30 if foreground else 40) + basic)

    styles = {role: f"\x1b[{sgr(fg, True)};{sgr(bg, False)}m" for role, (fg, bg) in _SURFACES.items()}
    if not (indexed or truecolor):
        # У восьмицветной палитры нет полутонов. Сохраняем контраст заливок и текста.
        styles.update(brand="\x1b[36;44m", bar="\x1b[37;44m", bar_text="\x1b[37;44m", picked="\x1b[30;46m",
                      indicator="\x1b[30;46m", locked="\x1b[37;41m")
    return styles


def _safe(text: str) -> str:
    """Сохранить печатный текст, исключая управляющие последовательности даже в ответах действий."""
    return "".join(ch if ch.isprintable() else " " for ch in text)


def _width(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _length(text: str) -> int:
    return sum(map(_width, text))


def _wrap(text: str, width: int) -> list[str]:
    """Разбить строку по ширине терминала с переносом по пробелу, включая широкие символы."""
    text = _safe(text)
    if not text:
        return [""]
    result = []
    while text:
        size = 0
        for end, char in enumerate(text):
            size += _width(char)
            if size > width:
                break
        else:
            result.append(text)
            break
        split = text.rfind(" ", 0, end + 1)
        end = split if split > 0 else max(1, end)
        result.append(text[:end].rstrip())
        text = text[end:].lstrip()
    return result


def _cells(lines: Sequence[str], width: int, style: str = "") -> list[Cell]:
    return [(part, style) for line in lines for part in _wrap(line, width)]


def _draw(cell: Cell, palette: Palette, padded: int = 0) -> str:
    text, style = cell
    size = _length(text)
    if padded and size > padded:
        # При ширине в одну ячейку может не поместиться даже маркер выбора или один иероглиф.
        while size > padded:
            size -= _width(text[-1])
            text = text[:-1]
    text += " " * max(0, padded - size)
    return palette[style] + text + _RESET if palette else text


def _report_rows(lines: Sequence[str], width: int, palette: Palette, *, facts: bool) -> list[str]:
    """В широком отчёте выровнять подписи фактов. Длинный текст сохраняет всю ширину."""
    if not facts or width < 60:
        return [_draw(cell, palette, width) for cell in _cells(lines, width)]
    pairs = [_safe(line).partition(": ") for line in lines]
    labels = {key for key, sep, value in pairs if sep and value and key == key.strip() and 0 < _length(key) <= 32}
    label_width = max(map(_length, labels), default=0) + 1
    rows = []
    for line, (key, sep, value) in zip(lines, pairs):
        if sep and key in labels and value:
            for index, part in enumerate(_wrap(value, width-label_width-3)):
                prefix = key + ":" if index == 0 else ""
                rows.append(_draw((prefix, "muted"), palette, label_width) + _draw((" │ ", "line"), palette)
                            + _draw((part, ""), palette, width-label_width-3))
        else:
            rows.extend(_draw(cell, palette, width) for cell in _cells([line], width))
    return rows


def _band(left: Cell, right: Cell, width: int, palette: Palette, marker: Cell | None = None) -> list[str]:
    """Разнести подписи к краям полосы, на узком экране перенести вторую подпись."""
    prefix = _draw(marker, palette) if marker else ""
    prefix_width = _length(marker[0]) if marker else 0
    right_width = _length(right[0])
    if prefix_width + _length(left[0]) + right_width + 2 <= width:
        return [prefix + _draw(left, palette, width-prefix_width-right_width) + _draw(right, palette)]
    if prefix_width + _length(left[0]) <= width:
        first = [prefix + _draw(left, palette, width-prefix_width)]
    else:
        full = (marker[0] if marker else "") + left[0]
        first = [_draw((part, left[1]), palette, width) for part in _wrap(full, width)]
    return first + [_draw((part, right[1]), palette, width) for part in _wrap(right[0], width)]


def _reason(item: MenuItem) -> str:
    if item.available:
        return ""
    return _MARK.get(item.reason, "нет доступных пунктов")


def _item_line(item: MenuItem) -> str:
    reason = _reason(item)
    return f"{item.number}. {item.title}" + (f" ({reason})" if reason else "")


class InteractiveMenu:
    """Состояние одного экрана TTY. Выбор и поиск использует общий MenuNavigator."""

    def __init__(self, navigator: MenuNavigator, actions: Mapping[str, Action],
                 header: Header | None = None, exit_check: ExitCheck | None = None) -> None:
        self.navigator = navigator
        self.actions = actions
        self.header = header
        self.exit_check = exit_check
        self.finished = False
        self.exit_lines: list[str] = []
        self._header_lines: list[str] | None = None
        self._positions: dict[int, int] = {}
        self._digits = ""
        self._invalid_number = False
        self._searching = False
        self._detailed_list = False
        self._technical_card = False
        self._text = ""
        self._overlong = False
        self._notice = ""
        self._report: tuple[tuple[str, tuple[str, ...]], ...] = ()
        self._report_page = 0
        self._retry: InputLevel | None = None
        self._action_id = ""
        self._device_actions: tuple[MenuItem, ...] = ()
        self._question: ConfirmationRequest | ExitNotice | None = None
        self._scroll = 0
        self._page = 8
        self._list_offset: int | None = None
        self._visible_start = 0
        self._row_ranges: dict[int, range] = {}
        self._row_count = 0

    def _entries(self):
        level = self.navigator.current
        if isinstance(level, Menu):
            return level.items
        if isinstance(level, ListLevel):
            return level.entries
        return ()

    def _selectable(self) -> list[int]:
        return [item.number for item in self._entries() if not isinstance(item, MenuItem) or item.available]

    def _selection(self) -> int | None:
        selected = self._positions.get(self.navigator.depth)
        if self._list_offset is not None:
            visible = range(self._list_offset, self._list_offset + self._page)
            choices = [n for n, span in self._row_ranges.items() if span.start in visible]
        else:
            choices = self._selectable()
        if selected not in choices:
            selected = choices[0] if choices else None
        return selected

    def _reset_page(self) -> None:
        self._digits = self._text = self._notice = ""
        self._invalid_number = False
        self._searching = self._overlong = False
        self._scroll = 0
        self._list_offset = None

    def _exit(self, notice: ExitNotice | None, *, eof: bool = False) -> None:
        if notice is not None and type(notice) is not ExitNotice:
            raise MenuError("Проверка выхода возвращает ExitNotice.")
        if notice is not None and notice.confirm and not eof:
            self._question = notice
            self._reset_page()
            return
        self.finished = True
        self.exit_lines = list(notice.lines) if notice else []
        if notice and notice.confirm and eof:
            self.exit_lines.append(INPUT_ENDED)

    def _back(self) -> None:
        self._reset_page()
        if self._technical_card:
            self._technical_card = False
            return
        if self._report_page:
            self._report_page = 0
            return
        if self._report or self._question:
            self._report = ()
            self._question = self._retry = None
            return
        depth = self.navigator.depth
        if self.navigator.back().kind is SelectionKind.EXIT:
            self._exit(self.exit_check() if self.exit_check else None)
        else:
            self._positions.pop(depth, None)

    def _show_report(self, title: str, lines: Sequence[str], action_id: str = "") -> None:
        brief, sections = report_layout(action_id, lines)
        self._report = ((title, brief), *sections)
        self._report_page = self._scroll = 0

    def _open(self, number: int) -> None:
        level = self.navigator.current
        if isinstance(level, Menu):
            item = level.item(number)
            if item and not item.available:
                self._notice = f"{number}. {item.title} ({_reason(item)})"
                return
        selected = self.navigator.select(number)
        if selected.kind in (SelectionKind.UNKNOWN, SelectionKind.UNAVAILABLE):
            self._notice = "Такого доступного номера нет."
            return
        self._reset_page()
        if selected.kind is SelectionKind.ACTION:
            action = self.actions.get(selected.action_id)
            if action is None:
                raise MenuError("Для доступного действия не задан обработчик.")
            self._positions[self.navigator.depth] = number
            self._action_id = selected.action_id
            result = action()
            if type(result) is MenuList:
                self._detailed_list = False
                self._device_actions = tuple(item for item in level.items if item.number in (2, 3)) if selected.action_id == "devices.list" else ()
                self.navigator.open_list(result)
            elif type(result) is ValueRequest:
                self.navigator.open_input(selected.item.title, result)
            elif type(result) is ConfirmationRequest:
                self._question = result
            elif type(result) is ExitNotice:
                self._exit(result)
            else:
                self._show_report(selected.item.title, result, selected.action_id)
        else:
            self._positions[self.navigator.depth - 1] = number
        if self.navigator.depth:
            self._header_lines = None

    def _answer(self, value: str) -> None:
        question = self._question
        allowed = ("", "0", "1", "2") if isinstance(question, ConfirmationRequest) else ("", "1", "2")
        if value not in allowed:
            self._notice = CONFIRMATION_HINT if isinstance(question, ConfirmationRequest) else "Введите 1, 2 или пустую строку."
            return
        self._question = None
        self._reset_page()
        if value == "2":
            if isinstance(question, ConfirmationRequest):
                self._show_report("Результат действия", question.accept())
            else:
                self.finished = True

    def _edit(self, key: str) -> None:
        if key == "back":
            if self._searching:
                self._reset_page()
            else:
                self._back()
        elif key == "backspace":
            self._text = self._text[:-1]
        elif key == "enter":
            value, overflow = self._text, self._overlong
            self._text = ""
            self._overlong = False
            if overflow:
                self._notice = LINE_TOO_LONG
            elif self._searching:
                query = parse_query(value.strip())
                if not query:
                    self._notice = QUERY_HINT
                else:
                    self.navigator.search(query, show_empty=True, brief=not self._detailed_list)
                    self._reset_page()
            elif parse_choice(value) == 0:
                self._back()
            elif not value.strip():
                self._notice = INPUT_HINT
            else:
                level = self.navigator.current
                self._back()
                self._retry = level
                self._show_report(level.title, level.request.submit(value), self._action_id)
        elif len(key) == 1 and key.isprintable():
            if len(self._text) < MAX_INPUT_LENGTH and not self._overlong:
                self._text += key
            else:
                self._overlong = True

    def key(self, key: str) -> None:
        """Обработать клавишу или печатный символ; неподдерживаемая последовательность инертна."""
        if self.finished:
            return
        if key == "eof":
            if isinstance(self._question, ExitNotice):
                self.finished = True
                self.exit_lines = [*self._question.lines, INPUT_ENDED]
            else:
                self._exit(self.exit_check() if self.exit_check else None, eof=True)
            return
        level = self.navigator.current
        if key == "home" and not self._question:
            self._reset_page()
            self._report, self._retry, self._report_page = (), None, 0
            self._technical_card = False
            while self.navigator.depth:
                self._positions.pop(self.navigator.depth, None)
                self.navigator.back()
            self._header_lines = None
            return
        if self._searching or isinstance(level, InputLevel):
            self._edit(key)
            return
        if self._report and key == "tab" and len(self._report) > 1:
            self._report_page = (self._report_page + 1) % len(self._report)
            self._reset_page()
            return
        if key == "tab" and isinstance(level, CardLevel) and level.entry.preview:
            self._technical_card = not self._technical_card
            self._reset_page()
            return
        if self._report and self._retry and key.lower() in ("r", "к"):
            request = self._retry
            self._report, self._retry, self._report_page = (), None, 0
            self._reset_page()
            self.navigator.open_input(request.title, request.request)
            return
        if key in ("up", "down", "page_up", "page_down"):
            self._digits = self._notice = ""
            self._invalid_number = False
            step = -1 if key in ("up", "page_up") else 1
            step *= self._page if key.startswith("page_") else 1
            if self._report or self._question or isinstance(level, CardLevel):
                self._scroll = max(0, self._scroll + step)
            elif key.startswith("page_"):
                self._list_offset = min(max(0, self._row_count - self._page), max(0, self._visible_start + step))
            else:
                selected = self._selection()
                choices = self._selectable()
                if choices:
                    if selected is not None:
                        selected = choices[(choices.index(selected) + step) % len(choices)]
                    elif step > 0:
                        selected = next((n for n in choices if self._row_ranges[n].start >= self._visible_start), choices[0])
                    else:
                        selected = next((n for n in reversed(choices) if self._row_ranges[n].start < self._visible_start), choices[-1])
                    self._positions[self.navigator.depth] = selected
                self._list_offset = None
            return
        if key == "back":
            self._back()
            return
        if key == "backspace":
            if self._invalid_number:
                self._digits = ""
                self._invalid_number = False
            else:
                self._digits = self._digits[:-1]
            self._notice = ""
            return
        if len(key) == 1 and key in "0123456789":
            if len(self._digits) < 4:
                self._digits += key
            return
        if isinstance(level, ListLevel) and not self._report and not self._question:
            if key == "/":
                self._reset_page()
                self._searching = True
                return
            if level.source.summary and key.lower() in ("i", "ш"):
                self._reset_page()
                self._show_report("Сведения об источнике", level.source.header)
                return
            if level.source.summary and key == "tab":
                selected = self._selection()
                if level.filtered:
                    self._back()
                self._reset_page()
                if selected is not None:
                    self._positions[self.navigator.depth] = selected
                self._detailed_list = not self._detailed_list
                return
        if key != "enter":
            if len(key) == 1 and key.isprintable():
                self._invalid_number = True
                self._notice = "Ожидается номер. Backspace — очистить ввод."
            return
        if self._invalid_number:
            self._invalid_number = False
            self._digits = ""
            self._notice = "Неверный ввод. Выбор не выполнен."
            return
        value, self._digits = self._digits, ""
        if self._question:
            self._answer(value)
        elif value == "0":
            self._back()
        elif self._report or isinstance(level, CardLevel):
            if not value:
                self._back()
        else:
            number = parse_choice(value) if value else self._selection()
            if number is None:
                if value:
                    self._notice = "Введите доступный номер или 0."
            else:
                self._open(number)

    def _header(self, width: int, wide: bool, palette: Palette) -> list[str]:
        if self.header is None or self.navigator.depth or self._report or self._question:
            return []
        if self._header_lines is None:
            self._header_lines = list(self.header())
        lines = self._header_lines
        if not lines:
            return []
        areas = [line.strip().partition(": ") for line in lines if line.startswith("  ")]
        notices = [line for line in lines[1:] if not line.startswith("  ")]
        if not areas or any(not sep for _, sep, _ in areas):
            return [_draw(cell, palette, width) for cell in _cells(lines, width)]
        if not wide:
            labels = {"Ядро Xray": "Xray", "Доступность VPN": "VPN", "Черновик": "Черновик"}
            brief = "     ".join(f"{labels[name]} · {value}" for name, _, value in areas if name in labels)
            return [_draw(cell, palette, width) for cell in _cells([brief, *notices], width)]

        source_note = lines[0].removeprefix("Состояние по источникам, ").rstrip(":")
        result = _band(("Состояние роутера", "accent"), (_safe(source_note), "muted"), width, palette)
        dns_note = False
        for offset in range(0, len(areas), 4):
            columns = []
            for index, (name, _, value) in enumerate(areas[offset:offset+4]):
                cell_width = (index+1)*width//4 - index*width//4
                style = ""
                if name == "DNS и порт 53" and value.endswith(", не проверено"):
                    value = value.removesuffix(", не проверено") + "¹"
                    dns_note = True
                if value == "работает" and name == "Ядро Xray":
                    style = "good"
                elif value == "не проверено":
                    style = "amber"
                value = value[:1].upper() + value[1:]
                cells = _cells([name], cell_width-2, "muted") + _cells([value], cell_width-2, style)
                columns.append((cell_width, cells))
            for i in range(max(len(cells) for _, cells in columns)):
                row = "".join(_draw(("│ ", "line"), palette) +
                              _draw(cells[i] if i < len(cells) else ("", ""), palette, size-2)
                              for size, cells in columns)
                result.append(row + _draw(("", ""), palette, width-sum(size for size, _ in columns)))
        if dns_note:
            result.append(_draw(("¹ Работа DNS не проверялась.", "muted"), palette, width))
        return result + [_draw(cell, palette, width) for cell in _cells(notices, width, "warning")]

    def _menu_rows(self, prefix: list[Cell], width: int, marker_width: int) -> list[Cell]:
        """Запомнить экранные строки доступных пунктов с учётом заголовка и переносов."""
        cells = list(prefix)
        self._row_ranges = {}
        for entry in self._entries():
            if isinstance(entry, MenuItem):
                text = _item_line(entry)
                unavailable = not entry.available
            else:
                label = entry.label if self._detailed_list or not entry.brief else entry.brief
                text = f"{entry.number}. {label}"
                unavailable = False
            parts = _wrap(text, max(1, width-marker_width))
            if not unavailable:
                self._row_ranges[entry.number] = range(len(cells), len(cells) + len(parts))
            cells.extend((" " * marker_width + part, "locked" if unavailable else "") for part in parts)
        self._row_count = len(cells)
        return cells

    def _preview(self, width: int, roomy: bool) -> list[Cell]:
        level, selected = self.navigator.current, self._selection()
        if selected is None:
            return []
        if isinstance(level, ListLevel):
            entry = level.entry(selected)
            heading = ("Выбрано устройство" if self._action_id == "devices.list" else
                       f"{level.source.item_name} {entry.number}" if entry.preview else "Карточка")
            body = _cells(entry.preview or entry.card, width)
            if entry.preview:
                body.extend(_cells(["", "Enter · Полная карточка"], width, "accent"))
        else:
            item = level.item(selected)
            heading = "Обзор раздела" if item.submenu else "Выбранный пункт"
            body = _cells([item.title], width)
            if item.submenu:
                caption = _SECTION_CAPTIONS.get(item.title)
                if caption and not self.navigator.depth:
                    body.extend(_cells([caption], width, "muted"))
                for child in item.submenu.items:
                    body.extend(_cells([_item_line(child)], width, "" if child.available else "warning"))
            elif item.action and item.action.action_id in _ACTION_CAPTIONS:
                body.extend(_cells([_ACTION_CAPTIONS[item.action.action_id]], width, "muted"))
            command = "Открыть раздел" if item.submenu else "Выйти из меню" if item.action.action_id == "draft.save_and_exit" else "Открыть пункт"
            body.extend(_cells(["Enter · " + command], width, "accent"))
        prefix = _cells([heading], width, "accent")
        if roomy:
            prefix.append(("─" * width, "accent"))
        return prefix + body

    def _list_screen(self, width: int, height: int, wide: bool, roomy: bool, palette: Palette) -> list[str]:
        level = self.navigator.current
        if isinstance(level, ListLevel):
            wide = wide and level.source.split_preview
        left = (width-3)*42//100 if wide else width
        preface = []
        if isinstance(level, ListLevel):
            if level.filtered and not level.entries:
                empty = "Устройства не найдены." if level.source.item_name == "Устройство" else "Совпадений нет."
                preface = [empty, "Esc — очистить поиск · / — новый запрос"]
            elif level.filtered:
                preface = [f"Найдено: {len(level.entries)} из {len(level.source.entries)}."]
            elif not level.entries:
                preface = [*(level.source.summary or level.source.header), EMPTY_LIST]
            elif level.source.header:
                preface = list(level.source.summary or level.source.header)
        title = level.source.title if isinstance(level, ListLevel) else "Пункты раздела" if self.navigator.depth else "Разделы"
        if isinstance(level, ListLevel) and self._action_id == "devices.list":
            title = "Список устройств"
        prefix = _cells([title], left, "accent")
        if roomy:
            prefix.append(("─" * left, "accent"))
        prefix.extend(_cells(preface, left))
        if self._searching:
            prefix.extend(_cells(["Поиск · Введите текст и нажмите Enter."], left, "accent"))
        marker_width = 3 if roomy else 2
        full = self._menu_rows(prefix, left, marker_width)
        if self._list_offset is not None:
            self._list_offset = min(self._list_offset, max(0, len(full) - height))
        selected = self._selection()
        span = self._row_ranges.get(selected, range(0))
        offset = self._list_offset if self._list_offset is not None else min(span.start, max(0, span.stop-height))
        if selected is not None:
            self._positions[self.navigator.depth] = selected
            for index in span:
                text, _ = full[index]
                indicator = ("▎" if roomy else "") + ("› " if index == span.start else "  ")
                full[index] = (indicator + text[marker_width:], "picked")
        self._visible_start = offset
        left_cells = full[offset:offset+height]
        left_cells.extend([("", "")] * (height-len(left_cells)))
        def draw_left(cell: Cell) -> str:
            text, style = cell
            if style == "picked" and left > marker_width:
                return (_draw((text[:marker_width], "indicator"), palette) +
                        _draw((text[marker_width:], style), palette, left-marker_width))
            return _draw(cell, palette, left)

        if not wide:
            return [draw_left(cell) for cell in left_cells]
        right = width-left-3
        right_cells = self._preview(right, roomy)[:height]
        right_cells.extend([("", "")] * (height-len(right_cells)))
        divider = _draw((" │ ", "line"), palette)
        return [draw_left(a) + divider + _draw(b, palette, right)
                for a, b in zip(left_cells, right_cells)]

    def render(self, width: int, height: int, color: bool = True) -> str:
        """Собрать один кадр для фактических размеров TTY без перевода строки в последней колонке."""
        width, height = max(1, width-1), max(1, height)
        wide = width+1 >= WIDE_COLUMNS
        roomy = height >= 14 and width >= 31
        if roomy:
            width -= 4
        palette = _palette(color)

        def rule(left: str, right: str) -> str:
            return _draw((left + "─" * (width+2) + right, "line"), palette)

        def panel(rows: list[str], surface: str = "") -> list[str]:
            if not roomy:
                return rows
            edge = _draw(("│", "line"), palette)
            margin = _draw((" ", surface), palette)
            return [edge + margin + row + margin + edge for row in rows]

        level = self.navigator.current
        mode = "Обзор роутера" if wide else "Компактный SSH"
        banner = panel(_band(("KeenVPN", "bar_text"), (mode + " · Доступно сейчас", "bar"),
                             width, palette, marker=("›_ ", "brand")), "bar")
        header = [rule("┌", "┐"), *banner, rule("├", "┤")] if roomy else banner
        summary = self._header(width, wide, palette)
        if summary:
            header.extend(panel(summary))
            if roomy:
                header.append(rule("├", "┤"))
        numbers = self.navigator.section_numbers
        if (self._report or self._question or not isinstance(level, Menu)) and numbers:
            action_number = self._positions.get(len(numbers))
            if action_number is not None:
                numbers += (action_number,)
        if isinstance(level, CardLevel):
            numbers += (level.entry.number,)
        trail = " → ".join(str(number) for number in numbers)
        path = _cells([(trail + "  " if trail else "") + " › ".join(self.navigator.titles)], width, "muted")
        header.extend(panel([_draw(cell, palette, width) for cell in path]))
        footer = "↑↓ выбрать · Enter открыть · номер + Enter"
        if isinstance(level, ListLevel):
            footer += " · / поиск"
            if level.source.summary:
                toggle = "кратко" if self._detailed_list else "подробнее"
                footer = f"↑↓ выбор · Enter карточка · / поиск · Tab {toggle} · i источник"
        lines = None
        heading = ""
        if self._report:
            label, data = self._report[self._report_page]
            heading, lines = label, data
        elif self._question:
            lines = (render_exit_question(self._question) if isinstance(self._question, ExitNotice)
                     else list(self._question.lines))
        elif isinstance(level, CardLevel):
            related = ["5 → " + _item_line(item) for item in self._device_actions]
            heading = "Технические сведения" if self._technical_card else level.title
            lines = level.entry.card if self._technical_card or not level.entry.preview else (*level.entry.preview, *related)
        elif isinstance(level, InputLevel):
            heading, lines = level.title, level.request.prompt
        if lines is not None:
            footer = "↑↓ прокрутка · Esc назад"
            if len(self._report) > 1:
                next_group = self._report[self._report_page+1][0] if self._report_page+1 < len(self._report) else "Обзор"
                footer += " · Tab " + next_group
            if isinstance(level, CardLevel) and level.entry.preview:
                footer += " · Tab " + ("карточка" if self._technical_card else "технические сведения")
            if self._retry:
                footer += " · R повторить ввод"
        if isinstance(level, InputLevel) or self._searching:
            footer = f"Введено символов: {len(self._text)} · Enter подтвердить · Esc отменить"
        if self._question:
            footer = "Введите ответ и нажмите Enter · Esc отменить"
        messages = _cells([self._notice], width, "warning") if self._notice else []
        if self._digits and not self._invalid_number:
            messages += _cells(["Номер: " + self._digits], width)
        suffix = panel([_draw(cell, palette, width) for cell in messages])
        if roomy:
            suffix.append(rule("├", "┤"))
        if lines is None and not self._searching:
            back = "Home главное меню · Esc / 0+Enter Назад" if self.navigator.depth else "Esc / 0+Enter Выход"
            controls = _band((footer, "bar"), (back, "bar_text"), width, palette)
        else:
            controls = [_draw(cell, palette, width) for cell in _cells([footer], width, "bar")]
        suffix.extend(panel(controls, "bar"))
        if roomy:
            suffix.append(rule("└", "┘"))
        if len(header) + len(suffix) + 2 > height:
            # В низком окне оставляем место выбору и сообщениям об отказе.
            header = [rule("┌", "┐"), *banner[:1]] if roomy else banner[:1]
            if len(header) + len(suffix) >= height:
                header = header[:max(0, height-2)]
                suffix = suffix[:max(0, height-len(header)-1)]
        self._page = max(1, height-len(header)-len(suffix))
        if lines is None:
            content = self._list_screen(width, self._page, wide, roomy, palette)
        else:
            rows = [_draw(cell, palette, width) for cell in _cells([heading], width, "accent")] if heading else []
            if heading and roomy:
                rows.append(_draw(("─" * width, "line"), palette))
            rows.extend(_report_rows(lines, width, palette, facts=bool(self._report) and self._report_page == 0))
            self._scroll = min(self._scroll, max(0, len(rows)-self._page))
            content = rows[self._scroll:self._scroll+self._page]
            content.extend([_draw(("", ""), palette, width)] * (self._page-len(content)))
        return "\r\n".join(header + panel(content) + suffix)



class _Keys:
    """Читать клавиши с POSIX TTY без снятия ISIG. Одиночный Esc отличается от стрелок."""

    def __init__(self, fd: int, encoding: str) -> None:
        self.fd = fd
        self.decoder = codecs.getincrementaldecoder(encoding)(errors="ignore")
        self.pending = b""

    def read(self) -> str | None:
        if self.pending:
            data, self.pending = self.pending, b""
        else:
            if not select.select([self.fd], [], [], 0.25)[0]:
                return None
            data = os.read(self.fd, 1)
        if data in (b"", b"\x04"):
            return "eof"
        if data == b"\x1b":
            self.decoder.reset()
            if not select.select([self.fd], [], [], 0.09)[0]:
                return "back"
            introducer = os.read(self.fd, 1)
            if introducer not in (b"[", b"O"):
                self.pending = introducer
                return "back"
            seq = bytearray()
            while select.select([self.fd], [], [], 0.09)[0]:
                ch = os.read(self.fd, 1)
                if not ch:
                    return "eof"
                if len(seq) < 16:
                    seq.extend(ch)
                if 0x40 <= ch[0] <= 0x7e:
                    return {b"A":"up", b"B":"down", b"5~":"page_up", b"6~":"page_down",
                            b"H":"home", b"1~":"home", b"7~":"home"}.get(bytes(seq))
            return None
        if data in (b"\r", b"\n"):
            return "enter"
        if data == b"\t":
            return "tab"
        if data in (b"\x7f", b"\x08"):
            return "backspace"
        if data == b"\x03":
            raise KeyboardInterrupt
        text = self.decoder.decode(data)
        return text if text and text.isprintable() else None


def can_use_terminal(stdin: TextInput, stdout: TextOutput) -> bool:
    """Проверить доступность POSIX-режима и геометрии без изменения настроек терминала."""
    try:
        import termios
    except ImportError:
        return False
    try:
        termios.tcgetattr(stdin.fileno())
        os.get_terminal_size(stdout.fileno())
    except (AttributeError, OSError, ValueError, termios.error):
        return False
    return True


@contextmanager
def _terminal_session(fd, stdout, original, configured):
    """Восстановить TTY при штатном выходе, прерывании или завершении SSH-сессии."""
    import termios

    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    def restore_screen():
        stdout.write("\x1b[0m\x1b[?25h\x1b[?1049l")
        stdout.flush()

    with ExitStack() as cleanup:
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
                previous = signal.getsignal(signum)
                if previous == signal.SIG_DFL:
                    cleanup.callback(signal.signal, signum, previous)
                    signal.signal(signum, terminate)
        cleanup.callback(restore_screen)
        cleanup.callback(termios.tcsetattr, fd, termios.TCSANOW, original)
        termios.tcsetattr(fd, termios.TCSANOW, configured)
        stdout.write("\x1b[?1049h\x1b[?25l")
        stdout.flush()
        try:
            yield
        except BaseException:
            # Отбросить остаток большого кадра, если сигнал пришёл при заполненном буфере PTY.
            termios.tcflush(stdout.fileno(), termios.TCOFLUSH)
            raise


def run_interactive(
    navigator: MenuNavigator, actions: Mapping[str, Action], stdin: TextInput, stdout: TextOutput,
    header: Header | None = None, exit_check: ExitCheck | None = None,
) -> int:
    """Показать меню на POSIX TTY. При выходе и исключении восстановить атрибуты и экран."""
    import termios

    fd = stdin.fileno()
    out_fd = stdout.fileno()
    original = termios.tcgetattr(fd)
    configured = list(original)
    configured[6] = list(original[6])
    configured[3] &= ~(termios.ICANON | termios.ECHO | termios.ECHONL)
    configured[6][termios.VMIN] = 1
    configured[6][termios.VTIME] = 0
    keys = _Keys(fd, getattr(stdin, "encoding", None) or "utf-8")
    session = InteractiveMenu(navigator, actions, header, exit_check)
    color = "NO_COLOR" not in os.environ
    with _terminal_session(fd, stdout, original, configured):
        previous = None
        geometry = None
        dirty = True
        while not session.finished:
            size = os.get_terminal_size(out_fd)
            if dirty or size != geometry:
                frame = session.render(size.columns or 80, size.lines or 24, color)
                if frame != previous or size != geometry:
                    data = memoryview(("\x1b[H\x1b[2J" + frame).encode(getattr(stdout, "encoding", None) or "utf-8", "replace"))
                    while data:
                        data = data[os.write(out_fd, data):]
                previous, geometry, dirty = frame, size, False
            event = keys.read()
            if event is not None:
                session.key(event)
                dirty = True
    for line in session.exit_lines:
        stdout.write(_safe(line) + "\n")
    stdout.flush()
    return EXIT_OK
