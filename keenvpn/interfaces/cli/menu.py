"""Чистая модель меню и навигации без ввода-вывода.

Пункты имеют стабильные номера из утверждённого дерева; `0` зарезервирован
за возвратом на уровень выше и выходом. Модель не читает терминал, не печатает
и не выполняет действий: на выбор номера она отвечает типизированным исходом,
а цикл терминала решает, что показать и какое доступное действие вызвать.

Действие пункта может вернуть список элементов. Список, результаты поиска
по нему и карточка элемента — такие же уровни навигации, как подменю: номер
открывает карточку, `0` возвращает на один уровень, а поиск заменяет набор
показанных элементов, не трогая сам список.
"""

from dataclasses import dataclass, field
from enum import StrEnum
import re

from keenvpn.interfaces.cli.search import SearchQuery, matches, normalize


MAX_ITEM_NUMBER = 999
"""Наибольший номер пункта; `0` зарезервирован за возвратом и выходом."""
MAX_TITLE_LENGTH = 120
"""Предел длины заголовка пункта и меню в символах."""
MAX_LIST_LINE_LENGTH = 2000
"""Предел длины строки списка, его заголовка и карточки в символах."""
BACK_NUMBER = 0
"""Номер, который возвращает на уровень выше или завершает работу в корне."""

_ACTION_ID = re.compile(r"\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\Z")


class MenuError(ValueError):
    """Ошибка согласованности дерева меню: это ошибка кода, а не данных источника."""


class UnavailableReason(StrEnum):
    """Почему пункт показан, но не выполняется."""

    NOT_IMPLEMENTED = "not_implemented"
    """Сценария для пункта в этой версии нет."""
    SOURCE_NOT_CONNECTED = "source_not_connected"
    """Сценарий есть, но источник чтения при сборке не подключён."""
    INPUT_REQUIRED = "input_required"
    """Сценарий есть, но пункту нужен ввод значений, которого это меню не принимает."""


REASON_MESSAGES = {
    UnavailableReason.NOT_IMPLEMENTED: (
        "Пункт не реализован в этой версии меню: действие не выполняется, настройки не меняются."
    ),
    UnavailableReason.SOURCE_NOT_CONNECTED: (
        "Источник чтения роутера не подключён: показать данные нельзя, настройки не меняются."
    ),
    UnavailableReason.INPUT_REQUIRED: (
        "Пункт требует ввода значений, который это меню не принимает: действие не выполняется."
    ),
}
"""Заранее заданные тексты причин; введённые значения и строки источников сюда не попадают."""


def valid_action_id(value: object) -> bool:
    """Проверить стабильный идентификатор действия: латиница, цифры, `_` и точки между частями."""
    return type(value) is str and len(value) <= 64 and _ACTION_ID.fullmatch(value) is not None


def valid_title(value: object) -> bool:
    """Проверить заголовок: непустой печатный текст без управляющих символов и пробелов по краям."""
    return (
        type(value) is str
        and 0 < len(value) <= MAX_TITLE_LENGTH
        and value.isprintable()
        and value == value.strip()
    )


def valid_line(value: object) -> bool:
    """Проверить строку вывода списка: печатный текст без управляющих символов, не длиннее предела."""
    return type(value) is str and len(value) <= MAX_LIST_LINE_LENGTH and value.isprintable()


def _valid_lines(value: object) -> bool:
    return type(value) is tuple and all(valid_line(line) for line in value)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MenuError(message)


@dataclass(frozen=True, slots=True)
class MenuAction:
    """Действие пункта: стабильный идентификатор и причина недоступности, если он не выполняется."""

    action_id: str
    reason: UnavailableReason | None = None

    def __post_init__(self) -> None:
        _require(valid_action_id(self.action_id), "Некорректный идентификатор действия меню.")
        _require(
            self.reason is None or type(self.reason) is UnavailableReason,
            "Причина недоступности задаётся UnavailableReason или None.",
        )

    @property
    def available(self) -> bool:
        """Показать, выполняется ли действие при выборе пункта."""
        return self.reason is None


@dataclass(frozen=True, slots=True)
class MenuItem:
    """Пункт меню: номер, заголовок и ровно одно из подменю или действия."""

    number: int
    title: str
    submenu: "Menu | None" = None
    action: MenuAction | None = None

    def __post_init__(self) -> None:
        _require(
            type(self.number) is int and 1 <= self.number <= MAX_ITEM_NUMBER,
            "Номер пункта — целое число от 1 до 999; 0 зарезервирован за возвратом.",
        )
        _require(valid_title(self.title), "Некорректный заголовок пункта меню.")
        _require(
            (self.submenu is None) != (self.action is None),
            "Пункт содержит ровно одно из подменю или действия.",
        )
        _require(self.submenu is None or type(self.submenu) is Menu, "Подменю задаётся объектом Menu.")
        _require(self.action is None or type(self.action) is MenuAction, "Действие задаётся объектом MenuAction.")

    @property
    def available(self) -> bool:
        """Подменю всегда открывается; действие доступно только без причины недоступности."""
        return self.submenu is not None or self.action.available

    @property
    def reason(self) -> UnavailableReason | None:
        """Причина недоступности действия; у подменю и доступных действий — None."""
        return None if self.action is None else self.action.reason


@dataclass(frozen=True, slots=True)
class Menu:
    """Один уровень меню с уникальными номерами пунктов."""

    title: str
    items: tuple[MenuItem, ...]

    def __post_init__(self) -> None:
        _require(valid_title(self.title), "Некорректный заголовок меню.")
        _require(
            type(self.items) is tuple and all(type(item) is MenuItem for item in self.items),
            "Пункты меню задаются tuple объектов MenuItem.",
        )
        numbers = [item.number for item in self.items]
        _require(len(set(numbers)) == len(numbers), "Номера пунктов одного меню не повторяются.")

    def item(self, number: int) -> MenuItem | None:
        """Вернуть пункт с этим номером или None."""
        if type(number) is not int:
            return None
        for item in self.items:
            if item.number == number:
                return item
        return None


@dataclass(frozen=True, slots=True)
class ListEntry:
    """Элемент списка: стабильный номер, показанная строка и строки карточки.

    Строка и карточка уже прошли фильтры представления. Текст для поиска —
    нормализованная показанная строка без номера; других полей поиск не видит.
    """

    number: int
    label: str
    card: tuple[str, ...]
    search_text: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _require(
            type(self.number) is int and 1 <= self.number <= MAX_ITEM_NUMBER,
            "Номер элемента списка — целое число от 1 до 999; 0 зарезервирован за возвратом.",
        )
        _require(self.label != "" and valid_line(self.label), "Некорректная строка элемента списка.")
        _require(_valid_lines(self.card), "Карточка элемента задаётся tuple печатных строк.")
        object.__setattr__(self, "search_text", normalize(self.label))


@dataclass(frozen=True, slots=True)
class MenuList:
    """Список, который вернуло действие: заголовок уровня, имя элемента, вводные строки и элементы.

    Номера элементов возрастают и не повторяются; они не меняются при поиске.
    """

    title: str
    item_name: str
    header: tuple[str, ...]
    entries: tuple[ListEntry, ...]

    def __post_init__(self) -> None:
        _require(valid_title(self.title), "Некорректный заголовок списка.")
        _require(valid_title(self.item_name), "Некорректное имя элемента списка.")
        _require(_valid_lines(self.header), "Вводные строки списка задаются tuple печатных строк.")
        _require(
            type(self.entries) is tuple and all(type(entry) is ListEntry for entry in self.entries),
            "Элементы списка задаются tuple объектов ListEntry.",
        )
        numbers = [entry.number for entry in self.entries]
        _require(
            all(left < right for left, right in zip(numbers, numbers[1:])),
            "Номера элементов списка возрастают и не повторяются.",
        )


SEARCH_TITLE = "Результаты поиска"
"""Заголовок уровня с результатами поиска."""


@dataclass(frozen=True, slots=True)
class ListLevel:
    """Открытый список: весь список или результаты поиска по нему."""

    source: MenuList
    found: tuple[ListEntry, ...] | None = None
    """Найденные элементы; None — показан весь список."""

    def __post_init__(self) -> None:
        _require(type(self.source) is MenuList, "Список задаётся объектом MenuList.")
        if self.found is None:
            return
        listed = {id(entry) for entry in self.source.entries}
        _require(
            type(self.found) is tuple and len(self.found) > 0 and all(id(entry) in listed for entry in self.found),
            "Результаты поиска — непустая часть элементов своего списка.",
        )
        numbers = [entry.number for entry in self.found]
        _require(
            all(left < right for left, right in zip(numbers, numbers[1:])),
            "Результаты поиска сохраняют порядок списка без повторов.",
        )

    @property
    def filtered(self) -> bool:
        """Показаны ли результаты поиска, а не весь список."""
        return self.found is not None

    @property
    def entries(self) -> tuple[ListEntry, ...]:
        """Показанный набор: результаты поиска или весь список."""
        return self.source.entries if self.found is None else self.found

    @property
    def title(self) -> str:
        """Заголовок уровня в пути."""
        return SEARCH_TITLE if self.filtered else self.source.title

    def entry(self, number: int) -> ListEntry | None:
        """Элемент показанного набора с этим номером или None."""
        if type(number) is not int:
            return None
        for entry in self.entries:
            if entry.number == number:
                return entry
        return None


@dataclass(frozen=True, slots=True)
class CardLevel:
    """Открытая карточка элемента списка."""

    source: MenuList
    entry: ListEntry

    def __post_init__(self) -> None:
        _require(
            type(self.source) is MenuList and any(entry is self.entry for entry in self.source.entries),
            "Карточка открывается для элемента своего списка.",
        )

    @property
    def title(self) -> str:
        """Заголовок уровня в пути: имя элемента и его номер."""
        return f"{self.source.item_name} {self.entry.number}"


Level = Menu | ListLevel | CardLevel
"""Уровень навигации: подменю, список или карточка."""


class SelectionKind(StrEnum):
    """Исход выбора номера или поиска."""

    ENTERED = "entered"
    """Открыто подменю."""
    ACTION = "action"
    """Выбрано доступное действие; выполняет его вызывающий код."""
    UNAVAILABLE = "unavailable"
    """Пункт показан, но не выполняется."""
    UNKNOWN = "unknown"
    """Пункта с таким номером нет."""
    BACK = "back"
    """Возврат на уровень выше."""
    EXIT = "exit"
    """Выход из корневого меню."""
    OPENED = "opened"
    """Открыта карточка элемента списка."""
    FOUND = "found"
    """Показаны результаты поиска."""
    NO_MATCHES = "no_matches"
    """Совпадений нет; положение и показанный набор не изменились."""


@dataclass(frozen=True, slots=True)
class Selection:
    """Исход выбора и затронутый пункт меню или элемент списка, если он есть."""

    kind: SelectionKind
    item: MenuItem | None = None
    entry: ListEntry | None = None

    @property
    def action_id(self) -> str | None:
        """Идентификатор действия выбранного пункта или None."""
        return None if self.item is None or self.item.action is None else self.item.action.action_id

    @property
    def reason(self) -> UnavailableReason | None:
        """Причина недоступности выбранного пункта или None."""
        return None if self.item is None else self.item.reason


class MenuNavigator:
    """Текущее положение в дереве меню: стек открытых уровней от корня."""

    def __init__(self, root: Menu) -> None:
        _require(type(root) is Menu, "Корень навигации задаётся объектом Menu.")
        self._path: list[Level] = [root]

    @property
    def current(self) -> Level:
        """Открытый сейчас уровень."""
        return self._path[-1]

    @property
    def depth(self) -> int:
        """Глубина: 0 в корне."""
        return len(self._path) - 1

    @property
    def titles(self) -> tuple[str, ...]:
        """Заголовки уровней от корня до текущего."""
        return tuple(level.title for level in self._path)

    def open_list(self, source: MenuList) -> None:
        """Открыть список, который вернуло действие текущего подменю."""
        _require(type(source) is MenuList, "Список задаётся объектом MenuList.")
        _require(type(self.current) is Menu, "Список открывается только из подменю.")
        self._path.append(ListLevel(source))

    def select(self, number: int) -> Selection:
        """Обработать выбранный номер; `0` равнозначен возврату."""
        if type(number) is int and number == BACK_NUMBER:
            return self.back()
        level = self.current
        if type(level) is ListLevel:
            entry = level.entry(number)
            if entry is None:
                return Selection(SelectionKind.UNKNOWN)
            self._path.append(CardLevel(level.source, entry))
            return Selection(SelectionKind.OPENED, entry=entry)
        if type(level) is CardLevel:
            return Selection(SelectionKind.UNKNOWN)
        item = level.item(number)
        if item is None:
            return Selection(SelectionKind.UNKNOWN)
        if item.submenu is not None:
            self._path.append(item.submenu)
            return Selection(SelectionKind.ENTERED, item)
        if item.action.available:
            return Selection(SelectionKind.ACTION, item)
        return Selection(SelectionKind.UNAVAILABLE, item)

    def search(self, query: SearchQuery) -> Selection:
        """Найти элементы всего открытого списка; новый поиск заменяет прежние результаты.

        Без совпадений положение и показанный набор не меняются. Каждый элемент
        проверяется один раз: стоимость линейна по числу элементов.
        """
        _require(type(query) is SearchQuery, "Запрос задаётся объектом SearchQuery.")
        level = self.current
        _require(type(level) is ListLevel, "Поиск выполняется только в открытом списке.")
        found = tuple(entry for entry in level.source.entries if matches(query, entry.search_text))
        if not found:
            return Selection(SelectionKind.NO_MATCHES)
        results = ListLevel(level.source, found)
        if level.filtered:
            self._path[-1] = results
        else:
            self._path.append(results)
        return Selection(SelectionKind.FOUND)

    def back(self) -> Selection:
        """Подняться на уровень выше; в корне — выход."""
        if self.depth == 0:
            return Selection(SelectionKind.EXIT)
        self._path.pop()
        return Selection(SelectionKind.BACK)
