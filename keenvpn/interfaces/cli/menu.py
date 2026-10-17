"""Чистая модель меню и навигации без ввода-вывода.

Пункты имеют стабильные номера из утверждённого дерева; `0` зарезервирован
за возвратом на уровень выше и выходом. Модель не читает терминал, не печатает
и не выполняет действий: на выбор номера она отвечает типизированным исходом,
а цикл терминала решает, что показать и какое доступное действие вызвать.
"""

from dataclasses import dataclass
from enum import StrEnum
import re


MAX_ITEM_NUMBER = 999
"""Наибольший номер пункта; `0` зарезервирован за возвратом и выходом."""
MAX_TITLE_LENGTH = 120
"""Предел длины заголовка пункта и меню в символах."""
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


class SelectionKind(StrEnum):
    """Исход выбора номера."""

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


@dataclass(frozen=True, slots=True)
class Selection:
    """Исход выбора и затронутый пункт, если он есть."""

    kind: SelectionKind
    item: MenuItem | None = None

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
        self._path: list[Menu] = [root]

    @property
    def current(self) -> Menu:
        """Открытый сейчас уровень."""
        return self._path[-1]

    @property
    def depth(self) -> int:
        """Глубина: 0 в корне."""
        return len(self._path) - 1

    @property
    def titles(self) -> tuple[str, ...]:
        """Заголовки уровней от корня до текущего."""
        return tuple(menu.title for menu in self._path)

    def select(self, number: int) -> Selection:
        """Обработать выбранный номер; `0` равнозначен возврату."""
        if type(number) is int and number == BACK_NUMBER:
            return self.back()
        item = self.current.item(number)
        if item is None:
            return Selection(SelectionKind.UNKNOWN)
        if item.submenu is not None:
            self._path.append(item.submenu)
            return Selection(SelectionKind.ENTERED, item)
        if item.action.available:
            return Selection(SelectionKind.ACTION, item)
        return Selection(SelectionKind.UNAVAILABLE, item)

    def back(self) -> Selection:
        """Подняться на уровень выше; в корне — выход."""
        if self.depth == 0:
            return Selection(SelectionKind.EXIT)
        self._path.pop()
        return Selection(SelectionKind.BACK)
