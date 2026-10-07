"""JSON-документ конфигурации: имя, размер, SHA-256 и строгий разбор без исполнения.

Общая основа частей конфигурации Xray и настроек XKeen. Документ хранит
исходные байты и независимый JSON-снимок разобранного объекта; ничего не
читает с диска и не записывает. Комментарии `//` и `/* */` вне строк
допускаются и в документ не входят; границы токенов сохраняются.
Дубли ключей, `NaN`, `Infinity` и не-объект на верхнем уровне отклоняются.
"""

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import math
from typing import NoReturn


MAX_DOCUMENT_NAME_LENGTH = 255
"""Имя документа — имя файла без каталога, как его перечисляет источник."""
MAX_JSON_DEPTH = 64
"""Та же граница вложенности, что у снимков записей Keenetic."""


class ConfigDocumentErrorCode(StrEnum):
    """Причины отказа без имени, содержимого и фрагментов документа."""

    NAME = "invalid_document_name"
    CONTENT = "invalid_document_content"
    JSON = "invalid_document_json"
    DOCUMENT = "invalid_config_document"


_MESSAGES = {
    ConfigDocumentErrorCode.NAME: "Имя документа конфигурации имеет недопустимый формат.",
    ConfigDocumentErrorCode.CONTENT: "Содержимое документа конфигурации должно быть текстом UTF-8 в байтах.",
    ConfigDocumentErrorCode.JSON: (
        "Документ конфигурации должен быть строгим JSON-объектом без дублей ключей, NaN и Infinity."
    ),
    ConfigDocumentErrorCode.DOCUMENT: "Документ конфигурации повреждён или имеет неверный тип.",
}


class ConfigDocumentError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: ConfigDocumentErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: ConfigDocumentErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise ConfigDocumentError(code) from None
    except ConfigDocumentError as error:
        error.__context__ = None
        raise


def valid_document_name(value: object) -> bool:
    """Проверить имя файла без каталога: печатное, без разделителей путей и скрытых имён."""
    return (
        type(value) is str
        and 0 < len(value) <= MAX_DOCUMENT_NAME_LENGTH
        and value.isprintable()
        and value == value.strip()
        and "/" not in value
        and "\\" not in value
        and not value.startswith(".")
    )


def strip_json_comments(text: str) -> str:
    """Удалить комментарии `//` и `/* */` вне строк с сохранением границ токенов.

    Строки JSON с экранированием сохраняются целиком. Переводы строк внутри
    блочного комментария сохраняются; закрытый блок заменяется пробельным
    разделителем, поэтому токены по разные стороны блока не склеиваются.
    Незакрытый блочный комментарий отклоняется безопасной ошибкой JSON.
    """
    pieces = []
    index = 0
    length = len(text)
    in_string = escaped = False
    while index < length:
        char = text[index]
        if in_string:
            pieces.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
        elif char == '"':
            in_string = True
            pieces.append(char)
            index += 1
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                _raise_detached(ConfigDocumentErrorCode.JSON)
            stop = end + 2
            pieces.append(" " + "\n" * text.count("\n", index, stop))
            index = stop
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end < 0 else end
        else:
            pieces.append(char)
            index += 1
    return "".join(pieces)


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("Повтор ключа JSON.")
        result[key] = value
    return result


def _constant(_value: str) -> NoReturn:
    raise ValueError("Недопустимая константа JSON.")


def _check_tree(value: object, depth: int = 0) -> bool:
    """Отклонить бесконечные числа и вложенность свыше границы снимка."""
    if depth > MAX_JSON_DEPTH:
        return False
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(_check_tree(item, depth + 1) for item in value)
    if type(value) is dict:
        return all(_check_tree(item, depth + 1) for item in value.values())
    return True


def parse_strict_json_object(text: str) -> dict[str, object]:
    """Разобрать текст в объект JSON без дублей ключей, NaN, Infinity и глубоких структур."""
    if type(text) is not str:
        _raise_detached(ConfigDocumentErrorCode.JSON)
    document = None
    try:
        document = json.loads(strip_json_comments(text), object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, RecursionError):
        # Сообщение декодера содержит позицию и фрагмент текста: в ошибку оно не входит.
        pass
    if type(document) is not dict or not _check_tree(document):
        _raise_detached(ConfigDocumentErrorCode.JSON)
    return document


@dataclass(frozen=True, slots=True, init=False, repr=False)
class ConfigDocument:
    """Один файл конфигурации: имя, исходные байты, SHA-256 и разобранный объект.

    Размер и хеш относятся к исходным байтам вместе с комментариями. `export()`
    возвращает новую копию объекта для доверенного кода и не является безопасным
    выводом; для вывода служит `to_diagnostic()` без значений полей.
    """

    name: str
    content: bytes = field(repr=False)
    sha256: str
    _snapshot: str = field(repr=False)

    def __init__(self, name: str, content: bytes) -> None:
        if not valid_document_name(name):
            _raise_detached(ConfigDocumentErrorCode.NAME)
        if type(content) is not bytes:
            _raise_detached(ConfigDocumentErrorCode.CONTENT)
        text = None
        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        if text is None:
            _raise_detached(ConfigDocumentErrorCode.CONTENT)
        document = parse_strict_json_object(text)
        snapshot = None
        try:
            snapshot = json.dumps(document, ensure_ascii=True, allow_nan=False)
        except (ValueError, TypeError, RecursionError):
            pass
        if snapshot is None:
            _raise_detached(ConfigDocumentErrorCode.JSON)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "content", content)
        object.__setattr__(self, "sha256", hashlib.sha256(content).hexdigest())
        object.__setattr__(self, "_snapshot", snapshot)

    def __repr__(self) -> str:
        return f"ConfigDocument(size={len(self.content)})"

    @property
    def size(self) -> int:
        """Размер исходных байтов, включая комментарии и переводы строк."""
        return len(self.content)

    def export(self) -> dict[str, object]:
        """Получить копию разобранного объекта для доверенного кода, не для вывода."""
        return json.loads(self._snapshot)

    @property
    def sections(self) -> tuple[str, ...]:
        """Имена полей верхнего уровня в порядке документа."""
        return tuple(self.export())

    def to_diagnostic(self) -> dict[str, object]:
        """Имя, ревизия и имена полей верхнего уровня без значений."""
        return {"name": self.name, "size": self.size, "sha256": self.sha256, "sections": list(self.sections)}


def validate_config_document(document: ConfigDocument) -> None:
    """Проверить готовую модель заново: тип, байты, хеш и соответствие снимка содержимому."""
    if type(document) is not ConfigDocument:
        _raise_detached(ConfigDocumentErrorCode.DOCUMENT)
    rebuilt = ConfigDocument(document.name, document.content)
    if rebuilt.sha256 != document.sha256 or rebuilt._snapshot != document._snapshot:
        _raise_detached(ConfigDocumentErrorCode.DOCUMENT)
