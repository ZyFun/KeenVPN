"""Общее безопасное форматирование результатов прикладных сценариев."""

import re
from collections.abc import Callable, Iterable, Iterator, Mapping

from keenvpn.application.checks import CHECK_STATUS_LABELS, CheckView
from keenvpn.application.contract import (
    CONFLICT_STATE_LABELS, CONFLICT_SUBJECT_LABELS, CheckStatus, Conflict, ConflictSubject, ErrorDetail,
    Result, UNKNOWN_SOURCE_LABEL,
)
from keenvpn.application.proxy_config import XrayPositionView
from keenvpn.interfaces.cli.menu import MenuList


Lines = list[str]


Presenter = Callable[[object], Lines | MenuList]

HIDDEN = "<скрыто>"
"""Пометка вместо строки, не прошедшей проверку формата."""

MISSING = "нет данных"
"""Пометка вместо отсутствующего значения."""

SNAPSHOT_NOTE = (
    "Это снимок источников на момент чтения: работу VPN, перехват трафика и маршрут клиента он не подтверждает."
)

MAX_TEXT_LENGTH = 500

INDENT = "  "

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,63}")
"""Тег, код, состояние: правило `safe_identifier` домена — без `.`, `:`, `/`, `@` и пробелов."""

_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,58}\.(?:json|dat)")
"""Имя части Xray или файла геобазы: без каталога, только расширения `.json` и `.dat`."""

_INTERFACE_ID = re.compile(r"(?=.{1,64}\Z)[A-Za-z][A-Za-z0-9]*(?:[/.][A-Za-z0-9]+)*")
"""Интерфейс сегмента Keenetic вида `Bridge0` или `GigabitEthernet0/Vlan1`: с буквы, без `:` и пробелов."""

_DIGEST = re.compile(r"[0-9a-f]{64}")
"""SHA-256 в нижнем регистре."""

_GEO_SOURCE = re.compile(
    r"(?=.{1,128}\Z)(?:[A-Za-z0-9][A-Za-z0-9_+-]*(?:\.[A-Za-z0-9_+-]+)*"
    r"|https?://[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?)"
)
"""Источник геобазы в форме, которую оставляет домен: идентификатор либо схема и хост без пути."""

_GEO_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
"""Версия геобазы: короткий идентификатор, как у домена."""


def checked_text(pattern: re.Pattern[str], value: object) -> str:
    if type(value) is str and pattern.fullmatch(value) is not None:
        return value
    return HIDDEN


def identifier(value: object) -> str:
    """Показать тег, код или состояние только в формате технического идентификатора; иначе пометку."""
    return checked_text(_IDENTIFIER, value)


def file_name(value: object) -> str:
    """Показать имя части Xray или файла геобазы; иначе пометку."""
    return checked_text(_FILE_NAME, value)


def optional_file_name(value: object) -> str:
    """Имя файла или пометка отсутствия."""
    return MISSING if value is None else file_name(value)


def interface_id(value: object) -> str:
    """Показать идентификатор интерфейса сегмента Keenetic; иначе пометку."""
    return checked_text(_INTERFACE_ID, value)


def digest(value: object) -> str:
    """Показать SHA-256; иначе пометку."""
    return checked_text(_DIGEST, value)


def optional_digest(value: object) -> str:
    """SHA-256 или пометка отсутствия."""
    return MISSING if value is None else digest(value)


def geo_source(value: object) -> str:
    """Показать источник геобазы в форме домена; иначе пометку."""
    return checked_text(_GEO_SOURCE, value)


def geo_version(value: object) -> str:
    """Показать версию геобазы в форме домена; иначе пометку."""
    return checked_text(_GEO_VERSION, value)


def optional_identifier(value: object) -> str:
    """Идентификатор или пометка отсутствия."""
    return MISSING if value is None else identifier(value)


def user_text(value: object, limit: int) -> str:
    """Показать пользовательский текст только печатным, без пробелов по краям и в пределе длины; иначе пометку.

    Управляющие символы, ESC, невидимые символы, пробелы по краям, пустая
    и слишком длинная строка не выводятся: правило то же, что у моделей.
    """
    if type(value) is str and 1 <= len(value) <= limit and value.isprintable() and value == value.strip():
        return value
    return HIDDEN


def identifiers(values: Iterable[object]) -> str:
    """Перечислить идентификаторы через запятую; пустой список — «нет»."""
    items = [identifier(value) for value in values]
    return ", ".join(items) if items else "нет"


def known_value(known: object, value: object, show: Callable[[object], str], absent: str) -> str:
    """Различить отсутствие значения и известное, но скрытое сценарием значение.

    `known=False` — значения нет, показывается `absent`; `known=True` и `None` —
    значение задано, но application скрыл его как небезопасное, показывается
    пометка `<скрыто>`; иначе значение проходит фильтр своего вида.
    """
    if known is False:
        return absent
    if known is True:
        return HIDDEN if value is None else show(value)
    return HIDDEN


def flag(value: object) -> str:
    """Показать логическое значение словами; другой тип — пометка."""
    if type(value) is bool:
        return "да" if value else "нет"
    return HIDDEN


def optional_flag(value: object) -> str:
    """Логическое значение или пометка отсутствия."""
    return MISSING if value is None else flag(value)


def count(value: object) -> str:
    """Показать целое число; другой тип, включая bool, — пометка."""
    return str(value) if type(value) is int else HIDDEN


def optional_count(value: object) -> str:
    """Целое число или пометка отсутствия."""
    return MISSING if value is None else count(value)


def safe_text(value: object) -> str:
    """Показать заранее заданный текст сценария, если он печатный и не слишком длинный."""
    if type(value) is str and 0 < len(value) <= MAX_TEXT_LENGTH and value.isprintable():
        return value
    return HIDDEN


def enum_label(labels: Mapping[object, str], kind: type, value: object) -> str:
    """Подпись каталога application только для точного перечисления `kind`; строка вместо него — пометка."""
    if type(value) is kind:
        return safe_text(labels[value])
    return HIDDEN


def check_status(value: object) -> str:
    """Показать подпись статуса проверки только для точного `CheckStatus`; иначе пометку.

    Подпись берётся из каталога application: меню не выводит статус из состояния
    или кодов ошибок и не принимает строку вместо перечисления.
    """
    return enum_label(CHECK_STATUS_LABELS, CheckStatus, value)


def indented(lines: Iterable[str], level: int = 1) -> Lines:
    return [INDENT * level + line for line in lines]


def _conflict_line(conflict: Conflict) -> str:
    """Строка записи конфликта из подписей каталога application; источник — после проверки формата."""
    subject = CONFLICT_SUBJECT_LABELS[conflict.subject]
    if conflict.subject is ConflictSubject.SOURCE:
        source = UNKNOWN_SOURCE_LABEL if conflict.source is None else identifier(conflict.source.value)
        subject = f"{subject} {source}"
    return (
        f"Конфликт: {subject} — ожидалось: {CONFLICT_STATE_LABELS[conflict.expected]}, "
        f"найдено: {CONFLICT_STATE_LABELS[conflict.found]}"
    )


def present_error(error: ErrorDetail) -> Lines:
    """Показать отказ сценария: категорию, код, уточнение, текст, записи конфликта и безопасный следующий шаг.

    Записи конфликта и шаг берутся из `error` как есть: меню их не вычисляет,
    шаг не выбирает и не выполняет. Без записей и без шага строк нет. Код
    и уточнение контракт допускает подклассами `str`, например перечислениями:
    фильтр получает их значение обычной строкой.
    """
    if type(error) is not ErrorDetail:
        raise TypeError("Ожидается ErrorDetail.")
    lines = [f"Отказ: {identifier(error.category.value)} / {identifier(str.__str__(error.code))}"]
    if error.reason is not None:
        lines.append(f"Уточнение: {identifier(str.__str__(error.reason))}")
    lines.append(f"Причина: {safe_text(error.message)}")
    lines.extend(_conflict_line(conflict) for conflict in error.conflicts)
    step = error.next_step
    if step is not None:
        lines.append(f"Следующий шаг: {safe_text(step.message)}")
    return lines


def present_result(result: Result, present: Presenter) -> Lines | MenuList:
    """Показать результат: данные через переданное представление, отказ — общим способом."""
    if type(result) is not Result:
        raise TypeError("Ожидается Result сценария.")
    if result.succeeded:
        return present(result.data)
    return present_error(result.error)


def check_line(item: CheckView) -> str:
    line = f"{identifier(item.code)}: {check_status(item.status)}"
    if item.reason is not None:
        line += f", причина {identifier(item.reason)}"
    if item.network is True:
        line += " (сетевая проверка)"
    return line


def xray_position(value: object) -> str:
    """Позиция элемента Xray: имя части после фильтра и индекс; иной тип — пометка."""
    if type(value) is not XrayPositionView:
        return HIDDEN
    return f"часть {file_name(value.part)}, индекс {count(value.index)}"


def catalog_label(labels: Mapping[str, str], value: object) -> str:
    """Подпись каталога application только для точного строкового значения из него; иначе пометка."""
    if type(value) is str and value in labels:
        return safe_text(labels[value])
    return HIDDEN


ReportLayout = tuple[tuple[str, ...], tuple[tuple[str, tuple[str, ...]], ...]]


def report_paragraphs(lines: tuple[str, ...]) -> Iterator[tuple[str, tuple[str, ...]]]:
    """Соединить подпись представления с непосредственно следующими за ней строками с отступом."""
    start = 0
    while start < len(lines):
        end = start + 1
        while end < len(lines) and lines[end].startswith("  "):
            end += 1
        yield lines[start], lines[start + 1:end]
        start = end
