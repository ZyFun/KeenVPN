"""Прочитанные настройки XKeen: `xkeen.json`, параметры init и списки портов и адресов.

Init читается построчно как данные, без исполнения и `source`: учитываются
строки вида `name=` после необязательных пробелов — так же их ищет штатная
функция переключения флагов XKeen. Повторы и неподдержанный синтаксис
отмечаются, а не исправляются. Списки разбираются по тем же правилам, что
в установленном init: комментарий начинается с `#`, записи портов допускают
запятые и диапазоны `a:b`/`a-b`, адреса распознаются по стандарту `ipaddress`.
Факты по порту 53 возвращаются раздельно; вывод о фактическом перехвате
трафика не делается. Модели не обращаются к роутеру и ничего не записывают.
"""

from dataclasses import dataclass, field
from enum import StrEnum
import ipaddress
import re
from typing import NoReturn

from keenvpn.domain.config_document import ConfigDocument, validate_config_document


DNS_PORT = 53
"""TCP/UDP-порт DNS, исключение которого выбирает пользователь."""
XKEEN_SETTINGS_NAME = "xkeen.json"
"""Имя документа общих настроек XKeen."""
KNOWN_INIT_FLAGS = ("start_auto", "proxy_dns", "proxy_router", "ipv6_support")
"""Флаги `on`/`off`, состояние которых показывает сводка."""

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ASSIGNMENT = re.compile(r"([ \t\f\v]*)([A-Za-z_][A-Za-z0-9_]*)=(.*)")
_LITERAL = re.compile(r'"([^"$`\\]*)"[ \t]*')
_PORT = re.compile(r"[0-9]+")


class XKeenConfigErrorCode(StrEnum):
    """Причины отказа без содержимого файлов и значений параметров."""

    SETTINGS = "invalid_xkeen_settings"
    INIT = "invalid_xkeen_init"
    LIST = "invalid_xkeen_list"
    CONFIG = "invalid_xkeen_config"


_MESSAGES = {
    XKeenConfigErrorCode.SETTINGS: "Настройки XKeen должны быть документом xkeen.json.",
    XKeenConfigErrorCode.INIT: "Параметры init XKeen должны быть текстом UTF-8 в байтах либо кортежем присваиваний.",
    XKeenConfigErrorCode.LIST: "Список XKeen должен иметь известное имя и текст UTF-8 в байтах.",
    XKeenConfigErrorCode.CONFIG: "Собранные настройки XKeen не согласованы или имеют неверный тип.",
}


class XKeenConfigError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: XKeenConfigErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: XKeenConfigErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise XKeenConfigError(code) from None
    except XKeenConfigError as error:
        error.__context__ = None
        raise


class XKeenFlagStatus(StrEnum):
    """Состояние одного флага; значение известно только для `present`."""

    PRESENT = "present"
    MISSING = "missing"
    DUPLICATE = "duplicate"
    UNSUPPORTED = "unsupported"
    UNEXPECTED = "unexpected"


@dataclass(frozen=True, slots=True)
class XKeenFlag:
    """Флаг `on`/`off`: значение заполнено только при статусе `present`."""

    status: XKeenFlagStatus
    value: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not XKeenFlagStatus or not (
            self.value in ("on", "off") if self.status is XKeenFlagStatus.PRESENT else self.value is None
        ):
            _raise_detached(XKeenConfigErrorCode.CONFIG)

    def to_diagnostic(self) -> dict[str, str | None]:
        """Статус и значение `on`/`off`; другие значения не показываются."""
        return {"status": self.status.value, "value": self.value}


def _switch(status: XKeenFlagStatus, value: str | None) -> XKeenFlag:
    """Свести произвольное значение к `on`/`off`; иное — `unexpected` без значения."""
    if status is XKeenFlagStatus.PRESENT:
        if value in ("on", "off"):
            return XKeenFlag(XKeenFlagStatus.PRESENT, value)
        return XKeenFlag(XKeenFlagStatus.UNEXPECTED)
    return XKeenFlag(status)


@dataclass(frozen=True, slots=True, repr=False)
class XKeenSettings:
    """Файл `xkeen.json` целиком; `killswitch` извлекается из объекта `xkeen`.

    XKeen считает включённым только строковое `"on"`, любое другое значение —
    выключенным. Модель не подменяет значение: отсутствие, другой тип
    и неожиданная строка показываются своими статусами.
    """

    document: ConfigDocument

    def __post_init__(self) -> None:
        if (
            type(self.document) is not ConfigDocument
            or type(self.document.name) is not str
            or self.document.name != XKEEN_SETTINGS_NAME
        ):
            _raise_detached(XKeenConfigErrorCode.SETTINGS)

    def __repr__(self) -> str:
        return f"XKeenSettings(size={self.document.size})"

    def export(self) -> dict[str, object]:
        """Копия всего объекта настроек для доверенного кода, не для вывода."""
        return self.document.export()

    @property
    def settings_keys(self) -> tuple[str, ...]:
        """Имена полей объекта `xkeen` в порядке файла; без объекта — пусто."""
        section = self.export().get("xkeen")
        return tuple(section) if type(section) is dict else ()

    @property
    def killswitch(self) -> XKeenFlag:
        """Сохранённый флаг kill-switch без вывода о фактической защите."""
        document = self.export()
        if "xkeen" not in document:
            return XKeenFlag(XKeenFlagStatus.MISSING)
        section = document["xkeen"]
        if type(section) is not dict:
            return XKeenFlag(XKeenFlagStatus.UNSUPPORTED)
        if "killswitch" not in section:
            return XKeenFlag(XKeenFlagStatus.MISSING)
        value = section["killswitch"]
        if type(value) is not str:
            return XKeenFlag(XKeenFlagStatus.UNSUPPORTED)
        return _switch(XKeenFlagStatus.PRESENT, value)

    def to_diagnostic(self) -> dict[str, object]:
        """Ревизия файла, имена полей и статус kill-switch без остальных значений."""
        return {
            **self.document.to_diagnostic(),
            "has_xkeen_section": type(self.export().get("xkeen")) is dict,
            "settings_keys": list(self.settings_keys),
            "killswitch": self.killswitch.to_diagnostic(),
        }


def validate_xkeen_settings(settings: XKeenSettings) -> None:
    """Проверить готовую модель заново по имени и байтам документа."""
    if type(settings) is not XKeenSettings:
        _raise_detached(XKeenConfigErrorCode.SETTINGS)
    XKeenSettings(settings.document)
    validate_config_document(settings.document)


@dataclass(frozen=True, slots=True, repr=False)
class XKeenInitAssignment:
    """Одна строка init вида `name=...`: правая часть хранится как написана.

    `literal` истинно для `name="значение"` без `$`, обратных кавычек,
    экранирования и хвоста после закрывающей кавычки — единственной формы,
    которую можно безопасно прочитать и позже изменить. `indented` отмечает
    строку с отступом: обычно это присваивание внутри функции, а не параметр.
    """

    name: str
    raw: str = field(repr=False)
    line_number: int | None
    indented: bool

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str or _IDENTIFIER.fullmatch(self.name) is None
            or type(self.raw) is not str or "\n" in self.raw
            or (self.line_number is not None and (type(self.line_number) is not int or self.line_number < 1))
            or type(self.indented) is not bool
        ):
            _raise_detached(XKeenConfigErrorCode.INIT)

    def __repr__(self) -> str:
        return "XKeenInitAssignment(<скрыто>)"

    @property
    def literal(self) -> bool:
        """Правая часть — одно значение в двойных кавычках без подстановок."""
        return _LITERAL.fullmatch(self.raw) is not None

    @property
    def value(self) -> str | None:
        """Значение без кавычек только для поддержанной формы."""
        match = _LITERAL.fullmatch(self.raw)
        return None if match is None else match[1]


@dataclass(frozen=True, slots=True, repr=False)
class XKeenInitParameter:
    """Итог чтения одного имени: статус, значение и число присваиваний."""

    name: str
    status: XKeenFlagStatus
    value: str | None
    top_level_count: int
    indented_count: int

    def __repr__(self) -> str:
        return f"XKeenInitParameter(status={self.status.value})"


def _line_numbers_consistent(assignments: tuple[XKeenInitAssignment, ...]) -> bool:
    numbers = [assignment.line_number for assignment in assignments]
    if all(number is None for number in numbers):
        return True
    if any(number is None for number in numbers):
        return False
    return all(earlier < later for earlier, later in zip(numbers, numbers[1:]))


@dataclass(frozen=True, slots=True, repr=False)
class XKeenInitParameters:
    """Присваивания init в порядке файла; параметр — присваивание без отступа.

    Статус имени считается по всем его присваиваниям: ничего не выбирается
    по первому. Любой повтор, в том числе с отступом, даёт `duplicate` без
    значения: отступ не доказывает, что строка находится внутри функции,
    штатная функция XKeen правит первую найденную строку независимо от
    отступа, а повтор может переопределить значение во время выполнения.
    """

    assignments: tuple[XKeenInitAssignment, ...]

    def __post_init__(self) -> None:
        if (
            type(self.assignments) is not tuple
            or any(type(item) is not XKeenInitAssignment for item in self.assignments)
        ):
            _raise_detached(XKeenConfigErrorCode.INIT)
        for item in self.assignments:
            XKeenInitAssignment(item.name, item.raw, item.line_number, item.indented)
        if not _line_numbers_consistent(self.assignments):
            _raise_detached(XKeenConfigErrorCode.INIT)

    def __repr__(self) -> str:
        return f"XKeenInitParameters(assignments={len(self.assignments)})"

    @property
    def parameter_names(self) -> tuple[str, ...]:
        """Уникальные имена присваиваний без отступа в порядке первого появления."""
        return tuple(dict.fromkeys(item.name for item in self.assignments if not item.indented))

    def parameter(self, name: str) -> XKeenInitParameter:
        """Статус и значение имени без выбора первого из повторов."""
        if type(name) is not str or _IDENTIFIER.fullmatch(name) is None:
            _raise_detached(XKeenConfigErrorCode.INIT)
        matching = [item for item in self.assignments if item.name == name]
        top_level = [item for item in matching if not item.indented]
        indented_count = len(matching) - len(top_level)
        value = None
        if not matching:
            status = XKeenFlagStatus.MISSING
        elif len(matching) >= 2:
            # Отступ не доказывает контекст функции: повтор с отступом тоже может переопределить значение.
            status = XKeenFlagStatus.DUPLICATE
        elif matching[0].indented or not matching[0].literal:
            status = XKeenFlagStatus.UNSUPPORTED
        else:
            status = XKeenFlagStatus.PRESENT
            value = matching[0].value
        return XKeenInitParameter(name, status, value, len(top_level), indented_count)

    def switch(self, name: str) -> XKeenFlag:
        """Флаг `on`/`off`; другое поддержанное значение даёт `unexpected`."""
        parameter = self.parameter(name)
        return _switch(parameter.status, parameter.value)

    def to_diagnostic(self) -> dict[str, object]:
        """Счётчики, имена повторов и известные флаги без значений остальных параметров."""
        top_level = [item for item in self.assignments if not item.indented]
        counts: dict[str, int] = {}
        for item in self.assignments:
            counts[item.name] = counts.get(item.name, 0) + 1
        flags = {}
        for name in KNOWN_INIT_FLAGS:
            parameter = self.parameter(name)
            flags[name] = {**self.switch(name).to_diagnostic(), "indented_count": parameter.indented_count}
        return {
            "assignment_count": len(self.assignments),
            "top_level_count": len(top_level),
            "indented_count": len(self.assignments) - len(top_level),
            "literal_count": sum(item.literal for item in top_level),
            "expression_count": sum(not item.literal for item in top_level),
            "parameter_count": len(self.parameter_names),
            "duplicate_names": sorted(name for name, count in counts.items() if count > 1),
            "flags": flags,
        }


def parse_xkeen_init(content: bytes) -> XKeenInitParameters:
    """Прочитать присваивания из текста init построчно, без семантики shell.

    Условия, функции, heredoc и `export`/`local` не разбираются: строка
    учитывается, только если начинается с имени и `=` после пробелов.
    Завершающий `\\r` отбрасывается, как это делает XKeen при чтении.
    """
    if type(content) is not bytes:
        _raise_detached(XKeenConfigErrorCode.INIT)
    text = None
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    if text is None:
        _raise_detached(XKeenConfigErrorCode.INIT)
    assignments = []
    for number, line in enumerate(text.split("\n"), start=1):
        if line.endswith("\r"):
            line = line[:-1]
        match = _ASSIGNMENT.fullmatch(line)
        if match is not None:
            assignments.append(XKeenInitAssignment(match[2], match[3], number, bool(match[1])))
    return XKeenInitParameters(tuple(assignments))


def validate_xkeen_init(init: XKeenInitParameters) -> None:
    """Проверить готовую модель и поля каждого вложенного присваивания заново."""
    if type(init) is not XKeenInitParameters:
        _raise_detached(XKeenConfigErrorCode.INIT)
    XKeenInitParameters(init.assignments)


class XKeenListName(StrEnum):
    """Три списка каталога XKeen; имя задаёт правила разбора записей."""

    PORT_EXCLUDE = "port_exclude.lst"
    PORT_PROXYING = "port_proxying.lst"
    IP_EXCLUDE = "ip_exclude.lst"


class XKeenListLineKind(StrEnum):
    """Строка списка: пустая, только комментарий либо запись."""

    BLANK = "blank"
    COMMENT = "comment"
    ENTRY = "entry"


class XKeenListItemKind(StrEnum):
    """Элемент записи: порт, диапазон портов, адрес или нераспознанный текст."""

    PORT = "port"
    RANGE = "range"
    ADDRESS = "address"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True, repr=False)
class XKeenListLine:
    """Исходная строка без перевода строки и её запись после удаления комментария."""

    number: int
    text: str
    kind: XKeenListLineKind
    entry: str | None

    def __repr__(self) -> str:
        return f"XKeenListLine(number={self.number}, kind={self.kind.value})"


@dataclass(frozen=True, slots=True, repr=False)
class XKeenListItem:
    """Элемент записи списка; диапазон задан для портов и диапазонов."""

    line_number: int
    text: str
    kind: XKeenListItemKind
    port_range: tuple[int, int] | None = None

    def __repr__(self) -> str:
        return f"XKeenListItem(line={self.line_number}, kind={self.kind.value})"


def _port_number(text: str) -> int | None:
    """Число порта 1–65535 как у awk в XKeen: ведущие нули допустимы.

    Длина проверяется по значащей части до `int()`, поэтому длинная запись
    не упирается в предел длины строк CPython и не вызывает исключение.
    """
    if _PORT.fullmatch(text) is None:
        return None
    significant = text.lstrip("0")
    if not significant or len(significant) > 5:
        return None
    port = int(significant)
    return port if port <= 65535 else None


def _port_items(number: int, entry: str) -> list[XKeenListItem]:
    """Разобрать запись портов, как `validate_and_clean_ports` установленного XKeen."""
    items = []
    for piece in entry.split(","):
        text = re.sub(r"\s+", "", piece)
        if not text:
            continue
        ports = [_port_number(part) for part in text.replace("-", ":").split(":")]
        if len(ports) == 1 and ports[0] is not None:
            items.append(XKeenListItem(number, piece, XKeenListItemKind.PORT, (ports[0], ports[0])))
        elif len(ports) == 2 and None not in ports:
            start, end = sorted(ports)
            items.append(XKeenListItem(number, piece, XKeenListItemKind.RANGE, (start, end)))
        else:
            items.append(XKeenListItem(number, piece, XKeenListItemKind.INVALID))
    return items


def _address_items(number: int, entry: str) -> list[XKeenListItem]:
    """Распознать адреса и сети записи по `ipaddress`, не нормализуя их."""
    items = []
    for token in re.split(r"[\s,;]+", entry):
        if not token:
            continue
        recognized = "%" not in token
        if recognized:
            try:
                ipaddress.ip_network(token, strict=False)
            except ValueError:
                recognized = False
        kind = XKeenListItemKind.ADDRESS if recognized else XKeenListItemKind.INVALID
        items.append(XKeenListItem(number, token, kind))
    return items


@dataclass(frozen=True, slots=True, init=False, repr=False)
class XKeenList:
    """Один список XKeen с сохранением исходного текста.

    Строки разбираются как в установленном init: `#` начинает комментарий
    до конца строки, пробелы по краям и завершающий `\\r` не учитываются.
    Значения записей доступны доверенному коду через `lines` и `items`
    и не входят в `to_diagnostic()`.
    """

    name: XKeenListName
    text: str = field(repr=False)

    def __init__(self, name: XKeenListName, content: bytes) -> None:
        if type(name) is not XKeenListName or type(content) is not bytes:
            _raise_detached(XKeenConfigErrorCode.LIST)
        text = None
        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        if text is None:
            _raise_detached(XKeenConfigErrorCode.LIST)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "text", text)

    def __repr__(self) -> str:
        return f"XKeenList(name={self.name.value}, lines={len(self.lines)})"

    @property
    def is_port_list(self) -> bool:
        """Списки портов разбираются по правилам портов, список адресов — по адресам."""
        return self.name is not XKeenListName.IP_EXCLUDE

    @property
    def lines(self) -> tuple[XKeenListLine, ...]:
        """Строки файла с их видом и записью после удаления комментария."""
        raw_lines = self.text.split("\n")
        if raw_lines and raw_lines[-1] == "":
            raw_lines.pop()
        lines = []
        for number, text in enumerate(raw_lines, start=1):
            stripped = text[:-1] if text.endswith("\r") else text
            entry = stripped.split("#", 1)[0].strip()
            if entry:
                kind = XKeenListLineKind.ENTRY
            elif "#" in stripped:
                kind = XKeenListLineKind.COMMENT
            else:
                kind = XKeenListLineKind.BLANK
            lines.append(XKeenListLine(number, text, kind, entry or None))
        return tuple(lines)

    @property
    def items(self) -> tuple[XKeenListItem, ...]:
        """Элементы всех записей в порядке файла."""
        parse = _port_items if self.is_port_list else _address_items
        items: list[XKeenListItem] = []
        for line in self.lines:
            if line.kind is XKeenListLineKind.ENTRY:
                items.extend(parse(line.number, line.entry))
        return tuple(items)

    def lists_port(self, port: int) -> bool:
        """Есть ли отдельная запись именно этого порта."""
        return any(item.kind is XKeenListItemKind.PORT and item.port_range[0] == port for item in self.items)

    def covers_port_by_range(self, port: int) -> bool:
        """Попадает ли порт в какой-либо диапазон списка."""
        return any(
            item.kind is XKeenListItemKind.RANGE and item.port_range[0] <= port <= item.port_range[1]
            for item in self.items
        )

    def to_diagnostic(self) -> dict[str, object]:
        """Счётчики строк и элементов без значений портов и адресов."""
        lines = self.lines
        items = self.items
        counts = {kind: sum(item.kind is kind for item in items) for kind in XKeenListItemKind}
        return {
            "name": self.name.value,
            "line_count": len(lines),
            "blank_count": sum(line.kind is XKeenListLineKind.BLANK for line in lines),
            "comment_count": sum(line.kind is XKeenListLineKind.COMMENT for line in lines),
            "entry_count": sum(line.kind is XKeenListLineKind.ENTRY for line in lines),
            "port_count": counts[XKeenListItemKind.PORT] if self.is_port_list else None,
            "range_count": counts[XKeenListItemKind.RANGE] if self.is_port_list else None,
            "address_count": None if self.is_port_list else counts[XKeenListItemKind.ADDRESS],
            "invalid_count": counts[XKeenListItemKind.INVALID],
        }


def validate_xkeen_list(xkeen_list: XKeenList) -> None:
    """Проверить тип модели, имя списка и текст."""
    if (
        type(xkeen_list) is not XKeenList
        or type(xkeen_list.name) is not XKeenListName
        or type(xkeen_list.text) is not str
    ):
        _raise_detached(XKeenConfigErrorCode.LIST)


@dataclass(frozen=True, slots=True)
class Port53Facts:
    """Раздельные факты о порту 53: записи списков и флаги init.

    Это не вывод о фактическом перехвате DNS: путь пакета зависит от netfilter,
    приоритета списка перехватываемых портов и настроек Keenetic. Отсутствие
    записи не является ошибкой.
    """

    port_exclude_entry: bool
    port_exclude_range: bool
    port_proxying_entry: bool
    port_proxying_range: bool
    proxy_dns: XKeenFlag
    proxy_router: XKeenFlag

    def __post_init__(self) -> None:
        if any(type(getattr(self, name)) is not bool for name in (
            "port_exclude_entry", "port_exclude_range", "port_proxying_entry", "port_proxying_range",
        )) or type(self.proxy_dns) is not XKeenFlag or type(self.proxy_router) is not XKeenFlag:
            _raise_detached(XKeenConfigErrorCode.CONFIG)

    def to_diagnostic(self) -> dict[str, object]:
        """Все факты в JSON-совместимом виде."""
        return {
            "port": DNS_PORT,
            "port_exclude_entry": self.port_exclude_entry,
            "port_exclude_range": self.port_exclude_range,
            "port_proxying_entry": self.port_proxying_entry,
            "port_proxying_range": self.port_proxying_range,
            "proxy_dns": self.proxy_dns.to_diagnostic(),
            "proxy_router": self.proxy_router.to_diagnostic(),
        }


def port_53_facts(init: XKeenInitParameters, port_exclude: XKeenList, port_proxying: XKeenList) -> Port53Facts:
    """Собрать факты из init и двух списков портов без их интерпретации."""
    if (
        type(init) is not XKeenInitParameters
        or type(port_exclude) is not XKeenList or port_exclude.name is not XKeenListName.PORT_EXCLUDE
        or type(port_proxying) is not XKeenList or port_proxying.name is not XKeenListName.PORT_PROXYING
    ):
        _raise_detached(XKeenConfigErrorCode.CONFIG)
    return Port53Facts(
        port_exclude.lists_port(DNS_PORT), port_exclude.covers_port_by_range(DNS_PORT),
        port_proxying.lists_port(DNS_PORT), port_proxying.covers_port_by_range(DNS_PORT),
        init.switch("proxy_dns"), init.switch("proxy_router"),
    )


@dataclass(frozen=True, slots=True, repr=False)
class XKeenConfig:
    """Настройки, параметры init и три списка, прочитанные раздельно.

    Это снимок на момент чтения, а не черновик применения. Согласованность
    выбранного режима DNS со списками и флагами здесь не проверяется.
    """

    settings: XKeenSettings
    init: XKeenInitParameters
    port_exclude: XKeenList
    port_proxying: XKeenList
    ip_exclude: XKeenList

    def __post_init__(self) -> None:
        validate_xkeen_config(self)

    def __repr__(self) -> str:
        return f"XKeenConfig(assignments={len(self.init.assignments)}, lists=3)"

    @property
    def port_53(self) -> Port53Facts:
        """Факты по порту 53 из init и списков портов."""
        return port_53_facts(self.init, self.port_exclude, self.port_proxying)

    def to_diagnostic(self) -> dict[str, object]:
        """Сводка всех источников без значений записей и параметров."""
        return {
            "settings": self.settings.to_diagnostic(),
            "init": self.init.to_diagnostic(),
            "lists": {
                "port_exclude": self.port_exclude.to_diagnostic(),
                "port_proxying": self.port_proxying.to_diagnostic(),
                "ip_exclude": self.ip_exclude.to_diagnostic(),
            },
            "port_53": self.port_53.to_diagnostic(),
        }


def validate_xkeen_config(config: XKeenConfig) -> None:
    """Проверить типы полей, имена списков и каждую модель заново."""
    if type(config) is not XKeenConfig:
        _raise_detached(XKeenConfigErrorCode.CONFIG)
    validate_xkeen_settings(config.settings)
    validate_xkeen_init(config.init)
    for field_name, expected in (
        ("port_exclude", XKeenListName.PORT_EXCLUDE),
        ("port_proxying", XKeenListName.PORT_PROXYING),
        ("ip_exclude", XKeenListName.IP_EXCLUDE),
    ):
        xkeen_list = getattr(config, field_name)
        validate_xkeen_list(xkeen_list)
        if xkeen_list.name is not expected:
            _raise_detached(XKeenConfigErrorCode.CONFIG)


def assemble_xkeen_config(
    settings: XKeenSettings,
    init: XKeenInitParameters,
    port_exclude: XKeenList,
    port_proxying: XKeenList,
    ip_exclude: XKeenList,
) -> XKeenConfig:
    """Собрать настройки из раздельно прочитанных моделей без ввода-вывода."""
    return XKeenConfig(settings, init, port_exclude, port_proxying, ip_exclude)
