"""Преобразование прочитанных файлов XKeen в модели без обращения к роутеру.

Функции принимают байты уже прочитанных файлов либо извлечённые флаги
обезличенного снимка. Чтение по SSH, таймауты, права файлов и ограничение
размера принадлежат адаптеру транспорта, которого здесь нет. Команды XKeen
не вызываются: даже `xkeen -status` меняет служебные файлы, а init не
исполняется и не подключается через `source`.
"""

from collections.abc import Mapping
import re
from typing import NoReturn

from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import (
    XKeenConfigError, XKeenConfigErrorCode, XKeenInitAssignment, XKeenInitParameters, XKeenList, XKeenListName,
    XKeenSettings, parse_xkeen_init,
)


XKEEN_SETTINGS_PATH = "/opt/etc/xkeen/xkeen.json"
"""Общие настройки XKeen и kill-switch на проверенной платформе."""
XKEEN_INIT_PATH = "/opt/etc/init.d/S05xkeen"
"""Стартовый сценарий с параметрами; читается только как текст."""
XKEEN_LIST_DIRECTORY = "/opt/etc/xkeen"
"""Каталог трёх списков: имена файлов заданы `XKeenListName`."""
XKEEN_SETTINGS_NAME = "xkeen.json"

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SAFE_VALUE = re.compile(r'[^"$`\\\n]*')


def _reject_init() -> NoReturn:
    """Отсоединить отказ от активного чужого исключения, как в моделях домена."""
    try:
        raise XKeenConfigError(XKeenConfigErrorCode.INIT) from None
    except XKeenConfigError as error:
        error.__context__ = None
        raise


def xkeen_settings_from_bytes(content: bytes) -> XKeenSettings:
    """Разобрать `xkeen.json` целиком как документ конфигурации."""
    return XKeenSettings(ConfigDocument(XKEEN_SETTINGS_NAME, content))


def xkeen_init_from_bytes(content: bytes) -> XKeenInitParameters:
    """Прочитать присваивания из текста init как данные."""
    return parse_xkeen_init(content)


def xkeen_init_from_flags(flags: Mapping[str, str]) -> XKeenInitParameters:
    """Собрать параметры из уже извлечённых флагов, например из обезличенного снимка.

    Каждый флаг становится единственным присваиванием без номера строки
    и отступа в поддержанной форме `name="значение"`.
    """
    if not isinstance(flags, Mapping):
        _reject_init()
    assignments = []
    for name, value in flags.items():
        if (
            type(name) is not str or _IDENTIFIER.fullmatch(name) is None
            or type(value) is not str or _SAFE_VALUE.fullmatch(value) is None
        ):
            _reject_init()
        assignments.append(XKeenInitAssignment(name, f'"{value}"', None, False))
    return XKeenInitParameters(tuple(assignments))


def xkeen_list_from_bytes(name: XKeenListName, content: bytes) -> XKeenList:
    """Сохранить текст одного списка; правила разбора задаёт его имя."""
    return XKeenList(name, content)
