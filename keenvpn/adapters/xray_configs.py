"""Преобразование прочитанных файлов конфигурации Xray в модели без обращения к роутеру.

Функции принимают уже прочитанные байты файлов по именам. Перечисление
каталога, чтение по SSH, таймауты и ограничение размера файла принадлежат
адаптеру транспорта, которого здесь нет. Ничего не записывается и не
запускается; установленный Xray для проверки не вызывается.
"""

from collections.abc import Mapping
from typing import NoReturn

from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xray_config import XrayConfigError, XrayConfigErrorCode, XrayConfigSet


XRAY_CONFIG_DIRECTORY = "/opt/etc/xray/configs"
"""Каталог частей конфигурации на проверенной платформе; XKeen загружает из него `*.json`."""


def _reject_parts() -> NoReturn:
    """Отсоединить отказ от активного чужого исключения, как в моделях домена."""
    try:
        raise XrayConfigError(XrayConfigErrorCode.PARTS) from None
    except XrayConfigError as error:
        error.__context__ = None
        raise


def xray_config_from_files(files: Mapping[str, bytes]) -> XrayConfigSet:
    """Собрать набор частей из байтов файлов, упорядочив их по имени.

    Порядок по имени повторяет загрузку каталога конфигураций Xray. Отбор
    файлов `*.json` выполняет источник при перечислении каталога; здесь
    каждое переданное имя становится частью и проверяется документом.
    """
    if not isinstance(files, Mapping) or any(type(name) is not str for name in files):
        _reject_parts()
    return XrayConfigSet(tuple(ConfigDocument(name, files[name]) for name in sorted(files)))
