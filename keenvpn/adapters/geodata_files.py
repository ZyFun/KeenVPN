"""Преобразование наблюдений каталога геобаз в модели без обращения к роутеру.

Функции принимают уже прочитанные байты файлов либо уже вычисленные размер и
SHA-256. Перечисление каталога, чтение по SSH, `stat`, `sha256sum`, таймауты
и ограничение размера принадлежат адаптеру транспорта, которого здесь нет.
Файлы не создаются, не загружаются и не обновляются; известные источник
и версия базы передаются вызывающим кодом, а не выводятся из имени файла.
"""

from collections.abc import Mapping
import hashlib
from typing import NoReturn

from keenvpn.domain.geodata import (
    STANDARD_FILE_NAMES, GeoDatabaseFile, GeoDatabaseInventory, GeoDataError, GeoDataErrorCode,
)


XRAY_ASSET_DIRECTORY = "/opt/etc/xray/dat"
"""Каталог геобаз установленного Xray на проверенной платформе; его задаёт XKeen."""


def _reject(code: GeoDataErrorCode) -> NoReturn:
    """Отсоединить отказ от активного чужого исключения, как в моделях домена."""
    try:
        raise GeoDataError(code) from None
    except GeoDataError as error:
        error.__context__ = None
        raise


def geo_database_file_from_bytes(
    name: str, content: bytes, *, source: str | None = None, version: str | None = None,
) -> GeoDatabaseFile:
    """Описать найденный файл по его байтам: размер и SHA-256 вычисляются здесь."""
    if type(content) is not bytes:
        _reject(GeoDataErrorCode.FILE)
    return GeoDatabaseFile(name, True, len(content), hashlib.sha256(content).hexdigest(), source, version)


def geo_database_file_from_digest(
    name: str, size: int, sha256: str, *, source: str | None = None, version: str | None = None,
) -> GeoDatabaseFile:
    """Описать найденный файл по размеру и хешу, вычисленным транспортом, например `sha256sum`."""
    return GeoDatabaseFile(name, True, size, sha256, source, version)


def missing_geo_database_file(name: str, *, source: str | None = None, version: str | None = None) -> GeoDatabaseFile:
    """Описать отсутствующий файл; он не создаётся и не загружается."""
    return GeoDatabaseFile(name, False, None, None, source, version)


def geo_inventory_from_files(files: Mapping[str, bytes | None]) -> GeoDatabaseInventory:
    """Собрать инвентарь из байтов файлов по именам; `None` означает отсутствующий файл.

    Стандартные `geoip.dat` и `geosite.dat`, не упомянутые в словаре, добавляются
    как отсутствующие. Порядок записей — порядок словаря, затем недостающие
    стандартные имена. Отбор файлов каталога выполняет источник при перечислении.
    """
    if not isinstance(files, Mapping) or any(type(name) is not str for name in files):
        _reject(GeoDataErrorCode.INVENTORY)
    records = []
    for name, content in files.items():
        if content is None:
            records.append(missing_geo_database_file(name))
        else:
            records.append(geo_database_file_from_bytes(name, content))
    for name in STANDARD_FILE_NAMES.values():
        if name not in files:
            records.append(missing_geo_database_file(name))
    return GeoDatabaseInventory(tuple(records))
