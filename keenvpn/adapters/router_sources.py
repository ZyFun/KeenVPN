"""Источники чтения роутера: файлы Xray, XKeen и геобаз Entware и наблюдение процесса Xray.

Каждый класс реализует один порт чтения и передаёт прочитанные байты или
вывод команды существующим преобразователям адаптеров. Пути — константы
проверенной платформы (KN-1811, Entware в `/opt`); корень подменяется только
в тестах. Файлы читаются без перехода по ссылкам и с пределами размера
(`entware_files`), команда — массивом аргументов без shell, с таймаутом,
пустым окружением и проверкой кода возврата. Ничего не записывается и не
запускается, кроме `pidof`; команды XKeen и init не вызываются, init
читается как текст. Успешное чтение не подтверждает работу VPN.
"""

from collections.abc import Callable
import os
import posixpath
import selectors
import subprocess
import time

from keenvpn.adapters.entware_files import digest_files, fail_read, read_file, read_files, regular_file_exists
from keenvpn.adapters.geodata_files import XRAY_ASSET_DIRECTORY, geo_inventory_from_digests
from keenvpn.adapters.xkeen_files import (
    XKEEN_INIT_PATH, XKEEN_LIST_DIRECTORY, XKEEN_SETTINGS_PATH, xkeen_init_from_bytes, xkeen_list_from_bytes,
    xkeen_settings_from_bytes,
)
from keenvpn.adapters.xkeen_runtime import XKEEN_READY_MARKER_PATH, XRAY_PROCESS_NAME, xray_process_from_pidof
from keenvpn.adapters.xray_configs import XRAY_CONFIG_DIRECTORY, xray_config_from_files
from keenvpn.application.ports import RouterReadFailure
from keenvpn.domain.geodata import GeoDatabaseInventory
from keenvpn.domain.manager_metadata import valid_storage_path
from keenvpn.domain.xkeen_config import XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation


KIB = 1024
MIB = 1024 * KIB
XRAY_PART_LIMIT = 1 * MIB
"""Предел одной части конфигурации Xray."""
XRAY_PART_COUNT_LIMIT = 64
"""Предел числа частей `*.json` в каталоге конфигураций."""
XRAY_PARTS_TOTAL_LIMIT = 8 * MIB
"""Предел суммарного размера частей."""
XKEEN_SETTINGS_LIMIT = 256 * KIB
XKEEN_INIT_LIMIT = 1 * MIB
XKEEN_LIST_LIMIT = 256 * KIB
GEO_DATABASE_LIMIT = 256 * MIB
"""Предел одного файла геобазы; файл не загружается в память, SHA-256 считается потоком."""
GEO_DATABASE_COUNT_LIMIT = 32
PIDOF_PATH = "/opt/bin/pidof"
"""`pidof` BusyBox Entware: во встроенной системе Keenetic его нет."""
PIDOF_TIMEOUT = 3.0
"""Секунды на `pidof`; после таймаута процесс завершается."""
PIDOF_OUTPUT_LIMIT = 64 * KIB
_OUTPUT_CHUNK = 64 * KIB

CommandRunner = Callable[[tuple[str, ...], float, int], tuple[int, bytes]]
"""Запуск команды чтения: аргументы, таймаут, предел вывода → код возврата и stdout; отказ — RouterReadError."""


def _collect_output(process: subprocess.Popen, deadline: float, limit: int, chunks: list[bytes]) -> RouterReadFailure | None:
    """Читать stdout до конца порциями, не больше `limit` байт и до крайнего срока; вернуть отказ или None."""
    descriptor = process.stdout.fileno()
    size = 0
    with selectors.DefaultSelector() as selector:
        selector.register(descriptor, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                return RouterReadFailure.TIMEOUT
            # Не больше предела плюс один байт: этого достаточно, чтобы отклонить лишний вывод.
            chunk = os.read(descriptor, min(_OUTPUT_CHUNK, limit + 1 - size))
            if not chunk:
                return None
            size += len(chunk)
            if size > limit:
                return RouterReadFailure.TOO_LARGE
            chunks.append(chunk)


def run_read_command(arguments: tuple[str, ...], timeout: float, limit: int) -> tuple[int, bytes]:
    """Запустить команду массивом аргументов без shell и вернуть код возврата и stdout.

    stdin закрыт, окружение пустое, stderr отбрасывается и в сообщения не
    попадает. stdout читается порциями, всего не больше `limit` плюс один байт,
    в пределах общего срока `timeout`: лишний вывод и истёкший срок завершают
    процесс, не дожидаясь его окончания. Отказ запуска, таймаут и вывод
    больше `limit` — `RouterReadError`.
    """
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            list(arguments), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={}, close_fds=True,
        )
    except FileNotFoundError:
        fail_read(RouterReadFailure.MISSING)
    except PermissionError:
        fail_read(RouterReadFailure.PERMISSION_DENIED)
    except (OSError, subprocess.SubprocessError):
        fail_read(RouterReadFailure.IO_ERROR)
    chunks: list[bytes] = []
    status = None
    try:
        failure = _collect_output(process, deadline, limit, chunks)
        if failure is None:
            try:
                status = process.wait(max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failure = RouterReadFailure.TIMEOUT
    except OSError:
        failure = RouterReadFailure.IO_ERROR
    finally:
        # Процесс, не завершившийся сам, завершается при любом исходе, включая прерывание.
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
    if failure is not None:
        fail_read(failure)
    return status, b"".join(chunks)


def _under(root: str, path: str) -> str:
    """Путь платформы внутри корня; корень, отличный от `/`, задают только тесты."""
    if root == "/":
        return path
    if not valid_storage_path(root):
        raise ValueError("Корень источников чтения роутера задаётся абсолютным нормализованным путём.")
    return root + path


class XrayConfigFiles:
    """`XrayConfigSource`: части `*.json` каталога конфигураций Xray, по порядку имён.

    Подкаталоги пропускаются, как при загрузке каталога Xray; ссылка или
    объект другого типа с окончанием `.json` — отказ всего чтения.
    """

    def __init__(self, *, root: str = "/") -> None:
        self._directory = _under(root, XRAY_CONFIG_DIRECTORY)

    def current_xray_config(self) -> XrayConfigSet:
        files = read_files(
            self._directory, ".json", file_limit=XRAY_PART_LIMIT, total_limit=XRAY_PARTS_TOTAL_LIMIT,
            count_limit=XRAY_PART_COUNT_LIMIT,
        )
        return xray_config_from_files(files)


class XKeenSettingsFile:
    """`XKeenSettingsSource`: `xkeen.json` целиком."""

    def __init__(self, *, root: str = "/") -> None:
        self._path = _under(root, XKEEN_SETTINGS_PATH)

    def current_xkeen_settings(self) -> XKeenSettings:
        return xkeen_settings_from_bytes(read_file(self._path, XKEEN_SETTINGS_LIMIT))


class XKeenInitFile:
    """`XKeenInitSource`: текст стартового сценария XKeen как данные; сценарий не исполняется."""

    def __init__(self, *, root: str = "/") -> None:
        self._path = _under(root, XKEEN_INIT_PATH)

    def current_xkeen_init(self) -> XKeenInitParameters:
        return xkeen_init_from_bytes(read_file(self._path, XKEEN_INIT_LIMIT))


class XKeenListFiles:
    """`XKeenListSource`: один из трёх списков каталога XKeen по имени."""

    def __init__(self, *, root: str = "/") -> None:
        self._directory = _under(root, XKEEN_LIST_DIRECTORY)

    def current_xkeen_list(self, name: XKeenListName) -> XKeenList:
        if type(name) is not XKeenListName:
            raise TypeError("Список XKeen задаётся XKeenListName.")
        return xkeen_list_from_bytes(name, read_file(posixpath.join(self._directory, name.value), XKEEN_LIST_LIMIT))


class GeoDatabaseFiles:
    """`GeoDatabaseSource`: размер и SHA-256 файлов `*.dat` каталога геобаз.

    Отсутствующие стандартные базы описываются как отсутствующие; отсутствие
    самого каталога — отказ. Источник и версия базы не выводятся из имени файла.
    """

    def __init__(self, *, root: str = "/") -> None:
        self._directory = _under(root, XRAY_ASSET_DIRECTORY)

    def current_geo_databases(self) -> GeoDatabaseInventory:
        files = digest_files(
            self._directory, ".dat", file_limit=GEO_DATABASE_LIMIT, count_limit=GEO_DATABASE_COUNT_LIMIT,
        )
        return geo_inventory_from_digests(files)


class XrayProcessObserver:
    """`XrayProcessSource`: вывод `pidof xray` и наличие маркера готовности XKeen.

    `pidof` с кодом 0 и PID либо с кодом 1 и пустым выводом — наблюдение;
    другое сочетание — отказ `exit_status`. Затем проверяется маркер без
    перехода по ссылке: отсутствие файла или каталога — маркера нет.
    Между двумя наблюдениями состояние может измениться.
    """

    def __init__(self, *, root: str = "/", run: CommandRunner = run_read_command) -> None:
        if not callable(run):
            raise TypeError("Запуск команды задаётся вызываемым объектом.")
        self._marker = _under(root, XKEEN_READY_MARKER_PATH)
        self._run = run

    def current_xray_process(self) -> XrayProcessObservation:
        status, output = self._run((PIDOF_PATH, XRAY_PROCESS_NAME), PIDOF_TIMEOUT, PIDOF_OUTPUT_LIMIT)
        if type(status) is not int or type(output) is not bytes:
            raise TypeError("Запуск команды вернул результат неверного типа.")
        if not ((status == 0 and output.strip()) or (status == 1 and not output)):
            fail_read(RouterReadFailure.EXIT_STATUS)
        return xray_process_from_pidof(output, regular_file_exists(self._marker))
