"""Чтение файлов Entware без перехода по символическим ссылкам и с пределами размера.

Пути задаёт вызывающий код константами проверенной платформы; из ввода они
не принимаются. Каталог открывается от корня по одному компоненту с
`O_NOFOLLOW`, поэтому символическая ссылка в любом компоненте пути — отказ,
а не переход. Файл читается через дескриптор не больше предела плюс один
байт; состояние файла сверяется до и после чтения, набор файлов каталога
— повторным перечислением, а сам каталог — повторным проходом пути от корня.
Ничего не записывается, не создаётся и не
исполняется. Отказы — `RouterReadError` с безопасным кодом без путей и
текста системной ошибки.

Обход каталогов без ссылок используют также хранилище метаданных менеджера:
`walk_directory` и `classify_open_failure` переводят отказ в вид
`PathFailure`, а вызывающий код — в свои коды.
"""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import StrEnum
import errno
import hashlib
import os
import posixpath
import stat
from typing import NoReturn

from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.domain.manager_metadata import valid_storage_path


DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
"""Флаги открытия каталога без перехода по ссылке."""
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
"""`O_NONBLOCK` не даёт зависнуть на FIFO: его тип отклоняется после открытия."""
_CHUNK = 1024 * 1024


class PathFailure(StrEnum):
    """Почему не открылся компонент пути; вызывающий код переводит вид в свой отказ."""

    MISSING = "missing"
    SYMLINK = "symlink"
    NOT_DIRECTORY = "not_directory"
    NOT_REGULAR_FILE = "not_regular_file"
    PERMISSION_DENIED = "permission_denied"
    IO_ERROR = "io_error"


def classify_open_failure(parent: int, name: str, error: OSError, *, directory: bool) -> PathFailure:
    """Объяснить отказ открытия по типу объекта без перехода по ссылке.

    Коды ошибок `O_NOFOLLOW` для ссылки различаются между системами,
    поэтому тип определяется отдельным `lstat` относительно дескриптора родителя.
    """
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return PathFailure.MISSING
    except OSError:
        return PathFailure.IO_ERROR
    if stat.S_ISLNK(info.st_mode):
        return PathFailure.SYMLINK
    if directory and not stat.S_ISDIR(info.st_mode):
        return PathFailure.NOT_DIRECTORY
    if not directory and not stat.S_ISREG(info.st_mode):
        return PathFailure.NOT_REGULAR_FILE
    if error.errno in (errno.EACCES, errno.EPERM):
        return PathFailure.PERMISSION_DENIED
    return PathFailure.IO_ERROR


@contextmanager
def walk_directory(path: str, fail: Callable[[PathFailure], NoReturn]) -> Iterator[int]:
    """Открыть каталог по абсолютному пути, не проходя по ссылкам ни в одном компоненте.

    Отказ передаётся в `fail`, который обязан поднять исключение вызывающего кода.
    Дескриптор закрывается при выходе из блока.
    """
    try:
        descriptor = os.open("/", DIRECTORY_FLAGS)
    except OSError:
        fail(PathFailure.IO_ERROR)
    try:
        for name in (part for part in path.split("/") if part):
            try:
                child = os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as error:
                fail(classify_open_failure(descriptor, name, error, directory=True))
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


_PATH_FAILURES = {
    PathFailure.MISSING: RouterReadFailure.MISSING,
    PathFailure.SYMLINK: RouterReadFailure.UNSAFE,
    PathFailure.NOT_DIRECTORY: RouterReadFailure.UNSAFE,
    PathFailure.NOT_REGULAR_FILE: RouterReadFailure.UNSAFE,
    PathFailure.PERMISSION_DENIED: RouterReadFailure.PERMISSION_DENIED,
    PathFailure.IO_ERROR: RouterReadFailure.IO_ERROR,
}


def fail_read(failure: RouterReadFailure) -> NoReturn:
    """Отказ чтения без активного чужого исключения в цепочке: его текст содержит путь."""
    try:
        raise RouterReadError(failure) from None
    except RouterReadError as error:
        error.__context__ = None
        raise


def _fail_path(kind: PathFailure) -> NoReturn:
    fail_read(_PATH_FAILURES[kind])


def _split(path: str) -> tuple[str, str]:
    """Каталог и имя файла по абсолютному нормализованному пути; иной путь отклоняется."""
    if not valid_storage_path(path):
        fail_read(RouterReadFailure.UNSAFE)
    return posixpath.dirname(path), posixpath.basename(path)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    """Признаки, по которым видна замена или правка файла между двумя наблюдениями."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _changed_path(kind: PathFailure) -> NoReturn:
    fail_read(RouterReadFailure.IO_ERROR if kind is PathFailure.IO_ERROR else RouterReadFailure.CHANGED)


def _confirm_path(path: str, directory: int) -> None:
    """Путь по-прежнему ведёт к удерживаемому каталогу; иначе — отказ `changed`.

    Удерживаемый дескриптор видит прежний каталог и после его замены
    переименованием, поэтому путь проходится от корня заново без перехода
    по ссылкам. Замена каталога или его предка, исчезновение компонента
    и ссылка на его месте означают, что источник изменился во время чтения.
    """
    try:
        held = os.fstat(directory)
    except OSError:
        fail_read(RouterReadFailure.IO_ERROR)
    with walk_directory(path, _changed_path) as current:
        try:
            current_info = os.fstat(current)
        except OSError:
            fail_read(RouterReadFailure.IO_ERROR)
    if not os.path.samestat(held, current_info):
        fail_read(RouterReadFailure.CHANGED)


def _read_entry(
    directory: int, name: str, limit: int, consume: Callable[[bytes], object], *, listed: bool = False,
) -> int:
    """Прочитать обычный файл каталога потоком не больше `limit` байт и вернуть размер.

    Файл, изменившийся или заменённый во время чтения, — отказ `changed`;
    исчезновение файла, найденного перечислением каталога (`listed`), — тоже.
    """
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory)
    except OSError as error:
        kind = classify_open_failure(directory, name, error, directory=False)
        if listed and kind is PathFailure.MISSING:
            fail_read(RouterReadFailure.CHANGED)
        _fail_path(kind)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail_read(RouterReadFailure.UNSAFE)
        if before.st_size > limit:
            fail_read(RouterReadFailure.TOO_LARGE)
        size = 0
        # Не больше предела плюс один байт: этого достаточно, чтобы отклонить выросший файл.
        while chunk := os.read(descriptor, min(_CHUNK, limit + 1 - size)):
            size += len(chunk)
            if size > limit:
                fail_read(RouterReadFailure.TOO_LARGE)
            consume(chunk)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        fail_read(RouterReadFailure.CHANGED)
    except OSError:
        fail_read(RouterReadFailure.IO_ERROR)
    finally:
        os.close(descriptor)
    if _identity(before) != _identity(after) or size != after.st_size or _identity(current) != _identity(after):
        fail_read(RouterReadFailure.CHANGED)
    return size


def read_file(path: str, limit: int) -> bytes:
    """Прочитать обычный файл целиком, не больше `limit` байт."""
    parent, name = _split(path)
    chunks: list[bytes] = []
    with walk_directory(parent, _fail_path) as directory:
        _read_entry(directory, name, limit, chunks.append)
        _confirm_path(parent, directory)
    return b"".join(chunks)


def _entries(directory: int, suffix: str, count_limit: int) -> dict[str, tuple[int, ...]]:
    """Обычные файлы каталога с окончанием `suffix` по именам; подкаталоги пропускаются.

    Ссылка или объект другого типа с таким окончанием — отказ: прочитать
    вместо него ничего нельзя, а пропуск исказил бы набор файлов.
    """
    try:
        names = os.listdir(directory)
    except OSError:
        fail_read(RouterReadFailure.IO_ERROR)
    entries = {}
    for name in sorted(name for name in names if name.endswith(suffix)):
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            fail_read(RouterReadFailure.CHANGED)
        except OSError:
            fail_read(RouterReadFailure.IO_ERROR)
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            fail_read(RouterReadFailure.UNSAFE)
        entries[name] = _identity(info)
        if len(entries) > count_limit:
            fail_read(RouterReadFailure.TOO_LARGE)
    return entries


def _read_directory(
    path: str, suffix: str, count_limit: int, read: Callable[[int, str], object],
) -> dict[str, object]:
    """Прочитать файлы каталога по порядку имён и убедиться, что ни набор, ни каталог по пути не изменились."""
    if not valid_storage_path(path):
        fail_read(RouterReadFailure.UNSAFE)
    with walk_directory(path, _fail_path) as directory:
        entries = _entries(directory, suffix, count_limit)
        values = {name: read(directory, name) for name in entries}
        if _entries(directory, suffix, count_limit) != entries:
            fail_read(RouterReadFailure.CHANGED)
        _confirm_path(path, directory)
    return values


def read_files(path: str, suffix: str, *, file_limit: int, total_limit: int, count_limit: int) -> dict[str, bytes]:
    """Прочитать обычные файлы каталога с окончанием `suffix`: имя — байты, по порядку имён."""
    total = 0

    def read(directory: int, name: str) -> bytes:
        nonlocal total
        chunks: list[bytes] = []
        total += _read_entry(directory, name, file_limit, chunks.append, listed=True)
        if total > total_limit:
            fail_read(RouterReadFailure.TOO_LARGE)
        return b"".join(chunks)

    return _read_directory(path, suffix, count_limit, read)


def digest_files(path: str, suffix: str, *, file_limit: int, count_limit: int) -> dict[str, tuple[int, str]]:
    """Размер и SHA-256 обычных файлов каталога с окончанием `suffix`; файлы не загружаются в память."""

    def digest(directory: int, name: str) -> tuple[int, str]:
        hasher = hashlib.sha256()
        size = _read_entry(directory, name, file_limit, hasher.update, listed=True)
        return size, hasher.hexdigest()

    return _read_directory(path, suffix, count_limit, digest)


def regular_file_exists(path: str) -> bool:
    """Есть ли обычный файл по пути; отсутствие файла или каталога — `False`, ссылка — отказ."""
    parent, name = _split(path)
    try:
        with walk_directory(parent, _fail_path) as directory:
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return False
            except PermissionError:
                fail_read(RouterReadFailure.PERMISSION_DENIED)
            except OSError:
                fail_read(RouterReadFailure.IO_ERROR)
    except RouterReadError as error:
        if error.failure is RouterReadFailure.MISSING:
            return False
        raise
    if not stat.S_ISREG(info.st_mode):
        fail_read(RouterReadFailure.UNSAFE)
    return True
