"""Файловое хранилище собственных метаданных менеджера в явно заданном каталоге.

Каталог задаёт вызывающий код: значение по умолчанию не выбирается, а при
недоступности не используются другой каталог, `/opt` или RAM. Родитель
каталога должен существовать; ни один компонент пути не может быть
символической ссылкой. Собственный каталог создаётся при первой записи
с правами 700, файл записывается с правами 600: временный файл в том же
каталоге, fsync файла, переименование поверх прежнего и fsync каталога.
Запись требует ожидаемой ревизии и выполняется под эксклюзивной
блокировкой каталога; конфликт возвращается отказом без перезаписи.
Каталоги конфигураций Xray и XKeen для метаданных запрещены. Идентичность
раздела по UUID и свободное место заранее этот адаптер не проверяет.
"""

from collections.abc import Iterator
from contextlib import contextmanager
import errno
import fcntl
import os
import posixpath
import re
import stat
from typing import NoReturn

from keenvpn.adapters.xkeen_files import XKEEN_LIST_DIRECTORY
from keenvpn.adapters.xray_configs import XRAY_CONFIG_DIRECTORY
from keenvpn.application.ports import ManagerMetadataStoreError, MetadataStoreFailure, MetadataStoreReason
from keenvpn.domain.manager_metadata import (
    MAX_METADATA_SIZE, ManagerMetadata, ManagerMetadataError, StoredManagerMetadata,
    decode_manager_metadata, encode_manager_metadata, metadata_revision, valid_storage_path,
)


METADATA_FILE_NAME = "manager-metadata.json"
"""Имя файла метаданных в собственном каталоге."""
PROTECTED_DIRECTORIES = (posixpath.dirname(XRAY_CONFIG_DIRECTORY), XKEEN_LIST_DIRECTORY)
"""Каталоги конфигураций Xray и XKeen: метаданные не размещаются в них и внутри них."""

_TEMPORARY_PREFIX = "." + METADATA_FILE_NAME + ".tmp-"
_TEMPORARY = re.compile(re.escape(_TEMPORARY_PREFIX) + r"[0-9a-f]{16}")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700
_NO_SPACE = frozenset(code for code in (errno.ENOSPC, getattr(errno, "EDQUOT", None)) if code is not None)


def _raise(failure: MetadataStoreFailure, reason: MetadataStoreReason | str | None = None) -> NoReturn:
    """Отказ без активного чужого исключения в цепочке: его текст содержит путь."""
    value = reason.value if isinstance(reason, MetadataStoreReason) else reason
    try:
        raise ManagerMetadataStoreError(failure, reason=value) from None
    except ManagerMetadataStoreError as error:
        error.__context__ = None
        raise


def _write_reason(error: OSError) -> MetadataStoreReason:
    if error.errno in _NO_SPACE:
        return MetadataStoreReason.NO_SPACE
    if error.errno == errno.EROFS:
        return MetadataStoreReason.READ_ONLY
    if error.errno in (errno.EACCES, errno.EPERM):
        return MetadataStoreReason.PERMISSION_DENIED
    return MetadataStoreReason.IO_ERROR


def _open_failed(parent: int, name: str, error: OSError, *, directory: bool) -> NoReturn:
    """Объяснить отказ открытия по типу объекта без перехода по ссылке.

    Коды ошибок `O_NOFOLLOW` для ссылки различаются между системами,
    поэтому тип определяется отдельным `lstat`.
    """
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        _raise(MetadataStoreFailure.UNAVAILABLE, MetadataStoreReason.MISSING)
    except OSError:
        _raise(MetadataStoreFailure.UNAVAILABLE, MetadataStoreReason.IO_ERROR)
    if stat.S_ISLNK(info.st_mode):
        _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.SYMLINK)
    if directory and not stat.S_ISDIR(info.st_mode):
        _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.NOT_DIRECTORY)
    if not directory and not stat.S_ISREG(info.st_mode):
        _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.NOT_REGULAR_FILE)
    if error.errno in (errno.EACCES, errno.EPERM):
        _raise(MetadataStoreFailure.UNAVAILABLE, MetadataStoreReason.PERMISSION_DENIED)
    _raise(MetadataStoreFailure.UNAVAILABLE, MetadataStoreReason.IO_ERROR)


@contextmanager
def _walk(path: str) -> Iterator[int]:
    """Открыть каталог по абсолютному пути, не проходя по ссылкам ни в одном компоненте."""
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for name in (part for part in path.split("/") if part):
            try:
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as error:
                _open_failed(descriptor, name, error, directory=True)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


class ManagerMetadataFiles:
    """Реализация `ManagerMetadataStore` на файловой системе.

    `directory` — абсолютный нормализованный путь собственного каталога
    метаданных без символических ссылок, например на выбранном разделе.
    Каталог, совпадающий с одним из `protected_directories` или вложенный
    в него, отклоняется до любого обращения к файловой системе.
    """

    def __init__(self, directory: str, *, protected_directories: tuple[str, ...] = PROTECTED_DIRECTORIES) -> None:
        self._directory = directory
        self._protected = protected_directories

    def _location(self) -> tuple[str, str]:
        directory, protected = self._directory, self._protected
        if (
            not valid_storage_path(directory) or type(protected) is not tuple
            or not all(valid_storage_path(item) for item in protected)
        ):
            _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.INVALID_DIRECTORY)
        if any(directory == item or directory.startswith(item + "/") for item in protected):
            _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.PROTECTED_DIRECTORY)
        return posixpath.dirname(directory), posixpath.basename(directory)

    def read_metadata(self) -> StoredManagerMetadata | None:
        """Прочитать файл без блокировки: запись публикует его одним переименованием.

        `None` — собственного каталога или файла ещё нет; отсутствие родителя
        является отказом `metadata_store_unavailable`.
        """
        parent_path, name = self._location()
        with _walk(parent_path) as parent:
            directory = self._open_directory(parent, name, create=False)
            if directory is None:
                return None
            try:
                return self._read(directory)
            finally:
                os.close(directory)

    def write_metadata(self, metadata: ManagerMetadata, expected_revision: str | None) -> str:
        """Записать при совпадении ревизии и вернуть новую.

        Модель проверяется до обращения к файловой системе: некорректная
        вызывает `ManagerMetadataError`. Повреждённый файл и файл другой
        версии схемы не перезаписываются. Совпадающие байты не записываются
        повторно, но файл и каталог закрепляются fsync.
        """
        content = encode_manager_metadata(metadata)
        revision = metadata_revision(content)
        parent_path, name = self._location()
        with _walk(parent_path) as parent:
            directory = self._open_directory(parent, name, create=True)
            try:
                try:
                    fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    _raise(MetadataStoreFailure.BUSY)
                except OSError:
                    _raise(MetadataStoreFailure.UNAVAILABLE, MetadataStoreReason.IO_ERROR)
                self._remove_stale(directory)
                current = self._check_revision(directory, expected_revision)
                if current is None or current.revision != revision:
                    self._replace(directory, content, expected_revision)
                else:
                    self._confirm(directory)
            finally:
                # Закрытие дескриптора снимает блокировку.
                os.close(directory)
        return revision

    def _open_directory(self, parent: int, name: str, *, create: bool) -> int | None:
        created = False
        if create:
            try:
                os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
            except OSError as error:
                _raise(MetadataStoreFailure.WRITE_FAILED, _write_reason(error))
        try:
            descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            if not create:
                return None
            _raise(MetadataStoreFailure.UNAVAILABLE, MetadataStoreReason.MISSING)
        except OSError as error:
            _open_failed(parent, name, error, directory=True)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid():
                _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.OWNER)
            if created:
                # Права после umask; родителя закрепить на диске вместе с новым каталогом.
                os.fchmod(descriptor, _DIRECTORY_MODE)
                os.fsync(parent)
                info = os.fstat(descriptor)
            if stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE:
                _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.PERMISSIONS)
        except BaseException as error:
            os.close(descriptor)
            if not isinstance(error, OSError):
                raise
            reason = _write_reason(error)
        else:
            return descriptor
        _raise(MetadataStoreFailure.WRITE_FAILED if created else MetadataStoreFailure.UNAVAILABLE, reason)

    def _read(self, directory: int) -> StoredManagerMetadata | None:
        try:
            descriptor = os.open(METADATA_FILE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError as error:
            _open_failed(directory, METADATA_FILE_NAME, error, directory=False)
        chunks = []
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.NOT_REGULAR_FILE)
            if info.st_uid != os.geteuid():
                _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.OWNER)
            if stat.S_IMODE(info.st_mode) != _FILE_MODE:
                _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.PERMISSIONS)
            size = 0
            # Не больше предела плюс один байт: этого достаточно, чтобы отклонить большой файл.
            while size <= MAX_METADATA_SIZE:
                chunk = os.read(descriptor, MAX_METADATA_SIZE + 1 - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
        except OSError:
            _raise(MetadataStoreFailure.UNAVAILABLE, MetadataStoreReason.IO_ERROR)
        finally:
            os.close(descriptor)
        code = None
        try:
            return decode_manager_metadata(b"".join(chunks))
        except ManagerMetadataError as error:
            code = error.code
        _raise(MetadataStoreFailure.INVALID, code.value)

    def _check_revision(self, directory: int, expected_revision: str | None) -> StoredManagerMetadata | None:
        """Прочитать текущий файл и отказать, если его ревизия не совпала с ожидаемой."""
        current = self._read(directory)
        if (None if current is None else current.revision) != expected_revision:
            _raise(MetadataStoreFailure.CONFLICT)
        return current

    def _confirm(self, directory: int) -> None:
        """Закрепить на диске уже опубликованный файл с теми же байтами без перезаписи.

        Иначе повтор после `metadata_write_unconfirmed` вернул бы успех,
        так и не подтвердив сохранность файла и переименования.
        """
        try:
            descriptor = os.open(METADATA_FILE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory)
        except OSError:
            _raise(MetadataStoreFailure.WRITE_UNCONFIRMED, MetadataStoreReason.IO_ERROR)

    def _remove_stale(self, directory: int) -> None:
        """Удалить временные файлы прерванной записи; под блокировкой живых записей нет.

        Удаляются только обычные файлы владельца с именем временного файла
        этого адаптера; остальное содержимое каталога не трогается.
        """
        try:
            names = os.listdir(directory)
        except OSError:
            return
        for name in names:
            if _TEMPORARY.fullmatch(name) is None:
                continue
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid():
                    os.unlink(name, dir_fd=directory)
            except OSError:
                # Оставшийся временный файл не читается как метаданные и не мешает записи.
                pass

    def _check_identity(self, directory: int) -> None:
        """Каталог по настроенному пути должен оставаться тем, в котором идёт запись."""
        expected = os.fstat(directory)
        replaced = False
        try:
            with _walk(self._directory) as current:
                replaced = not os.path.samestat(expected, os.fstat(current))
        except ManagerMetadataStoreError:
            replaced = True
        if replaced:
            _raise(MetadataStoreFailure.UNSAFE, MetadataStoreReason.REPLACED)

    def _replace(self, directory: int, content: bytes, expected_revision: str | None) -> None:
        name = _TEMPORARY_PREFIX + os.urandom(8).hex()
        descriptor = None
        created = False
        reason = None
        try:
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, _FILE_MODE, dir_fd=directory,
            )
            created = True
            os.fchmod(descriptor, _FILE_MODE)
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            self._check_identity(directory)
            # Писатели через адаптер исключены блокировкой. Правку в обход неё, сделанную
            # во время записи временного файла, ловит повторное сравнение; остаётся только
            # промежуток между этим чтением и переименованием.
            self._check_revision(directory, expected_revision)
            os.replace(name, METADATA_FILE_NAME, src_dir_fd=directory, dst_dir_fd=directory)
            created = False
        except BaseException as error:
            # Прежний файл не тронут, пока переименование не выполнено.
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if created:
                try:
                    os.unlink(name, dir_fd=directory)
                except OSError:
                    pass
            if not isinstance(error, OSError):
                raise
            reason = _write_reason(error)
        if reason is not None:
            _raise(MetadataStoreFailure.WRITE_FAILED, reason)
        try:
            os.fsync(directory)
        except OSError:
            _raise(MetadataStoreFailure.WRITE_UNCONFIRMED, MetadataStoreReason.IO_ERROR)
