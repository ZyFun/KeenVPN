"""Один приватный файл менеджера в явно заданном собственном каталоге.

Общая механика хранилищ метаданных и черновика. Каталог задаёт вызывающий
код: значение по умолчанию не выбирается, а при недоступности не
используются другой каталог, `/opt` или RAM. Родитель каталога должен
существовать; ни один компонент пути не может быть символической ссылкой.
Собственный каталог создаётся при первой записи с правами 700, файл
записывается с правами 600: временный файл в том же каталоге, fsync файла,
переименование поверх прежнего и fsync каталога. Запись и удаление требуют
ожидаемой ревизии и выполняются под эксклюзивной блокировкой каталога;
конфликт возвращается отказом без изменения файла. Каталоги конфигураций
Xray и XKeen и каталог init для хранилищ запрещены. Идентичность раздела
по UUID и свободное место заранее не проверяются.
"""

from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from enum import StrEnum
import errno
import fcntl
import os
import posixpath
import re
import stat
from typing import ClassVar, NoReturn, Protocol

from keenvpn.adapters.entware_files import DIRECTORY_FLAGS, PathFailure, classify_open_failure, walk_directory
from keenvpn.adapters.xkeen_files import XKEEN_INIT_PATH, XKEEN_LIST_DIRECTORY
from keenvpn.adapters.xray_configs import XRAY_CONFIG_DIRECTORY
from keenvpn.application.ports import StoreReason
from keenvpn.domain.manager_metadata import valid_storage_path


PROTECTED_DIRECTORIES = (
    posixpath.dirname(XRAY_CONFIG_DIRECTORY), XKEEN_LIST_DIRECTORY, posixpath.dirname(XKEEN_INIT_PATH),
)
"""Каталоги конфигураций Xray и XKeen и init: хранилища менеджера не размещаются в них и внутри них."""

_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700
_NO_SPACE = frozenset(code for code in (errno.ENOSPC, getattr(errno, "EDQUOT", None)) if code is not None)


class StoreFailure(StrEnum):
    """Вид отказа хранилища; каждый подкласс переводит его в коды своего порта."""

    UNAVAILABLE = "unavailable"
    UNSAFE = "unsafe"
    BUSY = "busy"
    CONFLICT = "conflict"
    INVALID = "invalid"
    WRITE_FAILED = "write_failed"
    WRITE_UNCONFIRMED = "write_unconfirmed"


class StoredFile(Protocol):
    """Разобранное содержимое файла с ревизией его байтов."""

    revision: str


def _write_reason(error: OSError) -> StoreReason:
    if error.errno in _NO_SPACE:
        return StoreReason.NO_SPACE
    if error.errno == errno.EROFS:
        return StoreReason.READ_ONLY
    if error.errno in (errno.EACCES, errno.EPERM):
        return StoreReason.PERMISSION_DENIED
    return StoreReason.IO_ERROR


_UNSAFE_PATHS = {
    PathFailure.SYMLINK: StoreReason.SYMLINK,
    PathFailure.NOT_DIRECTORY: StoreReason.NOT_DIRECTORY,
    PathFailure.NOT_REGULAR_FILE: StoreReason.NOT_REGULAR_FILE,
}


class PrivateFileStore[StoredT: StoredFile]:
    """Файл с именем `file_name` в собственном каталоге `directory`.

    Подкласс задаёт имя и предел размера файла, тип отказа и перевод видов
    отказа в коды своего порта, разбор байтов и ревизию; публичные методы
    порта вызывают `_read_file`, `_write_file` и `_remove_file`. Отказ — всегда
    исключение `error_type` без активного чужого исключения в цепочке.
    `directory` — абсолютный нормализованный путь без символических ссылок;
    каталог, совпадающий с одним из `protected_directories` или вложенный
    в него, отклоняется до любого обращения к файловой системе.
    """

    file_name: ClassVar[str]
    max_size: ClassVar[int]
    error_type: ClassVar[type[Exception]]
    failures: ClassVar[Mapping[StoreFailure, StrEnum]]
    revision_of: ClassVar[Callable[[bytes], str]]

    def __init__(self, directory: str, *, protected_directories: tuple[str, ...] = PROTECTED_DIRECTORIES) -> None:
        self._directory = directory
        self._protected = protected_directories
        self._temporary_prefix = "." + self.file_name + ".tmp-"
        self._temporary = re.compile(re.escape(self._temporary_prefix) + r"[0-9a-f]{16}")

    def _decode(self, content: bytes) -> StoredT:
        """Разобрать байты файла; нарушение формата — `_raise(StoreFailure.INVALID, код домена)`."""
        raise NotImplementedError

    def _raise(self, failure: StoreFailure, reason: StoreReason | str | None = None) -> NoReturn:
        """Отказ без активного чужого исключения в цепочке: его текст содержит путь."""
        value = reason.value if isinstance(reason, StoreReason) else reason
        try:
            raise self.error_type(self.failures[failure], reason=value) from None
        except self.error_type as error:
            error.__context__ = None
            raise

    def _path_failed(self, kind: PathFailure, missing_failure: StoreFailure = StoreFailure.UNAVAILABLE) -> NoReturn:
        """Перевести отказ компонента пути в отказ хранилища.

        При подтверждении файла его отсутствие означает конфликт ревизии,
        а не недоступность хранилища.
        """
        if kind is PathFailure.MISSING:
            self._raise(missing_failure, StoreReason.MISSING if missing_failure is StoreFailure.UNAVAILABLE else None)
        if kind in _UNSAFE_PATHS:
            self._raise(StoreFailure.UNSAFE, _UNSAFE_PATHS[kind])
        if kind is PathFailure.PERMISSION_DENIED:
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.PERMISSION_DENIED)
        self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)

    def _open_failed(
        self, parent: int, name: str, error: OSError, *, directory: bool,
        missing_failure: StoreFailure = StoreFailure.UNAVAILABLE,
    ) -> NoReturn:
        """Объяснить отказ открытия по типу объекта без перехода по ссылке."""
        self._path_failed(classify_open_failure(parent, name, error, directory=directory), missing_failure)

    def _walk(self, path: str) -> AbstractContextManager[int]:
        """Открыть каталог по абсолютному пути, не проходя по ссылкам ни в одном компоненте."""
        return walk_directory(path, self._path_failed)

    def _location(self) -> tuple[str, str]:
        directory, protected = self._directory, self._protected
        if (
            not valid_storage_path(directory) or type(protected) is not tuple
            or not all(valid_storage_path(item) for item in protected)
        ):
            self._raise(StoreFailure.UNSAFE, StoreReason.INVALID_DIRECTORY)
        if any(directory == item or directory.startswith(item + "/") for item in protected):
            self._raise(StoreFailure.UNSAFE, StoreReason.PROTECTED_DIRECTORY)
        return posixpath.dirname(directory), posixpath.basename(directory)

    def _read_file(self) -> StoredT | None:
        """Прочитать файл без блокировки: запись публикует его одним переименованием.

        `None` — собственного каталога или файла ещё нет; отсутствие родителя
        является отказом `UNAVAILABLE`.
        """
        parent_path, name = self._location()
        with self._walk(parent_path) as parent:
            directory = self._open_directory(parent, name, create=False)
            if directory is None:
                return None
            try:
                return self._read(directory)
            finally:
                os.close(directory)

    def _write_file(self, content: bytes, expected_revision: str | None) -> str:
        """Записать готовые байты при совпадении ревизии и вернуть новую.

        `expected_revision=None` — файла быть не должно. Повреждённый файл
        и файл другой версии схемы не перезаписываются. Совпадающие байты
        не записываются повторно, но файл и каталог закрепляются fsync.
        """
        revision = self.revision_of(content)
        parent_path, name = self._location()
        with self._walk(parent_path) as parent:
            directory = self._open_directory(parent, name, create=True)
            try:
                self._lock(directory)
                self._remove_stale(directory)
                current = self._check_revision(directory, expected_revision)
                if current is None or current.revision != revision:
                    self._replace(directory, content, expected_revision)
                else:
                    self._confirm(directory, expected_revision)
            finally:
                # Закрытие дескриптора снимает блокировку.
                os.close(directory)
        return revision

    def _remove_file(self, expected_revision: str) -> None:
        """Удалить файл при совпадении ревизии; каталог и чужие файлы в нём остаются.

        Повреждённый файл и файл другой версии схемы не удаляются: их ревизию
        нельзя сверить. Отсутствие каталога или файла — конфликт ревизии.
        """
        parent_path, name = self._location()
        with self._walk(parent_path) as parent:
            directory = self._open_directory(parent, name, create=False)
            if directory is None:
                self._raise(StoreFailure.CONFLICT)
            try:
                self._lock(directory)
                self._remove_stale(directory)
                self._unlink(directory, expected_revision)
            finally:
                os.close(directory)

    def _confirm_absent(self) -> None:
        """Закрепить на диске отсутствие файла, ничего не меняя в каталоге.

        Иначе повтор после неподтверждённого удаления вернул бы успех, так и
        не подтвердив удаление. Нет собственного каталога — подтверждать
        нечего: хранилище его не удаляет. Появившийся файл не трогается —
        конфликт ревизии.
        """
        parent_path, name = self._location()
        with self._walk(parent_path) as parent:
            directory = self._open_directory(parent, name, create=False)
            if directory is None:
                return
            try:
                self._lock(directory)
                self._check_identity(directory)
                self._check_absent(directory)
                self._sync_absent(directory)
            finally:
                os.close(directory)

    def _lock(self, directory: int) -> None:
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._raise(StoreFailure.BUSY)
        except OSError:
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)

    def _open_directory(self, parent: int, name: str, *, create: bool) -> int | None:
        created = False
        if create:
            try:
                os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
            except OSError as error:
                self._raise(StoreFailure.WRITE_FAILED, _write_reason(error))
        try:
            descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            if not create:
                return None
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.MISSING)
        except OSError as error:
            self._open_failed(parent, name, error, directory=True)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid():
                self._raise(StoreFailure.UNSAFE, StoreReason.OWNER)
            if created:
                # Точные права после umask.
                os.fchmod(descriptor, _DIRECTORY_MODE)
                info = os.fstat(descriptor)
            if stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE:
                self._raise(StoreFailure.UNSAFE, StoreReason.PERMISSIONS)
            if create:
                # Предыдущая попытка могла оставить каталог после отказа fsync родителя.
                os.fsync(parent)
        except BaseException as error:
            os.close(descriptor)
            if not isinstance(error, OSError):
                raise
            reason = _write_reason(error)
        else:
            return descriptor
        self._raise(StoreFailure.WRITE_FAILED if created else StoreFailure.UNAVAILABLE, reason)

    def _read(self, directory: int) -> StoredT | None:
        try:
            descriptor = os.open(self.file_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError as error:
            self._open_failed(directory, self.file_name, error, directory=False)
        chunks = []
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                self._raise(StoreFailure.UNSAFE, StoreReason.NOT_REGULAR_FILE)
            if info.st_uid != os.geteuid():
                self._raise(StoreFailure.UNSAFE, StoreReason.OWNER)
            if stat.S_IMODE(info.st_mode) != _FILE_MODE:
                self._raise(StoreFailure.UNSAFE, StoreReason.PERMISSIONS)
            size = 0
            # Не больше предела плюс один байт: этого достаточно, чтобы отклонить большой файл.
            while size <= self.max_size:
                chunk = os.read(descriptor, self.max_size + 1 - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
        except OSError:
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)
        finally:
            os.close(descriptor)
        return self._decode(b"".join(chunks))

    def _check_revision(self, directory: int, expected_revision: str | None) -> StoredT | None:
        """Прочитать текущий файл и отказать, если его ревизия не совпала с ожидаемой."""
        current = self._read(directory)
        if (None if current is None else current.revision) != expected_revision:
            self._raise(StoreFailure.CONFLICT)
        return current

    def _open_current(self, directory: int) -> int:
        """Открыть итоговый файл для fsync; его отсутствие — конфликт ревизии."""
        try:
            return os.open(self.file_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            self._raise(StoreFailure.CONFLICT)
        except OSError as error:
            self._open_failed(directory, self.file_name, error, directory=False, missing_failure=StoreFailure.CONFLICT)

    def _confirm(self, directory: int, expected_revision: str | None) -> None:
        """Закрепить на диске уже опубликованный файл с теми же байтами без перезаписи.

        Иначе повтор после неподтверждённой записи вернул бы успех,
        так и не подтвердив сохранность файла и переименования.
        Проверки до и после fsync отклоняют внешнюю правку файла и подмену
        каталога, сделанные в обход блокировки во время подтверждения.
        """
        self._check_identity(directory)
        self._check_revision(directory, expected_revision)
        descriptor = self._open_current(directory)
        try:
            try:
                self._check_file_identity(directory, descriptor)
                os.fsync(descriptor)
                os.fsync(directory)
                self._check_identity(directory)
                self._check_revision(directory, expected_revision)
                self._check_file_identity(directory, descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            self._raise(StoreFailure.WRITE_UNCONFIRMED, StoreReason.IO_ERROR)

    def _check_file_identity(self, directory: int, descriptor: int) -> None:
        """Итоговый путь должен указывать на удерживаемый и синхронизированный файл.

        Дескриптор остаётся открытым до этой проверки, поэтому inode исходного
        файла не может быть повторно использован после внешней замены.
        """
        try:
            expected = os.fstat(descriptor)
            current = os.stat(self.file_name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            self._raise(StoreFailure.CONFLICT)
        except OSError:
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)
        if not os.path.samestat(expected, current):
            self._raise(StoreFailure.UNSAFE, StoreReason.REPLACED)
        for info in (expected, current):
            if not stat.S_ISREG(info.st_mode):
                self._raise(StoreFailure.UNSAFE, StoreReason.NOT_REGULAR_FILE)
            if info.st_uid != os.geteuid():
                self._raise(StoreFailure.UNSAFE, StoreReason.OWNER)
            if stat.S_IMODE(info.st_mode) != _FILE_MODE:
                self._raise(StoreFailure.UNSAFE, StoreReason.PERMISSIONS)

    def _remove_stale(self, directory: int) -> None:
        """Удалить временные файлы прерванной записи; под блокировкой живых записей нет.

        Удаляются только обычные файлы владельца с именем временного файла
        этого хранилища; остальное содержимое каталога не трогается.
        """
        try:
            names = os.listdir(directory)
        except OSError:
            return
        for name in names:
            if self._temporary.fullmatch(name) is None:
                continue
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid():
                    os.unlink(name, dir_fd=directory)
            except OSError:
                # Оставшийся временный файл не читается как содержимое хранилища и не мешает записи.
                pass

    def _check_identity(self, directory: int) -> None:
        """Каталог по настроенному пути должен оставаться тем, в котором идёт запись."""
        try:
            expected = os.fstat(directory)
        except OSError:
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)
        replaced = False
        try:
            with self._walk(self._directory) as current:
                current_info = os.fstat(current)
                replaced = not os.path.samestat(expected, current_info)
        except OSError:
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)
        except self.error_type as error:
            if error.reason not in (
                StoreReason.MISSING.value, StoreReason.SYMLINK.value, StoreReason.NOT_DIRECTORY.value,
            ):
                raise
            replaced = True
        if replaced:
            self._raise(StoreFailure.UNSAFE, StoreReason.REPLACED)
        for info in (expected, current_info):
            if info.st_uid != os.geteuid():
                self._raise(StoreFailure.UNSAFE, StoreReason.OWNER)
            if stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE:
                self._raise(StoreFailure.UNSAFE, StoreReason.PERMISSIONS)

    def _replace(self, directory: int, content: bytes, expected_revision: str | None) -> None:
        name = self._temporary_prefix + os.urandom(8).hex()
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
            self._check_identity(directory)
            # Писатели через хранилище исключены блокировкой. Правку в обход неё, сделанную
            # во время записи временного файла, ловит повторное сравнение; остаётся только
            # промежуток между этим чтением и переименованием.
            self._check_revision(directory, expected_revision)
            os.replace(name, self.file_name, src_dir_fd=directory, dst_dir_fd=directory)
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
            self._raise(StoreFailure.WRITE_FAILED, reason)
        try:
            try:
                os.fsync(directory)
            except OSError:
                self._raise(StoreFailure.WRITE_UNCONFIRMED, StoreReason.IO_ERROR)
            # Удерживаем дескриптор синхронизированного файла до проверки итогового пути.
            self._check_identity(directory)
            self._check_revision(directory, self.revision_of(content))
            self._check_file_identity(directory, descriptor)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                self._raise(StoreFailure.WRITE_UNCONFIRMED, StoreReason.IO_ERROR)

    def _unlink(self, directory: int, expected_revision: str) -> None:
        """Удалить сверенный файл и закрепить удаление fsync каталога.

        Дескриптор файла открывается до сверки ревизии и удерживается до
        удаления: подмена файла между ними отклоняется проверкой inode.
        Писатель в обход блокировки может успеть только в промежуток между
        последней проверкой и удалением. Файл, появившийся после удаления
        до проверки после fsync, не трогается: удаление не подтверждено.
        """
        self._check_identity(directory)
        descriptor = self._open_current(directory)
        reason = None
        try:
            self._check_revision(directory, expected_revision)
            self._check_file_identity(directory, descriptor)
            os.unlink(self.file_name, dir_fd=directory)
        except OSError as error:
            reason = _write_reason(error)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if reason is not None:
            self._raise(StoreFailure.WRITE_FAILED, reason)
        self._sync_absent(directory)

    def _sync_absent(self, directory: int) -> None:
        """Закрепить отсутствие файла fsync каталога и проверить его после закрепления."""
        try:
            os.fsync(directory)
        except OSError:
            self._raise(StoreFailure.WRITE_UNCONFIRMED, StoreReason.IO_ERROR)
        self._check_identity(directory)
        self._check_absent(directory)

    def _check_absent(self, directory: int) -> None:
        """По итоговому пути ничего нет; появившийся в обход блокировки объект — конфликт ревизии."""
        try:
            os.stat(self.file_name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)
        self._raise(StoreFailure.CONFLICT)
