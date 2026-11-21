"""Проверенная запись копии применения в выделенный приватный каталог."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import os
import posixpath
from typing import NoReturn

from keenvpn.adapters.private_files import PrivateFileStore, StoreFailure
from keenvpn.application.draft_backup import DraftBackupStorageError
from keenvpn.application.ports import StoreReason
from keenvpn.domain.draft_session import MAX_DRAFT_SIZE, valid_draft_id
from keenvpn.domain.manager_metadata import metadata_revision, valid_metadata_revision


@dataclass(frozen=True, slots=True, repr=False)
class _StoredBackup:
    revision: str


class _BackupFile(PrivateFileStore[_StoredBackup]):
    max_size = 2 * MAX_DRAFT_SIZE
    error_type = DraftBackupStorageError
    revision_of = staticmethod(metadata_revision)

    def __init__(self, directory: str, backup_id: str, parent_identity: tuple[int, int]) -> None:
        self.file_name = f"apply-{backup_id}.json"
        super().__init__(directory)
        self._parent_identity = parent_identity

    def _raise(self, failure: StoreFailure, reason: StoreReason | str | None = None) -> NoReturn:
        # Наследуемые проверки каталога опираются на reason. Вид отказа
        # хранилища черновиков здесь не является кодом прикладного сценария.
        value = reason.value if isinstance(reason, StoreReason) else reason
        try:
            raise DraftBackupStorageError(reason=value) from None
        except DraftBackupStorageError as error:
            error.__context__ = None
            raise

    @contextmanager
    def _walk(self, path: str) -> Iterator[int]:
        with super()._walk(path) as directory:
            # Во время записи базовое хранилище повторно открывает итоговый
            # каталог. Проверяем и выбранного родителя, и устройство файла.
            parent_path = posixpath.dirname(self._directory)
            try:
                info = os.fstat(directory)
                if path == parent_path:
                    identity = info.st_dev, info.st_ino
                else:
                    with super()._walk(parent_path) as parent:
                        parent_info = os.fstat(parent)
                        identity = parent_info.st_dev, parent_info.st_ino
            except OSError:
                self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)
            if identity != self._parent_identity or info.st_dev != self._parent_identity[0]:
                self._raise(StoreFailure.UNSAFE, StoreReason.REPLACED)
            yield directory

    def _open_directory(self, parent: int, name: str, *, create: bool, sync_parent: bool = False) -> int | None:
        directory = super()._open_directory(parent, name, create=create, sync_parent=sync_parent)
        if directory is None:
            return None
        try:
            if os.fstat(directory).st_dev != self._parent_identity[0]:
                self._raise(StoreFailure.UNSAFE, StoreReason.REPLACED)
        except BaseException:
            os.close(directory)
            raise
        return directory

    def _decode(self, content: bytes) -> _StoredBackup:
        if not content or len(content) > self.max_size:
            self._raise(StoreFailure.INVALID)
        return _StoredBackup(self.revision_of(content))


class DraftBackupFiles:
    """Хранилище в явно выбранном каталоге менеджера без запасного пути.

    Вызывающий передаёт (st_dev, st_ino) родителя, установленную при
    проверке выбранного хранилища. Каждая попытка получает новое имя.
    """

    def __init__(self, directory: str, *, parent_identity: tuple[int, int]) -> None:
        if (type(parent_identity) is not tuple or len(parent_identity) != 2
                or any(type(value) is not int or value < 0 for value in parent_identity)):
            raise DraftBackupStorageError()
        self._directory = directory
        self._parent_identity = parent_identity

    def _file(self, backup_id: str) -> _BackupFile:
        if not valid_draft_id(backup_id):
            raise DraftBackupStorageError()
        return _BackupFile(self._directory, backup_id, self._parent_identity)

    def save(self, backup_id: str, content: bytes) -> str:
        """Синхронизировать файл и каталог и сверить SHA-256 повторного чтения."""
        if type(content) is not bytes:
            raise DraftBackupStorageError()
        backup = self._file(backup_id)
        backup._decode(content)
        # Хранилище подтверждает post-fsync чтение и идентичность файла.
        return backup._write_file(content, expected_revision=None)

    def confirm(self, backup_id: str, expected_sha256: str) -> None:
        """Повторно подтвердить опубликованную копию перед продолжением apply."""
        if not valid_metadata_revision(expected_sha256):
            raise DraftBackupStorageError()
        backup = self._file(backup_id)
        with backup._locked_directory(sync_parent=True) as directory:
            if directory is None:
                raise DraftBackupStorageError()
            backup._confirm(directory, expected_sha256)
