"""Проверенная запись копии применения в выделенный приватный каталог."""

from keenvpn.adapters.draft_operation_files import ApplyPrivateFile
from keenvpn.application.draft_backup import DraftBackupStorageError
from keenvpn.domain.draft_session import valid_draft_id
from keenvpn.domain.manager_metadata import valid_metadata_revision


class _BackupFile(ApplyPrivateFile):
    error_type = DraftBackupStorageError


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

    def directory_writable(self) -> bool:
        """Проверить доступ к каталогу копий без записи."""
        return _BackupFile(self._directory, "probe", self._parent_identity).directory_writable()

    def _file(self, backup_id: str) -> _BackupFile:
        if not valid_draft_id(backup_id):
            raise DraftBackupStorageError()
        return _BackupFile(self._directory, f"apply-{backup_id}.json", self._parent_identity)

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
