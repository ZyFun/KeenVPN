"""Устойчивый журнал применения в выделенном приватном каталоге."""

from keenvpn.adapters.draft_operation_files import ApplyPrivateFile
from keenvpn.domain.draft_session import valid_draft_id
from keenvpn.domain.manager_metadata import valid_metadata_revision


class _JournalStorageError(Exception):
    def __init__(self, *, reason: str | None = None) -> None:
        self.reason = reason
        super().__init__("Не удалось сохранить и подтвердить журнал применения.")


class _JournalFile(ApplyPrivateFile):
    error_type = _JournalStorageError


class DraftJournalFiles:
    """Хранить один JSON на попытку, заменяя только подтверждённую версию.

    Родитель каталога выбран вызывающим и идентифицирован устройством и inode.
    Запись подтверждается после fsync файла и каталога.
    """

    def __init__(self, directory: str, *, parent_identity: tuple[int, int]) -> None:
        if (type(parent_identity) is not tuple or len(parent_identity) != 2
                or any(type(value) is not int or value < 0 for value in parent_identity)):
            raise _JournalStorageError()
        self._directory = directory
        self._parent_identity = parent_identity

    def save(self, operation_id: str, content: bytes, expected_revision: str | None) -> str:
        if (not valid_draft_id(operation_id) or type(content) is not bytes
                or (expected_revision is not None and not valid_metadata_revision(expected_revision))):
            raise _JournalStorageError()
        journal = _JournalFile(self._directory, f"journal-{operation_id}.json", self._parent_identity)
        journal._decode(content)
        return journal._write_file(content, expected_revision)
