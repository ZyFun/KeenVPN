"""Общее приватное хранилище файлов одной операции применения."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import os
import posixpath
from typing import NoReturn

from keenvpn.adapters.private_files import PrivateFileStore, StoreFailure
from keenvpn.application.ports import StoreReason
from keenvpn.domain.draft_session import MAX_DRAFT_SIZE
from keenvpn.domain.manager_metadata import metadata_revision


@dataclass(frozen=True, slots=True, repr=False)
class _StoredApplyFile:
    revision: str


class ApplyPrivateFile(PrivateFileStore[_StoredApplyFile]):
    """Приватный файл с проверкой идентичности выбранного родителя."""

    max_size = 2 * MAX_DRAFT_SIZE
    revision_of = staticmethod(metadata_revision)

    def __init__(self, directory: str, file_name: str, parent_identity: tuple[int, int]) -> None:
        self.file_name = file_name
        super().__init__(directory)
        self._parent_identity = parent_identity

    def _raise(self, failure: StoreFailure, reason: StoreReason | str | None = None) -> NoReturn:
        # Наследуемые проверки каталога опираются на reason. Вид отказа
        # хранилища черновиков здесь не является кодом прикладного сценария.
        value = reason.value if isinstance(reason, StoreReason) else reason
        try:
            raise self.error_type(reason=value) from None
        except self.error_type as error:
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

    def _decode(self, content: bytes) -> _StoredApplyFile:
        if not content or len(content) > self.max_size:
            self._raise(StoreFailure.INVALID)
        return _StoredApplyFile(self.revision_of(content))
