"""Файловое хранилище одной сессии черновика в явно заданном собственном каталоге.

Каталог задаёт вызывающий код: значение по умолчанию не выбирается, а при
недоступности не используются другой каталог, `/opt` или RAM. Механика
приватного файла — общая с хранилищем метаданных (`private_files`): права
700/600, обход без ссылок, атомарная публикация через временный файл под
эксклюзивной блокировкой каталога, запрет каталогов конфигураций Xray
и XKeen и каталога init. Создание не перезаписывает существующий черновик,
замена и удаление сверяют ревизию и меняют только файл сессии. Хранилище ничего
не применяет: конфигурация Xray и XKeen, Keenetic и службы не затрагиваются.
"""

from collections.abc import Iterator
from contextlib import contextmanager
import os
import stat

from keenvpn.adapters.file_writes import exclusive_rename_available, read_linux_inode_flags, rename_new_file
from keenvpn.adapters.private_files import PrivateFileStore, StoreFailure
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure, LockedDraftSession, StoreReason
from keenvpn.domain.draft_session import (
    MAX_DRAFT_SIZE, DraftSession, DraftSessionError, DraftSessionErrorCode, StoredDraftSession, decode_draft_session,
    draft_revision, encode_draft_session, valid_draft_id,
)
from keenvpn.domain.manager_metadata import valid_metadata_revision


DRAFT_FILE_NAME = "draft-session.json"
"""Имя файла сессии черновика в собственном каталоге."""
_CLOSED_DRAFT_PREFIX = "draft-close-"
_SYSTEM = os.uname()
_LINUX_ARCH = _SYSTEM.machine if _SYSTEM.sysname == "Linux" else None
_LINUX_RENAME_BLOCKING_FLAGS = 0x10 | 0x20  # FS_IMMUTABLE_FL и FS_APPEND_FL
_BSD_RENAME_BLOCKING_FLAGS = (
    stat.UF_IMMUTABLE | stat.SF_IMMUTABLE | stat.UF_APPEND | stat.SF_APPEND | stat.UF_NOUNLINK | stat.SF_NOUNLINK
)


def _rename_blocked_by_flags(descriptor: int) -> bool:
    flags = getattr(os.fstat(descriptor), "st_flags", 0)
    return bool(flags & _BSD_RENAME_BLOCKING_FLAGS
                or read_linux_inode_flags(descriptor, _LINUX_ARCH) & _LINUX_RENAME_BLOCKING_FLAGS)


class _DraftFile(PrivateFileStore[StoredDraftSession]):
    max_size = MAX_DRAFT_SIZE
    error_type = DraftSessionStoreError
    failures = {failure: DraftStoreFailure[failure.name] for failure in StoreFailure}
    revision_of = staticmethod(draft_revision)

    def _decode(self, content: bytes) -> StoredDraftSession:
        code = None
        try:
            return decode_draft_session(content)
        except DraftSessionError as error:
            code = error.code
        self._raise(StoreFailure.INVALID, code.value)


class _ClosedDraftFile(_DraftFile):
    """Приватный файл сессии, снятой с активного места при применении."""

    def __init__(self, directory: str, protected: tuple[str, ...], operation_id: str) -> None:
        self.file_name = f"{_CLOSED_DRAFT_PREFIX}{operation_id}.json"
        super().__init__(directory, protected_directories=protected)


class DraftSessionFiles(_DraftFile):
    """Реализация `DraftSessionStore` на файловой системе.

    `directory` — абсолютный нормализованный путь собственного каталога
    черновика без символических ссылок, например на выбранном разделе.
    Каталог, совпадающий с одним из `protected_directories` или вложенный
    в него, отклоняется до любого обращения к файловой системе.
    """

    file_name = DRAFT_FILE_NAME

    @contextmanager
    def lock_for_apply(self) -> Iterator[LockedDraftSession | None]:
        """Взять блокировку существующего каталога без создания файлов и каталогов."""
        with self._locked_directory() as directory:
            if directory is None:
                yield None
                return
            session = _LockedDraftSession(self, directory)
            try:
                yield session
            finally:
                session.close()

    def _close_applied_draft(self, directory: int, expected_revision: str, operation_id: str) -> None:
        """Закрепить перенос и перечитать ревизию по новому имени, сохраняя файл."""
        if not valid_metadata_revision(expected_revision):
            raise DraftSessionError(DraftSessionErrorCode.REVISION)
        if not valid_draft_id(operation_id):
            self._raise(StoreFailure.CONFLICT)
        closed = _ClosedDraftFile(self._directory, self._protected, operation_id)
        self._check_identity(directory)
        descriptor = self._open_current(directory)
        try:
            self._check_revision(directory, expected_revision)
            self._check_file_identity(directory, descriptor)
            try:
                rename_new_file(self.file_name, closed.file_name, src_dir_fd=directory, dst_dir_fd=directory)
            except FileExistsError:
                self._raise(StoreFailure.CONFLICT)
            try:
                moved = closed._open_current(directory)
                try:
                    closed._check_file_identity(directory, moved)
                    os.fsync(moved)
                finally:
                    os.close(moved)
            finally:
                self._sync_absent(directory)
            closed._check_file_identity(directory, descriptor)
            closed._check_revision(directory, expected_revision)
            closed._check_file_identity(directory, descriptor)
            self._check_identity(directory)
            self._check_absent(directory)
        except OSError:
            self._raise(StoreFailure.WRITE_UNCONFIRMED, StoreReason.IO_ERROR)
        finally:
            os.close(descriptor)

    def _check_close_applied_draft(self, directory: int, expected_revision: str, operation_id: str | None) -> None:
        """Отклонить известные препятствия переносу без побочных записей."""
        self._check_identity(directory)
        try:
            if (not os.access(".", os.W_OK | os.X_OK, dir_fd=directory, effective_ids=True)
                    or _rename_blocked_by_flags(directory)):
                self._raise(StoreFailure.WRITE_FAILED, StoreReason.PERMISSION_DENIED)
            descriptor = self._open_current(directory)
            try:
                self._check_revision(directory, expected_revision)
                self._check_file_identity(directory, descriptor)
                if _rename_blocked_by_flags(descriptor):
                    self._raise(StoreFailure.WRITE_FAILED, StoreReason.PERMISSION_DENIED)
            finally:
                os.close(descriptor)
            if operation_id is None:
                if not exclusive_rename_available(rename_new_file):
                    self._raise(StoreFailure.WRITE_FAILED, StoreReason.IO_ERROR)
            else:
                if not valid_draft_id(operation_id):
                    self._raise(StoreFailure.CONFLICT)
                closed = _ClosedDraftFile(self._directory, self._protected, operation_id)
                closed._check_absent(directory)
            self._check_identity(directory)
        except (NotImplementedError, OSError):
            self._raise(StoreFailure.UNAVAILABLE, StoreReason.IO_ERROR)

    def read_draft(self) -> StoredDraftSession | None:
        """Прочитать файл без блокировки: создание публикует его одним переименованием.

        `None` — собственного каталога или файла ещё нет; отсутствие родителя
        является отказом `draft_store_unavailable`.
        """
        return self._read_file()

    def create_draft(self, session: DraftSession) -> str:
        """Создать черновик, если его ещё нет, и вернуть ревизию.

        Модель проверяется до обращения к файловой системе: некорректная
        вызывает `DraftSessionError`. Существующий черновик, в том числе
        с теми же байтами, — `draft_revision_conflict` без перезаписи;
        повреждённый файл — `invalid_stored_draft`.
        """
        return self._write_file(encode_draft_session(session), None)

    def remove_draft(self, expected_revision: str) -> None:
        """Удалить файл сессии с этой ревизией; собственный каталог остаётся.

        Ревизия неверного формата вызывает `DraftSessionError` до обращения
        к файловой системе. Отсутствующий черновик и черновик другой ревизии —
        `draft_revision_conflict`; повреждённый файл не удаляется — `invalid_stored_draft`.
        """
        if not valid_metadata_revision(expected_revision):
            raise DraftSessionError(DraftSessionErrorCode.REVISION)
        self._remove_file(expected_revision)

    def replace_draft(self, session: DraftSession, expected_revision: str) -> str:
        """Заменить сессию по SHA-256 файла, сохранив общую блокировку и проверки.

        Неверная ревизия или модель отклоняются до файловых обращений.
        Повреждённый файл не перезаписывается. Совпадающие байты повторно
        закрепляются fsync без переименования; возвращается их ревизия.
        """
        if not valid_metadata_revision(expected_revision):
            raise DraftSessionError(DraftSessionErrorCode.REVISION)
        return self._write_file(encode_draft_session(session), expected_revision)

    def confirm_draft_absent(self) -> None:
        """Закрепить на диске отсутствие черновика под той же блокировкой, ничего не удаляя.

        Нужен повтору отмены после `draft_write_unconfirmed`: удалённый файл
        исчез, но fsync каталога не удался. Нет собственного каталога —
        подтверждать нечего. Появившийся черновик — `draft_revision_conflict`
        без удаления; отказ fsync каталога — снова `draft_write_unconfirmed`.
        """
        self._confirm_absent()


class _LockedDraftSession:
    """Работать с сессией по дескриптору заблокированного каталога."""

    def __init__(self, store: DraftSessionFiles, directory: int) -> None:
        self._store = store
        self._directory: int | None = directory

    def read_draft(self) -> StoredDraftSession | None:
        directory = self._directory
        if directory is None:
            raise DraftSessionStoreError(DraftStoreFailure.UNAVAILABLE)
        self._store._check_identity(directory)
        stored = self._store._read(directory)
        self._store._check_identity(directory)
        return stored

    def close_applied_draft(self, expected_revision: str, operation_id: str) -> None:
        directory = self._directory
        if directory is None:
            raise DraftSessionStoreError(DraftStoreFailure.UNAVAILABLE)
        self._store._close_applied_draft(directory, expected_revision, operation_id)

    def check_close_applied_draft(self, expected_revision: str, operation_id: str | None = None) -> None:
        directory = self._directory
        if directory is None:
            raise DraftSessionStoreError(DraftStoreFailure.UNAVAILABLE)
        self._store._check_close_applied_draft(directory, expected_revision, operation_id)

    def close(self) -> None:
        """Отключить операции перед закрытием дескриптора владельцем блокировки."""
        self._directory = None
