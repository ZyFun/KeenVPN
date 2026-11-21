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

from keenvpn.adapters.private_files import PrivateFileStore, StoreFailure
from keenvpn.application.ports import DraftSessionReader, DraftSessionStoreError, DraftStoreFailure
from keenvpn.domain.draft_session import (
    MAX_DRAFT_SIZE, DraftSession, DraftSessionError, DraftSessionErrorCode, StoredDraftSession, decode_draft_session,
    draft_revision, encode_draft_session,
)
from keenvpn.domain.manager_metadata import valid_metadata_revision


DRAFT_FILE_NAME = "draft-session.json"
"""Имя файла сессии черновика в собственном каталоге."""


class DraftSessionFiles(PrivateFileStore[StoredDraftSession]):
    """Реализация `DraftSessionStore` на файловой системе.

    `directory` — абсолютный нормализованный путь собственного каталога
    черновика без символических ссылок, например на выбранном разделе.
    Каталог, совпадающий с одним из `protected_directories` или вложенный
    в него, отклоняется до любого обращения к файловой системе.
    """

    file_name = DRAFT_FILE_NAME
    max_size = MAX_DRAFT_SIZE
    error_type = DraftSessionStoreError
    failures = {failure: DraftStoreFailure[failure.name] for failure in StoreFailure}
    revision_of = staticmethod(draft_revision)

    @contextmanager
    def lock_for_apply(self) -> Iterator[DraftSessionReader | None]:
        """Взять блокировку существующего каталога без создания файлов и каталогов."""
        with self._locked_directory() as directory:
            if directory is None:
                yield None
                return
            reader = _LockedDraftReader(self, directory)
            try:
                yield reader
            finally:
                reader.close()

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

    def _decode(self, content: bytes) -> StoredDraftSession:
        code = None
        try:
            return decode_draft_session(content)
        except DraftSessionError as error:
            code = error.code
        self._raise(StoreFailure.INVALID, code.value)


class _LockedDraftReader:
    """Читать сессию из того же каталога, дескриптор которого держит блокировку."""

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

    def close(self) -> None:
        """Отключить чтение перед закрытием дескриптора владельцем блокировки."""
        self._directory = None
