"""Эксклюзивный запуск операции применения для проверенной сессии черновика."""

from collections.abc import Callable
from contextlib import ExitStack

from keenvpn.application.contract import ConflictState, ErrorDetail, invalid_command
from keenvpn.application.draft_backup import (
    DraftBackupSource, DraftBackupStorage, VerifiedDraftBackup, prepare_draft_backup,
)
from keenvpn.application.draft_session import (
    DRAFT_CHANGED, DRAFT_GONE, check_draft_current, read_stored_draft, store_error_detail, valid_expected_draft,
)
from keenvpn.application.ports import DraftApplyLock, DraftSessionReader, SourceFingerprintSource
from keenvpn.domain.draft_session import StoredDraftSession


def run_draft_apply[T](
    lock: DraftApplyLock,
    fingerprints: SourceFingerprintSource,
    draft_id: object,
    expected_revision: object,
    apply: Callable[[StoredDraftSession], T],
) -> T | ErrorDetail:
    """Вызвать операцию применения только после сверки черновика под общей блокировкой.

    Идентификатор и токен берутся из команды интерфейса. Операция получает
    прочитанную сессию, включая полную ревизию для записи. Она должна завершить
    работу до возврата и не захватывать повторно блокировку этого хранилища.
    Отказ блокировки или проверки возвращается без вызова операции. Результат
    и исключения самой операции передаются вызывающему после снятия блокировки.
    """
    return _with_current_draft(lock, fingerprints, draft_id, expected_revision, lambda _reader, stored: apply(stored))


def run_draft_apply_with_backup[T](
    lock: DraftApplyLock,
    fingerprints: SourceFingerprintSource,
    draft_id: object,
    expected_revision: object,
    source: DraftBackupSource,
    storage: DraftBackupStorage,
    apply: Callable[[StoredDraftSession, VerifiedDraftBackup], T],
) -> T | ErrorDetail:
    """Вызвать исполнителя подтверждённой ревизии после проверки её копии.

    Проверки кандидата и подтверждение команды принадлежат вызывающему.
    Копирование и повторная сверка сессии и источников выполняются под
    общей блокировкой. При отказе исполнитель не вызывается.
    """
    def with_backup(reader: DraftSessionReader, stored: StoredDraftSession) -> T | ErrorDetail:
        def recheck_sources() -> ErrorDetail | None:
            current = check_draft_current(reader, fingerprints, draft_id, expected_revision)
            if isinstance(current, ErrorDetail):
                return current
            return None if current.revision == stored.revision else DRAFT_CHANGED

        def recheck_revision() -> ErrorDetail | None:
            current = read_stored_draft(reader)
            if isinstance(current, ErrorDetail):
                return current
            if current is None:
                return DRAFT_GONE
            return None if current.revision == stored.revision else DRAFT_CHANGED

        backup = prepare_draft_backup(stored, source, storage, recheck_sources, recheck_revision)
        if isinstance(backup, ErrorDetail):
            return backup
        return apply(stored, backup)

    return _with_current_draft(lock, fingerprints, draft_id, expected_revision, with_backup)


def _with_current_draft[T](
    lock: DraftApplyLock,
    fingerprints: SourceFingerprintSource,
    draft_id: object,
    expected_revision: object,
    apply: Callable[[DraftSessionReader, StoredDraftSession], T],
) -> T | ErrorDetail:
    if not valid_expected_draft(draft_id, expected_revision):
        return invalid_command()
    with ExitStack() as stack:
        try:
            reader = stack.enter_context(lock.lock_for_apply())
        except Exception as error:
            return store_error_detail(error, ConflictState.PRESENT)
        if reader is None:
            return DRAFT_GONE
        stored = check_draft_current(reader, fingerprints, draft_id, expected_revision)
        if isinstance(stored, ErrorDetail):
            return stored
        return apply(reader, stored)
