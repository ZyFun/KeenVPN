"""Эксклюзивный запуск операции применения для проверенной сессии черновика."""

from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass

from keenvpn.application.contract import ConflictState, ErrorDetail, invalid_command
from keenvpn.application.draft_backup import (
    DraftBackupSource, DraftBackupStorage, DraftProcessBackup, PreparedSnapshotCheck, VerifiedDraftBackup,
    prepare_draft_backup,
)
from keenvpn.application.draft_session import (
    DRAFT_CHANGED, DRAFT_GONE, check_draft_current, read_stored_draft, store_error_detail, valid_expected_draft,
)
from keenvpn.application.ports import DraftApplyLock, DraftSessionReader, SourceFingerprintSource
from keenvpn.domain.draft_session import StoredDraftSession


@dataclass(frozen=True, slots=True)
class DraftApplyRecheck:
    """Сверки под уже захваченной блокировкой до первой активной записи."""

    sources: Callable[[], ErrorDetail | None]
    revision: Callable[[], ErrorDetail | None]


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


def run_draft_apply_with_backup[T, R](
    lock: DraftApplyLock,
    fingerprints: SourceFingerprintSource,
    draft_id: object,
    expected_revision: object,
    source: DraftBackupSource,
    storage: DraftBackupStorage,
    apply: Callable[[StoredDraftSession, VerifiedDraftBackup], T],
    *,
    check_prepared: PreparedSnapshotCheck | None = None,
    on_lock_release_error: Callable[[T | ErrorDetail], R] | None = None,
) -> T | ErrorDetail | R:
    """Вызвать исполнителя подтверждённой ревизии после проверки её копии.

    Проверки кандидата и подтверждение команды принадлежат вызывающему.
    Копирование и повторная сверка сессии и источников выполняются под
    общей блокировкой. check_prepared может проверить файловые ограничения
    по сверенным снимкам перед копированием. При отказе исполнитель не вызывается.
    on_lock_release_error получает готовый результат, если не удалось выйти
    из контекста блокировки. Исключения самого исполнителя передаются вызывающему.
    """
    return run_draft_apply_with_backup_recheck(
        lock, fingerprints, draft_id, expected_revision, source, storage,
        lambda stored, backup, _recheck: apply(stored, backup),
        check_prepared=check_prepared, on_lock_release_error=on_lock_release_error,
    )


def run_draft_apply_with_backup_recheck[T, R](
    lock: DraftApplyLock,
    fingerprints: SourceFingerprintSource,
    draft_id: object,
    expected_revision: object,
    source: DraftBackupSource,
    storage: DraftBackupStorage,
    apply: Callable[[StoredDraftSession, VerifiedDraftBackup, DraftApplyRecheck], T],
    *,
    check_prepared: PreparedSnapshotCheck | None = None,
    process_before: DraftProcessBackup | None = None,
    on_lock_release_error: Callable[[T | ErrorDetail], R] | None = None,
) -> T | ErrorDetail | R:
    """Передать исполнителю копию и возможность повторной сверки под той же блокировкой.

    Сверки используют захваченный DraftSessionReader. Перед началом записи
    можно сверить исходные отпечатки и полную ревизию, а у точки первой
    записи перечитать только ревизию. Обе сверки доступны до выхода из
    исполнителя.
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

        backup = prepare_draft_backup(
            stored, source, storage, recheck_sources, recheck_revision, check_prepared=check_prepared,
            process_before=process_before,
        )
        if isinstance(backup, ErrorDetail):
            return backup
        return apply(stored, backup, DraftApplyRecheck(recheck_sources, recheck_revision))

    return _with_current_draft(
        lock, fingerprints, draft_id, expected_revision, with_backup, on_lock_release_error=on_lock_release_error,
    )


def _with_current_draft[T, R](
    lock: DraftApplyLock,
    fingerprints: SourceFingerprintSource,
    draft_id: object,
    expected_revision: object,
    apply: Callable[[DraftSessionReader, StoredDraftSession], T],
    *,
    on_lock_release_error: Callable[[T | ErrorDetail], R] | None = None,
) -> T | ErrorDetail | R:
    if not valid_expected_draft(draft_id, expected_revision):
        return invalid_command()
    with ExitStack() as stack:
        try:
            reader = stack.enter_context(lock.lock_for_apply())
        except Exception as error:
            return store_error_detail(error, ConflictState.PRESENT)
        if reader is None:
            result = DRAFT_GONE
        else:
            stored = check_draft_current(reader, fingerprints, draft_id, expected_revision)
            result = stored if isinstance(stored, ErrorDetail) else apply(reader, stored)
        if on_lock_release_error is not None:
            try:
                stack.close()
            except Exception:
                return on_lock_release_error(result)
        return result
