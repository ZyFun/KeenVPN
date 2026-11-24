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
from keenvpn.application.ports import DraftApplyLock, LockedDraftSession, SourceFingerprintSource
from keenvpn.domain.draft_session import StoredDraftSession


@dataclass(frozen=True, slots=True)
class DraftApplyRecheck:
    """Сверки и завершение прочитанной ревизии под уже захваченной блокировкой."""

    sources: Callable[[], ErrorDetail | None]
    revision: Callable[[], ErrorDetail | None]
    check_close: Callable[[], ErrorDetail | None]
    close_applied_draft: Callable[[], None]


def run_draft_apply[T, R](
    lock: DraftApplyLock,
    fingerprints: SourceFingerprintSource,
    draft_id: object,
    expected_revision: object,
    apply: Callable[[StoredDraftSession], T],
    *,
    check_before_baseline: Callable[[], ErrorDetail | None] | None = None,
    on_lock_release_error: Callable[[T | ErrorDetail], R] | None = None,
) -> T | ErrorDetail | R:
    """Вызвать операцию применения только после сверки черновика под общей блокировкой.

    Идентификатор и токен берутся из команды интерфейса. Операция получает
    прочитанную сессию, включая полную ревизию для записи. Она должна завершить
    работу до возврата и не захватывать повторно блокировку этого хранилища.
    check_before_baseline выполняется после захвата блокировки, до сверки
    сессии и отпечатков действующих источников.
    Отказ блокировки или проверки возвращается без вызова операции. Результат
    и исключения самой операции передаются вызывающему после снятия блокировки.
    on_lock_release_error получает результат при ошибке выхода из блокировки.
    """
    return _with_current_draft(
        lock, fingerprints, draft_id, expected_revision, lambda _reader, stored: apply(stored),
        check_before_baseline=check_before_baseline, on_lock_release_error=on_lock_release_error,
    )


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
    check_before_baseline: Callable[[], ErrorDetail | None] | None = None,
    check_current: Callable[[StoredDraftSession], ErrorDetail | None] | None = None,
    check_prepared: PreparedSnapshotCheck | None = None,
    check_draft_close: bool = False,
    process_before: DraftProcessBackup | None = None,
    on_lock_release_error: Callable[[T | ErrorDetail], R] | None = None,
) -> T | ErrorDetail | R:
    """Передать исполнителю копию и возможность повторной сверки под той же блокировкой.

    Сверки используют захваченный LockedDraftSession. Перед началом записи
    можно сверить исходные отпечатки и полную ревизию, а у точки первой
    записи перечитать только ревизию. Обе сверки доступны до выхода из
    исполнителя. check_before_baseline выполняется только при входе в операцию.
    check_draft_close проверяет возможность закрытия до создания копии.
    Исполнитель может повторить проверку с уже назначенным UUID попытки.
    """
    def with_backup(reader: LockedDraftSession, stored: StoredDraftSession) -> T | ErrorDetail:
        def check_close(operation_id: str | None = None) -> ErrorDetail | None:
            try:
                reader.check_close_applied_draft(stored.revision, operation_id)
            except Exception as error:
                return store_error_detail(error, ConflictState.PRESENT)
            return None

        if check_draft_close:
            error = check_close()
            if error is not None:
                return error
        if check_current is not None:
            error = check_current(stored)
            if error is not None:
                return error

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

        def close_applied_draft() -> None:
            reader.close_applied_draft(stored.revision, backup.backup_id)

        return apply(stored, backup, DraftApplyRecheck(
            recheck_sources, recheck_revision, lambda: check_close(backup.backup_id), close_applied_draft,
        ))

    return _with_current_draft(
        lock, fingerprints, draft_id, expected_revision, with_backup,
        check_before_baseline=check_before_baseline, on_lock_release_error=on_lock_release_error,
    )


def _with_current_draft[T, R](
    lock: DraftApplyLock,
    fingerprints: SourceFingerprintSource,
    draft_id: object,
    expected_revision: object,
    apply: Callable[[LockedDraftSession, StoredDraftSession], T],
    *,
    check_before_baseline: Callable[[], ErrorDetail | None] | None = None,
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
            error = check_before_baseline() if check_before_baseline is not None else None
            stored = error if error is not None else check_draft_current(reader, fingerprints, draft_id, expected_revision)
            result = stored if isinstance(stored, ErrorDetail) else apply(reader, stored)
        if on_lock_release_error is not None:
            try:
                stack.close()
            except Exception:
                return on_lock_release_error(result)
        return result
