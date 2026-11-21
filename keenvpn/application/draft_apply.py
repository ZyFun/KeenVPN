"""Эксклюзивный запуск операции применения для проверенной сессии черновика."""

from collections.abc import Callable
from contextlib import ExitStack

from keenvpn.application.contract import ConflictState, ErrorDetail, invalid_command
from keenvpn.application.draft_session import DRAFT_GONE, check_draft_current, store_error_detail, valid_expected_draft
from keenvpn.application.ports import DraftApplyLock, SourceFingerprintSource
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
        return apply(stored)
