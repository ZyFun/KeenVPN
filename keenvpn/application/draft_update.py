"""Изменение только приватного кандидата по идентификатору и токену сессии."""

from dataclasses import dataclass, replace
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ConflictState, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.draft_session import (
    DraftView, INVALID_STORE_RESULT, read_expected_draft, store_error_detail, valid_expected_draft,
)
from keenvpn.application.ports import DraftSessionStore
from keenvpn.application.source_baseline import compare_baseline
from keenvpn.domain.draft_candidate_state import build_draft_candidate
from keenvpn.domain.draft_session import draft_revision, encode_draft_session
from keenvpn.domain.draft_snapshot import DraftDiffSnapshot, prepare_snapshot
from keenvpn.domain.routing import GeoDatabase


_INVALID_CANDIDATE = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_candidate",
    "Для сохранения нужны полные допустимые снимки и ожидаемые ревизии геобаз в пределах размера сессии.",
)
_ORIGINAL_MISMATCH = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "draft_original_mismatch",
    "Исходный снимок не соответствует сохранённым отпечаткам черновика.",
)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class UpdateDraft:
    """Сохранить полный кандидат; original обязателен при первом редактировании.

    Последующие вызовы могут опустить original и geo_revisions: сохраняются
    записанные исходные данные и ожидания геобаз. Пустой кортеж явно очищает
    известные ожидания геобаз. Ни один источник на роутере не читается.
    """

    name: ClassVar[str] = "update_draft"
    draft_id: str
    expected_revision: str
    candidate: DraftDiffSnapshot
    original: DraftDiffSnapshot | None = None
    geo_revisions: tuple[GeoDatabase, ...] | None = None
    contract_version: int = CONTRACT_VERSION


class UpdateDraftHandler:
    """Повторно проверить входы, сохранить исходные отпечатки и заменить сессию.

    Ревизия для записи берётся из проверенного чтения хранилища. Проверка
    исходного снимка не удостоверяет актуальность живой конфигурации и не
    заменяет отдельную проверку перед применением. Результат — DraftView
    с токеном записанных байтов, без кандидата и полных ревизий.
    """

    def __init__(self, store: DraftSessionStore, *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._store = store
        self._operation_ids = operation_ids

    def execute(self, command: UpdateDraft) -> Result[DraftView]:
        operation_id, name = self._operation_ids(), UpdateDraft.name
        if type(command) is not UpdateDraft:
            return failed(operation_id, name, invalid_command())
        try:
            version, draft_id, token = command.contract_version, command.draft_id, command.expected_revision
            original, candidate, revisions = command.original, command.candidate, command.geo_revisions
        except AttributeError:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(version)
        if error is not None:
            return failed(operation_id, name, error)
        if not valid_expected_draft(draft_id, token):
            return failed(operation_id, name, invalid_command())
        stored = read_expected_draft(self._store, draft_id, token)
        if isinstance(stored, ErrorDetail):
            return failed(operation_id, name, stored)
        previous = stored.session.candidate
        if original is None and previous is not None:
            original = previous.original
        if revisions is None:
            revisions = () if previous is None else previous.geo_revisions
        try:
            state = build_draft_candidate(original, candidate, revisions, previous)
            # Проверяем именно отделённые данные, которые попадут в файл:
            # исходная команда может содержать изменяемые вложенные словари.
            prepared = prepare_snapshot(state.original, require_sorted_parts=True)
            if compare_baseline(prepared, stored.session.baseline) is not None:
                return failed(operation_id, name, _ORIGINAL_MISMATCH)
            session = replace(stored.session, candidate=state)
            content = encode_draft_session(session)
        except Exception:
            return failed(operation_id, name, _INVALID_CANDIDATE)
        try:
            revision = self._store.replace_draft(session, stored.revision)
        except Exception as error:
            return failed(operation_id, name, store_error_detail(error, ConflictState.PRESENT))
        if type(revision) is not str or revision != draft_revision(content):
            return failed(operation_id, name, INVALID_STORE_RESULT)
        return succeeded(operation_id, name, DraftView.from_session(session, revision))
