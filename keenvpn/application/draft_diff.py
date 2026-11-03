"""Маскированный diff полных снимков черновика, привязанный к исходным отпечаткам сессии."""

from dataclasses import dataclass
from itertools import islice
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result, check_contract_version,
    failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.draft_diff_changes import DiffEntry, snapshot_changes
from keenvpn.application.draft_diff_snapshot import DraftDiffSnapshot, prepare_snapshot
from keenvpn.application.draft_session import check_draft_current, read_expected_draft, valid_expected_draft
from keenvpn.application.ports import DraftSessionStore, SourceFingerprintSource
from keenvpn.application.source_baseline import BASELINE_CHANGED, compare_baseline


MAX_DIFF_ENTRIES = 256
_INVALID_SNAPSHOT = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "invalid_diff_snapshot",
    "Для сравнения требуются полные согласованные снимки управляемых источников.",
)
_ORIGINAL_MISMATCH = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "diff_original_mismatch",
    "Переданный исходный снимок не соответствует отпечаткам сессии. Проверьте источник снимка.",
)
_TOO_MANY = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "diff_entry_limit", "Изменения превышают предел одного отчёта.",
)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CompareDraft:
    """Сравнить два приватных снимка той ревизии сессии, которую видел вызывающий."""

    name: ClassVar[str] = "compare_draft"
    draft_id: str
    expected_revision: str
    original: DraftDiffSnapshot
    candidate: DraftDiffSnapshot
    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class DraftDiffView:
    """Полный отчёт просмотра. Пустой кортеж означает проверенное совпадение."""

    entries: tuple[DiffEntry, ...]

    def to_dict(self) -> dict[str, object]:
        return {"entries": [entry.to_dict() for entry in self.entries]}


class CompareDraftHandler:
    """Сверить исходное содержимое с сессией и проверить актуальность перед выдачей отчёта."""

    def __init__(self, store: DraftSessionStore, fingerprints: SourceFingerprintSource,
                 *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._store = store
        self._fingerprints = fingerprints
        self._operation_ids = operation_ids

    def execute(self, command: CompareDraft) -> Result[DraftDiffView]:
        operation_id = self._operation_ids()
        name = CompareDraft.name
        if type(command) is not CompareDraft:
            return failed(operation_id, name, invalid_command())
        try:
            version, draft_id, revision = command.contract_version, command.draft_id, command.expected_revision
            old_snapshot, new_snapshot = command.original, command.candidate
        except AttributeError:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(version)
        if error is not None:
            return failed(operation_id, name, error)
        if not valid_expected_draft(draft_id, revision):
            return failed(operation_id, name, invalid_command())
        stored = read_expected_draft(self._store, draft_id, revision)
        if isinstance(stored, ErrorDetail):
            return failed(operation_id, name, stored)
        original = prepare_snapshot(old_snapshot)
        candidate = prepare_snapshot(new_snapshot)
        if original is None or candidate is None:
            return failed(operation_id, name, _INVALID_SNAPSHOT)
        error = compare_baseline(original, stored.session.baseline)
        if error is not None:
            if error.code == BASELINE_CHANGED.code:
                current = check_draft_current(self._store, self._fingerprints, draft_id, revision)
                error = current if isinstance(current, ErrorDetail) else _ORIGINAL_MISMATCH
            return failed(operation_id, name, error)
        try:
            entries = tuple(islice(snapshot_changes(original, candidate), MAX_DIFF_ENTRIES + 1))
        except (ValueError, TypeError, RecursionError):
            return failed(operation_id, name, _INVALID_SNAPSHOT)
        current = check_draft_current(self._store, self._fingerprints, draft_id, revision)
        if isinstance(current, ErrorDetail):
            return failed(operation_id, name, current)
        if len(entries) > MAX_DIFF_ENTRIES:
            return failed(operation_id, name, _TOO_MANY)
        return succeeded(operation_id, name, DraftDiffView(entries))
