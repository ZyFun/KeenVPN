"""Подготовка и подтверждение применения одной сохранённой ревизии."""

from collections.abc import Callable
from dataclasses import dataclass, field
import hashlib
import re

from keenvpn.application.contract import CheckStatus, ErrorCategory, ErrorDetail, invalid_command
from keenvpn.application.draft_apply import run_draft_apply
from keenvpn.application.draft_backup import DraftBackupStorage
from keenvpn.application.draft_diff import DraftDiffView
from keenvpn.application.draft_diff_changes import DiffEntry, DiffOperation
from keenvpn.application.draft_file_apply import DraftFileApplyRejection, FileStepFailure
from keenvpn.application.draft_journal import DraftApplyJournalStorage
from keenvpn.application.draft_journal_apply import (
    DraftJournalApplyResult, DraftJournalFileSource, _run_draft_journal_apply,
)
from keenvpn.application.draft_session import DRAFT_CHANGED, draft_revision_token
from keenvpn.application.ports import DraftApplyLock, DraftSessionReader, GeoDatabaseSource
from keenvpn.application.saved_draft import (
    CandidateAssetSource, CheckSavedDraft, CheckSavedDraftHandler, CompareSavedDraft,
    CompareSavedDraftHandler, GeoCategorySource, SavedDraftCheckView,
)
from keenvpn.application.xray_candidate import (
    MAX_ASSET_BYTES, MAX_TOTAL_ASSET_BYTES, InstalledXrayPort, candidate_geo_references,
)
from keenvpn.domain.config_document import parse_strict_json_object
from keenvpn.domain.draft_candidate_state import DraftCandidateState
from keenvpn.domain.draft_session import StoredDraftSession
from keenvpn.domain.draft_snapshot import prepare_snapshot
from keenvpn.domain.routing import GeoDatabase
from keenvpn.domain.source_baseline import BaselineSource

_NETWORK_BLOCKED = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_network_apply_blocked",
    "Изменение может повлиять на сеть. Для применения нужен проверенный временный откат.",
)
_UNKNOWN_SOURCE_CHANGES = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_unknown_source_changes",
    "Изменились источники неизвестного формата. Черновик доступен только для просмотра.",
)
_CHECK_REQUIRED = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_apply_check_required",
    "Для применения нужны успешная статическая проверка и проверка установленным Xray.",
)
_APPLY_UNAVAILABLE = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_apply_unavailable",
    "Не удалось подтвердить доступность исполнителя записи.",
)
_ASSETS_CHANGED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_apply_assets_changed",
    "Не удалось подтвердить ревизии геобаз проверенного кандидата.",
)
_JOURNAL_PENDING = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_apply_recovery_required",
    "Не удалось подтвердить завершение предыдущих операций. Перед записью проверьте журнал применения.",
)
_NO_CHANGES = ErrorDetail(ErrorCategory.UNSUPPORTED, "draft_backup_no_changes", "В черновике нет изменений.")
_NO_CANDIDATE = ErrorDetail(ErrorCategory.UNSUPPORTED, "draft_candidate_missing", "В черновике нет полного кандидата.")

# Сравниваем лексемы, сохраняя текст ключей, значений и порядок, включая
# экранирование и запись чисел. Игнорируются только пробелы строгого JSON.
_JSON_TOKENS = re.compile(rb'"(?:[^"\\]|\\.)*"|[{}\[\],:]|[^"{}\[\],: \t\r\n]+', re.DOTALL)


def _only_json_whitespace(before: bytes, after: bytes) -> bool:
    try:
        for content in (before, after):
            parse_strict_json_object(content.decode("utf-8"), comments=False)
    except ValueError:
        return False
    return _JSON_TOKENS.findall(before) == _JSON_TOKENS.findall(after)


def _check_scope(state: DraftCandidateState) -> ErrorDetail | None:
    """До временного отката допустить только правку пробелов существующих частей Xray."""
    if state.has_unknown_source_changes():
        return _UNKNOWN_SOURCE_CHANGES
    before = prepare_snapshot(state.original, require_sorted_parts=True)
    after = prepare_snapshot(state.snapshot, require_sorted_parts=True)
    if before is None or after is None:
        return _NETWORK_BLOCKED
    if before.sources == after.sources:
        return _NO_CHANGES
    xray = BaselineSource.XRAY_CONFIGS
    if any(before.sources[source] != after.sources[source] for source in BaselineSource if source is not xray):
        return _NETWORK_BLOCKED
    old, new = before.sources[xray], after.sources[xray]
    if old is None or new is None or old.keys() != new.keys():
        return _NETWORK_BLOCKED
    if any(old[name] != new[name] and not _only_json_whitespace(old[name], new[name]) for name in old):
        return _NETWORK_BLOCKED
    return None


def _checks_passed(report: SavedDraftCheckView) -> bool:
    return (
        report.static_error is None and report.binary_error is None
        and report.static is not None and report.static.outcome == "passed"
        and report.binary is not None and report.binary.status is CheckStatus.PASSED
    )


@dataclass(frozen=True, slots=True)
class DraftApplyPreview:
    """Маскированный diff и результаты проверки. Полная ревизия остаётся в приложении."""

    checks: SavedDraftCheckView
    diff: DraftDiffView
    rejection: ErrorDetail | None
    _draft_id: str = field(repr=False)
    _revision: str = field(repr=False)


class ApplySavedDraftHandler:
    """Единственная точка записи сохранённого кандидата с подготовкой и подтверждением."""

    name = "apply_saved_draft"

    def __init__(
        self, store: DraftSessionReader, lock: DraftApplyLock, files: DraftJournalFileSource,
        backup: DraftBackupStorage, journal: DraftApplyJournalStorage, *,
        tester: InstalledXrayPort, readiness: Callable[[], ErrorDetail | None],
        geodata: GeoDatabaseSource | None = None, assets: CandidateAssetSource | None = None,
        catalogs: GeoCategorySource | None = None,
    ) -> None:
        self._lock, self._files, self._backup, self._journal = lock, files, backup, journal
        self._check = CheckSavedDraftHandler(store, files, geodata, assets, catalogs, tester)
        self._compare = CompareSavedDraftHandler(store, files)
        self._assets = assets
        self._readiness = readiness

    def _ready(self) -> ErrorDetail | None:
        try:
            result = self._readiness()
        except Exception:
            return _APPLY_UNAVAILABLE
        return result if result is None or type(result) is ErrorDetail else _APPLY_UNAVAILABLE

    def _checks(self, stored: StoredDraftSession) -> SavedDraftCheckView | ErrorDetail:
        result = self._check.execute(CheckSavedDraft(
            draft_id=stored.session.draft_id, expected_revision=draft_revision_token(stored.revision),
        ))
        return result.data if result.succeeded else result.error

    def check_journal(self) -> ErrorDetail | None:
        """Проверить завершение всех операций записи в приватном журнале."""
        try:
            return None if self._journal.is_clear() is True else _JOURNAL_PENDING
        except Exception:
            return _JOURNAL_PENDING

    def _check_before_baseline(self) -> ErrorDetail | None:
        """Проверить размещение и предыдущие операции под общей блокировкой."""
        return self._ready() or self.check_journal()

    def last_applied_diff(self) -> DraftDiffView | ErrorDetail | None:
        """Прочитать маскированный отчёт завершённой операции из журнала."""
        try:
            parts = self._journal.last_applied_parts()
        except Exception:
            return _JOURNAL_PENDING
        if parts is None:
            return None
        return DraftDiffView(tuple(
            DiffEntry(BaselineSource.XRAY_CONFIGS, "representation", DiffOperation.CHANGED, part)
            for part in parts
        ))

    def prepare(
        self, draft_id: str, expected_revision: str,
    ) -> DraftApplyPreview | DraftFileApplyRejection | ErrorDetail:
        """Сверить и показать кандидата под блокировкой, освободив её перед ответом пользователя."""
        def preview(stored: StoredDraftSession) -> DraftApplyPreview | ErrorDetail:
            state = stored.session.candidate
            if state is None:
                return _NO_CANDIDATE
            checks = self._checks(stored)
            if isinstance(checks, ErrorDetail):
                return checks
            diff = self._compare.execute(CompareSavedDraft(draft_id=draft_id, expected_revision=expected_revision))
            if not diff.succeeded:
                return diff.error
            rejection = _check_scope(state)
            if rejection is None and not _checks_passed(checks):
                rejection = _CHECK_REQUIRED
            return DraftApplyPreview(checks, diff.data, rejection, draft_id, stored.revision)

        def lock_release_failed(result: DraftApplyPreview | ErrorDetail) -> DraftFileApplyRejection:
            error = result if isinstance(result, ErrorDetail) else result.rejection or _APPLY_UNAVAILABLE
            return DraftFileApplyRejection(error)

        return run_draft_apply(
            self._lock, self._files, draft_id, expected_revision, preview,
            check_before_baseline=self._check_before_baseline,
            on_lock_release_error=lock_release_failed,
        )

    def _verify_assets(self, expected: tuple[GeoDatabase, ...]) -> bool:
        """Перечитать именно зависимости проверенного кандидата перед публикацией."""
        total = 0
        try:
            for item in expected:
                limit = min(MAX_ASSET_BYTES, MAX_TOTAL_ASSET_BYTES - total)
                data = self._assets.read_asset(item.reference, limit)
                if type(data) is not bytes or len(data) > limit or hashlib.sha256(data).hexdigest() != item.sha256:
                    return False
                total += len(data)
                del data
        except Exception:
            return False
        return True

    def apply(self, preview: DraftApplyPreview) -> DraftJournalApplyResult | DraftFileApplyRejection | ErrorDetail:
        """Подтвердить показанную полную ревизию и повторить обязательные проверки до копии."""
        if type(preview) is not DraftApplyPreview or not _checks_passed(preview.checks):
            return invalid_command()
        if preview.rejection is not None:
            return preview.rejection

        assets = ()

        def check_candidate(stored: StoredDraftSession) -> ErrorDetail | None:
            nonlocal assets
            if stored.revision != preview._revision:
                return DRAFT_CHANGED
            state = stored.session.candidate
            if state is None:
                return _NO_CANDIDATE
            error = _check_scope(state)
            if error is not None:
                return error
            checks = self._checks(stored)
            if isinstance(checks, ErrorDetail):
                return checks
            if not _checks_passed(checks):
                return _CHECK_REQUIRED
            dependencies = candidate_geo_references(state.snapshot.xray_configs)
            if not isinstance(dependencies, tuple):
                return _CHECK_REQUIRED
            expected = {(item.kind, item.reference): item for item in state.geo_revisions}
            try:
                assets = tuple(expected[key] for key in dict.fromkeys((kind, name) for kind, name, _ in dependencies))
            except KeyError:
                return _ASSETS_CHANGED
            return None if self._verify_assets(assets) else _ASSETS_CHANGED

        def check_publication() -> FileStepFailure | None:
            if self._ready() is not None:
                return FileStepFailure.READ_FAILED
            return None if self._verify_assets(assets) else FileStepFailure.CONFLICT

        return _run_draft_journal_apply(
            self._lock, self._files, preview._draft_id, draft_revision_token(preview._revision),
            self._backup, self._journal, check_candidate=check_candidate,
            check_before_baseline=self._check_before_baseline,
            check_before_publication=check_publication, verify=lambda: check_publication() is None,
            next_session_sequence=self._journal.next_sequence,
        )
