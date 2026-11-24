"""Драйвер файловых тестов на временном корне, без пользовательских точек входа."""

from dataclasses import dataclass, replace

from keenvpn.application.contract import ErrorDetail
from keenvpn.application.draft_apply import run_draft_apply_with_backup
from keenvpn.application.draft_file_apply import (
    DraftConfigFileSource, DraftFileApplyRejection, DraftFileTarget, FileStepFailure, PlannedFileChange,
    _INVALID_BACKUP, bind_draft_files, check_file_creations, check_file_source, fingerprint_after_file, plan_draft_files,
)
from keenvpn.application.draft_backup import DraftBackupStorage, VerifiedDraftBackup
from keenvpn.application.ports import DraftApplyLock
from keenvpn.domain.draft_session import StoredDraftSession
from keenvpn.domain.draft_snapshot import PreparedSnapshot
from keenvpn.domain.source_baseline import BaselineSource


@dataclass(frozen=True, slots=True, repr=False)
class DraftFileFailure:
    target: DraftFileTarget
    code: FileStepFailure | None
    cleanup_failed: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class DraftFileApplyResult:
    """Подтверждённые шаги в порядке записи и первый отказ, если он был."""

    backup: VerifiedDraftBackup
    completed: tuple[DraftFileTarget, ...]
    failure: DraftFileFailure | None = None
    lock_release_failed: bool = False



def _apply_draft_files(
    stored: StoredDraftSession, backup: VerifiedDraftBackup, files: DraftConfigFileSource,
    plan: tuple[PlannedFileChange, ...],
) -> DraftFileApplyResult | ErrorDetail:
    changes = bind_draft_files(plan, stored.revision, backup)
    if isinstance(changes, ErrorDetail):
        return changes
    error = check_file_creations(changes, files)
    if error is not None:
        return error

    # У каждой нетронутой части ожидается исходный SHA-256. Для подтверждённых
    # шагов учитываем только собственное изменение, не принимая чужой снимок.
    xray_expected = stored.session.baseline.fingerprint(BaselineSource.XRAY_CONFIGS)
    completed = []
    for change in changes:
        target = change.target
        expected = stored.session.baseline.fingerprint(target.source)
        if target.part is not None:
            expected = xray_expected
        step = files.write_draft_file(change, lambda: check_file_source(files, expected))
        if step.code is None:
            completed.append(target)
        if step.code is not None or step.cleanup_failed:
            failure = DraftFileFailure(target, step.code, step.cleanup_failed)
            return DraftFileApplyResult(backup, tuple(completed), failure)
        if target.part is not None:
            xray_expected = fingerprint_after_file(expected, change)
    return DraftFileApplyResult(backup, tuple(completed))


def exercise_file_steps(
    lock: DraftApplyLock, files: DraftConfigFileSource, draft_id: object, expected_revision: object,
    storage: DraftBackupStorage,
) -> DraftFileApplyResult | ErrorDetail | DraftFileApplyRejection:
    """Проверить файловый адаптер отдельно от прикладной транзакции на тестовом корне."""
    plan: tuple[PlannedFileChange, ...] | None = None

    def check_prepared(original: PreparedSnapshot, candidate: PreparedSnapshot) -> ErrorDetail | None:
        nonlocal plan
        prepared = plan_draft_files(original, candidate, files)
        if isinstance(prepared, ErrorDetail):
            return prepared
        plan = prepared
        return None

    def apply(stored: StoredDraftSession, backup: VerifiedDraftBackup) -> DraftFileApplyResult | ErrorDetail:
        return _INVALID_BACKUP if plan is None else _apply_draft_files(stored, backup, files, plan)

    def lock_release_failed(
        result: DraftFileApplyResult | ErrorDetail,
    ) -> DraftFileApplyResult | DraftFileApplyRejection:
        if isinstance(result, ErrorDetail):
            return DraftFileApplyRejection(result)
        return replace(result, lock_release_failed=True)

    return run_draft_apply_with_backup(
        lock, files, draft_id, expected_revision, files, storage, apply,
        check_prepared=check_prepared, on_lock_release_error=lock_release_failed,
    )
