"""Файловый этап применения подтверждённой ревизии черновика."""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
import hashlib
from typing import Protocol

from keenvpn.application.contract import ErrorCategory, ErrorDetail
from keenvpn.application.draft_apply import run_draft_apply_with_backup
from keenvpn.application.draft_backup import DraftBackupSource, DraftBackupStorage, FileMetadata, VerifiedDraftBackup
from keenvpn.application.ports import DraftApplyLock, SourceFingerprintSource
from keenvpn.domain.draft_session import StoredDraftSession
from keenvpn.domain.draft_snapshot import PreparedSnapshot
from keenvpn.domain.source_baseline import (
    BaselineSource, FingerprintState, SourceFingerprint, same_fingerprint, validate_source_fingerprint,
)


@dataclass(frozen=True, slots=True, repr=False)
class DraftFileTarget:
    """Источник и, для Xray, имя одной части. Имя предназначено для доверенного кода."""

    source: BaselineSource
    part: str | None


@dataclass(frozen=True, slots=True, repr=False)
class DraftFileChange:
    target: DraftFileTarget
    content: bytes | None
    original_metadata: FileMetadata | None
    restore_metadata: FileMetadata | None = None
    expected_version: tuple[int, ...] | None = None
    expected_parent: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True, repr=False)
class PlannedFileChange:
    target: DraftFileTarget
    before: bytes | None
    content: bytes | None


@dataclass(frozen=True, slots=True, repr=False)
class FilePublication:
    """Идентичность каталога и подтверждённое состояние записи или удаления."""

    parent_identity: tuple[int, int]
    metadata: FileMetadata | None
    version: tuple[int, ...] | None


class FileStepFailure(StrEnum):
    READ_FAILED = "read_failed"
    CONFLICT = "conflict"
    WRITE_FAILED = "write_failed"
    UNCONFIRMED = "unconfirmed"


@dataclass(frozen=True, slots=True)
class FileStepResult:
    """Отказ записи и сбой очистки отражаются независимо."""

    code: FileStepFailure | None
    cleanup_failed: bool
    published: FilePublication | None = None


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


@dataclass(frozen=True, slots=True)
class DraftFileApplyRejection:
    """Исходный отказ до записи и ошибка освобождения общей блокировки."""

    error: ErrorDetail
    lock_release_failed: bool = field(default=True, init=False)


class DraftConfigFileSource(DraftBackupSource, SourceFingerprintSource, Protocol):
    """Чтение, копирование и замена одного и того же набора файлов."""

    def supports_file_name(self, target: DraftFileTarget) -> bool: ...

    def file_size_limit(self, target: DraftFileTarget) -> int: ...

    def supports_exclusive_rename(self) -> bool: ...

    def supports_exclusive_rename_in(self, targets: tuple[DraftFileTarget, ...]) -> bool: ...

    def write_draft_file(
        self, change: DraftFileChange, check_current: Callable[[], FileStepFailure | None],
    ) -> FileStepResult:
        """Проверить исходное состояние через check_current непосредственно перед записью.

        При code=None состояние файла подтверждено, в том числе при сбое очистки.
        """
        ...


_INVALID_BACKUP = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "draft_files_invalid_backup",
    "Проверенная копия не соответствует прочитанной ревизии и набору изменяемых файлов.",
)
_DIRECTORY_CHANGE = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_files_xray_directory_change",
    "Файловый этап требует существующий каталог частей Xray для их изменения.",
)
_FILE_TOO_LARGE = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "draft_files_too_large",
    "Размер файла кандидата превышает предел чтения источника.",
)
_INVALID_FILE_NAME = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "draft_files_invalid_name",
    "Имя изменяемого файла не поддерживается файловой системой.",
)
_EXCLUSIVE_RENAME_UNAVAILABLE = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_files_exclusive_rename_unavailable",
    "Для добавления файла требуется атомарное переименование без перезаписи.",
)
_INIT_PRESENCE_CHANGE = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_files_init_presence_change",
    "Файловый этап заменяет существующий init XKeen с сохранением его прав и владельца.",
)


def check_file_source(
    files: SourceFingerprintSource, expected: SourceFingerprint,
) -> FileStepFailure | None:
    try:
        actual = files.current_fingerprint(expected.source)
        validate_source_fingerprint(actual)
        if actual.source is not expected.source:
            return FileStepFailure.READ_FAILED
        if not same_fingerprint(expected, actual):
            return FileStepFailure.CONFLICT
    except Exception:
        return FileStepFailure.READ_FAILED
    return None


def plan_draft_files(
    original: PreparedSnapshot, candidate: PreparedSnapshot, files: DraftConfigFileSource,
) -> tuple[PlannedFileChange, ...] | ErrorDetail:
    changes = []
    for source, before in original.sources.items():
        after = candidate.sources[source]
        if before == after:
            continue
        if source is BaselineSource.XRAY_CONFIGS:
            if before is None or after is None:
                return _DIRECTORY_CHANGE
            # Сначала удаления: промежуточный набор не превышает предел по числу частей.
            names = sorted(before.keys() | after.keys(), key=lambda name: (name in after, name))
            entries = ((name, before.get(name), after.get(name)) for name in names)
        elif source in (BaselineSource.KEENETIC_POLICIES, BaselineSource.KEENETIC_HOTSPOT_SETTINGS):
            continue
        else:
            if source is BaselineSource.XKEEN_INIT and (before is None or after is None):
                return _INIT_PRESENCE_CHANGE
            entries = ((None, before, after),)
        for part, old, new in entries:
            if old == new:
                continue
            target = DraftFileTarget(source, part)
            if not files.supports_file_name(target):
                return _INVALID_FILE_NAME
            if new is not None and len(new) > files.file_size_limit(target):
                return _FILE_TOO_LARGE
            changes.append(PlannedFileChange(target, old, new))
    if any(item.before is None for item in changes) and not files.supports_exclusive_rename():
        return _EXCLUSIVE_RENAME_UNAVAILABLE
    return tuple(changes)


def bind_draft_files(
    plan: tuple[PlannedFileChange, ...], revision: str, backup: VerifiedDraftBackup,
) -> tuple[DraftFileChange, ...] | ErrorDetail:
    if backup.draft_revision != revision:
        return _INVALID_BACKUP
    metadata = {(source, part): value for source, part, value in backup.files}
    if len(metadata) != len(backup.files):
        return _INVALID_BACKUP
    changes = []
    for item in plan:
        key = item.target.source, item.target.part
        if key not in metadata or (metadata[key] is None) != (item.before is None):
            return _INVALID_BACKUP
        changes.append(DraftFileChange(item.target, item.content, metadata.pop(key)))
    return _INVALID_BACKUP if metadata else tuple(changes)


def check_file_creations(
    changes: tuple[DraftFileChange, ...], files: DraftConfigFileSource, *, include_restores: bool = False,
) -> ErrorDetail | None:
    targets = tuple(item.target for item in changes
                    if item.original_metadata is None or (include_restores and item.content is None))
    if targets and ((include_restores and not files.supports_exclusive_rename())
                    or not files.supports_exclusive_rename_in(targets)):
        return _EXCLUSIVE_RENAME_UNAVAILABLE
    return None


def fingerprint_after_file(expected: SourceFingerprint, change: DraftFileChange) -> SourceFingerprint:
    """Изменить ожидаемый отпечаток ровно на один подтверждённый файловый шаг."""
    part, content = change.target.part, change.content
    digest = None if content is None else hashlib.sha256(content).hexdigest()
    if part is None:
        state = FingerprintState.ABSENT if digest is None else FingerprintState.PRESENT
        return SourceFingerprint(expected.source, state, sha256=digest)
    parts = dict(expected.parts or ())
    if digest is None:
        del parts[part]
    else:
        parts[part] = digest
    return SourceFingerprint(expected.source, FingerprintState.PRESENT, parts=tuple(sorted(parts.items())))


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


def run_draft_file_apply(
    lock: DraftApplyLock, files: DraftConfigFileSource, draft_id: object, expected_revision: object,
    storage: DraftBackupStorage,
) -> DraftFileApplyResult | ErrorDetail | DraftFileApplyRejection:
    """Заменить файлы после копии и под общей блокировкой до возврата результата.

    Проверка кандидата и подтверждение команды принадлежат вызывающему.
    Если менялись только native-ресурсы, файловый результат пуст.
    """
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
