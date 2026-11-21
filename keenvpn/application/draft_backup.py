"""Подготовка и проверка приватной копии одной ревизии черновика."""

import base64
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
from typing import Protocol
from uuid import uuid4

from keenvpn.application.contract import ErrorCategory, ErrorDetail
from keenvpn.application.ports import StoreReason
from keenvpn.application.source_baseline import compare_baseline
from keenvpn.domain.draft_session import StoredDraftSession
from keenvpn.domain.draft_snapshot import PreparedSnapshot, prepare_snapshot
from keenvpn.domain.source_baseline import BaselineSource


@dataclass(frozen=True, slots=True, repr=False)
class FileMetadata:
    """Исходные POSIX-права и владелец обычного файла или каталога."""

    mode: int
    uid: int
    gid: int

    def export(self) -> dict[str, int]:
        if (type(self.mode) is not int or not 0 <= self.mode <= 0o7777
                or any(type(value) is not int or value < 0 for value in (self.uid, self.gid))):
            raise ValueError("Некорректные метаданные источника копии.")
        return {"mode": self.mode, "uid": self.uid, "gid": self.gid}


@dataclass(frozen=True, slots=True, repr=False)
class BackupFile:
    content: bytes
    metadata: FileMetadata


@dataclass(frozen=True, slots=True, repr=False)
class BackupXrayDirectory:
    parts: dict[str, BackupFile]
    metadata: FileMetadata


type BackupSourceContent = BackupFile | BackupXrayDirectory | bytes | None


class DraftBackupSource(Protocol):
    """Свежие данные источника для копирования.

    Xray — полный каталог частей, XKeen — отдельные файлы, оба с
    метаданными. RCI — канонический JSON полного ресурса. None означает
    подтверждённое отсутствие. При отказе чтения источник вызывает исключение.
    """

    def read_backup_source(self, source: BaselineSource) -> BackupSourceContent: ...


class DraftBackupStorage(Protocol):
    """Приватное хранилище копий применения."""

    def save(self, backup_id: str, content: bytes) -> str:
        """Создать новую копию, закрепить её на диске и вернуть SHA-256 из повторного чтения.

        При любом отказе записи или проверки вызвать исключение.
        """
        ...

    def confirm(self, backup_id: str, expected_sha256: str) -> None:
        """Подтвердить читаемость, приватность и целостность опубликованной копии."""
        ...


class DraftBackupStorageError(Exception):
    """Отказ без путей и содержимого копии."""

    def __init__(self, *, reason: str | None = None) -> None:
        self.reason = reason
        super().__init__("Не удалось сохранить и проверить резервную копию применения.")


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedDraftBackup:
    """Приватная ссылка на проверенную копию, передаваемая исполнителю."""

    backup_id: str
    draft_revision: str
    sha256: str


_INVALID_CANDIDATE = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "draft_backup_invalid_candidate",
    "Для резервной копии требуется полный кандидат с исходным снимком и файловым порядком частей Xray.",
)
_NO_CHANGES = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_backup_no_changes", "В черновике нет изменений для применения.",
)
_READ_FAILED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_backup_source_unavailable",
    "Не удалось полностью прочитать затрагиваемый источник для резервной копии.",
)
_SOURCE_CHANGED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_backup_source_changed",
    "Данные для резервной копии неполны или расходятся с исходным снимком черновика.",
)
_UNVERIFIED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_backup_unverified",
    "Не удалось подтвердить целостность записанной резервной копии.",
)


def _payload(content: bytes) -> dict[str, object]:
    return {
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "base64": base64.b64encode(content).decode("ascii"),
    }


def _metadata(value: object) -> dict[str, int]:
    if type(value) is not FileMetadata:
        raise ValueError("Отсутствуют метаданные источника копии.")
    return value.export()


def _file_snapshot(value: object) -> bytes:
    if type(value) is not BackupFile or type(value.content) is not bytes:
        raise ValueError("Некорректный снимок файла.")
    _metadata(value.metadata)
    return value.content


def _file_record(value: BackupFile) -> dict[str, object]:
    return {**_payload(value.content), "metadata": _metadata(value.metadata)}


def _xray_record(
    current: BackupSourceContent, before: dict[str, bytes] | None, after: dict[str, bytes] | None,
) -> dict[str, object]:
    if current is None and before is None:
        entries = {name: None for name in sorted(after or {})}
        return {"state": "absent", "parts": entries}
    if type(current) is not BackupXrayDirectory or type(current.parts) is not dict:
        raise ValueError("Некорректный снимок каталога Xray.")
    files = current.parts
    if any(type(name) is not str for name in files):
        raise ValueError("Некорректный снимок каталога Xray.")
    old = {name: _file_snapshot(value) for name, value in files.items()}
    if old != before:
        raise ValueError("Содержимое каталога изменилось.")
    new = after or {}
    records = {}
    for name in sorted(old.keys() | new.keys()):
        if old.get(name) != new.get(name):
            records[name] = _file_record(files[name]) if name in files else None
    return {"state": "present", "metadata": _metadata(current.metadata), "parts": records}


def _record(which: BaselineSource, current: BackupSourceContent, before, after) -> object:
    if which is BaselineSource.XRAY_CONFIGS:
        return _xray_record(current, before, after)
    if current is None and before is None:
        return None
    if which in (BaselineSource.KEENETIC_POLICIES, BaselineSource.KEENETIC_HOTSPOT_SETTINGS):
        if type(current) is bytes and current == before:
            return _payload(current)
    elif _file_snapshot(current) == before:
        return _file_record(current)
    raise ValueError("Содержимое источника изменилось.")


def _read_changes(original: PreparedSnapshot, candidate: PreparedSnapshot,
                  source: DraftBackupSource) -> dict[str, object] | ErrorDetail:
    changes = {}
    for which, before in original.sources.items():
        after = candidate.sources[which]
        if before == after:
            continue
        try:
            current = source.read_backup_source(which)
        except Exception:
            return _READ_FAILED
        try:
            changes[which.value] = _record(which, current, before, after)
        except (AttributeError, TypeError, ValueError):
            return _SOURCE_CHANGED
    return changes


def prepare_draft_backup(
    stored: StoredDraftSession, source: DraftBackupSource, storage: DraftBackupStorage,
    recheck_sources: Callable[[], ErrorDetail | None],
    recheck_revision: Callable[[], ErrorDetail | None],
) -> VerifiedDraftBackup | ErrorDetail:
    """Подготовить копию внутри блокировки применения для уже сверенной сессии."""
    state = stored.session.candidate
    if state is None:
        return _INVALID_CANDIDATE
    original = prepare_snapshot(state.original, require_sorted_parts=True)
    candidate = prepare_snapshot(state.snapshot, require_sorted_parts=True)
    if original is None or candidate is None:
        return _INVALID_CANDIDATE
    error = compare_baseline(original, stored.session.baseline)
    if error is not None:
        return error

    changes = _read_changes(original, candidate, source)
    if isinstance(changes, ErrorDetail):
        return changes
    if not changes:
        return _NO_CHANGES

    backup_id = str(uuid4())
    content = json.dumps({
        "format": "keenvpn-draft-backup",
        "schema_version": 1,
        "backup_id": backup_id,
        "draft_id": stored.session.draft_id,
        "draft_revision": stored.revision,
        "sources": changes,
    }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    expected = hashlib.sha256(content).hexdigest()
    try:
        actual = storage.save(backup_id, content)
    except Exception as error:
        reason = getattr(error, "reason", None) if type(error) is DraftBackupStorageError else None
        reason = reason if type(reason) is str and reason in {item.value for item in StoreReason} else None
        return ErrorDetail(
            ErrorCategory.SOURCE_FAILED, "draft_backup_storage_failed",
            "Не удалось сохранить и проверить резервную копию применения.", reason=reason,
        )
    if type(actual) is not str or actual != expected:
        return _UNVERIFIED

    error = recheck_sources()
    if error is not None:
        return error
    current = _read_changes(original, candidate, source)
    if isinstance(current, ErrorDetail):
        return current
    if changes != current:
        return _SOURCE_CHANGED
    # Сессия может измениться в обход блокировки во время чтения источников.
    error = recheck_revision()
    if error is not None:
        return error
    try:
        confirmed = storage.confirm(backup_id, expected)
    except Exception:
        return _UNVERIFIED
    if confirmed is not None:
        return _UNVERIFIED
    return VerifiedDraftBackup(backup_id, stored.revision, actual)
