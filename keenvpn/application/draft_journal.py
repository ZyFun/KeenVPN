"""Порядок и приватный формат журнала одной попытки применения."""

from dataclasses import dataclass
from enum import StrEnum
import json
from typing import Protocol

from keenvpn.application.draft_backup import VerifiedDraftBackup
from keenvpn.application.draft_file_apply import FilePublication, FileStepFailure
from keenvpn.domain.manager_metadata import metadata_revision
from keenvpn.domain.source_baseline import BaselineSource


class DraftJournalStorage(Protocol):
    """Приватное хранилище журнала с проверкой предыдущей версии."""

    def save(self, operation_id: str, content: bytes, expected_revision: str | None) -> str:
        """Подтвердить запись повторным чтением и вернуть SHA-256.

        None как ожидаемая ревизия разрешает только создание. При отказе,
        конфликте или неопределённом исходе записи вызвать исключение.
        """
        ...


class DraftJournalStatus(StrEnum):
    APPLIED = "applied"
    REJECTED = "rejected"
    COMPENSATED = "compensated"
    RECOVERY_REQUIRED = "recovery_required"


class DraftStage(StrEnum):
    FILE = "file"
    NATIVE = "native"
    PROCESS = "process"
    VERIFY = "verify"
    VERIFY_BACKUP = "verify_backup"
    VERIFY_RESTORED_ROUTE = "verify_restored_route"


class StageDirection(StrEnum):
    APPLY = "apply"
    COMPENSATE = "compensate"


@dataclass(frozen=True, slots=True, repr=False)
class DraftStageEvent:
    stage: DraftStage
    direction: StageDirection
    source: BaselineSource | None
    part_index: int | None
    phase: str
    failure: FileStepFailure | None = None
    cleanup_failed: bool = False
    process_revision: str | None = None
    before_sha256: str | None = None
    after_sha256: str | None = None
    publication: FilePublication | None = None

    def _export(self) -> dict[str, object]:
        publication = self.publication
        return {
            "stage": self.stage.value,
            "direction": self.direction.value,
            "source": self.source,
            "part_index": self.part_index,
            "phase": self.phase,
            "failure": self.failure,
            "cleanup_failed": self.cleanup_failed,
            "process_revision": self.process_revision,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "publication": None if publication is None else {
                "parent_identity": publication.parent_identity,
                "version": publication.version,
                "metadata": None if publication.metadata is None else publication.metadata.export(),
            },
        }


class DraftJournal:
    """Один писатель под общей блокировкой. После отказа запись прекращается."""

    def __init__(
        self, storage: DraftJournalStorage, draft_id: str, backup: VerifiedDraftBackup,
        process: dict[str, object] | None,
    ) -> None:
        self._storage = storage
        # ID проверенной копии однозначно определяет одну попытку применения.
        self._header = {
            "format": "keenvpn-draft-journal",
            "schema_version": 1,
            "operation_id": backup.backup_id,
            "draft_id": draft_id,
            "draft_revision": backup.draft_revision,
            "backup_id": backup.backup_id,
            "backup_sha256": backup.sha256,
            "process": process,
        }
        self._operation_id = backup.backup_id
        self._revision = None
        self.events: list[DraftStageEvent] = []
        self.confirmed_events = 0
        self.failed = False

    def persist(self, status: DraftJournalStatus | None = None) -> bool:
        if self.failed:
            return False
        try:
            content = json.dumps({
                **self._header,
                "status": status or "in_progress",
                "events": [event._export() for event in self.events],
            }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            expected = metadata_revision(content)
            actual = self._storage.save(self._operation_id, content, self._revision)
        except Exception:
            self.failed = True
            return False
        if type(actual) is not str or actual != expected:
            self.failed = True
            return False
        self._revision = expected
        self.confirmed_events = len(self.events)
        return True

    def record(self, event: DraftStageEvent) -> bool:
        self.events.append(event)
        return self.persist()
