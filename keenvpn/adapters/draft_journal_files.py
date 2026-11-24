"""Устойчивый журнал применения в выделенном приватном каталоге."""

from dataclasses import dataclass
import os

from keenvpn.adapters.draft_operation_files import ApplyPrivateFile
from keenvpn.application.draft_file_apply import FileStepFailure
from keenvpn.application.draft_journal import DRAFT_JOURNAL_SCHEMA_VERSION, DraftJournalStatus, DraftStage, StageDirection
from keenvpn.domain.config_document import parse_strict_json_object
from keenvpn.domain.draft_session import valid_draft_id
from keenvpn.domain.manager_metadata import valid_metadata_revision
from keenvpn.domain.source_baseline import MAX_BASELINE_PARTS, BaselineSource


class _JournalStorageError(Exception):
    def __init__(self, *, reason: str | None = None) -> None:
        self.reason = reason
        super().__init__("Не удалось сохранить и подтвердить журнал применения.")


class _JournalFile(ApplyPrivateFile):
    error_type = _JournalStorageError


_FILE_PLAN_FIELDS = ("source", "part_index", "before_sha256", "after_sha256")
_PAIR_FIELDS = ("stage", "direction", *_FILE_PLAN_FIELDS)
_EVENT_FIELDS = frozenset((*_PAIR_FIELDS, "phase", "failure", "cleanup_failed", "process_revision", "publication"))
_VERIFICATIONS = (DraftStage.VERIFY, DraftStage.VERIFY_BACKUP)


def _integer_tuple(values: object, length: int) -> bool:
    return (type(values) is list and len(values) == length
            and all(type(value) is int and value >= 0 for value in values))


def _valid_publication(publication: object) -> bool:
    if type(publication) is not dict or publication.keys() != {"parent_identity", "version", "metadata"}:
        return False
    metadata = publication["metadata"]
    return (
        _integer_tuple(publication["parent_identity"], 2) and _integer_tuple(publication["version"], 5)
        and publication["parent_identity"][0] == publication["version"][0]
        and type(metadata) is dict and metadata.keys() == {"mode", "uid", "gid"}
        and all(type(value) is int and value >= 0 for value in metadata.values()) and metadata["mode"] <= 0o7777
    )


def _valid_xray_replacement(step: dict) -> bool:
    return (
        step["source"] == BaselineSource.XRAY_CONFIGS
        and type(step["part_index"]) is int and 0 <= step["part_index"] < MAX_BASELINE_PARTS
        and all(valid_metadata_revision(step[key]) for key in ("before_sha256", "after_sha256"))
        and step["before_sha256"] != step["after_sha256"]
    )


def _valid_event(event: object) -> bool:
    if (type(event) is not dict or event.keys() != _EVENT_FIELDS
            or event["direction"] not in tuple(StageDirection)
            or event["failure"] not in (None, FileStepFailure.CONFLICT, FileStepFailure.READ_FAILED,
                                        FileStepFailure.WRITE_FAILED)
            or event["cleanup_failed"] is not False or event["process_revision"] is not None):
        return False
    if event["stage"] in (*_VERIFICATIONS, DraftStage.CLOSE_DRAFT):
        return all(event[key] is None for key in ("source", "part_index", "before_sha256", "after_sha256", "publication"))
    if event["stage"] != DraftStage.FILE or not _valid_xray_replacement(event):
        return False
    if event["phase"] == "finished" and event["failure"] is None:
        return _valid_publication(event["publication"])
    return event["publication"] is None


def _stages(events: list[dict]) -> tuple:
    return tuple(event["stage"] for event in events)


def _finished_events(events: object, status: str, file_plan: object, diff_parts: object) -> bool:
    """Подтвердить завершение замены существующих частей Xray из доступного режима меню."""
    if type(file_plan) is not list or not 0 < len(file_plan) <= MAX_BASELINE_PARTS:
        return False
    if (type(diff_parts) is not list or len(diff_parts) != len(file_plan)
            or any(type(part) is not int or not 0 <= part < MAX_BASELINE_PARTS for part in diff_parts)
            or diff_parts != sorted(set(diff_parts))):
        return False
    for index, step in enumerate(file_plan):
        if (type(step) is not dict or step.keys() != set(_FILE_PLAN_FIELDS)
                or not _valid_xray_replacement(step) or step["part_index"] != index):
            return False
    if type(events) is not list or not events or len(events) % 2 or not all(map(_valid_event, events)):
        return False
    for started, finished in zip(events[::2], events[1::2], strict=True):
        if (started["phase"] != "started" or finished["phase"] != "finished"
                or started["failure"] is not None or any(started[key] != finished[key] for key in _PAIR_FIELDS)):
            return False
    finished = events[1::2]
    forward = [event for event in finished if event["direction"] == StageDirection.APPLY]
    reverse = [event for event in finished if event["direction"] == StageDirection.COMPENSATE]
    if forward + reverse != finished or not forward:
        return False
    file_count = sum(event["stage"] == DraftStage.FILE for event in forward)
    changes = forward[:file_count]
    if not 0 < file_count <= len(file_plan) or _stages(changes) != (DraftStage.FILE,) * file_count:
        return False
    if [{key: event[key] for key in _FILE_PLAN_FIELDS} for event in changes] != file_plan[:file_count]:
        return False
    verificators = _stages(forward[file_count:])
    if verificators and file_count != len(file_plan):
        return False
    failures = [event["failure"] for event in forward]
    if status == DraftJournalStatus.APPLIED:
        return (not reverse and verificators == (*_VERIFICATIONS, DraftStage.CLOSE_DRAFT)
                and all(failure is None for failure in failures))
    if failures[-1] is None or any(failure is not None for failure in failures[:-1]):
        return False
    if status == DraftJournalStatus.REJECTED:
        return not reverse and len(forward) == 1 and not verificators
    if status != DraftJournalStatus.COMPENSATED or verificators != _VERIFICATIONS[:len(verificators)]:
        return False
    if changes[-1]["failure"] is not None:
        changes = changes[:-1]
    if not changes or len(reverse) != len(changes) + 2 or any(event["failure"] is not None for event in reverse):
        return False
    if reverse[0]["stage"] != DraftStage.VERIFY or reverse[-1]["stage"] != DraftStage.VERIFY:
        return False
    for change, undo in zip(reversed(changes), reverse[1:-1], strict=True):
        if (undo["stage"] != DraftStage.FILE or undo["part_index"] != change["part_index"]
                or undo["after_sha256"] != change["before_sha256"] or undo["before_sha256"] != change["after_sha256"]):
            return False
    return True


@dataclass(frozen=True, slots=True, repr=False)
class _StoredJournalStatus:
    revision: str
    sequence: int | None
    applied_parts: tuple[int, ...] | None


class _JournalStatusFile(_JournalFile):
    def _decode(self, content: bytes) -> _StoredJournalStatus:
        stored = super()._decode(content)
        document = parse_strict_json_object(content.decode("ascii"), comments=False)
        operation_id = self.file_name.removeprefix("journal-").removesuffix(".json")
        status, diff_parts, sequence = document.get("status"), document.get("diff_parts"), document.get("sequence")
        finished = (
            document.get("format") == "keenvpn-draft-journal"
            and type(document.get("schema_version")) is int and document["schema_version"] == DRAFT_JOURNAL_SCHEMA_VERSION
            and document.get("operation_id") == operation_id and document.get("backup_id") == operation_id
            and valid_draft_id(document.get("draft_id"))
            and all(valid_metadata_revision(document.get(key)) for key in ("draft_revision", "backup_sha256"))
            and type(sequence) is int and sequence > 0
            and "process" in document and document["process"] is None
            and _finished_events(document.get("events"), status, document.get("file_plan"), diff_parts)
        )
        return _StoredJournalStatus(
            stored.revision, sequence if finished else None,
            tuple(diff_parts) if finished and status == DraftJournalStatus.APPLIED else None,
        )


class DraftJournalFiles:
    """Хранить один JSON на попытку, заменяя только подтверждённую версию.

    Родитель каталога выбран вызывающим и идентифицирован устройством и inode.
    Запись подтверждается после fsync файла и каталога.
    """

    def __init__(self, directory: str, *, parent_identity: tuple[int, int]) -> None:
        if (type(parent_identity) is not tuple or len(parent_identity) != 2
                or any(type(value) is not int or value < 0 for value in parent_identity)):
            raise _JournalStorageError()
        self._directory = directory
        self._parent_identity = parent_identity

    def directory_writable(self) -> bool:
        """Проверить доступ к каталогу журнала без записи."""
        return _JournalFile(self._directory, "probe", self._parent_identity).directory_writable()

    def save(self, operation_id: str, content: bytes, expected_revision: str | None) -> str:
        if (not valid_draft_id(operation_id) or type(content) is not bytes
                or (expected_revision is not None and not valid_metadata_revision(expected_revision))):
            raise _JournalStorageError()
        journal = _JournalFile(self._directory, f"journal-{operation_id}.json", self._parent_identity)
        journal._decode(content)
        return journal._write_file(content, expected_revision)

    def is_clear(self) -> bool:
        """Сверить результаты прежних операций записи существующих частей Xray."""
        return self._scan() is not None

    def next_sequence(self) -> int:
        """Получить номер новой попытки под общей блокировкой сессии."""
        confirmed = self._scan()
        if confirmed is None:
            raise _JournalStorageError()
        return max(confirmed, default=0) + 1

    def last_applied_parts(self) -> tuple[int, ...] | None:
        """Выбрать последний подтверждённый diff в порядке применения."""
        confirmed = self._scan()
        if confirmed is None:
            raise _JournalStorageError()
        last = max((sequence for sequence, parts in confirmed.items() if parts is not None), default=0)
        return confirmed.get(last)

    def _scan(self) -> dict[int, tuple[int, ...] | None] | None:
        directory_guard = _JournalFile(self._directory, "scan", self._parent_identity)
        confirmed = {}
        with directory_guard._locked_directory(sync_parent=True) as directory:
            if directory is None:
                return confirmed
            for name in os.listdir(directory):
                if not name.startswith("journal-"):
                    continue
                if not name.endswith(".json") or not valid_draft_id(name[8:-5]):
                    return None
                journal = _JournalStatusFile(self._directory, name, self._parent_identity)
                stored = journal._read(directory)
                if stored is None or stored.sequence is None or stored.sequence in confirmed:
                    return None
                journal._confirm(directory, stored.revision)
                confirmed[stored.sequence] = stored.applied_parts
            directory_guard._check_identity(directory)
            return confirmed
