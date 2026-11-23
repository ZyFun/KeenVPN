"""Журналируемое применение файлов, native-настроек и состояния процесса."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol

from keenvpn.application.contract import ErrorCategory, ErrorDetail, invalid_command
from keenvpn.application.draft_apply import DraftApplyRecheck, run_draft_apply_with_backup_recheck
from keenvpn.application.draft_backup import DraftBackupStorage, DraftProcessBackup, FileMetadata, VerifiedDraftBackup
from keenvpn.application.draft_file_apply import (
    DraftConfigFileSource, DraftFileApplyRejection, DraftFileChange, DraftFileTarget, FilePublication, FileStepFailure,
    FileStepResult, PlannedFileChange, bind_draft_files, check_file_creations, check_file_source,
    fingerprint_after_file, plan_draft_files,
)
from keenvpn.application.draft_journal import (
    DraftJournal, DraftJournalStatus, DraftJournalStorage, DraftStage, DraftStageEvent, StageDirection,
)
from keenvpn.application.ports import DraftApplyLock
from keenvpn.domain.draft_session import StoredDraftSession
from keenvpn.domain.draft_snapshot import PreparedSnapshot
from keenvpn.domain.manager_metadata import metadata_revision, valid_metadata_revision
from keenvpn.domain.source_baseline import BaselineSource, SourceFingerprint
from keenvpn.domain.xkeen_config import XKeenFlagStatus, parse_xkeen_init


@dataclass(frozen=True, slots=True, repr=False)
class NativeChange:
    """Полные канонические снимки одного ресурса для сверки границ правки."""

    source: BaselineSource
    before: bytes | None
    after: bytes | None


class DraftNativePort(Protocol):
    def supports(self, change: NativeChange) -> bool:
        """Проверить возможность точечной записи и компенсации без изменения ресурса."""
        ...

    def change(
        self, change: NativeChange, check_current: Callable[[], FileStepFailure | None],
    ) -> FileStepFailure | None:
        """Сверить before перед изменением и подтвердить after повторным чтением.

        После подготовки вызвать check_current непосредственно перед записью.
        При отказе проверки вернуть его без записи и сохранения.
        Менять и сохранять только разницу согласованного ресурса. None
        подтверждает запись, UNCONFIRMED означает возможное частичное
        выполнение. Остальные отказы гарантируют отсутствие изменений.
        """
        ...


class DraftJournalFileSource(DraftConfigFileSource, Protocol):
    def supports_file_restore_metadata(self, target: DraftFileTarget, metadata: FileMetadata) -> bool:
        """Проверить на целевой файловой системе без изменения активного файла."""
        ...

    def check_draft_file_publication(
        self, target: DraftFileTarget, expected: FilePublication,
    ) -> FileStepFailure | None:
        """Сверить подтверждённую версию или отсутствие файла без записи."""
        ...


@dataclass(frozen=True, slots=True)
class ProcessState:
    running: bool
    autostart: bool


@dataclass(frozen=True, slots=True, repr=False)
class ProcessSnapshot:
    state: ProcessState
    revision: str
    """SHA-256 ревизии управляемого состояния, различающей и перезапуски."""


@dataclass(frozen=True, slots=True, repr=False)
class ProcessChange:
    before: ProcessSnapshot
    after: ProcessState
    reload: bool = False


class DraftProcessPort(Protocol):
    def supports(self, change: ProcessChange, changed_sources: frozenset[BaselineSource]) -> bool:
        """Проверить оба перехода и гарантировать, что они не пишут управляемые источники.

        changed_sources сообщает, какие источники уже изменит файловый или
        native-шаг. Процессный порт должен учитывать эти изменения при чтении
        состояния и выполнении перехода.
        """
        ...

    def read(self) -> ProcessSnapshot:
        """Прочитать состояние службы и автозапуска либо сообщить об отказе."""
        ...

    def change(
        self, change: ProcessChange, check_current: Callable[[], FileStepFailure | None],
    ) -> ProcessSnapshot | FileStepFailure:
        """Сверить before у точки записи и повторно проверить итоговый снимок.

        После подготовки вызвать check_current непосредственно перед
        переходом. При отказе вернуть его без изменения состояния.
        При reload перечитать уже опубликованную конфигурацию. Остальные
        переходы меняют только заданное состояние вне управляемых файлов
        и native-ресурсов. Частичный результат
        или потеря ответа означают UNCONFIRMED. Прочие отказы гарантируют
        отсутствие изменений состояния и исполнения процесса.
        """
        ...


@dataclass(frozen=True, slots=True, repr=False)
class DraftJournalApplyResult:
    backup: VerifiedDraftBackup
    status: DraftJournalStatus
    events: tuple[DraftStageEvent, ...]
    confirmed_events: int
    journal_failed: bool
    lock_release_failed: bool = False


@dataclass(frozen=True, slots=True)
class _Outcome:
    failure: FileStepFailure | None = None
    cleanup_failed: bool = False
    compensate: Callable[[], "_Outcome"] | None = None
    process_revision: str | None = None
    publication: FilePublication | None = None


@dataclass(frozen=True, slots=True, repr=False)
class _Step:
    stage: DraftStage
    execute: Callable[[], _Outcome]
    source: BaselineSource | None = None
    part_index: int | None = None
    before_sha256: str | None = None
    after_sha256: str | None = None


_NATIVE_SOURCES = (BaselineSource.KEENETIC_POLICIES, BaselineSource.KEENETIC_HOTSPOT_SETTINGS)
_NATIVE_UNAVAILABLE = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_native_apply_unavailable",
    "Для изменения native-настроек требуется проверенный адаптер записи и компенсации.",
)
_PROCESS_UNAVAILABLE = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_process_apply_unavailable",
    "Для изменения состояния службы и автозапуска требуется проверенный адаптер.",
)
_XKEEN_AUTOSTART_IN_INIT = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_process_autostart_in_init",
    "Автозапуск XKeen в init меняется через отдельный файловый шаг черновика.",
)
_PROCESS_CHANGED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_process_changed",
    "Не удалось подтвердить исходное состояние службы и автозапуска.",
)
_FILE_RESTORE_UNAVAILABLE = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_file_restore_unavailable",
    "Не удалось подтвердить возможность восстановить владельца и права удаляемого файла.",
)
_PREFLIGHT_FAILED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_journal_preflight_failed",
    "Не удалось проверить возможность журналируемого применения.",
)


def _valid_state(value: object) -> bool:
    return type(value) is ProcessState and type(value.running) is bool and type(value.autostart) is bool


def _valid_snapshot(value: object) -> bool:
    return (type(value) is ProcessSnapshot and _valid_state(value.state)
            and valid_metadata_revision(value.revision))


def _valid_process_change(value: object) -> bool:
    return (type(value) is ProcessChange and _valid_snapshot(value.before) and _valid_state(value.after)
            and type(value.reload) is bool and (not value.reload or (value.before.state.running and value.after.running))
            and (value.reload or value.before.state != value.after))


def _process_overlaps_xkeen_autostart(
    original: PreparedSnapshot, candidate: PreparedSnapshot, change: ProcessChange,
) -> bool:
    before_init = original.sources[BaselineSource.XKEEN_INIT]
    after_init = candidate.sources[BaselineSource.XKEEN_INIT]
    toggles_autostart = change.before.state.autostart != change.after.autostart
    if before_init == after_init and not toggles_autostart:
        return False

    before = parse_xkeen_init(before_init or b"").switch("start_auto")
    after = parse_xkeen_init(after_init or b"").switch("start_auto")
    if before.status is XKeenFlagStatus.MISSING and after.status is XKeenFlagStatus.MISSING:
        return False
    # При правке неоднозначного присваивания нельзя подтвердить, что
    # автозапуск останется прежним для запланированного процессного шага.
    return toggles_autostart or before != after or before.status is not XKeenFlagStatus.PRESENT


def _file_step(
    files: DraftJournalFileSource, change: DraftFileChange, original: bytes | None,
    expected: dict[BaselineSource, SourceFingerprint],
    publications: dict[DraftFileTarget, FilePublication],
    check_process: Callable[[], FileStepFailure | None], *, part_index: int | None,
    check_initial_state: Callable[[], FileStepFailure | None] | None = None,
    check_initial_revision: Callable[[], FileStepFailure | None] | None = None,
) -> _Step:
    target = change.target

    def write(
        item: DraftFileChange, check_initial: Callable[[], FileStepFailure | None] | None = None,
        check_revision: Callable[[], FileStepFailure | None] | None = None,
    ) -> FileStepResult:
        before = expected[target.source]

        def check_current() -> FileStepFailure | None:
            failure = None if check_initial is None else check_initial()
            failure = failure or check_file_source(files, before) or check_process()
            return failure if failure is not None or check_revision is None else check_revision()

        result = files.write_draft_file(item, check_current)
        if (type(result) is not FileStepResult or type(result.cleanup_failed) is not bool
                or (result.code is not None and type(result.code) is not FileStepFailure)):
            return FileStepResult(FileStepFailure.UNCONFIRMED, False)
        if result.code is None:
            published = result.published
            if (type(published) is not FilePublication
                    or (published.metadata is None) != (item.content is None)
                    or (published.version is None) != (item.content is None)):
                return FileStepResult(FileStepFailure.UNCONFIRMED, result.cleanup_failed)
            expected[target.source] = fingerprint_after_file(before, item)
            publications[target] = published
        return result

    def apply() -> _Outcome:
        result = write(change, check_initial_state, check_initial_revision)
        if result.code is not None:
            return _Outcome(result.code, result.cleanup_failed)
        published = result.published
        reverse = DraftFileChange(
            target, original, published.metadata, restore_metadata=change.original_metadata,
            expected_version=published.version, expected_parent=published.parent_identity,
        )

        def compensate() -> _Outcome:
            restored = write(reverse)
            publication = restored.published if restored.code is None else None
            return _Outcome(restored.code, restored.cleanup_failed, publication=publication)

        return _Outcome(cleanup_failed=result.cleanup_failed, compensate=compensate, publication=published)

    return _Step(DraftStage.FILE, apply, target.source, part_index,
                 None if original is None else metadata_revision(original),
                 None if change.content is None else metadata_revision(change.content))


def _native_step(
    port: DraftNativePort, change: NativeChange, current: SourceFingerprint,
    candidate: SourceFingerprint, files: DraftConfigFileSource,
    expected: dict[BaselineSource, SourceFingerprint],
    check_process: Callable[[], FileStepFailure | None], *,
    check_initial_backup: Callable[[], FileStepFailure | None] | None = None,
    check_initial_revision: Callable[[], FileStepFailure | None] | None = None,
) -> _Step:
    def write(
        request: NativeChange, before: SourceFingerprint, after: SourceFingerprint,
        check_backup: Callable[[], FileStepFailure | None] | None = None,
        check_revision: Callable[[], FileStepFailure | None] | None = None,
    ) -> FileStepFailure | None:
        def check_current() -> FileStepFailure | None:
            failure = None if check_backup is None else check_backup()
            failure = failure or check_file_source(files, before) or check_process()
            return failure if failure is not None or check_revision is None else check_revision()

        failure = check_current()
        if failure is not None:
            return failure
        failure = port.change(request, check_current)
        if failure is None:
            if check_file_source(files, after) is not None:
                return FileStepFailure.UNCONFIRMED
            expected[request.source] = after
        elif type(failure) is not FileStepFailure:
            return FileStepFailure.UNCONFIRMED
        return failure

    def apply() -> _Outcome:
        failure = write(change, current, candidate, check_initial_backup, check_initial_revision)
        if failure is not None:
            return _Outcome(failure)
        reverse = NativeChange(change.source, change.after, change.before)
        return _Outcome(compensate=lambda: _Outcome(write(reverse, candidate, current)))

    return _Step(DraftStage.NATIVE, apply, change.source,
                 before_sha256=current.sha256, after_sha256=candidate.sha256)


def _process_step(
    port: DraftProcessPort, change: ProcessChange, observed: list[ProcessSnapshot],
    check_sources: Callable[[], FileStepFailure | None],
    check_backup: Callable[[], FileStepFailure | None],
    check_process: Callable[[], FileStepFailure | None], *,
    check_initial_revision: Callable[[], FileStepFailure | None] | None = None,
) -> _Step:
    def switch(
        request: ProcessChange, check_revision: Callable[[], FileStepFailure | None] | None = None,
    ) -> ProcessSnapshot | FileStepFailure:
        def check_current() -> FileStepFailure | None:
            failure = check_backup() or check_sources() or check_process()
            return failure if failure is not None or check_revision is None else check_revision()

        failure = check_current()
        if failure is not None:
            return failure
        result = port.change(request, check_current)
        if type(result) is FileStepFailure:
            return result
        if not _valid_snapshot(result) or result.state != request.after or result.revision == request.before.revision:
            return FileStepFailure.UNCONFIRMED
        if port.read() != result:
            return FileStepFailure.UNCONFIRMED
        observed.append(result)
        return result

    def apply() -> _Outcome:
        result = switch(change, check_initial_revision)
        if type(result) is FileStepFailure:
            return _Outcome(result)
        # Повторная загрузка нужна, если прямой шаг загрузил кандидата в
        # работавшую службу. Изменение одного автозапуска загрузки не требует.
        reverse = ProcessChange(result, change.before.state, change.reload)

        def compensate() -> _Outcome:
            restored = switch(reverse)
            if type(restored) is FileStepFailure:
                return _Outcome(restored)
            return _Outcome(process_revision=restored.revision)

        return _Outcome(compensate=compensate, process_revision=result.revision)

    return _Step(DraftStage.PROCESS, apply)


def _process_record(change: ProcessChange | None, before: DraftProcessBackup | None) -> dict[str, object] | None:
    if change is None or before is None:
        return None
    return {
        "before": before.export(),
        "after": {"running": change.after.running, "autostart": change.after.autostart},
        "reload": change.reload,
    }


def _run_step(
    journal: DraftJournal, step: _Step, direction: StageDirection,
    *, check: Callable[[], FileStepFailure | None] | None = None,
) -> _Outcome | None:
    event = DraftStageEvent(step.stage, direction, step.source, step.part_index, "started",
                            before_sha256=step.before_sha256, after_sha256=step.after_sha256)
    if not journal.record(event):
        return None
    try:
        failure = None if check is None else check()
    except Exception:
        failure = FileStepFailure.READ_FAILED
    if failure is None:
        try:
            outcome = step.execute()
        except Exception:
            read_only = step.stage in (DraftStage.VERIFY, DraftStage.VERIFY_BACKUP, DraftStage.VERIFY_RESTORED_ROUTE)
            failure = FileStepFailure.READ_FAILED if read_only else FileStepFailure.UNCONFIRMED
            outcome = _Outcome(failure)
    else:
        outcome = _Outcome(failure)
    journal.record(replace(event, phase="finished", failure=outcome.failure, cleanup_failed=outcome.cleanup_failed,
                           process_revision=outcome.process_revision, publication=outcome.publication))
    return outcome


def _execute(
    journal: DraftJournal, steps: list[_Step], check_backup: Callable[[], FileStepFailure | None],
    check_process: Callable[[], FileStepFailure | None], check_sources: Callable[[], FileStepFailure | None],
    check_draft: Callable[[], FileStepFailure | None],
    *, restore_running_process_last: bool, verify_restored: Callable[[], bool] | None,
) -> DraftJournalStatus:
    if not journal.persist():
        return DraftJournalStatus.REJECTED
    completed = []
    cleanup_failed = False

    def check_first_write() -> FileStepFailure | None:
        return check_backup() or check_process() or check_draft()

    for index, step in enumerate(steps):
        check = check_first_write if index == 0 else check_process
        outcome = _run_step(journal, step, StageDirection.APPLY, check=check)
        if outcome is None:
            return DraftJournalStatus.RECOVERY_REQUIRED if completed else DraftJournalStatus.REJECTED
        if outcome.compensate is not None:
            completed.append(replace(step, execute=outcome.compensate, before_sha256=step.after_sha256,
                                     after_sha256=step.before_sha256))
        if outcome.failure is FileStepFailure.UNCONFIRMED:
            return DraftJournalStatus.RECOVERY_REQUIRED
        cleanup_failed = outcome.cleanup_failed
        if journal.failed:
            return DraftJournalStatus.RECOVERY_REQUIRED if completed or cleanup_failed else DraftJournalStatus.REJECTED
        if outcome.failure is not None or cleanup_failed:
            break
    else:
        return DraftJournalStatus.APPLIED

    if not completed:
        return DraftJournalStatus.RECOVERY_REQUIRED if cleanup_failed else DraftJournalStatus.REJECTED
    checked = _run_step(journal, _Step(DraftStage.VERIFY, lambda: _Outcome(check_backup() or check_process())),
                        StageDirection.COMPENSATE)
    if checked is None or journal.failed or checked.failure is not None:
        return DraftJournalStatus.RECOVERY_REQUIRED

    # Вновь запущенную службу останавливаем перед возвратом источников.
    # Возврат работавшей службы, если он нужен, идёт после возврата данных.
    process = None
    if restore_running_process_last and completed[-1].stage is DraftStage.PROCESS:
        process = completed.pop()
    completed.reverse()
    if process is not None:
        completed.append(process)
    if verify_restored is not None:
        def verify_restored_route() -> _Outcome:
            return _Outcome(None if verify_restored() is True else FileStepFailure.CONFLICT)

        completed.append(_Step(DraftStage.VERIFY_RESTORED_ROUTE, verify_restored_route))
    completed.append(_Step(DraftStage.VERIFY, lambda: _Outcome(check_sources() or check_process())))
    for step in completed:
        outcome = _run_step(journal, step, StageDirection.COMPENSATE, check=check_process)
        if outcome is None or journal.failed or outcome.failure is not None or outcome.cleanup_failed:
            return DraftJournalStatus.RECOVERY_REQUIRED
    return DraftJournalStatus.RECOVERY_REQUIRED if cleanup_failed else DraftJournalStatus.COMPENSATED


def run_draft_journal_apply(
    lock: DraftApplyLock, files: DraftJournalFileSource, draft_id: object, expected_revision: object,
    storage: DraftBackupStorage, journal_storage: DraftJournalStorage, *, verify: Callable[[], bool],
    native: DraftNativePort | None = None, process: DraftProcessPort | None = None,
    process_change: ProcessChange | None = None,
    requires_network_verification: bool = False, verify_restored: Callable[[], bool] | None = None,
) -> DraftJournalApplyResult | DraftFileApplyRejection | ErrorDetail:
    """Применить проверенный и подтверждённый черновик под общей блокировкой.

    verify выполняет только чтение и возвращает True после всех обязательных
    проверок живого поведения. Если операция требует сетевой проверки, вызывающий
    указывает requires_network_verification и передаёт отдельную verify_restored
    для проверки исходного режима после обратных изменений.
    Адаптеры изменяют только собственный ресурс.
    При неопределённом исходе требуется отдельная сверка перед восстановлением.
    """
    if (
        not callable(verify) or (process_change is not None and not _valid_process_change(process_change))
        or type(requires_network_verification) is not bool
        or (verify_restored is not None and not callable(verify_restored))
        or (requires_network_verification and verify_restored is None)
    ):
        return invalid_command()

    plan: tuple[PlannedFileChange, ...] = ()
    native_plan: list[tuple[NativeChange, SourceFingerprint, SourceFingerprint]] = []
    process_before = None
    if process_change is not None:
        before = process_change.before
        process_before = DraftProcessBackup(before.state.running, before.state.autostart, before.revision)

    def prepare(original: PreparedSnapshot, candidate: PreparedSnapshot) -> ErrorDetail | None:
        nonlocal plan
        try:
            prepared = plan_draft_files(original, candidate, files)
            if isinstance(prepared, ErrorDetail):
                return prepared
            plan = prepared
            for source in _NATIVE_SOURCES:
                before, after = original.sources[source], candidate.sources[source]
                if before != after:
                    change = NativeChange(source, before, after)
                    if native is None or native.supports(change) is not True:
                        return _NATIVE_UNAVAILABLE
                    native_plan.append((change, original.current_fingerprint(source),
                                        candidate.current_fingerprint(source)))
            if process_change is not None:
                if _process_overlaps_xkeen_autostart(original, candidate, process_change):
                    return _XKEEN_AUTOSTART_IN_INIT
                sources = frozenset(source for source in BaselineSource
                                    if original.sources[source] != candidate.sources[source])
                if process is None or process.supports(process_change, sources) is not True:
                    return _PROCESS_UNAVAILABLE
                if process.read() != process_change.before:
                    return _PROCESS_CHANGED
        except Exception:
            return _PREFLIGHT_FAILED
        return None

    def apply(
        stored: StoredDraftSession, backup: VerifiedDraftBackup, recheck: DraftApplyRecheck,
    ) -> DraftJournalApplyResult | ErrorDetail:
        changes = bind_draft_files(plan, stored.revision, backup)
        if isinstance(changes, ErrorDetail):
            return changes
        try:
            error = check_file_creations(changes, files, include_restores=True)
            if error is not None:
                return error
            for change in changes:
                if change.content is None and (
                    change.original_metadata is None
                    or not files.supports_file_restore_metadata(change.target, change.original_metadata)
                ):
                    return _FILE_RESTORE_UNAVAILABLE
            if process_change is not None and process.read() != process_change.before:
                return _PROCESS_CHANGED
        except Exception:
            return _PREFLIGHT_FAILED

        expected = {source: stored.session.baseline.fingerprint(source) for source in BaselineSource}
        publications = {}
        observed = [] if process_change is None else [process_change.before]

        def check_backup() -> FileStepFailure | None:
            try:
                confirmed = storage.confirm(backup.backup_id, backup.sha256)
            except Exception:
                return FileStepFailure.READ_FAILED
            return None if confirmed is None else FileStepFailure.READ_FAILED

        def check_process() -> FileStepFailure | None:
            if not observed:
                return None
            try:
                current = process.read()
            except Exception:
                return FileStepFailure.READ_FAILED
            return None if current == observed[-1] else FileStepFailure.CONFLICT

        def draft_failure(error: ErrorDetail | None) -> FileStepFailure | None:
            if error is None:
                return None
            return FileStepFailure.CONFLICT if error.conflicts else FileStepFailure.READ_FAILED

        def check_draft() -> FileStepFailure | None:
            return draft_failure(recheck.sources())

        def check_revision() -> FileStepFailure | None:
            return draft_failure(recheck.revision())

        def check_initial_state() -> FileStepFailure | None:
            return check_backup() or check_draft()

        # Номер ссылается на отсортированные ключи parts в проверенной копии.
        xray_parts = sorted(part for source, part, _ in backup.files
                            if source is BaselineSource.XRAY_CONFIGS and part is not None)
        part_indices = {part: index for index, part in enumerate(xray_parts)}
        steps = [
            _file_step(
                files, change, item.before, expected, publications, check_process,
                part_index=None if change.target.part is None else part_indices[change.target.part],
                check_initial_state=check_initial_state if index == 0 else None,
                check_initial_revision=check_revision if index == 0 else None,
            )
            for index, (item, change) in enumerate(zip(plan, changes, strict=True))
        ]
        for change, before, after in native_plan:
            steps.append(_native_step(
                native, change, before, after, files, expected, check_process,
                check_initial_backup=check_backup if not steps else None,
                check_initial_revision=check_revision if not steps else None,
            ))

        def check_sources() -> FileStepFailure | None:
            for fingerprint in expected.values():
                failure = check_file_source(files, fingerprint)
                if failure is not None:
                    return failure
            for target, publication in publications.items():
                failure = files.check_draft_file_publication(target, publication)
                if failure is not None:
                    return failure
            return None

        if process_change is not None:
            steps.append(_process_step(
                process, process_change, observed, check_sources, check_backup, check_process,
                check_initial_revision=check_revision if not steps else None,
            ))

        def verify_applied() -> _Outcome:
            if verify() is not True:
                return _Outcome(FileStepFailure.CONFLICT)
            failure = check_sources()
            if failure is not None:
                return _Outcome(failure)
            return _Outcome(check_process())

        steps.append(_Step(DraftStage.VERIFY, verify_applied))
        steps.append(_Step(DraftStage.VERIFY_BACKUP, lambda: _Outcome(check_backup() or check_sources() or check_process())))
        journal = DraftJournal(journal_storage, stored.session.draft_id, backup,
                               _process_record(process_change, process_before))
        status = _execute(
            journal, steps, check_backup, check_process, check_sources, check_draft,
            restore_running_process_last=process_change is not None and process_change.before.state.running,
            verify_restored=verify_restored,
        )
        if not journal.persist(status) and status is not DraftJournalStatus.REJECTED:
            status = DraftJournalStatus.RECOVERY_REQUIRED
        return DraftJournalApplyResult(backup, status, tuple(journal.events), journal.confirmed_events, journal.failed)

    def lock_release_failed(result: DraftJournalApplyResult | ErrorDetail) -> DraftJournalApplyResult | DraftFileApplyRejection:
        if isinstance(result, ErrorDetail):
            return DraftFileApplyRejection(result)
        return replace(result, lock_release_failed=True)

    return run_draft_apply_with_backup_recheck(
        lock, files, draft_id, expected_revision, files, storage, apply,
        check_prepared=prepare, process_before=process_before, on_lock_release_error=lock_release_failed,
    )
