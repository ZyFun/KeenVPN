"""Просмотр и проверки сохранённого кандидата без записи и терминального ввода."""

from dataclasses import dataclass
from typing import ClassVar, Protocol

from keenvpn.application.checks import CheckView
from keenvpn.application.contract import (
    CONTRACT_VERSION, CheckStatus, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.draft_candidate import (
    CheckDraftCandidate, CheckDraftCandidateHandler, DraftCandidate, DraftCandidateView, GeoCategoryCatalog,
)
from keenvpn.application.draft_diff import CompareDraft, CompareDraftHandler, DraftDiffView
from keenvpn.application.draft_session import (
    CheckDraftBaseline, CheckDraftBaselineHandler, read_expected_draft, valid_expected_draft,
)
from keenvpn.application.ports import DraftSessionStore, GeoDatabaseSource, SourceFingerprintSource
from keenvpn.application.xray_candidate import (
    MAX_ASSET_BYTES, MAX_TOTAL_ASSET_BYTES, CandidateAsset, CheckInstalledXray, CheckInstalledXrayHandler,
    InstalledXrayPort, candidate_geo_references,
)
from keenvpn.domain.draft_candidate_state import DraftCandidateState
from keenvpn.domain.draft_snapshot import DraftDiffSnapshot
from keenvpn.domain.routing import GeoDatabase
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, parse_xkeen_init


class CandidateAssetSource(Protocol):
    """Доверенный источник байтов из каталога геобаз, без выбора запасного пути."""

    def read_asset(self, name: str, limit: int) -> bytes:
        """Прочитать файл целиком в пределах limit без ссылок и с проверкой неизменности.

        Имя уже проверено общим разбором ссылок Xray. Источник дополнительно
        проверяет имя на своей границе, при отказе не возвращает часть файла.
        Хеш возвращённых байтов сверяет общий CheckInstalledXray.
        """
        ...


class GeoCategorySource(Protocol):
    """Доверенный поставщик свидетельств, подключаемый сборкой, а не пользователем."""

    def read_catalogs(self, revisions: tuple[GeoDatabase, ...]) -> tuple[GeoCategoryCatalog, ...]:
        """Вернуть только подтверждённые полные каталоги для точных kind/name/SHA.

        Отсутствие записи означает отсутствие свидетельства. Хеш, имя или
        обещание пользователя не доказывают категории. Саму привязку и
        содержимое свидетельства повторно проверяет CheckDraftCandidate.
        """
        ...


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CompareSavedDraft:
    """Сравнить полные снимки сохранённой сессии, которую видел интерфейс."""

    name: ClassVar[str] = "compare_saved_draft"
    draft_id: str
    expected_revision: str
    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CheckSavedDraft:
    """Проверить сохранённые байты и ожидания одной ревизии сессии."""

    name: ClassVar[str] = "check_saved_draft"
    draft_id: str
    expected_revision: str
    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class SavedDraftCheckView:
    """Раздельные безопасные результаты; успешная статика не подменяет Xray."""

    static: DraftCandidateView | None
    static_error: ErrorDetail | None
    binary: CheckView | None
    binary_error: ErrorDetail | None

    def to_dict(self) -> dict[str, object]:
        return {name: value.to_dict() if value is not None else None for name, value in (
            ("static", self.static), ("static_error", self.static_error),
            ("binary", self.binary), ("binary_error", self.binary_error),
        )}


_NO_CANDIDATE = ErrorDetail(ErrorCategory.UNSUPPORTED, "draft_candidate_missing",
    "В сохранённой сессии нет полного кандидата. Подготовьте кандидат перед просмотром и проверкой.")
_STATIC_INPUT = ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, "draft_check_input_unavailable",
    "Сохранённые данные Xray и XKeen не позволяют выполнить статическую проверку.")
_ASSET_SOURCE = ErrorDetail(ErrorCategory.SOURCE_FAILED, "draft_assets_unavailable",
    "Не удалось получить полные байты кандидатных геобаз из доверенного источника.")
_CATALOG_SOURCE = ErrorDetail(ErrorCategory.SOURCE_FAILED, "draft_catalogs_unavailable",
    "Доверенный источник свидетельств категорий недоступен.")


class _SavedDraft:
    def __init__(self, store: DraftSessionStore, fingerprints: SourceFingerprintSource,
                 *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._store, self._fingerprints, self._operation_ids = store, fingerprints, operation_ids
        self._compare = CompareDraftHandler(store, fingerprints, operation_ids=operation_ids)
        self._baseline = CheckDraftBaselineHandler(store, fingerprints, operation_ids=operation_ids)

    def _load(self, command, command_type) -> DraftCandidateState | ErrorDetail:
        if type(command) is not command_type:
            return invalid_command()
        try:
            error = check_contract_version(command.contract_version)
            valid = valid_expected_draft(command.draft_id, command.expected_revision)
        except AttributeError:
            return invalid_command()
        if error is not None or not valid:
            return error or invalid_command()
        stored = read_expected_draft(self._store, command.draft_id, command.expected_revision)
        if isinstance(stored, ErrorDetail):
            return stored
        return stored.session.candidate or _NO_CANDIDATE


class CompareSavedDraftHandler(_SavedDraft):
    """Передать полные сохранённые снимки общему diff; не восстанавливать их из хешей."""

    def execute(self, command: CompareSavedDraft) -> Result[DraftDiffView]:
        operation_id, name = self._operation_ids(), CompareSavedDraft.name
        state = self._load(command, CompareSavedDraft)
        if isinstance(state, ErrorDetail):
            return failed(operation_id, name, state)
        result = self._compare.execute(CompareDraft(draft_id=command.draft_id,
            expected_revision=command.expected_revision, original=state.original, candidate=state.snapshot))
        return (succeeded(operation_id, name, result.data) if result.succeeded
                else failed(operation_id, name, result.error))


class CheckSavedDraftHandler(_SavedDraft):
    """Связать общие проверки с одним сохранённым кандидатом и его ожиданиями.

    Исходный снимок проверяется общим CompareDraft с самим собой: это
    проверяет полноту и baseline без построения ограниченного списка изменений.
    Конфликт сессии/источников отменяет весь отчёт, включая полученные ранее
    результаты. Два чтения не блокируют внешнего писателя после завершения.
    """

    def __init__(self, store: DraftSessionStore, fingerprints: SourceFingerprintSource,
                 geodata: GeoDatabaseSource | None = None, assets: CandidateAssetSource | None = None,
                 catalogs: GeoCategorySource | None = None, tester: InstalledXrayPort | None = None,
                 *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        super().__init__(store, fingerprints, operation_ids=operation_ids)
        self._geodata, self._assets, self._catalogs, self._tester = geodata, assets, catalogs, tester

    def _static(self, snapshot: DraftDiffSnapshot, revisions: tuple[GeoDatabase, ...], command) -> Result:
        try:
            candidate = DraftCandidate(snapshot.xray_configs, parse_xkeen_init(snapshot.xkeen_init),
                XKeenList(XKeenListName.PORT_EXCLUDE, snapshot.xkeen_port_exclude),
                XKeenList(XKeenListName.PORT_PROXYING, snapshot.xkeen_port_proxying), revisions)
            if snapshot.xray_configs is None:
                raise ValueError
        except Exception:
            return failed(self._operation_ids(), CheckDraftCandidate.name, _STATIC_INPUT)
        try:
            catalogs = () if self._catalogs is None else self._catalogs.read_catalogs(revisions)
        except Exception:
            return failed(self._operation_ids(), CheckDraftCandidate.name, _CATALOG_SOURCE)
        return CheckDraftCandidateHandler(self._store, self._fingerprints, self._geodata, catalogs,
            operation_ids=self._operation_ids).execute(CheckDraftCandidate(draft_id=command.draft_id,
                expected_revision=command.expected_revision, candidate=candidate))

    def _binary(self, snapshot: DraftDiffSnapshot, revisions: tuple[GeoDatabase, ...], command) -> Result:
        name, operation_id = CheckInstalledXray.name, self._operation_ids()
        if snapshot.xray_configs is None:
            return succeeded(operation_id, name, CheckView("installed_xray_candidate", CheckStatus.NOT_CHECKED,
                False, "candidate_xray_absent"))
        if not snapshot.xray_configs.parts:
            return succeeded(operation_id, name, CheckView("installed_xray_candidate", CheckStatus.NOT_CHECKED,
                False, "candidate_xray_empty"))
        dependencies = candidate_geo_references(snapshot.xray_configs)
        assets = []
        if not isinstance(dependencies, CheckView):
            expected = {(item.kind, item.reference): item for item in revisions}
            required = tuple(dict.fromkeys((kind, name) for kind, name, _ in dependencies))
            if any(key not in expected for key in required):
                return succeeded(operation_id, name, CheckView("installed_xray_candidate", CheckStatus.NOT_CHECKED,
                    False, "geo_revision_unknown"))
            if self._assets is None:
                return failed(operation_id, name, _ASSET_SOURCE)
            total = 0
            try:
                for key in required:
                    revision = expected[key]
                    limit = min(MAX_ASSET_BYTES, MAX_TOTAL_ASSET_BYTES - total)
                    data = self._assets.read_asset(revision.reference, limit)
                    if type(data) is not bytes or len(data) > limit:
                        raise ValueError
                    total += len(data)
                    assets.append(CandidateAsset(revision.kind, revision.reference, revision.sha256, data))
            except Exception:
                return failed(operation_id, name, _ASSET_SOURCE)
        result = CheckInstalledXrayHandler(self._store, self._fingerprints, self._tester,
            operation_ids=self._operation_ids).execute(CheckInstalledXray(draft_id=command.draft_id,
                expected_revision=command.expected_revision, xray=snapshot.xray_configs, assets=tuple(assets)))
        if result.error == invalid_command():
            # Сессия допустима, но бинарный контракт строже (например, предел
            # структуры JSON). Его правила не дублируются и не ослабляются;
            # неполнота binary не отменяет статику. Итоговый baseline обязателен.
            return succeeded(operation_id, name, CheckView("installed_xray_candidate", CheckStatus.NOT_CHECKED,
                False, "candidate_binary_input_unsupported"))
        return result

    def execute(self, command: CheckSavedDraft) -> Result[SavedDraftCheckView]:
        operation_id, name = self._operation_ids(), CheckSavedDraft.name
        state = self._load(command, CheckSavedDraft)
        if isinstance(state, ErrorDetail):
            return failed(operation_id, name, state)
        original, snapshot, revisions = state.original, state.snapshot, state.geo_revisions
        original_check = self._compare.execute(CompareDraft(draft_id=command.draft_id,
            expected_revision=command.expected_revision, original=original, candidate=original))
        if not original_check.succeeded:
            return failed(operation_id, name, original_check.error)
        static = self._static(snapshot, revisions, command)
        if not static.succeeded and static.error not in (_STATIC_INPUT, _CATALOG_SOURCE):
            return failed(operation_id, name, static.error)
        baseline = self._baseline.execute(CheckDraftBaseline(draft_id=command.draft_id,
            expected_revision=command.expected_revision))
        if not baseline.succeeded:
            return failed(operation_id, name, baseline.error)
        binary = self._binary(snapshot, revisions, command)
        if not binary.succeeded and binary.error.code not in ("draft_assets_unavailable", "xray_test_unavailable"):
            return failed(operation_id, name, binary.error)
        baseline = self._baseline.execute(CheckDraftBaseline(draft_id=command.draft_id,
            expected_revision=command.expected_revision))
        if not baseline.succeeded:
            return failed(operation_id, name, baseline.error)
        return succeeded(operation_id, name, SavedDraftCheckView(static.data, static.error, binary.data, binary.error))
