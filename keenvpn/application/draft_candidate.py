"""Предварительная статическая проверка кандидата черновика в памяти."""

from dataclasses import dataclass
from typing import ClassVar

from keenvpn.application.checks import ChecksView, CheckView, port_53_mode_check
from keenvpn.application.contract import (
    CONTRACT_VERSION, NEXT_STEP_MESSAGES, CheckStatus, ErrorDetail, NextStep, NextStepCode, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.draft_session import check_draft_current, valid_expected_draft
from keenvpn.application.installation import read_geo_databases
from keenvpn.application.ports import DraftSessionStore, GeoDatabaseSource, SourceFingerprintSource
from keenvpn.domain.config_document import valid_document_name
from keenvpn.domain.geodata import GeoDataState, UnsupportedGeoReference, parse_geo_reference
from keenvpn.domain.manager_metadata import valid_metadata_revision
from keenvpn.domain.routing import ConditionFamily, GeoDatabase, GeoDatabaseKind
from keenvpn.domain.routing_import import ImportReason as Reason, RoutingScheme, inspect_routing_declarations
from keenvpn.domain.routing_order import RuleOverlap, rule_overlaps
from keenvpn.domain.xkeen_config import (
    XKeenInitParameters, XKeenList, XKeenListName, validate_xkeen_init, validate_xkeen_list,
)
from keenvpn.domain.xray_config import CandidateReferences, XrayConfigSet, candidate_references, validate_xray_config_set


@dataclass(frozen=True, slots=True, repr=False)
class DraftCandidate:
    """Полные кандидаты частей Xray, параметров DNS XKeen и ожидаемые ревизии зависимых геобаз."""

    xray: XrayConfigSet
    init: XKeenInitParameters
    port_exclude: XKeenList
    port_proxying: XKeenList
    geo_revisions: tuple[GeoDatabase, ...] = ()


@dataclass(frozen=True, slots=True, repr=False)
class GeoCategoryCatalog:
    """Свидетельство доверенного источника для конкретного файла, типа базы и SHA-256.

    categories — полный набор кодов категорий в верхнем регистре. Пустой
    набор подтверждает отсутствие категорий, None — известное повреждение.
    Отсутствующее свидетельство передаётся отсутствием записи.
    """

    database: GeoDatabase
    categories: frozenset[str] | None


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CheckDraftCandidate:
    """Проверить кандидата из указанной ревизии черновика."""

    name: ClassVar[str] = "check_draft_candidate"
    draft_id: str
    expected_revision: str
    candidate: DraftCandidate
    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class DraftCandidateView:
    """Независимые проверки и позиции пересечений действующих правил."""

    checks: ChecksView
    warnings: tuple[RuleOverlap, ...]

    @property
    def outcome(self) -> str:
        statuses = self.checks.statuses.values()
        if CheckStatus.FAILED in statuses:
            return "failed"
        if any(item.status is not CheckStatus.PASSED and item.reason != "no_references"
               for item in self.checks.items):
            return "incomplete"
        return "passed"

    @property
    def next_step(self) -> NextStep | None:
        """Предложить безопасную сверку, если выявлена ошибка или проверка неполна."""
        for item in self.checks.items:
            if item.status is CheckStatus.FAILED:
                if item.reason in ("missing_geo_file", "corrupt_geo_file"):
                    code = NextStepCode.CHECK_SOURCE
                elif item.reason == "geo_revision_changed":
                    code = NextStepCode.OPEN_VIEW
                else:
                    code = NextStepCode.REVIEW_DRAFT
                break
        else:
            if self.outcome == "passed":
                return None
            geo_reason = next((
                item.reason for item in self.checks.items
                if item.code == "candidate_geo_categories" and item.status is CheckStatus.NOT_CHECKED
            ), None)
            if geo_reason == "geo_revision_unknown":
                code = NextStepCode.REVIEW_DRAFT
            elif geo_reason not in (None, "no_references", "schema_incomplete"):
                code = NextStepCode.CHECK_SOURCE
            else:
                code = NextStepCode.CONSULT_DOCUMENTATION
        return NextStep(code, NEXT_STEP_MESSAGES[code])

    def to_dict(self) -> dict[str, object]:
        step = self.next_step
        return {
            "outcome": self.outcome, "checks": self.checks.to_dict(),
            "warnings": [item.to_dict() for item in self.warnings],
            "next_step": step.to_dict() if step else None,
        }


def _valid_revision(database: object) -> bool:
    return (type(database) is GeoDatabase and type(database.kind) is GeoDatabaseKind
            and valid_document_name(database.reference) and valid_metadata_revision(database.sha256))


def _valid_candidate(candidate: object) -> bool:
    if type(candidate) is not DraftCandidate:
        return False
    try:
        validate_xray_config_set(candidate.xray)
        validate_xkeen_init(candidate.init)
        validate_xkeen_list(candidate.port_exclude)
        validate_xkeen_list(candidate.port_proxying)
        revisions = candidate.geo_revisions
        return (
            candidate.port_exclude.name is XKeenListName.PORT_EXCLUDE
            and candidate.port_proxying.name is XKeenListName.PORT_PROXYING
            and type(revisions) is tuple and all(_valid_revision(item) for item in revisions)
            and len(revisions) == len({(item.kind, item.reference) for item in revisions})
        )
    except Exception:
        return False


def _check(code: str, status: CheckStatus = CheckStatus.PASSED, reason: str | None = None) -> CheckView:
    return CheckView(code, status, False, reason)


_SCHEMA_ERRORS = (Reason.ROUTING_UNSUPPORTED, Reason.RULES_UNSUPPORTED, Reason.RULE_NOT_OBJECT,
                  Reason.VALUES_INVALID, Reason.VALUES_EMPTY, Reason.RULE_WITHOUT_CONDITIONS,
                  Reason.OUTBOUNDS_UNSUPPORTED, Reason.OUTBOUND_PROTOCOL_INVALID, Reason.BALANCERS_UNSUPPORTED)
_LINK_ERRORS = (Reason.TARGET_INVALID, Reason.TARGET_MISSING, Reason.TARGET_AMBIGUOUS, Reason.TARGET_DUPLICATE,
                Reason.TARGET_UNRESOLVED, Reason.FALLBACK_UNRESOLVED, Reason.BALANCER_INVALID, Reason.BALANCER_EMPTY)


def _schema_check(reasons: set[Reason], declarations: tuple[Reason, ...], refs: CandidateReferences) -> CheckView:
    code = "candidate_schema"
    for reason in _SCHEMA_ERRORS:
        if reason in reasons:
            return _check(code, CheckStatus.FAILED, reason.value)
    if refs.schema_invalid:
        return _check(code, CheckStatus.FAILED, "invalid_reference_structure")
    if Reason.ROUTING_MISSING in reasons:
        return _check(code, CheckStatus.UNSUPPORTED, Reason.ROUTING_MISSING.value)
    for reason in declarations:
        if reason not in _LINK_ERRORS and reason is not Reason.TARGET_API:
            return _check(code, CheckStatus.UNSUPPORTED, reason.value)
    return _check(code)


def _target_check(reasons: set[Reason], refs: CandidateReferences, schema: CheckView) -> CheckView:
    code = "candidate_targets"
    for reason in _LINK_ERRORS:
        if reason in reasons:
            return _check(code, CheckStatus.FAILED, reason.value)
    if refs.duplicate_inbound:
        return _check(code, CheckStatus.FAILED, "duplicate_inbound")
    if refs.missing_inbound:
        return _check(code, CheckStatus.FAILED, "missing_inbound")
    if schema.status is CheckStatus.FAILED or schema.reason == Reason.ROUTING_MISSING.value:
        return _check(code, CheckStatus.NOT_CHECKED, "schema_incomplete")
    return _check(code)


def _routing_checks(
    scheme: RoutingScheme, declarations: tuple[Reason, ...], refs: CandidateReferences,
) -> tuple[tuple[CheckView, ...], tuple[RuleOverlap, ...]]:
    codes = ("candidate_schema", "candidate_targets", "candidate_rule_order")
    if refs.case_variant or Reason.FIELD_CASE_VARIANT in scheme.reasons:
        return tuple(_check(code, CheckStatus.UNSUPPORTED, Reason.FIELD_CASE_VARIANT.value) for code in codes), ()

    conditions = []
    targets = set(declarations)
    for group in scheme.groups:
        if group.api_service:
            continue
        targets.update(group.target.reasons)
        conditions.extend(group.reasons)
        conditions.extend(value.reason for value in group.value_reasons)
    schema = _schema_check(set(scheme.reasons).union(declarations, conditions), declarations, refs)
    links = _target_check(targets, refs, schema)
    warnings, complete = rule_overlaps(scheme)
    if Reason.CATCH_ALL_NOT_LAST in conditions:
        order = _check("candidate_rule_order", CheckStatus.FAILED, Reason.CATCH_ALL_NOT_LAST.value)
    elif conditions or scheme.policy is None:
        reason = next(iter(conditions or scheme.reasons), Reason.RULE_ACTION_UNRESOLVED)
        order = _check("candidate_rule_order", CheckStatus.UNSUPPORTED, reason.value)
    elif not complete:
        order = _check("candidate_rule_order", CheckStatus.NOT_CHECKED, "comparison_limit")
    else:
        order = _check("candidate_rule_order")
    return (schema, links, order), warnings


def _catalog_index(catalogs: tuple[GeoCategoryCatalog, ...]):
    index = {}
    if type(catalogs) is not tuple:
        return None
    for item in catalogs:
        if type(item) is not GeoCategoryCatalog or not _valid_revision(item.database):
            return None
        categories = item.categories
        if categories is not None and (
            type(categories) is not frozenset
            or any(type(code) is not str or not code or code != code.upper() for code in categories)
        ):
            return None
        key = (item.database.kind, item.database.reference, item.database.sha256)
        if key in index:
            return None
        index[key] = categories
    return index


def _geo_check(refs: CandidateReferences, revisions: tuple[GeoDatabase, ...],
               source: GeoDatabaseSource | None, catalogs: tuple[GeoCategoryCatalog, ...]) -> CheckView:
    code = "candidate_geo_categories"
    if refs.case_variant:
        return _check(code, CheckStatus.UNSUPPORTED, Reason.FIELD_CASE_VARIANT.value)
    references = tuple(ref for value in refs.values if (ref := parse_geo_reference(value)) is not None)
    if any(type(ref) is UnsupportedGeoReference for ref in references):
        return _check(code, CheckStatus.FAILED, "invalid_geo_reference")
    if not references:
        if refs.schema_invalid:
            return _check(code, CheckStatus.NOT_CHECKED, "schema_incomplete")
        return _check(code, CheckStatus.NOT_CHECKED, "no_references")
    if source is None:
        return _check(code, CheckStatus.NOT_CHECKED, "source_not_connected")
    inventory = read_geo_databases(source)
    if isinstance(inventory, ErrorDetail):
        return _check(code, CheckStatus.NOT_CHECKED, inventory.code)
    evidence = _catalog_index(catalogs)
    expected = {(item.kind, item.reference): item.sha256 for item in revisions}
    incomplete = "schema_incomplete" if refs.schema_invalid else None
    for resolution in GeoDataState(inventory, references).resolve():
        ref = resolution.reference
        kind = GeoDatabaseKind.GEOIP if ref.family is ConditionFamily.IP else GeoDatabaseKind.GEOSITE
        file = resolution.file
        if file is None:
            incomplete = "file_not_inventoried"
            continue
        if not file.present:
            return _check(code, CheckStatus.FAILED, "missing_geo_file")
        if not file.size:
            return _check(code, CheckStatus.FAILED, "corrupt_geo_file")
        revision = expected.get((kind, file.name))
        if revision is not None and revision != file.sha256:
            return _check(code, CheckStatus.FAILED, "geo_revision_changed")
        key = (kind, file.name, file.sha256)
        if evidence is None or key not in evidence:
            incomplete = "geo_categories_unverified"
            continue
        if evidence[key] is None:
            return _check(code, CheckStatus.FAILED, "corrupt_geo_file")
        if ref.code not in evidence[key]:
            return _check(code, CheckStatus.FAILED, "geo_category_missing")
        if revision is None:
            incomplete = "geo_revision_unknown"
    if incomplete:
        return _check(code, CheckStatus.NOT_CHECKED, incomplete)
    return _check(code)


class CheckDraftCandidateHandler:
    """Проверить кандидата, используя чтение сессии, исходных отпечатков и инвентаря.

    Доверенные каталоги категорий передаются отдельно от команды. Ни имени файла,
    ни одного хеша без подтверждения содержимого недостаточно для успеха.
    """

    def __init__(self, store: DraftSessionStore, fingerprints: SourceFingerprintSource,
                 geodata: GeoDatabaseSource | None = None, catalogs: tuple[GeoCategoryCatalog, ...] = (),
                 *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._store = store
        self._fingerprints = fingerprints
        self._geodata = geodata
        self._catalogs = catalogs
        self._operation_ids = operation_ids

    def execute(self, command: CheckDraftCandidate) -> Result[DraftCandidateView]:
        """Вернуть отчёт проверок или отказ общего контракта при неверной команде и конфликте."""
        operation_id = self._operation_ids()
        name = CheckDraftCandidate.name
        if type(command) is not CheckDraftCandidate:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        candidate = command.candidate
        if not valid_expected_draft(command.draft_id, command.expected_revision) or not _valid_candidate(candidate):
            return failed(operation_id, name, invalid_command())
        scheme, declarations = inspect_routing_declarations(candidate.xray)
        refs = candidate_references(candidate.xray)
        routing, warnings = _routing_checks(scheme, declarations, refs)
        geo = _geo_check(refs, candidate.geo_revisions, self._geodata, self._catalogs)
        dns = port_53_mode_check(candidate.init, candidate.port_exclude, candidate.port_proxying)
        # Сверка последней обнаруживает и изменение во время чтения инвентаря геобаз.
        current = check_draft_current(self._store, self._fingerprints, command.draft_id, command.expected_revision)
        if isinstance(current, ErrorDetail):
            return failed(operation_id, name, current)
        return succeeded(operation_id, name, DraftCandidateView(ChecksView(False, (*routing, geo, dns)), warnings))
