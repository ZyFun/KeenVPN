"""Проверка полного кандидата Xray и его ресурсов в указанной ревизии сессии."""

from dataclasses import dataclass
from enum import Enum
import hashlib
from typing import ClassVar, Protocol

from keenvpn.application.checks import CheckView
from keenvpn.application.contract import (
    CONTRACT_VERSION, CheckStatus, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.draft_session import check_draft_current, valid_expected_draft
from keenvpn.application.ports import DraftSessionStore, SourceFingerprintSource
from keenvpn.domain.config_document import ConfigDocument, valid_document_name
from keenvpn.domain.geodata import STANDARD_FILE_NAMES, UnsupportedGeoReference, parse_geo_reference
from keenvpn.domain.manager_metadata import valid_metadata_revision
from keenvpn.domain.routing import ConditionFamily, GeoDatabaseKind
from keenvpn.domain.source_baseline import MAX_BASELINE_PARTS, valid_part_name
from keenvpn.domain.xray_config import XrayConfigSet, candidate_references


MAX_PART_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 8 * MAX_PART_BYTES
MAX_ASSET_BYTES = 256 * MAX_PART_BYTES
MAX_TOTAL_ASSET_BYTES = 2 * MAX_ASSET_BYTES
MAX_ASSETS = 32
MAX_CONFIG_SEPARATORS = 16_384
"""Общий консервативный предел структуры JSON и разворачиваемых StringList до создания объектов."""


@dataclass(frozen=True, slots=True, repr=False)
class CandidateAsset:
    """Приватные байты кандидата и их ожидаемая ревизия из доверенного входа."""

    kind: GeoDatabaseKind
    name: str
    sha256: str
    content: bytes


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CheckInstalledXray:
    """Проверить указанный кандидат установленным ядром через изолированный порт."""

    name: ClassVar[str] = "check_installed_xray"
    draft_id: str
    expected_revision: str
    xray: XrayConfigSet
    assets: tuple[CandidateAsset, ...]
    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True, repr=False)
class XrayTestInput:
    """Собственный снимок байтов в исходном порядке и зависимостей действующих разделов."""

    parts: tuple[tuple[str, bytes], ...]
    assets: tuple[CandidateAsset, ...]
    categories: tuple[tuple[GeoDatabaseKind, str, str], ...]


class XrayTestOutcome(Enum):
    """Закрытый ответ исполнителя. Системные ошибки и потоки процесса за порт не выходят."""

    PASSED = "passed"
    REJECTED = "xray_candidate_rejected"
    MISSING = "xray_binary_missing"
    UNSUPPORTED = "xray_version_unsupported"
    ISOLATION = "xray_isolation_unavailable"
    FILE_ACCESS_DENIED = "xray_file_access_denied"
    TIMEOUT = "xray_test_timeout"
    OUTPUT_LIMIT = "xray_output_limit"
    BAD_OUTPUT = "xray_output_invalid"
    INTERRUPTED = "xray_test_interrupted"
    EXECUTION = "xray_execution_failed"
    FILES = "xray_staging_failed"
    CHANGED = "xray_staging_changed"
    CLEANUP = "xray_cleanup_failed"


class InstalledXrayPort(Protocol):
    """Доверенная реализация проверяет именно переданный набор."""

    def test(self, candidate: XrayTestInput) -> XrayTestOutcome:
        """Вернуть результат после завершения группы процесса и очистки приватной подготовки."""
        ...


def _check(status: CheckStatus, reason: str | None = None) -> CheckView:
    return CheckView("installed_xray_candidate", status, False, reason)


def _parts(entries: object, *, documents: bool) -> XrayConfigSet:
    """Прочитать модели команды либо пары байтов порта с единым бюджетом до разбора JSON."""
    if type(entries) is not tuple or not 0 < len(entries) <= MAX_BASELINE_PARTS:
        raise ValueError
    copies = []
    total = separators = 0
    for entry in entries:
        if documents:
            if type(entry) is not ConfigDocument or type(entry.sha256) is not str or type(entry._snapshot) is not str:
                raise ValueError
            name, content = entry.name, entry.content
        else:
            if type(entry) is not tuple or len(entry) != 2:
                raise ValueError
            name, content = entry
        if not valid_part_name(name) or type(content) is not bytes or len(content) > MAX_PART_BYTES:
            raise ValueError
        total += len(content)
        # Учитываем и запятые в строках/комментариях, в том числе JSON-экранирование запятой.
        separators += sum(content.count(mark) for mark in (b",", b":", b"{", b"[", br"\u002c", br"\u002C"))
        if total > MAX_CONFIG_BYTES or separators > MAX_CONFIG_SEPARATORS:
            raise ValueError
        copy = ConfigDocument(name, content)
        if documents and (copy.sha256 != entry.sha256 or copy._snapshot != entry._snapshot):
            raise ValueError
        copies.append(copy)
    return XrayConfigSet(tuple(copies))


def _assets(items: tuple[CandidateAsset, ...]) -> tuple[CandidateAsset, ...] | CheckView:
    if type(items) is not tuple or len(items) > MAX_ASSETS:
        raise ValueError
    names = set()
    copies = []
    total = 0
    for item in items:
        if type(item) is not CandidateAsset:
            raise ValueError
        kind, name, digest, data = item.kind, item.name, item.sha256, item.content
        if (kind is not GeoDatabaseKind.GEOIP and kind is not GeoDatabaseKind.GEOSITE
                or not valid_document_name(name) or name in names or not valid_metadata_revision(digest)
                or type(data) is not bytes):
            raise ValueError
        names.add(name)
        total += len(data)
        if not data or len(data) > MAX_ASSET_BYTES or total > MAX_TOTAL_ASSET_BYTES:
            return _check(CheckStatus.FAILED, "candidate_asset_size")
        if hashlib.sha256(data).hexdigest() != digest:
            return _check(CheckStatus.FAILED, "candidate_asset_digest")
        copies.append(CandidateAsset(kind, name, digest, data))
    return tuple(copies)


def _prepare(config: XrayConfigSet, assets: tuple[CandidateAsset, ...]) -> XrayTestInput | CheckView:
    resources = _assets(assets)
    if type(resources) is CheckView:
        return resources
    refs = candidate_references(config)
    if refs.schema_invalid or refs.case_variant:
        return _check(CheckStatus.NOT_CHECKED, "candidate_references_incomplete")
    categories = {}
    for value in refs.values:
        ref = parse_geo_reference(value)
        if ref is None:
            continue
        if (type(ref) is UnsupportedGeoReference or not valid_document_name(ref.file_name)
                or not ref.set_name.isascii()):
            return _check(CheckStatus.NOT_CHECKED, "candidate_references_incomplete")
        kind = GeoDatabaseKind.GEOIP if ref.family is ConditionFamily.IP else GeoDatabaseKind.GEOSITE
        categories[kind, ref.file_name, ref.code] = None
    required = {(kind, name) for kind, name, _ in categories}
    if not set(STANDARD_FILE_NAMES.items()).issubset(required):
        return _check(CheckStatus.NOT_CHECKED, "both_geo_references_required")
    if {(item.kind, item.name) for item in resources} != required:
        return _check(CheckStatus.FAILED, "candidate_assets_mismatch")
    return XrayTestInput(tuple((p.name, p.content) for p in config.parts), resources, tuple(categories))


def checked_port_input(value: object) -> XrayTestInput | None:
    """Перед файловыми эффектами восстановить набор из байтов и проверить переданные зависимости."""
    if type(value) is not XrayTestInput:
        return None
    try:
        claimed = value.categories
        if type(claimed) is not tuple or len(claimed) > MAX_CONFIG_SEPARATORS:
            return None
        for entry in claimed:
            if (type(entry) is not tuple or len(entry) != 3
                    or entry[0] is not GeoDatabaseKind.GEOIP and entry[0] is not GeoDatabaseKind.GEOSITE
                    or type(entry[1]) is not str or type(entry[2]) is not str):
                return None
        verified = _prepare(_parts(value.parts, documents=False), value.assets)
        if type(verified) is XrayTestInput and verified.categories == claimed:
            return verified
    except (AttributeError, ValueError, TypeError, RecursionError):
        pass
    return None


def _interpret(outcome: object) -> CheckView | ErrorDetail:
    if outcome is XrayTestOutcome.PASSED:
        return _check(CheckStatus.PASSED)
    if outcome is XrayTestOutcome.REJECTED:
        return _check(CheckStatus.FAILED, "xray_candidate_rejected")
    if outcome is XrayTestOutcome.UNSUPPORTED:
        return _check(CheckStatus.UNSUPPORTED, "xray_version_unsupported")
    reason = next((member.value for member in XrayTestOutcome if member is outcome), "invalid_port_response")
    return ErrorDetail(ErrorCategory.SOURCE_FAILED, "xray_test_unavailable",
                       "Проверка установленным Xray не завершена.", reason=reason)


class CheckInstalledXrayHandler:
    """Сверить состояние до проверки и повторно после подготовки, исполнения и очистки."""

    def __init__(self, store: DraftSessionStore, fingerprints: SourceFingerprintSource,
                 tester: InstalledXrayPort | None = None, *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._store = store
        self._fingerprints = fingerprints
        self._tester = tester
        self._operation_ids = operation_ids

    def execute(self, command: CheckInstalledXray) -> Result[CheckView]:
        operation_id, name = self._operation_ids(), CheckInstalledXray.name
        if type(command) is not CheckInstalledXray:
            return failed(operation_id, name, invalid_command())
        try:
            error = check_contract_version(command.contract_version)
            draft_id, revision = command.draft_id, command.expected_revision
            config, assets = command.xray, command.assets
        except AttributeError:
            return failed(operation_id, name, invalid_command())
        if error is not None or not valid_expected_draft(draft_id, revision):
            return failed(operation_id, name, error or invalid_command())
        try:
            current = check_draft_current(self._store, self._fingerprints, draft_id, revision)
        except KeyboardInterrupt:
            return failed(operation_id, name, _interpret(XrayTestOutcome.INTERRUPTED))
        if isinstance(current, ErrorDetail):
            return failed(operation_id, name, current)
        try:
            if type(config) is not XrayConfigSet:
                raise ValueError
            prepared = _prepare(_parts(config.parts, documents=True), assets)
        except (AttributeError, ValueError, TypeError, RecursionError):
            return failed(operation_id, name, invalid_command())
        except KeyboardInterrupt:
            prepared = None
        if prepared is None:
            result = _interpret(XrayTestOutcome.INTERRUPTED)
        elif type(prepared) is CheckView:
            result = prepared
        elif self._tester is None:
            result = _interpret(XrayTestOutcome.ISOLATION)
        else:
            try:
                outcome = self._tester.test(prepared)
            except KeyboardInterrupt:
                outcome = XrayTestOutcome.INTERRUPTED
            except Exception:
                outcome = XrayTestOutcome.EXECUTION
            result = _interpret(outcome)
        try:
            current = check_draft_current(self._store, self._fingerprints, draft_id, revision)
        except KeyboardInterrupt:
            return failed(operation_id, name, _interpret(XrayTestOutcome.INTERRUPTED))
        if isinstance(current, ErrorDetail):
            return failed(operation_id, name, current)
        if type(result) is ErrorDetail:
            return failed(operation_id, name, result)
        return succeeded(operation_id, name, result)
