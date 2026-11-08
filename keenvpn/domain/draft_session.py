"""Сессия черновика изменений: модель, строгий формат и ревизия.

Одна редактируемая сессия менеджера хранится отдельно от active configs
Xray и XKeen. Модуль ничего не читает с диска и не записывает: он разбирает
и собирает байты файла, ревизия — SHA-256 этих байтов, как у метаданных
менеджера. Версия схемы 1 содержит идентификатор черновика, время его
создания, необязательный `baseline` — исходные отпечатки управляемых
источников, и `candidate` — полные исходный и изменённый снимки.
Наличие файла означает открытую сессию. Разделы добавляются как
необязательные поля верхнего уровня; неизвестные поля сохраняются
и записываются обратно после известных. Разбор строгий: UTF-8, без
комментариев, дублей ключей, NaN и Infinity, с ограничением размера
и глубины. Неподдерживаемая версия схемы не угадывается и не мигрирует.
Черновик ничего не применяет.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import json
import re
from typing import NoReturn

from keenvpn.domain.config_document import ConfigDocumentError, parse_strict_json_object, valid_json_tree
from keenvpn.domain.draft_candidate_state import (
    DraftCandidateState, DraftCandidateStateError, rebuild_draft_candidate,
)
from keenvpn.domain.manager_metadata import (
    ManagerMetadataError, UnknownFields, metadata_revision, rebuild_unknown_fields, valid_metadata_revision,
)
from keenvpn.domain.source_baseline import (
    SourceBaseline, SourceBaselineError, export_source_baseline, parse_source_baseline, rebuild_source_baseline,
)


DRAFT_FORMAT = "keenvpn-draft-session"
"""Маркер формата: отличает файл черновика от чужого JSON и от метаданных менеджера."""
DRAFT_SCHEMA_VERSION = 1
"""Единственная поддерживаемая версия схемы."""
MAX_DRAFT_SIZE = 1024 * 1024
"""Предел размера файла в байтах при чтении и записи."""

_DRAFT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_CREATED_AT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
_TOP_KEYS = ("format", "schema_version", "draft_id", "created_at", "baseline", "candidate")


class DraftSessionErrorCode(StrEnum):
    """Стабильные коды нарушений формата и модели черновика."""

    CONTENT = "invalid_draft_content"
    JSON = "invalid_draft_json"
    FORMAT = "invalid_draft_format"
    SCHEMA_VERSION = "unsupported_draft_schema_version"
    DRAFT_ID = "invalid_draft_id"
    CREATED_AT = "invalid_draft_created_at"
    UNKNOWN_FIELDS = "invalid_unknown_fields"
    BASELINE = "invalid_draft_baseline"
    CANDIDATE = "invalid_draft_candidate"
    REVISION = "invalid_draft_revision"
    SESSION = "invalid_draft_session"


_MESSAGES = {
    DraftSessionErrorCode.CONTENT: "Файл черновика не является текстом UTF-8 допустимого размера.",
    DraftSessionErrorCode.JSON: "Файл черновика не является строгим JSON-объектом.",
    DraftSessionErrorCode.FORMAT: "Файл не является черновиком KeenVPN или нарушает структуру формата.",
    DraftSessionErrorCode.SCHEMA_VERSION: "Версия схемы черновика не поддерживается этой версией менеджера.",
    DraftSessionErrorCode.DRAFT_ID: "Идентификатор черновика должен быть UUID в нижнем регистре.",
    DraftSessionErrorCode.CREATED_AT: "Время создания черновика должно быть моментом UTC с точностью до секунды.",
    DraftSessionErrorCode.UNKNOWN_FIELDS: "Неизвестные поля черновика нельзя сохранить без изменения.",
    DraftSessionErrorCode.BASELINE: "Раздел исходных отпечатков черновика повреждён.",
    DraftSessionErrorCode.CANDIDATE: "Раздел кандидата черновика повреждён или неполон.",
    DraftSessionErrorCode.REVISION: "Ревизия черновика должна быть SHA-256 в нижнем регистре.",
    DraftSessionErrorCode.SESSION: "Сессия черновика повреждена.",
}


class DraftSessionError(ValueError):
    """Отказ с машинным кодом и фиксированным текстом.

    `field` — имя поля известного формата либо `None`. Значения и имена
    неизвестных полей в ошибку не попадают.
    """

    def __init__(self, code: DraftSessionErrorCode, field: str | None = None) -> None:
        self.code = code
        self.field = field
        super().__init__(_MESSAGES[code])


def _fail(code: DraftSessionErrorCode, field: str | None = None) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise DraftSessionError(code, field) from None
    except DraftSessionError as error:
        error.__context__ = None
        raise


def valid_draft_id(value: object) -> bool:
    """Проверить формат идентификатора черновика: UUID 8-4-4-4-12 в нижнем регистре.

    Регистр не нормализуется, версия UUID не проверяется.
    """
    return type(value) is str and _DRAFT_ID.fullmatch(value) is not None


def valid_created_at(value: object) -> bool:
    """Проверить время создания: `datetime` в UTC (`timezone.utc`) без долей секунды."""
    return type(value) is datetime and value.tzinfo is timezone.utc and value.microsecond == 0 and value.fold == 0


def format_created_at(value: datetime) -> str:
    """Записать проверенное время создания как `YYYY-MM-DDTHH:MM:SSZ`; год всегда из четырёх цифр."""
    return (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}"
        f"T{value.hour:02d}:{value.minute:02d}:{value.second:02d}Z"
    )


def _parse_created_at(value: object) -> datetime:
    match = _CREATED_AT.fullmatch(value) if type(value) is str else None
    parsed = None
    if match is not None:
        try:
            parsed = datetime(*(int(part) for part in match.groups()), tzinfo=timezone.utc)
        except ValueError:
            # Несуществующая дата или время, например 30 февраля или 24 часа.
            pass
    if parsed is None:
        _fail(DraftSessionErrorCode.CREATED_AT, "created_at")
    return parsed


def _unknown_fields(values: dict[str, object]) -> UnknownFields:
    extra = None
    try:
        extra = UnknownFields(values)
    except ManagerMetadataError:
        # Например, целое длиннее предела преобразования в текст.
        pass
    if extra is None:
        _fail(DraftSessionErrorCode.UNKNOWN_FIELDS)
    return extra


def _no_fields() -> UnknownFields:
    return UnknownFields()


def _baseline(value: object) -> SourceBaseline:
    """Разобрать раздел `baseline`; код ошибки отпечатка в ошибку черновика не переносится."""
    baseline = None
    try:
        baseline = parse_source_baseline(value)
    except SourceBaselineError:
        pass
    if baseline is None:
        _fail(DraftSessionErrorCode.BASELINE, "baseline")
    return baseline


def _candidate(value: object) -> DraftCandidateState:
    candidate = None
    try:
        candidate = DraftCandidateState(value)
    except DraftCandidateStateError:
        pass
    if candidate is None:
        _fail(DraftSessionErrorCode.CANDIDATE, "candidate")
    return candidate


@dataclass(frozen=True, slots=True)
class DraftSession:
    """Сессия черновика текущей версии схемы.

    `draft_id` — случайный UUID, выданный при создании; `created_at` — момент
    создания в UTC; `baseline` — исходные отпечатки источников либо None,
    если их в файле нет. Значения неизвестных полей — данные другой версии
    менеджера: `repr` показывает только их число. Хеши, будущая полезная
    нагрузка изменений не должны попадать в `repr` и диагностику.
    `candidate` — приватный полный раздел либо None у прежнего черновика.
    """

    draft_id: str
    created_at: datetime
    extra: UnknownFields = field(default_factory=_no_fields)
    baseline: SourceBaseline | None = None
    candidate: DraftCandidateState | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not valid_draft_id(self.draft_id):
            _fail(DraftSessionErrorCode.DRAFT_ID, "draft_id")
        if not valid_created_at(self.created_at):
            _fail(DraftSessionErrorCode.CREATED_AT, "created_at")
        if type(self.extra) is not UnknownFields or any(name in _TOP_KEYS for name in self.extra.names):
            _fail(DraftSessionErrorCode.UNKNOWN_FIELDS)
        if self.baseline is not None and type(self.baseline) is not SourceBaseline:
            _fail(DraftSessionErrorCode.BASELINE, "baseline")
        if self.candidate is not None and type(self.candidate) is not DraftCandidateState:
            _fail(DraftSessionErrorCode.CANDIDATE, "candidate")

    def to_diagnostic(self) -> dict[str, object]:
        """Версия схемы, идентификатор, время создания, число неизвестных полей и состояния источников.

        Имена и значения неизвестных полей, хеши и имена частей Xray сюда не входят.
        """
        return {
            "schema_version": DRAFT_SCHEMA_VERSION, "draft_id": self.draft_id,
            "created_at": format_created_at(self.created_at), "unknown_field_count": len(self.extra),
            "baseline": None if self.baseline is None else self.baseline.to_diagnostic(),
        }


@dataclass(frozen=True, slots=True)
class StoredDraftSession:
    """Сессия, прочитанная из файла, и ревизия — SHA-256 его байтов."""

    session: DraftSession
    revision: str

    def __post_init__(self) -> None:
        if type(self.session) is not DraftSession:
            _fail(DraftSessionErrorCode.SESSION)
        if not valid_metadata_revision(self.revision):
            _fail(DraftSessionErrorCode.REVISION)


def draft_revision(content: bytes) -> str:
    """Ревизия байтов файла черновика; вычисляется так же, как у метаданных менеджера."""
    return metadata_revision(content)


def decode_draft_session(content: bytes) -> StoredDraftSession:
    """Разобрать байты файла в сессию с ревизией.

    Сначала проверяются маркер формата и версия схемы: файл другой версии
    отклоняется кодом `unsupported_draft_schema_version` без разбора
    остальных полей.
    """
    if type(content) is not bytes or len(content) > MAX_DRAFT_SIZE:
        _fail(DraftSessionErrorCode.CONTENT)
    text = None
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    if text is None:
        _fail(DraftSessionErrorCode.CONTENT)
    document = None
    try:
        document = parse_strict_json_object(text, comments=False)
    except ConfigDocumentError:
        pass
    if document is None:
        _fail(DraftSessionErrorCode.JSON)
    marker = document.get("format")
    if type(marker) is not str or marker != DRAFT_FORMAT:
        _fail(DraftSessionErrorCode.FORMAT, "format")
    version = document.get("schema_version")
    if type(version) is not int or version < 1:
        _fail(DraftSessionErrorCode.FORMAT, "schema_version")
    if version != DRAFT_SCHEMA_VERSION:
        _fail(DraftSessionErrorCode.SCHEMA_VERSION, "schema_version")
    for key in ("draft_id", "created_at"):
        if key not in document:
            _fail(DraftSessionErrorCode.FORMAT, key)
    if not valid_draft_id(document["draft_id"]):
        _fail(DraftSessionErrorCode.DRAFT_ID, "draft_id")
    created_at = _parse_created_at(document["created_at"])
    baseline = _baseline(document["baseline"]) if "baseline" in document else None
    candidate = _candidate(document["candidate"]) if "candidate" in document else None
    extra = _unknown_fields({key: value for key, value in document.items() if key not in _TOP_KEYS})
    session = DraftSession(document["draft_id"], created_at, extra, baseline, candidate)
    return StoredDraftSession(session, draft_revision(content))


def validate_draft_session(session: DraftSession) -> None:
    """Проверить готовую модель заново, пересобрав её из собственных полей.

    Конструктор требует точных типов, поэтому подкласс `str` или `datetime`,
    испорченный снимок неизвестных полей и подменённые отпечатки не проходят.
    Код ошибки поля сохраняется.
    """
    code = name = None
    try:
        if type(session) is not DraftSession:
            _fail(DraftSessionErrorCode.SESSION)
        baseline = session.baseline
        DraftSession(
            session.draft_id, session.created_at, rebuild_unknown_fields(session.extra),
            None if baseline is None else rebuild_source_baseline(baseline),
            None if session.candidate is None else rebuild_draft_candidate(session.candidate),
        )
    except DraftSessionError as error:
        code, name = error.code, error.field
    except ManagerMetadataError:
        code = DraftSessionErrorCode.UNKNOWN_FIELDS
    except SourceBaselineError:
        code, name = DraftSessionErrorCode.BASELINE, "baseline"
    except DraftCandidateStateError:
        code, name = DraftSessionErrorCode.CANDIDATE, "candidate"
    except Exception:
        # Повреждённая модель: атрибут не того типа, испорченный снимок и подобное.
        code = DraftSessionErrorCode.SESSION
    if code is not None:
        _fail(code, name)


def encode_draft_session(session: DraftSession) -> bytes:
    """Собрать байты файла текущей версии схемы после повторной проверки модели.

    Известные поля идут в фиксированном порядке, неизвестные — после них
    в исходном порядке; текст ASCII с отступом и переводом строки в конце.
    """
    validate_draft_session(session)
    document: dict[str, object] = {
        "format": DRAFT_FORMAT, "schema_version": DRAFT_SCHEMA_VERSION,
        "draft_id": session.draft_id, "created_at": format_created_at(session.created_at),
    }
    if session.baseline is not None:
        baseline = export_source_baseline(session.baseline)
        # Неизвестные записи раздела лежат на уровень глубже собственной проверки
        # снимка: документ с ними должен остаться читаемым строгим разбором.
        if not valid_json_tree({"baseline": baseline}):
            _fail(DraftSessionErrorCode.BASELINE, "baseline")
        document["baseline"] = baseline
    if session.candidate is not None:
        candidate = session.candidate.export()
        if not valid_json_tree({"candidate": candidate}):
            _fail(DraftSessionErrorCode.CANDIDATE, "candidate")
        document["candidate"] = candidate
    # Неизвестные поля верхнего уровня: их глубину уже проверил снимок `UnknownFields`.
    document.update(session.extra.export())
    content = (json.dumps(document, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("ascii")
    if len(content) > MAX_DRAFT_SIZE:
        _fail(DraftSessionErrorCode.CONTENT)
    return content
