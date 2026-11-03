"""Создание, просмотр, проверка актуальности и отмена одной сессии черновика изменений.

Сценарии работают с собственным хранилищем черновика через порт
`DraftSessionStore`; создание и проверка актуальности, кроме того, читают
отпечатки управляемых источников через порт `SourceFingerprintSource`.
Черновик ничего не применяет: конфигурация Xray и XKeen, настройки Keenetic
и службы не меняются и не разбираются. Сессия одна: создание при
существующем черновике — отказ без перезаписи. Отмена удаляет только файл
сессии с идентификатором и токеном ревизии из команды. Проверка актуальности
ничего не записывает: черновик, источники которого изменились после его
создания, — отказ с записями конфликта; общий помощник этой проверки
вызывает и будущее применение. Результаты содержат идентификатор,
непрозрачный токен ревизии, время создания, число неизвестных полей
и состояния источников, без путей, ревизии файла, хешей и значений
неизвестных полей. Расхождение черновика с ожидаемым командой возвращается
с записью конфликта контракта. Применение — не этого модуля.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import re
from typing import ClassVar
import uuid

from keenvpn.application.contract import (
    CONTRACT_VERSION, Conflict, ConflictState, ConflictSubject, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, revision_conflict, succeeded,
)
from keenvpn.application.ports import (
    DraftSessionStore, DraftSessionStoreError, DraftStoreFailure, SourceFingerprintSource, StoreReason,
)
from keenvpn.application.source_baseline import capture_baseline, compare_baseline
from keenvpn.application.views import view_dict, view_fields
from keenvpn.domain.draft_session import (
    DraftSession, DraftSessionErrorCode, StoredDraftSession, draft_revision, encode_draft_session, valid_draft_id,
    validate_draft_session,
)
from keenvpn.domain.manager_metadata import valid_metadata_revision


DraftIdFactory = Callable[[], str]
Clock = Callable[[], datetime]

REVISION_TOKEN_LENGTH = 32
"""Длина токена ревизии черновика в шестнадцатеричных цифрах: 128 бит."""
_REVISION_TOKEN = re.compile(f"[0-9a-f]{{{REVISION_TOKEN_LENGTH}}}")
_REVISION_TOKEN_DOMAIN = b"keenvpn-draft-revision-token-v1\n"


def draft_revision_token(revision: str) -> str:
    """Непрозрачный токен ревизии черновика для интерфейсов.

    Первые 128 бит SHA-256 от метки домена и ревизии файла: токен меняется
    вместе с любым байтом файла, но не совпадает ни с ревизией, ни с хешами
    источников и не позволяет их получить. Формат — 32 шестнадцатеричные
    цифры, поэтому сырую ревизию из 64 цифр с токеном не спутать.
    """
    if not valid_metadata_revision(revision):
        raise TypeError("Токен строится из ревизии черновика.")
    return hashlib.sha256(_REVISION_TOKEN_DOMAIN + revision.encode("ascii")).hexdigest()[:REVISION_TOKEN_LENGTH]


def valid_revision_token(value: object) -> bool:
    """Проверить формат токена ревизии: 32 шестнадцатеричные цифры в нижнем регистре, точный `str`."""
    return type(value) is str and _REVISION_TOKEN.fullmatch(value) is not None


def valid_expected_draft(draft_id: object, expected_revision: object) -> bool:
    """Проверить формат идентификатора и токена ревизии, которые команда взяла из представления черновика."""
    return valid_draft_id(draft_id) and valid_revision_token(expected_revision)


def new_draft_id() -> str:
    """Создать случайный идентификатор черновика без обращения к сети и файлам."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Текущий момент UTC; доли секунды отбрасывает сценарий создания."""
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True, kw_only=True)
class CreateDraft:
    """Создать сессию черновика, если её ещё нет."""

    name: ClassVar[str] = "create_draft"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectDraft:
    """Прочитать сессию черновика без записи."""

    name: ClassVar[str] = "inspect_draft"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True, kw_only=True)
class DiscardDraft:
    """Отменить черновик с этим идентификатором и токеном ревизии: удалить файл сессии, ничего не применяя.

    `draft_id` и `expected_revision` берутся из `DraftView`, а не вводятся
    пользователем: устаревшее представление не удалит изменённый черновик.
    """

    name: ClassVar[str] = "discard_draft"

    draft_id: str
    expected_revision: str
    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckDraftBaseline:
    """Проверить, что черновик с этим идентификатором и токеном ревизии не устарел, ничего не записывая.

    `draft_id` и `expected_revision` берутся из `DraftView`, как у отмены.
    """

    name: ClassVar[str] = "check_draft_baseline"

    draft_id: str
    expected_revision: str
    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class BaselineSourceView:
    """Источник исходного отпечатка и его состояние: `present` или `absent`, без хешей."""

    source: str
    state: str

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return view_dict(self)


@dataclass(frozen=True, slots=True)
class DraftBaselineView:
    """Зафиксированные источники в порядке перечня и число записей, неизвестных этой версии.

    Хеши, имена частей Xray и значения неизвестных записей сюда не входят.
    """

    sources: tuple[BaselineSourceView, ...]
    unknown_source_count: int

    @classmethod
    def from_diagnostic(cls, values: dict[str, object]) -> "DraftBaselineView":
        """Построить представление из безопасной диагностики раздела."""
        fields = view_fields(cls, values)
        fields["sources"] = tuple(
            BaselineSourceView(**view_fields(BaselineSourceView, item)) for item in fields["sources"]
        )
        return cls(**fields)

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "sources": [item.to_dict() for item in self.sources], "unknown_source_count": self.unknown_source_count,
        }


@dataclass(frozen=True, slots=True)
class DraftView:
    """Безопасное представление сессии: идентификатор, токен ревизии, время создания UTC, неизвестные поля и источники.

    `revision` — непрозрачный токен ревизии (`draft_revision_token`): интерфейс
    передаёт его в команды, меняющие черновик, вместе с `draft_id`. `baseline`
    — состояния зафиксированных источников либо None, если раздела в файле
    нет. Путь, ревизия файла, хеши, имена и значения неизвестных полей сюда не входят.
    """

    draft_id: str
    revision: str
    created_at: str
    unknown_field_count: int
    baseline: DraftBaselineView | None

    @classmethod
    def from_session(cls, session: DraftSession, revision: str) -> "DraftView":
        """Построить представление из безопасной диагностики домена и ревизии файла."""
        fields = view_fields(cls, {**session.to_diagnostic(), "revision": draft_revision_token(revision)})
        if fields["baseline"] is not None:
            fields["baseline"] = DraftBaselineView.from_diagnostic(fields["baseline"])
        return cls(**fields)

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        fields = view_dict(self)
        fields["baseline"] = None if self.baseline is None else self.baseline.to_dict()
        return fields


@dataclass(frozen=True, slots=True)
class DraftStatusView:
    """Наличие черновика и его безопасное представление.

    `present=False` — черновика нет; это состояние, а не отказ.
    """

    present: bool
    draft: DraftView | None

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {"present": self.present, "draft": None if self.draft is None else self.draft.to_dict()}


class DraftDiscardOutcome(StrEnum):
    """Итог успешной отмены черновика."""

    DISCARDED = "discarded"
    """Файл сессии с этим идентификатором удалён."""
    ALREADY_ABSENT = "already_absent"
    """Черновика уже не было; операция ничего не удаляла."""


@dataclass(frozen=True, slots=True)
class DraftDiscardView:
    """Итог отмены и идентификатор из команды."""

    outcome: str
    draft_id: str

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return view_dict(self)


class DraftBaselineOutcome(StrEnum):
    """Итог успешной проверки актуальности черновика."""

    CURRENT = "current"
    """Все управляемые источники совпали с исходными отпечатками черновика на момент проверки."""


@dataclass(frozen=True, slots=True)
class DraftBaselineCheckView:
    """Итог проверки актуальности и идентификатор из команды; токена, хешей и источников нет."""

    outcome: str
    draft_id: str

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return view_dict(self)


DRAFT_EXISTS = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_exists",
    "Черновик уже открыт: поддерживается одна сессия, существующий черновик не перезаписывается.",
    conflicts=(Conflict(ConflictSubject.DRAFT, ConflictState.ABSENT, ConflictState.PRESENT),),
)
"""Отказ создания: черновик уже есть; его нужно открыть или отменить."""
DRAFT_MISMATCH = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_mismatch",
    "Открыт другой черновик: отмена отклонена, черновик не удалён.",
    conflicts=(Conflict(ConflictSubject.DRAFT, ConflictState.PRESENT, ConflictState.CHANGED),),
)
"""Отказ отмены: идентификатор команды не совпал с идентификатором существующего черновика."""
INVALID_STORE_RESULT = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_store_result",
    "Хранилище черновика вернуло некорректный ответ: перечитайте его состояние.",
)
"""Отказ: ответ хранилища не по контракту порта, в том числе ревизия, не совпавшая с записанными байтами."""
_STORE_FAILED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_store_failed",
    "Хранилище черновика отказало непредвиденно: перечитайте его состояние.",
)
_STORE_FAILURES = {
    DraftStoreFailure.UNAVAILABLE: (ErrorCategory.SOURCE_FAILED, "Хранилище черновика недоступно."),
    DraftStoreFailure.UNSAFE: (
        ErrorCategory.SOURCE_FAILED,
        "Хранилище черновика небезопасно: ссылка, неверные права, владелец, тип или подмена.",
    ),
    DraftStoreFailure.BUSY: (ErrorCategory.SOURCE_FAILED, "Черновик изменяет другая операция: повторите позже."),
    DraftStoreFailure.CONFLICT: (
        ErrorCategory.SOURCE_FAILED, "Черновик изменился после чтения: операция отклонена, перечитайте его.",
    ),
    DraftStoreFailure.INVALID: (
        ErrorCategory.INVALID_SOURCE_DATA,
        "Файл черновика повреждён или имеет неподдерживаемую версию схемы: он не перезаписывается и не удаляется.",
    ),
    DraftStoreFailure.WRITE_FAILED: (
        ErrorCategory.SOURCE_FAILED, "Не удалось изменить черновик: прежнее состояние файла сохранено.",
    ),
    DraftStoreFailure.WRITE_UNCONFIRMED: (
        ErrorCategory.SOURCE_FAILED, "Черновик изменён, но сохранность на диске не подтверждена: перечитайте его.",
    ),
}
_CONFLICT_CATEGORY, _CONFLICT_MESSAGE = _STORE_FAILURES[DraftStoreFailure.CONFLICT]
DRAFT_CHANGED = ErrorDetail(
    _CONFLICT_CATEGORY, DraftStoreFailure.CONFLICT.value, _CONFLICT_MESSAGE,
    conflicts=(Conflict(ConflictSubject.DRAFT, ConflictState.PRESENT, ConflictState.CHANGED),),
)
"""Отказ изменения: токен ревизии команды не совпал с текущим — черновик изменился после чтения интерфейсом."""
DRAFT_GONE = ErrorDetail(
    _CONFLICT_CATEGORY, DraftStoreFailure.CONFLICT.value, _CONFLICT_MESSAGE,
    conflicts=(Conflict(ConflictSubject.DRAFT, ConflictState.PRESENT, ConflictState.ABSENT),),
)
"""Отказ проверки: черновика, который ожидала команда, нет — он отменён или ещё не создан."""
_STORE_REASONS = {reason.value: reason.value for reason in StoreReason}
_DOMAIN_REASONS = {code.value: code.value for code in DraftSessionErrorCode}


def _reason(failure: DraftStoreFailure, value: object) -> str | None:
    """Передать причину только из известного набора; иначе строка хранилища не выводится."""
    if type(value) is str:
        return (_DOMAIN_REASONS if failure is DraftStoreFailure.INVALID else _STORE_REASONS).get(value)
    reasons = DraftSessionErrorCode if failure is DraftStoreFailure.INVALID else StoreReason
    return next((known.value for known in reasons if value is known), None)


def store_error_detail(error: Exception, expected: ConflictState | None = None) -> ErrorDetail:
    """Перевести отказ хранилища черновика в ErrorDetail без текста и цепочки исключения.

    Только точный тип `DraftSessionStoreError` с известным видом отказа
    сохраняет свой код; подкласс и любое другое исключение — непредвиденный
    отказ, а не конфликт или подмена. `expected` — состояние черновика,
    которое сценарий передал хранилищу при изменении (`present` — прочитанная
    ревизия, `absent` — черновика быть не должно): конфликт ревизии получает
    по нему запись конфликта. У чтения ожидаемого состояния нет.
    """
    if type(error) is not DraftSessionStoreError:
        return _STORE_FAILED
    failure = getattr(error, "failure", None)
    if not any(failure is known for known in DraftStoreFailure):
        return _STORE_FAILED
    category, message = _STORE_FAILURES[failure]
    conflicts = ()
    if failure is DraftStoreFailure.CONFLICT and expected is not None:
        conflicts = (revision_conflict(ConflictSubject.DRAFT, expected),)
    return ErrorDetail(
        category, failure.value, message, reason=_reason(failure, getattr(error, "reason", None)), conflicts=conflicts,
    )


def check_expected_draft(stored: StoredDraftSession, draft_id: str, expected_revision: str) -> ErrorDetail | None:
    """Сверить прочитанный черновик с идентификатором и токеном ревизии из команды.

    Другой идентификатор — `draft_mismatch`, другой токен — `draft_revision_conflict`;
    оба отказа несут запись конфликта черновика. Формат полей команды
    проверяет `valid_expected_draft` до чтения хранилища; изменение после
    этого чтения сверяет само хранилище по прочитанной ревизии.
    """
    if stored.session.draft_id != draft_id:
        return DRAFT_MISMATCH
    if draft_revision_token(stored.revision) != expected_revision:
        return DRAFT_CHANGED
    return None


def read_stored_draft(store: DraftSessionStore) -> StoredDraftSession | None | ErrorDetail:
    """Прочитать черновик один раз и повторно проверить ответ хранилища.

    `None` — черновика нет; отказ хранилища и ответ не по контракту
    возвращаются как `ErrorDetail` без текста и цепочки исключения.
    """
    try:
        stored = store.read_draft()
    except Exception as error:
        # Текст и цепочка исключения хранилища могут содержать пути.
        return store_error_detail(error)
    if stored is None:
        return None
    if type(stored) is not StoredDraftSession:
        return INVALID_STORE_RESULT
    try:
        validate_draft_session(stored.session)
        valid = valid_metadata_revision(stored.revision)
    except Exception:
        # Повреждённый после создания ответ: подменённые поля, неверные типы.
        valid = False
    return stored if valid else INVALID_STORE_RESULT


def read_expected_draft(store: DraftSessionStore, draft_id: str, expected_revision: str) -> StoredDraftSession | ErrorDetail:
    """Прочитать сессию и сверить её с уже проверенными полями команды."""
    stored = read_stored_draft(store)
    if isinstance(stored, ErrorDetail):
        return stored
    if stored is None:
        return DRAFT_GONE
    error = check_expected_draft(stored, draft_id, expected_revision)
    return stored if error is None else error


def check_draft_current(
    store: DraftSessionStore, fingerprints: SourceFingerprintSource, draft_id: object, expected_revision: object,
) -> StoredDraftSession | ErrorDetail:
    """Проверить, что черновик из команды не устарел: общий помощник проверки и будущего применения.

    Порядок: формат идентификатора и токена до чтения хранилища, чтение
    черновика, сверка с командой (`check_expected_draft`), повторное чтение
    всех управляемых источников и сравнение с исходными отпечатками
    (`compare_baseline`), затем повторное чтение черновика. Черновик,
    изменившийся или исчезнувший за время проверки, — конфликт черновика,
    он важнее расхождений источников. Успех — черновик первого чтения:
    ревизию для записи вызывающий берёт из него, а не из команды. Ни
    хранилище, ни источники не изменяются.

    Проверка — снимок на момент чтения: она не блокирует источники
    и не обнаруживает изменение, сделанное после её завершения.
    """
    if not valid_expected_draft(draft_id, expected_revision):
        # Идентификатор и токен берутся из представления черновика, а не вводятся пользователем.
        return invalid_command()
    stored = read_expected_draft(store, draft_id, expected_revision)
    if isinstance(stored, ErrorDetail):
        return stored
    error = compare_baseline(fingerprints, stored.session.baseline)
    again = read_stored_draft(store)
    if isinstance(again, ErrorDetail):
        return again
    if again is None:
        return DRAFT_GONE
    if again.revision != stored.revision:
        return DRAFT_CHANGED
    return stored if error is None else error


class InspectDraftHandler:
    """Прочитать черновик один раз и вернуть безопасное представление.

    Хранилище только читается: файл и каталог не создаются. Отсутствие
    черновика — успешный результат с `present=False`; отказ хранилища
    возвращается его кодом без частичного результата.
    """

    def __init__(self, store: DraftSessionStore, *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._store = store
        self._operation_ids = operation_ids

    def execute(self, command: InspectDraft) -> Result[DraftStatusView]:
        """Выполнить просмотр; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = InspectDraft.name
        if type(command) is not InspectDraft:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        stored = read_stored_draft(self._store)
        if isinstance(stored, ErrorDetail):
            return failed(operation_id, name, stored)
        if stored is None:
            return succeeded(operation_id, name, DraftStatusView(False, None))
        view = DraftView.from_session(stored.session, stored.revision)
        return succeeded(operation_id, name, DraftStatusView(True, view))


class CreateDraftHandler:
    """Создать сессию черновика с новым идентификатором, временем создания UTC и исходными отпечатками.

    Порядок: одно чтение хранилища, затем по одному чтению отпечатка каждого
    управляемого источника и не больше одной записи. Существующий черновик —
    отказ `draft_exists` без чтения источников и без записи; повреждённый файл
    — отказ хранилища без перезаписи. Недоступный источник или некорректный
    отпечаток — отказ без записи: черновик без полного исходного состояния не
    создаётся. Отсутствие черновика в последний момент перед записью сверяет
    хранилище: появившийся после чтения черновик — конфликт ревизии. Отказ
    записи, включая неподтверждённую, не превращается в успех. `draft_ids`
    и `clock` подменяются в тестах; время берётся с точностью до секунды.
    """

    def __init__(
        self, store: DraftSessionStore, fingerprints: SourceFingerprintSource, *,
        operation_ids: OperationIdFactory = new_operation_id, draft_ids: DraftIdFactory = new_draft_id,
        clock: Clock = utc_now,
    ) -> None:
        self._store = store
        self._fingerprints = fingerprints
        self._operation_ids = operation_ids
        self._draft_ids = draft_ids
        self._clock = clock

    def execute(self, command: CreateDraft) -> Result[DraftView]:
        """Выполнить создание; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = CreateDraft.name
        if type(command) is not CreateDraft:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        stored = read_stored_draft(self._store)
        if isinstance(stored, ErrorDetail):
            return failed(operation_id, name, stored)
        if stored is not None:
            return failed(operation_id, name, DRAFT_EXISTS)
        baseline = capture_baseline(self._fingerprints)
        if isinstance(baseline, ErrorDetail):
            return failed(operation_id, name, baseline)

        created_at = self._clock().astimezone(timezone.utc).replace(microsecond=0)
        session = DraftSession(self._draft_ids(), created_at, baseline=baseline)
        content = encode_draft_session(session)
        try:
            revision = self._store.create_draft(session)
        except Exception as error:
            return failed(operation_id, name, store_error_detail(error, ConflictState.ABSENT))
        if type(revision) is not str or revision != draft_revision(content):
            return failed(operation_id, name, INVALID_STORE_RESULT)
        return succeeded(operation_id, name, DraftView.from_session(session, revision))


class DiscardDraftHandler:
    """Отменить черновик: удалить файл сессии с идентификатором и токеном ревизии из команды, ничего не применяя.

    Порядок: проверка формата полей команды, одно чтение хранилища и не
    больше одного изменения — удаления по прочитанной ревизии или
    подтверждения отсутствия. Черновика нет — хранилище закрепляет его
    отсутствие на диске, затем успех `already_absent`: так повтор после
    `draft_write_unconfirmed` не сообщает успех без подтверждения. Другой
    идентификатор — отказ `draft_mismatch`, другой токен ревизии — конфликт
    `draft_revision_conflict`, оба без удаления; повреждённый файл — отказ
    хранилища, файл не удаляется. Изменение черновика после чтения сверяет
    хранилище: удаление отклоняется конфликтом ревизии.
    """

    def __init__(self, store: DraftSessionStore, *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._store = store
        self._operation_ids = operation_ids

    def execute(self, command: DiscardDraft) -> Result[DraftDiscardView]:
        """Выполнить отмену; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = DiscardDraft.name
        if type(command) is not DiscardDraft:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        if not valid_expected_draft(command.draft_id, command.expected_revision):
            # Идентификатор и токен берутся из представления черновика, а не вводятся пользователем.
            return failed(operation_id, name, invalid_command())
        stored = read_stored_draft(self._store)
        if isinstance(stored, ErrorDetail):
            return failed(operation_id, name, stored)
        if stored is None:
            error = _change_store(self._store.confirm_draft_absent, ConflictState.ABSENT)
            outcome = DraftDiscardOutcome.ALREADY_ABSENT
        else:
            error = check_expected_draft(stored, command.draft_id, command.expected_revision)
            if error is not None:
                return failed(operation_id, name, error)
            error = _change_store(lambda: self._store.remove_draft(stored.revision), ConflictState.PRESENT)
            outcome = DraftDiscardOutcome.DISCARDED
        if error is not None:
            return failed(operation_id, name, error)
        return succeeded(operation_id, name, DraftDiscardView(outcome.value, command.draft_id))


class CheckDraftBaselineHandler:
    """Проверить актуальность черновика из команды перед подтверждением, ничего не записывая.

    Выполняет `check_draft_current`: два чтения хранилища и по одному чтению
    отпечатка каждого управляемого источника. Устаревший черновик —
    `draft_baseline_changed` с записями конфликта и шагом `recreate_draft`;
    источник, который не удалось прочитать, — отказ чтения с записями
    конфликта, а не совпадение. Черновик, файлы и настройки не меняются.
    """

    def __init__(
        self, store: DraftSessionStore, fingerprints: SourceFingerprintSource, *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._store = store
        self._fingerprints = fingerprints
        self._operation_ids = operation_ids

    def execute(self, command: CheckDraftBaseline) -> Result[DraftBaselineCheckView]:
        """Выполнить проверку; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = CheckDraftBaseline.name
        if type(command) is not CheckDraftBaseline:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        checked = check_draft_current(self._store, self._fingerprints, command.draft_id, command.expected_revision)
        if isinstance(checked, ErrorDetail):
            return failed(operation_id, name, checked)
        return succeeded(
            operation_id, name, DraftBaselineCheckView(DraftBaselineOutcome.CURRENT.value, command.draft_id),
        )


def _change_store(change: Callable[[], object], expected: ConflictState) -> ErrorDetail | None:
    """Выполнить изменение хранилища, которое по контракту возвращает None; `expected` — для записи конфликта."""
    try:
        outcome = change()
    except Exception as error:
        return store_error_detail(error, expected)
    return None if outcome is None else INVALID_STORE_RESULT
