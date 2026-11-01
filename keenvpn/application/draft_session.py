"""Создание, просмотр и отмена одной сессии черновика изменений.

Сценарии работают только с собственным хранилищем черновика через порт
`DraftSessionStore`: черновик ничего не применяет, конфигурация Xray
и XKeen, настройки Keenetic и службы не читаются и не меняются. Сессия
одна: создание при существующем черновике — отказ без перезаписи. Отмена
удаляет только файл сессии с идентификатором из команды и ревизией из
чтения. Результаты содержат идентификатор, время создания и число
неизвестных полей, без путей, ревизии и значений неизвестных полей.
Ревизии и конфликты для будущих интерфейсов, исходные хеши, блокировка
устаревшего черновика и применение — не этого модуля.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import ClassVar
import uuid

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result, check_contract_version, failed,
    invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import DraftSessionStore, DraftSessionStoreError, DraftStoreFailure, StoreReason
from keenvpn.application.views import view_dict, view_fields
from keenvpn.domain.draft_session import (
    DraftSession, DraftSessionErrorCode, StoredDraftSession, draft_revision, encode_draft_session, valid_draft_id,
    validate_draft_session,
)
from keenvpn.domain.manager_metadata import valid_metadata_revision


DraftIdFactory = Callable[[], str]
Clock = Callable[[], datetime]


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
    """Отменить черновик с этим идентификатором: удалить файл сессии, ничего не применяя."""

    name: ClassVar[str] = "discard_draft"

    draft_id: str
    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class DraftView:
    """Безопасное представление сессии: идентификатор, время создания UTC и число неизвестных полей.

    Путь, ревизия, имена и значения неизвестных полей сюда не входят.
    """

    draft_id: str
    created_at: str
    unknown_field_count: int

    @classmethod
    def from_session(cls, session: DraftSession) -> "DraftView":
        """Построить представление из безопасной диагностики домена."""
        return cls(**view_fields(cls, session.to_diagnostic()))

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return view_dict(self)


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


DRAFT_EXISTS = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_exists",
    "Черновик уже открыт: поддерживается одна сессия, существующий черновик не перезаписывается.",
)
"""Отказ создания: черновик уже есть; его нужно открыть или отменить."""
DRAFT_MISMATCH = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "draft_mismatch",
    "Открыт другой черновик: отмена отклонена, черновик не удалён.",
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
_STORE_REASONS = {reason.value: reason.value for reason in StoreReason}
_DOMAIN_REASONS = {code.value: code.value for code in DraftSessionErrorCode}


def _reason(failure: DraftStoreFailure, value: object) -> str | None:
    """Передать причину только из известного набора; иначе строка хранилища не выводится."""
    if type(value) in (StoreReason, DraftSessionErrorCode):
        value = value.value
    if type(value) is not str:
        return None
    return (_DOMAIN_REASONS if failure is DraftStoreFailure.INVALID else _STORE_REASONS).get(value)


def store_error_detail(error: Exception) -> ErrorDetail:
    """Перевести отказ хранилища черновика в ErrorDetail без текста и цепочки исключения.

    Только точный тип `DraftSessionStoreError` с известным видом отказа
    сохраняет свой код; подкласс и любое другое исключение — непредвиденный
    отказ, а не конфликт или подмена.
    """
    if type(error) is not DraftSessionStoreError:
        return _STORE_FAILED
    failure = getattr(error, "failure", None)
    if type(failure) is not DraftStoreFailure:
        return _STORE_FAILED
    category, message = _STORE_FAILURES[failure]
    return ErrorDetail(category, failure.value, message, reason=_reason(failure, getattr(error, "reason", None)))


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
        return succeeded(operation_id, name, DraftStatusView(True, DraftView.from_session(stored.session)))


class CreateDraftHandler:
    """Создать сессию черновика с новым идентификатором и временем создания UTC.

    Порядок: одно чтение хранилища и не больше одной записи. Существующий
    черновик — отказ `draft_exists` без записи; повреждённый файл — отказ
    хранилища без перезаписи. Отсутствие черновика в последний момент перед
    записью сверяет хранилище: появившийся после чтения черновик — конфликт
    ревизии. Отказ записи, включая неподтверждённую, не превращается в успех.
    `draft_ids` и `clock` подменяются в тестах; время берётся с точностью до секунды.
    """

    def __init__(
        self, store: DraftSessionStore, *, operation_ids: OperationIdFactory = new_operation_id,
        draft_ids: DraftIdFactory = new_draft_id, clock: Clock = utc_now,
    ) -> None:
        self._store = store
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

        created_at = self._clock().astimezone(timezone.utc).replace(microsecond=0)
        session = DraftSession(self._draft_ids(), created_at)
        content = encode_draft_session(session)
        try:
            revision = self._store.create_draft(session)
        except Exception as error:
            return failed(operation_id, name, store_error_detail(error))
        if type(revision) is not str or revision != draft_revision(content):
            return failed(operation_id, name, INVALID_STORE_RESULT)
        return succeeded(operation_id, name, DraftView.from_session(session))


class DiscardDraftHandler:
    """Отменить черновик: удалить файл сессии с идентификатором из команды, ничего не применяя.

    Порядок: одно чтение хранилища и не больше одного изменения — удаления
    по прочитанной ревизии или подтверждения отсутствия. Черновика нет —
    хранилище закрепляет его отсутствие на диске, затем успех `already_absent`:
    так повтор после `draft_write_unconfirmed` не сообщает успех без
    подтверждения. Другой идентификатор — отказ `draft_mismatch` без удаления;
    повреждённый файл — отказ хранилища, файл не удаляется. Изменение черновика
    после чтения сверяет хранилище: удаление отклоняется конфликтом ревизии.
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
        if not valid_draft_id(command.draft_id):
            # Идентификатор берётся из представления черновика, а не вводится пользователем.
            return failed(operation_id, name, invalid_command())
        stored = read_stored_draft(self._store)
        if isinstance(stored, ErrorDetail):
            return failed(operation_id, name, stored)
        if stored is None:
            error = _change_store(self._store.confirm_draft_absent)
            outcome = DraftDiscardOutcome.ALREADY_ABSENT
        elif stored.session.draft_id != command.draft_id:
            return failed(operation_id, name, DRAFT_MISMATCH)
        else:
            error = _change_store(lambda: self._store.remove_draft(stored.revision))
            outcome = DraftDiscardOutcome.DISCARDED
        if error is not None:
            return failed(operation_id, name, error)
        return succeeded(operation_id, name, DraftDiscardView(outcome.value, command.draft_id))


def _change_store(change: Callable[[], object]) -> ErrorDetail | None:
    """Выполнить изменение хранилища, которое по контракту возвращает None."""
    try:
        outcome = change()
    except Exception as error:
        return store_error_detail(error)
    return None if outcome is None else INVALID_STORE_RESULT
