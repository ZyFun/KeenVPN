"""Первичный импорт обнаруженного размещения хранилищ и просмотр метаданных менеджера.

Импорт читает обнаруженное размещение собственных данных, истории и копий
и лимиты истории через порт источника и сохраняет их в собственных
метаданных менеджера как есть: значения по умолчанию не выбираются, лимиты
не увеличиваются, неизвестное не заменяется отсутствующим. Если размещение
уже записано, импорт его не меняет: совпадение не вызывает записи,
расхождение — отказ без перезаписи; смена размещения — отдельный перенос.
Active configs Xray и XKeen, Keenetic и процессы не затрагиваются.

Просмотр только читает метаданные. Оба сценария возвращают безопасное
представление без путей, идентификаторов хранилищ, ревизии и значений
неизвестных полей.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import (
    ManagerMetadataStore, ManagerMetadataStoreError, MetadataStoreFailure, MetadataStoreReason,
    StoragePlacementSource,
)
from keenvpn.application.views import view_dict, view_fields
from keenvpn.domain.manager_metadata import (
    ManagerMetadata, ManagerMetadataError, ManagerMetadataErrorCode, StoragePlacement, StoredManagerMetadata,
    UnknownFields, encode_manager_metadata, metadata_revision, valid_metadata_revision, validate_manager_metadata,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectManagerMetadata:
    """Прочитать метаданные менеджера без записи."""

    name: ClassVar[str] = "inspect_manager_metadata"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True, kw_only=True)
class ImportStoragePlacement:
    """Сохранить обнаруженное размещение хранилищ и лимиты истории при первичном импорте."""

    name: ClassVar[str] = "import_storage_placement"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class StorageRoleView:
    """Роль хранения: состояния роли, идентификатора и пути и признак проверки без значений.

    У роли `unknown` и `absent` состояния идентификатора и пути и `verified` — `None`.
    """

    role: str
    state: str
    storage_id_state: str | None
    path_state: str | None
    verified: bool | None


@dataclass(frozen=True, slots=True)
class HistoryLimitsView:
    """Состояния и значения размера истории в байтах и срока хранения в секундах."""

    size_state: str
    size_bytes: int | None
    retention_state: str
    retention_seconds: int | None


@dataclass(frozen=True, slots=True)
class StoragePlacementView:
    """Вариант хранения, роли, число различных известных хранилищ и лимиты истории."""

    variant_state: str
    variant: str | None
    roles: tuple[StorageRoleView, ...]
    distinct_storage_count: int
    history_limits: HistoryLimitsView


@dataclass(frozen=True, slots=True)
class ManagerMetadataView:
    """Безопасное представление метаданных менеджера.

    `storage` — `None`, если раздел размещения не записан. Пути, UUID,
    ревизия, имена и значения неизвестных полей сюда не входят.
    """

    schema_version: int
    storage: StoragePlacementView | None
    unknown_field_count: int

    @classmethod
    def from_metadata(cls, metadata: ManagerMetadata) -> "ManagerMetadataView":
        """Построить представление из безопасной диагностики домена."""
        diagnostic = metadata.to_diagnostic()
        storage = diagnostic["storage"]
        return cls(
            schema_version=diagnostic["schema_version"],
            storage=None if storage is None else StoragePlacementView(
                variant_state=storage["variant_state"],
                variant=storage["variant"],
                roles=tuple(StorageRoleView(**view_fields(StorageRoleView, item)) for item in storage["roles"]),
                distinct_storage_count=storage["distinct_storage_count"],
                history_limits=HistoryLimitsView(**view_fields(HistoryLimitsView, storage["history_limits"])),
            ),
            unknown_field_count=diagnostic["unknown_field_count"],
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        storage = None
        if self.storage is not None:
            storage = {
                **view_dict(self.storage),
                "roles": [view_dict(role) for role in self.storage.roles],
                "history_limits": view_dict(self.storage.history_limits),
            }
        return {**view_dict(self), "storage": storage}


@dataclass(frozen=True, slots=True)
class ManagerMetadataStatusView:
    """Наличие метаданных менеджера и их безопасное представление.

    `present=False` — метаданных ещё нет; это состояние, а не отказ.
    """

    present: bool
    metadata: ManagerMetadataView | None

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {"present": self.present, "metadata": None if self.metadata is None else self.metadata.to_dict()}


class StoragePlacementImportOutcome(StrEnum):
    """Итог успешного первичного импорта размещения."""

    CREATED = "created"
    """Размещение записано: файл создан или раздел `storage` дописан к существующему."""
    UNCHANGED = "unchanged"
    """Видимый файл уже содержит это размещение; операция ничего не записывала и не выполняла fsync."""


@dataclass(frozen=True, slots=True)
class StoragePlacementImportView:
    """Итог импорта и метаданные после операции в безопасной форме."""

    outcome: str
    metadata: ManagerMetadataView

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {"outcome": self.outcome, "metadata": self.metadata.to_dict()}


_PLACEMENT_UNAVAILABLE = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "storage_placement_unavailable",
    "Не удалось прочитать обнаруженное размещение хранилищ.",
)
_INVALID_PLACEMENT = "invalid_storage_placement"
_INVALID_PLACEMENT_TYPE = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, _INVALID_PLACEMENT,
    "Источник вернул размещение хранилищ в неподдерживаемом формате.",
)
_INVALID_PLACEMENT_MESSAGE = "Источник вернул некорректное размещение хранилищ."
_PLACEMENT_MISMATCH = ErrorDetail(
    ErrorCategory.UNSUPPORTED, "storage_placement_mismatch",
    "Обнаруженное размещение отличается от сохранённого: импорт его не меняет, смена размещения — отдельный перенос.",
)
_INCONSISTENT = "manager_metadata_inconsistent"
_INCONSISTENT_MESSAGE = "Обнаруженное размещение не удалось объединить с сохранёнными метаданными менеджера."
_INVALID_STORE_RESULT = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "invalid_metadata_store_result",
    "Хранилище метаданных менеджера вернуло некорректный ответ: перечитайте их состояние.",
)
_STORE_FAILED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "metadata_store_failed",
    "Хранилище метаданных менеджера отказало непредвиденно: перечитайте их состояние.",
)
_STORE_FAILURES = {
    MetadataStoreFailure.UNAVAILABLE: (ErrorCategory.SOURCE_FAILED, "Хранилище метаданных менеджера недоступно."),
    MetadataStoreFailure.UNSAFE: (
        ErrorCategory.SOURCE_FAILED,
        "Хранилище метаданных менеджера небезопасно: ссылка, неверные права, владелец, тип или подмена.",
    ),
    MetadataStoreFailure.BUSY: (
        ErrorCategory.SOURCE_FAILED, "Метаданные менеджера записывает другая операция: повторите позже.",
    ),
    MetadataStoreFailure.CONFLICT: (
        ErrorCategory.SOURCE_FAILED, "Метаданные менеджера изменились после чтения: запись отклонена, перечитайте их.",
    ),
    MetadataStoreFailure.INVALID: (
        ErrorCategory.INVALID_SOURCE_DATA,
        "Файл метаданных менеджера повреждён или имеет неподдерживаемую версию схемы: он не перезаписывается.",
    ),
    MetadataStoreFailure.WRITE_FAILED: (
        ErrorCategory.SOURCE_FAILED, "Не удалось записать метаданные менеджера: прежний файл сохранён.",
    ),
    MetadataStoreFailure.WRITE_UNCONFIRMED: (
        ErrorCategory.SOURCE_FAILED,
        "Метаданные менеджера записаны, но сохранность на диске не подтверждена: перечитайте их.",
    ),
}
_STORE_REASONS = {reason.value: reason.value for reason in MetadataStoreReason}
_DOMAIN_REASONS = {code.value: code.value for code in ManagerMetadataErrorCode}


def _reason(failure: MetadataStoreFailure, value: object) -> str | None:
    """Передать причину только из известного набора; иначе строка хранилища не выводится."""
    if type(value) in (MetadataStoreReason, ManagerMetadataErrorCode):
        value = value.value
    if type(value) is not str:
        return None
    return (_DOMAIN_REASONS if failure is MetadataStoreFailure.INVALID else _STORE_REASONS).get(value)


def _store_error(error: Exception) -> ErrorDetail:
    """Перевести отказ хранилища в ErrorDetail без текста и цепочки исключения.

    Только точный тип `ManagerMetadataStoreError` с известным видом отказа
    сохраняет свой код; подкласс и любое другое исключение — непредвиденный
    отказ, а не конфликт или подмена.
    """
    if type(error) is not ManagerMetadataStoreError:
        return _STORE_FAILED
    failure = getattr(error, "failure", None)
    if type(failure) is not MetadataStoreFailure:
        return _STORE_FAILED
    category, message = _STORE_FAILURES[failure]
    return ErrorDetail(category, failure.value, message, reason=_reason(failure, getattr(error, "reason", None)))


def _read_stored(store: ManagerMetadataStore) -> StoredManagerMetadata | None | ErrorDetail:
    """Прочитать метаданные один раз и повторно проверить ответ хранилища."""
    try:
        stored = store.read_metadata()
    except Exception as error:
        # Текст и цепочка исключения хранилища могут содержать пути.
        return _store_error(error)
    if stored is None:
        return None
    if type(stored) is not StoredManagerMetadata:
        return _INVALID_STORE_RESULT
    try:
        validate_manager_metadata(stored.metadata)
        valid = valid_metadata_revision(stored.revision)
    except Exception:
        # Повреждённый после создания ответ: подменённые поля, неверные типы.
        valid = False
    return stored if valid else _INVALID_STORE_RESULT


def _canonical(metadata: ManagerMetadata) -> bytes | None:
    """Канонические байты прочитанной модели; `None`, если она не кодируется в пределах формата."""
    try:
        return encode_manager_metadata(metadata)
    except ManagerMetadataError:
        return None


class InspectManagerMetadataHandler:
    """Прочитать метаданные менеджера один раз и вернуть безопасное представление.

    Хранилище только читается: файл и каталог не создаются. Отсутствие
    метаданных — успешный результат с `present=False`; отказ хранилища
    возвращается его кодом без частичного результата.
    """

    def __init__(self, store: ManagerMetadataStore, *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._store = store
        self._operation_ids = operation_ids

    def execute(self, command: InspectManagerMetadata) -> Result[ManagerMetadataStatusView]:
        """Выполнить просмотр; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = InspectManagerMetadata.name
        if type(command) is not InspectManagerMetadata:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        stored = _read_stored(self._store)
        if isinstance(stored, ErrorDetail):
            return failed(operation_id, name, stored)
        if stored is None:
            return succeeded(operation_id, name, ManagerMetadataStatusView(False, None))
        view = ManagerMetadataView.from_metadata(stored.metadata)
        return succeeded(operation_id, name, ManagerMetadataStatusView(True, view))


class ImportStoragePlacementHandler:
    """Сохранить обнаруженное размещение и лимиты истории в метаданных менеджера как есть.

    Порядок: источник размещения, одно чтение хранилища, сравнение и не больше
    одной записи. Совпадение с записанным размещением определяется по
    каноническим байтам раздела `storage`, включая его неизвестные поля:
    при совпадении запись не вызывается, при расхождении — отказ без
    перезаписи. Кандидат на запись — обнаруженное размещение вместе
    с неизвестными полями верхнего уровня прочитанного файла. Ревизию
    в последний момент перед записью сверяет хранилище. Отказ записи,
    включая неподтверждённую, не превращается в успех.
    """

    def __init__(
        self, source: StoragePlacementSource, store: ManagerMetadataStore, *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._source = source
        self._store = store
        self._operation_ids = operation_ids

    def execute(self, command: ImportStoragePlacement) -> Result[StoragePlacementImportView]:
        """Выполнить импорт; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = ImportStoragePlacement.name
        if type(command) is not ImportStoragePlacement:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)

        placement = self._detect()
        if isinstance(placement, ErrorDetail):
            return failed(operation_id, name, placement)
        stored = _read_stored(self._store)
        if isinstance(stored, ErrorDetail):
            return failed(operation_id, name, stored)

        if stored is not None and stored.metadata.storage is not None:
            # Неизвестные поля верхнего уровня у кандидата и файла одинаковы и в сравнение не входят:
            # иначе посторонний раздел, выросший при каноническом кодировании, блокировал бы импорт.
            detected = _canonical(ManagerMetadata(storage=placement))
            if detected is None or detected != _canonical(ManagerMetadata(storage=stored.metadata.storage)):
                return failed(operation_id, name, _PLACEMENT_MISMATCH)
            view = StoragePlacementImportView(
                StoragePlacementImportOutcome.UNCHANGED.value, ManagerMetadataView.from_metadata(stored.metadata),
            )
            return succeeded(operation_id, name, view)

        reason = None
        try:
            candidate = ManagerMetadata(
                storage=placement, extra=UnknownFields() if stored is None else stored.metadata.extra,
            )
            content = encode_manager_metadata(candidate)
        except ManagerMetadataError as error:
            # Например, вместе с прежними неизвестными полями файл превысил бы предел размера.
            reason = error.code.value
        if reason is not None:
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, _INCONSISTENT, _INCONSISTENT_MESSAGE, reason=reason,
            ))

        try:
            revision = self._store.write_metadata(candidate, None if stored is None else stored.revision)
        except Exception as error:
            return failed(operation_id, name, _store_error(error))
        if type(revision) is not str or revision != metadata_revision(content):
            return failed(operation_id, name, _INVALID_STORE_RESULT)
        view = StoragePlacementImportView(
            StoragePlacementImportOutcome.CREATED.value, ManagerMetadataView.from_metadata(candidate),
        )
        return succeeded(operation_id, name, view)

    def _detect(self) -> StoragePlacement | ErrorDetail:
        """Прочитать источник один раз и проверить размещение вместе с вложенными объектами."""
        try:
            placement = self._source.current_storage_placement()
        except Exception:
            # Текст и цепочка исключения источника могут содержать пути и вывод команд.
            return _PLACEMENT_UNAVAILABLE
        if type(placement) is not StoragePlacement:
            return _INVALID_PLACEMENT_TYPE
        reason = None
        try:
            metadata = ManagerMetadata(storage=placement)
            validate_manager_metadata(metadata)
            if metadata.to_diagnostic()["unknown_field_count"]:
                # Источник сообщает только понятое: чужой JSON не попадает в файл менеджера.
                reason = ManagerMetadataErrorCode.UNKNOWN_FIELDS.value
        except ManagerMetadataError as error:
            reason = error.code.value
        except Exception:
            reason = ManagerMetadataErrorCode.METADATA.value
        if reason is not None:
            return ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, _INVALID_PLACEMENT, _INVALID_PLACEMENT_MESSAGE, reason=reason,
            )
        return placement
