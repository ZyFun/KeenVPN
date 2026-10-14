"""Собственные версионированные метаданные менеджера: модель, строгий формат и ревизия.

Метаданные описывают только собственные данные менеджера и хранятся
отдельно от active configs Xray и XKeen. Модуль ничего не читает с диска
и не записывает: он разбирает и собирает байты файла, ревизия — SHA-256
этих байтов. Разбор строгий: UTF-8, без комментариев, дублей ключей, NaN
и Infinity, с ограничением размера и глубины. Неподдерживаемая версия
схемы не угадывается и не мигрирует. Неизвестные поля верхнего уровня
и известных объектов сохраняются и записываются обратно после известных.
Значение с тремя состояниями отличает неизвестное от отсутствующего.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import posixpath
import re
from typing import NoReturn

from keenvpn.domain.config_document import ConfigDocumentError, parse_strict_json_object, valid_json_tree


METADATA_FORMAT = "keenvpn-manager-metadata"
"""Маркер формата: отличает файл метаданных от чужого JSON."""
METADATA_SCHEMA_VERSION = 1
"""Единственная поддерживаемая версия схемы."""
MAX_METADATA_SIZE = 1024 * 1024
"""Предел размера файла в байтах при чтении и записи."""
MAX_PATH_LENGTH = 4096
"""Предел длины пути, как `PATH_MAX` Linux."""
MAX_PATH_COMPONENT = 255
"""Предел длины одного компонента пути в байтах UTF-8, как `NAME_MAX` ext4."""
MAX_LIMIT_VALUE = 2**63 - 1
"""Техническая граница представления лимита: знаковое 64-битное целое, не политика хранения."""

_STORAGE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_REVISION = re.compile(r"[0-9a-f]{64}")


class ManagerMetadataErrorCode(StrEnum):
    """Причины отказа без значений, путей и фрагментов файла."""

    CONTENT = "invalid_metadata_content"
    JSON = "invalid_metadata_json"
    FORMAT = "invalid_metadata_format"
    SCHEMA_VERSION = "unsupported_metadata_schema_version"
    STATE = "invalid_value_state"
    VARIANT = "invalid_storage_variant"
    STORAGE_ID = "invalid_storage_id"
    PATH = "invalid_storage_path"
    VERIFIED = "invalid_storage_verification"
    LIMIT = "invalid_history_limit"
    UNKNOWN_FIELDS = "invalid_unknown_fields"
    REVISION = "invalid_metadata_revision"
    METADATA = "invalid_manager_metadata"


_MESSAGES = {
    ManagerMetadataErrorCode.CONTENT: "Файл метаданных менеджера должен быть текстом UTF-8 не больше допустимого размера.",
    ManagerMetadataErrorCode.JSON: (
        "Файл метаданных менеджера должен быть строгим JSON-объектом без комментариев, дублей ключей, NaN и Infinity."
    ),
    ManagerMetadataErrorCode.FORMAT: "Структура метаданных менеджера не соответствует формату.",
    ManagerMetadataErrorCode.SCHEMA_VERSION: "Версия схемы метаданных менеджера не поддерживается.",
    ManagerMetadataErrorCode.STATE: "Состояние значения метаданных должно быть known, unknown или absent.",
    ManagerMetadataErrorCode.VARIANT: "Вариант хранения должен быть simple или extended.",
    ManagerMetadataErrorCode.STORAGE_ID: "Идентификатор хранилища должен быть UUID в нижнем регистре.",
    ManagerMetadataErrorCode.PATH: "Путь хранилища должен быть абсолютным нормализованным путём без управляющих символов.",
    ManagerMetadataErrorCode.VERIFIED: "Признак проверки размещения задан неверно.",
    ManagerMetadataErrorCode.LIMIT: "Лимит истории должен быть положительным целым числом в допустимом диапазоне.",
    ManagerMetadataErrorCode.UNKNOWN_FIELDS: "Неизвестные поля метаданных должны быть значениями JSON с новыми именами.",
    ManagerMetadataErrorCode.REVISION: "Ревизия метаданных должна быть SHA-256 в нижнем регистре.",
    ManagerMetadataErrorCode.METADATA: "Модель метаданных менеджера повреждена или имеет неверный тип.",
}


class ManagerMetadataError(ValueError):
    """Отказ с машинным кодом и фиксированным текстом.

    `field` — путь к полю из имён известного формата через точку, например
    `storage.roles.data.path`, либо `None`. Значения и имена неизвестных
    полей в ошибку не попадают.
    """

    def __init__(self, code: ManagerMetadataErrorCode, field: str | None = None) -> None:
        self.code = code
        self.field = field
        super().__init__(_MESSAGES[code])


def _fail(code: ManagerMetadataErrorCode, field: str | None = None) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise ManagerMetadataError(code, field) from None
    except ManagerMetadataError as error:
        error.__context__ = None
        raise


def _join(prefix: str, name: str | None) -> str:
    if name is None:
        return prefix
    return f"{prefix}.{name}" if prefix else name


class ValueState(StrEnum):
    """Известно, неизвестно или отсутствует.

    `unknown` — значение есть, но его не удалось определить; `absent` —
    значения нет. Неизвестное не равно отсутствующему и не заменяется им.
    """

    KNOWN = "known"
    UNKNOWN = "unknown"
    ABSENT = "absent"


class StorageVariant(StrEnum):
    """Простой: каталоги раздела Entware; расширенный: выбранные подготовленные разделы."""

    SIMPLE = "simple"
    EXTENDED = "extended"


class StorageRole(StrEnum):
    """Роли хранения: постоянные данные, история и локальные копии."""

    DATA = "data"
    HISTORY = "history"
    BACKUPS = "backups"


def valid_storage_id(value: object) -> bool:
    """Проверить UUID файловой системы: 8-4-4-4-12 шестнадцатеричных цифр в нижнем регистре.

    Имя устройства, метка и порядок обнаружения идентификатором не являются.
    """
    return type(value) is str and _STORAGE_ID.fullmatch(value) is not None


def valid_storage_path(value: object) -> bool:
    """Проверить абсолютный нормализованный путь каталога.

    Без `.`/`..`, двойных и конечной `/`, управляющих символов и NUL,
    в пределах длины пути и компонента; корень `/` не допускается.
    Существование и отсутствие ссылок проверяет адаптер хранилища.
    """
    if (
        type(value) is not str or not 1 < len(value) <= MAX_PATH_LENGTH
        or not value.startswith("/") or value.startswith("//")
        or not value.isprintable() or posixpath.normpath(value) != value
    ):
        return False
    try:
        encoded = [part.encode("utf-8") for part in value[1:].split("/")]
    except UnicodeEncodeError:
        return False
    return all(0 < len(part) <= MAX_PATH_COMPONENT for part in encoded)


def _valid_limit(value: object) -> bool:
    return type(value) is int and 0 < value <= MAX_LIMIT_VALUE


@dataclass(frozen=True, slots=True, init=False, repr=False)
class UnknownFields:
    """Поля, неизвестные этой версии формата: имена и значения JSON в исходном порядке.

    Хранятся как канонический JSON-снимок, поэтому `true` и `1`, строка и
    число различаются при сравнении. Имена — любые строки, в том числе
    пустая и отличающиеся только регистром. Значения — данные
    пользователя: `repr` показывает только число полей.
    """

    _snapshot: str
    _names: tuple[str, ...]

    def __init__(self, fields: dict[str, object] | None = None) -> None:
        values = {} if fields is None else fields
        if type(values) is not dict or not valid_json_tree(values):
            _fail(ManagerMetadataErrorCode.UNKNOWN_FIELDS)
        snapshot = None
        try:
            snapshot = json.dumps(values, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        except (ValueError, TypeError, RecursionError):
            # Целое длиннее предела преобразования в текст и подобные значения.
            pass
        if snapshot is None:
            _fail(ManagerMetadataErrorCode.UNKNOWN_FIELDS)
        object.__setattr__(self, "_snapshot", snapshot)
        object.__setattr__(self, "_names", tuple(values))

    def __repr__(self) -> str:
        return f"UnknownFields(count={len(self._names)})"

    def __len__(self) -> int:
        return len(self._names)

    @property
    def names(self) -> tuple[str, ...]:
        """Имена полей в исходном порядке для доверенного кода, не для вывода."""
        return self._names

    def export(self) -> dict[str, object]:
        """Получить копию полей для доверенного кода, не для вывода."""
        return json.loads(self._snapshot)


def _no_fields() -> UnknownFields:
    return UnknownFields()


def _check_extra(extra: object, known: tuple[str, ...]) -> None:
    """Неизвестное поле не может носить имя известного поля того же объекта."""
    if type(extra) is not UnknownFields or any(name in known for name in extra.names):
        _fail(ManagerMetadataErrorCode.UNKNOWN_FIELDS)


_TRACKED_KEYS = ("state", "value")
_ROLE_KEYS = ("state", "storage_id", "path", "verified")
_LIMIT_KEYS = ("size_bytes", "retention_seconds")
_ROLES_KEYS = tuple(role.value for role in StorageRole)
_STORAGE_KEYS = ("variant", "roles", "history_limits")
_TOP_KEYS = ("format", "schema_version", "storage")
_STATES = frozenset(state.value for state in ValueState)
_VARIANTS = frozenset(variant.value for variant in StorageVariant)


@dataclass(frozen=True, slots=True, repr=False)
class TrackedValue[T]:
    """Значение с тремя состояниями; только известное содержит `value`.

    Тип и формат `value` проверяет объект-владелец. `repr` не показывает
    значение: пути и идентификаторы хранилищ — данные пользователя.
    """

    state: ValueState
    value: T | None = None
    extra: UnknownFields = field(default_factory=_no_fields)

    def __post_init__(self) -> None:
        if type(self.state) is not ValueState or (self.state is ValueState.KNOWN) == (self.value is None):
            _fail(ManagerMetadataErrorCode.STATE)
        _check_extra(self.extra, _TRACKED_KEYS)

    def __repr__(self) -> str:
        return f"TrackedValue(state={self.state.value})"

    @property
    def known(self) -> bool:
        """Показать, известно ли значение."""
        return self.state is ValueState.KNOWN


def _check_tracked(
    value: object, name: str, valid: Callable[[object], bool], code: ManagerMetadataErrorCode,
) -> None:
    if type(value) is not TrackedValue:
        _fail(ManagerMetadataErrorCode.FORMAT, name)
    if value.known and not valid(value.value):
        _fail(code, name)


@dataclass(frozen=True, slots=True)
class RoleLocation:
    """Размещение одной роли.

    Известная роль содержит идентификатор хранилища и путь, каждый со своим
    состоянием, и признак `verified`: путь проверен на выбранном хранилище.
    Проверка допустима только при известных идентификаторе и пути. Для
    неизвестной и отсутствующей роли эти поля пусты.
    """

    state: ValueState
    storage_id: TrackedValue[str] | None = None
    path: TrackedValue[str] | None = None
    verified: bool | None = None
    extra: UnknownFields = field(default_factory=_no_fields)

    def __post_init__(self) -> None:
        if type(self.state) is not ValueState:
            _fail(ManagerMetadataErrorCode.STATE, "state")
        _check_extra(self.extra, _ROLE_KEYS)
        if self.state is not ValueState.KNOWN:
            for name in ("storage_id", "path", "verified"):
                if getattr(self, name) is not None:
                    _fail(ManagerMetadataErrorCode.FORMAT, name)
            return
        _check_tracked(self.storage_id, "storage_id", valid_storage_id, ManagerMetadataErrorCode.STORAGE_ID)
        _check_tracked(self.path, "path", valid_storage_path, ManagerMetadataErrorCode.PATH)
        if type(self.verified) is not bool or (self.verified and not (self.storage_id.known and self.path.known)):
            _fail(ManagerMetadataErrorCode.VERIFIED, "verified")


@dataclass(frozen=True, slots=True)
class StorageRoles:
    """Размещение трёх ролей; роли могут находиться на одном или разных хранилищах."""

    data: RoleLocation
    history: RoleLocation
    backups: RoleLocation
    extra: UnknownFields = field(default_factory=_no_fields)

    def __post_init__(self) -> None:
        for role in StorageRole:
            if type(getattr(self, role.value)) is not RoleLocation:
                _fail(ManagerMetadataErrorCode.FORMAT, role.value)
        _check_extra(self.extra, _ROLES_KEYS)

    def items(self) -> tuple[tuple[StorageRole, RoleLocation], ...]:
        """Роли в фиксированном порядке: данные, история, копии."""
        return tuple((role, getattr(self, role.value)) for role in StorageRole)


@dataclass(frozen=True, slots=True)
class HistoryLimits:
    """Независимые размер истории в байтах и срок хранения в секундах."""

    size_bytes: TrackedValue[int]
    retention_seconds: TrackedValue[int]
    extra: UnknownFields = field(default_factory=_no_fields)

    def __post_init__(self) -> None:
        for name in _LIMIT_KEYS:
            _check_tracked(getattr(self, name), name, _valid_limit, ManagerMetadataErrorCode.LIMIT)
        _check_extra(self.extra, _LIMIT_KEYS)


def _valid_variant(value: object) -> bool:
    return type(value) is StorageVariant


@dataclass(frozen=True, slots=True)
class StoragePlacement:
    """Вариант хранения, размещение ролей и лимиты истории так, как они записаны."""

    variant: TrackedValue[StorageVariant]
    roles: StorageRoles
    history_limits: HistoryLimits
    extra: UnknownFields = field(default_factory=_no_fields)

    def __post_init__(self) -> None:
        _check_tracked(self.variant, "variant", _valid_variant, ManagerMetadataErrorCode.VARIANT)
        if type(self.roles) is not StorageRoles:
            _fail(ManagerMetadataErrorCode.FORMAT, "roles")
        if type(self.history_limits) is not HistoryLimits:
            _fail(ManagerMetadataErrorCode.FORMAT, "history_limits")
        _check_extra(self.extra, _STORAGE_KEYS)


@dataclass(frozen=True, slots=True)
class ManagerMetadata:
    """Метаданные менеджера текущей версии схемы.

    `storage` — `None`, если раздел размещения не записан. Будущие разделы
    добавляются как необязательные поля верхнего уровня; прежняя версия
    менеджера сохраняет их как неизвестные.
    """

    storage: StoragePlacement | None = None
    extra: UnknownFields = field(default_factory=_no_fields)

    def __post_init__(self) -> None:
        if self.storage is not None and type(self.storage) is not StoragePlacement:
            _fail(ManagerMetadataErrorCode.FORMAT, "storage")
        _check_extra(self.extra, _TOP_KEYS)

    def to_diagnostic(self) -> dict[str, object]:
        """Роли, вариант, состояния, проверка, лимиты и счётчики без путей и идентификаторов."""
        extras = len(self.extra)
        storage = None
        if self.storage is not None:
            placement = self.storage
            limits = placement.history_limits
            extras += len(placement.extra) + len(placement.variant.extra) + len(placement.roles.extra)
            extras += len(limits.extra) + len(limits.size_bytes.extra) + len(limits.retention_seconds.extra)
            roles = []
            storage_ids = set()
            for role, location in placement.roles.items():
                extras += len(location.extra)
                entry = {
                    "role": role.value, "state": location.state.value,
                    "storage_id_state": None, "path_state": None, "verified": location.verified,
                }
                if location.state is ValueState.KNOWN:
                    extras += len(location.storage_id.extra) + len(location.path.extra)
                    entry["storage_id_state"] = location.storage_id.state.value
                    entry["path_state"] = location.path.state.value
                    if location.storage_id.known:
                        storage_ids.add(location.storage_id.value)
                roles.append(entry)
            storage = {
                "variant_state": placement.variant.state.value,
                "variant": placement.variant.value.value if placement.variant.known else None,
                "roles": roles,
                "distinct_storage_count": len(storage_ids),
                "history_limits": {
                    "size_state": limits.size_bytes.state.value,
                    "size_bytes": limits.size_bytes.value,
                    "retention_state": limits.retention_seconds.state.value,
                    "retention_seconds": limits.retention_seconds.value,
                },
            }
        return {"schema_version": METADATA_SCHEMA_VERSION, "storage": storage, "unknown_field_count": extras}


@dataclass(frozen=True, slots=True)
class StoredManagerMetadata:
    """Метаданные, прочитанные из файла, и ревизия — SHA-256 его байтов."""

    metadata: ManagerMetadata
    revision: str

    def __post_init__(self) -> None:
        if type(self.metadata) is not ManagerMetadata:
            _fail(ManagerMetadataErrorCode.METADATA)
        if not valid_metadata_revision(self.revision):
            _fail(ManagerMetadataErrorCode.REVISION)


def valid_metadata_revision(value: object) -> bool:
    """Проверить формат ревизии: 64 шестнадцатеричные цифры в нижнем регистре."""
    return type(value) is str and _REVISION.fullmatch(value) is not None


def metadata_revision(content: bytes) -> str:
    """Ревизия байтов файла метаданных."""
    return hashlib.sha256(content).hexdigest()


def _build[M](prefix: str, factory: Callable[..., M], **values: object) -> M:
    """Собрать модель и дописать к пути поля ошибки префикс владельца."""
    code = name = None
    try:
        return factory(**values)
    except ManagerMetadataError as error:
        code, name = error.code, error.field
    _fail(code, _join(prefix, name))


def _object(value: object, name: str) -> dict[str, object]:
    if type(value) is not dict:
        _fail(ManagerMetadataErrorCode.FORMAT, name)
    return value


def _extra(document: dict[str, object], known: tuple[str, ...]) -> UnknownFields:
    return UnknownFields({key: value for key, value in document.items() if key not in known})


def _parse_tracked[T](value: object, name: str, convert: Callable[[object, str], T]) -> TrackedValue[T]:
    document = _object(value, name)
    state = document.get("state")
    if type(state) is not str or state not in _STATES:
        _fail(ManagerMetadataErrorCode.STATE, _join(name, "state"))
    known = state == ValueState.KNOWN.value
    if known != ("value" in document):
        _fail(ManagerMetadataErrorCode.FORMAT, _join(name, "value"))
    converted = convert(document["value"], _join(name, "value")) if known else None
    return _build(name, TrackedValue, state=ValueState(state), value=converted, extra=_extra(document, _TRACKED_KEYS))


def _as_is(value: object, name: str) -> object:
    # Формат значения проверяет владелец; null известного значения отклоняется как отсутствие value.
    if value is None:
        _fail(ManagerMetadataErrorCode.STATE, name)
    return value


def _as_variant(value: object, name: str) -> StorageVariant:
    if type(value) is not str or value not in _VARIANTS:
        _fail(ManagerMetadataErrorCode.VARIANT, name)
    return StorageVariant(value)


def _require(document: dict[str, object], key: str, name: str) -> object:
    if key not in document:
        _fail(ManagerMetadataErrorCode.FORMAT, _join(name, key))
    return document[key]


def _parse_role(value: object, name: str) -> RoleLocation:
    document = _object(value, name)
    state = document.get("state")
    if type(state) is not str or state not in _STATES:
        _fail(ManagerMetadataErrorCode.STATE, _join(name, "state"))
    values: dict[str, object] = {"state": ValueState(state), "extra": _extra(document, _ROLE_KEYS)}
    if state == ValueState.KNOWN.value:
        values["storage_id"] = _parse_tracked(_require(document, "storage_id", name), _join(name, "storage_id"), _as_is)
        values["path"] = _parse_tracked(_require(document, "path", name), _join(name, "path"), _as_is)
        values["verified"] = _require(document, "verified", name)
    else:
        for key in ("storage_id", "path", "verified"):
            if key in document:
                _fail(ManagerMetadataErrorCode.FORMAT, _join(name, key))
    return _build(name, RoleLocation, **values)


def _parse_storage(value: object) -> StoragePlacement:
    name = "storage"
    document = _object(value, name)
    roles_name = _join(name, "roles")
    roles = _object(_require(document, "roles", name), roles_name)
    limits_name = _join(name, "history_limits")
    limits = _object(_require(document, "history_limits", name), limits_name)
    parsed_roles = _build(roles_name, StorageRoles, **{
        key: _parse_role(_require(roles, key, roles_name), _join(roles_name, key)) for key in _ROLES_KEYS
    }, extra=_extra(roles, _ROLES_KEYS))
    parsed_limits = _build(limits_name, HistoryLimits, **{
        key: _parse_tracked(_require(limits, key, limits_name), _join(limits_name, key), _as_is) for key in _LIMIT_KEYS
    }, extra=_extra(limits, _LIMIT_KEYS))
    variant = _parse_tracked(_require(document, "variant", name), _join(name, "variant"), _as_variant)
    return _build(
        name, StoragePlacement, variant=variant, roles=parsed_roles, history_limits=parsed_limits,
        extra=_extra(document, _STORAGE_KEYS),
    )


def decode_manager_metadata(content: bytes) -> StoredManagerMetadata:
    """Разобрать байты файла в метаданные с ревизией.

    Сначала проверяются маркер формата и версия схемы: файл другой версии
    отклоняется кодом `unsupported_metadata_schema_version` без разбора
    остальных полей.
    """
    if type(content) is not bytes or len(content) > MAX_METADATA_SIZE:
        _fail(ManagerMetadataErrorCode.CONTENT)
    text = None
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    if text is None:
        _fail(ManagerMetadataErrorCode.CONTENT)
    document = None
    try:
        document = parse_strict_json_object(text, comments=False)
    except ConfigDocumentError:
        pass
    if document is None:
        _fail(ManagerMetadataErrorCode.JSON)
    marker = document.get("format")
    if type(marker) is not str or marker != METADATA_FORMAT:
        _fail(ManagerMetadataErrorCode.FORMAT, "format")
    version = document.get("schema_version")
    if type(version) is not int or version < 1:
        _fail(ManagerMetadataErrorCode.FORMAT, "schema_version")
    if version != METADATA_SCHEMA_VERSION:
        _fail(ManagerMetadataErrorCode.SCHEMA_VERSION, "schema_version")
    storage = _parse_storage(document["storage"]) if "storage" in document else None
    metadata = _build("", ManagerMetadata, storage=storage, extra=_extra(document, _TOP_KEYS))
    return StoredManagerMetadata(metadata, metadata_revision(content))


def _rebuild_extra(extra: object) -> UnknownFields:
    if type(extra) is not UnknownFields:
        _fail(ManagerMetadataErrorCode.UNKNOWN_FIELDS)
    rebuilt = UnknownFields(extra.export())
    if rebuilt._snapshot != extra._snapshot or rebuilt._names != extra._names:
        _fail(ManagerMetadataErrorCode.UNKNOWN_FIELDS)
    return rebuilt


def _rebuild_tracked(value: object, name: str) -> TrackedValue:
    if type(value) is not TrackedValue:
        _fail(ManagerMetadataErrorCode.FORMAT, name)
    return _build(name, TrackedValue, state=value.state, value=value.value, extra=_rebuild_extra(value.extra))


def _rebuild_role(location: object, name: str) -> RoleLocation:
    if type(location) is not RoleLocation:
        _fail(ManagerMetadataErrorCode.FORMAT, name)
    values: dict[str, object] = {
        "state": location.state, "verified": location.verified, "extra": _rebuild_extra(location.extra),
    }
    for key in ("storage_id", "path"):
        item = getattr(location, key)
        values[key] = None if item is None else _rebuild_tracked(item, _join(name, key))
    return _build(name, RoleLocation, **values)


def _rebuild_storage(placement: object) -> StoragePlacement:
    name = "storage"
    if type(placement) is not StoragePlacement:
        _fail(ManagerMetadataErrorCode.FORMAT, name)
    roles, limits = placement.roles, placement.history_limits
    roles_name, limits_name = _join(name, "roles"), _join(name, "history_limits")
    if type(roles) is not StorageRoles:
        _fail(ManagerMetadataErrorCode.FORMAT, roles_name)
    if type(limits) is not HistoryLimits:
        _fail(ManagerMetadataErrorCode.FORMAT, limits_name)
    rebuilt_roles = _build(roles_name, StorageRoles, **{
        key: _rebuild_role(getattr(roles, key), _join(roles_name, key)) for key in _ROLES_KEYS
    }, extra=_rebuild_extra(roles.extra))
    rebuilt_limits = _build(limits_name, HistoryLimits, **{
        key: _rebuild_tracked(getattr(limits, key), _join(limits_name, key)) for key in _LIMIT_KEYS
    }, extra=_rebuild_extra(limits.extra))
    return _build(
        name, StoragePlacement, variant=_rebuild_tracked(placement.variant, _join(name, "variant")),
        roles=rebuilt_roles, history_limits=rebuilt_limits, extra=_rebuild_extra(placement.extra),
    )


def validate_manager_metadata(metadata: ManagerMetadata) -> None:
    """Проверить готовую модель заново, пересобрав вложенные объекты из их собственных полей.

    Конструкторы требуют точных типов, поэтому строка вместо `ValueState`
    или `StorageVariant` и `True` вместо целого не проходят, даже если они
    равны по `==`. Код ошибки вложенного поля сохраняется.
    """
    code = name = None
    try:
        if type(metadata) is not ManagerMetadata:
            _fail(ManagerMetadataErrorCode.METADATA)
        storage = None if metadata.storage is None else _rebuild_storage(metadata.storage)
        ManagerMetadata(storage=storage, extra=_rebuild_extra(metadata.extra))
    except ManagerMetadataError as error:
        code, name = error.code, error.field
    except Exception:
        # Повреждённая модель: атрибут не того типа, испорченный снимок и подобное.
        code = ManagerMetadataErrorCode.METADATA
    if code is not None:
        _fail(code, name)


def _tracked_json(value: TrackedValue, encode: Callable[[object], object] = lambda item: item) -> dict[str, object]:
    document: dict[str, object] = {"state": value.state.value}
    if value.known:
        document["value"] = encode(value.value)
    document.update(value.extra.export())
    return document


def _role_json(location: RoleLocation) -> dict[str, object]:
    document: dict[str, object] = {"state": location.state.value}
    if location.state is ValueState.KNOWN:
        document["storage_id"] = _tracked_json(location.storage_id)
        document["path"] = _tracked_json(location.path)
        document["verified"] = location.verified
    document.update(location.extra.export())
    return document


def _storage_json(placement: StoragePlacement) -> dict[str, object]:
    roles = {role.value: _role_json(location) for role, location in placement.roles.items()}
    roles.update(placement.roles.extra.export())
    limits = placement.history_limits
    limits_document = {key: _tracked_json(getattr(limits, key)) for key in _LIMIT_KEYS}
    limits_document.update(limits.extra.export())
    document: dict[str, object] = {
        "variant": _tracked_json(placement.variant, lambda variant: variant.value),
        "roles": roles,
        "history_limits": limits_document,
    }
    document.update(placement.extra.export())
    return document


def encode_manager_metadata(metadata: ManagerMetadata) -> bytes:
    """Собрать байты файла текущей версии схемы после повторной проверки модели.

    Известные поля идут в фиксированном порядке, неизвестные — после них
    в исходном порядке; текст ASCII с отступом и переводом строки в конце.
    """
    validate_manager_metadata(metadata)
    document: dict[str, object] = {"format": METADATA_FORMAT, "schema_version": METADATA_SCHEMA_VERSION}
    if metadata.storage is not None:
        document["storage"] = _storage_json(metadata.storage)
    document.update(metadata.extra.export())
    # Неизвестное поле, допустимое само по себе, внутри вложенного объекта может
    # превысить общую глубину: такой файл не прочитался бы обратно.
    if not valid_json_tree(document):
        _fail(ManagerMetadataErrorCode.UNKNOWN_FIELDS)
    content = (json.dumps(document, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("ascii")
    if len(content) > MAX_METADATA_SIZE:
        _fail(ManagerMetadataErrorCode.CONTENT)
    return content
