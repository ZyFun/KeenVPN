"""Прочитанное состояние Keenetic: политики, назначения сегментов, записи, регистрация и runtime.

Четыре ресурса RCI читаются раздельно и сопоставляются только по MAC.
Модели хранят неизменяемые JSON-снимки прочитанных объектов, не обращаются
к роутеру и ничего не записывают. Состав сегмента по наблюдаемому интерфейсу
не выводится: назначение сегмента хранится отдельно от записей устройств.
"""

from dataclasses import dataclass, field
from enum import StrEnum
import json
from typing import NoReturn

from keenvpn.domain.keenetic_device import (
    DeviceIdentity, DevicePolicyMode, KeeneticDevice, KeeneticDeviceError, KeeneticDeviceInventory,
    _access_supported, _validate_json,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicySet, valid_policy_id, validate_policy_set
from keenvpn.domain.keenetic_segment import _valid_segment_id


class KeeneticNativeErrorCode(StrEnum):
    """Причины отказа без MAC, имён, адресов и значений неизвестных полей."""

    SEGMENT_ASSIGNMENT = "invalid_segment_assignment"
    HOTSPOT_SETTINGS = "invalid_hotspot_settings"
    REGISTRATIONS = "invalid_registrations"
    HOTSPOT_RUNTIME = "invalid_hotspot_runtime"
    POLICIES = "invalid_native_policies"
    STATE = "invalid_native_state"


_MESSAGES = {
    KeeneticNativeErrorCode.SEGMENT_ASSIGNMENT: (
        "Назначение сегмента должно содержать поддерживаемые JSON-данные и допустимый идентификатор интерфейса."
    ),
    KeeneticNativeErrorCode.HOTSPOT_SETTINGS: (
        "Настройки hotspot должны быть объектом JSON со списками записей устройств и назначений сегментов."
    ),
    KeeneticNativeErrorCode.REGISTRATIONS: "Реестр регистраций должен быть объектом JSON с записями по именам.",
    KeeneticNativeErrorCode.HOTSPOT_RUNTIME: "Наблюдаемое состояние hotspot должно быть объектом JSON со списком записей.",
    KeeneticNativeErrorCode.POLICIES: "Передан некорректный список политик Keenetic.",
    KeeneticNativeErrorCode.STATE: "Собранное состояние Keenetic не согласовано с его источниками.",
}


class KeeneticNativeError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: KeeneticNativeErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: KeeneticNativeErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise KeeneticNativeError(code) from None
    except KeeneticNativeError as error:
        error.__context__ = None
        raise


def _snapshot(document: object, code: KeeneticNativeErrorCode) -> str:
    """Проверить JSON-данные объекта и сохранить их независимой строкой."""
    if type(document) is not dict:
        _raise_detached(code)
    try:
        _validate_json(document)
    except KeeneticDeviceError:
        _raise_detached(code)
    snapshot = None
    try:
        snapshot = json.dumps(document, ensure_ascii=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        pass
    if snapshot is None:
        _raise_detached(code)
    return snapshot


def _canonical(document: object) -> str:
    """Сравнивать снимки как JSON-текст: `true` и `1`, `false` и `0` различаются."""
    return json.dumps(document, ensure_ascii=True, allow_nan=False, sort_keys=False)


def _identity(value: object) -> DeviceIdentity | None:
    """Вернуть ключ MAC либо None для отсутствующего или недопустимого значения."""
    try:
        return DeviceIdentity(value)
    except KeeneticDeviceError:
        return None


def _list_of_objects(value: object) -> bool:
    return type(value) is list and all(type(item) is dict for item in value)


class SegmentPolicyMode(StrEnum):
    """Отсутствие политики сегмента не означает прямой доступ."""

    EXPLICIT = "explicit"
    UNASSIGNED = "unassigned"
    UNKNOWN = "unknown"


def _segment_policy(settings: dict[str, object]) -> tuple[SegmentPolicyMode, str | None]:
    """Разобрать сохранённую политику сегмента, не вычисляя её по runtime."""
    policy = settings.get("policy")
    if "policy" in settings and type(policy) is not str:
        return SegmentPolicyMode.UNKNOWN, None
    if policy:
        if valid_policy_id(policy):
            return SegmentPolicyMode.EXPLICIT, policy
        return SegmentPolicyMode.UNKNOWN, None
    return SegmentPolicyMode.UNASSIGNED, None


@dataclass(frozen=True, slots=True, init=False, repr=False)
class KeeneticSegmentAssignment:
    """Приватная запись `ip/hotspot.policy`: сегмент, его политика и запрет доступа.

    Запись описывает только назначение сегмента. Какие устройства относятся
    к сегменту, модель не знает и не выводит по наблюдаемому интерфейсу.
    `export()` раскрывает данные доверенному коду; для вывода — `to_diagnostic()`.
    """

    _snapshot: str = field(repr=False)

    def __init__(self, settings: dict[str, object]) -> None:
        snapshot = _snapshot(settings, KeeneticNativeErrorCode.SEGMENT_ASSIGNMENT)
        if not _valid_segment_id(settings.get("interface")):
            _raise_detached(KeeneticNativeErrorCode.SEGMENT_ASSIGNMENT)
        object.__setattr__(self, "_snapshot", snapshot)

    def __repr__(self) -> str:
        return "KeeneticSegmentAssignment(<скрыто>)"

    def export(self) -> dict[str, object]:
        """Получить копию записи для доверенного кода, не для вывода."""
        return json.loads(self._snapshot)

    @property
    def segment_id(self) -> str:
        """Технический идентификатор интерфейса сегмента на роутере."""
        return self.export()["interface"]

    @property
    def mode(self) -> SegmentPolicyMode:
        """Сохранённое назначение; runtime-состояние не используется."""
        return _segment_policy(self.export())[0]

    @property
    def policy_id(self) -> str | None:
        """ID политики только для явного назначения."""
        return _segment_policy(self.export())[1]

    @property
    def access_denied(self) -> bool:
        """Запрет доступа сегмента хранится и показывается отдельно от политики."""
        settings = self.export()
        return settings.get("access") == "deny" or settings.get("deny") is True

    @property
    def read_only(self) -> bool:
        """Неизвестную семантику политики или доступа нельзя безопасно менять."""
        settings = self.export()
        return _segment_policy(settings)[0] is SegmentPolicyMode.UNKNOWN or not _access_supported(settings)

    def to_diagnostic(self) -> dict[str, str | bool | None]:
        """Технические идентификаторы и признаки без неизвестных значений."""
        settings = self.export()
        mode, policy_id = _segment_policy(settings)
        return {
            "segment_id": settings["interface"],
            "assignment": mode.value,
            "policy_id": policy_id,
            "access_denied": settings.get("access") == "deny" or settings.get("deny") is True,
            "read_only": mode is SegmentPolicyMode.UNKNOWN or not _access_supported(settings),
        }


@dataclass(frozen=True, slots=True, init=False, repr=False)
class KeeneticHotspotSettings:
    """Снимок объекта `ip/hotspot`: записи устройств, назначения сегментов и прочие поля.

    `host` даёт настройки записей по MAC, `policy` — назначения сегментов.
    Остальные поля, например `auto-register`, сохраняются в снимке без разбора.
    """

    _snapshot: str = field(repr=False)
    segment_assignments: tuple[KeeneticSegmentAssignment, ...]

    def __init__(self, document: dict[str, object]) -> None:
        snapshot = _snapshot(document, KeeneticNativeErrorCode.HOTSPOT_SETTINGS)
        hosts = document.get("host", [])
        assignments = document.get("policy", [])
        if not _list_of_objects(hosts) or not _list_of_objects(assignments):
            _raise_detached(KeeneticNativeErrorCode.HOTSPOT_SETTINGS)
        for settings in hosts:
            # Запись без допустимого MAC нельзя сопоставить: ошибка устройства проходит наружу.
            KeeneticDevice(settings)
        object.__setattr__(self, "_snapshot", snapshot)
        object.__setattr__(
            self, "segment_assignments", tuple(KeeneticSegmentAssignment(entry) for entry in assignments),
        )

    def __repr__(self) -> str:
        return f"KeeneticHotspotSettings(hosts={len(self.host_settings)}, segments={len(self.segment_assignments)})"

    def export(self) -> dict[str, object]:
        """Получить копию всего объекта для доверенного кода."""
        return json.loads(self._snapshot)

    @property
    def host_settings(self) -> tuple[dict[str, object], ...]:
        """Копии настроек записей устройств в порядке источника."""
        return tuple(self.export().get("host", []))

    def to_diagnostic(self) -> dict[str, int]:
        """Счётчики без MAC, имён и идентификаторов."""
        diagnostics = [assignment.to_diagnostic() for assignment in self.segment_assignments]
        return {
            "host_record_count": len(self.host_settings),
            "segment_count": len(diagnostics),
            "segment_explicit_count": sum(item["assignment"] == SegmentPolicyMode.EXPLICIT.value for item in diagnostics),
            "segment_unassigned_count": sum(
                item["assignment"] == SegmentPolicyMode.UNASSIGNED.value for item in diagnostics
            ),
            "segment_unknown_count": sum(item["assignment"] == SegmentPolicyMode.UNKNOWN.value for item in diagnostics),
            "segment_denied_count": sum(item["access_denied"] for item in diagnostics),
        }


def validate_hotspot_settings(settings: KeeneticHotspotSettings) -> None:
    """Проверить готовую модель заново, включая данные, изменённые после создания."""
    if type(settings) is not KeeneticHotspotSettings:
        _raise_detached(KeeneticNativeErrorCode.HOTSPOT_SETTINGS)
    rebuilt = KeeneticHotspotSettings(settings.export())
    if (
        type(settings.segment_assignments) is not tuple
        or any(type(item) is not KeeneticSegmentAssignment for item in settings.segment_assignments)
        or [_canonical(item.export()) for item in rebuilt.segment_assignments]
        != [_canonical(item.export()) for item in settings.segment_assignments]
    ):
        _raise_detached(KeeneticNativeErrorCode.HOTSPOT_SETTINGS)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class KeeneticRegistrations:
    """Снимок объекта `known/host`: имя регистрации — ключ, MAC — значение.

    Имена регистраций — персональные данные, поэтому доступны только через
    `export()`. Запись без допустимого MAC сохраняется, но не сопоставляется.
    """

    _snapshot: str = field(repr=False)

    def __init__(self, document: dict[str, object]) -> None:
        snapshot = _snapshot(document, KeeneticNativeErrorCode.REGISTRATIONS)
        if any(type(entry) is not dict for entry in document.values()):
            _raise_detached(KeeneticNativeErrorCode.REGISTRATIONS)
        object.__setattr__(self, "_snapshot", snapshot)

    def __repr__(self) -> str:
        return f"KeeneticRegistrations(count={len(self.export())})"

    def export(self) -> dict[str, dict[str, object]]:
        """Получить копию реестра для доверенного кода, не для вывода."""
        return json.loads(self._snapshot)

    @property
    def identities(self) -> tuple[DeviceIdentity, ...]:
        """Ключи MAC сопоставимых записей в порядке источника, с повторами."""
        identities = (_identity(entry.get("mac")) for entry in self.export().values())
        return tuple(identity for identity in identities if identity is not None)

    def for_identity(self, identity: DeviceIdentity) -> dict[str, dict[str, object]]:
        """Копии всех регистраций одного MAC по именам; регистр MAC не важен."""
        if type(identity) is not DeviceIdentity:
            _raise_detached(KeeneticNativeErrorCode.REGISTRATIONS)
        return {
            name: entry for name, entry in self.export().items() if _identity(entry.get("mac")) == identity
        }

    def to_diagnostic(self) -> dict[str, int]:
        """Счётчики без имён и MAC."""
        identities = self.identities
        return {
            "registration_count": len(self.export()),
            "distinct_mac_count": len(set(identities)),
            "duplicate_mac_count": len(identities) - len(set(identities)),
            "unresolvable_count": len(self.export()) - len(identities),
        }


def validate_registrations(registrations: KeeneticRegistrations) -> None:
    """Проверить готовую модель заново по её снимку."""
    if type(registrations) is not KeeneticRegistrations:
        _raise_detached(KeeneticNativeErrorCode.REGISTRATIONS)
    KeeneticRegistrations(registrations.export())


@dataclass(frozen=True, slots=True, init=False, repr=False)
class KeeneticHotspotRuntime:
    """Снимок объекта `show/ip/hotspot`: наблюдаемые записи клиентов.

    Наблюдение описывает состояние на момент чтения и не является
    настройкой: вычисленная роутером политика в нём не заменяет назначение.
    """

    _snapshot: str = field(repr=False)

    def __init__(self, document: dict[str, object]) -> None:
        snapshot = _snapshot(document, KeeneticNativeErrorCode.HOTSPOT_RUNTIME)
        if not _list_of_objects(document.get("host", [])):
            _raise_detached(KeeneticNativeErrorCode.HOTSPOT_RUNTIME)
        object.__setattr__(self, "_snapshot", snapshot)

    def __repr__(self) -> str:
        return f"KeeneticHotspotRuntime(count={len(self.observations)})"

    def export(self) -> dict[str, object]:
        """Получить копию всего объекта для доверенного кода."""
        return json.loads(self._snapshot)

    @property
    def observations(self) -> tuple[dict[str, object], ...]:
        """Копии наблюдений в порядке источника."""
        return tuple(self.export().get("host", []))

    @property
    def identities(self) -> tuple[DeviceIdentity, ...]:
        """Ключи MAC сопоставимых наблюдений в порядке источника, с повторами."""
        identities = (_identity(entry.get("mac")) for entry in self.observations)
        return tuple(identity for identity in identities if identity is not None)

    def for_identity(self, identity: DeviceIdentity) -> tuple[dict[str, object], ...]:
        """Копии всех наблюдений одного MAC; выбор первого не выполняется."""
        if type(identity) is not DeviceIdentity:
            _raise_detached(KeeneticNativeErrorCode.HOTSPOT_RUNTIME)
        return tuple(entry for entry in self.observations if _identity(entry.get("mac")) == identity)

    def to_diagnostic(self) -> dict[str, int]:
        """Счётчики без MAC, имён, адресов и интерфейсов."""
        observations = self.observations
        identities = self.identities
        return {
            "record_count": len(observations),
            "distinct_mac_count": len(set(identities)),
            "duplicate_mac_count": len(identities) - len(set(identities)),
            "unresolvable_count": len(observations) - len(identities),
            "active_count": sum(entry.get("active") is True for entry in observations),
            "registered_count": sum(entry.get("registered") is True for entry in observations),
        }


def validate_hotspot_runtime(runtime: KeeneticHotspotRuntime) -> None:
    """Проверить готовую модель заново по её снимку."""
    if type(runtime) is not KeeneticHotspotRuntime:
        _raise_detached(KeeneticNativeErrorCode.HOTSPOT_RUNTIME)
    KeeneticHotspotRuntime(runtime.export())


def _unique(identities: tuple[DeviceIdentity, ...]) -> tuple[DeviceIdentity, ...]:
    return tuple(dict.fromkeys(identities))


def _index_registrations(registrations: KeeneticRegistrations) -> dict[DeviceIdentity, dict[str, dict[str, object]]]:
    """Один разбор реестра: регистрации каждого MAC по именам в порядке источника."""
    index: dict[DeviceIdentity, dict[str, dict[str, object]]] = {}
    for name, entry in registrations.export().items():
        identity = _identity(entry.get("mac"))
        if identity is not None:
            index.setdefault(identity, {})[name] = entry
    return index


def _index_runtime(runtime: KeeneticHotspotRuntime) -> dict[DeviceIdentity, list[dict[str, object]]]:
    """Один разбор наблюдений: все записи каждого MAC в порядке источника."""
    index: dict[DeviceIdentity, list[dict[str, object]]] = {}
    for entry in runtime.observations:
        identity = _identity(entry.get("mac"))
        if identity is not None:
            index.setdefault(identity, []).append(entry)
    return index


def _derive(
    hotspot: KeeneticHotspotSettings, registrations: KeeneticRegistrations, runtime: KeeneticHotspotRuntime,
) -> tuple[
    tuple[KeeneticDevice, ...], tuple[DeviceIdentity, ...], tuple[DeviceIdentity, ...], tuple[DeviceIdentity, ...],
]:
    """Сопоставить три источника только по MAC, ничего не объединяя и не отбрасывая.

    Записи `ip/hotspot.host` задают состав устройств. Регистрации одного MAC
    попадают в `details["registration"]` по именам, единственное наблюдение —
    в `details["observation"]`. Несколько наблюдений одного MAC не выбираются
    по первому: запись остаётся без наблюдения и отмечается как неоднозначная.
    Каждый источник разбирается один раз; стоимость линейна по числу записей.
    """
    registration_index = _index_registrations(registrations)
    runtime_index = _index_runtime(runtime)
    records = []
    ambiguous = []
    known: set[DeviceIdentity] = set()
    for settings in hotspot.host_settings:
        identity = DeviceIdentity(settings["mac"])
        known.add(identity)
        details: dict[str, object] = {}
        registration = registration_index.get(identity)
        if registration:
            details["registration"] = registration
        observations = runtime_index.get(identity, [])
        if len(observations) == 1:
            details["observation"] = observations[0]
        elif observations:
            ambiguous.append(identity)
        records.append(KeeneticDevice(settings, details=details))
    unmatched_registrations = tuple(identity for identity in registration_index if identity not in known)
    unmatched_runtime = tuple(identity for identity in runtime_index if identity not in known)
    return tuple(records), unmatched_registrations, unmatched_runtime, _unique(tuple(ambiguous))


@dataclass(frozen=True, slots=True, repr=False)
class KeeneticNativeState:
    """Согласованный результат раздельного чтения четырёх ресурсов Keenetic.

    Источники сохраняются целиком для доверенного кода. Записи без пары
    в другом источнике перечислены ключами MAC, а не объединены и не удалены.
    Политики, назначения сегментов и записи устройств не проверяются на
    согласованность с роутером: это снимок на момент чтения.
    """

    policies: KeeneticPolicySet
    hotspot: KeeneticHotspotSettings
    registrations: KeeneticRegistrations
    runtime: KeeneticHotspotRuntime
    devices: KeeneticDeviceInventory
    registrations_without_device: tuple[DeviceIdentity, ...]
    runtime_without_device: tuple[DeviceIdentity, ...]
    ambiguous_observations: tuple[DeviceIdentity, ...]

    def __post_init__(self) -> None:
        validate_keenetic_state(self)

    def __repr__(self) -> str:
        return (
            f"KeeneticNativeState(policies={len(self.policies)}, records={len(self.devices.devices)}, "
            f"segments={len(self.segments)})"
        )

    @property
    def segments(self) -> tuple[KeeneticSegmentAssignment, ...]:
        """Назначения сегментов из настроек hotspot."""
        return self.hotspot.segment_assignments

    def to_diagnostic(self) -> dict[str, object]:
        """Технические идентификаторы политик и сегментов и счётчики без приватных данных."""
        policy_ids = self.policies.policy_ids
        modes = {mode: 0 for mode in DevicePolicyMode}
        denied = read_only = with_registration = with_observation = missing_policy = 0
        for device in self.devices.devices:
            diagnostic = device.to_diagnostic()
            assignment = device.assignment
            modes[assignment.mode] += 1
            denied += diagnostic["access_denied"]
            read_only += diagnostic["read_only"]
            details = device.export()["details"]
            with_registration += "registration" in details
            with_observation += "observation" in details
            missing_policy += assignment.mode is DevicePolicyMode.EXPLICIT and assignment.policy_id not in policy_ids
        segments = [segment.to_diagnostic() for segment in self.segments]
        return {
            "policy_count": len(policy_ids),
            "policy_ids": list(policy_ids),
            "segments": segments,
            "segment_missing_policy_count": sum(
                item["policy_id"] is not None and item["policy_id"] not in policy_ids for item in segments
            ),
            "devices": {
                **self.devices.to_diagnostic(),
                "explicit_count": modes[DevicePolicyMode.EXPLICIT],
                "inherit_count": modes[DevicePolicyMode.INHERIT],
                "unassigned_count": modes[DevicePolicyMode.UNASSIGNED],
                "unknown_assignment_count": modes[DevicePolicyMode.UNKNOWN],
                "access_denied_count": denied,
                "read_only_count": read_only,
                "with_registration_count": with_registration,
                "with_observation_count": with_observation,
                "ambiguous_observation_count": len(self.ambiguous_observations),
                "missing_policy_count": missing_policy,
            },
            "registrations": {
                **self.registrations.to_diagnostic(),
                "without_device_count": len(self.registrations_without_device),
            },
            "runtime": {
                **self.runtime.to_diagnostic(),
                "without_device_count": len(self.runtime_without_device),
            },
        }


def _check_policies(policies: object) -> None:
    valid = False
    if type(policies) is KeeneticPolicySet:
        try:
            validate_policy_set(policies)
            valid = True
        except Exception:
            pass
    if not valid:
        _raise_detached(KeeneticNativeErrorCode.POLICIES)


def _identity_tuple(value: object) -> bool:
    return type(value) is tuple and all(type(item) is DeviceIdentity for item in value)


def validate_keenetic_state(state: KeeneticNativeState) -> None:
    """Проверить типы полей и повторно вывести сопоставление из источников."""
    if type(state) is not KeeneticNativeState:
        _raise_detached(KeeneticNativeErrorCode.STATE)
    _check_policies(state.policies)
    validate_hotspot_settings(state.hotspot)
    validate_registrations(state.registrations)
    validate_hotspot_runtime(state.runtime)
    if (
        type(state.devices) is not KeeneticDeviceInventory
        or not all(_identity_tuple(getattr(state, name)) for name in (
            "registrations_without_device", "runtime_without_device", "ambiguous_observations",
        ))
    ):
        _raise_detached(KeeneticNativeErrorCode.STATE)
    KeeneticDeviceInventory(state.devices.devices)
    records, unmatched_registrations, unmatched_runtime, ambiguous = _derive(
        state.hotspot, state.registrations, state.runtime,
    )
    if (
        [_canonical(device.export()) for device in state.devices.devices]
        != [_canonical(device.export()) for device in records]
        or state.registrations_without_device != unmatched_registrations
        or state.runtime_without_device != unmatched_runtime
        or state.ambiguous_observations != ambiguous
    ):
        _raise_detached(KeeneticNativeErrorCode.STATE)


def assemble_keenetic_state(
    policies: KeeneticPolicySet,
    hotspot: KeeneticHotspotSettings,
    registrations: KeeneticRegistrations,
    runtime: KeeneticHotspotRuntime,
) -> KeeneticNativeState:
    """Собрать состояние из раздельно прочитанных моделей без ввода-вывода.

    Политики не проверяются на наличие в них ID, на которые ссылаются записи
    и сегменты: отсутствующая политика отражается счётчиком в диагностике,
    а не подменяется и не удаляется.
    """
    _check_policies(policies)
    validate_hotspot_settings(hotspot)
    validate_registrations(registrations)
    validate_hotspot_runtime(runtime)
    records, unmatched_registrations, unmatched_runtime, ambiguous = _derive(hotspot, registrations, runtime)
    return KeeneticNativeState(
        policies, hotspot, registrations, runtime, KeeneticDeviceInventory(records),
        unmatched_registrations, unmatched_runtime, ambiguous,
    )
