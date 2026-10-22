"""Список устройств Keenetic для меню: записи, назначения, политики, online и запрет доступа.

Сценарий читает четыре источника обработчиком `InspectKeeneticState` в его
порядке и с его кодами отказов и собирает один список записей `ip/hotspot.host`
в порядке источника. У записи — позиция, имя регистрации `known/host` после
проверки формата, сохранённое назначение и ID политики с признаком её наличия
в списке политик, online по наблюдению, запрет доступа, признак «только
просмотр», повтор MAC, наблюдаемый интерфейс и назначение сегмента с тем же
интерфейсом как сопоставление технических идентификаторов. MAC, имена хостов,
адреса и описания политик в представление не входят; состав сегмента
и действующая политика устройства не вычисляются. Успех описывает снимок
на момент чтения, а не маршрут клиента или работу VPN.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result, check_contract_version, failed,
    invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler, KeeneticSegmentView, KeeneticStateView
from keenvpn.application.views import view_dict
from keenvpn.domain.keenetic_device import DevicePolicyMode, DevicePresence, KeeneticDeviceError
from keenvpn.domain.keenetic_native import KeeneticNativeError, KeeneticNativeState
from keenvpn.domain.keenetic_policy import KeeneticPolicyError, valid_policy_id
from keenvpn.domain.keenetic_segment import valid_segment_id


@dataclass(frozen=True, slots=True, kw_only=True)
class ListKeeneticDevices:
    """Показать записи устройств списком с назначениями, online и запретом доступа без MAC, имён хостов и адресов."""

    name: ClassVar[str] = "list_keenetic_devices"

    contract_version: int = CONTRACT_VERSION


class PresenceReason(StrEnum):
    """Почему online записи неизвестен; не причина offline и не результат сетевой проверки."""

    NO_OBSERVATION = "no_observation"
    """Наблюдения с MAC записи нет."""
    AMBIGUOUS_OBSERVATION = "ambiguous_observation"
    """MAC повторяется среди записей или наблюдений: наблюдение не выбирается по первому."""
    ACTIVE_UNKNOWN = "active_unknown"
    """Наблюдение есть, но признак активности не булев."""


class SegmentMatch(StrEnum):
    """Как наблюдаемый интерфейс сопоставлен с назначениями сегментов `ip/hotspot.policy`.

    Это сопоставление технических идентификаторов по наблюдению, а не состав
    сегмента и не действующая политика устройства.
    """

    NOT_OBSERVED = "not_observed"
    """Интерфейс в наблюдении не указан."""
    UNASSIGNED = "unassigned"
    """Назначения сегмента с таким интерфейсом нет."""
    MATCHED = "matched"
    """Ровно одно назначение сегмента с таким интерфейсом."""
    AMBIGUOUS = "ambiguous"
    """Несколько назначений с таким интерфейсом: ни одно не выбирается."""


ASSIGNMENT_LABELS: Mapping[str, str] = MappingProxyType({
    DevicePolicyMode.EXPLICIT.value: "явная политика",
    DevicePolicyMode.INHERIT.value: "наследует политику сегмента",
    DevicePolicyMode.UNASSIGNED.value: "без назначения",
    DevicePolicyMode.UNKNOWN.value: "назначение не распознано",
})
"""Русские подписи сохранённого назначения записи. Таблица только для чтения."""
PRESENCE_LABELS: Mapping[str, str] = MappingProxyType({
    DevicePresence.ONLINE.value: "online",
    DevicePresence.OFFLINE.value: "offline",
    DevicePresence.UNKNOWN.value: "online неизвестно",
})
"""Русские подписи online по наблюдению; «неизвестно» не означает offline. Таблица только для чтения."""
PRESENCE_REASON_LABELS: Mapping[str, str] = MappingProxyType({
    PresenceReason.NO_OBSERVATION.value: "наблюдения нет",
    PresenceReason.AMBIGUOUS_OBSERVATION.value: "наблюдение неоднозначно: MAC повторяется",
    PresenceReason.ACTIVE_UNKNOWN.value: "признак активности не распознан",
})
"""Русские подписи причин неизвестного online. Таблица только для чтения."""
SEGMENT_MATCH_LABELS: Mapping[str, str] = MappingProxyType({
    SegmentMatch.NOT_OBSERVED.value: "интерфейс не наблюдался",
    SegmentMatch.UNASSIGNED.value: "назначения сегмента с этим интерфейсом нет",
    SegmentMatch.MATCHED.value: "назначение сегмента с этим интерфейсом",
    SegmentMatch.AMBIGUOUS.value: "несколько назначений сегментов с этим интерфейсом",
})
"""Русские подписи сопоставления интерфейса с назначениями сегментов. Таблица только для чтения."""

MAX_DEVICE_NAME_LENGTH = 64
"""Предел имени регистрации в символах: тот же, что у названия правила."""

_ASSIGNMENTS = frozenset(mode.value for mode in DevicePolicyMode)
_PRESENCES = frozenset(presence.value for presence in DevicePresence)
_REASONS = frozenset(reason.value for reason in PresenceReason)
_MATCHES = frozenset(match.value for match in SegmentMatch)
_HIDDEN_INTERFACE_MATCHES = frozenset({SegmentMatch.NOT_OBSERVED.value, SegmentMatch.UNASSIGNED.value})


def valid_device_name(value: object) -> bool:
    """Проверить имя регистрации — пользовательский текст: печатное, 1–64 символа, без пробелов по краям."""
    return (
        type(value) is str and 1 <= len(value) <= MAX_DEVICE_NAME_LENGTH
        and value.isprintable() and value == value.strip()
    )


def _non_negative(value: object) -> bool:
    return type(value) is int and value >= 0


def _optional_name(value: object) -> bool:
    return value is None or valid_device_name(value)


@dataclass(frozen=True, slots=True)
class DeviceEntryView:
    """Запись устройства без MAC, имён хостов и адресов.

    `position` — индекс записи в `ip/hotspot.host`, счёт с нуля; он различает
    записи с одинаковыми или скрытыми именами. `registration_names` — имена
    регистраций того же MAC в порядке реестра, `None` на месте имени вне
    формата; `name` заполнено только при единственной регистрации
    (`name_known`), иначе имена перечислены в карточке. `policy_present`
    задано только для явного назначения. `presence_reason` — только при
    неизвестном online. `observed_interface_id` показывается, только когда
    наблюдаемое значение совпало с техническим ID назначения сегмента того же
    чтения (`matched` или `ambiguous`); иначе оно известно, но скрыто (`None`):
    наблюдение может содержать MAC, адрес или имя хоста вместо ID интерфейса.
    `segment` задан только при `segment_match == matched`.
    """

    position: int
    registration_count: int
    registration_names: tuple[str | None, ...]
    name_known: bool
    name: str | None
    assignment: str
    policy_id: str | None
    policy_present: bool | None
    presence: str
    presence_reason: str | None
    access_denied: bool
    read_only: bool
    mac_duplicate: bool
    observed_interface_known: bool
    observed_interface_id: str | None
    segment_match: str
    segment: KeeneticSegmentView | None

    def __post_init__(self) -> None:
        explicit = self.assignment == DevicePolicyMode.EXPLICIT.value
        unknown = self.presence == DevicePresence.UNKNOWN.value
        if (
            not _non_negative(self.position)
            or type(self.registration_names) is not tuple or not all(_optional_name(item) for item in self.registration_names)
            or self.registration_count != len(self.registration_names)
            or type(self.name_known) is not bool or self.name_known != (self.registration_count == 1)
            or self.name != (self.registration_names[0] if self.name_known else None)
            or type(self.assignment) is not str or self.assignment not in _ASSIGNMENTS
            or (explicit and not valid_policy_id(self.policy_id)) or (not explicit and self.policy_id is not None)
            or (explicit and type(self.policy_present) is not bool) or (not explicit and self.policy_present is not None)
            or type(self.presence) is not str or self.presence not in _PRESENCES
            or (unknown and (type(self.presence_reason) is not str or self.presence_reason not in _REASONS))
            or (not unknown and self.presence_reason is not None)
            or any(type(value) is not bool for value in (self.access_denied, self.read_only, self.mac_duplicate))
            or type(self.observed_interface_known) is not bool
            or not (self.observed_interface_id is None or valid_segment_id(self.observed_interface_id))
            or (not self.observed_interface_known and self.observed_interface_id is not None)
            or type(self.segment_match) is not str or self.segment_match not in _MATCHES
            or (self.segment_match == SegmentMatch.NOT_OBSERVED.value) != (not self.observed_interface_known)
            # ID показан ровно тогда, когда совпал с назначением сегмента; остальное наблюдение скрыто.
            or (self.observed_interface_id is None) != (self.segment_match in _HIDDEN_INTERFACE_MATCHES)
            or (self.segment is not None) != (self.segment_match == SegmentMatch.MATCHED.value)
            or not (self.segment is None or type(self.segment) is KeeneticSegmentView)
        ):
            raise TypeError("Некорректное описание устройства в списке устройств.")

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление; имя — только в полях `name` и `registration_names`."""
        return {
            **view_dict(self),
            "registration_names": list(self.registration_names),
            "segment": None if self.segment is None else view_dict(self.segment),
        }


@dataclass(frozen=True, slots=True)
class DeviceCountsView:
    """Счётчики списка: записи, online, назначения, запреты, повторы MAC, скрытые имена и записи без пары."""

    record_count: int
    distinct_mac_count: int
    duplicate_mac_count: int
    online_count: int
    offline_count: int
    unknown_count: int
    explicit_count: int
    inherit_count: int
    unassigned_count: int
    unknown_assignment_count: int
    missing_policy_count: int
    access_denied_count: int
    read_only_count: int
    hidden_name_count: int
    ambiguous_observation_count: int
    registrations_without_device_count: int
    runtime_without_device_count: int

    def __post_init__(self) -> None:
        if not all(_non_negative(getattr(self, name)) for name in self.__dataclass_fields__):
            raise TypeError("Некорректные счётчики списка устройств.")


def _counts_from_entries(
    entries: tuple[DeviceEntryView, ...], distinct_mac_count: int, registrations_without_device: int,
    runtime_without_device: int,
) -> DeviceCountsView:
    """Вывести счётчики из записей; список проверяет ими свою согласованность."""
    def total(predicate) -> int:
        return sum(1 for item in entries if predicate(item))

    return DeviceCountsView(
        record_count=len(entries),
        distinct_mac_count=distinct_mac_count,
        duplicate_mac_count=total(lambda item: item.mac_duplicate),
        online_count=total(lambda item: item.presence == DevicePresence.ONLINE.value),
        offline_count=total(lambda item: item.presence == DevicePresence.OFFLINE.value),
        unknown_count=total(lambda item: item.presence == DevicePresence.UNKNOWN.value),
        explicit_count=total(lambda item: item.assignment == DevicePolicyMode.EXPLICIT.value),
        inherit_count=total(lambda item: item.assignment == DevicePolicyMode.INHERIT.value),
        unassigned_count=total(lambda item: item.assignment == DevicePolicyMode.UNASSIGNED.value),
        unknown_assignment_count=total(lambda item: item.assignment == DevicePolicyMode.UNKNOWN.value),
        missing_policy_count=total(lambda item: item.policy_present is False),
        access_denied_count=total(lambda item: item.access_denied),
        read_only_count=total(lambda item: item.read_only),
        hidden_name_count=sum(item.registration_names.count(None) for item in entries),
        ambiguous_observation_count=total(lambda item: item.presence_reason == PresenceReason.AMBIGUOUS_OBSERVATION.value),
        registrations_without_device_count=registrations_without_device,
        runtime_without_device_count=runtime_without_device,
    )


@dataclass(frozen=True, slots=True)
class DeviceListView:
    """Список записей устройств с политиками, назначениями сегментов и счётчиками.

    `devices` идут в порядке `ip/hotspot.host`, позиция записи — её индекс
    в этом кортеже. `segments` — назначения сегментов из того же источника;
    показанный интерфейс записи — всегда ID одного из них. Счётчики
    согласованы с записями, наличие явной политики — со списком `policy_ids`.
    """

    policy_count: int
    policy_ids: tuple[str, ...]
    segments: tuple[KeeneticSegmentView, ...]
    segment_missing_policy_count: int
    counts: DeviceCountsView
    devices: tuple[DeviceEntryView, ...]

    def __post_init__(self) -> None:
        if (
            type(self.policy_ids) is not tuple or not all(valid_policy_id(item) for item in self.policy_ids)
            or self.policy_count != len(self.policy_ids)
            or type(self.segments) is not tuple or any(type(item) is not KeeneticSegmentView for item in self.segments)
            or not _non_negative(self.segment_missing_policy_count)
            or type(self.counts) is not DeviceCountsView
            or type(self.devices) is not tuple or any(type(item) is not DeviceEntryView for item in self.devices)
            or [item.position for item in self.devices] != list(range(len(self.devices)))
            or any(
                item.policy_present != (item.policy_id in self.policy_ids)
                for item in self.devices if item.policy_present is not None
            )
            or any(item.segment is not None and item.segment not in self.segments for item in self.devices)
            or any(
                item.observed_interface_id is not None
                and item.observed_interface_id not in {segment.segment_id for segment in self.segments}
                for item in self.devices
            )
            or self.counts != _counts_from_entries(
                self.devices, self.counts.distinct_mac_count, self.counts.registrations_without_device_count,
                self.counts.runtime_without_device_count,
            )
        ):
            raise TypeError("Список устройств не согласован со своими счётчиками и политиками.")

    @classmethod
    def from_state(cls, state: KeeneticNativeState) -> "DeviceListView":
        """Построить список из доверенного состояния; наружу выходят только безопасные поля."""
        if type(state) is not KeeneticNativeState:
            raise TypeError("Ожидается KeeneticNativeState.")
        base = KeeneticStateView.from_state(state)
        by_interface: dict[str, list[KeeneticSegmentView]] = {}
        for segment in base.segments:
            by_interface.setdefault(segment.segment_id, []).append(segment)
        records = state.devices.devices
        identities = [device.identity for device in records]
        identity_counts: dict[object, int] = {}
        for identity in identities:
            identity_counts[identity] = identity_counts.get(identity, 0) + 1
        ambiguous = set(state.ambiguous_observations)
        policy_ids = set(base.policy_ids)
        entries = []
        for position, device in enumerate(records):
            details = device.export()["details"]
            names = tuple(name if valid_device_name(name) else None for name in details.get("registration", {}))
            diagnostic = device.to_diagnostic()
            assignment = device.assignment
            presence = device.presence
            reason = None
            if presence is DevicePresence.UNKNOWN:
                if "observation" in details:
                    reason = PresenceReason.ACTIVE_UNKNOWN.value
                elif identities[position] in ambiguous:
                    reason = PresenceReason.AMBIGUOUS_OBSERVATION.value
                else:
                    reason = PresenceReason.NO_OBSERVATION.value
            observed = device.observed_interface_id
            match, segment, shown_interface = SegmentMatch.NOT_OBSERVED, None, None
            if observed is not None:
                # Наблюдаемое значение показывается, только если это ID назначения сегмента того же чтения:
                # иначе runtime мог подставить MAC, адрес или имя хоста, которые представление не выводит.
                found = by_interface.get(observed, [])
                if not found:
                    match = SegmentMatch.UNASSIGNED
                elif len(found) == 1:
                    match, segment, shown_interface = SegmentMatch.MATCHED, found[0], observed
                else:
                    match, shown_interface = SegmentMatch.AMBIGUOUS, observed
            entries.append(DeviceEntryView(
                position=position,
                registration_count=len(names),
                registration_names=names,
                name_known=len(names) == 1,
                name=names[0] if len(names) == 1 else None,
                assignment=assignment.mode.value,
                policy_id=assignment.policy_id,
                policy_present=None if assignment.policy_id is None else assignment.policy_id in policy_ids,
                presence=presence.value,
                presence_reason=reason,
                access_denied=diagnostic["access_denied"],
                read_only=diagnostic["read_only"],
                mac_duplicate=identity_counts[identities[position]] > 1,
                observed_interface_known=observed is not None,
                observed_interface_id=shown_interface,
                segment_match=match.value,
                segment=segment,
            ))
        devices = tuple(entries)
        return cls(
            policy_count=base.policy_count,
            policy_ids=base.policy_ids,
            segments=base.segments,
            segment_missing_policy_count=base.segment_missing_policy_count,
            counts=_counts_from_entries(
                devices, len(identity_counts), len(state.registrations_without_device), len(state.runtime_without_device),
            ),
            devices=devices,
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "policy_count": self.policy_count,
            "policy_ids": list(self.policy_ids),
            "segments": [view_dict(segment) for segment in self.segments],
            "segment_missing_policy_count": self.segment_missing_policy_count,
            "counts": view_dict(self.counts),
            "devices": [item.to_dict() for item in self.devices],
        }


_LIST_INCONSISTENT = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "device_list_inconsistent",
    "Список устройств не удалось собрать из прочитанного состояния Keenetic.",
)
_DOMAIN_ERRORS = (KeeneticNativeError, KeeneticDeviceError, KeeneticPolicyError)


class ListKeeneticDevicesHandler:
    """Прочитать состояние Keenetic его обработчиком и показать записи устройств списком.

    Четыре источника читаются обработчиком `InspectKeeneticState` в его порядке
    и с его кодами отказов; отказ любого завершает сценарий без частичного
    результата. Ничего не записывается; успех не подтверждает маршрут клиента,
    работу XKeen или VPN.
    """

    def __init__(
        self, keenetic: InspectKeeneticStateHandler, *, operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._keenetic = keenetic
        self._operation_ids = operation_ids

    def execute(self, command: ListKeeneticDevices) -> Result[DeviceListView]:
        """Выполнить чтение; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = ListKeeneticDevices.name
        if type(command) is not ListKeeneticDevices:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        state = self._keenetic.read()
        if isinstance(state, ErrorDetail):
            return failed(operation_id, name, state)
        try:
            view = DeviceListView.from_state(state)
        except (TypeError, *_DOMAIN_ERRORS):
            # Текст исключения может содержать данные записей: наружу выходит фиксированный код.
            return failed(operation_id, name, _LIST_INCONSISTENT)
        return succeeded(operation_id, name, view)
