"""Режим одного сегмента и предварительный расчёт назначений только в памяти."""

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import NoReturn

from keenvpn.domain.keenetic_device import (
    DeviceIdentity, DevicePolicyAssignment, DevicePolicyMode, KeeneticDevice, KeeneticDeviceError, KeeneticDeviceInventory,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicySet, validate_policy_set, valid_policy_id


class SegmentSelectionMode(StrEnum):
    """Режим по умолчанию сегмента с сохранением индивидуальных назначений."""

    SELECTED_ONLY = "selected_only"
    WHOLE_SEGMENT = "whole_segment"
    EXCEPT_SELECTED = "except_selected"


class KeeneticSegmentErrorCode(StrEnum):
    """Отказы без исходных идентификаторов и приватных данных."""

    SEGMENT = "invalid_segment"
    SELECTION = "invalid_segment_selection"
    SCOPE_MISMATCH = "segment_scope_mismatch"
    DUPLICATE_DEVICE = "segment_device_ambiguous"
    POLICIES = "invalid_segment_policies"
    POLICY_TARGET = "invalid_segment_policy_target"
    POLICY_MISSING = "segment_policy_missing"
    PREVIEW = "invalid_segment_preview"


_MESSAGES = {
    KeeneticSegmentErrorCode.SEGMENT: "Передан некорректный сегмент или его состав.",
    KeeneticSegmentErrorCode.SELECTION: "Режим сегмента и списки выбранных устройств противоречивы.",
    KeeneticSegmentErrorCode.SCOPE_MISMATCH: "Выбор относится к другому сегменту.",
    KeeneticSegmentErrorCode.DUPLICATE_DEVICE: "Состав сегмента неоднозначен: MAC записи повторяется.",
    KeeneticSegmentErrorCode.POLICIES: "Передан некорректный текущий список политик.",
    KeeneticSegmentErrorCode.POLICY_TARGET: "Нужны две различные существующие политики VPN и прямого режима.",
    KeeneticSegmentErrorCode.POLICY_MISSING: "Текущей политики сегмента нет в переданном списке политик.",
    KeeneticSegmentErrorCode.PREVIEW: "Результат расчёта сегмента содержит несогласованные данные.",
}


class KeeneticSegmentError(ValueError):
    """Ошибка расчёта с фиксированным текстом и машинным кодом."""

    def __init__(self, code: KeeneticSegmentErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: KeeneticSegmentErrorCode) -> NoReturn:
    """Не сохранять чужое активное исключение в безопасном отказе."""
    try:
        raise KeeneticSegmentError(code) from None
    except KeeneticSegmentError as error:
        error.__context__ = None
        raise


def _valid_segment_id(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", value) is not None


@dataclass(frozen=True, slots=True, repr=False)
class KeeneticSegment:
    """Явно сопоставленный состав одного сегмента, включая offline-записи.

    Вызывающий доверенный код определяет принадлежность записей. Наблюдаемый
    интерфейс, IP, имя и производитель MAC не используются для её угадывания.
    Это не RCI-объект: модель не сериализует настройки сегмента для записи.
    """

    segment_id: str
    devices: KeeneticDeviceInventory
    policy_id: str | None = None

    def __post_init__(self) -> None:
        if not _valid_segment_id(self.segment_id) or type(self.devices) is not KeeneticDeviceInventory:
            _raise_detached(KeeneticSegmentErrorCode.SEGMENT)
        KeeneticDeviceInventory(self.devices.devices)
        if self.policy_id is not None and not valid_policy_id(self.policy_id):
            _raise_detached(KeeneticSegmentErrorCode.SEGMENT)

    def __repr__(self) -> str:
        return f"KeeneticSegment(records={len(self.devices.devices)})"


@dataclass(frozen=True, slots=True, repr=False)
class SegmentSelection:
    """Явный выбор для одного сегмента; списки содержат только ключи MAC.

    SELECTED_ONLY принимает selected_devices, EXCEPT_SELECTED — excluded_devices.
    WHOLE_SEGMENT не принимает списков. Пустой список допустим во всех режимах.
    """

    segment_id: str
    mode: SegmentSelectionMode
    selected_devices: tuple[DeviceIdentity, ...] = ()
    excluded_devices: tuple[DeviceIdentity, ...] = ()

    def __post_init__(self) -> None:
        if not _valid_segment_id(self.segment_id) or type(self.mode) is not SegmentSelectionMode:
            _raise_detached(KeeneticSegmentErrorCode.SELECTION)
        for identities in (self.selected_devices, self.excluded_devices):
            if type(identities) is not tuple or any(type(item) is not DeviceIdentity for item in identities):
                _raise_detached(KeeneticSegmentErrorCode.SELECTION)
            for item in identities:
                DeviceIdentity(item.mac)
            if len(set(identities)) != len(identities):
                _raise_detached(KeeneticSegmentErrorCode.SELECTION)
        if (
            (self.mode is not SegmentSelectionMode.SELECTED_ONLY and self.selected_devices)
            or (self.mode is not SegmentSelectionMode.EXCEPT_SELECTED and self.excluded_devices)
        ):
            _raise_detached(KeeneticSegmentErrorCode.SELECTION)

    def __repr__(self) -> str:
        return (
            f"SegmentSelection(mode={self.mode.value}, selected={len(self.selected_devices)}, "
            f"excluded={len(self.excluded_devices)})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SegmentSelectionPreview:
    """Результат расчёта; не черновик применения и не свидетельство маршрута.

    before/after, policy ID и ключи изменений — приватные данные. Безопасный
    вывод даёт to_diagnostic(). asdict() и локальные переменные traceback
    могут раскрывать записи. Ревизии внешнего источника здесь нет.
    """

    selection: SegmentSelection
    before: KeeneticSegment
    after: KeeneticSegment
    default_policy_id: str
    policy_ids: tuple[str, ...]
    changed_devices: tuple[DeviceIdentity, ...]
    vpn_policy_id: str
    direct_policy_id: str

    def __post_init__(self) -> None:
        valid = False
        try:
            valid = _preview_is_consistent(self)
        except (KeeneticSegmentError, KeeneticDeviceError):
            pass
        if not valid:
            _raise_detached(KeeneticSegmentErrorCode.PREVIEW)

    @property
    def before_default_policy_id(self) -> str | None:
        """Исходная политика; None не означает DIRECT или наследование."""
        return self.before.policy_id

    @property
    def default_changed(self) -> bool | None:
        """Неизвестный исходный default не позволяет утверждать изменение."""
        if self.before_default_policy_id is None:
            return None
        return self.before_default_policy_id != self.default_policy_id

    @property
    def new_device_mode(self) -> str:
        """Намерение для нового устройства без индивидуального назначения."""
        return "direct" if self.selection.mode is SegmentSelectionMode.SELECTED_ONLY else "vpn"

    @property
    def conflicting_devices(self) -> tuple[DeviceIdentity, ...]:
        """Известные индивидуальные отклонения от default вне явного выбора.

        Это предупреждение для просмотра, не запрет режима. Неопределённые
        назначения учитываются отдельно; ключи записей не подходят для журнала.
        """
        explicit_choice = set(self.selection.selected_devices + self.selection.excluded_devices)
        conflicts = []
        for device in self.after.devices.devices:
            identity = device.identity
            if identity not in explicit_choice:
                policy_id = self._policy_for_device(device)
                if policy_id is not None and policy_id != self.default_policy_id:
                    conflicts.append(identity)
        return tuple(conflicts)

    def policy_for(self, mac: str) -> str | None:
        """Предварительный ID по назначению, отдельно от запрета доступа.

        Только conform означает наследование. Неизвестная семантика, отсутствие
        назначения или исчезнувшая индивидуальная политика дают None, не DIRECT.
        Отсутствующий MAC не считается новым устройством: select() выдаёт ошибку.
        """
        return self._policy_for_device(self.after.devices.select(mac))

    def _policy_for_device(self, device: KeeneticDevice) -> str | None:
        """Использовать готовую запись без повторного поиска по всему составу."""
        if device.read_only:
            return None
        assignment = device.assignment
        if assignment.mode is DevicePolicyMode.INHERIT:
            return self.default_policy_id
        if assignment.mode is DevicePolicyMode.EXPLICIT and assignment.policy_id in self.policy_ids:
            return assignment.policy_id
        return None

    def __repr__(self) -> str:
        return f"SegmentSelectionPreview(mode={self.selection.mode.value}, changed={len(self.changed_devices)})"

    def to_diagnostic(self) -> dict[str, str | int | bool | None]:
        """Счётчики без MAC, имён, IP, ID сегмента и политик."""
        changed = set(self.changed_devices)
        explicit_choice = set(self.selection.selected_devices + self.selection.excluded_devices)
        preserved_count = conflicting_count = unresolved_count = denied_count = 0
        for device in self.after.devices.devices:
            identity = device.identity
            policy_id = self._policy_for_device(device)
            preserved_count += identity not in changed and device.assignment.mode is DevicePolicyMode.EXPLICIT
            unresolved_count += policy_id is None
            conflicting_count += (
                identity not in explicit_choice and policy_id is not None and policy_id != self.default_policy_id
            )
            denied_count += device.to_diagnostic()["access_denied"]
        return {
            "mode": self.selection.mode.value,
            "new_device_mode": self.new_device_mode,
            "default_changed": self.default_changed,
            "record_count": len(self.after.devices.devices),
            "changed_device_count": len(changed),
            "conflicting_explicit_count": conflicting_count,
            "preserved_explicit_count": preserved_count,
            "unresolved_device_count": unresolved_count,
            "access_denied_count": denied_count,
        }


def _preview_is_consistent(preview: SegmentSelectionPreview) -> bool:
    """Проверить публичный результат, не обращаясь к внешним источникам."""
    if (
        type(preview.selection) is not SegmentSelection
        or type(preview.before) is not KeeneticSegment or type(preview.after) is not KeeneticSegment
        or type(preview.policy_ids) is not tuple or not all(valid_policy_id(item) for item in preview.policy_ids)
        or not valid_policy_id(preview.default_policy_id)
        or not valid_policy_id(preview.vpn_policy_id) or not valid_policy_id(preview.direct_policy_id)
        or type(preview.changed_devices) is not tuple
        or any(type(item) is not DeviceIdentity for item in preview.changed_devices)
    ):
        return False
    selection = preview.selection
    SegmentSelection(selection.segment_id, selection.mode, selection.selected_devices, selection.excluded_devices)
    for segment in (preview.before, preview.after):
        KeeneticSegment(segment.segment_id, segment.devices, segment.policy_id)
        if segment.segment_id != selection.segment_id:
            return False
        if segment.policy_id is not None and segment.policy_id not in preview.policy_ids:
            return False
    if (
        len(set(preview.policy_ids)) != len(preview.policy_ids)
        or preview.default_policy_id not in preview.policy_ids
        or preview.after.policy_id != preview.default_policy_id
        or preview.vpn_policy_id == preview.direct_policy_id
        or preview.vpn_policy_id not in preview.policy_ids or preview.direct_policy_id not in preview.policy_ids
    ):
        return False
    selected_only = selection.mode is SegmentSelectionMode.SELECTED_ONLY
    if preview.default_policy_id != (preview.direct_policy_id if selected_only else preview.vpn_policy_id):
        return False
    before = preview.before.devices.devices
    after = preview.after.devices.devices
    identities = tuple(device.identity for device in before)
    if len(set(identities)) != len(identities) or identities != tuple(device.identity for device in after):
        return False
    for item in preview.changed_devices:
        if DeviceIdentity(item.mac) != item:
            return False
    choices = set(selection.selected_devices + selection.excluded_devices)
    target = DevicePolicyAssignment(
        DevicePolicyMode.EXPLICIT, preview.vpn_policy_id if selected_only else preview.direct_policy_id,
    )
    for device in after:
        if device.identity in choices and (device.read_only or device.assignment != target):
            return False
    actual_changes = tuple(original.identity for original, updated in zip(before, after) if original != updated)
    return (
        choices.issubset(identities)
        and preview.changed_devices == actual_changes
        and set(preview.changed_devices).issubset(choices)
    )


def preview_segment_selection(
    segment: KeeneticSegment,
    selection: SegmentSelection,
    *,
    policies: KeeneticPolicySet,
    vpn_policy_id: str,
    direct_policy_id: str,
) -> SegmentSelectionPreview:
    """Рассчитать режим сегмента и копии явно выбранных записей без I/O.

    Политики передаются после определения их роли по текущему состоянию.
    Наличие ID не доказывает правильность WAN-разрешений или работу VPN.
    Индивидуальные назначения вне явного выбора сохраняются во всех режимах.
    Снятие прежних исключений и возврат наследования — отдельный явный выбор.
    """
    if type(segment) is not KeeneticSegment:
        _raise_detached(KeeneticSegmentErrorCode.SEGMENT)
    if type(selection) is not SegmentSelection:
        _raise_detached(KeeneticSegmentErrorCode.SELECTION)
    # Перепроверяем готовые модели перед расчётом, как и список политик.
    KeeneticSegment(segment.segment_id, segment.devices, segment.policy_id)
    SegmentSelection(selection.segment_id, selection.mode, selection.selected_devices, selection.excluded_devices)
    if selection.segment_id != segment.segment_id:
        _raise_detached(KeeneticSegmentErrorCode.SCOPE_MISMATCH)
    identities = tuple(device.identity for device in segment.devices.devices)
    if len(set(identities)) != len(identities):
        _raise_detached(KeeneticSegmentErrorCode.DUPLICATE_DEVICE)
    by_identity = dict(zip(identities, segment.devices.devices))
    valid = False
    if type(policies) is KeeneticPolicySet:
        try:
            validate_policy_set(policies)
            valid = True
        except Exception:
            pass
    if not valid:
        _raise_detached(KeeneticSegmentErrorCode.POLICIES)
    if segment.policy_id is not None and segment.policy_id not in policies.policy_ids:
        _raise_detached(KeeneticSegmentErrorCode.POLICY_MISSING)
    if (
        not valid_policy_id(vpn_policy_id) or not valid_policy_id(direct_policy_id)
        or vpn_policy_id == direct_policy_id
        or vpn_policy_id not in policies.policy_ids or direct_policy_id not in policies.policy_ids
    ):
        _raise_detached(KeeneticSegmentErrorCode.POLICY_TARGET)

    selected_only = selection.mode is SegmentSelectionMode.SELECTED_ONLY
    default_policy_id = direct_policy_id if selected_only else vpn_policy_id
    overrides = selection.selected_devices if selected_only else selection.excluded_devices
    target = DevicePolicyAssignment(DevicePolicyMode.EXPLICIT, vpn_policy_id if selected_only else direct_policy_id)
    replacements = {}
    for identity in overrides:
        # Отсутствующий или чужой MAC не игнорируется, offline не фильтруется.
        original = by_identity.get(identity)
        if original is None:
            # Сохранить существующий безопасный отказ device_missing.
            original = segment.devices.select(identity.mac)
        replacements[identity] = original.with_assignment(target, policies=policies)
    records = tuple(replacements.get(identity, device) for identity, device in by_identity.items())
    changed = tuple(
        original.identity for original, updated in zip(segment.devices.devices, records)
        if original is not updated
    )
    return SegmentSelectionPreview(
        selection, segment, KeeneticSegment(segment.segment_id, KeeneticDeviceInventory(records), default_policy_id),
        default_policy_id, policies.policy_ids, changed, vpn_policy_id, direct_policy_id,
    )
