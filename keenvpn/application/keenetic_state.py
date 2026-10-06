"""Чтение состояния Keenetic из раздельных источников без записи и слияния записей."""

from dataclasses import dataclass
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.keenetic_policies import check_policies
from keenvpn.application.ports import (
    KeeneticHotspotRuntimeSource, KeeneticHotspotSettingsSource, KeeneticPolicySource, KeeneticRegistrationSource,
)
from keenvpn.domain.keenetic_device import KeeneticDeviceError
from keenvpn.domain.keenetic_native import (
    KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticNativeError, KeeneticNativeState, KeeneticRegistrations,
    assemble_keenetic_state, validate_hotspot_runtime, validate_hotspot_settings, validate_registrations,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicyError


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectKeeneticState:
    """Прочитать политики, назначения сегментов, записи, регистрацию и runtime."""

    name: ClassVar[str] = "inspect_keenetic_state"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class KeeneticSegmentView:
    """Назначение одного сегмента: технические идентификаторы и признаки."""

    segment_id: str
    assignment: str
    policy_id: str | None
    access_denied: bool
    read_only: bool


@dataclass(frozen=True, slots=True)
class KeeneticDeviceCountsView:
    """Счётчики записей устройств без MAC, имён и адресов."""

    record_count: int
    distinct_mac_count: int
    online_count: int
    offline_count: int
    unknown_count: int
    observation_mismatch_count: int
    explicit_count: int
    inherit_count: int
    unassigned_count: int
    unknown_assignment_count: int
    access_denied_count: int
    read_only_count: int
    with_registration_count: int
    with_observation_count: int
    ambiguous_observation_count: int
    missing_policy_count: int


@dataclass(frozen=True, slots=True)
class KeeneticRegistrationCountsView:
    """Счётчики реестра регистраций без имён."""

    registration_count: int
    distinct_mac_count: int
    duplicate_mac_count: int
    unresolvable_count: int
    without_device_count: int


@dataclass(frozen=True, slots=True)
class KeeneticRuntimeCountsView:
    """Счётчики наблюдаемых записей на момент чтения."""

    record_count: int
    distinct_mac_count: int
    duplicate_mac_count: int
    unresolvable_count: int
    active_count: int
    registered_count: int
    without_device_count: int


def _fields(view_type: type, values: dict[str, object]) -> dict[str, object]:
    return {name: values[name] for name in view_type.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class KeeneticStateView:
    """Безопасное представление прочитанного состояния.

    ID политик и интерфейсов сегментов — технические идентификаторы роутера.
    MAC, имена, адреса, описания политик и неизвестные поля сюда не входят.
    """

    policy_count: int
    policy_ids: tuple[str, ...]
    segments: tuple[KeeneticSegmentView, ...]
    segment_missing_policy_count: int
    devices: KeeneticDeviceCountsView
    registrations: KeeneticRegistrationCountsView
    runtime: KeeneticRuntimeCountsView

    @classmethod
    def from_state(cls, state: KeeneticNativeState) -> "KeeneticStateView":
        """Построить представление из безопасной диагностики домена."""
        diagnostic = state.to_diagnostic()
        return cls(
            policy_count=diagnostic["policy_count"],
            policy_ids=tuple(diagnostic["policy_ids"]),
            segments=tuple(KeeneticSegmentView(**_fields(KeeneticSegmentView, item)) for item in diagnostic["segments"]),
            segment_missing_policy_count=diagnostic["segment_missing_policy_count"],
            devices=KeeneticDeviceCountsView(**_fields(KeeneticDeviceCountsView, diagnostic["devices"])),
            registrations=KeeneticRegistrationCountsView(
                **_fields(KeeneticRegistrationCountsView, diagnostic["registrations"]),
            ),
            runtime=KeeneticRuntimeCountsView(**_fields(KeeneticRuntimeCountsView, diagnostic["runtime"])),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "policy_count": self.policy_count,
            "policy_ids": list(self.policy_ids),
            "segments": [_view_dict(segment) for segment in self.segments],
            "segment_missing_policy_count": self.segment_missing_policy_count,
            "devices": _view_dict(self.devices),
            "registrations": _view_dict(self.registrations),
            "runtime": _view_dict(self.runtime),
        }


def _view_dict(view: object) -> dict[str, object]:
    """Снять поля frozen dataclass со слотами, у которого нет `__dict__`."""
    return {name: getattr(view, name) for name in view.__dataclass_fields__}


_UNAVAILABLE = {
    "policies": ("keenetic_policies_unavailable", "Не удалось прочитать политики Keenetic."),
    "hotspot": ("keenetic_hotspot_unavailable", "Не удалось прочитать настройки hotspot Keenetic."),
    "registrations": ("keenetic_registrations_unavailable", "Не удалось прочитать реестр регистраций Keenetic."),
    "runtime": ("keenetic_runtime_unavailable", "Не удалось прочитать наблюдаемое состояние клиентов Keenetic."),
}
_INVALID = {
    "hotspot": (
        "invalid_keenetic_hotspot", KeeneticHotspotSettings, validate_hotspot_settings,
        "Источник вернул настройки hotspot Keenetic в неподдерживаемом формате.",
        "Источник вернул некорректные настройки hotspot Keenetic.",
    ),
    "registrations": (
        "invalid_keenetic_registrations", KeeneticRegistrations, validate_registrations,
        "Источник вернул реестр регистраций Keenetic в неподдерживаемом формате.",
        "Источник вернул некорректный реестр регистраций Keenetic.",
    ),
    "runtime": (
        "invalid_keenetic_runtime", KeeneticHotspotRuntime, validate_hotspot_runtime,
        "Источник вернул наблюдаемое состояние Keenetic в неподдерживаемом формате.",
        "Источник вернул некорректное наблюдаемое состояние Keenetic.",
    ),
}
_DOMAIN_ERRORS = (KeeneticNativeError, KeeneticDeviceError, KeeneticPolicyError)


def _unavailable(source: str) -> ErrorDetail:
    code, message = _UNAVAILABLE[source]
    return ErrorDetail(ErrorCategory.SOURCE_FAILED, code, message)


def _check_model(source: str, value: object) -> ErrorDetail | None:
    """Проверить тип ответа и повторно проверить модель по её снимку."""
    code, model_type, validate, type_message, data_message = _INVALID[source]
    if type(value) is not model_type:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, type_message)
    try:
        validate(value)
    except _DOMAIN_ERRORS as error:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, data_message, reason=error.code.value)
    except Exception:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, type_message)
    return None


class InspectKeeneticStateHandler:
    """Прочитать четыре источника раздельно и собрать согласованное состояние.

    Источники вызываются по одному разу в фиксированном порядке: политики,
    настройки hotspot, регистрация, runtime. Отказ или некорректный ответ
    любого из них завершает сценарий отдельным кодом; частичного результата нет.
    Успех описывает снимок на момент чтения, а не работу VPN или маршрут клиента.
    """

    def __init__(
        self,
        policies: KeeneticPolicySource,
        hotspot: KeeneticHotspotSettingsSource,
        registrations: KeeneticRegistrationSource,
        runtime: KeeneticHotspotRuntimeSource,
        *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._policies = policies
        self._hotspot = hotspot
        self._registrations = registrations
        self._runtime = runtime
        self._operation_ids = operation_ids

    def execute(self, command: InspectKeeneticState) -> Result[KeeneticStateView]:
        """Выполнить чтение; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = InspectKeeneticState.name
        if type(command) is not InspectKeeneticState:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)

        try:
            policies = self._policies.current_policies()
        except Exception:
            # Текст и цепочка исключения адаптера могут содержать описания политик.
            return failed(operation_id, name, _unavailable("policies"))
        error = check_policies(policies)
        if error is not None:
            return failed(operation_id, name, error)

        models = {}
        for source, read in (
            ("hotspot", self._hotspot.current_hotspot_settings),
            ("registrations", self._registrations.current_registrations),
            ("runtime", self._runtime.current_hotspot_runtime),
        ):
            try:
                value = read()
            except Exception:
                # Ответ и исключение источника могут содержать MAC, имена и адреса.
                return failed(operation_id, name, _unavailable(source))
            error = _check_model(source, value)
            if error is not None:
                return failed(operation_id, name, error)
            models[source] = value

        try:
            state = assemble_keenetic_state(policies, models["hotspot"], models["registrations"], models["runtime"])
        except _DOMAIN_ERRORS as error:
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, "keenetic_state_inconsistent",
                "Прочитанные источники Keenetic не удалось согласовать.", reason=error.code.value,
            ))
        return succeeded(operation_id, name, KeeneticStateView.from_state(state))
