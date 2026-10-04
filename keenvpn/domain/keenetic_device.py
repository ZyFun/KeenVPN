"""Запись устройства и смена назначения в памяти с сохранением остальных данных."""

from dataclasses import dataclass, field
from enum import StrEnum
import json
import math
import re
from typing import NoReturn

from keenvpn.domain.keenetic_policy import (
    KeeneticPolicySet, valid_policy_id, validate_policy_set,
)


class KeeneticDeviceErrorCode(StrEnum):
    """Причины отказа без MAC, адресов, имён и значений неизвестных полей."""

    DATA = "invalid_device_data"
    MAC = "invalid_device_mac"
    ASSIGNMENT = "invalid_device_assignment"
    READ_ONLY = "device_read_only"
    POLICY_MISSING = "device_policy_missing"
    POLICIES = "invalid_device_policies"
    INVENTORY = "invalid_device_inventory"
    MISSING = "device_missing"
    AMBIGUOUS = "device_ambiguous"


_MESSAGES = {
    KeeneticDeviceErrorCode.DATA: "Запись устройства должна содержать только поддерживаемые JSON-данные.",
    KeeneticDeviceErrorCode.MAC: "MAC записи устройства имеет недопустимый формат.",
    KeeneticDeviceErrorCode.ASSIGNMENT: "Назначение политики устройства имеет недопустимый формат.",
    KeeneticDeviceErrorCode.READ_ONLY: "Неоднозначные или неподдерживаемые настройки устройства доступны только для просмотра.",
    KeeneticDeviceErrorCode.POLICY_MISSING: "Выбранной политики нет в переданном списке политик.",
    KeeneticDeviceErrorCode.POLICIES: "Передан некорректный список политик устройства.",
    KeeneticDeviceErrorCode.INVENTORY: "Передан некорректный список записей устройств.",
    KeeneticDeviceErrorCode.MISSING: "Выбранной записи нет в переданном списке устройств.",
    KeeneticDeviceErrorCode.AMBIGUOUS: "В списке несколько записей с выбранным MAC; автоматический выбор запрещён.",
}


class KeeneticDeviceError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: KeeneticDeviceErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: KeeneticDeviceErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise KeeneticDeviceError(code) from None
    except KeeneticDeviceError as error:
        error.__context__ = None
        raise


@dataclass(frozen=True, slots=True, repr=False)
class DeviceIdentity:
    """Ключ записи одного MAC, не идентификатор физического устройства.

    Регистр не влияет на равенство ключей. Исходная запись при этом сохраняет
    свой MAC без изменений. Поле mac приватно по назначению, не для журнала.
    """

    mac: str

    def __post_init__(self) -> None:
        if type(self.mac) is not str or re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", self.mac) is None:
            _raise_detached(KeeneticDeviceErrorCode.MAC)
        object.__setattr__(self, "mac", self.mac.lower())

    def __repr__(self) -> str:
        return "DeviceIdentity(<скрыто>)"


class DevicePresence(StrEnum):
    """Активность в переданном наблюдении, не результат сетевой проверки."""

    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class DevicePolicyMode(StrEnum):
    """Отсутствие назначения не означает наследование или прямой доступ."""

    EXPLICIT = "explicit"
    INHERIT = "inherit"
    UNASSIGNED = "unassigned"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, repr=False)
class DevicePolicyAssignment:
    """Назначение отдельно от разрешения доступа; UNKNOWN служит для чтения."""

    mode: DevicePolicyMode
    policy_id: str | None = None

    def __post_init__(self) -> None:
        valid = type(self.mode) is DevicePolicyMode
        if self.mode is DevicePolicyMode.EXPLICIT:
            valid = valid and valid_policy_id(self.policy_id)
        else:
            valid = valid and self.policy_id is None
        if not valid:
            _raise_detached(KeeneticDeviceErrorCode.ASSIGNMENT)

    def __repr__(self) -> str:
        return f"DevicePolicyAssignment(mode={self.mode.value})"


def _validate_json(value: object, depth: int = 0) -> None:
    """Отклонить циклы, глубокие структуры и объекты с пользовательскими хуками.

    Граница 64 относится к вложенности, а не числу полей. Строки, порядок
    массивов/полей и неизвестные JSON-значения не нормализуются.
    """
    if depth > 64:
        _raise_detached(KeeneticDeviceErrorCode.DATA)
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _validate_json(item, depth + 1)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _validate_json(item, depth + 1)
        return
    _raise_detached(KeeneticDeviceErrorCode.DATA)


def _assignment(settings: dict[str, object]) -> DevicePolicyAssignment:
    """Разобрать только сохранённое назначение, не вычислять его по runtime."""
    policy = settings.get("policy")
    conform = settings.get("conform", False)
    if ("policy" in settings and type(policy) is not str) or type(conform) is not bool:
        return DevicePolicyAssignment(DevicePolicyMode.UNKNOWN)
    if policy:
        if conform or not valid_policy_id(policy):
            return DevicePolicyAssignment(DevicePolicyMode.UNKNOWN)
        return DevicePolicyAssignment(DevicePolicyMode.EXPLICIT, policy)
    return DevicePolicyAssignment(DevicePolicyMode.INHERIT if conform else DevicePolicyMode.UNASSIGNED)


def _access_supported(settings: dict[str, object]) -> bool:
    """Не редактировать неизвестный или противоречивый режим доступа."""
    access = settings.get("access")
    if "access" in settings and (type(access) is not str or access not in ("permit", "deny")):
        return False
    if any(key in settings and type(settings[key]) is not bool for key in ("permit", "deny")):
        return False
    # Отсутствующий флаг не отрицает access; явный false может ему противоречить.
    deny, permit = settings.get("deny"), settings.get("permit")
    if deny is True and permit is True:
        return False
    if access == "deny":
        return deny is not False and permit is not True
    if access == "permit":
        return permit is not False and deny is not True
    return True


@dataclass(frozen=True, slots=True, init=False, repr=False)
class KeeneticDevice:
    """Приватная запись: сохранённые настройки и сопутствующие данные.

    `settings` — полный объект настроек одного MAC. `details` — отдельные
    данные имени/регистрации/адресов/наблюдения, которые вызывающий код уже
    сопоставил с записью. Они не участвуют в определении назначения.
    Модель не объединяет источники и устройства и не обращается к RCI.

    Внутри хранится JSON-снимок, а export() возвращает новую глубокую копию.
    Это изоляция от мутаций, не шифрование. export(), asdict() и содержимое
    кадров исключения не подходят для журналов; используйте to_diagnostic().
    """

    _snapshot: str = field(repr=False)

    def __init__(self, settings: dict[str, object], *, details: dict[str, object] | None = None) -> None:
        if type(settings) is not dict or (details is not None and type(details) is not dict):
            _raise_detached(KeeneticDeviceErrorCode.DATA)
        data = {"settings": settings, "details": {} if details is None else details}
        _validate_json(data)
        mac = settings.get("mac")
        DeviceIdentity(mac)
        # Не нормализуем даже регистр MAC и не теряем отсутствие/пустоту поля.
        snapshot = None
        try:
            snapshot = json.dumps(data, ensure_ascii=True, allow_nan=False)
        except (ValueError, TypeError, RecursionError):
            # Например, целое за пределами ограничения десятичной сериализации.
            pass
        if snapshot is None:
            _raise_detached(KeeneticDeviceErrorCode.DATA)
        object.__setattr__(self, "_snapshot", snapshot)

    def __repr__(self) -> str:
        return "KeeneticDevice(<скрыто>)"

    def export(self) -> dict[str, object]:
        """Получить приватные данные для доверенного кода, не для вывода."""
        return json.loads(self._snapshot)

    @property
    def identity(self) -> DeviceIdentity:
        """Сравнивать записи по MAC, независимо от имени, IP и активности."""
        return DeviceIdentity(self.export()["settings"]["mac"])

    def _matched_observation(self) -> dict[str, object]:
        """Использовать наблюдение только при явно совпадающем MAC."""
        data = self.export()
        observation = data["details"].get("observation")
        if type(observation) is dict:
            mac = observation.get("mac")
            if type(mac) is str and mac.lower() == data["settings"]["mac"].lower():
                return observation
        return {}

    @property
    def observation_mismatch(self) -> bool:
        """Явный строковый MAC наблюдения отличается от MAC записи.

        Отсутствующий или нестроковый MAC не даёт основания для сравнения.
        False не подтверждает корректность или наличие наблюдения.
        """
        data = self.export()
        observation = data["details"].get("observation")
        if type(observation) is not dict:
            return False
        mac = observation.get("mac")
        return type(mac) is str and mac.lower() != data["settings"]["mac"].lower()

    @property
    def presence(self) -> DevicePresence:
        """Не заменять отсутствие или неизвестный формат active состоянием offline."""
        active = self._matched_observation().get("active")
        if type(active) is not bool:
            return DevicePresence.UNKNOWN
        return DevicePresence.ONLINE if active else DevicePresence.OFFLINE

    @property
    def observed_interface_id(self) -> str | None:
        """Приватный ID интерфейса роутера; не тип и не ID интерфейса клиента."""
        interface = self._matched_observation().get("interface")
        if type(interface) is dict:
            interface_id = interface.get("id")
            if type(interface_id) is str and interface_id.strip():
                return interface_id
        return None

    @property
    def assignment(self) -> DevicePolicyAssignment:
        """Сохранённое назначение; runtime policy в details не используется."""
        return _assignment(self.export()["settings"])

    @property
    def read_only(self) -> bool:
        """Не разрешать изменение неизвестной семантики назначения или доступа."""
        settings = self.export()["settings"]
        return _assignment(settings).mode is DevicePolicyMode.UNKNOWN or not _access_supported(settings)

    def to_diagnostic(self) -> dict[str, str | bool]:
        """Безопасное представление без MAC, имён, адресов и свободного текста."""
        settings = self.export()["settings"]
        assignment = _assignment(settings)
        return {
            "assignment": assignment.mode.value,
            "read_only": assignment.mode is DevicePolicyMode.UNKNOWN or not _access_supported(settings),
            "access_denied": settings.get("access") == "deny" or settings.get("deny") is True,
            "observation_mismatch": self.observation_mismatch,
        }

    def with_assignment(
        self, assignment: DevicePolicyAssignment, *, policies: KeeneticPolicySet,
    ) -> "KeeneticDevice":
        """Вернуть новую модель, изменив только policy/conform; ничего не применять.

        Явный ID должен существовать в переданном текущем списке политик.
        Разрешение доступа, неизвестные поля и details сохраняются целиком.
        Повтор того же назначения сохраняет даже исходную форму полей.
        """
        if type(assignment) is not DevicePolicyAssignment:
            _raise_detached(KeeneticDeviceErrorCode.ASSIGNMENT)
        # Проверка готовых объектов не вызывает переопределяемые хуки.
        target = DevicePolicyAssignment(assignment.mode, assignment.policy_id)
        if target.mode is DevicePolicyMode.UNKNOWN:
            _raise_detached(KeeneticDeviceErrorCode.ASSIGNMENT)
        if self.read_only:
            _raise_detached(KeeneticDeviceErrorCode.READ_ONLY)
        valid = False
        if type(policies) is KeeneticPolicySet:
            try:
                validate_policy_set(policies)
                valid = True
            except Exception:
                pass
        if not valid:
            _raise_detached(KeeneticDeviceErrorCode.POLICIES)
        if target.mode is DevicePolicyMode.EXPLICIT and target.policy_id not in policies.policy_ids:
            _raise_detached(KeeneticDeviceErrorCode.POLICY_MISSING)
        if target == self.assignment:
            return self
        data = self.export()
        settings = data["settings"]
        settings.pop("policy", None)
        settings.pop("conform", None)
        if target.mode is DevicePolicyMode.EXPLICIT:
            settings["policy"] = target.policy_id
        elif target.mode is DevicePolicyMode.INHERIT:
            settings["conform"] = True
        return KeeneticDevice(settings, details=data["details"])


@dataclass(frozen=True, slots=True, repr=False)
class KeeneticDeviceInventory:
    """Записи одного источника без слияния, удаления offline и переноса настроек.

    Повторяющиеся MAC сохраняются для просмотра, но выбрать такой MAC нельзя.
    Список не сопоставляет разные источники и не определяет приватность MAC.
    """

    devices: tuple[KeeneticDevice, ...]

    def __post_init__(self) -> None:
        if type(self.devices) is not tuple or any(type(device) is not KeeneticDevice for device in self.devices):
            _raise_detached(KeeneticDeviceErrorCode.INVENTORY)

    def __repr__(self) -> str:
        return f"KeeneticDeviceInventory(count={len(self.devices)})"

    def select(self, mac: str) -> KeeneticDevice:
        """Выбрать единственную запись по MAC без предпочтения активной записи."""
        identity = DeviceIdentity(mac)
        matches = tuple(device for device in self.devices if device.identity == identity)
        if not matches:
            _raise_detached(KeeneticDeviceErrorCode.MISSING)
        if len(matches) != 1:
            _raise_detached(KeeneticDeviceErrorCode.AMBIGUOUS)
        return matches[0]

    def to_diagnostic(self) -> dict[str, int]:
        """Безопасные счётчики без MAC, имён, адресов и интерфейсов."""
        return {
            "record_count": len(self.devices),
            "distinct_mac_count": len({device.identity for device in self.devices}),
            "online_count": sum(device.presence is DevicePresence.ONLINE for device in self.devices),
            "offline_count": sum(device.presence is DevicePresence.OFFLINE for device in self.devices),
            "unknown_count": sum(device.presence is DevicePresence.UNKNOWN for device in self.devices),
            "observation_mismatch_count": sum(device.observation_mismatch for device in self.devices),
        }
