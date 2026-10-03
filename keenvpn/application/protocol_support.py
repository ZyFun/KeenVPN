"""Проверка доступности протокола и операции без выполнения операции."""

from dataclasses import dataclass
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.protocol_registry import (
    EngineCapability, EngineRegistry, ProtocolCapability, ProtocolField,
    ProtocolRegistry, RegistryError, RegistryErrorCode,
)
from keenvpn.domain.connection import SecretValue


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class InspectProtocolSupport:
    """Указать ровно один источник выбора: тип профиля либо секретную URI.

    Для операции движка обязательно явно указать engine и engine_capability.
    Ссылка служит только селектором модуля; её корректность не проверяется.
    """

    name: ClassVar[str] = "inspect_protocol_support"
    protocol: str | None = None
    uri: SecretValue | None = None
    capability: ProtocolCapability | None = None
    engine: str | None = None
    engine_capability: EngineCapability | None = None
    contract_version: int = CONTRACT_VERSION

    def __repr__(self) -> str:
        return "InspectProtocolSupport(<скрытый выбор>)"


@dataclass(frozen=True, slots=True)
class ProtocolSupportView:
    """Только метаданные из поставки; без URI, модели и вызываемых объектов."""

    protocol: str
    uri_schemes: tuple[str, ...]
    capabilities: tuple[str, ...]
    fields: tuple[ProtocolField, ...]
    engine: str | None
    engine_capability: str | None

    def to_dict(self) -> dict[str, object]:
        """Вернуть статические сведения о возможностях в формате JSON."""
        return {
            "protocol": self.protocol,
            "uri_schemes": list(self.uri_schemes),
            "capabilities": list(self.capabilities),
            "fields": [
                {"name": field.name, "secret": field.secret, "required": field.required}
                for field in self.fields
            ],
            "engine": self.engine,
            "engine_capability": self.engine_capability,
        }


class InspectProtocolSupportHandler:
    """Выбрать доверенный модуль и отдельно проверить операцию движка.

    Успех подтверждает только наличие обработчиков в переданном составе
    поставки, а не валидность URI, профиля, окружения или рабочий VPN.
    """

    def __init__(
        self, protocols: ProtocolRegistry, engines: EngineRegistry | None = None,
        *, operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._protocols = protocols
        self._engines = engines if engines is not None else EngineRegistry()
        self._operation_ids = operation_ids

    def execute(self, command: InspectProtocolSupport) -> Result[ProtocolSupportView]:
        """Вернуть метаданные или статический отказ, не вызывая адаптеры."""
        operation_id = self._operation_ids()
        name = InspectProtocolSupport.name
        if type(command) is not InspectProtocolSupport:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        if (
            (command.protocol is None) == (command.uri is None)
            or (command.protocol is not None and type(command.protocol) is not str)
            or (command.uri is not None and (
                type(command.uri) is not SecretValue or type(command.uri.reveal()) is not str
            ))
            or (command.capability is not None and type(command.capability) is not ProtocolCapability)
            or (command.engine is None) != (command.engine_capability is None)
            or (command.engine is not None and type(command.engine) is not str)
            or (command.engine_capability is not None and type(command.engine_capability) is not EngineCapability)
        ):
            return failed(operation_id, name, invalid_command())
        try:
            module = (
                self._protocols.by_protocol(command.protocol) if command.protocol is not None
                else self._protocols.by_uri(command.uri.reveal())
            )
            if command.capability is not None:
                self._protocols.require(module, command.capability)
            binding = None
            if command.engine is not None:
                binding = self._engines.resolve(command.engine, module.protocol, command.engine_capability)
            view = ProtocolSupportView(
                protocol=module.protocol, uri_schemes=module.uri_schemes,
                capabilities=tuple(sorted(capability.value for capability in module.capabilities)),
                fields=module.fields, engine=None if binding is None else binding.engine,
                engine_capability=None if binding is None else command.engine_capability.value,
            )
        except RegistryError as rejection:
            error = registry_error_detail(rejection.code)
        except Exception:
            error = ErrorDetail(
                ErrorCategory.SOURCE_FAILED, "registry_failed",
                "Не удалось прочитать реестр возможностей.",
            )
        else:
            return succeeded(operation_id, name, view)
        return failed(operation_id, name, error)


def registry_error_detail(code: RegistryErrorCode) -> ErrorDetail:
    """Не переносить текст исключения или произвольный код в результат."""
    messages = {
        RegistryErrorCode.INVALID_SELECTOR: "Некорректный идентификатор или схема ссылки.",
        RegistryErrorCode.INVALID_ENGINE_SELECTOR: "Некорректный идентификатор движка.",
        RegistryErrorCode.UNKNOWN_PROTOCOL: "Протокол не зарегистрирован.",
        RegistryErrorCode.UNKNOWN_SCHEME: "Схема ссылки не зарегистрирована.",
        RegistryErrorCode.PROTOCOL_CAPABILITY: "Операция протокола не поддерживается.",
        RegistryErrorCode.UNKNOWN_ENGINE: "Движок не зарегистрирован.",
        RegistryErrorCode.ENGINE_PROTOCOL: "Движок не поддерживает выбранный протокол.",
        RegistryErrorCode.ENGINE_CAPABILITY: "Операция движка для выбранного протокола не поддерживается.",
    }
    if type(code) is not RegistryErrorCode or code not in messages:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_registry_data",
            "Реестр вернул данные в неподдерживаемом формате.",
        )
    category = (
        ErrorCategory.INVALID_INPUT
        if code in (RegistryErrorCode.INVALID_SELECTOR, RegistryErrorCode.INVALID_ENGINE_SELECTOR)
        else ErrorCategory.UNSUPPORTED
    )
    return ErrorDetail(category, code.value, messages[code])
