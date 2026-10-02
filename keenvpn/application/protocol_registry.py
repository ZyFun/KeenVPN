"""Явная регистрация доверенного кода; пользовательский ввод только выбирает его.

Реестр не является песочницей для Python. Состав задаётся кодом сборки из
поставки, а не настройками, URI, именами импортов или обнаружением плагинов.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
import re
from types import MappingProxyType
from typing import NoReturn

from keenvpn.domain.profile import ProfileParameters, valid_protocol_id


class ProtocolCapability(StrEnum):
    """Локальные операции с параметрами, независимые от движка."""

    PARSE_URI = "parse_uri"
    VALIDATE_PARAMETERS = "validate_parameters"


class EngineCapability(StrEnum):
    """Операции адаптера движка; наличие регистрации не означает их выполнение."""

    GENERATE_CONFIG = "generate_config"
    CHECK_CONFIG = "check_config"
    PROBE = "probe"
    START = "start"
    STOP = "stop"


class RegistryErrorCode(StrEnum):
    """Статические причины отказа выбора без копирования входа."""

    INVALID_SELECTOR = "invalid_protocol_selector"
    INVALID_ENGINE_SELECTOR = "invalid_engine_selector"
    UNKNOWN_PROTOCOL = "unknown_protocol"
    UNKNOWN_SCHEME = "unknown_uri_scheme"
    PROTOCOL_CAPABILITY = "unsupported_protocol_capability"
    UNKNOWN_ENGINE = "unknown_engine"
    ENGINE_PROTOCOL = "unsupported_engine_protocol"
    ENGINE_CAPABILITY = "unsupported_engine_capability"
    INVALID_REGISTRATION = "invalid_registration"
    DUPLICATE_PROTOCOL = "duplicate_protocol"
    DUPLICATE_SCHEME = "duplicate_uri_scheme"
    DUPLICATE_ENGINE = "duplicate_engine_binding"


class RegistryError(ValueError):
    """Отказ без исходного идентификатора, ссылки или объекта регистрации."""

    def __init__(self, code: RegistryErrorCode) -> None:
        self.code = code
        super().__init__("Не удалось выбрать зарегистрированную возможность.")


def _reject(code: RegistryErrorCode) -> NoReturn:
    """Не удерживать внешнюю цепочку исключений, способную содержать секрет."""
    try:
        raise RegistryError(code) from None
    except RegistryError as error:
        error.__context__ = None
        raise


def valid_identifier(value: object) -> bool:
    """Проверить идентификатор движка или поля без преобразований."""
    return type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value) is not None


def _uri_scheme(uri: str) -> str | None:
    """Извлечь схему без исключения: этот кадр не входит в traceback отказа."""
    match = re.match(r"([A-Za-z][A-Za-z0-9+.-]{0,31})://", uri)
    return None if match is None else match[1].lower()


@dataclass(frozen=True, slots=True)
class ProtocolField:
    """Статическое описание поля формы, без текущего значения и default."""

    name: str
    secret: bool
    required: bool

    def __post_init__(self) -> None:
        if not valid_identifier(self.name) or type(self.secret) is not bool or type(self.required) is not bool:
            _reject(RegistryErrorCode.INVALID_REGISTRATION)


@dataclass(frozen=True, slots=True, repr=False)
class ProtocolModule[ParametersT: ProfileParameters]:
    """Доверенная модель и её доступные операции.

    Возможности вычисляются по наличию обработчиков: отдельный валидатор
    не заявляется только потому, что парсер проверяет входную ссылку.
    Метаданные поставки должны содержать лишь открытые статические имена.
    """

    protocol: str
    uri_schemes: tuple[str, ...]
    parameters_type: type[ParametersT]
    fields: tuple[ProtocolField, ...]
    parse_uri: Callable[[str], ParametersT] | None = None
    validate_parameters: Callable[[ParametersT], None] | None = None

    def __post_init__(self) -> None:
        if (
            not valid_protocol_id(self.protocol)
            or type(self.uri_schemes) is not tuple
            or any(type(s) is not str or re.fullmatch(r"[a-z][a-z0-9+.-]{0,31}", s) is None for s in self.uri_schemes)
            or len(set(self.uri_schemes)) != len(self.uri_schemes)
            or not isinstance(self.parameters_type, type)
            or type(self.fields) is not tuple
            or any(type(field) is not ProtocolField for field in self.fields)
            or len({field.name for field in self.fields}) != len(self.fields)
            or (self.parse_uri is not None and not callable(self.parse_uri))
            or (self.validate_parameters is not None and not callable(self.validate_parameters))
            or (self.parse_uri is not None and not self.uri_schemes)
        ):
            _reject(RegistryErrorCode.INVALID_REGISTRATION)

    @property
    def capabilities(self) -> frozenset[ProtocolCapability]:
        """Показать только операции с явно переданными обработчиками."""
        return frozenset(
            capability for capability, handler in (
                (ProtocolCapability.PARSE_URI, self.parse_uri),
                (ProtocolCapability.VALIDATE_PARAMETERS, self.validate_parameters),
            ) if handler is not None
        )

    def __repr__(self) -> str:
        return "ProtocolModule(<доверенный модуль>)"


@dataclass(frozen=True, slots=True, repr=False)
class EngineBinding:
    """Один движок для одного протокола и явные обработчики его операций.

    Сигнатура и требования запуска каждого обработчика принадлежат адаптеру.
    Выбор никогда не вызывает обработчик и не меняет состояние движка.
    """

    engine: str
    protocol: str
    operations: tuple[tuple[EngineCapability, Callable], ...]

    def __post_init__(self) -> None:
        if (
            not valid_identifier(self.engine) or not valid_protocol_id(self.protocol)
            or type(self.operations) is not tuple or not self.operations
            or any(
                type(item) is not tuple or len(item) != 2
                or type(item[0]) is not EngineCapability or not callable(item[1])
                for item in self.operations
            )
            or len({item[0] for item in self.operations}) != len(self.operations)
        ):
            _reject(RegistryErrorCode.INVALID_REGISTRATION)

    def operation(self, capability: EngineCapability) -> Callable:
        """Выбрать обработчик без запуска и без подстановки другой операции."""
        if type(capability) is not EngineCapability:
            _reject(RegistryErrorCode.INVALID_SELECTOR)
        for name, handler in self.operations:
            if name is capability:
                return handler
        _reject(RegistryErrorCode.ENGINE_CAPABILITY)

    def __repr__(self) -> str:
        return "EngineBinding(<доверенный адаптер>)"


class ProtocolRegistry:
    """Снимок явного состава поставки, без регистрации из пользовательских данных."""

    def __init__(self, modules: tuple[ProtocolModule, ...]) -> None:
        if type(modules) is not tuple or any(type(module) is not ProtocolModule for module in modules):
            _reject(RegistryErrorCode.INVALID_REGISTRATION)
        protocols, schemes = {}, {}
        for module in modules:
            if module.protocol in protocols:
                _reject(RegistryErrorCode.DUPLICATE_PROTOCOL)
            protocols[module.protocol] = module
            for scheme in module.uri_schemes:
                if scheme in schemes:
                    _reject(RegistryErrorCode.DUPLICATE_SCHEME)
                schemes[scheme] = module
        self._protocols = MappingProxyType(protocols)
        self._schemes = MappingProxyType(schemes)

    def by_protocol(self, protocol: str) -> ProtocolModule:
        """Выбрать точный тип профиля; не нормализовать неизвестные имена."""
        if not valid_protocol_id(protocol):
            _reject(RegistryErrorCode.INVALID_SELECTOR)
        module = self._protocols.get(protocol)
        if module is None:
            _reject(RegistryErrorCode.UNKNOWN_PROTOCOL)
        return module

    def by_uri(self, uri: str) -> ProtocolModule:
        """Прочитать только схему; тело URI проверяет выбранный парсер.

        Схема ASCII нечувствительна к регистру. Percent-decoding, импорт,
        чтение файлов и сетевые обращения при выборе не выполняются.
        """
        scheme = _uri_scheme(uri) if type(uri) is str else None
        # Отказ ниже не должен удерживать исходную ссылку в собственном кадре.
        del uri
        if scheme is None:
            _reject(RegistryErrorCode.INVALID_SELECTOR)
        module = self._schemes.get(scheme)
        # Неизвестная схема тоже может оказаться приватным вводом.
        del scheme
        if module is None:
            _reject(RegistryErrorCode.UNKNOWN_SCHEME)
        return module

    def require(self, module: ProtocolModule, capability: ProtocolCapability) -> None:
        """Проверить возможность выбранного именно из этого реестра модуля."""
        if type(capability) is not ProtocolCapability or type(module) is not ProtocolModule:
            _reject(RegistryErrorCode.INVALID_SELECTOR)
        if self._protocols.get(module.protocol) is not module:
            _reject(RegistryErrorCode.UNKNOWN_PROTOCOL)
        if capability not in module.capabilities:
            _reject(RegistryErrorCode.PROTOCOL_CAPABILITY)


class EngineRegistry:
    """Независимый выбор движка по явному ID, протоколу и операции."""

    def __init__(self, bindings: tuple[EngineBinding, ...] = ()) -> None:
        if type(bindings) is not tuple or any(type(binding) is not EngineBinding for binding in bindings):
            _reject(RegistryErrorCode.INVALID_REGISTRATION)
        entries = {}
        for binding in bindings:
            key = (binding.engine, binding.protocol)
            if key in entries:
                _reject(RegistryErrorCode.DUPLICATE_ENGINE)
            entries[key] = binding
        self._bindings = MappingProxyType(entries)
        self._engines = frozenset(binding.engine for binding in bindings)

    def resolve(self, engine: str, protocol: str, capability: EngineCapability) -> EngineBinding:
        """Отклонить неизвестный движок, сочетание или операцию без fallback."""
        if not valid_identifier(engine):
            _reject(RegistryErrorCode.INVALID_ENGINE_SELECTOR)
        if not valid_protocol_id(protocol) or type(capability) is not EngineCapability:
            _reject(RegistryErrorCode.INVALID_SELECTOR)
        if engine not in self._engines:
            _reject(RegistryErrorCode.UNKNOWN_ENGINE)
        binding = self._bindings.get((engine, protocol))
        if binding is None:
            _reject(RegistryErrorCode.ENGINE_PROTOCOL)
        binding.operation(capability)
        return binding
