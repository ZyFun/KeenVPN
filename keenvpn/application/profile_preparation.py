"""Сборка общего профиля в памяти без сохранения и изменения конфигурации."""

from typing import NoReturn

from keenvpn.application.connections import link_rejection_detail
from keenvpn.application.contract import ErrorCategory, ErrorDetail
from keenvpn.application.ports import ConnectionLinkRejected
from keenvpn.application.protocol_registry import ProtocolCapability, ProtocolRegistry, RegistryError
from keenvpn.application.protocol_support import registry_error_detail
from keenvpn.domain.connection import SecretValue
from keenvpn.domain.profile import (
    PROFILE_FORMAT_VERSION, ConnectionProfile, ProfileIdentity, ProfileParameters,
    ProfileValidationError, validate_profile_identity,
)


class ProfilePreparationError(ValueError):
    """Безопасный отказ сборки; не содержит исходной модели или URI."""

    def __init__(self, detail: ErrorDetail) -> None:
        self.detail = detail
        super().__init__(detail.message)


def _reject(detail: ErrorDetail) -> NoReturn:
    """Создать новый отказ без цепочки и кадров внутренних операций."""
    try:
        raise ProfilePreparationError(detail) from None
    except ProfilePreparationError as error:
        error.__context__ = None
        raise


def _error_detail(error: Exception) -> ErrorDetail:
    """Сохранить известные коды; заменить непредвиденный отказ статическим."""
    if type(error) is ProfilePreparationError:
        return error.detail
    if type(error) is ProfileValidationError:
        return ErrorDetail(
            ErrorCategory.INVALID_INPUT, "invalid_profile_model",
            "Некорректная структура профиля подключения.", reason=error.code.value,
        )
    if type(error) is RegistryError:
        return registry_error_detail(error.code)
    if type(error) is ConnectionLinkRejected:
        return link_rejection_detail(error)
    return ErrorDetail(
        ErrorCategory.SOURCE_FAILED, "profile_preparation_failed",
        "Не удалось подготовить профиль подключения.",
    )


class ConnectionProfileFactory:
    """Общая сборка через доверенный реестр, без ветвлений по протоколу.

    Приватный профиль предназначен только для внутреннего кода. Интерфейс
    получает безопасное представление через сценарии application. ID и имя
    назначаются явно; имя из URI не копируется в идентичность автоматически.
    """

    def __init__(self, protocols: ProtocolRegistry) -> None:
        self._protocols = protocols

    def from_parameters(
        self, identity: ProfileIdentity, parameters: ProfileParameters,
    ) -> ConnectionProfile:
        """Обернуть готовую модель без копирования, валидации протокольных
        значений и вызова парсера. Неизвестная версия остаётся непрозрачной.
        """
        try:
            return self._wrap(identity, parameters)
        except Exception as error:
            detail = _error_detail(error)
        del identity, parameters
        _reject(detail)

    def from_link(self, identity: ProfileIdentity, link: SecretValue) -> ConnectionProfile:
        """Разобрать URI выбранным модулем и собрать профиль поддержанной версии."""
        parameters = None
        try:
            self._check_identity(identity)
            if identity.format_version != PROFILE_FORMAT_VERSION:
                _reject(ErrorDetail(
                    ErrorCategory.UNSUPPORTED, "unsupported_profile_format_version",
                    "Версия формата профиля не поддерживается для разбора ссылки.",
                ))
            if type(link) is not SecretValue or type(link.reveal()) is not str:
                _reject(ErrorDetail(
                    ErrorCategory.INVALID_INPUT, "invalid_profile_link",
                    "Ссылка должна быть передана как секретная строка.",
                ))
            module = self._protocols.by_protocol(identity.protocol)
            self._protocols.require(module, ProtocolCapability.PARSE_URI)
            parameters = module.parse_uri(link.reveal())
            return self._wrap(identity, parameters)
        except Exception as error:
            detail = _error_detail(error)
        # Новый отказ не удерживает исходные кадры парсера и приватные аргументы.
        del identity, link, parameters
        _reject(detail)

    def _check_identity(self, identity: ProfileIdentity) -> None:
        if type(identity) is not ProfileIdentity:
            _reject(ErrorDetail(
                ErrorCategory.INVALID_INPUT, "invalid_profile_identity",
                "Ожидается идентичность профиля подключения.",
            ))
        validate_profile_identity(identity)

    def _wrap(self, identity: ProfileIdentity, parameters: ProfileParameters) -> ConnectionProfile:
        self._check_identity(identity)
        if identity.format_version == PROFILE_FORMAT_VERSION:
            module = self._protocols.by_protocol(identity.protocol)
            if not isinstance(parameters, module.parameters_type):
                _reject(ErrorDetail(
                    ErrorCategory.INVALID_SOURCE_DATA, "invalid_connection_model",
                    "Параметры не соответствуют зарегистрированной модели протокола.",
                ))
        try:
            return ConnectionProfile(identity, parameters)
        except ProfileValidationError as error:
            detail = ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, "invalid_connection_model",
                "Параметры не соответствуют общей структуре профиля.", reason=error.code.value,
            )
        _reject(detail)
