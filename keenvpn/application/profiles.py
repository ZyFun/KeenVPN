"""Просмотр общей структуры профиля по стабильному ID без изменения источника."""

from dataclasses import KW_ONLY, dataclass
from typing import ClassVar
from uuid import UUID

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import ConnectionProfileSource
from keenvpn.domain.profile import (
    PROFILE_FORMAT_VERSION, ConnectionProfile, ProfileValidationError, validate_profile,
)


@dataclass(frozen=True, slots=True, repr=False)
class InspectConnectionProfile:
    """Прочитать профиль по ID; имя и адрес подключения ключом не являются."""

    name: ClassVar[str] = "inspect_connection_profile"

    profile_id: UUID
    _: KW_ONLY
    contract_version: int = CONTRACT_VERSION

    def __repr__(self) -> str:
        return "InspectConnectionProfile(<скрыто>)"


@dataclass(frozen=True, slots=True)
class ConnectionProfileView:
    """Идентификатор и общая структура без имени и параметров подключения."""

    profile_id: str
    protocol: str
    format_version: int
    has_name: bool

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление без исходной модели."""
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class InspectConnectionProfileHandler:
    """Прочитать и проверить оболочку профиля, не проверяя работоспособность VPN."""

    def __init__(
        self, source: ConnectionProfileSource, *, operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._source = source
        self._operation_ids = operation_ids

    def execute(self, command: InspectConnectionProfile) -> Result[ConnectionProfileView]:
        """Один запрос к источнику; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = InspectConnectionProfile.name
        if type(command) is not InspectConnectionProfile or type(command.profile_id) is not UUID:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        if command.profile_id.int == 0:
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.INVALID_INPUT, "invalid_profile_id",
                "Пустой идентификатор профиля недопустим.",
            ))
        try:
            profile = self._source.get_profile(command.profile_id)
        except Exception:
            # Текст и цепочка ошибки источника могут содержать приватный профиль.
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.SOURCE_FAILED, "profile_source_failed",
                "Не удалось прочитать профиль подключения.",
            ))
        if profile is None:
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.INVALID_INPUT, "profile_not_found",
                "Профиль с указанным идентификатором не найден.",
            ))
        error = _check_profile(profile, command.profile_id)
        if error is not None:
            return failed(operation_id, name, error)
        return succeeded(operation_id, name, ConnectionProfileView(**profile.to_diagnostic()))


def _check_profile(profile: object, requested_id: UUID) -> ErrorDetail | None:
    """Проверить ответ источника до построения безопасного представления."""
    if type(profile) is not ConnectionProfile:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_profile_model",
            "Источник вернул данные в неподдерживаемом формате.",
        )
    try:
        # Повторная проверка ловит повреждённые данные и изменённые параметры.
        # Методы подклассов источника не участвуют в построении представления.
        validate_profile(profile)
        if profile.identity.format_version != PROFILE_FORMAT_VERSION:
            return ErrorDetail(
                ErrorCategory.UNSUPPORTED, "unsupported_profile_format_version",
                "Версия формата профиля не поддерживается.",
            )
    except ProfileValidationError as error:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_profile_model",
            "Источник вернул некорректную структуру профиля.", reason=error.code.value,
        )
    except Exception:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_profile_model",
            "Источник вернул данные в неподдерживаемом формате.",
        )
    if profile.identity.profile_id != requested_id:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "profile_id_mismatch",
            "Источник вернул другой профиль подключения.",
        )
    return None
