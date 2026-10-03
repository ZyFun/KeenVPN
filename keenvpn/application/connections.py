"""Сценарий проверки ссылки подключения без сохранения и применения."""

from dataclasses import KW_ONLY, dataclass
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import ConnectionLinkParser, ConnectionLinkRejected, LinkRejection
from keenvpn.domain.connection import SecretValue, TrojanConnection


_CATEGORIES = {
    LinkRejection.INVALID: ErrorCategory.INVALID_INPUT,
    LinkRejection.UNSUPPORTED: ErrorCategory.UNSUPPORTED,
}


@dataclass(frozen=True, slots=True, repr=False)
class InspectConnectionLink:
    """Разобрать ссылку и показать её формат; ссылка передаётся как секрет."""

    name: ClassVar[str] = "inspect_connection_link"

    link: SecretValue
    _: KW_ONLY
    contract_version: int = CONTRACT_VERSION

    def __repr__(self) -> str:
        return "InspectConnectionLink(<скрыто>)"


@dataclass(frozen=True, slots=True)
class ConnectionLinkView:
    """Формат подключения и наличие необязательных полей без их значений."""

    protocol: str
    security: str
    transport: str
    has_sni: bool
    has_host: bool
    has_fingerprint: bool
    has_name: bool

    @classmethod
    def from_connection(cls, connection: TrojanConnection) -> "ConnectionLinkView":
        """Построить представление из безопасной диагностики модели."""
        diagnostic = connection.to_diagnostic()
        return cls(**{name: diagnostic[name] for name in cls.__dataclass_fields__})

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class InspectConnectionLinkHandler:
    """Проверить формат ссылки: без сети, записи файлов и изменения роутера.

    Успех означает только корректный разбор, а не работоспособность сервера.
    """

    def __init__(self, parser: ConnectionLinkParser, *, operation_ids: OperationIdFactory = new_operation_id) -> None:
        self._parser = parser
        self._operation_ids = operation_ids

    def execute(self, command: InspectConnectionLink) -> Result[ConnectionLinkView]:
        """Выполнить команду и вернуть результат, не вызывая исключений отказа."""
        operation_id = self._operation_ids()
        name = InspectConnectionLink.name
        if (
            type(command) is not InspectConnectionLink
            or not isinstance(command.link, SecretValue)
            or not isinstance(command.link.reveal(), str)
        ):
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        try:
            connection = self._parser.parse(command.link.reveal())
        except ConnectionLinkRejected as rejection:
            error = link_rejection_detail(rejection)
        except Exception:
            # Сырое исключение может содержать ссылку: заменяем его кодом.
            error = ErrorDetail(
                ErrorCategory.SOURCE_FAILED, "connection_parser_failed",
                "Не удалось разобрать ссылку подключения.",
            )
        else:
            if isinstance(connection, TrojanConnection):
                return succeeded(operation_id, name, ConnectionLinkView.from_connection(connection))
            error = ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, "invalid_connection_model",
                "Парсер вернул данные в неподдерживаемом формате.",
            )
        return failed(operation_id, name, error)


def link_rejection_detail(rejection: ConnectionLinkRejected) -> ErrorDetail:
    """Преобразовать отказ доверенного парсера для сценариев ссылки и профиля."""
    category = _CATEGORIES.get(rejection.rejection) if isinstance(rejection.rejection, LinkRejection) else None
    try:
        if category is None:
            raise TypeError
        return ErrorDetail(category, rejection.code, str(rejection), rejection.reason)
    except TypeError:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_parser_rejection",
            "Парсер сообщил об отказе в неподдерживаемом формате.",
        )
