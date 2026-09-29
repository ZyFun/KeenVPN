"""Общий контракт команд, результатов и ошибок прикладных сценариев.

Сценарий не печатает, не читает терминал и не запрашивает подтверждение:
он получает типизированную команду и возвращает структурированный результат.
Интерфейс сам решает, как показать данные и сообщение об ошибке.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
import uuid


CONTRACT_VERSION = 1
"""Версия формата команд и результатов; меняется при несовместимом изменении."""


class OperationStatus(StrEnum):
    """Состояние выполнения сценария, а не результат отдельной проверки."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ErrorCategory(StrEnum):
    """Класс отказа для выбора реакции интерфейса без разбора текста."""

    INVALID_REQUEST = "invalid_request"
    """Команда сформирована интерфейсом неверно или несовместимой версии."""
    INVALID_INPUT = "invalid_input"
    """Значение, введённое пользователем, некорректно."""
    UNSUPPORTED = "unsupported"
    """Значение корректно по форме, но не поддерживается."""
    SOURCE_FAILED = "source_failed"
    """Внешний источник данных не смог выполнить запрос."""
    INVALID_SOURCE_DATA = "invalid_source_data"
    """Источник вернул данные, противоречащие контракту или модели."""


class ErrorCode(StrEnum):
    """Коды отказов, определённые самим прикладным слоем."""

    INVALID_COMMAND = "invalid_command"
    UNSUPPORTED_CONTRACT_VERSION = "unsupported_contract_version"


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    """Безопасное описание отказа.

    `code` и `reason` — стабильные английские идентификаторы, `message` —
    заранее заданный русский текст. Входные значения и сырые исключения
    внешних источников сюда не попадают.
    """

    category: ErrorCategory
    code: str
    message: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.category, ErrorCategory)
            or not isinstance(self.code, str) or not self.code
            or not isinstance(self.message, str) or not self.message
            or (self.reason is not None and (not isinstance(self.reason, str) or not self.reason))
        ):
            raise TypeError("Некорректное описание ошибки сценария.")

    def to_dict(self) -> dict[str, str | None]:
        """Вернуть JSON-совместимое представление."""
        return {
            "category": self.category.value,
            "code": self.code,
            "reason": self.reason,
            "message": self.message,
        }


class SafeView(Protocol):
    """Безопасные данные результата, пригодные для любого интерфейса."""

    def to_dict(self) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class Result[DataT: SafeView]:
    """Итог одного вызова сценария.

    Успех содержит только безопасные данные, отказ — только ErrorDetail.
    Доменные модели с секретами в результат не передаются.
    """

    operation_id: str
    command: str
    status: OperationStatus
    data: DataT | None = None
    error: ErrorDetail | None = None
    contract_version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.operation_id, str) or not self.operation_id
            or not isinstance(self.command, str) or not self.command
            or not isinstance(self.status, OperationStatus)
            or type(self.contract_version) is not int
        ):
            raise TypeError("Некорректный результат сценария.")
        if self.status is OperationStatus.SUCCEEDED:
            consistent = self.data is not None and self.error is None
        else:
            consistent = self.data is None and isinstance(self.error, ErrorDetail)
        if not consistent:
            raise TypeError("Результат сценария должен содержать либо данные, либо ошибку.")

    @property
    def succeeded(self) -> bool:
        """Показать, завершился ли сценарий без отказа."""
        return self.status is OperationStatus.SUCCEEDED

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление для CLI и будущего Web."""
        return {
            "contract_version": self.contract_version,
            "operation_id": self.operation_id,
            "command": self.command,
            "status": self.status.value,
            "data": None if self.data is None else self.data.to_dict(),
            "error": None if self.error is None else self.error.to_dict(),
        }


OperationIdFactory = Callable[[], str]


def new_operation_id() -> str:
    """Создать случайный идентификатор вызова без обращения к сети и файлам."""
    return uuid.uuid4().hex


def succeeded[DataT: SafeView](operation_id: str, command: str, data: DataT) -> Result[DataT]:
    """Собрать успешный результат."""
    return Result(operation_id=operation_id, command=command, status=OperationStatus.SUCCEEDED, data=data)


def failed(operation_id: str, command: str, error: ErrorDetail) -> Result:
    """Собрать результат отказа."""
    return Result(operation_id=operation_id, command=command, status=OperationStatus.FAILED, error=error)


def check_contract_version(version: object) -> ErrorDetail | None:
    """Отклонить команду другой версии контракта вместо угадывания смысла."""
    if type(version) is int and version == CONTRACT_VERSION:
        return None
    return ErrorDetail(
        ErrorCategory.INVALID_REQUEST,
        ErrorCode.UNSUPPORTED_CONTRACT_VERSION.value,
        f"Поддерживается только версия контракта {CONTRACT_VERSION}.",
    )


def invalid_command() -> ErrorDetail:
    """Описать команду неверного типа или с полями неверных типов."""
    return ErrorDetail(
        ErrorCategory.INVALID_REQUEST,
        ErrorCode.INVALID_COMMAND.value,
        "Команда сформирована некорректно.",
    )
