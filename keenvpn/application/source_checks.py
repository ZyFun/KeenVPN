"""Проверка ответов источников чтения перед использованием в сценарии.

Сценарии чтения вызывают каждый источник один раз и не доверяют его ответу:
проверяют точный тип модели и повторно проверяют её данные доменной функцией.
Отказ источника и некорректный ответ дают отдельные коды без текста и цепочки
исключения: они могут содержать пути, пароли, адреса и вывод команд.
"""

from collections.abc import Callable
from dataclasses import dataclass

from keenvpn.application.contract import ErrorCategory, ErrorDetail


def unavailable(code: str, message: str) -> ErrorDetail:
    """Описать отказ источника категорией `source_failed` с фиксированным текстом."""
    return ErrorDetail(ErrorCategory.SOURCE_FAILED, code, message)


@dataclass(frozen=True, slots=True)
class SourceCheck:
    """Как проверять ответ одного источника.

    `code` — код отказа `invalid_source_data` для этого источника, `model_type`
    — точный ожидаемый тип, `validate` — доменная повторная проверка модели,
    `domain_errors` — ошибки домена, чей код передаётся в `reason`.
    `type_message` описывает ответ неподдерживаемого формата, `data_message`
    — модель, не прошедшую повторную проверку.
    """

    code: str
    model_type: type
    validate: Callable[[object], None]
    type_message: str
    data_message: str
    domain_errors: tuple[type[Exception], ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.code, str) or not self.code
            or not isinstance(self.model_type, type)
            or not callable(self.validate)
            or not isinstance(self.type_message, str) or not self.type_message
            or not isinstance(self.data_message, str) or not self.data_message
            or type(self.domain_errors) is not tuple or not self.domain_errors
            or any(not (isinstance(item, type) and issubclass(item, Exception)) for item in self.domain_errors)
        ):
            raise TypeError("Некорректное описание проверки источника.")


def check_source_model(check: SourceCheck, value: object) -> ErrorDetail | None:
    """Проверить тип ответа и повторно проверить модель вместе с вложенными записями.

    Ошибка домена даёт `data_message` с её кодом в `reason`; любое другое
    исключение повторной проверки — `type_message` без причины, потому что
    его текст не является безопасным кодом.
    """
    if type(value) is not check.model_type:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, check.code, check.type_message)
    try:
        check.validate(value)
    except check.domain_errors as error:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, check.code, check.data_message, reason=error.code.value)
    except Exception:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, check.code, check.type_message)
    return None
