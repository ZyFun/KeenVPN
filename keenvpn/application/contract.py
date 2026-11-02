"""Общий контракт команд, результатов и ошибок прикладных сценариев.

Сценарий не печатает, не читает терминал и не запрашивает подтверждение:
он получает типизированную команду и возвращает структурированный результат.
Интерфейс сам решает, как показать данные и сообщение об ошибке. Безопасный
следующий шаг отказа задаёт каталог этого модуля по категории и коду ошибки:
интерфейсы только показывают его и ничего не выполняют. Отказ из-за того,
что состояние объекта разошлось с ожидаемым командой, дополнительно несёт
структурированные записи конфликта без хешей, путей и значений.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
import uuid

from keenvpn.domain.source_baseline import BaselineSource


CONTRACT_VERSION = 1
"""Версия формата команд и результатов; меняется при несовместимом изменении."""


class OperationStatus(StrEnum):
    """Состояние выполнения сценария, а не результат отдельной проверки."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CheckStatus(StrEnum):
    """Общий словарь итогов отдельной проверки внутри данных результата.

    Это не состояние сценария: сценарий завершается `OperationStatus.SUCCEEDED`
    и может вернуть проверки с любым из четырёх статусов. Недоступная
    или не выполненная проверка никогда не становится `PASSED`; `NOT_CHECKED`
    и `UNSUPPORTED` не приравниваются ни к успеху, ни к ошибке. Модели
    проверок и их построители — в `keenvpn.application.checks`.
    """

    PASSED = "passed"
    """Проверка выполнена и подтвердила ожидаемое."""
    FAILED = "failed"
    """Проверка выполнена и обнаружила расхождение."""
    NOT_CHECKED = "not_checked"
    """Проверка не выполнялась: нет проб, нечего проверять или источник недоступен."""
    UNSUPPORTED = "unsupported"
    """Проверка не умеет оценить это значение или не реализована в этой версии."""


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
    """Общие коды отказов контракта, не зависящие от сценария.

    Коды отказов источников задаёт модуль сценария, коды домена и парсера
    передаются без изменения.
    """

    INVALID_COMMAND = "invalid_command"
    UNSUPPORTED_CONTRACT_VERSION = "unsupported_contract_version"


class NextStepCode(StrEnum):
    """Стабильные коды безопасного следующего шага после отказа.

    Шаг только предлагает действие пользователю и ничего не выполняет.
    Ни один шаг не предлагает прямой маршрут, отключение защиты, kill-switch
    или автозапуска как исправление.
    """

    RETRY_INPUT = "retry_input"
    """Исправить введённое значение и повторить ввод."""
    CONSULT_DOCUMENTATION = "consult_documentation"
    """Значение корректно, но не поддерживается: сверить с документацией."""
    CHECK_SOURCE = "check_source"
    """Проверить доступность источника чтения и повторить попытку."""
    INSPECT_SOURCE_DATA = "inspect_source_data"
    """Проверить данные источника вручную, ничего не изменяя."""
    RETRY_LATER = "retry_later"
    """Повторить позже: ресурс занят другой операцией."""
    OPEN_VIEW = "open_view"
    """Открыть просмотр текущего состояния и сверить его перед повтором."""
    PRESERVE_FILE = "preserve_file"
    """Не перезаписывать и не удалять файл: сохранить копию и проверить вручную."""
    UPDATE_INTERFACE = "update_interface"
    """Использовать интерфейс, совместимый с версией контракта менеджера."""
    RECREATE_DRAFT = "recreate_draft"
    """Черновик устарел: сверить текущее состояние и создать черновик заново."""
    REVIEW_DRAFT = "review_draft"
    """Исправить отмеченные проверкой ошибки в черновике."""


NEXT_STEP_MESSAGES: Mapping[NextStepCode, str] = MappingProxyType({
    NextStepCode.RETRY_INPUT: "Исправьте введённое значение и повторите ввод.",
    NextStepCode.CONSULT_DOCUMENTATION: (
        "Значение корректно, но не поддерживается этой версией: сверьтесь с документацией поддерживаемых вариантов."
    ),
    NextStepCode.CHECK_SOURCE: (
        "Проверьте доступность источника чтения и повторите попытку; настройки роутера при этом не менялись."
    ),
    NextStepCode.INSPECT_SOURCE_DATA: (
        "Проверьте данные источника вручную, ничего не изменяя: менеджер их не исправляет."
    ),
    NextStepCode.RETRY_LATER: "Повторите операцию позже: её выполняет другая операция, настройки не менялись.",
    NextStepCode.OPEN_VIEW: (
        "Откройте просмотр текущего состояния и сверьте его перед повторной попыткой; данные при этом не меняются."
    ),
    NextStepCode.PRESERVE_FILE: (
        "Не перезаписывайте и не удаляйте файл: сохраните его копию и проверьте вручную по документации."
    ),
    NextStepCode.UPDATE_INTERFACE: "Используйте интерфейс, совместимый с версией контракта установленного менеджера.",
    NextStepCode.REVIEW_DRAFT: "Исправьте отмеченные ошибки в черновике и повторите проверку.",
    NextStepCode.RECREATE_DRAFT: (
        "Сверьте текущее состояние и создайте черновик заново: устаревший черновик не применяется, "
        "настройки роутера при этом не менялись."
    ),
})
"""Заранее заданный русский текст каждого шага; других текстов у шагов нет. Таблица только для чтения."""


@dataclass(frozen=True, slots=True)
class NextStep:
    """Безопасный следующий шаг: стабильный код и его заранее заданный текст.

    Текст берётся только из `NEXT_STEP_MESSAGES`, поэтому входные значения,
    адреса, фрагменты ссылок и текст внешних исключений в шаг не попадают.
    Таблицы каталога только для чтения: созданные ошибки сериализуются одинаково
    на всём протяжении работы процесса.
    """

    code: NextStepCode
    message: str

    def __post_init__(self) -> None:
        if type(self.code) is not NextStepCode or self.message != NEXT_STEP_MESSAGES[self.code]:
            raise TypeError("Некорректное описание следующего шага.")

    def to_dict(self) -> dict[str, str]:
        """Вернуть JSON-совместимое представление."""
        return {"code": self.code.value, "message": self.message}


CATEGORY_NEXT_STEPS: Mapping[ErrorCategory, NextStepCode | None] = MappingProxyType({
    ErrorCategory.INVALID_REQUEST: None,
    ErrorCategory.INVALID_INPUT: NextStepCode.RETRY_INPUT,
    ErrorCategory.UNSUPPORTED: NextStepCode.CONSULT_DOCUMENTATION,
    ErrorCategory.SOURCE_FAILED: NextStepCode.CHECK_SOURCE,
    ErrorCategory.INVALID_SOURCE_DATA: NextStepCode.INSPECT_SOURCE_DATA,
})
"""Шаг по умолчанию для каждой категории; `None` — безопасного шага нет. Таблица только для чтения."""

CODE_NEXT_STEPS: Mapping[tuple[ErrorCategory, str], NextStepCode | None] = MappingProxyType({
    # Единственный отказ запроса, где у пользователя есть действие: сменить интерфейс.
    (ErrorCategory.INVALID_REQUEST, ErrorCode.UNSUPPORTED_CONTRACT_VERSION.value): NextStepCode.UPDATE_INTERFACE,
    (ErrorCategory.INVALID_REQUEST, ErrorCode.INVALID_COMMAND.value): None,
    # Отказы хранилища метаданных менеджера: ни один шаг не подталкивает к перезаписи файла.
    (ErrorCategory.SOURCE_FAILED, "metadata_store_busy"): NextStepCode.RETRY_LATER,
    (ErrorCategory.SOURCE_FAILED, "metadata_revision_conflict"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "metadata_write_unconfirmed"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "metadata_store_failed"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.INVALID_SOURCE_DATA, "invalid_metadata_store_result"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "metadata_store_unsafe"): NextStepCode.PRESERVE_FILE,
    (ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_metadata"): NextStepCode.PRESERVE_FILE,
    (ErrorCategory.UNSUPPORTED, "storage_placement_mismatch"): NextStepCode.OPEN_VIEW,
    # Отказы хранилища черновика: ни один шаг не подталкивает к перезаписи или удалению файла.
    (ErrorCategory.SOURCE_FAILED, "draft_store_busy"): NextStepCode.RETRY_LATER,
    (ErrorCategory.SOURCE_FAILED, "draft_revision_conflict"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "draft_write_unconfirmed"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "draft_store_failed"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_store_result"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "draft_store_unsafe"): NextStepCode.PRESERVE_FILE,
    (ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_draft"): NextStepCode.PRESERVE_FILE,
    (ErrorCategory.UNSUPPORTED, "draft_exists"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.UNSUPPORTED, "draft_mismatch"): NextStepCode.OPEN_VIEW,
    # Устаревший черновик: повтор не поможет, применять его поверх нового состояния нельзя.
    (ErrorCategory.SOURCE_FAILED, "draft_baseline_changed"): NextStepCode.RECREATE_DRAFT,
})
"""Переопределения по паре «категория, код»; остальные коды получают шаг категории. Таблица только для чтения."""


def next_step_for(category: ErrorCategory, code: str) -> NextStep | None:
    """Выбрать безопасный следующий шаг по категории и коду отказа; `None` — шага нет.

    Сначала ищется переопределение для пары, затем шаг категории. Интерфейсы
    этот выбор не повторяют: они читают `ErrorDetail.next_step`. Код принимается
    в тех же типах, что и `ErrorDetail.code`, включая подклассы `str`; ключ
    таблицы — его значение обычной строкой, без сравнения `StrEnum` со строкой.
    """
    if type(category) is not ErrorCategory or not isinstance(code, str):
        raise TypeError("Шаг выбирается по категории ErrorCategory и строковому коду.")
    step_code = CODE_NEXT_STEPS.get((category, str.__str__(code)), CATEGORY_NEXT_STEPS[category])
    return None if step_code is None else NextStep(step_code, NEXT_STEP_MESSAGES[step_code])


class ConflictSubject(StrEnum):
    """Объект, состояние которого разошлось с ожидаемым командой."""

    DRAFT = "draft"
    """Сессия черновика: появилась, исчезла, другая или другой ревизии."""
    METADATA = "metadata"
    """Метаданные менеджера изменились после чтения."""
    SOURCE = "source"
    """Управляемый источник разошёлся с исходными отпечатками черновика."""


class ConflictState(StrEnum):
    """Состояние объекта в записи конфликта: без значений, ревизий и хешей."""

    PRESENT = "present"
    """Объект есть; в ожидаемом состоянии — в той ревизии, которую знала команда."""
    ABSENT = "absent"
    """Объекта нет."""
    CHANGED = "changed"
    """Объект есть, но другой или другой ревизии; бывает только найденным состоянием."""
    UNKNOWN = "unknown"
    """Состояние не установлено: не зафиксировано, не прочитано или хранилище его не сообщило."""


CONFLICT_SUBJECT_LABELS: Mapping[ConflictSubject, str] = MappingProxyType({
    ConflictSubject.DRAFT: "черновик",
    ConflictSubject.METADATA: "метаданные менеджера",
    ConflictSubject.SOURCE: "источник",
})
"""Заранее заданная русская подпись объекта конфликта; интерфейсы только показывают её. Таблица только для чтения."""

CONFLICT_STATE_LABELS: Mapping[ConflictState, str] = MappingProxyType({
    ConflictState.PRESENT: "есть",
    ConflictState.ABSENT: "нет",
    ConflictState.CHANGED: "другая ревизия",
    ConflictState.UNKNOWN: "не установлено",
})
"""Заранее заданная русская подпись состояния в записи конфликта. Таблица только для чтения."""

UNKNOWN_SOURCE_LABEL = "неизвестен этой версии"
"""Подпись источника записи конфликта, которого нет в перечне этой версии менеджера."""

_MATCHING_STATES = frozenset({
    (ConflictState.PRESENT, ConflictState.PRESENT), (ConflictState.ABSENT, ConflictState.ABSENT),
})
"""Совпадение ожидаемого и найденного — не конфликт."""


@dataclass(frozen=True, slots=True)
class Conflict:
    """Запись конфликта: какой объект, что ожидала команда и что найдено.

    `source` — управляемый источник для `subject=source` либо `None`, если
    запись источника неизвестна этой версии; у черновика и метаданных — всегда
    `None`. Ожидаемое состояние не бывает `changed`, найденное `changed` бывает
    только при ожидаемом `present`. Хешей, ревизий, путей, идентификаторов
    и значений в записи нет.
    """

    subject: ConflictSubject
    expected: ConflictState
    found: ConflictState
    source: BaselineSource | None = None

    def __post_init__(self) -> None:
        if (
            type(self.subject) is not ConflictSubject
            or type(self.expected) is not ConflictState or type(self.found) is not ConflictState
            or (self.source is not None and type(self.source) is not BaselineSource)
            or (self.source is not None and self.subject is not ConflictSubject.SOURCE)
            or self.expected is ConflictState.CHANGED
            or (self.found is ConflictState.CHANGED and self.expected is not ConflictState.PRESENT)
            or (self.expected, self.found) in _MATCHING_STATES
        ):
            raise TypeError("Некорректное описание конфликта.")

    def to_dict(self) -> dict[str, str | None]:
        """Вернуть JSON-совместимое представление."""
        return {
            "subject": self.subject.value,
            "source": None if self.source is None else self.source.value,
            "expected": self.expected.value,
            "found": self.found.value,
        }


def revision_conflict(subject: ConflictSubject, expected: ConflictState) -> Conflict:
    """Запись конфликта по отказу хранилища, которое сообщает только несовпадение ревизии.

    Ожидалось отсутствие — значит, объект найден; ожидалась прочитанная
    ревизия — найденное состояние не установлено: объект мог исчезнуть
    или измениться.
    """
    if type(expected) is not ConflictState or expected not in (ConflictState.PRESENT, ConflictState.ABSENT):
        raise TypeError("Ожидается состояние present или absent.")
    found = ConflictState.PRESENT if expected is ConflictState.ABSENT else ConflictState.UNKNOWN
    return Conflict(subject, expected, found)


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    """Безопасное описание отказа.

    `code` и `reason` — стабильные английские идентификаторы, `message` —
    заранее заданный русский текст. Входные значения и сырые исключения
    внешних источников сюда не попадают. `next_step` — безопасный следующий
    шаг из каталога контракта по категории и коду; `None` означает, что
    безопасного шага нет. `conflicts` — записи конфликта, если отказ вызван
    расхождением состояния объекта с ожидаемым командой; каждый объект
    не больше одного раза.
    """

    category: ErrorCategory
    code: str
    message: str
    reason: str | None = None
    conflicts: tuple[Conflict, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.category, ErrorCategory)
            or not isinstance(self.code, str) or not self.code
            or not isinstance(self.message, str) or not self.message
            or (self.reason is not None and (not isinstance(self.reason, str) or not self.reason))
            or type(self.conflicts) is not tuple
            or any(type(item) is not Conflict for item in self.conflicts)
            or len({(item.subject, item.source) for item in self.conflicts}) != len(self.conflicts)
        ):
            raise TypeError("Некорректное описание ошибки сценария.")

    @property
    def next_step(self) -> NextStep | None:
        """Безопасный следующий шаг по каталогу контракта; `None` — шага нет."""
        return next_step_for(self.category, self.code)

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление; ключи `next_step` и `conflicts` добавлены в версии контракта 1."""
        step = self.next_step
        return {
            "category": self.category.value,
            "code": self.code,
            "reason": self.reason,
            "message": self.message,
            "next_step": None if step is None else step.to_dict(),
            "conflicts": [item.to_dict() for item in self.conflicts],
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
