"""Решение о выходе из меню при неприменённом черновике.

Сценарий читает хранилище черновика один раз общим `read_stored_draft`
и решает, можно ли выйти сразу или нужно спросить пользователя: остаться
или выйти, сохранив черновик. Отсутствие черновика — выход без вопроса
только после подтверждения чтением; отказ хранилища, повреждённый файл
и ответ не по контракту — вопрос, а не молчаливый выход, будто черновика
нет. Неподключённое хранилище — выход с причиной `draft_store_not_connected`:
интерфейс сообщает, что черновик не проверялся. Актуальность черновика
не проверяется, черновик, конфигурация и службы не меняются: выход
и отказ от выхода ничего не записывают. Результат содержит решение,
причину, время создания и безопасное описание отказа хранилища, без
идентификатора, токена ревизии, путей и хешей.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorDetail, OperationIdFactory, Result, check_contract_version, failed, invalid_command,
    new_operation_id, succeeded,
)
from keenvpn.application.draft_session import DraftView, read_stored_draft
from keenvpn.application.ports import DraftSessionStore


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectMenuExit:
    """Решить, можно ли выйти из меню без вопроса о неприменённом черновике."""

    name: ClassVar[str] = "inspect_menu_exit"

    contract_version: int = CONTRACT_VERSION


class MenuExitDecision(StrEnum):
    """Что делает интерфейс при выходе."""

    EXIT = "exit"
    """Выйти без вопроса."""
    CONFIRM = "confirm"
    """Спросить: остаться в меню или выйти, сохранив черновик."""


class MenuExitReason(StrEnum):
    """Почему принято решение."""

    NO_DRAFT = "no_draft"
    """Чтение хранилища подтвердило, что черновика нет."""
    DRAFT_PRESENT = "draft_present"
    """Есть неприменённый черновик."""
    DRAFT_NOT_CHECKED = "draft_not_checked"
    """Хранилище прочитать не удалось: черновик может быть."""
    DRAFT_STORE_NOT_CONNECTED = "draft_store_not_connected"
    """Хранилище черновика не подключено: сценарий его не вызывал."""


_DECISIONS = {
    MenuExitReason.NO_DRAFT: MenuExitDecision.EXIT,
    MenuExitReason.DRAFT_PRESENT: MenuExitDecision.CONFIRM,
    MenuExitReason.DRAFT_NOT_CHECKED: MenuExitDecision.CONFIRM,
    MenuExitReason.DRAFT_STORE_NOT_CONNECTED: MenuExitDecision.EXIT,
}


@dataclass(frozen=True, slots=True)
class MenuExitView:
    """Решение о выходе, его причина, время создания черновика и отказ хранилища.

    `draft_created_at` — время создания UTC из представления черновика, только
    при `draft_present`. `store_error` — безопасное описание отказа, только при
    `draft_not_checked`. Решение однозначно задаётся причиной.
    """

    decision: MenuExitDecision
    reason: MenuExitReason
    draft_created_at: str | None = None
    store_error: ErrorDetail | None = None

    def __post_init__(self) -> None:
        if type(self.decision) is not MenuExitDecision or type(self.reason) is not MenuExitReason:
            raise TypeError("Решение и причина выхода задаются перечислениями.")
        present = self.reason is MenuExitReason.DRAFT_PRESENT
        not_checked = self.reason is MenuExitReason.DRAFT_NOT_CHECKED
        if (
            _DECISIONS[self.reason] is not self.decision
            or (type(self.draft_created_at) is str) is not present
            or (self.draft_created_at is not None and type(self.draft_created_at) is not str)
            or (type(self.store_error) is ErrorDetail) is not not_checked
            or (self.store_error is not None and type(self.store_error) is not ErrorDetail)
        ):
            raise TypeError("Решение, причина, время создания и отказ выхода не согласованы.")

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление со стабильными кодами."""
        return {
            "decision": self.decision.value,
            "reason": self.reason.value,
            "draft_created_at": self.draft_created_at,
            "store_error": None if self.store_error is None else self.store_error.to_dict(),
        }


class InspectMenuExitHandler:
    """Прочитать хранилище черновика не больше одного раза и вернуть решение о выходе.

    `None` вместо хранилища — оно не подключено: выход без чтения с причиной
    `draft_store_not_connected`. Отказ хранилища не делает сценарий
    неуспешным: решение — вопрос с описанием отказа. Хранилище только
    читается: файл и каталог не создаются и не меняются.
    """

    def __init__(
        self, store: DraftSessionStore | None, *, operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._store = store
        self._operation_ids = operation_ids

    def execute(self, command: InspectMenuExit) -> Result[MenuExitView]:
        """Выполнить решение; отказывает только на команде."""
        operation_id = self._operation_ids()
        name = InspectMenuExit.name
        if type(command) is not InspectMenuExit:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        if self._store is None:
            view = MenuExitView(MenuExitDecision.EXIT, MenuExitReason.DRAFT_STORE_NOT_CONNECTED)
            return succeeded(operation_id, name, view)
        stored = read_stored_draft(self._store)
        if isinstance(stored, ErrorDetail):
            view = MenuExitView(MenuExitDecision.CONFIRM, MenuExitReason.DRAFT_NOT_CHECKED, store_error=stored)
        elif stored is None:
            view = MenuExitView(MenuExitDecision.EXIT, MenuExitReason.NO_DRAFT)
        else:
            draft = DraftView.from_session(stored.session, stored.revision)
            view = MenuExitView(MenuExitDecision.CONFIRM, MenuExitReason.DRAFT_PRESENT, draft.created_at)
        return succeeded(operation_id, name, view)
