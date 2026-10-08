"""Наблюдение процесса Xray и ready-маркера XKeen без команд XKeen и init.

Источник наблюдает процесс и маркер только чтением: `pidof`, метаданные файла
маркера. Команды `xkeen -status`, `xkeen -v` и сам стартовый сценарий меняют
служебные файлы даже на пути status, поэтому для чтения не используются.
Наблюдение описывает состояние службы на момент чтения и не подтверждает
готовность VPN-канала, правила перехвата, DNS или маршрут клиента.
Расхождение процесса и маркера — отдельное состояние, а не работающий VPN.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn


PID_MAX = 4194304
"""Верхняя граница `pid_max` Linux на 64-битных ядрах; большее значение — не PID."""


class XrayProcessErrorCode(StrEnum):
    """Причина отказа без вывода команд и значений наблюдения."""

    OBSERVATION = "invalid_xray_process_observation"


_MESSAGES = {
    XrayProcessErrorCode.OBSERVATION: (
        "Наблюдение процесса Xray должно содержать кортеж уникальных PID и булев признак маркера готовности."
    ),
}


class XrayProcessError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: XrayProcessErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: XrayProcessErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise XrayProcessError(code) from None
    except XrayProcessError as error:
        error.__context__ = None
        raise


class XrayProcessState(StrEnum):
    """Согласованность процесса и маркера; ни одно состояние не означает работающий VPN."""

    STOPPED = "stopped"
    """Процесса нет и маркер снят: штатная остановка либо служба не запускалась."""
    RUNNING = "running"
    """Один процесс и маркер готовности; готовность канала этим не подтверждается."""
    PROCESS_WITHOUT_MARKER = "process_without_marker"
    """Процесс есть, маркера нет: запуск не завершён или маркер снят; не работающий VPN."""
    MARKER_WITHOUT_PROCESS = "marker_without_process"
    """Маркер остался без процесса: аварийное завершение или не очищенное состояние."""
    MULTIPLE_PROCESSES = "multiple_processes"
    """Несколько процессов Xray; состояние службы по ним не выводится и первый не выбирается."""


_CONSISTENT_STATES = frozenset({XrayProcessState.STOPPED, XrayProcessState.RUNNING})


def _valid_pid(value: object) -> bool:
    return type(value) is int and 1 <= value <= PID_MAX


@dataclass(frozen=True, slots=True)
class XrayProcessObservation:
    """PID процессов Xray в порядке наблюдения и наличие ready-маркера XKeen.

    Несколько PID сохраняются все: вспомогательные вызовы `xray api` тоже
    видны как процессы `xray`, и по ним нельзя выбрать «основной».
    """

    pids: tuple[int, ...]
    ready_marker: bool

    def __post_init__(self) -> None:
        if (
            type(self.pids) is not tuple
            or not all(_valid_pid(pid) for pid in self.pids)
            or len(set(self.pids)) != len(self.pids)
            or type(self.ready_marker) is not bool
        ):
            _raise_detached(XrayProcessErrorCode.OBSERVATION)

    @property
    def process_count(self) -> int:
        """Число наблюдаемых процессов."""
        return len(self.pids)

    @property
    def state(self) -> XrayProcessState:
        """Согласованность процесса и маркера без вывода о работе VPN."""
        if len(self.pids) > 1:
            return XrayProcessState.MULTIPLE_PROCESSES
        if self.pids and self.ready_marker:
            return XrayProcessState.RUNNING
        if self.pids:
            return XrayProcessState.PROCESS_WITHOUT_MARKER
        if self.ready_marker:
            return XrayProcessState.MARKER_WITHOUT_PROCESS
        return XrayProcessState.STOPPED

    @property
    def consistent(self) -> bool:
        """Истинно только для `stopped` и `running`; расхождения требуют внимания."""
        return self.state in _CONSISTENT_STATES

    def to_diagnostic(self) -> dict[str, object]:
        """PID, маркер и состояние в JSON-совместимом виде."""
        return {
            "process_count": self.process_count,
            "pids": list(self.pids),
            "ready_marker": self.ready_marker,
            "state": self.state.value,
            "consistent": self.consistent,
        }


def validate_xray_process_observation(observation: XrayProcessObservation) -> None:
    """Проверить готовую модель заново: тип, PID и признак маркера."""
    if type(observation) is not XrayProcessObservation:
        _raise_detached(XrayProcessErrorCode.OBSERVATION)
    XrayProcessObservation(observation.pids, observation.ready_marker)
