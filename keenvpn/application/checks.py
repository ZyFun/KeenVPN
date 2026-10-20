"""Безопасные представления проверок и построители для пассивных сценариев просмотра.

Статус проверки берётся из общего словаря `CheckStatus` контракта. Проверка
описывается стабильным кодом, статусом, признаком сетевой проверки и, при
необходимости, стабильным кодом причины; значений источников, адресов и текста
чужих исключений здесь нет. Признак активной сетевой проверки задаёт сценарий,
а не интерфейс: пассивный результат не может нести итог сетевой проверки,
поэтому скрытых сетевых проб в просмотре быть не может. Этап наблюдения
(DNS, транспорт, туннель, запрос) и факт VPN либо DIRECT в модели проверки
не представлены; статусов ровно четыре.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
import re
from types import MappingProxyType

from keenvpn.application.contract import CheckStatus
from keenvpn.domain.geodata import GeoDataState, GeoFileStatus, UnsupportedGeoReference
from keenvpn.domain.xray_process import XrayProcessObservation


CHECK_STATUS_LABELS: Mapping[CheckStatus, str] = MappingProxyType({
    CheckStatus.PASSED: "успешно",
    CheckStatus.FAILED: "ошибка",
    CheckStatus.NOT_CHECKED: "не проверено",
    CheckStatus.UNSUPPORTED: "не поддерживается",
})
"""Заранее заданная русская подпись каждого статуса; интерфейсы только показывают её. Таблица только для чтения."""

XRAY_PROCESS_CHECK = "xray_process_consistent"
"""Процесс Xray и ready-маркер XKeen согласованы между собой."""
GEODATA_REFERENCES_CHECK = "geodata_references_resolved"
"""Все ссылки правил и DNS на наборы геобаз ведут к найденным файлам инвентаря."""
VPN_REACHABLE_CHECK = "vpn_reachable"
"""Доступность VPN; требует сетевой пробы, которую пассивный просмотр не выполняет."""

_CODE = re.compile(r"\A[a-z][a-z0-9_]{2,63}\Z")


class CheckReason(StrEnum):
    """Стабильные причины статусов проверок этого модуля; состояния процесса передаются своим кодом."""

    NETWORK_CHECK_NOT_PERFORMED = "network_check_not_performed"
    """Сетевая проба не выполнялась: результат пассивного просмотра."""
    NO_REFERENCES = "no_references"
    """В конфигурации нет ссылок на наборы геобаз: проверять нечего."""
    MISSING_FILES = "missing_files"
    """Хотя бы одна ссылка ведёт к файлу, описанному инвентарём как отсутствующий."""
    UNSUPPORTED_REFERENCES = "unsupported_references"
    """Хотя бы одну ссылку загрузчик Xray отклонил бы."""
    FILES_NOT_INVENTORIED = "files_not_inventoried"
    """Хотя бы одна ссылка ведёт к файлу, которого источник инвентаря не наблюдал."""
    PROCESS_WITHOUT_MARKER = "process_without_marker"
    MARKER_WITHOUT_PROCESS = "marker_without_process"
    MULTIPLE_PROCESSES = "multiple_processes"


def _valid_code(value: object) -> bool:
    return type(value) is str and _CODE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class CheckView:
    """Одна проверка: стабильный код, статус из словаря контракта, признак сети и причина.

    `network` — требует ли проверка сетевой пробы. `reason` — стабильный код
    причины статуса либо `None`; значения источников и текст исключений сюда
    не попадают. Статус принимается только точным типом `CheckStatus`:
    строка `"failed"` или `OperationStatus.FAILED` отклоняются.
    """

    code: str
    status: CheckStatus
    network: bool
    reason: str | None

    def __post_init__(self) -> None:
        if (
            not _valid_code(self.code)
            or type(self.status) is not CheckStatus
            or type(self.network) is not bool
            or (self.reason is not None and not _valid_code(self.reason))
        ):
            raise TypeError("Некорректное описание проверки.")

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление со стабильными кодами."""
        return {"code": self.code, "status": self.status.value, "network": self.network, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class ChecksView:
    """Проверки одного результата и признак, выполнялась ли активная сетевая проверка.

    Признак задаёт сценарий. Без активной проверки ни одна сетевая проверка
    не может иметь статус `passed` или `failed`: пассивный просмотр отличим
    от диагностики по самому представлению, а не по кодам ошибок.
    """

    active_network_check: bool
    items: tuple[CheckView, ...]

    def __post_init__(self) -> None:
        if (
            type(self.active_network_check) is not bool
            or type(self.items) is not tuple
            or any(type(item) is not CheckView for item in self.items)
            or len({item.code for item in self.items}) != len(self.items)
        ):
            raise TypeError("Некорректный набор проверок.")
        if not self.active_network_check and any(
            item.network and item.status in (CheckStatus.PASSED, CheckStatus.FAILED) for item in self.items
        ):
            raise TypeError("Пассивный результат не может нести итог сетевой проверки.")

    @property
    def statuses(self) -> dict[str, CheckStatus]:
        """Статусы по кодам проверок в порядке результата."""
        return {item.code: item.status for item in self.items}

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {"active_network_check": self.active_network_check, "items": [item.to_dict() for item in self.items]}


def xray_process_check(observation: XrayProcessObservation) -> CheckView:
    """Согласованность процесса Xray и маркера: `passed` для `stopped` и `running`, иначе `failed` с состоянием.

    `passed` подтверждает только согласованность наблюдения, не работу VPN.
    """
    if type(observation) is not XrayProcessObservation:
        raise TypeError("Ожидается XrayProcessObservation.")
    if observation.consistent:
        return CheckView(XRAY_PROCESS_CHECK, CheckStatus.PASSED, False, None)
    return CheckView(XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, CheckReason(observation.state.value).value)


def geodata_references_check(state: GeoDataState) -> CheckView:
    """Разрешимость ссылок на наборы геобаз по инвентарю, без кодов наборов и имён файлов.

    Без ссылок — `not_checked`; отсутствующий файл или отклоняемая загрузчиком
    ссылка — `failed`; файл, которого источник не наблюдал, — `unsupported`;
    иначе `passed`. Сопоставление по имени не подтверждает, что Xray загрузил файл.
    """
    if type(state) is not GeoDataState:
        raise TypeError("Ожидается GeoDataState.")
    if not state.references:
        return CheckView(GEODATA_REFERENCES_CHECK, CheckStatus.NOT_CHECKED, False, CheckReason.NO_REFERENCES.value)
    statuses = {resolution.status for resolution in state.resolve()}
    if GeoFileStatus.MISSING in statuses:
        return CheckView(GEODATA_REFERENCES_CHECK, CheckStatus.FAILED, False, CheckReason.MISSING_FILES.value)
    if any(type(item) is UnsupportedGeoReference for item in state.references):
        return CheckView(GEODATA_REFERENCES_CHECK, CheckStatus.FAILED, False, CheckReason.UNSUPPORTED_REFERENCES.value)
    if GeoFileStatus.UNKNOWN in statuses:
        return CheckView(GEODATA_REFERENCES_CHECK, CheckStatus.UNSUPPORTED, False, CheckReason.FILES_NOT_INVENTORIED.value)
    return CheckView(GEODATA_REFERENCES_CHECK, CheckStatus.PASSED, False, None)


def vpn_reachability_not_checked() -> CheckView:
    """Доступность VPN в пассивном просмотре: сетевая проверка не выполнялась."""
    return CheckView(VPN_REACHABLE_CHECK, CheckStatus.NOT_CHECKED, True, CheckReason.NETWORK_CHECK_NOT_PERFORMED.value)
