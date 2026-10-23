"""Быстрая проверка без изменений: согласованность прочитанных источников и явный перечень непроверенного.

Сводка состояния отвечает, что настроено и наблюдается; быстрая проверка —
согласованы ли прочитанные источники между собой и что из этого не
проверялось. Источники читаются один раз теми же функциями, что у сводки,
проверки её областей берутся из собранной сводки, а не вычисляются второй
раз; сверх них проверяются ссылки и теги конфигурации Xray, ссылки на наборы
геобаз по инвентарю и согласованность выбранного режима порта 53 со списками
портов и флагами init. Сетевых проб нет: доступность VPN и фактический путь
DNS всегда «не проверено», перехват не читается — «не поддерживается». Итог
не бывает «всё успешно»: без сетевой проверки часть проверок не выполнена,
и представление говорит об этом явно. Ничего не записывается, команды XKeen
не вызываются; успешный прямой выход или резерв не считается проверкой VPN.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar

from keenvpn.application.checks import (
    GEODATA_REFERENCES_CHECK, PORT_53_MODE_CHECK, VPN_REACHABLE_CHECK, XRAY_CONFIG_CHECK, XRAY_PROCESS_CHECK,
    ChecksView, CheckView, geodata_references_check, not_checked, port_53_mode_check, xray_config_check,
)
from keenvpn.application.contract import (
    CONTRACT_VERSION, CheckStatus, ErrorDetail, OperationIdFactory, Result, check_contract_version, failed,
    invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.installation import read_geo_databases
from keenvpn.application.ports import GeoDatabaseSource, XrayProcessSource
from keenvpn.application.proxy_config import InspectProxyConfigHandler, ProxyConfigSource
from keenvpn.application.status_summary import (
    AUTOSTART_CHECK, FALLBACK_CHECK, INTERCEPTION_CHECK, PORT_53_PATH_CHECK, SummaryReadings, SummaryReason,
    build_status_summary, port_53_path_not_checked, read_summary_sources,
)
from keenvpn.domain.geodata import GeoDatabaseInventory, GeoDataError, assemble_geodata_state
from keenvpn.domain.xray_config import XrayConfigSet


@dataclass(frozen=True, slots=True, kw_only=True)
class QuickCheck:
    """Проверить согласованность прочитанных источников без изменений и перечислить непроверенное."""

    name: ClassVar[str] = "quick_check"

    contract_version: int = CONTRACT_VERSION


class QuickCheckSource(StrEnum):
    """Источник быстрой проверки; порядок членов — порядок чтения."""

    XRAY = "xray"
    SETTINGS = "settings"
    INIT = "init"
    PORT_EXCLUDE = "port_exclude"
    PORT_PROXYING = "port_proxying"
    PROCESS = "process"
    GEODATA = "geodata"


class SourceState(StrEnum):
    """Итог чтения одного источника."""

    READ = "read"
    FAILED = "failed"
    NOT_CONNECTED = "not_connected"


class QuickCheckOutcome(StrEnum):
    """Общий итог: расхождения найдены либо не найдены при части невыполненных проверок.

    Значения «всё успешно» нет: без активной сетевой проверки доступность VPN
    остаётся «не проверено», поэтому в пассивном режиме такой итог недостижим.
    """

    FAILED = "failed"
    INCOMPLETE = "incomplete"


SOURCE_LABELS: Mapping[QuickCheckSource, str] = MappingProxyType({
    QuickCheckSource.XRAY: "части конфигурации Xray",
    QuickCheckSource.SETTINGS: "настройки XKeen",
    QuickCheckSource.INIT: "параметры init XKeen",
    QuickCheckSource.PORT_EXCLUDE: "список исключённых портов",
    QuickCheckSource.PORT_PROXYING: "список перехватываемых портов",
    QuickCheckSource.PROCESS: "процесс Xray",
    QuickCheckSource.GEODATA: "инвентарь геобаз",
})
"""Заранее заданная русская подпись каждого источника; интерфейсы только показывают её. Таблица только для чтения."""

SOURCE_STATE_LABELS: Mapping[SourceState, str] = MappingProxyType({
    SourceState.READ: "прочитан",
    SourceState.FAILED: "отказ",
    SourceState.NOT_CONNECTED: "не подключён",
})
"""Заранее заданная русская подпись итога чтения источника. Таблица только для чтения."""

OUTCOME_LABELS: Mapping[QuickCheckOutcome, str] = MappingProxyType({
    QuickCheckOutcome.FAILED: "найдены расхождения",
    QuickCheckOutcome.INCOMPLETE: "расхождений не найдено, часть проверок не выполнена или не поддерживается",
})
"""Заранее заданная русская подпись итога; интерфейсы только показывают её. Таблица только для чтения."""

CHECK_ORDER = (
    XRAY_CONFIG_CHECK, GEODATA_REFERENCES_CHECK, FALLBACK_CHECK, AUTOSTART_CHECK, PORT_53_MODE_CHECK,
    XRAY_PROCESS_CHECK, INTERCEPTION_CHECK, PORT_53_PATH_CHECK, VPN_REACHABLE_CHECK,
)
"""Коды проверок в порядке показа: конфигурация, настройки XKeen, процесс, затем невыполнимые без сети или чтения правил."""

_SOURCE_PORTS = {
    QuickCheckSource.XRAY: ProxyConfigSource.XRAY,
    QuickCheckSource.SETTINGS: ProxyConfigSource.SETTINGS,
    QuickCheckSource.INIT: ProxyConfigSource.INIT,
    QuickCheckSource.PORT_EXCLUDE: ProxyConfigSource.PORT_EXCLUDE,
    QuickCheckSource.PORT_PROXYING: ProxyConfigSource.PORT_PROXYING,
}


@dataclass(frozen=True, slots=True)
class SourceReadView:
    """Итог чтения источника: подключён ли, прочитан ли и безопасное описание отказа.

    `error` задан тогда и только тогда, когда состояние — `failed`; описание
    отказа со следующим шагом приводится здесь один раз, а зависящие проверки
    несут только его код в причине.
    """

    source: QuickCheckSource
    state: SourceState
    error: ErrorDetail | None = None

    def __post_init__(self) -> None:
        if (
            type(self.source) is not QuickCheckSource
            or type(self.state) is not SourceState
            or (self.error is not None and type(self.error) is not ErrorDetail)
            or (self.error is not None) is not (self.state is SourceState.FAILED)
        ):
            raise TypeError("Некорректный итог чтения источника.")

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление со стабильными кодами."""
        return {
            "source": self.source.value,
            "state": self.state.value,
            "error": None if self.error is None else self.error.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class QuickCheckView:
    """Итог, источники в порядке чтения и проверки в фиксированном порядке.

    Итог согласован с проверками: `failed` тогда и только тогда, когда хотя бы
    одна проверка нашла расхождение; иначе `incomplete`, и хотя бы одна проверка
    не выполнена или не поддерживается. Набор `checks` проверяет инвариант
    пассивного результата. PID, теги, имена файлов, адреса, записи списков
    и тексты исключений источников сюда не входят.
    """

    outcome: QuickCheckOutcome
    sources: tuple[SourceReadView, ...]
    checks: ChecksView

    def __post_init__(self) -> None:
        if (
            type(self.outcome) is not QuickCheckOutcome
            or type(self.sources) is not tuple
            or any(type(item) is not SourceReadView for item in self.sources)
            or [item.source for item in self.sources] != list(QuickCheckSource)
            or type(self.checks) is not ChecksView
            or [item.code for item in self.checks.items] != list(CHECK_ORDER)
        ):
            raise TypeError("Быстрая проверка содержит каждый источник и каждую проверку один раз в своём порядке.")
        counts = self.counts
        failed_found = counts[CheckStatus.FAILED.value] > 0
        incomplete = counts[CheckStatus.NOT_CHECKED.value] + counts[CheckStatus.UNSUPPORTED.value] > 0
        if (self.outcome is QuickCheckOutcome.FAILED) is not failed_found or (not failed_found and not incomplete):
            raise TypeError("Итог быстрой проверки не согласован с её проверками.")

    @property
    def active_network_check(self) -> bool:
        """Признак активной сетевой проверки набора; у быстрой проверки всегда выключен."""
        return self.checks.active_network_check

    @property
    def counts(self) -> dict[str, int]:
        """Число проверок каждого статуса в порядке словаря контракта."""
        statuses = [item.status for item in self.checks.items]
        return {status.value: statuses.count(status) for status in CheckStatus}

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "active_network_check": self.active_network_check,
            "outcome": self.outcome.value,
            "counts": self.counts,
            "sources": [item.to_dict() for item in self.sources],
            "checks": self.checks.to_dict(),
        }


class QuickCheckHandler:
    """Прочитать источники один раз, собрать проверки сводки и проверки согласованности без изменений.

    Порядок чтения: части Xray, `xkeen.json`, параметры init, списки исключённых
    и перехватываемых портов, наблюдение процесса — функциями сводки, затем
    инвентарь геобаз функцией чтения установки. Keenetic и список исключённых
    адресов не читаются. `None` вместо обработчика или источника — источник не
    подключён: зависящие проверки «не проверено» с причиной `source_not_connected`,
    сценарий его не вызывает. Отказ источника не прерывает чтение остальных
    и не делает сценарий неуспешным.
    """

    def __init__(
        self,
        proxy: InspectProxyConfigHandler | None,
        processes: XrayProcessSource | None,
        geodata: GeoDatabaseSource | None,
        *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._proxy = proxy
        self._processes = processes
        self._geodata = geodata
        self._operation_ids = operation_ids

    def execute(self, command: QuickCheck) -> Result[QuickCheckView]:
        """Выполнить чтение и проверки; отказы источников остаются в итоге чтения, сценарий отказывает только на команде."""
        operation_id = self._operation_ids()
        name = QuickCheck.name
        if type(command) is not QuickCheck:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)

        readings = read_summary_sources(self._proxy, self._processes)
        inventory = None if self._geodata is None else read_geo_databases(self._geodata)
        # Проверки областей берутся из сводки, собранной по тем же ответам источников. Путь DNS в сводке привязан
        # к области и наследует отказ её источников; здесь это сетевая проверка, которая не выполняется в любом случае.
        area_checks = {item.check.code: item.check for item in build_status_summary(readings).areas}
        xray = _value(readings, QuickCheckSource.XRAY)
        checks = ChecksView(False, (
            _dependent(XRAY_CONFIG_CHECK, (xray,), xray_config_check),
            _dependent(GEODATA_REFERENCES_CHECK, (xray, inventory), _geodata_check),
            area_checks[FALLBACK_CHECK],
            area_checks[AUTOSTART_CHECK],
            _dependent(
                PORT_53_MODE_CHECK,
                tuple(_value(readings, source) for source in (
                    QuickCheckSource.INIT, QuickCheckSource.PORT_EXCLUDE, QuickCheckSource.PORT_PROXYING,
                )),
                port_53_mode_check,
            ),
            area_checks[XRAY_PROCESS_CHECK],
            area_checks[INTERCEPTION_CHECK],
            port_53_path_not_checked(),
            area_checks[VPN_REACHABLE_CHECK],
        ))
        sources = tuple(
            _source_view(source, inventory if source is QuickCheckSource.GEODATA else _value(readings, source))
            for source in QuickCheckSource
        )
        failed_found = any(item.status is CheckStatus.FAILED for item in checks.items)
        outcome = QuickCheckOutcome.FAILED if failed_found else QuickCheckOutcome.INCOMPLETE
        return succeeded(operation_id, name, QuickCheckView(outcome, sources, checks))


def _value(readings: SummaryReadings, source: QuickCheckSource) -> object | None:
    """Ответ источника сводки: модель, `ErrorDetail` либо `None`, если источник не подключён."""
    if source is QuickCheckSource.PROCESS:
        return readings.process
    models = readings.models(_SOURCE_PORTS[source])
    return None if models is None else models[0]


def _dependent(code: str, values: tuple[object | None, ...], build) -> CheckView:
    """Проверка по ответам источников: первый неподключённый или отказавший источник в порядке чтения даёт «не проверено».

    Ответы просматриваются одним проходом в порядке чтения: более поздний
    неподключённый источник не перекрывает уже произошедший отказ более раннего.
    """
    for value in values:
        if value is None:
            return not_checked(code, False, SummaryReason.SOURCE_NOT_CONNECTED.value)
        if isinstance(value, ErrorDetail):
            return not_checked(code, False, str.__str__(value.code))
    return build(*values)


def _geodata_check(config: XrayConfigSet, inventory: GeoDatabaseInventory) -> CheckView:
    """Разрешимость ссылок на геобазы; несогласованность инвентаря и конфигурации — «не проверено» с кодом домена."""
    try:
        state = assemble_geodata_state(inventory, config)
    except GeoDataError as error:
        return not_checked(GEODATA_REFERENCES_CHECK, False, error.code.value)
    return geodata_references_check(state)


def _source_view(source: QuickCheckSource, value: object | None) -> SourceReadView:
    if value is None:
        return SourceReadView(source, SourceState.NOT_CONNECTED)
    if isinstance(value, ErrorDetail):
        return SourceReadView(source, SourceState.FAILED, value)
    return SourceReadView(source, SourceState.READ)
