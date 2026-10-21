"""Сводка состояния по областям для шапки главного меню и пункта «Сводка».

Один сценарий даёт раздельно ядро Xray, перехват, доступность VPN, DNS и порт 53,
автозапуск, режим резерва и черновик. Каждый источник читается один раз,
и чтение одного не зависит от других: отказ или неподключённый источник дают
«не проверено» только областям, которые от него зависят, а не отказ всей
сводки и не исправность. Сетевых проб нет: доступность VPN и фактический путь
DNS всегда «не проверено»; правила перехвата и черновики этой версией не
читаются — «не поддерживается». Ничего не записывается, команды XKeen не
вызываются. Успех описывает снимок на момент чтения и не подтверждает работу
VPN, перехват трафика или маршрут клиента.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar

from keenvpn.application.checks import (
    VPN_REACHABLE_CHECK, XRAY_PROCESS_CHECK, CheckReason, ChecksView, CheckView, vpn_reachability_not_checked,
    xray_process_check,
)
from keenvpn.application.contract import (
    CONTRACT_VERSION, CheckStatus, ErrorDetail, OperationIdFactory, Result, check_contract_version, failed,
    invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.installation import read_xray_process
from keenvpn.application.ports import XrayProcessSource
from keenvpn.application.proxy_config import InspectProxyConfigHandler, Port53View, ProxyConfigSource, XKeenFlagView
from keenvpn.application.views import view_dict
from keenvpn.domain.routing import RoutingAction
from keenvpn.domain.routing_import import RuleTarget, balancer_fallbacks
from keenvpn.domain.xkeen_config import (
    XKeenFlag, XKeenFlagStatus, XKeenInitParameters, XKeenList, XKeenSettings, port_53_facts,
)
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectStatusSummary:
    """Собрать раздельные состояния областей для шапки меню и пункта «Сводка»."""

    name: ClassVar[str] = "inspect_status_summary"

    contract_version: int = CONTRACT_VERSION


class SummaryArea(StrEnum):
    """Область сводки; порядок членов — порядок показа."""

    CORE = "core"
    INTERCEPTION = "interception"
    VPN = "vpn"
    DNS = "dns"
    AUTOSTART = "autostart"
    FALLBACK = "fallback"
    DRAFT = "draft"


class AreaState(StrEnum):
    """Прочитанное состояние области; это факт источника, а не вывод об исправности."""

    RUNNING = "running"
    """Один процесс Xray и маркер готовности; готовность канала этим не подтверждается."""
    STOPPED = "stopped"
    """Процесса нет и маркер снят."""
    PROCESS_WITHOUT_MARKER = "process_without_marker"
    MARKER_WITHOUT_PROCESS = "marker_without_process"
    MULTIPLE_PROCESSES = "multiple_processes"
    EXCLUDED = "excluded"
    """Порт 53 записан отдельной записью в списке исключённых портов."""
    EXCLUDED_BY_RANGE = "excluded_by_range"
    """Порт 53 входит только в диапазон списка исключённых портов."""
    NOT_EXCLUDED = "not_excluded"
    """Порта 53 нет в списке исключённых портов; это не ошибка и не доказательство перехвата."""
    ON = "on"
    OFF = "off"
    NO_DIRECT_FALLBACK = "no_direct_fallback"
    """kill-switch включён, fallback всех балансировщиков ведёт к блокировке."""
    DIRECT_FALLBACK = "direct_fallback"
    """kill-switch выключен, fallback всех балансировщиков ведёт к прямому выходу."""


AREA_STATES: Mapping[SummaryArea, frozenset[AreaState]] = MappingProxyType({
    SummaryArea.CORE: frozenset({
        AreaState.RUNNING, AreaState.STOPPED, AreaState.PROCESS_WITHOUT_MARKER, AreaState.MARKER_WITHOUT_PROCESS,
        AreaState.MULTIPLE_PROCESSES,
    }),
    SummaryArea.INTERCEPTION: frozenset(),
    SummaryArea.VPN: frozenset(),
    SummaryArea.DNS: frozenset({AreaState.EXCLUDED, AreaState.EXCLUDED_BY_RANGE, AreaState.NOT_EXCLUDED}),
    SummaryArea.AUTOSTART: frozenset({AreaState.ON, AreaState.OFF}),
    SummaryArea.FALLBACK: frozenset({AreaState.NO_DIRECT_FALLBACK, AreaState.DIRECT_FALLBACK}),
    SummaryArea.DRAFT: frozenset(),
})
"""Допустимые состояния каждой области. Таблица только для чтения."""

AREA_LABELS: Mapping[SummaryArea, str] = MappingProxyType({
    SummaryArea.CORE: "Ядро Xray",
    SummaryArea.INTERCEPTION: "Перехват",
    SummaryArea.VPN: "Доступность VPN",
    SummaryArea.DNS: "DNS и порт 53",
    SummaryArea.AUTOSTART: "Автозапуск",
    SummaryArea.FALLBACK: "Режим резерва",
    SummaryArea.DRAFT: "Черновик",
})
"""Заранее заданная русская подпись каждой области; интерфейсы только показывают её. Таблица только для чтения."""

STATE_LABELS: Mapping[AreaState, str] = MappingProxyType({
    AreaState.RUNNING: "работает",
    AreaState.STOPPED: "остановлено",
    AreaState.PROCESS_WITHOUT_MARKER: "процесс без маркера готовности",
    AreaState.MARKER_WITHOUT_PROCESS: "маркер готовности без процесса",
    AreaState.MULTIPLE_PROCESSES: "несколько процессов",
    AreaState.EXCLUDED: "исключение 53 включено",
    AreaState.EXCLUDED_BY_RANGE: "исключение 53 диапазоном",
    AreaState.NOT_EXCLUDED: "исключение 53 выключено",
    AreaState.ON: "включён",
    AreaState.OFF: "выключен",
    AreaState.NO_DIRECT_FALLBACK: "без прямого резерва",
    AreaState.DIRECT_FALLBACK: "прямой резерв разрешён",
})
"""Заранее заданная русская подпись каждого состояния; интерфейсы только показывают её. Таблица только для чтения."""

PORT_53_HINT = (
    "Включение исключения оставляет TCP/UDP DNS на порту 53 вне прозрачного перехвата XKeen. "
    "Это может помочь при конфликте DNS, например при работе с Pritunl. "
    "Опция не открывает порт и не гарантирует исправление любой проблемы рабочего VPN."
)
"""Подсказка к выбору исключения порта 53; тот же текст показывает мастер."""

INTERCEPTION_CHECK = "interception_active"
"""Перехват трафика XKeen действует; требует чтения правил перехвата, которого в этой версии нет."""
PORT_53_PATH_CHECK = "dns_port_53_path"
"""Фактический путь DNS через порт 53; требует сетевой пробы, которую сводка не выполняет."""
AUTOSTART_CHECK = "autostart_flag_unambiguous"
"""Флаг автозапуска XKeen в init прочитан однозначно; запуск при загрузке этим не проверяется."""
FALLBACK_CHECK = "fallback_profile_consistent"
"""kill-switch и fallback балансировщиков образуют один из двух профилей резерва."""
DRAFT_CHECK = "draft_present"
"""Есть ли черновик изменений; черновиков в этой версии нет."""


class SummaryReason(StrEnum):
    """Стабильные причины статусов сводки сверх причин `checks.py` и кодов отказов источников."""

    SOURCE_NOT_CONNECTED = "source_not_connected"
    """Источник области не подключён: сценарий его не вызывал."""
    INTERCEPTION_NOT_OBSERVED = "interception_not_observed"
    """Правила перехвата не читаются: перехват не выводится из процесса и файлов."""
    DRAFTS_NOT_IMPLEMENTED = "drafts_not_implemented"
    """Черновиков в этой версии нет."""
    FLAG_MISSING = "flag_missing"
    FLAG_DUPLICATE = "flag_duplicate"
    FLAG_UNEXPECTED = "flag_unexpected"
    FLAG_UNSUPPORTED = "flag_unsupported"
    KILLSWITCH_UNKNOWN = "killswitch_unknown"
    """Значение kill-switch не `on` и не `off` либо поля нет."""
    BALANCERS_UNSUPPORTED = "balancers_unsupported"
    """Outbound, раздел `routing` или список балансировщиков не читаются однозначно."""
    NO_BALANCERS = "no_balancers"
    FALLBACK_NOT_SET = "fallback_not_set"
    FALLBACK_NOT_RESOLVED = "fallback_not_resolved"
    """Цель fallback не найдена, неоднозначна, передаёт соединение дальше или имеет протокол без действия."""
    FALLBACK_TO_VPN = "fallback_to_vpn"
    """Fallback ведёт к другому outbound прокси или туннеля."""
    FALLBACK_PROFILE_MISMATCH = "fallback_profile_mismatch"
    """kill-switch противоречит цели fallback."""


_AREA_CHECKS: Mapping[SummaryArea, tuple[str, bool]] = MappingProxyType({
    SummaryArea.CORE: (XRAY_PROCESS_CHECK, False),
    SummaryArea.INTERCEPTION: (INTERCEPTION_CHECK, False),
    SummaryArea.VPN: (VPN_REACHABLE_CHECK, True),
    SummaryArea.DNS: (PORT_53_PATH_CHECK, True),
    SummaryArea.AUTOSTART: (AUTOSTART_CHECK, False),
    SummaryArea.FALLBACK: (FALLBACK_CHECK, False),
    SummaryArea.DRAFT: (DRAFT_CHECK, False),
})
_FLAG_OUTCOMES = {
    XKeenFlagStatus.MISSING: (CheckStatus.FAILED, SummaryReason.FLAG_MISSING),
    XKeenFlagStatus.DUPLICATE: (CheckStatus.FAILED, SummaryReason.FLAG_DUPLICATE),
    XKeenFlagStatus.UNEXPECTED: (CheckStatus.FAILED, SummaryReason.FLAG_UNEXPECTED),
    XKeenFlagStatus.UNSUPPORTED: (CheckStatus.UNSUPPORTED, SummaryReason.FLAG_UNSUPPORTED),
}
_AUTOSTART_FLAG = "start_auto"
_PROXY_SOURCES = (
    ProxyConfigSource.XRAY, ProxyConfigSource.SETTINGS, ProxyConfigSource.INIT, ProxyConfigSource.PORT_EXCLUDE,
    ProxyConfigSource.PORT_PROXYING,
)
_DNS_SOURCES = (ProxyConfigSource.INIT, ProxyConfigSource.PORT_EXCLUDE, ProxyConfigSource.PORT_PROXYING)


@dataclass(frozen=True, slots=True)
class SummaryAreaView:
    """Одна область: код, прочитанное состояние, проверка и отказ источника.

    `state` — состояние из допустимого набора области либо `None`, если оно
    не установлено. `check` — проверка с кодом и признаком сети, заданными для
    области. `source_error` — безопасное описание отказа источника, из-за которого
    область «не проверено»: причина проверки тогда равна коду отказа. Статус
    `passed` требует установленного состояния, поэтому область без прочитанного
    источника исправной не бывает.
    """

    area: SummaryArea
    state: AreaState | None
    check: CheckView
    source_error: ErrorDetail | None = None

    def __post_init__(self) -> None:
        if (
            type(self.area) is not SummaryArea
            or (self.state is not None and type(self.state) is not AreaState)
            or type(self.check) is not CheckView
            or (self.source_error is not None and type(self.source_error) is not ErrorDetail)
        ):
            raise TypeError("Некорректное описание области сводки.")
        code, network = _AREA_CHECKS[self.area]
        if (
            self.check.code != code or self.check.network is not network
            or (self.state is not None and self.state not in AREA_STATES[self.area])
            or (self.check.status is CheckStatus.PASSED and self.state is None)
            or (self.source_error is not None and (
                self.state is not None or self.check.status is not CheckStatus.NOT_CHECKED
                or self.check.reason != str.__str__(self.source_error.code)
            ))
        ):
            raise TypeError("Состояние, проверка и отказ не согласованы с областью сводки.")

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление со стабильными кодами."""
        return {
            "area": self.area.value,
            "state": None if self.state is None else self.state.value,
            "check": self.check.to_dict(),
            "source_error": None if self.source_error is None else self.source_error.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class FallbackView:
    """Факты режима резерва: kill-switch и цели fallback балансировщиков по видам, без тегов.

    Счётчики — `None`, если outbound или балансировщики не читаются однозначно.
    """

    killswitch: XKeenFlagView
    balancer_count: int | None
    direct_count: int | None
    blocked_count: int | None
    vpn_count: int | None
    unresolved_count: int | None
    unset_count: int | None

    def __post_init__(self) -> None:
        counts = (self.direct_count, self.blocked_count, self.vpn_count, self.unresolved_count, self.unset_count)
        if type(self.killswitch) is not XKeenFlagView or not (
            (self.balancer_count is None and all(item is None for item in counts))
            or (
                all(type(item) is int and item >= 0 for item in (self.balancer_count, *counts))
                and sum(counts) == self.balancer_count
            )
        ):
            raise TypeError("Некорректные факты режима резерва.")

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {**view_dict(self), "killswitch": view_dict(self.killswitch)}


@dataclass(frozen=True, slots=True)
class StatusSummaryView:
    """Семь областей в порядке показа и факты для подробностей.

    `active_network_check` задаёт сценарий; сводка пассивна, поэтому сетевые
    проверки областей не могут быть `passed` или `failed`: это проверяет набор
    `checks` из проверок всех областей. `port_53` — факты порта 53, если
    источники области DNS прочитаны; `fallback` — факты режима резерва, если
    прочитаны его источники. PID, теги, имена файлов, адреса и значения
    параметров сюда не входят.
    """

    active_network_check: bool
    areas: tuple[SummaryAreaView, ...]
    port_53: Port53View | None
    fallback: FallbackView | None
    checks: ChecksView = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.areas) is not tuple
            or any(type(item) is not SummaryAreaView for item in self.areas)
            or len(self.areas) != len(SummaryArea)
            or any(item.area is not area for item, area in zip(self.areas, SummaryArea))
            or (self.port_53 is not None and type(self.port_53) is not Port53View)
            or (self.fallback is not None and type(self.fallback) is not FallbackView)
        ):
            raise TypeError("Сводка содержит каждую область один раз в порядке показа.")
        dns, fallback = self.areas[3], self.areas[5]
        if (dns.state is None) is not (self.port_53 is None) or (
            (fallback.check.status is CheckStatus.NOT_CHECKED) is not (self.fallback is None)
        ):
            raise TypeError("Факты порта 53 и резерва есть, только когда их источники прочитаны.")
        # Набор проверок проверяет признак активной проверки и инвариант пассивного результата.
        checks = ChecksView(self.active_network_check, tuple(item.check for item in self.areas))
        object.__setattr__(self, "checks", checks)

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "active_network_check": self.active_network_check,
            "areas": [item.to_dict() for item in self.areas],
            "port_53": None if self.port_53 is None else self.port_53.to_dict(),
            "fallback": None if self.fallback is None else self.fallback.to_dict(),
        }


class InspectStatusSummaryHandler:
    """Прочитать источники областей по одному разу и собрать сводку с допуском отказов.

    Порядок: части Xray, `xkeen.json`, параметры init, списки исключённых
    и перехватываемых портов через обработчик конфигурации прокси, затем
    наблюдение процесса. Список исключённых адресов, Keenetic и геобазы не
    читаются: ни одна область от них не зависит. `None` вместо обработчика или
    источника — источник не подключён: его области «не проверено» с причиной
    `source_not_connected`, сценарий его не вызывает. Отказ источника не
    прерывает чтение остальных и не делает сценарий неуспешным.
    """

    def __init__(
        self,
        proxy: InspectProxyConfigHandler | None,
        processes: XrayProcessSource | None,
        *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._proxy = proxy
        self._processes = processes
        self._operation_ids = operation_ids

    def execute(self, command: InspectStatusSummary) -> Result[StatusSummaryView]:
        """Выполнить чтение; отказы источников остаются в областях, сценарий отказывает только на команде."""
        operation_id = self._operation_ids()
        name = InspectStatusSummary.name
        if type(command) is not InspectStatusSummary:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)

        proxy = None if self._proxy is None else {source: self._proxy.read_source(source) for source in _PROXY_SOURCES}
        process = None if self._processes is None else read_xray_process(self._processes)

        def models(*sources: ProxyConfigSource) -> tuple[object, ...] | None:
            return None if proxy is None else tuple(proxy[source] for source in sources)

        core, _ = _assemble(SummaryArea.CORE, None if process is None else (process,), _core)
        dns, port_53 = _assemble(SummaryArea.DNS, models(*_DNS_SOURCES), _dns)
        autostart, _ = _assemble(SummaryArea.AUTOSTART, models(ProxyConfigSource.INIT), _autostart)
        fallback, fallback_facts = _assemble(
            SummaryArea.FALLBACK, models(ProxyConfigSource.XRAY, ProxyConfigSource.SETTINGS), _fallback,
        )
        # Сводка пассивна: признак активной сетевой проверки всегда выключен, проб нет.
        view = StatusSummaryView(False, (
            core,
            _constant(SummaryArea.INTERCEPTION, CheckStatus.UNSUPPORTED, SummaryReason.INTERCEPTION_NOT_OBSERVED),
            SummaryAreaView(SummaryArea.VPN, None, vpn_reachability_not_checked()),
            dns,
            autostart,
            fallback,
            _constant(SummaryArea.DRAFT, CheckStatus.UNSUPPORTED, SummaryReason.DRAFTS_NOT_IMPLEMENTED),
        ), port_53, fallback_facts)
        return succeeded(operation_id, name, view)


_Built = tuple[SummaryAreaView, object]


def _assemble(area: SummaryArea, values: tuple[object, ...] | None, build: Callable[..., _Built]) -> _Built:
    """Собрать область из моделей её источников; первый отказ по порядку чтения даёт «не проверено»."""
    check_code, network = _AREA_CHECKS[area]
    if values is None:
        check = CheckView(check_code, CheckStatus.NOT_CHECKED, network, SummaryReason.SOURCE_NOT_CONNECTED.value)
        return SummaryAreaView(area, None, check), None
    for value in values:
        if isinstance(value, ErrorDetail):
            check = CheckView(check_code, CheckStatus.NOT_CHECKED, network, str.__str__(value.code))
            return SummaryAreaView(area, None, check, value), None
    return build(*values)


def _constant(area: SummaryArea, status: CheckStatus, reason: SummaryReason) -> SummaryAreaView:
    check_code, network = _AREA_CHECKS[area]
    return SummaryAreaView(area, None, CheckView(check_code, status, network, reason.value))


def _core(observation: XrayProcessObservation) -> _Built:
    return SummaryAreaView(SummaryArea.CORE, AreaState(observation.state.value), xray_process_check(observation)), None


def _dns(init: XKeenInitParameters, port_exclude: XKeenList, port_proxying: XKeenList) -> _Built:
    """Выбранное исключение — факт файла; путь DNS требует сетевой пробы и остаётся «не проверено»."""
    facts = port_53_facts(init, port_exclude, port_proxying)
    if facts.port_exclude_entry:
        state = AreaState.EXCLUDED
    elif facts.port_exclude_range:
        state = AreaState.EXCLUDED_BY_RANGE
    else:
        state = AreaState.NOT_EXCLUDED
    check = CheckView(PORT_53_PATH_CHECK, CheckStatus.NOT_CHECKED, True, CheckReason.NETWORK_CHECK_NOT_PERFORMED.value)
    return SummaryAreaView(SummaryArea.DNS, state, check), Port53View.from_facts(facts)


def _autostart(init: XKeenInitParameters) -> _Built:
    flag = init.switch(_AUTOSTART_FLAG)
    if flag.status is XKeenFlagStatus.PRESENT:
        check = CheckView(AUTOSTART_CHECK, CheckStatus.PASSED, False, None)
        return SummaryAreaView(SummaryArea.AUTOSTART, AreaState(flag.value), check), None
    status, reason = _FLAG_OUTCOMES[flag.status]
    return SummaryAreaView(SummaryArea.AUTOSTART, None, CheckView(AUTOSTART_CHECK, status, False, reason.value)), None


class _Fallback(StrEnum):
    DIRECT = "direct"
    BLOCKED = "blocked"
    VPN = "vpn"
    UNRESOLVED = "unresolved"
    UNSET = "unset"


_ACTION_KINDS = {
    RoutingAction.DIRECT: _Fallback.DIRECT, RoutingAction.BLOCK: _Fallback.BLOCKED, RoutingAction.VPN: _Fallback.VPN,
}
_UNDETERMINED = (
    (_Fallback.UNSET, SummaryReason.FALLBACK_NOT_SET),
    (_Fallback.UNRESOLVED, SummaryReason.FALLBACK_NOT_RESOLVED),
    (_Fallback.VPN, SummaryReason.FALLBACK_TO_VPN),
)


def _fallback_kind(target: RuleTarget | None) -> _Fallback:
    if target is None:
        return _Fallback.UNSET
    return _ACTION_KINDS.get(target.action, _Fallback.UNRESOLVED)


def _fallback(config: XrayConfigSet, settings: XKeenSettings) -> _Built:
    """Профиль резерва по kill-switch и целям fallback; цели разрешаются как назначения правил импорта."""
    killswitch = settings.killswitch
    targets = balancer_fallbacks(config)
    kinds = None if targets is None else [_fallback_kind(target) for target in targets]
    counts = (None,) * 6 if kinds is None else (len(kinds), *(kinds.count(kind) for kind in _Fallback))
    facts = FallbackView(XKeenFlagView(**killswitch.to_diagnostic()), *counts)
    state, status, reason = _fallback_profile(killswitch, kinds)
    check = CheckView(FALLBACK_CHECK, status, False, None if reason is None else reason.value)
    return SummaryAreaView(SummaryArea.FALLBACK, state, check), facts


def _fallback_profile(
    killswitch: XKeenFlag, kinds: list[_Fallback] | None,
) -> tuple[AreaState | None, CheckStatus, SummaryReason | None]:
    """Один из двух профилей плана; противоречие kill-switch и fallback важнее неопределённости целей."""
    if killswitch.status is not XKeenFlagStatus.PRESENT:
        return None, CheckStatus.UNSUPPORTED, SummaryReason.KILLSWITCH_UNKNOWN
    if kinds is None:
        return None, CheckStatus.UNSUPPORTED, SummaryReason.BALANCERS_UNSUPPORTED
    blocking = killswitch.value == "on"
    contradicting = _Fallback.DIRECT if blocking else _Fallback.BLOCKED
    if contradicting in kinds:
        return None, CheckStatus.FAILED, SummaryReason.FALLBACK_PROFILE_MISMATCH
    if not kinds:
        return None, CheckStatus.UNSUPPORTED, SummaryReason.NO_BALANCERS
    for kind, reason in _UNDETERMINED:
        if kind in kinds:
            return None, CheckStatus.UNSUPPORTED, reason
    return AreaState.NO_DIRECT_FALLBACK if blocking else AreaState.DIRECT_FALLBACK, CheckStatus.PASSED, None
