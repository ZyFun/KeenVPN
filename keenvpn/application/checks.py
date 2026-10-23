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

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
import re
from types import MappingProxyType

from keenvpn.application.contract import CheckStatus, ErrorDetail
from keenvpn.domain.geodata import GeoDataState, GeoFileStatus, UnsupportedGeoReference
from keenvpn.domain.xkeen_config import (
    XKeenFlagStatus, XKeenInitParameters, XKeenList, XKeenListItemKind, port_53_facts,
)
from keenvpn.domain.xray_config import (
    RuleTargetKind, TagRepeat, TagRepeats, XrayConfigSet, summarize_xray_config, tag_repeats,
)
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
XRAY_CONFIG_CHECK = "xray_config_consistent"
"""Ссылки и теги конфигурации Xray согласованы по структурной сводке; загрузку конфигурации Xray это не подтверждает."""
PORT_53_MODE_CHECK = "dns_port_53_mode_consistent"
"""Выбранный режим порта 53 не противоречит спискам портов и флагам init; фактический путь DNS не проверяется."""

_CODE = re.compile(r"\A[a-z][a-z0-9_]{2,63}\Z")
_PORT_ITEMS = (XKeenListItemKind.PORT, XKeenListItemKind.RANGE)
_REPLACED_SECTIONS = ("routing", "dns")
"""Разделы, которые `Config.Override` Xray заменяет целиком разделом последней части, а не объединяет."""


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
    DUPLICATE_TAGS = "duplicate_tags"
    """Тег повторяется там, где объединение частей его не схлопывает: в единственной или первой части; Xray такой набор не загрузит."""
    TAGS_REPEATED_ACROSS_PARTS = "tags_repeated_across_parts"
    """Повтор тега затрагивает объединение частей: Xray переопределяет теги и заменяет `routing`, а сводка это не моделирует."""
    SECTIONS_REPEATED_ACROSS_PARTS = "sections_repeated_across_parts"
    """Раздел `routing` или `dns` есть в нескольких частях: Xray берёт раздел последней, сводка действующий не выбирает."""
    UNRESOLVED_REFERENCES = "unresolved_references"
    """`inboundTag`, `outboundTag`, `balancerTag` правила или `fallbackTag` балансировщика не находит цель."""
    RULE_TARGET_AMBIGUOUS = "rule_target_ambiguous"
    """Правило указывает оба назначения или ни одного."""
    UNSUPPORTED_STRUCTURES = "unsupported_structures"
    """Сводка не прочитала часть мест конфигурации, поэтому согласованность не подтверждается."""
    PORT_53_IN_BOTH_LISTS = "port_53_in_both_lists"
    """Порт 53 есть и в списке исключённых, и в списке перехватываемых портов."""
    EXCLUDE_LIST_IGNORED = "exclude_list_ignored"
    """Исключение выбрано, но список перехватываемых портов непуст: XKeen игнорирует список исключений целиком."""
    PROXY_DNS_CONTRADICTS_EXCLUSION = "proxy_dns_contradicts_exclusion"
    """Исключение выбрано, а флаг `proxy_dns` включён."""
    FLAGS_UNKNOWN = "flags_unknown"
    """`proxy_dns` или `proxy_router` прочитан неоднозначно: согласованность с флагами не оценить."""


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


def not_checked(code: str, network: bool, reason: str) -> CheckView:
    """Проверка, которая не выполнялась: источник не подключён, отказал или проверять нечего."""
    return CheckView(code, CheckStatus.NOT_CHECKED, network, reason)


def first_source_error(values: Iterable[object]) -> ErrorDetail | None:
    """Первый отказ среди ответов источников в порядке их чтения либо `None`.

    Проверка с несколькими источниками объясняется первым отказом по порядку
    чтения: сценарии сводки и быстрой проверки используют одно правило.
    """
    for value in values:
        if isinstance(value, ErrorDetail):
            return value
    return None


def xray_config_check(config: XrayConfigSet) -> CheckView:
    """Согласованность ссылок и тегов конфигурации Xray по структурной сводке.

    По порядку: повтор непустого тега, который объединение частей не схлопывает,
    — `failed` / `duplicate_tags`: повтор внутри единственной части либо повтор
    inbound или outbound внутри первой части (`Config.Override` заменяет лишь
    первую найденную запись, вторая остаётся, и Xray набор не загрузит);
    раздел `routing` или `dns` в нескольких частях — `unsupported` /
    `sections_repeated_across_parts`: Xray берёт раздел последней части целиком,
    сводка действующий раздел не выбирает, поэтому ссылки и назначения правил
    оцениваются только при единственном разделе; ссылка правила или
    `fallbackTag` без цели — `failed` / `unresolved_references`; правило
    с обоими назначениями или без назначения — `failed` / `rule_target_ambiguous`;
    любой другой повтор тега — внутри последующей части, между частями,
    у балансировщиков при нескольких частях — `unsupported` /
    `tags_repeated_across_parts`: его итог зависит от объединения частей,
    которое сводка не моделирует; места, которые сводка не прочитала, —
    `unsupported` / `unsupported_structures`; иначе `passed`. «Успешно»
    не подтверждает, что Xray загрузит конфигурацию.
    """
    if type(config) is not XrayConfigSet:
        raise TypeError("Ожидается XrayConfigSet.")
    summary = summarize_xray_config(config.parts)
    repeats = tag_repeats(config.parts)
    rules = summary["rules"]
    balancers = summary["balancers"]
    if _unmerged_repeats(repeats, config):
        return CheckView(XRAY_CONFIG_CHECK, CheckStatus.FAILED, False, CheckReason.DUPLICATE_TAGS.value)
    if any(section in _REPLACED_SECTIONS for section in summary["duplicate_sections"]):
        return CheckView(XRAY_CONFIG_CHECK, CheckStatus.UNSUPPORTED, False, CheckReason.SECTIONS_REPEATED_ACROSS_PARTS.value)
    resolvable = (RuleTargetKind.OUTBOUND.value, RuleTargetKind.BALANCER.value)
    if (
        any(not rule["inbound_tags_resolved"] for rule in rules)
        or any(rule["target_kind"] in resolvable and not rule["target_resolved"] for rule in rules)
        or any(balancer["fallback_known"] and not balancer["fallback_resolved"] for balancer in balancers)
    ):
        return CheckView(XRAY_CONFIG_CHECK, CheckStatus.FAILED, False, CheckReason.UNRESOLVED_REFERENCES.value)
    if any(rule["target_kind"] not in resolvable for rule in rules):
        return CheckView(XRAY_CONFIG_CHECK, CheckStatus.FAILED, False, CheckReason.RULE_TARGET_AMBIGUOUS.value)
    if repeats.within_parts or repeats.between_parts:
        return CheckView(XRAY_CONFIG_CHECK, CheckStatus.UNSUPPORTED, False, CheckReason.TAGS_REPEATED_ACROSS_PARTS.value)
    if summary["unsupported_paths"]:
        return CheckView(XRAY_CONFIG_CHECK, CheckStatus.UNSUPPORTED, False, CheckReason.UNSUPPORTED_STRUCTURES.value)
    return CheckView(XRAY_CONFIG_CHECK, CheckStatus.PASSED, False, None)


def _unmerged_repeats(repeats: TagRepeats, config: XrayConfigSet) -> tuple[TagRepeat, ...]:
    """Повторы, которые объединение частей не схлопывает: все в единственной части, inbound и outbound в первой.

    В первой части `Config.Override` заменяет только первую запись с тегом,
    поэтому её повтор сохраняется; раздел `routing` последующая часть заменяет
    целиком, поэтому повтор балансировщика при нескольких частях зависит от
    объединения и сюда не входит.
    """
    if len(config.parts) <= 1:
        return repeats.within_parts
    first = config.parts[0].name
    return tuple(
        item for item in repeats.within_parts if item.section != "balancers" and item.parts.count(first) >= 2
    )


def port_53_mode_check(init: XKeenInitParameters, port_exclude: XKeenList, port_proxying: XKeenList) -> CheckView:
    """Согласованность выбранного режима порта 53 со списками портов и флагами init.

    Исключение выбрано, если порт 53 записан в списке исключённых портов
    отдельной записью или диапазоном. По порядку: порт 53 в обоих списках —
    `failed` / `port_53_in_both_lists`; исключение выбрано при непустом списке
    перехватываемых портов — `failed` / `exclude_list_ignored` (установленный
    XKeen тогда игнорирует список исключений целиком); исключение выбрано при
    `proxy_dns="on"` — `failed` / `proxy_dns_contradicts_exclusion`; `proxy_dns`
    или `proxy_router` прочитан неоднозначно — `unsupported` / `flags_unknown`;
    иначе `passed`, в том числе когда исключение не выбрано: его отсутствие —
    не ошибка и не доказательство перехвата. Для `proxy_router` правила
    противоречия нет: проверяется только его читаемость. Фактический путь DNS
    остаётся сетевой проверкой «не проверено».
    """
    facts = port_53_facts(init, port_exclude, port_proxying)
    excluded = facts.port_exclude_entry or facts.port_exclude_range
    if excluded and (facts.port_proxying_entry or facts.port_proxying_range):
        return CheckView(PORT_53_MODE_CHECK, CheckStatus.FAILED, False, CheckReason.PORT_53_IN_BOTH_LISTS.value)
    if excluded and any(item.kind in _PORT_ITEMS for item in port_proxying.items):
        return CheckView(PORT_53_MODE_CHECK, CheckStatus.FAILED, False, CheckReason.EXCLUDE_LIST_IGNORED.value)
    if excluded and facts.proxy_dns.status is XKeenFlagStatus.PRESENT and facts.proxy_dns.value == "on":
        return CheckView(PORT_53_MODE_CHECK, CheckStatus.FAILED, False, CheckReason.PROXY_DNS_CONTRADICTS_EXCLUSION.value)
    if facts.proxy_dns.status is not XKeenFlagStatus.PRESENT or facts.proxy_router.status is not XKeenFlagStatus.PRESENT:
        return CheckView(PORT_53_MODE_CHECK, CheckStatus.UNSUPPORTED, False, CheckReason.FLAGS_UNKNOWN.value)
    return CheckView(PORT_53_MODE_CHECK, CheckStatus.PASSED, False, None)
