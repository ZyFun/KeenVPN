"""Текстовые представления результатов сценариев для терминала.

Представления получают только безопасные данные `Result` и переносят их
в строки с фиксированными русскими подписями. Строки из источников попадают
в вывод только после проверки формата своего вида: теги и коды, имена файлов,
интерфейсы сегментов, хеши, источник и версия геобазы. Правило тегов не допускает
`.`, `:`, `/` и `@`, поэтому домены, адреса, MAC, пути и URL, записанные в тег,
не выводятся. Значение вне формата заменяется пометкой. Управляющие символы и ANSI
не используются, данные не вычисляются и не дополняются: показывается лишь то,
что вернул сценарий. Группы правил показываются списком с карточками: строка
списка и карточка собраны из тех же отфильтрованных значений, а поиск по списку
видит только строку.
"""

from collections.abc import Callable, Iterable, Mapping
import re

from keenvpn.application.checks import CHECK_STATUS_LABELS, ChecksView, CheckView
from keenvpn.application.contract import CONTRACT_VERSION, CheckStatus, ErrorDetail, Result
from keenvpn.application.installation import GeoDataView, InstallationView, XrayProcessView
from keenvpn.application.keenetic_devices import (
    ASSIGNMENT_LABELS, MAX_DEVICE_NAME_LENGTH, PRESENCE_LABELS, PRESENCE_REASON_LABELS, SEGMENT_MATCH_LABELS,
    DeviceEntryView, DeviceListView, SegmentMatch,
)
from keenvpn.application.keenetic_state import KeeneticSegmentView, KeeneticStateView
from keenvpn.application.manager_metadata import ManagerMetadataStatusView
from keenvpn.application.proxy_config import (
    Port53View, ProxyConfigView, XKeenFlagView, XKeenListView, XrayPositionView,
)
from keenvpn.application.proxy_connections import BalancerConnectionView, ConnectionsView, OutboundConnectionView
from keenvpn.application.quick_check import (
    OUTCOME_LABELS as QUICK_CHECK_OUTCOME_LABELS, SOURCE_LABELS, SOURCE_STATE_LABELS, QuickCheckOutcome, QuickCheckSource,
    QuickCheckView, SourceReadView, SourceState,
)
from keenvpn.application.routing import (
    OUTCOME_LABELS, STEP_RESULT_LABELS, STEP_SKIPPED_LABEL, RouteExplanationView, RouteOutcome, RouteSelectionView,
    RouteStepView,
)
from keenvpn.application.routing_import import RuleGroupView, RoutingSchemeView
from keenvpn.application.routing_rules import (
    MetadataState, RuleGroupIdentityView, RuleListEntryView, RuleListView, TargetPositionState,
)
from keenvpn.application.status_summary import (
    AREA_LABELS, PORT_53_HINT, STATE_LABELS, AreaState, FallbackView, StatusSummaryView, SummaryArea, SummaryAreaView,
)
from keenvpn.interfaces.cli.menu import MAX_ITEM_NUMBER, ListEntry, MenuList
from keenvpn.interfaces.cli.terminal import UNAVAILABLE_MARK


Lines = list[str]
Presenter = Callable[[object], Lines | MenuList]

HIDDEN = "<скрыто>"
"""Пометка вместо строки, не прошедшей проверку формата."""
MISSING = "нет данных"
"""Пометка вместо отсутствующего значения."""
SNAPSHOT_NOTE = (
    "Это снимок источников на момент чтения: работу VPN, перехват трафика и маршрут клиента он не подтверждает."
)
PORT_53_NOTE = (
    "Фактический перехват DNS не проверялся: это факты файлов, а не состояние трафика. "
    "Отсутствие исключения само по себе не ошибка и не доказательство перехвата."
)
DNS_PRITUNL_NOTE = (
    "DNS и рабочие сайты через Pritunl проверяются раздельно: эта проверка не подтверждает ни того, ни другого."
)
MAX_TEXT_LENGTH = 500
_INDENT = "  "

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,63}")
"""Тег, код, состояние: правило `safe_identifier` домена — без `.`, `:`, `/`, `@` и пробелов."""
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,58}\.(?:json|dat)")
"""Имя части Xray или файла геобазы: без каталога, только расширения `.json` и `.dat`."""
_INTERFACE_ID = re.compile(r"(?=.{1,64}\Z)[A-Za-z][A-Za-z0-9]*(?:[/.][A-Za-z0-9]+)*")
"""Интерфейс сегмента Keenetic вида `Bridge0` или `GigabitEthernet0/Vlan1`: с буквы, без `:` и пробелов."""
_DIGEST = re.compile(r"[0-9a-f]{64}")
"""SHA-256 в нижнем регистре."""
_GEO_SOURCE = re.compile(
    r"(?=.{1,128}\Z)(?:[A-Za-z0-9][A-Za-z0-9_+-]*(?:\.[A-Za-z0-9_+-]+)*"
    r"|https?://[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?)"
)
"""Источник геобазы в форме, которую оставляет домен: идентификатор либо схема и хост без пути."""
_GEO_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
"""Версия геобазы: короткий идентификатор, как у домена."""
_RULE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
"""Идентификатор правила: UUID 8-4-4-4-12 в нижнем регистре, как проверяет домен."""
MAX_RULE_NAME_LENGTH = 64
"""Предел названия правила в символах: тот же, что у модели маршрутизации."""


def _shown(pattern: re.Pattern[str], value: object) -> str:
    if type(value) is str and pattern.fullmatch(value) is not None:
        return value
    return HIDDEN


def identifier(value: object) -> str:
    """Показать тег, код или состояние только в формате технического идентификатора; иначе пометку."""
    return _shown(_IDENTIFIER, value)


def file_name(value: object) -> str:
    """Показать имя части Xray или файла геобазы; иначе пометку."""
    return _shown(_FILE_NAME, value)


def optional_file_name(value: object) -> str:
    """Имя файла или пометка отсутствия."""
    return MISSING if value is None else file_name(value)


def interface_id(value: object) -> str:
    """Показать идентификатор интерфейса сегмента Keenetic; иначе пометку."""
    return _shown(_INTERFACE_ID, value)


def digest(value: object) -> str:
    """Показать SHA-256; иначе пометку."""
    return _shown(_DIGEST, value)


def optional_digest(value: object) -> str:
    """SHA-256 или пометка отсутствия."""
    return MISSING if value is None else digest(value)


def geo_source(value: object) -> str:
    """Показать источник геобазы в форме домена; иначе пометку."""
    return _shown(_GEO_SOURCE, value)


def geo_version(value: object) -> str:
    """Показать версию геобазы в форме домена; иначе пометку."""
    return _shown(_GEO_VERSION, value)


def optional_identifier(value: object) -> str:
    """Идентификатор или пометка отсутствия."""
    return MISSING if value is None else identifier(value)


def rule_id(value: object) -> str:
    """Показать идентификатор правила только в канонической форме UUID; иначе пометку."""
    return _shown(_RULE_ID, value)


def _user_text(value: object, limit: int) -> str:
    """Показать пользовательский текст только печатным, без пробелов по краям и в пределе длины; иначе пометку.

    Управляющие символы, ESC, невидимые символы, пробелы по краям, пустая
    и слишком длинная строка не выводятся: правило то же, что у моделей.
    """
    if type(value) is str and 1 <= len(value) <= limit and value.isprintable() and value == value.strip():
        return value
    return HIDDEN


def rule_name(value: object) -> str:
    """Показать название правила — пользовательский текст — по общему правилу пользовательского текста."""
    return _user_text(value, MAX_RULE_NAME_LENGTH)


def device_name(value: object) -> str:
    """Показать имя регистрации устройства — пользовательский текст — по тому же правилу, что название правила."""
    return _user_text(value, MAX_DEVICE_NAME_LENGTH)


def identifiers(values: Iterable[object]) -> str:
    """Перечислить идентификаторы через запятую; пустой список — «нет»."""
    items = [identifier(value) for value in values]
    return ", ".join(items) if items else "нет"


def known_value(known: object, value: object, show: Callable[[object], str], absent: str) -> str:
    """Различить отсутствие значения и известное, но скрытое сценарием значение.

    `known=False` — значения нет, показывается `absent`; `known=True` и `None` —
    значение задано, но application скрыл его как небезопасное, показывается
    пометка `<скрыто>`; иначе значение проходит фильтр своего вида.
    """
    if known is False:
        return absent
    if known is True:
        return HIDDEN if value is None else show(value)
    return HIDDEN


def flag(value: object) -> str:
    """Показать логическое значение словами; другой тип — пометка."""
    if type(value) is bool:
        return "да" if value else "нет"
    return HIDDEN


def optional_flag(value: object) -> str:
    """Логическое значение или пометка отсутствия."""
    return MISSING if value is None else flag(value)


def count(value: object) -> str:
    """Показать целое число; другой тип, включая bool, — пометка."""
    return str(value) if type(value) is int else HIDDEN


def optional_count(value: object) -> str:
    """Целое число или пометка отсутствия."""
    return MISSING if value is None else count(value)


def safe_text(value: object) -> str:
    """Показать заранее заданный текст сценария, если он печатный и не слишком длинный."""
    if type(value) is str and 0 < len(value) <= MAX_TEXT_LENGTH and value.isprintable():
        return value
    return HIDDEN


def _exact_label(labels: Mapping[object, str], kind: type, value: object) -> str:
    """Подпись каталога application только для точного перечисления `kind`; строка вместо него — пометка."""
    if type(value) is kind:
        return safe_text(labels[value])
    return HIDDEN


def check_status(value: object) -> str:
    """Показать подпись статуса проверки только для точного `CheckStatus`; иначе пометку.

    Подпись берётся из каталога application: меню не выводит статус из состояния
    или кодов ошибок и не принимает строку вместо перечисления.
    """
    return _exact_label(CHECK_STATUS_LABELS, CheckStatus, value)


def _indent(lines: Iterable[str], level: int = 1) -> Lines:
    return [_INDENT * level + line for line in lines]


def present_error(error: ErrorDetail) -> Lines:
    """Показать отказ сценария: категорию, код, уточнение, текст и безопасный следующий шаг.

    Шаг берётся из `error.next_step` как есть: меню его не выбирает и не выполняет.
    Без шага строка не выводится. Код и уточнение контракт допускает подклассами
    `str`, например перечислениями: фильтр получает их значение обычной строкой.
    """
    if type(error) is not ErrorDetail:
        raise TypeError("Ожидается ErrorDetail.")
    lines = [f"Отказ: {identifier(error.category.value)} / {identifier(str.__str__(error.code))}"]
    if error.reason is not None:
        lines.append(f"Уточнение: {identifier(str.__str__(error.reason))}")
    lines.append(f"Причина: {safe_text(error.message)}")
    step = error.next_step
    if step is not None:
        lines.append(f"Следующий шаг: {safe_text(step.message)}")
    return lines


def present_result(result: Result, present: Presenter) -> Lines | MenuList:
    """Показать результат: данные через переданное представление, отказ — общим способом."""
    if type(result) is not Result:
        raise TypeError("Ожидается Result сценария.")
    if result.succeeded:
        return present(result.data)
    return present_error(result.error)


def _flag_view(value: XKeenFlagView) -> str:
    return f"{identifier(value.status)} ({optional_identifier(value.value)})"


def _list_view(label: str, value: XKeenListView) -> str:
    return (
        f"{label}: строк {count(value.line_count)}, записей {count(value.entry_count)}, "
        f"портов {optional_count(value.port_count)}, диапазонов {optional_count(value.range_count)}, "
        f"адресов {optional_count(value.address_count)}, некорректных {count(value.invalid_count)}"
    )


def _segment_line(segment: KeeneticSegmentView) -> str:
    """Строка назначения сегмента: технический ID интерфейса после фильтра и признаки."""
    if type(segment) is not KeeneticSegmentView:
        return HIDDEN
    return (
        f"Сегмент {interface_id(segment.segment_id)}: назначение {identifier(segment.assignment)}, "
        f"политика {optional_identifier(segment.policy_id)}, запрет доступа {flag(segment.access_denied)}, "
        f"только просмотр {flag(segment.read_only)}"
    )


def present_keenetic_state(view: KeeneticStateView) -> Lines:
    """Показать политики, назначения сегментов и счётчики устройств без MAC, имён и адресов."""
    if type(view) is not KeeneticStateView:
        raise TypeError("Ожидается KeeneticStateView.")
    devices, registrations, runtime = view.devices, view.registrations, view.runtime
    lines = [
        "Keenetic",
        f"Политик: {count(view.policy_count)}; идентификаторы: {identifiers(view.policy_ids)}",
        f"Назначений сегментов: {count(len(view.segments))}; без политики: {count(view.segment_missing_policy_count)}",
    ]
    lines.extend(_INDENT + _segment_line(segment) for segment in view.segments)
    lines += [
        f"Записи устройств: всего {count(devices.record_count)}, разных MAC {count(devices.distinct_mac_count)}, "
        f"online {count(devices.online_count)}, offline {count(devices.offline_count)}, "
        f"неизвестно {count(devices.unknown_count)}",
        f"{_INDENT}Назначения: явных {count(devices.explicit_count)}, наследуют {count(devices.inherit_count)}, "
        f"без назначения {count(devices.unassigned_count)}, неизвестных {count(devices.unknown_assignment_count)}; "
        f"запрет доступа {count(devices.access_denied_count)}; только просмотр {count(devices.read_only_count)}",
        f"{_INDENT}Связи: с регистрацией {count(devices.with_registration_count)}, "
        f"с наблюдением {count(devices.with_observation_count)}, "
        f"неоднозначных наблюдений {count(devices.ambiguous_observation_count)}, "
        f"расхождений наблюдений {count(devices.observation_mismatch_count)}, "
        f"без политики {count(devices.missing_policy_count)}",
        f"Регистрации: всего {count(registrations.registration_count)}, "
        f"разных MAC {count(registrations.distinct_mac_count)}, повторов MAC {count(registrations.duplicate_mac_count)}, "
        f"нераспознанных {count(registrations.unresolvable_count)}, "
        f"без записи устройства {count(registrations.without_device_count)}",
        f"Наблюдения: всего {count(runtime.record_count)}, разных MAC {count(runtime.distinct_mac_count)}, "
        f"повторов MAC {count(runtime.duplicate_mac_count)}, нераспознанных {count(runtime.unresolvable_count)}, "
        f"активных {count(runtime.active_count)}, зарегистрированных {count(runtime.registered_count)}, "
        f"без записи устройства {count(runtime.without_device_count)}",
    ]
    return lines


def present_proxy_summary(view: ProxyConfigView) -> Lines:
    """Показать структурную сводку Xray и XKeen без доменов, адресов, путей и паролей."""
    if type(view) is not ProxyConfigView:
        raise TypeError("Ожидается ProxyConfigView.")
    xray, xkeen = view.xray, view.xkeen
    return [
        "Xray",
        f"Частей: {count(xray.part_count)}; разделов верхнего уровня: {count(len(xray.sections))}; "
        f"повторяющихся разделов: {count(len(xray.duplicate_sections))}",
        f"Inbound: {count(len(xray.inbounds))}; outbound: {count(len(xray.outbounds))}; "
        f"балансировщиков: {count(len(xray.balancers))}; правил маршрутизации: {count(xray.rule_count)}",
        f"DNS-теги: {identifiers(xray.dns_tags)}; стратегии доменов: {identifiers(xray.domain_strategies)}",
        f"Неподдержанных мест конфигурации: {count(len(xray.unsupported_paths))}",
        "XKeen",
        f"kill-switch: {_flag_view(xkeen.settings.killswitch)}; присваиваний init: {count(xkeen.init.assignment_count)}; "
        f"повторов имён init: {count(len(xkeen.init.duplicate_names))}",
        _list_view("Список исключённых портов", xkeen.port_exclude),
        _list_view("Список перехватываемых портов", xkeen.port_proxying),
        _list_view("Список исключённых адресов", xkeen.ip_exclude),
    ]


def _port53_facts(facts: Port53View) -> Lines:
    return [
        f"Запись {count(facts.port)} в списке исключённых портов: {flag(facts.port_exclude_entry)}; "
        f"диапазон с этим портом: {flag(facts.port_exclude_range)}",
        f"Запись {count(facts.port)} в списке перехватываемых портов: {flag(facts.port_proxying_entry)}; "
        f"диапазон с этим портом: {flag(facts.port_proxying_range)}",
        f"proxy_dns: {_flag_view(facts.proxy_dns)}; proxy_router: {_flag_view(facts.proxy_router)}",
    ]


def present_port53(view: ProxyConfigView) -> Lines:
    """Показать раздельные факты о порту 53 из файлов XKeen; фактический перехват не проверяется."""
    if type(view) is not ProxyConfigView:
        raise TypeError("Ожидается ProxyConfigView.")
    return [
        "Порт 53 по файлам конфигурации XKeen",
        *_port53_facts(view.xkeen.port_53),
        _list_view("Список исключённых портов", view.xkeen.port_exclude),
        _list_view("Список перехватываемых портов", view.xkeen.port_proxying),
        PORT_53_NOTE,
    ]


def present_geodata(view: GeoDataView) -> Lines:
    """Показать инвентарь файлов геобаз и ссылки правил без кодов наборов."""
    if type(view) is not GeoDataView:
        raise TypeError("Ожидается GeoDataView.")
    lines = [
        "Геобазы",
        f"Файлов найдено: {count(view.present_count)}; отсутствует: {count(view.missing_count)}; "
        f"лишних: {count(view.extra_count)}",
    ]
    for item in view.files:
        source = known_value(item.source_known, item.source, geo_source, "неизвестен")
        version = known_value(item.version_known, item.version, geo_version, "неизвестна")
        lines.append(
            f"{_INDENT}{file_name(item.name)}: {'найден' if item.present is True else 'отсутствует'}, "
            f"размер {optional_count(item.size)}, SHA-256 {optional_digest(item.sha256)}, "
            f"источник {source}, версия {version}, ссылок {count(item.reference_count)}, "
            f"наборов {count(item.set_count)}"
        )
    lines.append(
        f"Ссылок правил и DNS на наборы: {count(view.reference_count)}; сопоставлено {count(view.resolved_count)}; "
        f"не сопоставлено {count(view.unresolved_count)}; неподдержанных {count(len(view.unsupported_references))}"
    )
    return lines


def present_xray_process(view: XrayProcessView) -> Lines:
    """Показать наблюдение процесса Xray; ни одно состояние не подтверждает работу VPN."""
    if type(view) is not XrayProcessView:
        raise TypeError("Ожидается XrayProcessView.")
    return [
        "Процесс Xray",
        f"Состояние: {identifier(view.state)}; процессов: {count(view.process_count)}; "
        f"маркер готовности: {flag(view.ready_marker)}; согласовано: {flag(view.consistent)}",
    ]


def _network_check(active: object) -> str:
    return "выполнялась" if active is True else "не выполнялась" if active is False else HIDDEN


def _check_line(item: CheckView) -> str:
    line = f"{identifier(item.code)}: {check_status(item.status)}"
    if item.reason is not None:
        line += f", причина {identifier(item.reason)}"
    if item.network is True:
        line += " (сетевая проверка)"
    return line


def present_checks(view: ChecksView) -> Lines:
    """Показать проверки результата: признак активной сетевой проверки и статус каждой проверки.

    Статусы и причины приходят из сценария как есть: меню их не вычисляет.
    """
    if type(view) is not ChecksView:
        raise TypeError("Ожидается ChecksView.")
    lines = ["Проверки", f"Активная сетевая проверка: {_network_check(view.active_network_check)}"]
    lines.extend(_INDENT + _check_line(item) for item in view.items)
    return lines


def present_installation(view: InstallationView) -> Lines:
    """Показать сводку прочитанной установки из четырёх областей и проверки по ним."""
    if type(view) is not InstallationView:
        raise TypeError("Ожидается InstallationView.")
    return [
        "Сводка установки по прочитанным источникам",
        *_indent(present_keenetic_state(view.keenetic)),
        *_indent(present_proxy_summary(view.proxy)),
        *_indent(present_geodata(view.geodata)),
        *_indent(present_xray_process(view.xray_process)),
        *_indent(present_checks(view.checks)),
        SNAPSHOT_NOTE,
    ]


def _area_text(item: SummaryAreaView) -> str:
    """Состояние области, если оно известно, и подпись статуса, если он не «успешно»."""
    status = item.check.status
    if item.state is None:
        return check_status(status)
    state = safe_text(STATE_LABELS[item.state]) if type(item.state) is AreaState else HIDDEN
    return state if status is CheckStatus.PASSED else f"{state}, {check_status(status)}"


def _area_line(item: SummaryAreaView) -> str:
    area = safe_text(AREA_LABELS[item.area]) if type(item.area) is SummaryArea else HIDDEN
    return f"{area}: {_area_text(item)}"


def _fallback_facts(facts: FallbackView) -> str:
    return (
        f"kill-switch: {_flag_view(facts.killswitch)}; балансировщиков: {optional_count(facts.balancer_count)}; "
        f"цель fallback: прямой выход {optional_count(facts.direct_count)}, "
        f"блокировка {optional_count(facts.blocked_count)}, VPN {optional_count(facts.vpn_count)}, "
        f"не определена {optional_count(facts.unresolved_count)}, не задана {optional_count(facts.unset_count)}"
    )


def present_status_header(view: StatusSummaryView) -> Lines:
    """Строки шапки главного меню: по строке на область сводки.

    Подпись состояния показывается, если оно известно, подпись статуса — если он
    не «успешно». Состояния, статусы и подписи приходят из сценария и каталогов
    application: меню их не вычисляет, а область без известного состояния
    никогда не выглядит исправной.
    """
    if type(view) is not StatusSummaryView:
        raise TypeError("Ожидается StatusSummaryView.")
    title = f"Состояние по источникам, активная сетевая проверка {_network_check(view.active_network_check)}:"
    return [title, *_indent(_area_line(item) for item in view.areas)]


def present_status_summary(view: StatusSummaryView) -> Lines:
    """Показать сводку по областям: строку шапки, проверку и отказ источника каждой области и её факты.

    Под областью DNS — факты порта 53 и подсказка о его исключении, под режимом
    резерва — kill-switch и цели fallback по видам. Отказ источника показывается
    так же, как отказ сценария, со следующим шагом из каталога application.
    """
    if type(view) is not StatusSummaryView:
        raise TypeError("Ожидается StatusSummaryView.")
    lines = ["Сводка состояния по областям", f"Активная сетевая проверка: {_network_check(view.active_network_check)}"]
    for item in view.areas:
        details = [f"Проверка {_check_line(item.check)}"]
        if item.source_error is not None:
            details += present_error(item.source_error)
        if item.area is SummaryArea.DNS:
            if view.port_53 is not None:
                details += [*_port53_facts(view.port_53), PORT_53_NOTE]
            details.append(f"Подсказка: {safe_text(PORT_53_HINT)}")
        if item.area is SummaryArea.FALLBACK and view.fallback is not None:
            details.append(_fallback_facts(view.fallback))
        lines += [_area_line(item), *_indent(details)]
    lines.append(SNAPSHOT_NOTE)
    return lines


def _source_lines(item: SourceReadView) -> Lines:
    """Строка источника с подписью итога чтения и, при отказе, строки отказа со следующим шагом."""
    source = _exact_label(SOURCE_LABELS, QuickCheckSource, item.source)
    lines = [f"{source}: {_exact_label(SOURCE_STATE_LABELS, SourceState, item.state)}"]
    if item.error is not None:
        lines += _indent(present_error(item.error))
    return lines


def present_quick_check(view: QuickCheckView) -> Lines:
    """Показать быструю проверку: итог со счётчиками, источники, проверки и оговорки.

    Итог, подписи источников и статусы приходят из сценария и каталогов
    application: меню их не вычисляет, строка вместо перечисления скрывается.
    Отказ источника показывается один раз, в блоке источников, со следующим
    шагом из каталога; зависящие проверки несут только его код.
    """
    if type(view) is not QuickCheckView:
        raise TypeError("Ожидается QuickCheckView.")
    counts = view.counts
    totals = ", ".join(
        f"{safe_text(CHECK_STATUS_LABELS[status])} {count(counts.get(status.value))}" for status in CheckStatus
    )
    lines = [
        "Быстрая проверка без изменений",
        f"Активная сетевая проверка: {_network_check(view.active_network_check)}",
        f"Итог: {_exact_label(QUICK_CHECK_OUTCOME_LABELS, QuickCheckOutcome, view.outcome)}; {totals}",
        "Источники:",
    ]
    for item in view.sources:
        lines += _indent(_source_lines(item))
    lines.append("Проверки:")
    lines.extend(_INDENT + _check_line(item) for item in view.checks.items)
    lines += [PORT_53_NOTE, DNS_PRITUNL_NOTE, SNAPSHOT_NOTE]
    return lines


ROUTING_LIST_TITLE = "Группы правил"
ROUTING_ITEM_NAME = "Группа правил"
OUTBOUND_TAGS_PER_LINE = 10
"""Сколько тегов outbound в строке карточки: тег после фильтра не длиннее 64 символов, строка остаётся в пределе."""


def _value_reasons(group: RuleGroupView) -> str:
    # Пути значений не выводятся: они ведут к условиям, а для диагностики достаточно кодов.
    counts: dict[str, int] = {}
    for item in group.value_reasons:
        code = identifier(item.reason)
        counts[code] = counts.get(code, 0) + 1
    return ", ".join(f"{code} ×{number}" for code, number in counts.items())


def _condition_types(group: RuleGroupView) -> str:
    return ", ".join(f"{identifier(item.name)} {count(item.count)}" for item in group.condition_types) or "нет"


def _group_label(group: RuleGroupView) -> str:
    target = group.target
    line = (
        f"{identifier(group.kind)}: условий {count(group.condition_count)} ({_condition_types(group)}), "
        f"значений {count(group.value_count)}, действие "
        f"{'нет' if group.action is None else identifier(group.action)}, назначение "
        f"{identifier(target.kind)} {known_value(target.tag_known, target.tag, identifier, 'без тега')}, "
        f"только просмотр {flag(group.read_only)}"
    )
    if group.reasons:
        line += f", причины: {identifiers(group.reasons)}"
    if target.reasons:
        line += f", причины назначения: {identifiers(target.reasons)}"
    if group.value_reasons:
        line += f", причины значений: {_value_reasons(group)}"
    if group.unknown_field_count:
        line += f", неизвестных полей {count(group.unknown_field_count)}"
    return line


def _rule_tag(has_rule_tag: object) -> str:
    if has_rule_tag is True:
        return "задан, значение не показывается"
    return "не задан" if has_rule_tag is False else HIDDEN


def _outbound_lines(tags: tuple[object, ...]) -> list[str]:
    # Число outbound задаёт конфигурация, поэтому теги идут строками по OUTBOUND_TAGS_PER_LINE.
    lines = [f"Outbound назначения: {count(len(tags))}"]
    for start in range(0, len(tags), OUTBOUND_TAGS_PER_LINE):
        lines.append(_INDENT + identifiers(tags[start:start + OUTBOUND_TAGS_PER_LINE]))
    return lines


def _group_card(group: RuleGroupView) -> tuple[str, ...]:
    target = group.target
    return (
        f"Часть: {file_name(group.part)}; индекс правила Xray: {count(group.index)} (счёт с нуля)",
        f"Вид: {identifier(group.kind)}; только просмотр: {flag(group.read_only)}; "
        f"причины: {identifiers(group.reasons)}",
        f"Условий: {count(group.condition_count)} ({_condition_types(group)}); значений: {count(group.value_count)}; "
        "сами значения не показываются",
        f"Причины значений: {_value_reasons(group) or 'нет'}",
        f"Поля правила: {identifiers(group.fields)}; неподдержанные: {identifiers(group.unsupported_fields)}; "
        f"неизвестных: {count(group.unknown_field_count)}",
        f"Тег правила: {_rule_tag(group.has_rule_tag)}",
        f"Действие: {'нет' if group.action is None else identifier(group.action)}",
        f"Назначение: {identifier(target.kind)} {known_value(target.tag_known, target.tag, identifier, 'без тега')}; "
        f"запасной: {known_value(target.fallback_known, target.fallback_tag, identifier, 'не задан')}; "
        f"стратегия: {known_value(target.strategy_known, target.strategy, identifier, 'не задана')}; "
        f"действие назначения: {'нет' if target.action is None else identifier(target.action)}",
        *_outbound_lines(target.outbound_tags),
        f"Причины назначения: {identifiers(target.reasons)}",
    )


def present_routing_scheme(view: RoutingSchemeView) -> MenuList:
    """Показать импортированные группы правил списком без доменов, адресов и кодов наборов.

    Номер группы — её позиция в схеме, начиная с 1: он не меняется при поиске.
    Строка списка и карточка собираются из тех же отфильтрованных значений.
    """
    if type(view) is not RoutingSchemeView:
        raise TypeError("Ожидается RoutingSchemeView.")
    header = [
        "Правила маршрутизации по конфигурации Xray",
        f"Часть с маршрутизацией: {optional_file_name(view.routing_part)}; частей с разделом routing: "
        f"{count(len(view.routing_parts))}",
        f"Групп правил: {count(view.group_count)}; правил модели: {count(view.rule_count)}; "
        f"финальное действие: {'не определено' if view.final_action is None else identifier(view.final_action)}",
        f"Только для просмотра: {flag(view.read_only)}; причины: {identifiers(view.reasons)}",
    ]
    policy = view.policy
    if policy is None:
        header.append("Политика маршрутизации не собрана: схема доступна только для просмотра.")
    else:
        header.append(
            f"Политика: правил {count(policy.rule_count)}, включено {count(policy.active_rule_count)}, "
            f"служебных {count(policy.protected_rule_count)}, финальное действие {identifier(policy.final_action)}, "
            f"только просмотр {flag(policy.read_only)}"
        )
    groups = view.groups[:MAX_ITEM_NUMBER]
    if len(view.groups) > MAX_ITEM_NUMBER:
        header.append(f"Групп больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.")
    entries = tuple(
        ListEntry(number, _group_label(group), _group_card(group)) for number, group in enumerate(groups, start=1)
    )
    return MenuList(ROUTING_LIST_TITLE, ROUTING_ITEM_NAME, tuple(header), entries)


CONNECTIONS_LIST_TITLE = "Подключения"
CONNECTIONS_ITEM_NAME = "Подключение"
SELECTORS_PER_LINE = 10
"""Сколько селекторов балансировщика в строке карточки; селектор после фильтра не длиннее 64 символов."""
CONNECTIONS_NOTE = (
    "Адреса серверов, порты, идентификаторы, пароли, SNI, пути и ссылки не читаются и не показываются; "
    "разбор ссылок не выполняется."
)
CONNECTIONS_HEALTH_NOTE = "Список не подтверждает доступность подключений: это снимок конфигурации на момент чтения."


def _position(value: object) -> str:
    """Позиция элемента Xray: имя части после фильтра и индекс; иной тип — пометка."""
    if type(value) is not XrayPositionView:
        return HIDDEN
    return f"часть {file_name(value.part)}, индекс {count(value.index)}"


def _selector(value: object) -> str:
    return "пустой" if value == "" else identifier(value)


def _connection_label(item: object) -> str:
    if type(item) is OutboundConnectionView:
        return (
            f"outbound: тег {known_value(item.tag_known, item.tag, identifier, 'без тега')}, "
            f"протокол {known_value(item.protocol_known, item.protocol, identifier, 'не задан')}, {_position(item.position)}"
        )
    if type(item) is BalancerConnectionView:
        return (
            f"балансировщик: тег {known_value(item.tag_known, item.tag, identifier, 'без тега')}, "
            f"селекторов {count(len(item.selector))}, совпадений {count(item.selector_match_count)}, "
            f"fallback {known_value(item.fallback_known, item.fallback_tag, identifier, 'не задан')}, "
            f"стратегия {known_value(item.strategy_known, item.strategy, identifier, 'не задана')}, {_position(item.position)}"
        )
    return HIDDEN


def _fallback_position(item: BalancerConnectionView) -> str:
    if item.fallback_known is not True:
        return "не задан"
    if item.fallback_resolved is not True:
        return "не найден"
    return "не определена однозначно" if item.fallback_position is None else _position(item.fallback_position)


def _connection_card(item: object) -> tuple[str, ...]:
    if type(item) is OutboundConnectionView:
        return (
            "Вид: outbound",
            f"Позиция: {_position(item.position)}",
            f"Тег: {known_value(item.tag_known, item.tag, identifier, 'без тега')}",
            f"Протокол: {known_value(item.protocol_known, item.protocol, identifier, 'не задан')}",
            CONNECTIONS_NOTE,
        )
    if type(item) is BalancerConnectionView:
        selectors = [f"Селекторов: {count(len(item.selector))}; совпадений outbound: {count(item.selector_match_count)}"]
        for start in range(0, len(item.selector), SELECTORS_PER_LINE):
            selectors.append(_INDENT + ", ".join(_selector(value) for value in item.selector[start:start + SELECTORS_PER_LINE]))
        return (
            "Вид: балансировщик",
            f"Позиция: {_position(item.position)}",
            f"Тег: {known_value(item.tag_known, item.tag, identifier, 'без тега')}",
            *selectors,
            f"Fallback: {known_value(item.fallback_known, item.fallback_tag, identifier, 'не задан')}; "
            f"позиция цели: {_fallback_position(item)}",
            f"Стратегия: {known_value(item.strategy_known, item.strategy, identifier, 'не задана')}",
            CONNECTIONS_NOTE,
        )
    return (HIDDEN,)


def present_connections(view: ConnectionsView) -> MenuList:
    """Показать outbound и балансировщики списком: номер — позиция в списке сценария, начиная с 1.

    Строка списка и карточка собраны из одних отфильтрованных значений;
    адреса, порты, пароли и ссылки в представление не входят.
    """
    if type(view) is not ConnectionsView:
        raise TypeError("Ожидается ConnectionsView.")
    header = [
        "Подключения по конфигурации Xray",
        f"Частей: {count(view.part_count)}; outbound: {count(view.outbound_count)}; "
        f"балансировщиков: {count(view.balancer_count)}",
        f"Повторов тегов outbound: {count(view.duplicate_outbound_tag_count)}; "
        f"повторов тегов балансировщиков: {count(view.duplicate_balancer_tag_count)}; "
        f"скрытых тегов: {count(view.hidden_tag_count)}",
        CONNECTIONS_NOTE,
        CONNECTIONS_HEALTH_NOTE,
    ]
    items = view.connections[:MAX_ITEM_NUMBER]
    if len(view.connections) > MAX_ITEM_NUMBER:
        header.append(f"Подключений больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.")
    entries = tuple(
        ListEntry(number, _connection_label(item), _connection_card(item)) for number, item in enumerate(items, start=1)
    )
    return MenuList(CONNECTIONS_LIST_TITLE, CONNECTIONS_ITEM_NAME, tuple(header), entries)


NAMES_PER_LABEL = 10
"""Сколько названий правил входит в строку группы: название не длиннее 64 символов, строка остаётся в пределе."""
METADATA_NOTES: dict[MetadataState, str] = {
    MetadataState.NOT_CONNECTED: "Хранилище метаданных не подключено: названия и идентификаторы правил не показываются.",
    MetadataState.ABSENT: "Метаданные менеджера не записаны: идентификаторы правилам ещё не присвоены.",
    MetadataState.PRESENT: "Метаданные менеджера прочитаны.",
    MetadataState.FAILED: "Названия и идентификаторы недоступны: хранилище метаданных отказало, список показан без них.",
}
TARGET_POSITION_LABELS: dict[TargetPositionState, str] = {
    TargetPositionState.AMBIGUOUS: "не определена однозначно: тег повторяется",
    TargetPositionState.UNRESOLVED: "не найдена: тега нет ни в одной части",
    TargetPositionState.ABSENT: "без тега",
    TargetPositionState.UNSUPPORTED: "не определена: заданы оба тега",
    TargetPositionState.UNAVAILABLE: "сводка не описывает это правило",
}


def _target_position(group: RuleGroupIdentityView) -> str:
    state = group.target_position_state
    if type(state) is not TargetPositionState:
        return HIDDEN
    if state is TargetPositionState.RESOLVED:
        return _position(group.target_position)
    return safe_text(TARGET_POSITION_LABELS[state])


def _rule_name_text(item: RuleListEntryView) -> str:
    return f"«{rule_name(item.name)}»" if item.has_name is True else "не задано"


def _identity_label(group: RuleGroupIdentityView) -> str:
    line = f", правил {count(group.rule_count)}"
    rules = group.rules
    if rules is None:
        return line
    with_id = sum(item.has_id is True for item in rules)
    names = [item for item in rules if item.has_name is True]
    line += f", с ID {count(with_id)}, с названием {count(len(names))}"
    if names:
        shown = ", ".join(_rule_name_text(item) for item in names[:NAMES_PER_LABEL])
        line += f", названия: {shown}"
        if len(names) > NAMES_PER_LABEL:
            line += f" (ещё {count(len(names) - NAMES_PER_LABEL)})"
    return line


def _rule_line(item: RuleListEntryView) -> str:
    return (
        f"{count(item.index)}: {identifier(item.condition_type)}, действие {identifier(item.action)}, "
        f"только просмотр {flag(item.read_only)}, ID {rule_id(item.rule_id) if item.has_id is True else 'не присвоен'}, "
        f"название {_rule_name_text(item)}, привязка {identifier(item.binding)}"
    )


def _identity_card(group: RuleGroupIdentityView) -> list[str]:
    lines = [f"Назначение по позиции: {_target_position(group)}"]
    if group.rules is None:
        lines.append(f"Правил модели: {count(group.rule_count)}; названия и идентификаторы недоступны")
        return lines
    lines.append(f"Правил модели: {count(group.rule_count)} (позиция в схеме, счёт с нуля)")
    lines.extend(_INDENT + _rule_line(item) for item in group.rules)
    return lines


def _metadata_state_lines(state: object, error: object) -> Lines:
    """Строка состояния метаданных и, при отказе хранилища, строки отказа с его шагом."""
    if type(state) is not MetadataState:
        return [HIDDEN]
    lines = [safe_text(METADATA_NOTES[state])]
    if error is not None:
        lines += _indent(present_error(error))
    return lines


def _metadata_lines(view: RuleListView) -> Lines:
    lines = _metadata_state_lines(view.metadata_state, view.metadata_error)
    identity = view.identity
    if identity is not None:
        records = "раздел записей не записан" if identity.record_count is None else f"записей правил {count(identity.record_count)}"
        lines.append(
            f"Идентичность: {records}; привязано {count(identity.bound_rule_count)}, "
            f"с названием {count(identity.named_rule_count)}, без привязки {count(identity.unbound_rule_count)}; "
            f"записей без правила {count(identity.unbound_record_count)}"
        )
    return lines


def present_rule_list(view: RuleListView) -> MenuList:
    """Показать группы правил в фактическом порядке с названиями и идентификаторами, когда они доступны.

    Список, строки и карточки групп те же, что у представления схемы; к строке
    добавляются число правил, счётчики идентичности и до `NAMES_PER_LABEL`
    названий, к карточке — позиция назначения и по строке на правило модели.
    Названия проходят фильтр `rule_name`, идентификаторы — `rule_id`.
    """
    if type(view) is not RuleListView:
        raise TypeError("Ожидается RuleListView.")
    base = present_routing_scheme(view.scheme)
    header = (*base.header, *_metadata_lines(view))
    entries = tuple(
        ListEntry(entry.number, entry.label + _identity_label(group), (*entry.card, *_identity_card(group)))
        for entry, group in zip(base.entries, view.groups[:MAX_ITEM_NUMBER], strict=True)
    )
    return MenuList(base.title, base.item_name, header, entries)


ROUTE_PROMPT = (
    "Домен, отдельный IP-адрес или домен с IP-адресами через пробел: не больше одного домена и 16 адресов, "
    "без CIDR, портов и зон.",
    "Введённое значение в вывод не повторяется; DNS и другие сетевые запросы не выполняются.",
)
"""Подсказка запроса значения для объяснения маршрута."""
ROUTE_NOTE = (
    "Это предварительный статический расчёт по снимку импортированных правил: реальный путь трафика, DNS, "
    "sniffing и работа VPN не проверялись, введённые значения не выводятся."
)
UNKNOWN_ROUTE_NOTE = "Маршрут не определён: это не DIRECT, не VPN и не BLOCK."
POLICY_ABSENT_NOTE = (
    "Правила не проверялись: политика действующей схемы не собрана, схема доступна только для просмотра; "
    "причины — в строке схемы."
)


def _route_position(index: object, group_index: object, offset: object) -> str:
    text = f"правило {count(index)}"
    if group_index is None:
        return text
    inside = "" if offset is None else f", правило {count(offset)} в группе"
    return f"{text} (группа {count(group_index)}{inside})"


def _route_identity(has_id: object, rule_id_value: object, has_name: object, name: object) -> str:
    shown_id = rule_id(rule_id_value) if has_id is True else "не присвоен"
    shown_name = f"«{rule_name(name)}»" if has_name is True else "не задано"
    return f"ID {shown_id}; название {shown_name}"


def _route_step_line(number: int, step: RouteStepView) -> str:
    result = STEP_SKIPPED_LABEL if step.result is None else _catalog(STEP_RESULT_LABELS, step.result)
    condition = "финальное правило" if step.condition_type is None else identifier(step.condition_type)
    line = (
        f"Шаг {count(number)}: {_route_position(step.index, step.group_index, step.offset)} — {condition}, "
        f"действие {identifier(step.action)}, {safe_text(result)}; {safe_text(step.reason)}"
    )
    if step.condition_type is not None:
        line += f"; {_route_identity(step.has_id, step.rule_id, step.has_name, step.name)}"
    if step.database_kind is not None:
        version = "известна" if step.database_version_known is True else "неизвестна"
        line += f"; база {identifier(step.database_kind)}, версия {version}"
    return line


def _route_target_line(selection: RouteSelectionView) -> str:
    target = selection.target
    if target is None:
        return f"Назначение: {MISSING}"
    state = selection.target_position_state
    if type(state) is not TargetPositionState:
        position = HIDDEN
    elif state is TargetPositionState.RESOLVED:
        position = f"{file_name(selection.target_position.part)}, индекс {count(selection.target_position.index)}"
    else:
        position = safe_text(TARGET_POSITION_LABELS[state])
    return (
        f"Назначение: {identifier(target.kind)} {known_value(target.tag_known, target.tag, identifier, 'без тега')}; "
        f"позиция: {position}"
    )


def _route_outcome_lines(view: RouteExplanationView) -> Lines:
    outcome = view.outcome
    label = _catalog(OUTCOME_LABELS, outcome.value) if type(outcome) is RouteOutcome else HIDDEN
    lines = [f"Итог: {label}"]
    selection = view.selection
    if outcome is RouteOutcome.POLICY_ABSENT:
        lines.append(_INDENT + POLICY_ABSENT_NOTE)
    elif outcome is RouteOutcome.UNKNOWN or selection is None:
        lines.append(_INDENT + f"Правило не выбрано: условие на шаге {count(len(view.steps))} неизвестно.")
        lines.append(_INDENT + UNKNOWN_ROUTE_NOTE)
    else:
        position = _route_position(selection.index, selection.group_index, selection.offset)
        if outcome is RouteOutcome.FINAL:
            lines.append(
                _INDENT + f"Ни одно включённое правило не совпало: действует финальное {position} — "
                f"действие {identifier(selection.action)}"
            )
        else:
            lines.append(
                _INDENT + f"Выбрано {position}: действие {identifier(selection.action)}; "
                + _route_identity(selection.has_id, selection.rule_id, selection.has_name, selection.name)
            )
        lines.append(_INDENT + _route_target_line(selection))
    return lines


def present_route_explanation(view: RouteExplanationView) -> Lines:
    """Показать предварительный расчёт маршрута: предположения, схему, шаги и один из четырёх итогов.

    Введённые домен и адреса, значения условий и коды наборов в представление
    не входят, поэтому вывести их нельзя; названия правил проходят фильтр
    `rule_name`, идентификаторы — `rule_id`, теги и части — свои фильтры.
    """
    if type(view) is not RouteExplanationView:
        raise TypeError("Ожидается RouteExplanationView.")
    lines = ["Предварительный расчёт маршрута", ROUTE_NOTE, "Предположения расчёта:"]
    lines += _indent(safe_text(item) for item in view.assumptions)
    lines.append(f"Адресов в расчёте: {optional_count(view.ip_count)}")
    scheme = view.scheme
    if scheme is not None:
        policy = "собрана" if scheme.policy_present is True else "не собрана"
        lines.append(
            f"Схема: часть {optional_file_name(scheme.routing_part)}; только просмотр {flag(scheme.read_only)}; "
            f"групп {count(scheme.group_count)}; правил модели {count(scheme.rule_count)}; политика {policy}; "
            f"причины: {identifiers(scheme.reasons)}"
        )
        lines += _metadata_state_lines(view.metadata_state, view.metadata_error)
    lines.append(f"Шагов проверки: {count(len(view.steps))}")
    lines += _indent(_route_step_line(number, step) for number, step in enumerate(view.steps, start=1))
    lines += _route_outcome_lines(view)
    return lines


DEVICES_LIST_TITLE = "Устройства"
DEVICES_ITEM_NAME = "Устройство"
POLICY_IDS_PER_LINE = 10
"""Сколько ID политик в одной вводной строке: ID после фильтра не длиннее 64 символов, строка остаётся в пределе."""
DEVICES_NOTE = (
    "MAC, имена хостов, адреса и описания политик не читаются представлением и не показываются; "
    "имя — регистрация устройства в Keenetic после проверки формата."
)
SEGMENT_MATCH_NOTE = (
    "Сегмент сопоставлен по техническому ID наблюдаемого интерфейса: это не состав сегмента "
    "и не действующая политика устройства."
)


def _catalog(labels: Mapping[str, str], value: object) -> str:
    """Подпись каталога application только для точного строкового значения из него; иначе пометка."""
    if type(value) is str and value in labels:
        return safe_text(labels[value])
    return HIDDEN


def _device_name_text(item: DeviceEntryView) -> str:
    absent = "без регистрации" if item.registration_count == 0 else f"регистраций {count(item.registration_count)}"
    return known_value(item.name_known, item.name, device_name, absent)


def _device_assignment(item: DeviceEntryView) -> str:
    text = _catalog(ASSIGNMENT_LABELS, item.assignment)
    if item.policy_id is not None:
        text += f" {identifier(item.policy_id)}"
    if item.policy_present is False:
        text += " (нет в списке политик)"
    return text


def _device_interface(item: DeviceEntryView) -> str:
    return known_value(item.observed_interface_known, item.observed_interface_id, interface_id, "не наблюдался")


def _device_label(item: DeviceEntryView) -> str:
    return (
        f"{_device_name_text(item)}: {_device_assignment(item)}, {_catalog(PRESENCE_LABELS, item.presence)}, "
        f"запрет доступа {flag(item.access_denied)}, интерфейс {_device_interface(item)}"
    )


def _policy_lines(view: DeviceListView) -> Lines:
    # Число политик задаёт роутер, поэтому идентификаторы идут строками по POLICY_IDS_PER_LINE.
    lines = [f"Политик: {count(view.policy_count)}"]
    if not view.policy_ids:
        lines.append(_INDENT + "нет")
    for start in range(0, len(view.policy_ids), POLICY_IDS_PER_LINE):
        lines.append(_INDENT + identifiers(view.policy_ids[start:start + POLICY_IDS_PER_LINE]))
    return lines


def _device_card(item: DeviceEntryView) -> tuple[str, ...]:
    registrations = [f"Регистраций: {count(item.registration_count)}"]
    registrations.extend(_INDENT + device_name(name) for name in item.registration_names)
    reason = "нет" if item.presence_reason is None else _catalog(PRESENCE_REASON_LABELS, item.presence_reason)
    segment = [f"Сегмент по интерфейсу: {_catalog(SEGMENT_MATCH_LABELS, item.segment_match)}"]
    if item.segment_match == SegmentMatch.MATCHED.value:
        segment.append(_INDENT + _segment_line(item.segment))
    return (
        f"Позиция записи: {count(item.position)} (счёт с нуля в ip/hotspot)",
        *registrations,
        f"Назначение: {identifier(item.assignment)} — {_device_assignment(item)}; "
        f"в списке политик: {optional_flag(item.policy_present)}",
        f"Online: {_catalog(PRESENCE_LABELS, item.presence)}; причина: {reason}",
        f"Запрет доступа: {flag(item.access_denied)}; только просмотр: {flag(item.read_only)}; "
        f"MAC повторяется: {flag(item.mac_duplicate)}",
        f"Наблюдаемый интерфейс: {_device_interface(item)}",
        *segment,
        SEGMENT_MATCH_NOTE,
        DEVICES_NOTE,
    )


def present_device_list(view: DeviceListView) -> MenuList:
    """Показать записи устройств списком: номер — позиция записи в `ip/hotspot.host`, начиная с 1.

    Строка списка и карточка собраны из одних отфильтрованных значений: имя
    регистрации после фильтра, подписи каталогов application для назначения,
    online и сопоставления сегмента, технические ID после проверки формата.
    MAC, имена хостов и адреса в представление не входят.
    """
    if type(view) is not DeviceListView:
        raise TypeError("Ожидается DeviceListView.")
    counts = view.counts
    header = [
        "Устройства Keenetic по прочитанному состоянию",
        *_policy_lines(view),
        f"Назначений сегментов: {count(len(view.segments))}; без политики в списке: "
        f"{count(view.segment_missing_policy_count)}",
        *(_INDENT + _segment_line(segment) for segment in view.segments),
        f"Записей устройств: всего {count(counts.record_count)}; online {count(counts.online_count)}, "
        f"offline {count(counts.offline_count)}, online неизвестно {count(counts.unknown_count)}; "
        f"разных MAC {count(counts.distinct_mac_count)}, записей с повтором MAC {count(counts.duplicate_mac_count)}",
        f"Назначения: явных {count(counts.explicit_count)}, наследуют {count(counts.inherit_count)}, "
        f"без назначения {count(counts.unassigned_count)}, не распознано {count(counts.unknown_assignment_count)}; "
        f"политики нет в списке {count(counts.missing_policy_count)}; запрет доступа {count(counts.access_denied_count)}; "
        f"только просмотр {count(counts.read_only_count)}",
        f"Регистраций без записи: {count(counts.registrations_without_device_count)}; "
        f"наблюдений без записи: {count(counts.runtime_without_device_count)}; "
        f"неоднозначных наблюдений: {count(counts.ambiguous_observation_count)}; "
        f"скрытых имён: {count(counts.hidden_name_count)}",
        DEVICES_NOTE,
        SNAPSHOT_NOTE,
    ]
    items = view.devices[:MAX_ITEM_NUMBER]
    if len(view.devices) > MAX_ITEM_NUMBER:
        header.append(f"Записей больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.")
    entries = tuple(
        ListEntry(number, _device_label(item), _device_card(item)) for number, item in enumerate(items, start=1)
    )
    return MenuList(DEVICES_LIST_TITLE, DEVICES_ITEM_NAME, tuple(header), entries)


def present_manager_metadata(view: ManagerMetadataStatusView) -> Lines:
    """Показать метаданные менеджера без путей, идентификаторов хранилищ и ревизии."""
    if type(view) is not ManagerMetadataStatusView:
        raise TypeError("Ожидается ManagerMetadataStatusView.")
    lines = ["Метаданные менеджера"]
    if view.present is not True or view.metadata is None:
        lines.append("Метаданных нет: размещение хранилищ ещё не записано.")
        return lines
    metadata = view.metadata
    lines.append(
        f"Версия схемы: {count(metadata.schema_version)}; неизвестных полей: {count(metadata.unknown_field_count)}"
    )
    storage = metadata.storage
    if storage is None:
        lines.append("Размещение хранилищ не записано.")
        return lines
    lines.append(
        f"Вариант хранения: {identifier(storage.variant_state)} {optional_identifier(storage.variant)}; "
        f"различных хранилищ: {count(storage.distinct_storage_count)}"
    )
    for role in storage.roles:
        lines.append(
            f"{_INDENT}Роль {identifier(role.role)}: состояние {identifier(role.state)}, "
            f"идентификатор {optional_identifier(role.storage_id_state)}, путь {optional_identifier(role.path_state)}, "
            f"проверено {optional_flag(role.verified)}"
        )
    limits = storage.history_limits
    lines.append(
        f"История: размер {identifier(limits.size_state)} {optional_count(limits.size_bytes)} байт; "
        f"срок {identifier(limits.retention_state)} {optional_count(limits.retention_seconds)} с"
    )
    return lines


def present_about() -> Lines:
    """Справка по навигации и версия контракта результатов."""
    return [
        "Справка по меню KeenVPN",
        "Выберите пункт, введя его номер и Enter. 0 возвращает на уровень выше, в корневом меню — завершает работу.",
        f"Пункты с пометкой {UNAVAILABLE_MARK} не выполняются: при выборе показывается причина, настройки не меняются.",
        "В списках номер открывает карточку элемента, другой текст ищет по показанным строкам, 0 возвращает назад.",
        "Меню только показывает данные подключённых источников чтения; конфигурация роутера, Xray и XKeen не изменяется.",
        f"Версия контракта результатов прикладных сценариев: {CONTRACT_VERSION}",
    ]
