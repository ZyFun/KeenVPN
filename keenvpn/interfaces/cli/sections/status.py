"""Состояние роутера и быстрые проверки."""

from keenvpn.application.checks import CHECK_STATUS_LABELS, ChecksView
from keenvpn.application.contract import CheckStatus, OperationIdFactory
from keenvpn.application.installation import GeoDataView, InstallationView, XrayProcessView
from keenvpn.application.proxy_config import InspectProxyConfigHandler, ProxyConfigView
from keenvpn.application.quick_check import (
    OUTCOME_LABELS as QUICK_CHECK_OUTCOME_LABELS, QuickCheck, QuickCheckHandler, QuickCheckOutcome,
    QuickCheckSource, QuickCheckView, SOURCE_LABELS, SOURCE_STATE_LABELS, SourceReadView, SourceState,
)
from keenvpn.application.status_summary import (
    AREA_LABELS, AreaState, FallbackView, InspectStatusSummary, InspectStatusSummaryHandler, PORT_53_HINT,
    STATE_LABELS, StatusSummaryView, SummaryArea, SummaryAreaView,
)
from keenvpn.interfaces.cli.bindings import MenuSources, SectionActions
from keenvpn.interfaces.cli.presentation import (
    check_line, enum_label, INDENT, indented, report_paragraphs, check_status, count, file_name, flag,
    geo_source, geo_version, HIDDEN, identifier, identifiers, known_value, Lines, optional_count,
    optional_digest, present_error, present_result, ReportLayout, safe_text, SNAPSHOT_NOTE,
)
from keenvpn.interfaces.cli.sections.devices import present_keenetic_state
from keenvpn.interfaces.cli.sections.failsafe import (
    flag_text, port_list_text, port53_facts, DNS_PRITUNL_NOTE, PORT_53_NOTE,
)
from keenvpn.interfaces.cli.terminal import Header


ACTION_CAPTIONS = {
    "status.summary": "Состояние семи областей роутера. У непрочитанных источников показан статус проверки.",
    "status.quick_check": "Статическая сверка источников и проверок без активной сетевой пробы.",
}


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
        f"kill-switch: {flag_text(xkeen.settings.killswitch)}; присваиваний init: {count(xkeen.init.assignment_count)}; "
        f"повторов имён init: {count(len(xkeen.init.duplicate_names))}",
        port_list_text("Список исключённых портов", xkeen.port_exclude),
        port_list_text("Список перехватываемых портов", xkeen.port_proxying),
        port_list_text("Список исключённых адресов", xkeen.ip_exclude),
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
            f"{INDENT}{file_name(item.name)}: {'найден' if item.present is True else 'отсутствует'}, "
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


def present_checks(view: ChecksView) -> Lines:
    """Показать проверки результата: признак активной сетевой проверки и статус каждой проверки.

    Статусы и причины приходят из сценария как есть: меню их не вычисляет.
    """
    if type(view) is not ChecksView:
        raise TypeError("Ожидается ChecksView.")
    lines = ["Проверки", f"Активная сетевая проверка: {_network_check(view.active_network_check)}"]
    lines.extend(INDENT + check_line(item) for item in view.items)
    return lines


def present_installation(view: InstallationView) -> Lines:
    """Показать сводку прочитанной установки из четырёх областей и проверки по ним."""
    if type(view) is not InstallationView:
        raise TypeError("Ожидается InstallationView.")
    return [
        "Сводка установки по прочитанным источникам",
        *indented(present_keenetic_state(view.keenetic)),
        *indented(present_proxy_summary(view.proxy)),
        *indented(present_geodata(view.geodata)),
        *indented(present_xray_process(view.xray_process)),
        *indented(present_checks(view.checks)),
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
        f"kill-switch: {flag_text(facts.killswitch)}; балансировщиков: {optional_count(facts.balancer_count)}; "
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
    return [title, *indented(_area_line(item) for item in view.areas)]


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
        details = [f"Проверка {check_line(item.check)}"]
        if item.source_error is not None:
            details += present_error(item.source_error)
        if item.area is SummaryArea.DNS:
            if view.port_53 is not None:
                details += [*port53_facts(view.port_53), PORT_53_NOTE]
            details.append(f"Подсказка: {safe_text(PORT_53_HINT)}")
        if item.area is SummaryArea.FALLBACK and view.fallback is not None:
            details.append(_fallback_facts(view.fallback))
        lines += [_area_line(item), *indented(details)]
    lines.append(SNAPSHOT_NOTE)
    return lines


def _source_lines(item: SourceReadView) -> Lines:
    """Строка источника с подписью итога чтения и, при отказе, строки отказа со следующим шагом."""
    source = enum_label(SOURCE_LABELS, QuickCheckSource, item.source)
    lines = [f"{source}: {enum_label(SOURCE_STATE_LABELS, SourceState, item.state)}"]
    if item.error is not None:
        lines += indented(present_error(item.error))
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
        f"Итог: {enum_label(QUICK_CHECK_OUTCOME_LABELS, QuickCheckOutcome, view.outcome)}; {totals}",
        "Источники:",
    ]
    for item in view.sources:
        lines += indented(_source_lines(item))
    lines.append("Проверки:")
    lines.extend(INDENT + check_line(item) for item in view.checks.items)
    lines += [PORT_53_NOTE, DNS_PRITUNL_NOTE, SNAPSHOT_NOTE]
    return lines


def status_layout(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    checks = []
    for line, children in report_paragraphs(body):
        summary.append(line)
        if children and line.partition(": ")[0] in AREA_LABELS.values():
            checks.extend((line, *children))
        else:
            summary.extend(children)
    return tuple(summary), (("Подробности проверок", tuple(checks)),) if checks else ()


def quick_check_layout(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    sections = []
    titles = {"Источники:": "Источники снимка", "Проверки:": "Все проверки"}
    for line, children in report_paragraphs(body):
        if line in titles and children:
            sections.append((titles[line], children))
        elif line.startswith("Итог: ") and "; " in line:
            outcome, counts = line.rsplit("; ", 1)
            summary.extend((outcome, "По статусам: " + counts, *children))
        else:
            summary.extend((line, *children))
    return tuple(summary), tuple(sections)


def bind_actions(
    bindings: SectionActions, proxy: InspectProxyConfigHandler | None, sources: MenuSources,
    operation_ids: OperationIdFactory, storage_notice: list[str],
) -> Header:
    """Подключить сводку и быструю проверку, вернуть шапку для главного меню."""
    summary = InspectStatusSummaryHandler(proxy, sources.process, drafts=sources.draft_store, operation_ids=operation_ids)
    bindings["status.summary"] = lambda: [
        *present_result(summary.execute(InspectStatusSummary()), present_status_summary), *storage_notice,
    ]

    def header() -> list[str]:
        return [*present_result(summary.execute(InspectStatusSummary()), present_status_header), *storage_notice]

    quick_check = QuickCheckHandler(proxy, sources.process, sources.geodata, operation_ids=operation_ids)
    bindings["status.quick_check"] = lambda: present_result(quick_check.execute(QuickCheck()), present_quick_check)
    return header
