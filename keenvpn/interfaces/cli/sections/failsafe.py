"""Автозапуск, DNS и поведение при сбое."""

from keenvpn.application.proxy_config import (
    InspectProxyConfig, InspectProxyConfigHandler, Port53View, ProxyConfigView, XKeenFlagView, XKeenListView,
)
from keenvpn.interfaces.cli.bindings import SectionActions
from keenvpn.interfaces.cli.presentation import (
    count, flag, identifier, Lines, optional_count, optional_identifier, present_result, ReportLayout,
)


ACTION_CAPTIONS = {
    "failsafe.port53_check": "Сверка списков портов и флагов XKeen. Фактический путь DNS проверяется отдельно.",
}


PORT_53_NOTE = (
    "Фактический перехват DNS не проверялся: это факты файлов, а не состояние трафика. "
    "Отсутствие исключения само по себе не ошибка и не доказательство перехвата."
)

DNS_PRITUNL_NOTE = (
    "DNS и рабочие сайты через Pritunl проверяются раздельно: эта проверка не подтверждает ни того, ни другого."
)


def flag_text(value: XKeenFlagView) -> str:
    return f"{identifier(value.status)} ({optional_identifier(value.value)})"


def port_list_text(label: str, value: XKeenListView) -> str:
    return (
        f"{label}: строк {count(value.line_count)}, записей {count(value.entry_count)}, "
        f"портов {optional_count(value.port_count)}, диапазонов {optional_count(value.range_count)}, "
        f"адресов {optional_count(value.address_count)}, некорректных {count(value.invalid_count)}"
    )


def port53_facts(facts: Port53View) -> Lines:
    return [
        f"Запись {count(facts.port)} в списке исключённых портов: {flag(facts.port_exclude_entry)}; "
        f"диапазон с этим портом: {flag(facts.port_exclude_range)}",
        f"Запись {count(facts.port)} в списке перехватываемых портов: {flag(facts.port_proxying_entry)}; "
        f"диапазон с этим портом: {flag(facts.port_proxying_range)}",
        f"proxy_dns: {flag_text(facts.proxy_dns)}; proxy_router: {flag_text(facts.proxy_router)}",
    ]


def present_port53(view: ProxyConfigView) -> Lines:
    """Показать раздельные факты о порту 53 из файлов XKeen; фактический перехват не проверяется."""
    if type(view) is not ProxyConfigView:
        raise TypeError("Ожидается ProxyConfigView.")
    return [
        "Порт 53 по файлам конфигурации XKeen",
        *port53_facts(view.xkeen.port_53),
        port_list_text("Список исключённых портов", view.xkeen.port_exclude),
        port_list_text("Список перехватываемых портов", view.xkeen.port_proxying),
        PORT_53_NOTE,
    ]


def port53_layout(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    files = []
    for line in body:
        if line.startswith(("Список исключённых портов: ", "Список перехватываемых портов: ")):
            files.append(line)
        elif line.startswith("proxy_dns: ") and "; proxy_router: " in line:
            for flag in line.split("; ", 1):
                name, _, value = flag.partition(": ")
                value = {"present (on)": "включён", "present (off)": "выключен"}.get(value, value)
                summary.append(f"{name}: {value}")
            files.append(line)
        else:
            summary.append(line)
    return tuple(summary), (("Сведения из файлов XKeen", tuple(files)),) if files else ()


def bind_actions(bindings: SectionActions, proxy: InspectProxyConfigHandler) -> None:
    """Подключить сверку режима порта 53 по конфигурации Xray и XKeen."""
    bindings["failsafe.port53_check"] = lambda: present_result(proxy.execute(InspectProxyConfig()), present_port53)
