"""Сводка и раскрываемые подробности полноэкранных отчётов по уже отфильтрованным строкам CLI."""

from collections.abc import Iterator, Sequence

from keenvpn.application.status_summary import AREA_LABELS


ReportLayout = tuple[tuple[str, ...], tuple[tuple[str, tuple[str, ...]], ...]]


def _paragraphs(lines: tuple[str, ...]) -> Iterator[tuple[str, tuple[str, ...]]]:
    """Соединить подпись представления с непосредственно следующими за ней строками с отступом."""
    start = 0
    while start < len(lines):
        end = start + 1
        while end < len(lines) and lines[end].startswith("  "):
            end += 1
        yield lines[start], lines[start + 1:end]
        start = end


def _status(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    checks = []
    for line, children in _paragraphs(body):
        summary.append(line)
        if children and line.partition(": ")[0] in AREA_LABELS.values():
            checks.extend((line, *children))
        else:
            summary.extend(children)
    return tuple(summary), (("Подробности проверок", tuple(checks)),) if checks else ()


def _quick(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    sections = []
    titles = {"Источники:": "Источники снимка", "Проверки:": "Все проверки"}
    for line, children in _paragraphs(body):
        if line in titles and children:
            sections.append((titles[line], children))
        elif line.startswith("Итог: ") and "; " in line:
            outcome, counts = line.rsplit("; ", 1)
            summary.extend((outcome, "По статусам: " + counts, *children))
        else:
            summary.extend((line, *children))
    return tuple(summary), tuple(sections)


def _route(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    sections = []
    outcome = []
    for line, children in _paragraphs(body):
        if line == "Предположения расчёта:" and children:
            sections.append(("Предположения расчёта", children))
        elif line.startswith("Шагов проверки: ") and children:
            summary.append(line)
            sections.append(("Шаги проверки", children))
        elif line.startswith("Итог: "):
            outcome.extend((line, *children))
        else:
            summary.extend((line, *children))
    return (*outcome, *summary), tuple(sections)


def _port53(body: tuple[str, ...]) -> ReportLayout:
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


def _storage(body: tuple[str, ...]) -> ReportLayout:
    roles = tuple(line for line in body if line.startswith("  Роль "))
    summary = tuple(line for line in body if not line.startswith("  Роль "))
    return summary, (("Роли хранилищ", roles),) if roles else ()


def _help(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    for line in body:
        if line == ("Выберите пункт, введя его номер и Enter. 0 возвращает на уровень выше, "
                    "в корневом меню — завершает работу."):
            summary.extend(("Выбор: ↑/↓ и Enter или номер и Enter.",
                            "Назад: Esc или 0 и Enter. В главном меню эти клавиши открывают выход.",
                            "Главное меню: Home."))
        elif line.startswith("Пункты с пометкой [недоступно]"):
            summary.append("Закрытые пункты: в скобках указана причина. Ввод номера показывает её.")
        elif line == ("В списках номер открывает карточку элемента, другой текст ищет по показанным строкам, "
                      "0 возвращает назад."):
            summary.extend(("Карточка: Enter на выбранной строке.", "Поиск: /, текст и Enter.",
                            "Подробности: Tab меняет вид списка, карточки или отчёта.",
                            "Источник: i в списке подключений, правил или устройств.",
                            "Прокрутка: ↑/↓ или PgUp/PgDn."))
        else:
            summary.append(line)
    return tuple(summary), ()


_REPORTS = {
    "status.summary": ("Сводка состояния по областям", _status),
    "status.quick_check": ("Быстрая проверка без изменений", _quick),
    "routing.explain": ("Предварительный расчёт маршрута", _route),
    "failsafe.port53_check": ("Порт 53 по файлам конфигурации XKeen", _port53),
    "settings.storage": ("Метаданные менеджера", _storage),
    "settings.about": ("Справка по меню KeenVPN", _help),
}


def report_layout(action_id: str, lines: Sequence[str]) -> ReportLayout:
    """Разложить знакомый отчёт по областям. Новые отчёты и отказы показать полностью."""
    original = tuple(lines)
    report = _REPORTS.get(action_id)
    if (not report or len(original) < 2 or original[0] != report[0]
            or any(line.lstrip().startswith("Отказ: ") for line in original)):
        return original, ()
    return report[1](original[1:])
