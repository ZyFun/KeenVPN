"""Сводка и раскрываемые подробности полноэкранных отчётов по уже отфильтрованным строкам CLI."""

from collections.abc import Sequence

from keenvpn.interfaces.cli.presentation import ReportLayout
from keenvpn.interfaces.cli.sections.failsafe import port53_layout
from keenvpn.interfaces.cli.sections.routing import route_layout
from keenvpn.interfaces.cli.sections.settings import help_layout, storage_layout
from keenvpn.interfaces.cli.sections.status import quick_check_layout, status_layout

_REPORTS = {
    "status.summary": ("Сводка состояния по областям", status_layout),
    "status.quick_check": ("Быстрая проверка без изменений", quick_check_layout),
    "routing.explain": ("Предварительный расчёт маршрута", route_layout),
    "failsafe.port53_check": ("Порт 53 по файлам конфигурации XKeen", port53_layout),
    "settings.storage": ("Метаданные менеджера", storage_layout),
    "settings.about": ("Справка по меню KeenVPN", help_layout),
}


def report_layout(action_id: str, lines: Sequence[str]) -> ReportLayout:
    """Разложить знакомый отчёт по областям. Новые отчёты и отказы показать полностью."""
    original = tuple(lines)
    report = _REPORTS.get(action_id)
    if (not report or len(original) < 2 or original[0] != report[0]
            or any(line.lstrip().startswith("Отказ: ") for line in original)):
        return original, ()
    return report[1](original[1:])
