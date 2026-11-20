"""Полноэкранные отчёты сохраняют неизвестные состояния, ограничения и сводки сценариев."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.status_summary import AREA_LABELS
from keenvpn.interfaces.cli.composition import assemble_main_menu
from keenvpn.interfaces.cli.presenters import PORT_53_NOTE, SNAPSHOT_NOTE
from keenvpn.interfaces.cli.report_layout import report_layout
from tests.test_cli_terminal import snapshot_menu_sources


class ReportLayoutTests(unittest.TestCase):
    def setUp(self):
        _, sources = snapshot_menu_sources()
        self.actions = assemble_main_menu(sources).actions

    def test_status_names_all_areas_and_separates_their_checks(self):
        facts, sections = report_layout("status.summary", self.actions["status.summary"]())
        self.assertEqual([name for name, _ in sections], ["Подробности проверок"])
        self.assertEqual(sum(line.partition(": ")[0] in AREA_LABELS.values() for line in facts), 7)
        self.assertIn(SNAPSHOT_NOTE, facts)
        self.assertFalse(any("Проверка xray_process_consistent" in line for line in facts))
        details = sections[0][1]
        self.assertTrue(any("Проверка xray_process_consistent" in line for line in details))
        self.assertTrue(any(PORT_53_NOTE in line for line in details))

    def test_quick_preserves_partial_outcome_and_source_and_check_sections(self):
        facts, sections = report_layout("status.quick_check", self.actions["status.quick_check"]())
        self.assertTrue(any("часть проверок не выполнена или не поддерживается" in line for line in facts))
        self.assertTrue(any(line.startswith("По статусам: ") for line in facts))
        self.assertIn("Активная сетевая проверка: не выполнялась", facts)
        self.assertEqual([name for name, _ in sections], ["Источники снимка", "Все проверки"])
        self.assertTrue(any("vpn_reachable" in line for line in sections[1][1]))

    def test_port53_separates_flags_while_preserving_ranges_and_unknown_states(self):
        lines = self.actions["failsafe.port53_check"]()
        facts, sections = report_layout("failsafe.port53_check", lines)
        for expected in ("в списке исключённых портов:", "в списке перехватываемых портов:", "proxy_dns:", "proxy_router:"):
            self.assertTrue(any(expected in line for line in facts))
        self.assertIn(PORT_53_NOTE, facts)
        self.assertEqual(sections[0][0], "Сведения из файлов XKeen")
        self.assertTrue(any("; proxy_router: " in line for line in sections[0][1]))
        facts, _ = report_layout("failsafe.port53_check", [lines[0], "proxy_dns: duplicate (нет данных); proxy_router: missing (нет данных)"])
        self.assertEqual(facts, ("proxy_dns: duplicate (нет данных)", "proxy_router: missing (нет данных)"))

    def test_route_preserves_the_outcome_and_its_context_without_the_request(self):
        lines = self.actions["routing.explain"]().submit("router.example")
        facts, sections = report_layout("routing.explain", lines)
        self.assertTrue(facts[0].startswith("Итог: "))
        self.assertTrue(any("политика действующей схемы не собрана" in line for line in facts))
        self.assertIn("Шагов проверки: 0", facts)
        self.assertEqual([name for name, _ in sections], ["Предположения расчёта"])
        self.assertNotIn("router.example", repr((facts, sections)))
        for outcome in ("выбрано правило", "действует финальное правило", "условие неизвестно"):
            with self.subTest(outcome=outcome):
                source = [lines[0], "Шагов проверки: 1", "  Шаг 1: сведения", "Итог: " + outcome, "  Пояснение итога"]
                facts, sections = report_layout("routing.explain", source)
                self.assertEqual(facts, ("Итог: " + outcome, "  Пояснение итога", "Шагов проверки: 1"))
                self.assertEqual(sections, (("Шаги проверки", ("  Шаг 1: сведения",)),))

    def test_metadata_and_help_use_real_values_and_terminal_controls(self):
        rows = ["Метаданные менеджера", "Версия схемы: 7", "  Роль data: состояние known", "История: не задана"]
        facts, sections = report_layout("settings.storage", rows)
        self.assertEqual(facts, (rows[1], rows[-1]))
        self.assertEqual(sections, (("Роли хранилищ", (rows[2],)),))
        help_lines = self.actions["settings.about"]()
        help_screen = "\n".join(report_layout("settings.about", help_lines)[0])
        self.assertIn("Поиск: /, текст и Enter", help_screen)
        self.assertIn("Esc", help_screen)
        for hint in ("Tab", "Источник: i", "Home", "в скобках указана причина"):
            self.assertIn(hint, help_screen)
        self.assertNotIn("[недоступно]", help_screen)
        self.assertIn(help_lines[-1], help_screen)
        self.assertNotIn("другой текст ищет", help_screen)

    def test_errors_drafts_and_unrecognised_formats_keep_the_original_report(self):
        for action, rows in (
            ("status.summary", ["Сводка состояния по областям", "Ядро Xray: ошибка", "  Отказ: source_failed", "  Причина: чтение"]),
            ("routing.explain", ["Отказ: invalid_input", "Следующий шаг: исправьте значение"]),
            ("draft.diff", ["Изменения без секретов:", "данные: изменено"]),
            ("draft.check", ["Статическая проверка:", "Итог: неполная", "Бинарная проверка установленным Xray:", "Отказ: ошибка"]),
            ("settings.storage", ["Новая версия отчёта", "Новая строка"]),
            ("settings.about", ["Отказ: чтение"]),
        ):
            with self.subTest(action=action):
                self.assertEqual(report_layout(action, rows), (tuple(rows), ()))
