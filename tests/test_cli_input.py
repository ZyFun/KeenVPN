"""Уровень запроса значения в меню: модель, цикл терминала и пункт 4 → 9 на снимке и искусственных источниках.

Ввод подаётся потоками в памяти под запретом терминала, файлов, сети
и процессов; введённые значения не должны появляться в выводе.
"""

import io
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import NEXT_STEP_MESSAGES, NextStepCode
from keenvpn.application.routing import OUTCOME_LABELS, RouteOutcome
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.interfaces.cli.composition import MenuSources, assemble_main_menu, default_sources
from keenvpn.interfaces.cli.menu import (
    InputLevel, Menu, MenuAction, MenuError, MenuItem, MenuList, MenuNavigator, SelectionKind, UnavailableReason,
    ValueRequest,
)
from keenvpn.interfaces.cli.presenters import ROUTE_NOTE, ROUTE_PROMPT
from keenvpn.interfaces.cli.terminal import (
    BACK_LABEL, HINT, INPUT_HINT, LINE_TOO_LONG, MAX_INPUT_LENGTH, PROMPT, REASON_MESSAGES, render_input, run_menu,
)
from tests.support.in_memory import InMemoryManagerMetadataStore
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import snapshot_installation_sources


# Кодек IDNA импортируется при первом обращении: прогреваем его до запрета внешних эффектов.
"пример.рф".encode("idna")

SECRET = "TEST_ONLY_INPUT_SECRET"
PRIVATE_MARKERS = (
    "02:00:00:54", "device-", "192.0.2.", "2001:db8", "fixture-password", "/fixture/ws", "/opt/etc", "\x1b",
    "fixture-rule", "host-0", "geoip:", "domain:",
)
ENTERED = ("sub.example.test", "198.51.100.7", "blocked.example.test", "2001:db8::7", "example.test", "service.another.test")
"""Вводимые значения: ни одно не должно попасть в вывод."""


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


def artificial_xray() -> XrayConfigSet:
    """Части Xray с собираемой политикой: BLOCK по домену, DIRECT по доменам, подсети и GeoIP, финальный VPN."""
    return XrayConfigSet((
        part("04_outbounds.json", {"outbounds": [
            {"tag": "proxy-out", "protocol": "trojan"}, {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ]}),
        part("05_routing.json", {"routing": {"rules": [
            {"type": "field", "domain": ["domain:blocked.example.test"], "outboundTag": "block"},
            {"type": "field", "domain": ["full:exact.example.test", "domain:example.test"], "outboundTag": "direct"},
            {"type": "field", "ip": ["198.51.100.0/24"], "outboundTag": "direct"},
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ]}}),
    ))


def sample_menu() -> Menu:
    section = Menu("Раздел", (
        MenuItem(1, "Запрос значения", action=MenuAction("section.ask")),
        MenuItem(2, "Строки", action=MenuAction("section.lines")),
    ))
    return Menu("Корень", (MenuItem(1, "Раздел", submenu=section),))


def run(text: str, submit=None, calls=None):
    """Выполнить цикл с действием, которое запрашивает значение; вернуть код, вывод и навигатор."""
    calls = [] if calls is None else calls

    def default_submit(value):
        calls.append(value)
        return ["Принято значение длиной " + str(len(value))]

    def ask():
        calls.append("ask")
        return ValueRequest(("Подсказка запроса",), default_submit if submit is None else submit)

    navigator = MenuNavigator(sample_menu())
    stdout = io.StringIO()
    with forbid_external_effects():
        code = run_menu(navigator, {"section.ask": ask, "section.lines": lambda: ["Строка"]}, io.StringIO(text), stdout)
    return code, stdout.getvalue(), navigator


class ValueRequestModelTests(unittest.TestCase):
    def test_request_requires_printable_prompt_and_callable(self):
        request = ValueRequest(("Строка",), lambda value: [])
        self.assertEqual(request.prompt, ("Строка",))
        for prompt, submit in (
            ((), lambda value: []), (("Строка",), None), (["Строка"], lambda value: []), (("tag\x1b",), lambda value: []),
            (("x" * 2001,), lambda value: []),
        ):
            with self.subTest(prompt=prompt):
                with self.assertRaises(MenuError):
                    ValueRequest(prompt, submit)

    def test_input_level_opens_only_from_menu_and_zero_returns(self):
        request = ValueRequest(("Строка",), lambda value: [])
        navigator = MenuNavigator(sample_menu())
        with self.assertRaises(MenuError):
            navigator.open_input(3, request)
        with self.assertRaises(MenuError):
            navigator.open_input("Заголовок", "не запрос")
        navigator.open_input("Заголовок", request)
        self.assertIs(type(navigator.current), InputLevel)
        self.assertEqual(navigator.titles, ("Корень", "Заголовок"))
        with self.assertRaises(MenuError):
            navigator.open_input("Ещё", request)
        with self.assertRaises(MenuError):
            navigator.open_list(MenuList("Список", "Элемент", (), ()))
        self.assertIs(navigator.select(5).kind, SelectionKind.UNKNOWN)
        self.assertIs(type(navigator.current), InputLevel)
        self.assertIs(navigator.select(0).kind, SelectionKind.BACK)
        self.assertIs(navigator.current, navigator.current)
        self.assertEqual(navigator.depth, 0)
        with self.assertRaises(MenuError):
            InputLevel("", request)

    def test_render_input_shows_path_prompt_and_zero(self):
        navigator = MenuNavigator(sample_menu())
        navigator.select(1)
        navigator.open_input("Запрос значения", ValueRequest(("Первая подсказка", "Вторая"), lambda value: []))
        self.assertEqual(
            render_input(navigator),
            ["Корень / Раздел / Запрос значения", "Первая подсказка", "Вторая", f"  0. {BACK_LABEL}"],
        )
        navigator.back()
        with self.assertRaises(MenuError):
            render_input(navigator)


class InputLoopTests(unittest.TestCase):
    def test_value_is_passed_once_without_echo_and_menu_returns(self):
        calls = []
        code, output, navigator = run(f"1\n1\n{SECRET} второе\n0\n0\n", calls=calls)
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["ask", f"{SECRET} второе"])
        self.assertIn("Корень / Раздел / Запрос значения\nПодсказка запроса\n  0. Назад\n", output)
        self.assertIn("\nПринято значение длиной 29\n\nКорень / Раздел\n", output)
        self.assertNotIn(SECRET, output)
        self.assertEqual(navigator.depth, 0)

    def test_zero_cancels_without_calling_submit(self):
        calls = []
        code, output, navigator = run("1\n1\n0\n0\n0\n", calls=calls)
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["ask"])
        self.assertEqual(output.count("Корень / Раздел\n"), 2)
        self.assertNotIn("Принято", output)
        self.assertEqual(navigator.depth, 0)

    def test_empty_and_blank_lines_repeat_the_prompt(self):
        calls = []
        code, output, _ = run("1\n1\n\n   \n\t\n0\n0\n0\n", calls=calls)
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["ask"])
        self.assertEqual(output.count(INPUT_HINT), 3)
        self.assertEqual(output.count("Корень / Раздел / Запрос значения\n"), 4)
        self.assertNotIn(HINT, output)

    def test_numbers_other_than_zero_are_values(self):
        calls = []
        code, _, _ = run("1\n1\n7\n0\n0\n", calls=calls)
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["ask", "7"])

    def test_overlong_line_is_dropped_and_prompt_stays(self):
        calls = []
        code, output, navigator = run("1\n1\n" + "x" * (MAX_INPUT_LENGTH + 1) + "\n0\n0\n0\n", calls=calls)
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["ask"])
        self.assertIn(LINE_TOO_LONG, output)
        self.assertEqual(navigator.depth, 0)
        code, _, _ = run("1\n1\n" + "y" * MAX_INPUT_LENGTH + "\n0\n0\n", calls=calls)
        self.assertEqual(code, 0)
        self.assertEqual(calls[-1], "y" * MAX_INPUT_LENGTH)

    def test_eof_and_interrupt_on_the_input_level(self):
        code, output, _ = run("1\n1\n")
        self.assertEqual(code, 0)
        self.assertTrue(output.endswith(f"{PROMPT}\n"))

        class Interrupting(io.StringIO):
            def readline(self, size=-1):
                line = super().readline(size)
                if line == "":
                    raise KeyboardInterrupt
                return line

        navigator = MenuNavigator(sample_menu())
        with self.assertRaises(KeyboardInterrupt), forbid_external_effects():
            run_menu(
                navigator, {"section.ask": lambda: ValueRequest(("П",), lambda value: [])}, Interrupting("1\n1\n"),
                io.StringIO(),
            )
        self.assertIs(type(navigator.current), InputLevel)

    def test_submit_must_return_lines(self):
        with self.assertRaises(MenuError):
            run("1\n1\nзначение\n0\n0\n", submit=lambda value: MenuList("Список", "Элемент", (), ()))
        with self.assertRaises(MenuError):
            run("1\n1\nзначение\n0\n0\n", submit=lambda value: "строка")

    def test_submit_exception_is_not_swallowed(self):
        def failing(value):
            raise RuntimeError("Текст с " + value)

        with self.assertRaises(RuntimeError):
            run("1\n1\nзначение\n0\n0\n", submit=failing)


def menu_sources(sources, metadata=None, geo_match=None) -> MenuSources:
    return MenuSources(
        policies=sources.keenetic.policies, hotspot=sources.keenetic.hotspot,
        registrations=sources.keenetic.registrations, runtime=sources.keenetic.runtime,
        xray=sources.proxy.xray, xkeen_settings=sources.proxy.settings, xkeen_init=sources.proxy.init,
        xkeen_lists=sources.proxy.lists, geodata=sources.geodata, process=sources.process, metadata=metadata,
        geo_match=geo_match,
    )


class ExplainRouteFlowTests(unittest.TestCase):
    """Пункт 4 → 9 на снимке и искусственных частях Xray: ввод, отмена, итоги и отказы."""

    def setUp(self):
        self.sources = snapshot_installation_sources()
        self.store = InMemoryManagerMetadataStore()

    def flow(self, text: str, sources: MenuSources | None = None):
        assembly = assemble_main_menu(menu_sources(self.sources, self.store) if sources is None else sources)
        stdout = io.StringIO()
        navigator = MenuNavigator(assembly.menu)
        with forbid_external_effects():
            code = run_menu(navigator, assembly.actions, io.StringIO(text), stdout)
        output = stdout.getvalue()
        for marker in (*PRIVATE_MARKERS, *ENTERED):
            self.assertNotIn(marker, output)
        self.assertTrue(all(line.isprintable() for line in output.splitlines()))
        return code, output, navigator

    def test_item_opens_the_prompt_and_zero_cancels_without_reading_sources(self):
        code, output, navigator = self.flow("4\n9\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn(
            "Главное меню KeenVPN / Правила маршрутизации / Объяснить выбор правила для домена/IP\n"
            + "\n".join(ROUTE_PROMPT) + f"\n  0. {BACK_LABEL}\n",
            output,
        )
        self.assertNotIn(REASON_MESSAGES[UnavailableReason.INPUT_REQUIRED], output)
        self.assertEqual(self.sources.proxy.calls[:3], (0, 0, 0))
        self.assertEqual(self.store.read_calls, 0)

    def test_empty_input_repeats_the_prompt_without_reading_sources(self):
        code, output, _ = self.flow("4\n9\n\n   \n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(output.count(INPUT_HINT), 2)
        self.assertEqual(self.sources.proxy.calls[:3], (0, 0, 0))

    def test_snapshot_policy_is_not_assembled_and_the_item_says_so(self):
        code, output, navigator = self.flow("4\n9\nexample.test\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn(ROUTE_NOTE, output)
        self.assertIn(f"Итог: {OUTCOME_LABELS[RouteOutcome.POLICY_ABSENT.value]}", output)
        self.assertIn("причины: final_rule_unresolved", output)
        self.assertIn("Шагов проверки: 0", output)
        self.assertNotIn("Выбрано правило", output)
        self.assertEqual(self.sources.proxy.calls[:3], (1, 1, 1))

    def test_invalid_destination_gives_scenario_code_and_step_without_reading_sources(self):
        for value in ("http://x", "a b", "198.51.100.0/24", "-bad", "2001:db8::7%eth0", f"{SECRET}\x1b"):
            with self.subTest(value=value):
                self.setUp()
                code, output, navigator = self.flow(f"4\n9\n{value}\n0\n0\n")
                self.assertEqual(code, 0)
                self.assertEqual(navigator.depth, 0)
                self.assertIn("Отказ: invalid_input / invalid_destination", output)
                self.assertIn(f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.RETRY_INPUT]}", output)
                self.assertNotIn(SECRET, output)
                self.assertEqual(self.sources.proxy.calls[:3], (0, 0, 0))

    def test_artificial_scheme_shows_steps_selection_final_and_unknown(self):
        self.sources.proxy.xray.outcome = artificial_xray()
        code, output, _ = self.flow("4\n9\nsub.example.test\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertIn(f"Итог: {OUTCOME_LABELS[RouteOutcome.RULE.value]}", output)
        self.assertIn("Шагов проверки: 3", output)
        self.assertIn("Выбрано правило 2 (группа 1, правило 1 в группе): действие DIRECT", output)
        self.assertIn("Назначение: outbound direct; позиция: 04_outbounds.json, индекс 1", output)

        code, output, _ = self.flow("4\n9\nblocked.example.test\n0\n0\n")
        self.assertIn("Выбрано правило 0 (группа 0, правило 0 в группе): действие BLOCK", output)

        code, output, _ = self.flow("4\n9\n198.51.100.7\n0\n0\n")
        self.assertIn(f"Итог: {OUTCOME_LABELS[RouteOutcome.UNKNOWN.value]}", output)
        self.assertIn("Шаг 1: правило 0 (группа 0, правило 0 в группе) — DomainCondition, действие BLOCK, неизвестно", output)

        code, output, _ = self.flow("4\n9\nservice.another.test 198.51.100.7\n0\n0\n")
        self.assertIn("Выбрано правило 3 (группа 2, правило 0 в группе): действие DIRECT", output)

        code, output, _ = self.flow("4\n9\nservice.another.test 2001:db8::7\n0\n0\n")
        self.assertIn(f"Итог: {OUTCOME_LABELS[RouteOutcome.UNKNOWN.value]}", output)
        self.assertIn("Источник содержимого геобазы не передан.", output)
        self.assertNotIn("Выбрано правило", output)
        self.assertIn("ID не присвоен", output)
        self.assertNotIn("Хранилище метаданных не подключено", output)

    def test_without_proxy_sources_the_item_is_unavailable(self):
        assembly = assemble_main_menu(default_sources())
        stdout = io.StringIO()
        with forbid_external_effects():
            code = run_menu(MenuNavigator(assembly.menu), assembly.actions, io.StringIO("4\n9\n0\n0\n"), stdout)
        self.assertEqual(code, 0)
        self.assertIn(REASON_MESSAGES[UnavailableReason.SOURCE_NOT_CONNECTED], stdout.getvalue())
        self.assertNotIn("\n".join(ROUTE_PROMPT), stdout.getvalue())

    def test_source_failure_is_shown_with_step_instead_of_explanation(self):
        self.sources.proxy.xray.outcome = OSError("/opt/etc/xray/configs/05_routing.json: fixture-password")
        code, output, navigator = self.flow("4\n9\nexample.test\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn("Отказ: source_failed / xray_config_unavailable", output)
        self.assertIn(f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}", output)
        self.assertNotIn("Итог:", output)


if __name__ == "__main__":
    unittest.main()
