"""Терминальный цикл и сборка меню на внедрённых потоках без терминала, файлов, сети и процессов."""

import io
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import NEXT_STEP_MESSAGES, NextStepCode, new_operation_id
from keenvpn.application.ports import ManagerMetadataStoreError, MetadataStoreFailure
from keenvpn.interfaces.cli.composition import (
    MenuAssembly, MenuSources, assemble_main_menu, assemble_setup_menu, default_sources,
)
from keenvpn.interfaces.cli.menu import (
    MAX_LIST_LINE_LENGTH, REASON_MESSAGES, Menu, MenuAction, MenuError, MenuItem, MenuNavigator, UnavailableReason,
)
from keenvpn.interfaces.cli.terminal import (
    BACK_LABEL, EXIT_LABEL, HINT, LIST_USAGE, NO_MATCHES, PROMPT, UNAVAILABLE_MARK, parse_choice, render_menu,
    run_menu,
)
from keenvpn.interfaces.cli.tree import ALL_ACTION_IDS, BOUND_SCENARIOS, MAIN_MENU_TITLE, SETUP_MENU_TITLE
from tests.support.in_memory import InMemoryManagerMetadataStore
from tests.support.isolation import forbid_external_effects
import json

from keenvpn.adapters.xray_configs import xray_config_from_files
from tests.support.snapshot import load_xray_snapshot_files, snapshot_installation_sources


SECRET = "TEST_ONLY_SECRET_LINE"
PRIVATE_MARKERS = ("02:00:00:54", "device-", "192.0.2.", "2001:db8", "fixture-password", "/fixture/ws", "/opt/etc", "\x1b")


def sample_menu() -> Menu:
    inner = Menu("Вложенное", (MenuItem(1, "Глубокое действие", action=MenuAction("inner.action")),))
    section = Menu("Раздел", (
        MenuItem(1, "Действие раздела", action=MenuAction("section.action")),
        MenuItem(2, "Нереализовано", action=MenuAction("section.missing", UnavailableReason.NOT_IMPLEMENTED)),
        MenuItem(3, "Вложенный раздел", submenu=inner),
    ))
    return Menu("Корень", (
        MenuItem(1, "Раздел", submenu=section),
        MenuItem(2, "Корневое действие", action=MenuAction("root.action")),
        MenuItem(3, "Без источника", action=MenuAction("root.detached", UnavailableReason.SOURCE_NOT_CONNECTED)),
    ))


def run(menu: Menu, text: str, actions=None):
    """Выполнить цикл на строках ввода под запретом внешних эффектов; вернуть код, вывод и навигатор."""
    navigator = MenuNavigator(menu)
    stdout = io.StringIO()
    with forbid_external_effects():
        code = run_menu(navigator, {} if actions is None else actions, io.StringIO(text), stdout)
    return code, stdout.getvalue(), navigator


def snapshot_menu_sources(metadata=None):
    sources = snapshot_installation_sources()
    return sources, MenuSources(
        policies=sources.keenetic.policies, hotspot=sources.keenetic.hotspot,
        registrations=sources.keenetic.registrations, runtime=sources.keenetic.runtime,
        xray=sources.proxy.xray, xkeen_settings=sources.proxy.settings, xkeen_init=sources.proxy.init,
        xkeen_lists=sources.proxy.lists, geodata=sources.geodata, process=sources.process, metadata=metadata,
    )


def states(assembly: MenuAssembly) -> dict[str, UnavailableReason | None]:
    found = {}
    pending = [assembly.menu]
    seen = set()
    while pending:
        menu = pending.pop()
        if id(menu) in seen:
            continue
        seen.add(id(menu))
        for item in menu.items:
            if item.submenu is not None:
                pending.append(item.submenu)
            else:
                found[item.action.action_id] = item.reason
    return found


class ChoiceParsingTests(unittest.TestCase):
    def test_canonical_numbers_only(self):
        for line, expected in (("0", 0), ("0\n", 0), ("1", 1), ("10\n", 10), (" 7 \n", 7), ("999", 999), ("\t3\r\n", 3)):
            with self.subTest(line=line):
                self.assertEqual(parse_choice(line), expected)
        for line in ("", "\n", "1000", "01", "00", "-1", "+1", "1a", "a", "١", "1 0", "1.0", "0x1", None, b"1", 1):
            with self.subTest(line=line):
                self.assertIsNone(parse_choice(line))


class RenderTests(unittest.TestCase):
    def test_root_and_submenu_rendering(self):
        navigator = MenuNavigator(sample_menu())
        root = render_menu(navigator)
        self.assertEqual(root[0], "Корень")
        self.assertEqual(root[1], "  1. Раздел")
        self.assertEqual(root[3], f"  3. Без источника {UNAVAILABLE_MARK}")
        self.assertEqual(root[-1], f"  0. {EXIT_LABEL}")
        navigator.select(1)
        section = render_menu(navigator)
        self.assertEqual(section[0], "Корень / Раздел")
        self.assertEqual(section[2], f"  2. Нереализовано {UNAVAILABLE_MARK}")
        self.assertEqual(section[-1], f"  0. {BACK_LABEL}")
        self.assertTrue(all(line.isprintable() for line in root + section))


class RunLoopTests(unittest.TestCase):
    def test_zero_at_root_exits_with_zero(self):
        code, output, navigator = run(sample_menu(), "0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertTrue(output.startswith("Корень\n  1. Раздел\n"))
        self.assertIn(f"  0. {EXIT_LABEL}\n{PROMPT}", output)
        self.assertNotIn(HINT, output)

    def test_zero_on_each_level_returns_one_level(self):
        code, output, navigator = run(sample_menu(), "1\n3\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertEqual(output.count("Корень / Раздел / Вложенное\n"), 1)
        self.assertEqual(output.count("Корень / Раздел\n"), 2)
        self.assertEqual(output.count("Корень\n"), 2)
        self.assertEqual(output.count(f"  0. {BACK_LABEL}"), 3)
        self.assertEqual(output.count(f"  0. {EXIT_LABEL}"), 2)

    def test_eof_exits_with_zero_without_hint(self):
        for text in ("", "1\n", "1\n3\n"):
            with self.subTest(text=text):
                code, output, _ = run(sample_menu(), text)
                self.assertEqual(code, 0)
                self.assertTrue(output.endswith(f"{PROMPT}\n"))
                self.assertNotIn(HINT, output)

    def test_unknown_and_empty_input_give_hint_and_keep_position(self):
        for text in ("99\n0\n", "\n0\n", "   \n0\n", "01\n0\n", "1000\n0\n", "один\n0\n"):
            with self.subTest(text=text):
                code, output, navigator = run(sample_menu(), text)
                self.assertEqual(code, 0)
                self.assertEqual(output.count(HINT), 1)
                self.assertEqual(output.count("Корень\n"), 2)
                self.assertEqual(navigator.depth, 0)

    def test_input_is_never_echoed_and_escape_sequences_do_not_reach_output(self):
        code, output, _ = run(sample_menu(), f"\x1b[31m{SECRET}\n\x9b1m\n2 {SECRET}\n0\n")
        self.assertEqual(code, 0)
        self.assertNotIn(SECRET, output)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\x9b", output)
        self.assertTrue(all(line.isprintable() for line in output.splitlines()))

    def test_unavailable_item_shows_reason_and_keeps_position(self):
        code, output, navigator = run(sample_menu(), "3\n1\n2\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertIn(REASON_MESSAGES[UnavailableReason.SOURCE_NOT_CONNECTED], output)
        self.assertIn(REASON_MESSAGES[UnavailableReason.NOT_IMPLEMENTED], output)
        self.assertEqual(navigator.depth, 0)

    def test_available_action_runs_once_per_selection_and_prints_its_lines(self):
        calls = []

        def action():
            calls.append(1)
            return ["Первая строка действия", "Вторая строка действия"]

        code, output, _ = run(sample_menu(), "2\n2\n1\n1\n0\n0\n", {"root.action": action, "section.action": action})
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 3)
        self.assertEqual(output.count("Первая строка действия\nВторая строка действия\n"), 3)
        # Корень показан при старте, после двух действий в нём и после возврата из раздела.
        self.assertEqual(output.count("Корень\n"), 4)
        self.assertEqual(output.count("Корень / Раздел\n"), 2)

    def test_available_action_without_handler_is_a_menu_error(self):
        with self.assertRaises(MenuError):
            run(sample_menu(), "2\n0\n")

    def test_interrupt_and_wrong_stream_types_are_not_swallowed(self):
        class Interrupting:
            def readline(self, size=-1):
                raise KeyboardInterrupt

        class Binary:
            def readline(self, size=-1):
                return b"0\n"

        for stdin, error in ((Interrupting(), KeyboardInterrupt), (Binary(), TypeError)):
            with self.subTest(error=error.__name__), self.assertRaises(error):
                with forbid_external_effects():
                    run_menu(MenuNavigator(sample_menu()), {}, stdin, io.StringIO())


class CompositionTests(unittest.TestCase):
    def test_default_sources_leave_only_help_available(self):
        assembly = assemble_main_menu(default_sources())
        found = states(assembly)
        self.assertEqual(set(found), set(ALL_ACTION_IDS))
        self.assertEqual(set(assembly.actions), {"settings.about"})
        self.assertIsNone(found["settings.about"])
        self.assertIs(found["routing.explain"], UnavailableReason.INPUT_REQUIRED)
        for action_id in set(BOUND_SCENARIOS) - {"routing.explain"}:
            self.assertIs(found[action_id], UnavailableReason.SOURCE_NOT_CONNECTED, action_id)
        for action_id in set(ALL_ACTION_IDS) - set(BOUND_SCENARIOS) - {"settings.about"}:
            self.assertIs(found[action_id], UnavailableReason.NOT_IMPLEMENTED, action_id)
        with self.assertRaises(TypeError):
            assembly.actions["x"] = lambda: []
        self.assertEqual(assemble_main_menu().menu.title, MAIN_MENU_TITLE)

    def test_connected_sources_make_bound_items_available(self):
        _, sources = snapshot_menu_sources(InMemoryManagerMetadataStore())
        found = states(assemble_main_menu(sources))
        for action_id in ("status.summary", "routing.list", "devices.list", "failsafe.port53_check", "settings.storage"):
            self.assertIsNone(found[action_id], action_id)
        self.assertIs(found["routing.explain"], UnavailableReason.INPUT_REQUIRED)
        self.assertEqual(
            set(assemble_main_menu(sources).actions),
            {"status.summary", "routing.list", "devices.list", "failsafe.port53_check", "settings.storage",
             "settings.about"},
        )

    def test_partial_sources_enable_only_what_they_cover(self):
        _, full = snapshot_menu_sources()
        keenetic_only = MenuSources(
            policies=full.policies, hotspot=full.hotspot, registrations=full.registrations, runtime=full.runtime,
        )
        found = states(assemble_main_menu(keenetic_only))
        self.assertIsNone(found["devices.list"])
        for action_id in ("status.summary", "routing.list", "failsafe.port53_check", "settings.storage"):
            self.assertIs(found[action_id], UnavailableReason.SOURCE_NOT_CONNECTED, action_id)
        three_of_four = MenuSources(policies=full.policies, hotspot=full.hotspot, registrations=full.registrations)
        self.assertIs(states(assemble_main_menu(three_of_four))["devices.list"], UnavailableReason.SOURCE_NOT_CONNECTED)
        without_process = MenuSources(
            policies=full.policies, hotspot=full.hotspot, registrations=full.registrations, runtime=full.runtime,
            xray=full.xray, xkeen_settings=full.xkeen_settings, xkeen_init=full.xkeen_init, xkeen_lists=full.xkeen_lists,
            geodata=full.geodata,
        )
        found = states(assemble_main_menu(without_process))
        self.assertIs(found["status.summary"], UnavailableReason.SOURCE_NOT_CONNECTED)
        self.assertIsNone(found["routing.list"])
        self.assertIsNone(found["failsafe.port53_check"])
        with self.assertRaises(MenuError):
            assemble_main_menu({"policies": full.policies})

    def test_setup_assembly_has_no_available_actions_in_tree(self):
        _, sources = snapshot_menu_sources(InMemoryManagerMetadataStore())
        assembly = assemble_setup_menu(sources)
        self.assertEqual(assembly.menu.title, SETUP_MENU_TITLE)
        self.assertTrue(all(item.reason is UnavailableReason.NOT_IMPLEMENTED for item in assembly.menu.items))
        self.assertEqual(assemble_setup_menu().menu.title, SETUP_MENU_TITLE)


class SnapshotFlowTests(unittest.TestCase):
    def setUp(self):
        self.sources, menu_sources = snapshot_menu_sources(InMemoryManagerMetadataStore())
        self.assembly = assemble_main_menu(menu_sources, operation_ids=new_operation_id)

    def flow(self, text: str):
        stdout = io.StringIO()
        navigator = MenuNavigator(self.assembly.menu)
        with forbid_external_effects():
            code = run_menu(navigator, self.assembly.actions, io.StringIO(text), stdout)
        output = stdout.getvalue()
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, output)
        self.assertTrue(all(line.isprintable() for line in output.splitlines()))
        return code, output, navigator

    def test_summary_reads_each_source_once_and_shows_snapshot(self):
        code, output, navigator = self.flow("1\n1\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn("Сводка установки по прочитанным источникам", output)
        self.assertIn("Политик: 3; идентификаторы: Policy10, Policy20, Policy30", output)
        # Блок проверок приходит из сценария: меню показывает статусы, не вычисляя их из состояния или ошибок.
        self.assertIn("  Активная сетевая проверка: не выполнялась", output)
        self.assertIn("    vpn_reachable: не проверено, причина network_check_not_performed (сетевая проверка)", output)
        self.assertIn("    xray_process_consistent: успешно", output)
        self.assertEqual(self.sources.keenetic.calls, (1, 1, 1, 1))
        self.assertEqual(self.sources.proxy.calls[:3], (1, 1, 1))
        self.assertEqual(len(self.sources.proxy.calls[3]), 3)
        self.assertEqual((self.sources.geodata.calls, self.sources.process.calls), (1, 1))

    def test_rendering_does_not_touch_sources(self):
        code, _, _ = self.flow("1\n0\n4\n0\n5\n0\n6\n0\n10\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(self.sources.keenetic.calls, (0, 0, 0, 0))
        self.assertEqual(self.sources.proxy.calls[:3], (0, 0, 0))
        self.assertEqual((self.sources.geodata.calls, self.sources.process.calls), (0, 0))

    def test_rules_devices_port53_storage_and_help_items(self):
        code, output, _ = self.flow("4\n1\n0\n0\n5\n1\n0\n6\n7\n0\n10\n1\n5\n0\n0\n")
        self.assertEqual(code, 0)
        for text in (
            "Правила маршрутизации по конфигурации Xray", "Keenetic", "Порт 53 по файлам конфигурации XKeen",
            "Метаданные менеджера", "Метаданных нет: размещение хранилищ ещё не записано.", "Справка по меню KeenVPN",
        ):
            self.assertIn(text, output)
        self.assertEqual(self.sources.proxy.calls[:3], (2, 2, 2))
        self.assertEqual(self.sources.keenetic.calls, (1, 1, 1, 1))

    def test_rule_groups_open_as_list_with_search_and_cards(self):
        code, output, navigator = self.flow("4\n1\nfallback_mixed\n3\n0\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        path = "Главное меню KeenVPN / Правила маршрутизации / Группы правил"
        self.assertIn(f"{path}\nПравила маршрутизации по конфигурации Xray\n", output)
        self.assertIn(f"{path} / Результаты поиска\nНайдено: 3 из 8.\n  3. rules:", output)
        found = output.split(f"{path} / Результаты поиска\n", 1)[1].split(LIST_USAGE, 1)[0]
        self.assertEqual([line.split(".")[0].strip() for line in found.splitlines()[1:]], ["3", "4", "8"])
        self.assertIn(
            f"{path} / Результаты поиска / Группа правил 3\n"
            "Часть: 05_routing.json; индекс правила Xray: 2 (счёт с нуля)\n",
            output,
        )
        self.assertIn(
            "Назначение: balancer vpn-group; запасной: blocked; стратегия: leastPing; действие назначения: нет\n"
            "Outbound назначения: 1\n  trojan-out\n", output,
        )
        self.assertIn("Тег правила: задан, значение не показывается", output)
        # Сценарий выполнен один раз: поиск, карточка и возвраты источники не читают.
        self.assertEqual(self.sources.proxy.calls[:3], (1, 1, 1))

    def test_balancer_with_many_long_outbound_tags_keeps_the_menu_running(self):
        # Регрессия review 72-R01: 40 outbound с тегами по 60 символов под селектором балансировщика.
        files = load_xray_snapshot_files()
        outbounds = json.loads(files["04_outbounds.json"])
        tags = [f"trojan-out-{number:02d}-" + "a" * 46 for number in range(40)]
        outbounds["outbounds"] += [{"tag": tag, "protocol": "freedom", "settings": {}} for tag in tags]
        files["04_outbounds.json"] = json.dumps(outbounds).encode("utf-8")
        self.sources.proxy.xray.outcome = xray_config_from_files(files)
        code, output, navigator = self.flow("4\n1\n3\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn("Outbound назначения: 41\n  trojan-out, " + ", ".join(tags[:9]) + "\n", output)
        self.assertIn("  " + ", ".join(tags[29:39]) + "\n  " + tags[39] + "\nПричины назначения:", output)
        self.assertTrue(all(len(line) <= MAX_LIST_LINE_LENGTH for line in output.splitlines()))
        self.assertEqual(output.count("Главное меню KeenVPN / Правила маршрутизации / Группы правил\n"), 2)

    def test_search_never_matches_hidden_values(self):
        # Значения условий, теги правил и сети снимка не показываются, поэтому поиск их не находит.
        for value in (
            "fixture-rule-03", "host-04.example", "10.0.0.0/8", "geoip:ru", "dns-local", "force-proxy-redirect",
            "tcp,udp", "localhost",
        ):
            with self.subTest(value=value):
                code, output, _ = self.flow(f"4\n1\n{value}\n0\n0\n0\n")
                self.assertEqual(code, 0)
                self.assertIn(NO_MATCHES, output)
                self.assertNotIn("Найдено:", output)
                self.assertNotIn(value, output)

    def test_explain_route_requires_input_and_runs_nothing(self):
        code, output, _ = self.flow("4\n9\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertIn(REASON_MESSAGES[UnavailableReason.INPUT_REQUIRED], output)
        self.assertEqual(self.sources.proxy.calls[:3], (0, 0, 0))

    def test_source_failure_is_shown_as_safe_error(self):
        self.sources.proxy.xray.outcome = OSError("/opt/etc/xray/configs/05_routing.json: fixture-password")
        code, output, _ = self.flow("6\n7\n0\n1\n1\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(output.count("Отказ: source_failed / xray_config_unavailable"), 2)
        self.assertIn("Причина: Не удалось прочитать части конфигурации Xray.", output)
        self.assertEqual(output.count(f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}"), 2)
        self.assertNotIn("05_routing.json: ", output)

    def test_routing_list_failure_shows_error_with_next_step_instead_of_list(self):
        # Отказ при выборе 4 → 1: строки отказа с безопасным шагом вместо списка, положение в меню прежнее.
        self.sources.proxy.xray.outcome = OSError("/opt/etc/xray/configs/05_routing.json: fixture-password")
        code, output, navigator = self.flow("4\n1\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn(
            "Отказ: source_failed / xray_config_unavailable\nПричина: Не удалось прочитать части конфигурации Xray.\n"
            f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}\n\nГлавное меню KeenVPN / Правила маршрутизации\n",
            output,
        )
        self.assertNotIn("Группы правил", output)
        self.assertNotIn("Номер — карточка", output)
        self.assertEqual(output.count("Следующий шаг:"), 1)

    def test_metadata_store_failures_show_their_own_steps(self):
        store = InMemoryManagerMetadataStore()
        _, menu_sources = snapshot_menu_sources(store)
        assembly = assemble_main_menu(menu_sources, operation_ids=new_operation_id)
        for failure, step in (
            (MetadataStoreFailure.BUSY, NextStepCode.RETRY_LATER),
            (MetadataStoreFailure.CONFLICT, NextStepCode.OPEN_VIEW),
            (MetadataStoreFailure.UNSAFE, NextStepCode.PRESERVE_FILE),
            (MetadataStoreFailure.UNAVAILABLE, NextStepCode.CHECK_SOURCE),
        ):
            with self.subTest(failure=failure.value):
                store.read_failure = ManagerMetadataStoreError(failure)
                stdout = io.StringIO()
                with forbid_external_effects():
                    code = run_menu(MenuNavigator(assembly.menu), assembly.actions, io.StringIO("10\n1\n0\n0\n"), stdout)
                output = stdout.getvalue()
                self.assertEqual(code, 0)
                self.assertIn(f"Отказ: source_failed / {failure.value}\n", output)
                self.assertIn(f"Следующий шаг: {NEXT_STEP_MESSAGES[step]}\n", output)
                for marker in PRIVATE_MARKERS:
                    self.assertNotIn(marker, output)
        self.assertEqual(store.write_calls, ())

    def test_user_tags_shaped_like_private_values_do_not_reach_the_terminal(self):
        # Регрессия review 71-R01: `dns.tag` и стратегию задаёт пользователь, сводка показывает их только как теги.
        values = ("probe.example", "192.0.2.10", "02:00:00:54:00:01", "https://example.invalid/TEST_ONLY_TOKEN")
        for value in values:
            files = load_xray_snapshot_files()
            dns = json.loads(files["02_dns.json"])
            dns["dns"]["tag"] = value
            files["02_dns.json"] = json.dumps(dns).encode("utf-8")
            routing = json.loads(files["05_routing.json"])
            routing["routing"]["domainStrategy"] = value
            files["05_routing.json"] = json.dumps(routing).encode("utf-8")
            self.sources.proxy.xray.outcome = xray_config_from_files(files)
            with self.subTest(value=value):
                code, output, _ = self.flow("1\n1\n0\n0\n")
                self.assertEqual(code, 0)
                self.assertIn("Сводка установки по прочитанным источникам", output)
                self.assertIn("DNS-теги: <скрыто>; стратегии доменов: <скрыто>", output)
                self.assertNotIn(value, output)
                self.assertNotIn("TEST_ONLY_TOKEN", output)

    def test_default_assembly_explains_missing_sources(self):
        assembly = assemble_main_menu(default_sources())
        stdout = io.StringIO()
        with forbid_external_effects():
            code = run_menu(MenuNavigator(assembly.menu), assembly.actions, io.StringIO("1\n1\n0\n10\n5\n0\n0\n"), stdout)
        output = stdout.getvalue()
        self.assertEqual(code, 0)
        self.assertIn(REASON_MESSAGES[UnavailableReason.SOURCE_NOT_CONNECTED], output)
        self.assertIn("Справка по меню KeenVPN", output)
        self.assertNotIn("Сводка установки", output)


if __name__ == "__main__":
    unittest.main()
