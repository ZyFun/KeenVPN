"""Терминальный цикл и сборка меню на внедрённых потоках без терминала, файлов, сети и процессов."""

import io
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import NEXT_STEP_MESSAGES, NextStepCode, new_operation_id
from keenvpn.application.routing_rules import AssignRuleIdentifiers, AssignRuleIdentifiersHandler
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.routing_import import ImportRoutingSchemeHandler
from keenvpn.domain.manager_metadata import ManagerMetadata, RuleRecord, decode_manager_metadata, encode_manager_metadata
from keenvpn.interfaces.cli.presenters import CONNECTIONS_NOTE, DEVICES_NOTE, METADATA_NOTES, SEGMENT_MATCH_NOTE
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet
from tests.support.in_memory import (
    InMemoryKeeneticHotspotRuntimeSource, InMemoryKeeneticHotspotSettingsSource, InMemoryKeeneticPolicySource,
    InMemoryKeeneticRegistrationSource,
)
from keenvpn.application.routing_rules import MetadataState
from keenvpn.application.ports import ManagerMetadataStoreError, MetadataStoreFailure
from keenvpn.application.status_summary import PORT_53_HINT
from keenvpn.domain.xkeen_config import XKeenListName
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

    def test_header_is_rendered_only_at_the_root(self):
        navigator = MenuNavigator(sample_menu())
        self.assertEqual(render_menu(navigator, ["Шапка"])[:3], ["Корень", "Шапка", "  1. Раздел"])
        navigator.select(1)
        self.assertNotIn("Шапка", render_menu(navigator, ["Шапка"]))


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

    def test_header_runs_on_entering_the_root_and_is_reused_for_hints(self):
        calls = []

        def header():
            calls.append(1)
            return [f"Шапка {len(calls)}"]

        stdout = io.StringIO()
        with forbid_external_effects():
            code = run_menu(
                MenuNavigator(sample_menu()), {"root.action": lambda: ["Действие"]},
                io.StringIO("x\n\n2\n1\n0\n1\n3\n0\n0\n0\n"), stdout, header,
            )
        output = stdout.getvalue()
        self.assertEqual(code, 0)
        # Шапка выполняется при старте и при каждом возврате в корень; подсказки и действие в корне её не повторяют.
        self.assertEqual(len(calls), 3)
        self.assertTrue(output.startswith("Корень\nШапка 1\n  1. Раздел\n"))
        self.assertEqual(output.count("Корень\nШапка 1\n"), 4)
        self.assertEqual(output.count("Корень\nШапка 2\n"), 1)
        self.assertEqual(output.count("Корень\nШапка 3\n"), 1)
        self.assertNotIn("Раздел\nШапка", output)
        self.assertNotIn("Вложенное\nШапка", output)

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
    def test_default_sources_leave_summary_and_help_available(self):
        assembly = assemble_main_menu(default_sources())
        found = states(assembly)
        self.assertEqual(set(found), set(ALL_ACTION_IDS))
        # Сводка допускает неподключённые источники: пункт доступен и показывает их области «не проверено».
        self.assertEqual(set(assembly.actions), {"settings.about", "status.summary"})
        self.assertIsNone(found["settings.about"])
        self.assertIsNone(found["status.summary"])
        self.assertIs(found["routing.explain"], UnavailableReason.INPUT_REQUIRED)
        for action_id in set(BOUND_SCENARIOS) - {"routing.explain", "status.summary"}:
            self.assertIs(found[action_id], UnavailableReason.SOURCE_NOT_CONNECTED, action_id)
        for action_id in set(ALL_ACTION_IDS) - set(BOUND_SCENARIOS) - {"settings.about"}:
            self.assertIs(found[action_id], UnavailableReason.NOT_IMPLEMENTED, action_id)
        with self.assertRaises(TypeError):
            assembly.actions["x"] = lambda: []
        self.assertTrue(callable(assembly.header))
        self.assertEqual(assemble_main_menu().menu.title, MAIN_MENU_TITLE)

    def test_connected_sources_make_bound_items_available(self):
        _, sources = snapshot_menu_sources(InMemoryManagerMetadataStore())
        found = states(assemble_main_menu(sources))
        for action_id in (
            "status.summary", "connections.list", "routing.list", "devices.list", "failsafe.port53_check",
            "settings.storage",
        ):
            self.assertIsNone(found[action_id], action_id)
        self.assertIs(found["routing.explain"], UnavailableReason.INPUT_REQUIRED)
        self.assertEqual(
            set(assemble_main_menu(sources).actions),
            {"status.summary", "connections.list", "routing.list", "devices.list", "failsafe.port53_check",
             "settings.storage", "settings.about"},
        )

    def test_partial_sources_enable_only_what_they_cover(self):
        _, full = snapshot_menu_sources()
        keenetic_only = MenuSources(
            policies=full.policies, hotspot=full.hotspot, registrations=full.registrations, runtime=full.runtime,
        )
        found = states(assemble_main_menu(keenetic_only))
        self.assertIsNone(found["devices.list"])
        self.assertIsNone(found["status.summary"])
        for action_id in ("connections.list", "routing.list", "failsafe.port53_check", "settings.storage"):
            self.assertIs(found[action_id], UnavailableReason.SOURCE_NOT_CONNECTED, action_id)
        three_of_four = MenuSources(policies=full.policies, hotspot=full.hotspot, registrations=full.registrations)
        self.assertIs(states(assemble_main_menu(three_of_four))["devices.list"], UnavailableReason.SOURCE_NOT_CONNECTED)
        without_process = MenuSources(
            policies=full.policies, hotspot=full.hotspot, registrations=full.registrations, runtime=full.runtime,
            xray=full.xray, xkeen_settings=full.xkeen_settings, xkeen_init=full.xkeen_init, xkeen_lists=full.xkeen_lists,
            geodata=full.geodata,
        )
        found = states(assemble_main_menu(without_process))
        self.assertIsNone(found["status.summary"])
        self.assertIsNone(found["connections.list"])
        # Список правил не требует хранилища метаданных: без него он показывается без названий и идентификаторов.
        self.assertIsNone(found["routing.list"])
        self.assertIsNone(found["failsafe.port53_check"])
        with self.assertRaises(MenuError):
            assemble_main_menu({"policies": full.policies})

    def test_setup_assembly_has_no_available_actions_in_tree(self):
        _, sources = snapshot_menu_sources(InMemoryManagerMetadataStore())
        assembly = assemble_setup_menu(sources)
        self.assertEqual(assembly.menu.title, SETUP_MENU_TITLE)
        self.assertTrue(all(item.reason is UnavailableReason.NOT_IMPLEMENTED for item in assembly.menu.items))
        self.assertIsNone(assembly.header)
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
        self.assertIn(
            "Сводка состояния по областям\nАктивная сетевая проверка: не выполнялась\nЯдро Xray: работает\n"
            "  Проверка xray_process_consistent: успешно\nПерехват: не поддерживается\n", output,
        )
        # Статусы приходят из сценария: меню показывает их, не вычисляя из состояния или ошибок.
        self.assertIn("  Проверка vpn_reachable: не проверено, причина network_check_not_performed (сетевая проверка)", output)
        self.assertIn("DNS и порт 53: исключение 53 включено, не проверено\n", output)
        self.assertIn(f"  Подсказка: {PORT_53_HINT}\n", output)
        self.assertIn("Режим резерва: без прямого резерва\n", output)
        self.assertEqual(self.sources.proxy.calls, (1, 1, 1, (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING)))
        self.assertEqual(self.sources.process.calls, 1)
        self.assertEqual(self.sources.keenetic.calls, (0, 0, 0, 0))
        self.assertEqual(self.sources.geodata.calls, 0)

    def test_rendering_does_not_touch_sources(self):
        code, _, _ = self.flow("1\n0\n4\n0\n5\n0\n6\n0\n10\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(self.sources.keenetic.calls, (0, 0, 0, 0))
        self.assertEqual(self.sources.proxy.calls[:3], (0, 0, 0))
        self.assertEqual((self.sources.geodata.calls, self.sources.process.calls), (0, 0))

    def test_rules_port53_storage_and_help_items(self):
        code, output, _ = self.flow("4\n1\n0\n0\n6\n7\n0\n10\n1\n5\n0\n0\n")
        self.assertEqual(code, 0)
        for text in (
            "Правила маршрутизации по конфигурации Xray", "Порт 53 по файлам конфигурации XKeen",
            "Метаданные менеджера", "Метаданных нет: размещение хранилищ ещё не записано.", "Справка по меню KeenVPN",
        ):
            self.assertIn(text, output)
        self.assertEqual(self.sources.proxy.calls[:3], (2, 2, 2))
        # Устройства Keenetic здесь не открывались: их список проверяет отдельный класс ниже.
        self.assertEqual(self.sources.keenetic.calls, (0, 0, 0, 0))

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
                self.assertIn("Сводка состояния по областям", output)
                self.assertIn("Режим резерва: без прямого резерва", output)
                self.assertNotIn(value, output)
                self.assertNotIn("TEST_ONLY_TOKEN", output)

    def test_default_assembly_explains_missing_sources(self):
        assembly = assemble_main_menu(default_sources())
        stdout = io.StringIO()
        with forbid_external_effects():
            code = run_menu(
                MenuNavigator(assembly.menu), assembly.actions, io.StringIO("1\n1\n0\n4\n1\n0\n10\n5\n0\n0\n"), stdout,
            )
        output = stdout.getvalue()
        self.assertEqual(code, 0)
        self.assertIn(REASON_MESSAGES[UnavailableReason.SOURCE_NOT_CONNECTED], output)
        self.assertIn("Справка по меню KeenVPN", output)
        self.assertIn(
            "Ядро Xray: не проверено\n  Проверка xray_process_consistent: не проверено, причина source_not_connected\n",
            output,
        )
        self.assertNotIn("Сводка установки", output)


SNAPSHOT_HEADER = [
    "Состояние по источникам, активная сетевая проверка не выполнялась:",
    "  Ядро Xray: работает",
    "  Перехват: не поддерживается",
    "  Доступность VPN: не проверено",
    "  DNS и порт 53: исключение 53 включено, не проверено",
    "  Автозапуск: включён",
    "  Режим резерва: без прямого резерва",
    "  Черновик: не поддерживается",
]


class HeaderFlowTests(unittest.TestCase):
    """Шапка главного меню из сценария сводки: только в корне, при входе в корень, без второго вычисления."""

    def setUp(self):
        self.sources, menu_sources = snapshot_menu_sources(InMemoryManagerMetadataStore())
        self.assembly = assemble_main_menu(menu_sources, operation_ids=new_operation_id)

    def flow(self, text: str, assembly: MenuAssembly | None = None):
        assembly = self.assembly if assembly is None else assembly
        stdout = io.StringIO()
        with forbid_external_effects():
            code = run_menu(MenuNavigator(assembly.menu), assembly.actions, io.StringIO(text), stdout, assembly.header)
        output = stdout.getvalue()
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, output)
        self.assertTrue(all(line.isprintable() for line in output.splitlines()))
        return code, output

    def test_root_shows_areas_separately_under_the_title(self):
        code, output = self.flow("0\n")
        self.assertEqual(code, 0)
        self.assertTrue(output.startswith("\n".join([MAIN_MENU_TITLE, *SNAPSHOT_HEADER, "  1. Состояние и быстрые действия"])))
        self.assertEqual(self.sources.process.calls, 1)
        self.assertEqual(self.sources.keenetic.calls, (0, 0, 0, 0))

    def test_header_is_read_on_entering_the_root_only(self):
        code, output = self.flow("x\n\n1\n0\n6\n7\n0\n0\n0\n")
        self.assertEqual(code, 0)
        # Запуск и два возврата в корень; подсказки в корне, подменю и пункт 6 → 7 шапку не выполняют.
        self.assertEqual(self.sources.process.calls, 3)
        self.assertEqual(output.count(SNAPSHOT_HEADER[1] + "\n"), 5)
        self.assertNotIn("Состояние и быстрые действия\n" + SNAPSHOT_HEADER[0], output)
        self.assertNotIn("Автозапуск, DNS и поведение при сбое\n" + SNAPSHOT_HEADER[0], output)

    def test_summary_item_repeats_the_header_from_the_same_scenario(self):
        code, output = self.flow("1\n1\n0\n0\n")
        self.assertEqual(code, 0)
        summary = output.split("Сводка состояния по областям\n", 1)[1]
        for line in SNAPSHOT_HEADER[1:]:
            self.assertIn("\n" + line.strip() + "\n", summary)
        # Шапка выполнена при запуске и при возврате в корень, пункт — один раз.
        self.assertEqual(self.sources.process.calls, 3)

    def test_header_marks_a_failed_source_without_its_text(self):
        self.sources.process.outcome = OSError("/opt/etc/TEST_ONLY_SECRET 192.0.2.1")
        code, output = self.flow("0\n")
        self.assertEqual(code, 0)
        self.assertIn("  Ядро Xray: не проверено\n  Перехват: не поддерживается\n", output)
        self.assertIn("  Автозапуск: включён\n", output)
        self.assertNotIn("TEST_ONLY_SECRET", output)

    def test_default_assembly_header_reads_nothing_and_never_shows_health(self):
        code, output = self.flow("0\n", assemble_main_menu(default_sources()))
        self.assertEqual(code, 0)
        for line in (
            "  Ядро Xray: не проверено", "  Перехват: не поддерживается", "  Доступность VPN: не проверено",
            "  DNS и порт 53: не проверено", "  Автозапуск: не проверено", "  Режим резерва: не проверено",
            "  Черновик: не поддерживается",
        ):
            self.assertIn(line + "\n", output)
        self.assertNotIn("работает", output)
        self.assertNotIn("успешно", output)

    def test_setup_menu_has_no_header(self):
        sources, menu_sources = snapshot_menu_sources()
        assembly = assemble_setup_menu(menu_sources)
        self.assertIsNone(assembly.header)
        code, output = self.flow("0\n", assembly)
        self.assertEqual(code, 0)
        self.assertNotIn("Ядро Xray", output)
        self.assertEqual(sources.process.calls, 0)


NAME_MARKER = "TEST_ONLY_PRIVATE_NAME"


def assign_snapshot_ids(sources, store, names=()):
    """Присвоить идентификаторы правилам снимка явной командой и дописать названия прямо в файл хранилища."""
    proxy = InspectProxyConfigHandler(sources.proxy.xray, sources.proxy.settings, sources.proxy.init, sources.proxy.lists)
    result = AssignRuleIdentifiersHandler(ImportRoutingSchemeHandler(proxy), store).execute(AssignRuleIdentifiers())
    assert result.succeeded, result.error
    metadata = decode_manager_metadata(store.content).metadata
    records = list(metadata.rules)
    for index, name in names:
        records[index] = RuleRecord(records[index].rule_id, name, records[index].key, records[index].extra)
    store.content = encode_manager_metadata(ManagerMetadata(metadata.storage, metadata.extra, rules=tuple(records)))
    return [record.rule_id for record in records]


class ConnectionsAndRulesFlowTests(unittest.TestCase):
    """Пункты 3 → 1 и 4 → 1 на снимке: списки, поиск, карточки, идентичность правил и её недоступность."""

    def setUp(self):
        self.store = InMemoryManagerMetadataStore()
        self.sources, self.menu_sources = snapshot_menu_sources(self.store)

    def flow(self, text: str, menu_sources=None):
        assembly = assemble_main_menu(self.menu_sources if menu_sources is None else menu_sources)
        stdout = io.StringIO()
        navigator = MenuNavigator(assembly.menu)
        with forbid_external_effects():
            code = run_menu(navigator, assembly.actions, io.StringIO(text), stdout)
        output = stdout.getvalue()
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, output)
        self.assertTrue(all(line.isprintable() for line in output.splitlines()))
        return code, output, navigator

    def test_connections_open_as_list_with_search_and_card(self):
        code, output, navigator = self.flow("3\n1\nбалансировщик\n4\n0\n0\n2\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        path = "Главное меню KeenVPN / VPN-подключения / Подключения"
        self.assertIn(
            f"{path}\nПодключения по конфигурации Xray\nЧастей: 7; outbound: 3; балансировщиков: 1\n"
            "Повторов тегов outbound: 0; повторов тегов балансировщиков: 0; скрытых тегов: 0\n", output,
        )
        self.assertIn("  1. outbound: тег trojan-out, протокол trojan, часть 04_outbounds.json, индекс 0\n", output)
        self.assertIn(f"{path} / Результаты поиска\nНайдено: 1 из 4.\n  4. балансировщик: тег vpn-group", output)
        self.assertIn(
            f"{path} / Результаты поиска / Подключение 4\nВид: балансировщик\nПозиция: часть 05_routing.json, индекс 0\n"
            "Тег: vpn-group\nСелекторов: 1; совпадений outbound: 1\n  trojan-out\n"
            f"Fallback: blocked; позиция цели: часть 04_outbounds.json, индекс 2\nСтратегия: leastPing\n{CONNECTIONS_NOTE}\n",
            output,
        )
        self.assertIn(f"{path} / Подключение 2\nВид: outbound\nПозиция: часть 04_outbounds.json, индекс 1\nТег: direct\nПротокол: freedom\n", output)
        # Сценарий выполнен один раз: поиск, карточки и возвраты источники не читают; процесс и Keenetic не нужны.
        self.assertEqual(self.sources.proxy.calls[:3], (1, 1, 1))
        self.assertEqual((self.sources.process.calls, self.sources.keenetic.calls), (0, (0, 0, 0, 0)))
        self.assertEqual(self.store.read_calls, 0)

    def test_connections_search_never_matches_server_values(self):
        for value in ("host-0", "fixture-password", "/fixture/ws", "127.0.0.1", "serverName", "streamSettings", "trojan://"):
            with self.subTest(value=value):
                code, output, _ = self.flow(f"3\n1\n{value}\n0\n0\n0\n")
                self.assertEqual(code, 0)
                self.assertIn(NO_MATCHES, output)
                self.assertNotIn("Найдено:", output)

    def test_rules_show_names_and_ids_from_metadata_without_write(self):
        ids = assign_snapshot_ids(self.sources, self.store, names=((0, NAME_MARKER), (1, "Рабочий сервис напрямую")))
        code, output, navigator = self.flow("4\n1\nрабочий сервис\n2\n0\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        path = "Главное меню KeenVPN / Правила маршрутизации / Группы правил"
        self.assertIn(f"{METADATA_NOTES[MetadataState.PRESENT]}\nИдентичность: записей правил 40; привязано 40, с названием 2", output)
        self.assertIn(f", правил 1, с ID 1, с названием 1, названия: «{NAME_MARKER}»\n", output)
        self.assertIn(f"{path} / Результаты поиска\nНайдено: 1 из 8.\n  2. rules:", output)
        self.assertIn(
            f"{path} / Результаты поиска / Группа правил 2\nЧасть: 05_routing.json; индекс правила Xray: 1 (счёт с нуля)\n",
            output,
        )
        self.assertIn(
            "Назначение по позиции: часть 04_outbounds.json, индекс 1\nПравил модели: 3 (позиция в схеме, счёт с нуля)\n"
            f"  1: DomainCondition, действие DIRECT, только просмотр нет, ID {ids[1]}, название «Рабочий сервис напрямую», привязка bound\n"
            f"  2: DomainCondition, действие DIRECT, только просмотр нет, ID {ids[2]}, название не задано, привязка bound\n",
            output,
        )
        # Присвоение прочитало источники один раз, выбор пункта — ещё один; меню хранилище читает один раз и не пишет.
        self.assertEqual(self.sources.proxy.calls[:3], (2, 2, 2))
        self.assertEqual(self.store.read_calls, 2)
        self.assertEqual(len(self.store.write_calls), 1)

    def test_rules_without_store_and_with_failing_store_still_open_the_list(self):
        without_store = MenuSources(
            xray=self.sources.proxy.xray, xkeen_settings=self.sources.proxy.settings, xkeen_init=self.sources.proxy.init,
            xkeen_lists=self.sources.proxy.lists,
        )
        code, output, navigator = self.flow("4\n1\n2\n0\n0\n0\n0\n", without_store)
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn(f"{METADATA_NOTES[MetadataState.NOT_CONNECTED]}\n  1. rules:", output)
        self.assertIn(", только просмотр нет, правил 3\n", output)
        self.assertIn("Правил модели: 3; названия и идентификаторы недоступны\n", output)
        self.assertNotIn("привязка", output)
        self.store.read_failure = ManagerMetadataStoreError(MetadataStoreFailure.UNAVAILABLE)
        code, output, navigator = self.flow("4\n1\n1\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertIn(
            f"{METADATA_NOTES[MetadataState.FAILED]}\n  Отказ: source_failed / metadata_store_unavailable\n"
            "  Причина: Хранилище метаданных менеджера недоступно.\n"
            f"  Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}\n  1. rules:", output,
        )
        self.assertIn("Правил модели: 1; названия и идентификаторы недоступны\n", output)
        self.assertEqual(self.store.write_calls, ())

    def test_rules_without_metadata_mark_ids_as_unassigned(self):
        code, output, _ = self.flow("4\n1\n1\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertIn(f"{METADATA_NOTES[MetadataState.ABSENT]}\nИдентичность: раздел записей не записан; привязано 0", output)
        self.assertIn("  0: UnsupportedRuleCondition, действие DIRECT, только просмотр да, ID не присвоен, название не задано, привязка record_missing\n", output)
        self.assertEqual((self.store.read_calls, self.store.write_calls, self.store.content), (1, (), None))

    def test_unsafe_names_in_metadata_do_not_reach_the_terminal(self):
        # Название записи — пользовательский текст: до меню доходят только печатные названия в пределе длины.
        assign_snapshot_ids(self.sources, self.store)
        metadata = decode_manager_metadata(self.store.content).metadata
        records = list(metadata.rules)
        records[0] = RuleRecord(records[0].rule_id, "ok-name", records[0].key, records[0].extra)
        self.store.content = encode_manager_metadata(ManagerMetadata(metadata.storage, metadata.extra, rules=tuple(records)))
        code, output, _ = self.flow("4\n1\nok-name\n1\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertIn("Найдено: 1 из 8.", output)
        self.assertIn("название «ok-name», привязка bound", output)


DEVICE_NAME = "TEST_ONLY_DEVICE"
DEVICE_HOSTNAME = "private-host.example.test"
DEVICE_MAC_A, DEVICE_MAC_B, DEVICE_MAC_C = "02:00:00:00:00:a1", "02:00:00:00:00:b2", "02:00:00:00:00:c3"
DEVICE_INTERFACE_HOST = "privatehost.example.test"
DEVICE_PRIVATE_MARKERS = (
    DEVICE_HOSTNAME, "guest-host", "198.51.100", "2001:db8", "02:00:00", "fixture-private", "fixture-interface",
    "privatehost", "\x1b",
)
# На снимке имена регистраций совпадают с именами хостов, поэтому там маркер `device-` не проверяется.
SNAPSHOT_DEVICE_MARKERS = ("02:00:00:54", "192.0.2.", "2001:db8", "fixture-interface", "fixture-policy", "\x1b")


def synthetic_keenetic_sources():
    """Искусственные источники Keenetic: имена регистраций отличаются от имён хостов, адреса документальные."""
    return dict(
        policies=InMemoryKeeneticPolicySource(KeeneticPolicySet((KeeneticPolicy("Policy7", "fixture-private-vpn"),))),
        hotspot=InMemoryKeeneticHotspotSettingsSource(KeeneticHotspotSettings({
            "host": [
                {"mac": DEVICE_MAC_A, "policy": "Policy7"}, {"mac": DEVICE_MAC_B, "access": "deny", "deny": True},
                {"mac": DEVICE_MAC_C},
            ],
            "policy": [
                {"interface": "Bridge0", "policy": "Policy7"}, {"interface": "Bridge1", "access": "deny"},
                {"interface": "Bridge1", "policy": "Policy7"},
            ],
        })),
        registrations=InMemoryKeeneticRegistrationSource(KeeneticRegistrations({
            DEVICE_NAME: {"mac": DEVICE_MAC_A}, "Гость": {"mac": DEVICE_MAC_B}, " в пробелах ": {"mac": DEVICE_MAC_B.upper()},
        })),
        runtime=InMemoryKeeneticHotspotRuntimeSource(KeeneticHotspotRuntime({"host": [
            {"mac": DEVICE_MAC_A, "active": True, "hostname": DEVICE_HOSTNAME, "ip": "198.51.100.7",
             "ip6": ["2001:db8::7"], "interface": {"id": "Bridge0", "name": "fixture-interface"}},
            {"mac": DEVICE_MAC_B, "active": False, "hostname": "guest-host", "interface": {"id": "Bridge1"}},
            # Регрессия review 75-R01: наблюдение подставило имя хоста вместо ID интерфейса.
            {"mac": DEVICE_MAC_C, "active": True, "interface": {"id": DEVICE_INTERFACE_HOST}},
        ]})),
    )


class DevicesFlowTests(unittest.TestCase):
    """Пункт 5 → 1 на снимке и искусственных источниках: список, поиск по имени, карточка, отказ источника."""

    def setUp(self):
        self.sources, self.menu_sources = snapshot_menu_sources()

    def flow(self, text: str, menu_sources=None, markers=SNAPSHOT_DEVICE_MARKERS):
        assembly = assemble_main_menu(self.menu_sources if menu_sources is None else menu_sources)
        stdout = io.StringIO()
        navigator = MenuNavigator(assembly.menu)
        with forbid_external_effects():
            code = run_menu(navigator, assembly.actions, io.StringIO(text), stdout)
        output = stdout.getvalue()
        for marker in markers:
            self.assertNotIn(marker, output)
        self.assertTrue(all(line.isprintable() for line in output.splitlines()))
        return code, output, navigator

    def test_devices_open_as_list_with_search_and_card_on_snapshot(self):
        code, output, navigator = self.flow("5\n1\noffline\n6\n0\n0\n12\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        path = "Главное меню KeenVPN / Устройства и политики / Устройства"
        self.assertIn(
            f"{path}\nУстройства Keenetic по прочитанному состоянию\nПолитик: 3\n  Policy10, Policy20, Policy30\n"
            "Назначений сегментов: 2; без политики в списке: 0\n"
            "  Сегмент Bridge0: назначение explicit, политика Policy10, запрет доступа нет, только просмотр нет\n"
            "  Сегмент Bridge1: назначение unassigned, политика нет данных, запрет доступа да, только просмотр нет\n"
            "Записей устройств: всего 19; online 12, offline 7, online неизвестно 0; разных MAC 19, записей с повтором MAC 0\n",
            output,
        )
        self.assertIn(f"{DEVICES_NOTE}\n", output)
        self.assertIn("  1. device-01: явная политика Policy10, online, запрет доступа нет, интерфейс Bridge0\n", output)
        self.assertIn("  6. device-06: без назначения, offline, запрет доступа да, интерфейс не наблюдался\n", output)
        self.assertIn(f"{path} / Результаты поиска\nНайдено: 7 из 19.\n  3. device-03:", output)
        self.assertIn(
            f"{path} / Результаты поиска / Устройство 6\nПозиция записи: 5 (счёт с нуля в ip/hotspot)\nРегистраций: 1\n  device-06\n"
            "Назначение: unassigned — без назначения; в списке политик: нет данных\nOnline: offline; причина: нет\n"
            "Запрет доступа: да; только просмотр: нет; MAC повторяется: нет\nНаблюдаемый интерфейс: не наблюдался\n"
            f"Сегмент по интерфейсу: интерфейс не наблюдался\n{SEGMENT_MATCH_NOTE}\n{DEVICES_NOTE}\n", output,
        )
        self.assertIn(
            f"{path} / Устройство 12\nПозиция записи: 11 (счёт с нуля в ip/hotspot)\nРегистраций: 1\n  device-12\n"
            "Назначение: inherit — наследует политику сегмента; в списке политик: нет данных\nOnline: online; причина: нет\n"
            "Запрет доступа: нет; только просмотр: нет; MAC повторяется: нет\nНаблюдаемый интерфейс: Bridge0\n"
            "Сегмент по интерфейсу: назначение сегмента с этим интерфейсом\n"
            "  Сегмент Bridge0: назначение explicit, политика Policy10, запрет доступа нет, только просмотр нет\n", output,
        )
        # Сценарий выполнен один раз: поиск, карточки и возвраты источники не читают.
        self.assertEqual(self.sources.keenetic.calls, (1, 1, 1, 1))

    def test_devices_search_matches_registration_name_and_never_hosts_or_addresses(self):
        menu_sources = MenuSources(**synthetic_keenetic_sources())
        code, output, navigator = self.flow("5\n1\ntest_only\n1\n0\n0\n2\n0\n0\n0\n0\n", menu_sources, DEVICE_PRIVATE_MARKERS)
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        path = "Главное меню KeenVPN / Устройства и политики / Устройства"
        self.assertIn(f"  1. {DEVICE_NAME}: явная политика Policy7, online, запрет доступа нет, интерфейс Bridge0\n", output)
        self.assertIn("  2. регистраций 2: без назначения, offline, запрет доступа да, интерфейс Bridge1\n", output)
        self.assertIn("  3. без регистрации: без назначения, online, запрет доступа нет, интерфейс <скрыто>\n", output)
        self.assertIn(f"{path} / Результаты поиска\nНайдено: 1 из 3.\n  1. {DEVICE_NAME}:", output)
        self.assertIn(f"{path} / Результаты поиска / Устройство 1\nПозиция записи: 0 (счёт с нуля в ip/hotspot)\nРегистраций: 1\n  {DEVICE_NAME}\n", output)
        self.assertIn(
            f"{path} / Устройство 2\nПозиция записи: 1 (счёт с нуля в ip/hotspot)\nРегистраций: 2\n  Гость\n  <скрыто>\n",
            output,
        )
        self.assertIn("Сегмент по интерфейсу: несколько назначений сегментов с этим интерфейсом\n", output)
        self.assertIn("Назначений сегментов: 3; без политики в списке: 0\n", output)
        code, output, _ = self.flow("5\n1\n3\n0\n0\n0\n0\n", menu_sources, DEVICE_PRIVATE_MARKERS)
        self.assertEqual(code, 0)
        self.assertIn("Наблюдаемый интерфейс: <скрыто>\nСегмент по интерфейсу: назначения сегмента с этим интерфейсом нет\n", output)
        for value in (
            DEVICE_HOSTNAME, "198.51.100.7", DEVICE_MAC_A, "guest-host", "fixture-private-vpn", "в пробелах",
            DEVICE_INTERFACE_HOST, "privatehost",
        ):
            with self.subTest(value=value):
                code, output, _ = self.flow(f"5\n1\n{value}\n0\n0\n0\n", menu_sources, DEVICE_PRIVATE_MARKERS)
                self.assertEqual(code, 0)
                self.assertIn(NO_MATCHES, output)
                self.assertNotIn("Найдено:", output)

    def test_many_long_policy_ids_keep_the_devices_menu_running(self):
        # Регрессия review 75-R02: 31 допустимый ID по 64 символа завершал меню кодом 1 при открытии 5 → 1.
        sources = synthetic_keenetic_sources()
        long_ids = [f"Policy{number:02d}" + "x" * 56 for number in range(31)]
        sources["policies"].outcome = KeeneticPolicySet((
            KeeneticPolicy("Policy7", "fixture-private-vpn"), *(KeeneticPolicy(policy_id) for policy_id in long_ids),
        ))
        code, output, navigator = self.flow("5\n1\n1\n0\n0\n0\n0\n", MenuSources(**sources), DEVICE_PRIVATE_MARKERS)
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn("Политик: 32\n  Policy7, " + ", ".join(long_ids[:9]) + "\n  " + ", ".join(long_ids[9:19]) + "\n", output)
        self.assertIn("\n  " + ", ".join(long_ids[29:31]) + "\nНазначений сегментов: 3", output)
        self.assertIn("Устройство 1\nПозиция записи: 0", output)
        self.assertTrue(all(len(line) <= MAX_LIST_LINE_LENGTH for line in output.splitlines()))
        self.assertNotIn("Внутренняя ошибка", output)

    def test_devices_failure_shows_error_with_next_step_instead_of_list(self):
        self.sources.keenetic.runtime.outcome = OSError(f"Отказ: {DEVICE_HOSTNAME} 192.0.2.20 02:00:00:54:00:01")
        code, output, navigator = self.flow("5\n1\n0\n0\n", markers=SNAPSHOT_DEVICE_MARKERS + (DEVICE_HOSTNAME,))
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn(
            "Отказ: source_failed / keenetic_runtime_unavailable\n"
            "Причина: Не удалось прочитать наблюдаемое состояние клиентов Keenetic.\n"
            f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}\n\nГлавное меню KeenVPN / Устройства и политики\n",
            output,
        )
        self.assertNotIn("Устройства Keenetic", output)
        self.assertNotIn("Номер — карточка", output)
        self.assertEqual(self.sources.keenetic.calls, (1, 1, 1, 1))


if __name__ == "__main__":
    unittest.main()
