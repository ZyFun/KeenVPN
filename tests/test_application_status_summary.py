"""Сводка состояния по областям на снимке и управляемых источниках прокси и процесса."""

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.checks import (
    VPN_REACHABLE_CHECK, XRAY_PROCESS_CHECK, CheckReason, CheckView, ChecksView, vpn_reachability_not_checked,
)
from keenvpn.application.contract import (
    CONTRACT_VERSION, NEXT_STEP_MESSAGES, CheckStatus, ErrorCategory, ErrorDetail, NextStepCode, OperationStatus,
)
from keenvpn.application.proxy_config import InspectProxyConfigHandler, Port53View, XKeenFlagView
from keenvpn.application.status_summary import (
    AREA_LABELS, AREA_STATES, AUTOSTART_CHECK, DRAFT_CHECK, FALLBACK_CHECK, INTERCEPTION_CHECK, PORT_53_HINT,
    PORT_53_PATH_CHECK, STATE_LABELS, AreaState, FallbackView, InspectStatusSummary, InspectStatusSummaryHandler,
    StatusSummaryView, SummaryArea, SummaryAreaView, SummaryReason,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation
from tests.support.in_memory import AdapterSetupError, UnconfiguredResponseError
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_MARKERS, reachable, unsafe_xkeen_settings, unsafe_xray_config
from tests.support.snapshot import SYNTHETIC_XRAY_PID, snapshot_installation_sources


CHECK_SOURCE_STEP = {"code": "check_source", "message": NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}
INSPECT_STEP = {"code": "inspect_source_data", "message": NEXT_STEP_MESSAGES[NextStepCode.INSPECT_SOURCE_DATA]}
EXPECTED_AREAS = [
    {"area": "core", "state": "running", "source_error": None,
     "check": {"code": "xray_process_consistent", "status": "passed", "network": False, "reason": None}},
    {"area": "interception", "state": None, "source_error": None,
     "check": {"code": "interception_active", "status": "unsupported", "network": False,
               "reason": "interception_not_observed"}},
    {"area": "vpn", "state": None, "source_error": None,
     "check": {"code": "vpn_reachable", "status": "not_checked", "network": True,
               "reason": "network_check_not_performed"}},
    {"area": "dns", "state": "excluded", "source_error": None,
     "check": {"code": "dns_port_53_path", "status": "not_checked", "network": True,
               "reason": "network_check_not_performed"}},
    {"area": "autostart", "state": "on", "source_error": None,
     "check": {"code": "autostart_flag_unambiguous", "status": "passed", "network": False, "reason": None}},
    {"area": "fallback", "state": "no_direct_fallback", "source_error": None,
     "check": {"code": "fallback_profile_consistent", "status": "passed", "network": False, "reason": None}},
    {"area": "draft", "state": None, "source_error": None,
     "check": {"code": "draft_present", "status": "unsupported", "network": False, "reason": "drafts_not_implemented"}},
]
EXPECTED_PORT_53 = {
    "port": 53, "port_exclude_entry": True, "port_exclude_range": False, "port_proxying_entry": False,
    "port_proxying_range": False, "proxy_dns": {"status": "present", "value": "off"},
    "proxy_router": {"status": "present", "value": "off"},
}
EXPECTED_FALLBACK = {
    "killswitch": {"status": "present", "value": "on"}, "balancer_count": 1, "direct_count": 0, "blocked_count": 1,
    "vpn_count": 0, "unresolved_count": 0, "unset_count": 0,
}
SOURCES = ("xray", "settings", "init", "port_exclude", "port_proxying", "process")
LIST_NAMES = {"port_exclude": XKeenListName.PORT_EXCLUDE, "port_proxying": XKeenListName.PORT_PROXYING}
AFFECTED = {
    "xray": ("fallback",), "settings": ("fallback",), "init": ("dns", "autostart"), "port_exclude": ("dns",),
    "port_proxying": ("dns",), "process": ("core",),
}
UNAVAILABLE = {
    "xray": ("xray_config_unavailable", "Не удалось прочитать части конфигурации Xray."),
    "settings": ("xkeen_settings_unavailable", "Не удалось прочитать настройки XKeen."),
    "init": ("xkeen_init_unavailable", "Не удалось прочитать параметры init XKeen."),
    "port_exclude": ("xkeen_port_exclude_unavailable", "Не удалось прочитать список исключённых портов XKeen."),
    "port_proxying": (
        "xkeen_port_proxying_unavailable", "Не удалось прочитать список перехватываемых портов XKeen.",
    ),
    "process": ("xray_process_unavailable", "Не удалось наблюдать процесс Xray и маркер готовности."),
}
INVALID_CODES = {
    "xray": "invalid_xray_config", "settings": "invalid_xkeen_settings", "init": "invalid_xkeen_init",
    "port_exclude": "invalid_xkeen_port_exclude", "port_proxying": "invalid_xkeen_port_proxying",
    "process": "invalid_xray_process",
}
PRIVATE_MARKERS = (
    str(SYNTHETIC_XRAY_PID), "trojan-out", "vpn-group", "fixture-password", "/fixture/ws", "probe.example", ".json",
    ".lst", "Обезличенный", "geoip:", "geosite:", "/opt/", "192.0.2.", "2001:db8",
)
OUTBOUNDS = [
    {"tag": "proxy-a", "protocol": "trojan"},
    {"tag": "direct-out", "protocol": "freedom"},
    {"tag": "block-out", "protocol": "blackhole"},
]


def handler_for(sources, *, proxy=True, process=True, **options):
    """Сценарий над источниками снимка; `proxy` и `process` выключают подключение источников."""
    proxy_handler = None
    if proxy:
        ports = sources.proxy
        proxy_handler = InspectProxyConfigHandler(ports.xray, ports.settings, ports.init, ports.lists)
    return InspectStatusSummaryHandler(proxy_handler, sources.process if process else None, **options)


def configure(sources, name, outcome):
    """Задать ответ или отказ источника по имени."""
    if name == "process":
        sources.process.outcome = outcome
    elif name in LIST_NAMES:
        sources.proxy.lists.set_response(LIST_NAMES[name], outcome)
    else:
        getattr(sources.proxy, name).outcome = outcome


def areas(result) -> dict[str, SummaryAreaView]:
    return {item.area.value: item for item in result.data.areas}


def outcome(result, name) -> tuple[str | None, str, str | None]:
    """Состояние, статус и причина области кодами."""
    item = areas(result)[name]
    return (None if item.state is None else item.state.value, item.check.status.value, item.check.reason)


def fallback_config(*balancers, outbounds=OUTBOUNDS):
    document = {"outbounds": outbounds, "routing": {"balancers": list(balancers)}}
    return XrayConfigSet((ConfigDocument("04_test.json", json.dumps(document).encode("utf-8")),))


def balancer(fallback=None, tag="group-a"):
    item = {"tag": tag, "selector": ["proxy-"], "strategy": {"type": "leastPing"}}
    if fallback is not None:
        item["fallbackTag"] = fallback
    return item


def killswitch_settings(value):
    """`xkeen.json` с заданным значением kill-switch; `...` — без поля."""
    section = {} if value is ... else {"killswitch": value}
    return XKeenSettings(ConfigDocument("xkeen.json", json.dumps({"xkeen": section}).encode("utf-8")))


class StatusSummaryScenarioTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_installation_sources()
        self.handler = handler_for(self.sources, operation_ids=lambda: "op-1")

    def execute(self, command=None):
        return self.handler.execute(InspectStatusSummary() if command is None else command)

    def assert_reads(self, xray=1, settings=1, init=1, lists=(XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING),
                     process=1):
        self.assertEqual(self.sources.proxy.calls, (xray, settings, init, lists))
        self.assertEqual(self.sources.process.calls, process)
        # Ни одна область не зависит от Keenetic и геобаз: их источники сводка не вызывает.
        self.assertEqual(self.sources.keenetic.calls, (0, 0, 0, 0))
        self.assertEqual(self.sources.geodata.calls, 0)

    def test_snapshot_summary_shows_seven_areas_separately(self):
        result = self.execute()
        self.assertTrue(result.succeeded)
        self.assertEqual(result.command, "inspect_status_summary")
        self.assertEqual(InspectStatusSummary.name, "inspect_status_summary")
        self.assertIsInstance(result.data, StatusSummaryView)
        self.assertEqual(result.to_dict()["data"], {
            "active_network_check": False, "areas": EXPECTED_AREAS, "port_53": EXPECTED_PORT_53,
            "fallback": EXPECTED_FALLBACK,
        })
        self.assertEqual([item.area for item in result.data.areas], list(SummaryArea))
        self.assertIs(result.data.checks.active_network_check, False)
        self.assertEqual(result.data.checks.items, tuple(item.check for item in result.data.areas))
        self.assertEqual(json.loads(json.dumps(result.to_dict(), ensure_ascii=False)), result.to_dict())
        self.assert_reads()

    def test_sources_are_read_once_in_fixed_order(self):
        journal = []
        ports = self.sources.proxy

        def record(name, method):
            def call(*args):
                journal.append(name if not args else f"{name}:{args[0].value}")
                return method(*args)
            return call

        ports.xray.current_xray_config = record("xray", ports.xray.current_xray_config)
        ports.settings.current_xkeen_settings = record("settings", ports.settings.current_xkeen_settings)
        ports.init.current_xkeen_init = record("init", ports.init.current_xkeen_init)
        ports.lists.current_xkeen_list = record("list", ports.lists.current_xkeen_list)
        self.sources.process.current_xray_process = record("process", self.sources.process.current_xray_process)
        self.assertTrue(self.execute().succeeded)
        self.assertEqual(journal, [
            "xray", "settings", "init", "list:port_exclude.lst", "list:port_proxying.lst", "process",
        ])

    def test_wrong_command_and_version_do_not_read_sources(self):
        for command, code in (
            (object(), "invalid_command"),
            (InspectStatusSummary(contract_version=CONTRACT_VERSION + 1), "unsupported_contract_version"),
            (InspectStatusSummary(contract_version=True), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                result = self.execute(command)
                self.assertIs(result.status, OperationStatus.FAILED)
                self.assertIs(result.error.category, ErrorCategory.INVALID_REQUEST)
                self.assertEqual(result.error.code, code)
        self.assert_reads(0, 0, 0, (), 0)

    def test_each_source_failure_marks_only_its_areas_not_checked(self):
        baseline = {item["area"]: item for item in EXPECTED_AREAS}
        for name in SOURCES:
            with self.subTest(source=name):
                sources = snapshot_installation_sources()
                configure(sources, name, OSError("/opt/etc/xray/configs/fixture-password probe.example 192.0.2.1"))
                result = handler_for(sources).execute(InspectStatusSummary())
                self.assertTrue(result.succeeded)
                code, message = UNAVAILABLE[name]
                payload = result.to_dict()["data"]
                for item in payload["areas"]:
                    if item["area"] in AFFECTED[name]:
                        self.assertIsNone(item["state"])
                        self.assertEqual(item["check"]["status"], "not_checked")
                        self.assertEqual(item["check"]["reason"], code)
                        self.assertEqual(item["source_error"], {
                            "category": "source_failed", "code": code, "reason": None, "message": message,
                            "next_step": CHECK_SOURCE_STEP,
                        })
                    else:
                        self.assertEqual(item, baseline[item["area"]])
                self.assertEqual(payload["port_53"] is None, "dns" in AFFECTED[name])
                self.assertEqual(payload["fallback"] is None, "fallback" in AFFECTED[name])
                # Отказ одного источника не прерывает чтение остальных: каждый вызван ровно один раз.
                self.assertEqual(sources.proxy.calls, (1, 1, 1, (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING)))
                self.assertEqual(sources.process.calls, 1)
                text = repr(result) + json.dumps(payload, ensure_ascii=False)
                for marker in ("fixture-password", "probe.example", "192.0.2.1", "/opt/"):
                    self.assertNotIn(marker, text)

    def test_first_failure_in_reading_order_explains_a_shared_area(self):
        configure(self.sources, "port_proxying", OSError("TEST_ONLY_SECRET"))
        configure(self.sources, "init", OSError("TEST_ONLY_SECRET"))
        result = self.execute()
        self.assertEqual(outcome(result, "dns"), (None, "not_checked", "xkeen_init_unavailable"))
        self.assertEqual(outcome(result, "autostart"), (None, "not_checked", "xkeen_init_unavailable"))
        self.assertEqual(areas(result)["dns"].source_error.code, "xkeen_init_unavailable")
        configure(self.sources, "init", parse_xkeen_init(b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\n'))
        configure(self.sources, "xray", object())
        configure(self.sources, "settings", OSError("TEST_ONLY_SECRET"))
        result = self.execute()
        self.assertEqual(outcome(result, "dns"), (None, "not_checked", "xkeen_port_proxying_unavailable"))
        self.assertEqual(outcome(result, "autostart"), ("on", "passed", None))
        self.assertEqual(outcome(result, "fallback"), (None, "not_checked", "invalid_xray_config"))

    def test_invalid_source_data_keeps_area_codes_and_domain_reasons(self):
        for name in SOURCES:
            with self.subTest(source=name, case="foreign type"):
                sources = snapshot_installation_sources()
                configure(sources, name, object())
                result = handler_for(sources).execute(InspectStatusSummary())
                for area in AFFECTED[name]:
                    item = areas(result)[area]
                    self.assertEqual(outcome(result, area), (None, "not_checked", INVALID_CODES[name]))
                    self.assertIs(item.source_error.category, ErrorCategory.INVALID_SOURCE_DATA)
                    self.assertIsNone(item.source_error.reason)
                    self.assertEqual(item.source_error.to_dict()["next_step"], INSPECT_STEP)
        corrupted = XrayProcessObservation((SYNTHETIC_XRAY_PID,), True)
        object.__setattr__(corrupted, "pids", (0,))
        configure(self.sources, "process", corrupted)
        configure(self.sources, "port_exclude", XKeenList(XKeenListName.PORT_PROXYING, b"53\n"))
        result = self.execute()
        self.assertEqual(outcome(result, "core"), (None, "not_checked", "invalid_xray_process"))
        self.assertEqual(areas(result)["core"].source_error.reason, "invalid_xray_process_observation")
        self.assertEqual(outcome(result, "dns"), (None, "not_checked", "invalid_xkeen_port_exclude"))
        self.assertEqual(areas(result)["dns"].source_error.reason, "xkeen_list_name_mismatch")
        self.assertEqual(outcome(result, "autostart"), ("on", "passed", None))

    def test_unconnected_sources_are_not_checked_without_reads(self):
        constant = {"interception", "vpn", "draft"}
        for proxy, process in ((False, False), (False, True), (True, False)):
            with self.subTest(proxy=proxy, process=process):
                sources = snapshot_installation_sources()
                result = handler_for(sources, proxy=proxy, process=process).execute(InspectStatusSummary())
                self.assertTrue(result.succeeded)
                missing = ({"dns", "autostart", "fallback"} if not proxy else set()) | ({"core"} if not process else set())
                for item in result.data.areas:
                    expected = next(area for area in EXPECTED_AREAS if area["area"] == item.area.value)
                    if item.area.value in missing:
                        self.assertEqual(outcome(result, item.area.value), (None, "not_checked", "source_not_connected"))
                        self.assertIsNone(item.source_error)
                        self.assertEqual(item.check.code, expected["check"]["code"])
                        self.assertEqual(item.check.network, expected["check"]["network"])
                    else:
                        self.assertEqual(item.to_dict(), expected)
                self.assertTrue(constant.isdisjoint(missing))
                self.assertEqual(result.data.port_53 is None, not proxy)
                self.assertEqual(result.data.fallback is None, not proxy)
                self.assertEqual(sources.proxy.calls[:3], (1, 1, 1) if proxy else (0, 0, 0))
                self.assertEqual(sources.process.calls, 1 if process else 0)

    def test_interruptions_are_not_converted_to_not_checked(self):
        for name in ("xray", "port_exclude", "process"):
            for interruption in (KeyboardInterrupt, SystemExit):
                with self.subTest(source=name, interruption=interruption.__name__):
                    sources = snapshot_installation_sources()
                    configure(sources, name, interruption())
                    with self.assertRaises(interruption):
                        handler_for(sources).execute(InspectStatusSummary())

    def test_unconfigured_source_is_a_test_setup_error(self):
        sources = snapshot_installation_sources()
        sources.process.outcome = UnconfiguredResponseError
        with self.assertRaises(AdapterSetupError):
            handler_for(sources).execute(InspectStatusSummary())

    def test_scenario_has_no_terminal_or_external_effects(self):
        failing = snapshot_installation_sources()
        configure(failing, "xray", OSError("TEST_ONLY_SECRET"))
        failing_handler = handler_for(failing)
        with forbid_external_effects():
            result = self.execute()
            failed_area = failing_handler.execute(InspectStatusSummary())
        self.assertTrue(result.succeeded)
        self.assertEqual(outcome(failed_area, "fallback"), (None, "not_checked", "xray_config_unavailable"))

    def test_rendering_is_frozen_and_does_not_reread_sources(self):
        result = self.execute()
        first = result.to_dict()
        self.assertEqual(result.to_dict(), first)
        self.assert_reads()
        with self.assertRaises(FrozenInstanceError):
            result.data.areas = ()
        with self.assertRaises(FrozenInstanceError):
            result.data.areas[0].state = AreaState.STOPPED
        with self.assertRaises(FrozenInstanceError):
            result.data.fallback.balancer_count = 0


class AreaOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_installation_sources()
        # Фиксированный идентификатор: проверки ищут синтетический PID во всём результате, случайный UUID мог бы его содержать.
        self.handler = handler_for(self.sources, operation_ids=lambda: "op-1")

    def run_case(self, name, value):
        configure(self.sources, name, value)
        result = self.handler.execute(InspectStatusSummary())
        self.assertTrue(result.succeeded)
        return result

    def test_core_follows_process_and_marker_states(self):
        for pids, marker, expected in (
            ((SYNTHETIC_XRAY_PID,), True, ("running", "passed", None)),
            ((), False, ("stopped", "passed", None)),
            ((SYNTHETIC_XRAY_PID,), False, ("process_without_marker", "failed", "process_without_marker")),
            ((), True, ("marker_without_process", "failed", "marker_without_process")),
            ((SYNTHETIC_XRAY_PID, 4243), True, ("multiple_processes", "failed", "multiple_processes")),
        ):
            with self.subTest(pids=pids, marker=marker):
                result = self.run_case("process", XrayProcessObservation(pids, marker))
                self.assertEqual(outcome(result, "core"), expected)
                self.assertEqual(areas(result)["core"].check.code, XRAY_PROCESS_CHECK)
                self.assertNotIn(str(SYNTHETIC_XRAY_PID), json.dumps(result.to_dict()))

    def test_dns_shows_selected_exclusion_separately_from_unchecked_path(self):
        for exclude, proxying, state, facts in (
            (b"53\n", b"", "excluded", (True, False, False, False)),
            (b"# comment\n50:60\n", b"", "excluded_by_range", (False, True, False, False)),
            (b"53,80\n1-100\n", b"", "excluded", (True, True, False, False)),
            (b"", b"", "not_excluded", (False, False, False, False)),
            (b"5353\n", b"53\n40-60\n", "not_excluded", (False, False, True, True)),
            (b"53\n", b"53\n", "excluded", (True, False, True, False)),
        ):
            with self.subTest(exclude=exclude, proxying=proxying):
                configure(self.sources, "port_exclude", XKeenList(XKeenListName.PORT_EXCLUDE, exclude))
                result = self.run_case("port_proxying", XKeenList(XKeenListName.PORT_PROXYING, proxying))
                # Выбор исключения — факт файла; путь DNS не проверяется, поэтому статус всегда «не проверено».
                self.assertEqual(outcome(result, "dns"), (state, "not_checked", "network_check_not_performed"))
                self.assertIs(areas(result)["dns"].check.network, True)
                port_53 = result.data.port_53
                self.assertEqual(
                    (port_53.port_exclude_entry, port_53.port_exclude_range, port_53.port_proxying_entry,
                     port_53.port_proxying_range),
                    facts,
                )
        result = self.run_case("init", parse_xkeen_init(b'start_auto="on"\nproxy_dns="on"\nproxy_dns="off"\n'))
        self.assertEqual(result.to_dict()["data"]["port_53"]["proxy_dns"], {"status": "duplicate", "value": None})
        self.assertEqual(result.to_dict()["data"]["port_53"]["proxy_router"], {"status": "missing", "value": None})
        self.assertEqual(outcome(result, "dns")[1:], ("not_checked", "network_check_not_performed"))

    def test_autostart_reaches_every_status(self):
        for content, expected in (
            (b'start_auto="on"\n', ("on", "passed", None)),
            (b'start_auto="off"\n', ("off", "passed", None)),
            (b'proxy_dns="off"\n', (None, "failed", "flag_missing")),
            (b'start_auto="on"\nstart_auto="off"\n', (None, "failed", "flag_duplicate")),
            (b'start_auto="on"\n  start_auto="off"\n', (None, "failed", "flag_duplicate")),
            (b'start_auto="yes"\n', (None, "failed", "flag_unexpected")),
            (b'  start_auto="on"\n', (None, "unsupported", "flag_unsupported")),
            (b"start_auto=$TEST_ONLY_AUTO\n", (None, "unsupported", "flag_unsupported")),
        ):
            with self.subTest(content=content):
                result = self.run_case("init", parse_xkeen_init(content))
                self.assertEqual(outcome(result, "autostart"), expected)
                self.assertEqual(areas(result)["autostart"].check.code, AUTOSTART_CHECK)
                self.assertNotIn("TEST_ONLY_AUTO", repr(result) + json.dumps(result.to_dict()))

    def test_fallback_profile_matrix(self):
        cases = (
            ("on", [balancer("block-out")], ("no_direct_fallback", "passed", None), (0, 1, 0, 0, 0)),
            ("off", [balancer("direct-out")], ("direct_fallback", "passed", None), (1, 0, 0, 0, 0)),
            ("on", [balancer("block-out"), balancer("block-out", "group-b")],
             ("no_direct_fallback", "passed", None), (0, 2, 0, 0, 0)),
            ("on", [balancer("direct-out")], (None, "failed", "fallback_profile_mismatch"), (1, 0, 0, 0, 0)),
            ("off", [balancer("block-out")], (None, "failed", "fallback_profile_mismatch"), (0, 1, 0, 0, 0)),
            ("on", [balancer("block-out"), balancer("direct-out", "group-b")],
             (None, "failed", "fallback_profile_mismatch"), (1, 1, 0, 0, 0)),
            # Противоречие важнее неопределённости: прямой резерв при включённом kill-switch — ошибка.
            ("on", [balancer(), balancer("direct-out", "group-b")],
             (None, "failed", "fallback_profile_mismatch"), (1, 0, 0, 0, 1)),
            ("on", [], (None, "unsupported", "no_balancers"), (0, 0, 0, 0, 0)),
            ("on", [balancer("block-out"), balancer(tag="group-b")],
             (None, "unsupported", "fallback_not_set"), (0, 1, 0, 0, 1)),
            ("on", [balancer("TEST_absent")], (None, "unsupported", "fallback_not_resolved"), (0, 0, 0, 1, 0)),
            ("off", [balancer("proxy-a")], (None, "unsupported", "fallback_to_vpn"), (0, 0, 1, 0, 0)),
        )
        for value, balancers, expected, counts in cases:
            with self.subTest(killswitch=value, balancers=balancers):
                configure(self.sources, "settings", killswitch_settings(value))
                result = self.run_case("xray", fallback_config(*balancers))
                self.assertEqual(outcome(result, "fallback"), expected)
                facts = result.data.fallback
                self.assertEqual(facts.balancer_count, len(balancers))
                self.assertEqual(
                    (facts.direct_count, facts.blocked_count, facts.vpn_count, facts.unresolved_count,
                     facts.unset_count),
                    counts,
                )
                self.assertEqual(facts.killswitch.status, "present")
                self.assertEqual(facts.killswitch.value, value)
                self.assertNotIn("TEST_absent", repr(result) + json.dumps(result.to_dict()))

    def test_fallback_needs_a_known_killswitch_and_resolvable_targets(self):
        for value, status in ((..., "missing"), ("yes", "unexpected"), (True, "unsupported")):
            with self.subTest(killswitch=value):
                configure(self.sources, "settings", killswitch_settings(value))
                result = self.run_case("xray", fallback_config(balancer("block-out")))
                self.assertEqual(outcome(result, "fallback"), (None, "unsupported", "killswitch_unknown"))
                self.assertEqual(result.data.fallback.killswitch.status, status)
                self.assertIsNone(result.data.fallback.killswitch.value)
        configure(self.sources, "settings", killswitch_settings("on"))
        duplicated = [*OUTBOUNDS, {"tag": "block-out", "protocol": "blackhole"}]
        unknown = [*OUTBOUNDS, {"tag": "odd-out", "protocol": "TEST_proto"}]
        # Прямой outbound с цепочкой передаёт соединение дальше: прямым выходом он не считается.
        chained = [*OUTBOUNDS, {"tag": "chain-out", "protocol": "freedom",
                                "streamSettings": {"sockopt": {"dialerProxy": "proxy-a"}}}]
        for outbounds, fallback in ((duplicated, "block-out"), (unknown, "odd-out"), (chained, "chain-out")):
            with self.subTest(fallback=fallback):
                result = self.run_case("xray", fallback_config(balancer(fallback), outbounds=outbounds))
                self.assertEqual(outcome(result, "fallback"), (None, "unsupported", "fallback_not_resolved"))
                self.assertEqual(result.data.fallback.unresolved_count, 1)
        document = {"outbounds": OUTBOUNDS, "routing": {"balancers": {"tag": "group-a"}}}
        result = self.run_case("xray", XrayConfigSet((ConfigDocument("04_test.json", json.dumps(document).encode()),)))
        self.assertEqual(outcome(result, "fallback"), (None, "unsupported", "balancers_unsupported"))
        self.assertEqual(result.to_dict()["data"]["fallback"], {
            "killswitch": {"status": "present", "value": "on"}, "balancer_count": None, "direct_count": None,
            "blocked_count": None, "vpn_count": None, "unresolved_count": None, "unset_count": None,
        })
        # Протокол сравнивается без учёта регистра, псевдонимы `direct` и `block` — те же выходы.
        for protocol, value, state in (
            ("BlackHole", "on", "no_direct_fallback"), ("block", "on", "no_direct_fallback"),
            ("Freedom", "off", "direct_fallback"), ("direct", "off", "direct_fallback"),
        ):
            with self.subTest(protocol=protocol):
                configure(self.sources, "settings", killswitch_settings(value))
                outbounds = [{"tag": "proxy-a", "protocol": "trojan"}, {"tag": "exit-out", "protocol": protocol}]
                result = self.run_case("xray", fallback_config(balancer("exit-out"), outbounds=outbounds))
                self.assertEqual(outcome(result, "fallback"), (state, "passed", None))

    def test_unsupported_balancer_structure_is_never_a_confirmed_profile(self):
        # Регрессия review 73-R01: неподдержанный балансировщик не подтверждает профиль резерва.
        configure(self.sources, "settings", killswitch_settings("on"))
        for item in (
            {"tag": "group-a", "selector": 7, "fallbackTag": "block-out"},
            {"tag": "group-a", "selector": ["proxy-"], "strategy": 7, "fallbackTag": "block-out"},
            {"tag": 7, "selector": ["proxy-"], "fallbackTag": "block-out"},
            {"selector": ["proxy-"], "fallbackTag": "block-out"},
        ):
            with self.subTest(balancer=item):
                result = self.run_case("xray", fallback_config(item))
                self.assertEqual(outcome(result, "fallback"), (None, "unsupported", "fallback_not_resolved"))
                self.assertEqual(result.data.fallback.unresolved_count, 1)

    def test_every_status_of_every_area_is_reachable_and_nothing_else(self):
        expected = {
            "core": {"passed", "failed", "not_checked"}, "interception": {"unsupported"}, "vpn": {"not_checked"},
            "dns": {"not_checked"}, "autostart": {"passed", "failed", "unsupported", "not_checked"},
            "fallback": {"passed", "failed", "unsupported", "not_checked"}, "draft": {"unsupported"},
        }
        seen = {area: set() for area in expected}

        def collect(result):
            for item in result.data.areas:
                seen[item.area.value].add(item.check.status.value)

        collect(self.handler.execute(InspectStatusSummary()))
        collect(handler_for(snapshot_installation_sources(), proxy=False, process=False).execute(InspectStatusSummary()))
        collect(self.run_case("process", XrayProcessObservation((), True)))
        collect(self.run_case("init", parse_xkeen_init(b'start_auto="yes"\n')))
        collect(self.run_case("init", parse_xkeen_init(b'  start_auto="on"\n')))
        configure(self.sources, "settings", killswitch_settings("off"))
        collect(self.run_case("xray", fallback_config(balancer("block-out"))))
        collect(self.run_case("xray", fallback_config()))
        self.assertEqual(seen, expected)


class SummaryViewModelTests(unittest.TestCase):
    def setUp(self):
        self.view = handler_for(snapshot_installation_sources()).execute(InspectStatusSummary()).data

    def test_passive_summary_cannot_claim_a_network_check_outcome(self):
        vpn_failed = SummaryAreaView(
            SummaryArea.VPN, None, CheckView(VPN_REACHABLE_CHECK, CheckStatus.FAILED, True, None),
        )
        for index, item in (
            (2, vpn_failed),
            (3, SummaryAreaView(
                SummaryArea.DNS, AreaState.EXCLUDED, CheckView(PORT_53_PATH_CHECK, CheckStatus.PASSED, True, None),
            )),
            (3, SummaryAreaView(
                SummaryArea.DNS, AreaState.EXCLUDED, CheckView(PORT_53_PATH_CHECK, CheckStatus.FAILED, True, None),
            )),
        ):
            with self.subTest(area=item.area.value, status=item.check.status.value):
                changed = list(self.view.areas)
                changed[index] = item
                with self.assertRaises(TypeError):
                    StatusSummaryView(False, tuple(changed), self.view.port_53, self.view.fallback)
        # «Успешно» без установленного состояния отклоняет уже модель области.
        with self.assertRaises(TypeError):
            SummaryAreaView(SummaryArea.VPN, None, CheckView(VPN_REACHABLE_CHECK, CheckStatus.PASSED, True, None))
        # С признаком активной проверки тот же набор допустим: признак задаёт сценарий, а не интерфейс.
        changed = list(self.view.areas)
        changed[2] = vpn_failed
        active = StatusSummaryView(True, tuple(changed), self.view.port_53, self.view.fallback)
        self.assertIs(active.checks.active_network_check, True)
        for flag in (0, None, "false"):
            with self.subTest(flag=flag), self.assertRaises(TypeError):
                StatusSummaryView(flag, self.view.areas, self.view.port_53, self.view.fallback)

    def test_area_view_requires_exact_types_and_area_rules(self):
        core = self.view.areas[0]
        passed = core.check
        not_checked = CheckView(XRAY_PROCESS_CHECK, CheckStatus.NOT_CHECKED, False, "source_not_connected")
        error = ErrorDetail(ErrorCategory.SOURCE_FAILED, "xray_process_unavailable", "Текст.")
        unavailable = CheckView(XRAY_PROCESS_CHECK, CheckStatus.NOT_CHECKED, False, "xray_process_unavailable")
        self.assertEqual(SummaryAreaView(SummaryArea.CORE, None, unavailable, error).source_error, error)
        for area, state, check, source_error in (
            ("core", AreaState.RUNNING, passed, None),
            (SummaryArea.CORE, "running", passed, None),
            (SummaryArea.CORE, AreaState.ON, passed, None),
            (SummaryArea.CORE, None, passed, None),
            (SummaryArea.CORE, AreaState.RUNNING, {"code": XRAY_PROCESS_CHECK}, None),
            (SummaryArea.DNS, AreaState.EXCLUDED, passed, None),
            (SummaryArea.CORE, AreaState.RUNNING, CheckView(XRAY_PROCESS_CHECK, CheckStatus.PASSED, True, None), None),
            (SummaryArea.CORE, None, not_checked, error),
            (SummaryArea.CORE, None, CheckView(XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, "x_unavailable"), error),
            (SummaryArea.CORE, AreaState.RUNNING, unavailable, error),
            (SummaryArea.CORE, None, unavailable, "xray_process_unavailable"),
        ):
            with self.subTest(area=area, state=state, check=check, source_error=source_error):
                with self.assertRaises(TypeError):
                    SummaryAreaView(area, state, check, source_error)

    def test_summary_view_requires_every_area_once_in_order(self):
        areas_ = self.view.areas
        for value in (areas_[1:], (*areas_[1:], areas_[0]), (*areas_, areas_[0]), list(areas_), (*areas_[:6], object())):
            with self.subTest(value=value), self.assertRaises(TypeError):
                StatusSummaryView(False, value, self.view.port_53, self.view.fallback)
        for port_53, fallback in ((None, self.view.fallback), (self.view.port_53, None), ({}, self.view.fallback)):
            with self.subTest(port_53=port_53, fallback=fallback), self.assertRaises(TypeError):
                StatusSummaryView(False, areas_, port_53, fallback)
        with self.assertRaises(TypeError):
            replace(self.view.fallback, balancer_count=True)
        with self.assertRaises(TypeError):
            replace(self.view.fallback, killswitch={"status": "present", "value": "on"})

    def test_labels_and_hint_are_read_only_catalogs(self):
        self.assertEqual(list(AREA_LABELS), list(SummaryArea))
        self.assertEqual(set(STATE_LABELS), set(AreaState))
        self.assertEqual(set(AREA_STATES), set(SummaryArea))
        self.assertEqual(set().union(*AREA_STATES.values()), set(AreaState))
        self.assertEqual([AREA_LABELS[area] for area in SummaryArea], [
            "Ядро Xray", "Перехват", "Доступность VPN", "DNS и порт 53", "Автозапуск", "Режим резерва", "Черновик",
        ])
        for table in (AREA_LABELS, STATE_LABELS, AREA_STATES):
            with self.assertRaises(TypeError):
                table[SummaryArea.CORE] = "x"
        self.assertTrue(all(label.isprintable() and label == label.strip() for label in STATE_LABELS.values()))
        self.assertEqual(PORT_53_HINT, (
            "Включение исключения оставляет TCP/UDP DNS на порту 53 вне прозрачного перехвата XKeen. "
            "Это может помочь при конфликте DNS, например при работе с Pritunl. "
            "Опция не открывает порт и не гарантирует исправление любой проблемы рабочего VPN."
        ))
        self.assertEqual(
            {INTERCEPTION_CHECK, PORT_53_PATH_CHECK, AUTOSTART_CHECK, FALLBACK_CHECK, DRAFT_CHECK},
            {"interception_active", "dns_port_53_path", "autostart_flag_unambiguous", "fallback_profile_consistent",
             "draft_present"},
        )
        self.assertEqual(SummaryReason.SOURCE_NOT_CONNECTED.value, "source_not_connected")
        self.assertEqual(vpn_reachability_not_checked().reason, CheckReason.NETWORK_CHECK_NOT_PERFORMED.value)


class SummaryPrivacyTests(unittest.TestCase):
    def assert_private(self, result, markers):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in markers:
            self.assertNotIn(marker, text)
        # Из результата достижимы только безопасные представления: модели источников и исключения — нет.
        allowed = (
            StatusSummaryView, SummaryAreaView, CheckView, ChecksView, ErrorDetail, Port53View, FallbackView,
            XKeenFlagView,
        )
        for value in reachable(result.data):
            self.assertNotIsInstance(value, BaseException)
            if hasattr(type(value), "__dataclass_fields__"):
                self.assertIsInstance(value, allowed)

    def test_snapshot_summary_has_no_pids_tags_file_names_or_private_values(self):
        # Регрессия review 73-R03: случайный UUID операции мог содержать синтетический PID и уронить проверку без утечки.
        result = handler_for(snapshot_installation_sources(), operation_ids=lambda: "op-1").execute(InspectStatusSummary())
        self.assert_private(result, PRIVATE_MARKERS)

    def test_unsafe_identifiers_and_source_texts_are_hidden(self):
        sources = snapshot_installation_sources()
        configure(sources, "xray", unsafe_xray_config())
        configure(sources, "settings", unsafe_xkeen_settings())
        result = handler_for(sources).execute(InspectStatusSummary())
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.fallback.balancer_count, 2)
        self.assert_private(result, UNSAFE_MARKERS)
        with patch.object(sources.process, "current_xray_process", side_effect=OSError("\n".join(UNSAFE_MARKERS))):
            result = handler_for(sources).execute(InspectStatusSummary())
        self.assertEqual(outcome(result, "core"), (None, "not_checked", "xray_process_unavailable"))
        self.assert_private(result, UNSAFE_MARKERS)


if __name__ == "__main__":
    unittest.main()
