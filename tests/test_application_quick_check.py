"""Быстрая проверка без изменений на снимке и управляемых источниках прокси, процесса и геобаз."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.checks import (
    GEODATA_REFERENCES_CHECK, PORT_53_MODE_CHECK, VPN_REACHABLE_CHECK, XRAY_CONFIG_CHECK, XRAY_PROCESS_CHECK,
    CheckReason, CheckView, ChecksView,
)
from keenvpn.application.contract import (
    CONTRACT_VERSION, NEXT_STEP_MESSAGES, CheckStatus, ErrorCategory, ErrorDetail, NextStepCode, OperationStatus,
)
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.quick_check import (
    CHECK_ORDER, OUTCOME_LABELS, SOURCE_LABELS, SOURCE_STATE_LABELS, QuickCheck, QuickCheckHandler, QuickCheckOutcome,
    QuickCheckSource, QuickCheckView, SourceReadView, SourceState,
)
from keenvpn.application.status_summary import (
    AUTOSTART_CHECK, FALLBACK_CHECK, INTERCEPTION_CHECK, PORT_53_PATH_CHECK, InspectStatusSummary,
    InspectStatusSummaryHandler, SummaryReason,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.geodata import (
    GEOIP_FILE_NAME, GEOSITE_FILE_NAME, GeoDatabaseFile, GeoDatabaseInventory, GeoDataError, GeoDataErrorCode,
)
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation
from tests.support.in_memory import AdapterSetupError, UnconfiguredResponseError
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_MARKERS, reachable, unsafe_xkeen_settings, unsafe_xray_config
from tests.support.snapshot import SYNTHETIC_XRAY_PID, snapshot_installation_sources


CHECK_SOURCE_STEP = {"code": "check_source", "message": NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}
INSPECT_STEP = {"code": "inspect_source_data", "message": NEXT_STEP_MESSAGES[NextStepCode.INSPECT_SOURCE_DATA]}
SOURCES = ("xray", "settings", "init", "port_exclude", "port_proxying", "process", "geodata")
LIST_NAMES = {"port_exclude": XKeenListName.PORT_EXCLUDE, "port_proxying": XKeenListName.PORT_PROXYING}
PASSED = {"status": "passed", "network": False, "reason": None}
EXPECTED_CHECKS = [
    {"code": "xray_config_consistent", **PASSED},
    {"code": "geodata_references_resolved", **PASSED},
    {"code": "fallback_profile_consistent", **PASSED},
    {"code": "autostart_flag_unambiguous", **PASSED},
    {"code": "dns_port_53_mode_consistent", **PASSED},
    {"code": "xray_process_consistent", **PASSED},
    {"code": "interception_active", "status": "unsupported", "network": False, "reason": "interception_not_observed"},
    {"code": "dns_port_53_path", "status": "not_checked", "network": True, "reason": "network_check_not_performed"},
    {"code": "vpn_reachable", "status": "not_checked", "network": True, "reason": "network_check_not_performed"},
]
EXPECTED_SOURCES = [{"source": name, "state": "read", "error": None} for name in SOURCES]
EXPECTED_COUNTS = {"passed": 6, "failed": 0, "not_checked": 2, "unsupported": 1}
AFFECTED = {
    "xray": ("xray_config_consistent", "geodata_references_resolved", "fallback_profile_consistent"),
    "settings": ("fallback_profile_consistent",),
    "init": ("autostart_flag_unambiguous", "dns_port_53_mode_consistent"),
    "port_exclude": ("dns_port_53_mode_consistent",),
    "port_proxying": ("dns_port_53_mode_consistent",),
    "process": ("xray_process_consistent",),
    "geodata": ("geodata_references_resolved",),
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
    "geodata": ("geo_databases_unavailable", "Не удалось прочитать инвентарь файлов геобаз."),
}
INVALID_CODES = {
    "xray": "invalid_xray_config", "settings": "invalid_xkeen_settings", "init": "invalid_xkeen_init",
    "port_exclude": "invalid_xkeen_port_exclude", "port_proxying": "invalid_xkeen_port_proxying",
    "process": "invalid_xray_process", "geodata": "invalid_geo_databases",
}
PRIVATE_MARKERS = (
    str(SYNTHETIC_XRAY_PID), "trojan-out", "vpn-group", "fixture-password", "/fixture/ws", "probe.example", ".json",
    ".lst", ".dat", "Обезличенный", "geoip:", "geosite:", "/opt/", "192.0.2.", "2001:db8", "fixture-geo-source", "3f3f",
)
OUTBOUNDS = [
    {"tag": "proxy-a", "protocol": "trojan"},
    {"tag": "direct-out", "protocol": "freedom"},
    {"tag": "block-out", "protocol": "blackhole"},
]
INIT_OFF = b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\n'


def handler_for(sources, *, proxy=True, process=True, geodata=True, **options):
    """Сценарий над источниками снимка; флаги выключают подключение источников."""
    proxy_handler = None
    if proxy:
        ports = sources.proxy
        proxy_handler = InspectProxyConfigHandler(ports.xray, ports.settings, ports.init, ports.lists)
    return QuickCheckHandler(
        proxy_handler, sources.process if process else None, sources.geodata if geodata else None, **options,
    )


def configure(sources, name, outcome):
    """Задать ответ или отказ источника по имени."""
    if name == "process":
        sources.process.outcome = outcome
    elif name == "geodata":
        sources.geodata.outcome = outcome
    elif name in LIST_NAMES:
        sources.proxy.lists.set_response(LIST_NAMES[name], outcome)
    else:
        getattr(sources.proxy, name).outcome = outcome


def checks(result) -> dict[str, CheckView]:
    return {item.code: item for item in result.data.checks.items}


def outcome(result, code) -> tuple[str, str | None]:
    """Статус и причина проверки кодами."""
    item = checks(result)[code]
    return (item.status.value, item.reason)


def xray_config(*rules, outbounds=OUTBOUNDS, balancers=(), inbounds=(), extra=None, more_parts=()):
    routing = {"rules": list(rules), "balancers": list(balancers)}
    if extra is not None:
        routing.update(extra)
    document = {"inbounds": list(inbounds), "outbounds": outbounds, "routing": routing}
    parts = [ConfigDocument("04_test.json", json.dumps(document).encode("utf-8"))]
    parts += [ConfigDocument(name, json.dumps(content).encode("utf-8")) for name, content in more_parts]
    return XrayConfigSet(tuple(parts))


def rule(**fields):
    return {"type": "field", "network": "tcp", **fields}


def inventory(geoip_present=True, geosite_present=False):
    files = (
        GeoDatabaseFile(GEOIP_FILE_NAME, True, 1024, "3f" * 32) if geoip_present else GeoDatabaseFile(GEOIP_FILE_NAME, False),
        GeoDatabaseFile(GEOSITE_FILE_NAME, True, 2048, "5a" * 32) if geosite_present else GeoDatabaseFile(GEOSITE_FILE_NAME, False),
    )
    return GeoDatabaseInventory(files)


class QuickCheckScenarioTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_installation_sources()
        # Фиксированный идентификатор: проверки ищут синтетический PID во всём результате, случайный UUID мог бы его содержать.
        self.handler = handler_for(self.sources, operation_ids=lambda: "op-1")

    def execute(self, command=None):
        return self.handler.execute(QuickCheck() if command is None else command)

    def assert_reads(self, xray=1, settings=1, init=1, lists=(XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING),
                     process=1, geodata=1):
        self.assertEqual(self.sources.proxy.calls, (xray, settings, init, lists))
        self.assertEqual(self.sources.process.calls, process)
        self.assertEqual(self.sources.geodata.calls, geodata)
        # Ни одна проверка не зависит от Keenetic: его источники быстрая проверка не вызывает.
        self.assertEqual(self.sources.keenetic.calls, (0, 0, 0, 0))

    def test_snapshot_quick_check_lists_sources_checks_and_outcome(self):
        result = self.execute()
        self.assertTrue(result.succeeded)
        self.assertEqual(result.command, "quick_check")
        self.assertEqual(QuickCheck.name, "quick_check")
        self.assertIsInstance(result.data, QuickCheckView)
        self.assertEqual(result.to_dict()["data"], {
            "active_network_check": False, "outcome": "incomplete", "counts": EXPECTED_COUNTS,
            "sources": EXPECTED_SOURCES, "checks": {"active_network_check": False, "items": EXPECTED_CHECKS},
        })
        self.assertIs(result.data.outcome, QuickCheckOutcome.INCOMPLETE)
        self.assertIs(result.data.active_network_check, False)
        self.assertEqual([item.code for item in result.data.checks.items], list(CHECK_ORDER))
        self.assertEqual(json.loads(json.dumps(result.to_dict(), ensure_ascii=False)), result.to_dict())
        self.assert_reads()

    def test_area_checks_match_the_summary_scenario_on_the_same_sources(self):
        # Проверки областей берутся из построителей сводки, а не вычисляются второй раз.
        result = self.execute()
        ports = self.sources.proxy
        summary = InspectStatusSummaryHandler(
            InspectProxyConfigHandler(ports.xray, ports.settings, ports.init, ports.lists), self.sources.process,
        ).execute(InspectStatusSummary()).data
        area_checks = {item.check.code: item.check for item in summary.areas}
        for code in (FALLBACK_CHECK, AUTOSTART_CHECK, XRAY_PROCESS_CHECK, INTERCEPTION_CHECK, PORT_53_PATH_CHECK, VPN_REACHABLE_CHECK):
            with self.subTest(code=code):
                self.assertEqual(checks(result)[code], area_checks[code])
        self.assertNotIn("draft_present", checks(result))

    def test_dns_path_stays_a_network_check_when_its_file_sources_fail(self):
        # В сводке путь DNS привязан к области и наследует отказ источников; здесь это невыполненная сетевая проверка.
        configure(self.sources, "init", OSError("TEST_ONLY_SECRET"))
        result = self.execute()
        self.assertEqual(outcome(result, PORT_53_PATH_CHECK), ("not_checked", "network_check_not_performed"))
        self.assertEqual(outcome(result, PORT_53_MODE_CHECK), ("not_checked", "xkeen_init_unavailable"))
        self.assertIs(checks(result)[PORT_53_PATH_CHECK].network, True)

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
        self.sources.geodata.current_geo_databases = record("geodata", self.sources.geodata.current_geo_databases)
        self.assertTrue(self.execute().succeeded)
        self.assertEqual(journal, [
            "xray", "settings", "init", "list:port_exclude.lst", "list:port_proxying.lst", "process", "geodata",
        ])

    def test_wrong_command_and_version_do_not_read_sources(self):
        for command, code in (
            (object(), "invalid_command"),
            (InspectStatusSummary(), "invalid_command"),
            (QuickCheck(contract_version=CONTRACT_VERSION + 1), "unsupported_contract_version"),
            (QuickCheck(contract_version=True), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                result = self.execute(command)
                self.assertIs(result.status, OperationStatus.FAILED)
                self.assertIs(result.error.category, ErrorCategory.INVALID_REQUEST)
                self.assertEqual(result.error.code, code)
        self.assert_reads(0, 0, 0, (), 0, 0)

    def test_each_source_failure_marks_only_dependent_checks_not_checked(self):
        baseline = {item["code"]: item for item in EXPECTED_CHECKS}
        for name in SOURCES:
            with self.subTest(source=name):
                sources = snapshot_installation_sources()
                configure(sources, name, OSError("/opt/etc/xray/configs/fixture-password probe.example 192.0.2.1"))
                result = handler_for(sources).execute(QuickCheck())
                self.assertTrue(result.succeeded)
                code, message = UNAVAILABLE[name]
                payload = result.to_dict()["data"]
                for item in payload["checks"]["items"]:
                    if item["code"] in AFFECTED[name]:
                        self.assertEqual((item["status"], item["reason"]), ("not_checked", code), item["code"])
                    else:
                        self.assertEqual(item, baseline[item["code"]])
                # Описание отказа со следующим шагом — один раз, в блоке источников.
                for source in payload["sources"]:
                    if source["source"] == name:
                        self.assertEqual(source, {"source": name, "state": "failed", "error": {
                            "category": "source_failed", "code": code, "reason": None, "message": message,
                            "next_step": CHECK_SOURCE_STEP,
                        }})
                    else:
                        self.assertEqual(source, {"source": source["source"], "state": "read", "error": None})
                self.assertEqual(payload["outcome"], "incomplete")
                self.assertEqual(payload["counts"]["failed"], 0)
                self.assertEqual(payload["counts"]["not_checked"], 2 + len(AFFECTED[name]))
                # Отказ одного источника не прерывает чтение остальных: каждый вызван ровно один раз.
                self.assertEqual(sources.proxy.calls, (1, 1, 1, (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING)))
                self.assertEqual((sources.process.calls, sources.geodata.calls), (1, 1))
                text = repr(result) + json.dumps(payload, ensure_ascii=False)
                for marker in ("fixture-password", "probe.example", "192.0.2.1", "/opt/"):
                    self.assertNotIn(marker, text)

    def test_first_failure_in_reading_order_explains_a_shared_check(self):
        configure(self.sources, "geodata", OSError("TEST_ONLY_SECRET"))
        configure(self.sources, "xray", OSError("TEST_ONLY_SECRET"))
        result = self.execute()
        self.assertEqual(outcome(result, GEODATA_REFERENCES_CHECK), ("not_checked", "xray_config_unavailable"))
        self.assertEqual(outcome(result, XRAY_CONFIG_CHECK), ("not_checked", "xray_config_unavailable"))
        configure(self.sources, "xray", xray_config(rule(outboundTag="direct-out")))
        configure(self.sources, "port_proxying", OSError("TEST_ONLY_SECRET"))
        configure(self.sources, "init", OSError("TEST_ONLY_SECRET"))
        result = self.execute()
        self.assertEqual(outcome(result, GEODATA_REFERENCES_CHECK), ("not_checked", "geo_databases_unavailable"))
        self.assertEqual(outcome(result, PORT_53_MODE_CHECK), ("not_checked", "xkeen_init_unavailable"))
        self.assertEqual(outcome(result, AUTOSTART_CHECK), ("not_checked", "xkeen_init_unavailable"))
        self.assertEqual(outcome(result, XRAY_CONFIG_CHECK), ("passed", None))
        states = {item.source.value: item.state.value for item in result.data.sources}
        self.assertEqual(states, {
            "xray": "read", "settings": "read", "init": "failed", "port_exclude": "read", "port_proxying": "failed",
            "process": "read", "geodata": "failed",
        })

    def test_earlier_failure_is_not_hidden_by_a_later_unconnected_source(self):
        # Регрессия review 76-R01: отказ Xray идёт раньше неподключённых геобаз в порядке чтения и объясняет проверку.
        configure(self.sources, "xray", OSError("TEST_ONLY_SECRET"))
        result = handler_for(self.sources, geodata=False, operation_ids=lambda: "op-1").execute(QuickCheck())
        self.assertEqual(outcome(result, GEODATA_REFERENCES_CHECK), ("not_checked", "xray_config_unavailable"))
        states = {item.source.value: item.state.value for item in result.data.sources}
        self.assertEqual((states["xray"], states["geodata"]), ("failed", "not_connected"))
        # Обратное сочетание: неподключённый обработчик прокси стоит раньше отказавших геобаз.
        sources = snapshot_installation_sources()
        configure(sources, "geodata", OSError("TEST_ONLY_SECRET"))
        result = handler_for(sources, proxy=False).execute(QuickCheck())
        self.assertEqual(outcome(result, GEODATA_REFERENCES_CHECK), ("not_checked", "source_not_connected"))
        self.assertEqual(outcome(result, XRAY_CONFIG_CHECK), ("not_checked", "source_not_connected"))
        states = {item.source.value: item.state.value for item in result.data.sources}
        self.assertEqual((states["xray"], states["geodata"]), ("not_connected", "failed"))

    def test_invalid_source_data_keeps_source_codes_and_domain_reasons(self):
        for name in SOURCES:
            with self.subTest(source=name, case="foreign type"):
                sources = snapshot_installation_sources()
                configure(sources, name, object())
                result = handler_for(sources).execute(QuickCheck())
                for code in AFFECTED[name]:
                    self.assertEqual(outcome(result, code), ("not_checked", INVALID_CODES[name]))
                source = next(item for item in result.data.sources if item.source.value == name)
                self.assertIs(source.state, SourceState.FAILED)
                self.assertIs(source.error.category, ErrorCategory.INVALID_SOURCE_DATA)
                self.assertIsNone(source.error.reason)
                self.assertEqual(source.error.to_dict()["next_step"], INSPECT_STEP)
        corrupted = XrayProcessObservation((SYNTHETIC_XRAY_PID,), True)
        object.__setattr__(corrupted, "pids", (0,))
        configure(self.sources, "process", corrupted)
        configure(self.sources, "port_exclude", XKeenList(XKeenListName.PORT_PROXYING, b"53\n"))
        result = self.execute()
        self.assertEqual(outcome(result, XRAY_PROCESS_CHECK), ("not_checked", "invalid_xray_process"))
        self.assertEqual(outcome(result, PORT_53_MODE_CHECK), ("not_checked", "invalid_xkeen_port_exclude"))
        errors = {item.source.value: item.error for item in result.data.sources if item.error is not None}
        self.assertEqual(errors["process"].reason, "invalid_xray_process_observation")
        self.assertEqual(errors["port_exclude"].reason, "xkeen_list_name_mismatch")
        self.assertEqual(outcome(result, AUTOSTART_CHECK), ("passed", None))

    def test_unconnected_sources_are_not_checked_without_reads(self):
        proxy_checks = {
            "xray_config_consistent", "geodata_references_resolved", "fallback_profile_consistent",
            "autostart_flag_unambiguous", "dns_port_53_mode_consistent",
        }
        for proxy, process, geodata in (
            (False, False, False), (False, True, True), (True, False, True), (True, True, False), (False, False, True),
        ):
            with self.subTest(proxy=proxy, process=process, geodata=geodata):
                sources = snapshot_installation_sources()
                result = handler_for(sources, proxy=proxy, process=process, geodata=geodata).execute(QuickCheck())
                self.assertTrue(result.succeeded)
                missing = (proxy_checks if not proxy else set()) | ({"xray_process_consistent"} if not process else set())
                missing |= {"geodata_references_resolved"} if not geodata else set()
                for item in result.data.checks.items:
                    expected = next(check for check in EXPECTED_CHECKS if check["code"] == item.code)
                    if item.code in missing:
                        self.assertEqual((item.status.value, item.reason), ("not_checked", "source_not_connected"), item.code)
                        self.assertEqual(item.network, expected["network"])
                    else:
                        self.assertEqual(item.to_dict(), expected)
                states = {item.source.value: item.state.value for item in result.data.sources}
                for name in SOURCES:
                    connected = {"process": process, "geodata": geodata}.get(name, proxy)
                    self.assertEqual(states[name], "read" if connected else "not_connected", name)
                self.assertTrue(all(item.error is None for item in result.data.sources))
                self.assertIs(result.data.outcome, QuickCheckOutcome.INCOMPLETE)
                self.assertEqual(sources.proxy.calls[:3], (1, 1, 1) if proxy else (0, 0, 0))
                self.assertEqual(sources.process.calls, 1 if process else 0)
                self.assertEqual(sources.geodata.calls, 1 if geodata else 0)
                if not (proxy or process or geodata):
                    # Без источников ни одна проверка не выглядит исправной.
                    self.assertEqual(result.data.counts, {"passed": 0, "failed": 0, "not_checked": 8, "unsupported": 1})

    def test_outcome_is_failed_only_when_a_check_found_a_discrepancy(self):
        result = self.execute()
        self.assertEqual((result.data.outcome.value, result.data.counts["failed"]), ("incomplete", 0))
        configure(self.sources, "process", XrayProcessObservation((), True))
        result = self.execute()
        self.assertEqual(outcome(result, XRAY_PROCESS_CHECK), ("failed", "marker_without_process"))
        self.assertIs(result.data.outcome, QuickCheckOutcome.FAILED)
        self.assertEqual(result.data.counts, {"passed": 5, "failed": 1, "not_checked": 2, "unsupported": 1})
        # Отказ источника другой проверки не превращает расхождение в «не проверено».
        configure(self.sources, "geodata", OSError("TEST_ONLY_SECRET"))
        result = self.execute()
        self.assertIs(result.data.outcome, QuickCheckOutcome.FAILED)
        self.assertEqual(result.data.counts, {"passed": 4, "failed": 1, "not_checked": 3, "unsupported": 1})

    def test_interruptions_are_not_converted_to_not_checked(self):
        for name in ("xray", "port_exclude", "process", "geodata"):
            for interruption in (KeyboardInterrupt, SystemExit):
                with self.subTest(source=name, interruption=interruption.__name__):
                    sources = snapshot_installation_sources()
                    configure(sources, name, interruption())
                    with self.assertRaises(interruption):
                        handler_for(sources).execute(QuickCheck())

    def test_unconfigured_source_is_a_test_setup_error(self):
        sources = snapshot_installation_sources()
        sources.geodata.outcome = UnconfiguredResponseError
        with self.assertRaises(AdapterSetupError):
            handler_for(sources).execute(QuickCheck())

    def test_scenario_has_no_terminal_or_external_effects(self):
        failing = snapshot_installation_sources()
        configure(failing, "xray", OSError("TEST_ONLY_SECRET"))
        failing_handler = handler_for(failing)
        with forbid_external_effects():
            result = self.execute()
            failed_source = failing_handler.execute(QuickCheck())
        self.assertTrue(result.succeeded)
        self.assertEqual(outcome(failed_source, XRAY_CONFIG_CHECK), ("not_checked", "xray_config_unavailable"))

    def test_rendering_is_frozen_and_does_not_reread_sources(self):
        result = self.execute()
        first = result.to_dict()
        self.assertEqual(result.to_dict(), first)
        self.assert_reads()
        with self.assertRaises(FrozenInstanceError):
            result.data.outcome = QuickCheckOutcome.FAILED
        with self.assertRaises(FrozenInstanceError):
            result.data.sources[0].state = SourceState.FAILED
        with self.assertRaises(FrozenInstanceError):
            result.data.checks.items = ()


class CheckOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_installation_sources()
        self.handler = handler_for(self.sources, operation_ids=lambda: "op-1")

    def run_case(self, name, value):
        configure(self.sources, name, value)
        result = self.handler.execute(QuickCheck())
        self.assertTrue(result.succeeded)
        return result

    def test_xray_config_consistency_reaches_every_status_in_priority_order(self):
        cases = (
            ("snapshot-like", xray_config(rule(outboundTag="direct-out"), rule(balancerTag="group-a"),
                                          balancers=[{"tag": "group-a", "selector": ["proxy-"], "fallbackTag": "block-out"}],
                                          inbounds=[{"tag": "lan", "protocol": "dokodemo-door"}]),
             ("passed", None)),
            ("inbound tag resolved through dns tag", xray_config(rule(inboundTag=["dns-local"], outboundTag="direct-out"),
                                                                extra=None), ("failed", "unresolved_references")),
            ("duplicate outbound tags", xray_config(rule(outboundTag="direct-out"),
                                                    outbounds=[*OUTBOUNDS, {"tag": "direct-out", "protocol": "freedom"}]),
             ("failed", "duplicate_tags")),
            ("duplicate inbound tags", xray_config(inbounds=[{"tag": "lan", "protocol": "tunnel"}, {"tag": "lan", "protocol": "tunnel"}]),
             ("failed", "duplicate_tags")),
            # Регрессия review 76-R04: пустой тег и отсутствующее поле — одно и то же отсутствие имени, не конфликт.
            ("empty tags are not duplicates", xray_config(
                outbounds=[*OUTBOUNDS, {"tag": "", "protocol": "freedom"}, {"tag": "", "protocol": "blackhole"}],
                inbounds=[{"tag": "", "protocol": "tunnel"}, {"tag": "", "protocol": "tunnel"}],
            ), ("passed", None)),
            ("missing tags are not duplicates", xray_config(
                outbounds=[*OUTBOUNDS, {"protocol": "freedom"}, {"protocol": "blackhole"}],
                inbounds=[{"protocol": "tunnel"}, {"protocol": "tunnel"}],
            ), ("passed", None)),
            ("non-empty repeat beside empty tags", xray_config(
                outbounds=[*OUTBOUNDS, {"tag": "", "protocol": "freedom"}, {"tag": "block-out", "protocol": "blackhole"}],
            ), ("failed", "duplicate_tags")),
            ("duplicate balancer tags", xray_config(balancers=[{"tag": "g", "selector": ["proxy-"]}, {"tag": "g", "selector": ["proxy-"]}]),
             ("failed", "duplicate_tags")),
            ("duplicates before unresolved", xray_config(rule(outboundTag="TEST_absent"),
                                                         outbounds=[*OUTBOUNDS, {"tag": "block-out", "protocol": "blackhole"}]),
             ("failed", "duplicate_tags")),
            # Регрессия review 76-R02: повтор тега в другой части — переопределение Xray, а не конфликт.
            ("override between parts", xray_config(rule(outboundTag="direct-out"), more_parts=(
                ("05_override.json", {"outbounds": [{"tag": "direct-out", "protocol": "freedom"}]}),
            )), ("unsupported", "tags_repeated_across_parts")),
            ("inbound override between parts", xray_config(inbounds=[{"tag": "lan", "protocol": "tunnel"}], more_parts=(
                ("05_override.json", {"inbounds": [{"tag": "lan", "protocol": "dokodemo-door"}]}),
            )), ("unsupported", "tags_repeated_across_parts")),
            ("conflict within the first part beside an override", xray_config(
                outbounds=[*OUTBOUNDS, {"tag": "block-out", "protocol": "blackhole"}],
                more_parts=(("05_override.json", {"outbounds": [{"tag": "direct-out", "protocol": "freedom"}]}),),
            ), ("failed", "duplicate_tags")),
            ("first-part repeat also overridden later", xray_config(
                outbounds=[*OUTBOUNDS, {"tag": "block-out", "protocol": "blackhole"}],
                more_parts=(("05_override.json", {"outbounds": [{"tag": "block-out", "protocol": "blackhole"}]}),),
            ), ("failed", "duplicate_tags")),
            # Регрессия повторного review 76-R02: повтор внутри последующей части зависит от объединения частей.
            ("new tag repeated inside a later part", xray_config(more_parts=(
                ("05_override.json", {"outbounds": [{"tag": "x-out", "protocol": "freedom"}, {"tag": "x-out", "protocol": "freedom"}]}),
            )), ("unsupported", "tags_repeated_across_parts")),
            ("known tag repeated inside a later part", xray_config(more_parts=(
                ("05_override.json", {"outbounds": [{"tag": "direct-out", "protocol": "freedom"}, {"tag": "direct-out", "protocol": "freedom"}]}),
            )), ("unsupported", "tags_repeated_across_parts")),
            ("new tag repeated inside a tail part", xray_config(more_parts=(
                ("09_tail.json", {"outbounds": [{"tag": "x-out", "protocol": "freedom"}, {"tag": "x-out", "protocol": "freedom"}]}),
            )), ("unsupported", "tags_repeated_across_parts")),
            ("balancer repeated with several parts", xray_config(
                balancers=[{"tag": "g", "selector": ["proxy-"]}, {"tag": "g", "selector": ["proxy-"]}],
                more_parts=(("05_more.json", {"log": {}}),),
            ), ("unsupported", "tags_repeated_across_parts")),
            # Регрессия повторного review 76-R02 (круг 3): раздел routing заменяется целиком — ссылки заменённого не оцениваются.
            ("broken reference inside a replaced routing", xray_config(rule(outboundTag="TEST_absent"), more_parts=(
                ("05_override.json", {"routing": {"rules": [rule(outboundTag="direct-out")]}}),
            )), ("unsupported", "sections_repeated_across_parts")),
            ("broken reference inside the acting routing", xray_config(rule(outboundTag="direct-out"), more_parts=(
                ("05_override.json", {"routing": {"rules": [rule(outboundTag="TEST_absent")]}}),
            )), ("unsupported", "sections_repeated_across_parts")),
            ("dns repeated across parts", xray_config(rule(outboundTag="direct-out"), more_parts=(
                ("02_dns.json", {"dns": {"tag": "dns-local"}}), ("03_dns.json", {"dns": {"tag": "dns-local"}}),
            )), ("unsupported", "sections_repeated_across_parts")),
            ("first-part conflict wins over a repeated routing", xray_config(
                outbounds=[*OUTBOUNDS, {"tag": "block-out", "protocol": "blackhole"}],
                more_parts=(("05_override.json", {"routing": {"rules": [rule(outboundTag="direct-out")]}}),),
            ), ("failed", "duplicate_tags")),
            ("single routing with a broken reference stays failed", xray_config(rule(outboundTag="TEST_absent"), more_parts=(
                ("05_more.json", {"log": {}}),
            )), ("failed", "unresolved_references")),
            ("unresolved before override", xray_config(rule(outboundTag="TEST_absent"), more_parts=(
                ("05_override.json", {"outbounds": [{"tag": "direct-out", "protocol": "freedom"}]}),
            )), ("failed", "unresolved_references")),
            ("override before unsupported place", xray_config(extra={"domainStrategy": 7}, more_parts=(
                ("05_override.json", {"outbounds": [{"tag": "direct-out", "protocol": "freedom"}]}),
            )), ("unsupported", "tags_repeated_across_parts")),
            ("unresolved outbound", xray_config(rule(outboundTag="TEST_absent")), ("failed", "unresolved_references")),
            ("unresolved balancer", xray_config(rule(balancerTag="TEST_absent")), ("failed", "unresolved_references")),
            ("unresolved inbound", xray_config(rule(inboundTag=["TEST_absent"], outboundTag="direct-out"),
                                               inbounds=[{"tag": "lan", "protocol": "tunnel"}]),
             ("failed", "unresolved_references")),
            ("unresolved fallback", xray_config(balancers=[{"tag": "g", "selector": ["proxy-"], "fallbackTag": "TEST_absent"}]),
             ("failed", "unresolved_references")),
            ("unresolved before ambiguous", xray_config(rule(outboundTag="TEST_absent"), rule(network="udp")),
             ("failed", "unresolved_references")),
            ("rule with both targets", xray_config(rule(outboundTag="direct-out", balancerTag="g"),
                                                   balancers=[{"tag": "g", "selector": ["proxy-"]}]),
             ("failed", "rule_target_ambiguous")),
            ("rule without target", xray_config(rule(network="udp")), ("failed", "rule_target_ambiguous")),
            ("ambiguous before unsupported", xray_config(rule(network="udp"), 7), ("failed", "rule_target_ambiguous")),
            ("unsupported rule structure", xray_config(7), ("unsupported", "unsupported_structures")),
            # Назначение нестрокового типа сводка читает как отсутствующее: расхождение важнее неподдержанного места.
            ("unsupported target type", xray_config(rule(outboundTag=7)), ("failed", "rule_target_ambiguous")),
            ("unsupported strategy", xray_config(extra={"domainStrategy": 7}), ("unsupported", "unsupported_structures")),
            ("unsupported place beside resolved rules", xray_config(rule(outboundTag="direct-out"), extra={"domainStrategy": 7}),
             ("unsupported", "unsupported_structures")),
            ("no routing at all", XrayConfigSet((ConfigDocument("04_test.json", json.dumps({"outbounds": OUTBOUNDS}).encode()),)),
             ("passed", None)),
        )
        for name, config, expected in cases:
            with self.subTest(case=name):
                result = self.run_case("xray", config)
                self.assertEqual(outcome(result, XRAY_CONFIG_CHECK), expected)
                self.assertIs(checks(result)[XRAY_CONFIG_CHECK].network, False)
                self.assertNotIn("TEST_absent", repr(result) + json.dumps(result.to_dict()))
                self.assertNotIn("x-out", repr(result) + json.dumps(result.to_dict()))

    def test_dns_tags_resolve_inbound_references(self):
        def config(inbound_tag, servers=()):
            document = {"outbounds": OUTBOUNDS, "dns": {"tag": "dns-local", "servers": list(servers)},
                        "routing": {"rules": [rule(inboundTag=[inbound_tag], outboundTag="direct-out")]}}
            return XrayConfigSet((ConfigDocument("04_test.json", json.dumps(document).encode()),))

        self.assertEqual(outcome(self.run_case("xray", config("dns-local")), XRAY_CONFIG_CHECK), ("passed", None))
        # Регрессия review 76-R03: тег отдельного DNS-сервера — тоже inbound-тег его запросов.
        servers = [{"address": "198.51.100.1", "tag": "dns-upstream"}, "198.51.100.2"]
        result = self.run_case("xray", config("dns-upstream", servers))
        self.assertEqual(outcome(result, XRAY_CONFIG_CHECK), ("passed", None))
        self.assertNotIn("dns-upstream", json.dumps(result.to_dict()))
        self.assertEqual(
            outcome(self.run_case("xray", config("TEST_absent", servers)), XRAY_CONFIG_CHECK), ("failed", "unresolved_references"),
        )
        # Регрессия повторного review 76-R05: пустой тег сервера и отсутствующее поле одинаково не разрешают ссылку.
        for empty in ([{"address": "198.51.100.1", "tag": ""}], [{"address": "198.51.100.1"}]):
            with self.subTest(servers=empty):
                self.assertEqual(outcome(self.run_case("xray", config("", empty)), XRAY_CONFIG_CHECK), ("failed", "unresolved_references"))
                self.assertEqual(outcome(self.run_case("xray", config("dns-local", empty)), XRAY_CONFIG_CHECK), ("passed", None))

    def test_unsafe_config_is_judged_without_leaking_values(self):
        result = self.run_case("xray", unsafe_xray_config())
        # Повтор тега outbound в небезопасной конфигурации — расхождение, а не скрытый успех.
        self.assertEqual(outcome(result, XRAY_CONFIG_CHECK), ("failed", "duplicate_tags"))
        text = repr(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in UNSAFE_MARKERS:
            self.assertNotIn(marker, text)

    def test_geodata_references_reach_every_status_on_managed_sources(self):
        geo_rule = rule(outboundTag="direct-out")
        cases = (
            ("snapshot", None, None, ("passed", None)),
            ("no references", xray_config(geo_rule), None, ("not_checked", "no_references")),
            ("missing file", xray_config({**geo_rule, "ip": ["geoip:ru"]}), inventory(geoip_present=False), ("failed", "missing_files")),
            ("unsupported reference", xray_config({**geo_rule, "ip": ["geoip:ru", "geoip:"]}), inventory(), ("failed", "unsupported_references")),
            ("file not inventoried", xray_config({**geo_rule, "ip": ["ext:fixture-private.dat:x", "geoip:ru"]}), inventory(),
             ("unsupported", "files_not_inventoried")),
            ("geosite present", xray_config({**geo_rule, "domain": ["geosite:test-set"]}), inventory(geosite_present=True), ("passed", None)),
        )
        for name, config, files, expected in cases:
            with self.subTest(case=name):
                if config is not None:
                    configure(self.sources, "xray", config)
                if files is not None:
                    configure(self.sources, "geodata", files)
                result = self.handler.execute(QuickCheck())
                self.assertEqual(outcome(result, GEODATA_REFERENCES_CHECK), expected)
                self.assertNotIn("fixture-private", repr(result) + json.dumps(result.to_dict()))

    def test_inconsistent_geodata_state_is_not_checked_with_the_domain_code(self):
        with patch("keenvpn.application.quick_check.assemble_geodata_state", side_effect=GeoDataError(GeoDataErrorCode.STATE)):
            result = self.handler.execute(QuickCheck())
        self.assertEqual(outcome(result, GEODATA_REFERENCES_CHECK), ("not_checked", "invalid_geodata_state"))
        states = {item.source.value: item.state.value for item in result.data.sources}
        self.assertEqual((states["xray"], states["geodata"]), ("read", "read"))

    def test_port_53_mode_matrix(self):
        cases = (
            (b"53\n", b"", INIT_OFF, ("passed", None)),
            (b"50:60\n", b"", INIT_OFF, ("passed", None)),
            (b"", b"", INIT_OFF, ("passed", None)),
            (b"", b"53\n", INIT_OFF, ("passed", None)),
            (b"", b"", b'start_auto="on"\nproxy_dns="on"\nproxy_router="off"\n', ("passed", None)),
            (b"53\n", b"# comment\nabc\n99999\n", INIT_OFF, ("passed", None)),
            (b"53\n", b"53\n", INIT_OFF, ("failed", "port_53_in_both_lists")),
            (b"50-60\n", b"40:60\n", INIT_OFF, ("failed", "port_53_in_both_lists")),
            (b"53\n", b"80\n", INIT_OFF, ("failed", "exclude_list_ignored")),
            (b"53\n", b"80,443\n", INIT_OFF, ("failed", "exclude_list_ignored")),
            (b"1-100\n", b"8000:9000\n", INIT_OFF, ("failed", "exclude_list_ignored")),
            (b"53\n", b"", b'start_auto="on"\nproxy_dns="on"\nproxy_router="off"\n', ("failed", "proxy_dns_contradicts_exclusion")),
            # Противоречия проверяются раньше неизвестных флагов, как в режиме резерва.
            (b"53\n", b"80\n", b'start_auto="on"\nproxy_dns="on"\nproxy_router="off"\n', ("failed", "exclude_list_ignored")),
            (b"53\n", b"53\n", b'start_auto="on"\n', ("failed", "port_53_in_both_lists")),
            (b"53\n", b"", b'start_auto="on"\nproxy_dns="off"\n', ("unsupported", "flags_unknown")),
            (b"53\n", b"", b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\nproxy_router="on"\n', ("unsupported", "flags_unknown")),
            (b"", b"", b'start_auto="on"\nproxy_dns="yes"\nproxy_router="off"\n', ("unsupported", "flags_unknown")),
            (b"", b"", b'start_auto="on"\nproxy_dns=$TEST_ONLY_DNS\nproxy_router="off"\n', ("unsupported", "flags_unknown")),
        )
        for exclude, proxying, init, expected in cases:
            with self.subTest(exclude=exclude, proxying=proxying, init=init):
                configure(self.sources, "port_exclude", XKeenList(XKeenListName.PORT_EXCLUDE, exclude))
                configure(self.sources, "port_proxying", XKeenList(XKeenListName.PORT_PROXYING, proxying))
                result = self.run_case("init", parse_xkeen_init(init))
                self.assertEqual(outcome(result, PORT_53_MODE_CHECK), expected)
                self.assertIs(checks(result)[PORT_53_MODE_CHECK].network, False)
                # Путь DNS остаётся сетевой проверкой «не проверено» при любом режиме.
                self.assertEqual(outcome(result, PORT_53_PATH_CHECK), ("not_checked", "network_check_not_performed"))
                self.assertNotIn("TEST_ONLY_DNS", repr(result) + json.dumps(result.to_dict()))

    def test_every_status_of_every_check_is_reachable_and_nothing_else(self):
        expected = {
            "xray_config_consistent": {"passed", "failed", "unsupported", "not_checked"},
            "geodata_references_resolved": {"passed", "failed", "unsupported", "not_checked"},
            "fallback_profile_consistent": {"passed", "failed", "unsupported", "not_checked"},
            "autostart_flag_unambiguous": {"passed", "failed", "unsupported", "not_checked"},
            "dns_port_53_mode_consistent": {"passed", "failed", "unsupported", "not_checked"},
            "xray_process_consistent": {"passed", "failed", "not_checked"},
            "interception_active": {"unsupported"},
            "dns_port_53_path": {"not_checked"},
            "vpn_reachable": {"not_checked"},
        }
        seen = {code: set() for code in expected}

        def collect(result):
            for item in result.data.checks.items:
                seen[item.code].add(item.status.value)

        collect(self.handler.execute(QuickCheck()))
        collect(handler_for(snapshot_installation_sources(), proxy=False, process=False, geodata=False).execute(QuickCheck()))
        collect(self.run_case("process", XrayProcessObservation((), True)))
        collect(self.run_case("init", parse_xkeen_init(b'start_auto="yes"\nproxy_dns="off"\n')))
        collect(self.run_case("init", parse_xkeen_init(b'  start_auto="on"\n')))
        configure(self.sources, "init", parse_xkeen_init(INIT_OFF))
        configure(self.sources, "port_proxying", XKeenList(XKeenListName.PORT_PROXYING, b"53\n"))
        collect(self.handler.execute(QuickCheck()))
        configure(self.sources, "port_proxying", XKeenList(XKeenListName.PORT_PROXYING, b""))
        configure(self.sources, "settings", unsafe_xkeen_settings())
        collect(self.run_case("xray", xray_config(rule(outboundTag="TEST_absent"))))
        collect(self.run_case("xray", xray_config(7)))
        collect(self.run_case("xray", xray_config(rule(outboundTag="direct-out", ip=["ext:fixture-private.dat:x"]),
                                                  balancers=[{"tag": "g", "selector": ["proxy-"], "fallbackTag": "direct-out"}])))
        configure(self.sources, "geodata", inventory(geoip_present=False))
        collect(self.run_case("xray", xray_config(rule(outboundTag="direct-out", ip=["geoip:ru"]))))
        self.assertEqual(seen, expected)


class QuickCheckViewModelTests(unittest.TestCase):
    def setUp(self):
        self.view = handler_for(snapshot_installation_sources()).execute(QuickCheck()).data

    def test_view_requires_fixed_check_order_and_consistent_outcome(self):
        items = self.view.checks.items
        for value in (items[1:], tuple(reversed(items)), (*items, items[0]), (*items[:-1], CheckView("other_check", CheckStatus.PASSED, False, None))):
            with self.subTest(value=value), self.assertRaises(TypeError):
                QuickCheckView(self.view.outcome, self.view.sources, ChecksView(False, value))
        failed = list(items)
        failed[5] = CheckView(XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, CheckReason.MULTIPLE_PROCESSES.value)
        with self.assertRaises(TypeError):
            QuickCheckView(QuickCheckOutcome.INCOMPLETE, self.view.sources, ChecksView(False, tuple(failed)))
        with self.assertRaises(TypeError):
            QuickCheckView(QuickCheckOutcome.FAILED, self.view.sources, self.view.checks)
        self.assertIs(QuickCheckView(QuickCheckOutcome.FAILED, self.view.sources, ChecksView(False, tuple(failed))).outcome, QuickCheckOutcome.FAILED)
        for outcome_value in ("incomplete", None, 1):
            with self.subTest(outcome=outcome_value), self.assertRaises(TypeError):
                QuickCheckView(outcome_value, self.view.sources, self.view.checks)
        with self.assertRaises(TypeError):
            QuickCheckView(self.view.outcome, self.view.sources, self.view.checks.to_dict())
        # Пассивный результат: инвариант набора проверок отклоняет итог сетевой проверки.
        network = list(items)
        network[8] = CheckView(VPN_REACHABLE_CHECK, CheckStatus.PASSED, True, None)
        with self.assertRaises(TypeError):
            ChecksView(False, tuple(network))

    def test_view_requires_every_source_once_in_reading_order(self):
        sources = self.view.sources
        for value in (sources[1:], (*sources[1:], sources[0]), (*sources, sources[0]), list(sources), (*sources[:6], object())):
            with self.subTest(value=value), self.assertRaises(TypeError):
                QuickCheckView(self.view.outcome, value, self.view.checks)
        self.assertEqual([item.source for item in sources], list(QuickCheckSource))

    def test_source_view_requires_exact_types_and_error_only_on_failure(self):
        error = ErrorDetail(ErrorCategory.SOURCE_FAILED, "xray_config_unavailable", "Текст.")
        self.assertEqual(SourceReadView(QuickCheckSource.XRAY, SourceState.FAILED, error).to_dict(), {
            "source": "xray", "state": "failed", "error": error.to_dict(),
        })
        self.assertEqual(SourceReadView(QuickCheckSource.GEODATA, SourceState.NOT_CONNECTED).to_dict(), {
            "source": "geodata", "state": "not_connected", "error": None,
        })
        for source, state, detail in (
            ("xray", SourceState.READ, None),
            (QuickCheckSource.XRAY, "read", None),
            (QuickCheckSource.XRAY, SourceState.READ, error),
            (QuickCheckSource.XRAY, SourceState.NOT_CONNECTED, error),
            (QuickCheckSource.XRAY, SourceState.FAILED, None),
            (QuickCheckSource.XRAY, SourceState.FAILED, error.to_dict()),
        ):
            with self.subTest(source=source, state=state, error=detail), self.assertRaises(TypeError):
                SourceReadView(source, state, detail)

    def test_counts_follow_statuses_in_dictionary_order(self):
        self.assertEqual(list(self.view.counts), ["passed", "failed", "not_checked", "unsupported"])
        self.assertEqual(sum(self.view.counts.values()), len(CHECK_ORDER))
        self.assertEqual(self.view.counts, EXPECTED_COUNTS)

    def test_labels_are_read_only_catalogs(self):
        self.assertEqual(list(SOURCE_LABELS), list(QuickCheckSource))
        self.assertEqual(list(SOURCE_STATE_LABELS), list(SourceState))
        self.assertEqual(list(OUTCOME_LABELS), list(QuickCheckOutcome))
        self.assertEqual(list(QuickCheckOutcome), [QuickCheckOutcome.FAILED, QuickCheckOutcome.INCOMPLETE])
        self.assertEqual(OUTCOME_LABELS[QuickCheckOutcome.FAILED], "найдены расхождения")
        for table in (SOURCE_LABELS, SOURCE_STATE_LABELS, OUTCOME_LABELS):
            with self.assertRaises(TypeError):
                table[QuickCheckOutcome.FAILED] = "x"
            self.assertTrue(all(label.isprintable() and label == label.strip() for label in table.values()))
        self.assertEqual(CHECK_ORDER, (
            XRAY_CONFIG_CHECK, GEODATA_REFERENCES_CHECK, FALLBACK_CHECK, AUTOSTART_CHECK, PORT_53_MODE_CHECK,
            XRAY_PROCESS_CHECK, INTERCEPTION_CHECK, PORT_53_PATH_CHECK, VPN_REACHABLE_CHECK,
        ))
        self.assertEqual((XRAY_CONFIG_CHECK, PORT_53_MODE_CHECK), ("xray_config_consistent", "dns_port_53_mode_consistent"))
        self.assertEqual(SummaryReason.SOURCE_NOT_CONNECTED.value, "source_not_connected")


class QuickCheckPrivacyTests(unittest.TestCase):
    def assert_private(self, result, markers):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in markers:
            self.assertNotIn(marker, text)
        # Из результата достижимы только безопасные представления: модели источников и исключения — нет.
        allowed = (QuickCheckView, SourceReadView, CheckView, ChecksView, ErrorDetail)
        for value in reachable(result.data):
            self.assertNotIsInstance(value, BaseException)
            if hasattr(type(value), "__dataclass_fields__"):
                self.assertIsInstance(value, allowed)

    def test_snapshot_result_has_no_pids_tags_file_names_or_private_values(self):
        result = handler_for(snapshot_installation_sources(), operation_ids=lambda: "op-1").execute(QuickCheck())
        self.assert_private(result, PRIVATE_MARKERS)

    def test_unsafe_identifiers_and_source_texts_are_hidden(self):
        sources = snapshot_installation_sources()
        configure(sources, "xray", unsafe_xray_config())
        configure(sources, "settings", unsafe_xkeen_settings())
        result = handler_for(sources, operation_ids=lambda: "op-1").execute(QuickCheck())
        self.assertTrue(result.succeeded)
        self.assert_private(result, UNSAFE_MARKERS)
        for name in ("process", "geodata", "init"):
            with self.subTest(source=name):
                configure(sources, name, OSError("\n".join(UNSAFE_MARKERS)))
                result = handler_for(sources, operation_ids=lambda: "op-1").execute(QuickCheck())
                self.assert_private(result, UNSAFE_MARKERS)


if __name__ == "__main__":
    unittest.main()
