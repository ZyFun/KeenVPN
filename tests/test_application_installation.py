"""Общий сценарий чтения установки на снимке и управляемых источниках геобаз и процесса."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.installation import InspectInstallation, InspectInstallationHandler, InstallationView
from keenvpn.application.keenetic_state import InspectKeeneticState, InspectKeeneticStateHandler
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.geodata import (
    GEOIP_FILE_NAME, GEOSITE_FILE_NAME, GeoDatabaseFile, GeoDatabaseInventory, GeoDataError, GeoDataErrorCode,
    GeoDataState, GeoReference, UnsupportedGeoReference,
)
from keenvpn.domain.keenetic_device import KeeneticDevice, KeeneticDeviceInventory
from keenvpn.domain.keenetic_native import (
    KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticNativeState, KeeneticRegistrations,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet
from keenvpn.domain.routing import GeoDatabase
from keenvpn.domain.xkeen_config import XKeenConfig, XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation
from tests.support.in_memory import (
    AdapterSetupError, InMemoryGeoDatabaseSource, InMemoryXrayProcessSource, UnconfiguredResponseError,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import (
    SYNTHETIC_GEOIP_SHA256, SYNTHETIC_GEOIP_SOURCE, SYNTHETIC_XRAY_PID, snapshot_installation_sources,
    snapshot_keenetic_sources, snapshot_proxy_sources, synthetic_geo_inventory,
)


PRIVATE_MARKERS = (
    "02:00:00:54", "02:00:00:00", "device-", "192.0.2.", "2001:db8", "fixture-policy", "fixture-interface",
    "fixture-private", "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "probe.example",
    "127.0.0.1", "/opt/var/log", "1181", "1191", "Обезличенный", "geoip:", "geosite:", "domain:", '"ru"', '"RU"',
    "fixture-set", "../", "fixture-user", "fixture-token", "fixture-query", "fixture-fragment", "token=",
)
PRIVATE_TYPES = (
    ConfigDocument, XrayConfigSet, XKeenSettings, XKeenInitParameters, XKeenList, XKeenConfig, KeeneticPolicy,
    KeeneticPolicySet, KeeneticDevice, KeeneticDeviceInventory, KeeneticHotspotSettings, KeeneticRegistrations,
    KeeneticHotspotRuntime, KeeneticNativeState, GeoDatabase, GeoDatabaseFile, GeoDatabaseInventory, GeoReference,
    UnsupportedGeoReference, GeoDataState, XrayProcessObservation, BaseException,
)
EXPECTED_GEODATA = {
    "files": [
        {"name": GEOIP_FILE_NAME, "present": True, "size": 1024, "sha256": SYNTHETIC_GEOIP_SHA256,
         "source_known": True, "source": SYNTHETIC_GEOIP_SOURCE, "version_known": False, "version": None,
         "reference_count": 1, "set_count": 1},
        {"name": GEOSITE_FILE_NAME, "present": False, "size": None, "sha256": None, "source_known": False,
         "source": None, "version_known": False, "version": None, "reference_count": 0, "set_count": 0},
    ],
    "present_count": 1, "missing_count": 1, "extra_count": 0,
    "references": [{
        "part": "05_routing.json", "path": "routing.rules[6].ip[0]", "family": "ip", "external": False,
        "file_name": GEOIP_FILE_NAME, "file_status": "present", "negated": False, "attribute_count": 0,
    }],
    "reference_count": 1, "resolved_count": 1, "unresolved_count": 0, "unsupported_references": [],
}
EXPECTED_PROCESS = {
    "process_count": 1, "pids": [SYNTHETIC_XRAY_PID], "ready_marker": True, "state": "running", "consistent": True,
}
KEENETIC_SOURCES = ("policies", "hotspot", "registrations", "runtime")
PROXY_SOURCES = ("xray", "settings", "init", "port_exclude", "port_proxying", "ip_exclude")
LIST_NAMES = (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING, XKeenListName.IP_EXCLUDE)
LIST_FIELDS = dict(zip(PROXY_SOURCES[3:], LIST_NAMES))
SOURCES = (*KEENETIC_SOURCES, *PROXY_SOURCES, "geodata", "process")
UNAVAILABLE_CODES = {
    "policies": "keenetic_policies_unavailable", "hotspot": "keenetic_hotspot_unavailable",
    "registrations": "keenetic_registrations_unavailable", "runtime": "keenetic_runtime_unavailable",
    "xray": "xray_config_unavailable", "settings": "xkeen_settings_unavailable", "init": "xkeen_init_unavailable",
    "port_exclude": "xkeen_port_exclude_unavailable", "port_proxying": "xkeen_port_proxying_unavailable",
    "ip_exclude": "xkeen_ip_exclude_unavailable", "geodata": "geo_databases_unavailable",
    "process": "xray_process_unavailable",
}
INVALID_CODES = {
    "policies": "invalid_keenetic_policies", "hotspot": "invalid_keenetic_hotspot",
    "registrations": "invalid_keenetic_registrations", "runtime": "invalid_keenetic_runtime",
    "xray": "invalid_xray_config", "settings": "invalid_xkeen_settings", "init": "invalid_xkeen_init",
    "port_exclude": "invalid_xkeen_port_exclude", "port_proxying": "invalid_xkeen_port_proxying",
    "ip_exclude": "invalid_xkeen_ip_exclude", "geodata": "invalid_geo_databases", "process": "invalid_xray_process",
}


def handler_for(sources, **options):
    keenetic, proxy = sources.keenetic, sources.proxy
    return InspectInstallationHandler(
        InspectKeeneticStateHandler(keenetic.policies, keenetic.hotspot, keenetic.registrations, keenetic.runtime),
        InspectProxyConfigHandler(proxy.xray, proxy.settings, proxy.init, proxy.lists),
        sources.geodata, sources.process, **options,
    )


def configure(sources, name, outcome):
    """Задать ответ или отказ источника по его имени в порядке чтения."""
    if name in KEENETIC_SOURCES:
        getattr(sources.keenetic, name).outcome = outcome
    elif name in LIST_FIELDS:
        sources.proxy.lists.set_response(LIST_FIELDS[name], outcome)
    elif name in PROXY_SOURCES:
        getattr(sources.proxy, name).outcome = outcome
    else:
        getattr(sources, name).outcome = outcome


def calls_after_failure(index):
    """Источники после отказавшего не читаются; порядок: Keenetic, Xray/XKeen, геобазы, процесс."""
    keenetic = tuple(1 if position <= index else 0 for position in range(4))
    proxy_scalar = tuple(1 if position + 4 <= index else 0 for position in range(3))
    lists = tuple(name for position, name in enumerate(LIST_NAMES) if position + 7 <= index)
    return (keenetic, (*proxy_scalar, lists), 1 if index >= 10 else 0, 1 if index >= 11 else 0)


ALL_READ = calls_after_failure(len(SOURCES) - 1)


def routing_config(*values, key="ip"):
    rule = {"type": "field", key: list(values), "outboundTag": "direct"}
    return XrayConfigSet((ConfigDocument("05_routing.json", json.dumps({"routing": {"rules": [rule]}}).encode()),))


class InspectInstallationTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_installation_sources()
        self.handler = handler_for(self.sources, operation_ids=lambda: "op-1")

    def execute(self, command=None):
        return self.handler.execute(InspectInstallation() if command is None else command)

    def assert_private(self, result):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertFalse(any(isinstance(value, PRIVATE_TYPES) for value in reachable(result)))

    def assert_failed(self, result, category, code, reason=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertIs(result.error.category, category)
        self.assertEqual(result.error.code, code)
        self.assertEqual(result.error.reason, reason)
        self.assert_private(result)

    def test_snapshot_installation_is_read_once_per_source_in_order(self):
        result = self.execute()
        self.assertTrue(result.succeeded)
        self.assertIs(type(result.data), InstallationView)
        data = result.to_dict()
        keenetic = InspectKeeneticStateHandler(
            self.sources.keenetic.policies, self.sources.keenetic.hotspot, self.sources.keenetic.registrations,
            self.sources.keenetic.runtime,
        ).execute(InspectKeeneticState()).to_dict()["data"]
        proxy = InspectProxyConfigHandler(
            self.sources.proxy.xray, self.sources.proxy.settings, self.sources.proxy.init, self.sources.proxy.lists,
        ).execute(InspectProxyConfig()).to_dict()["data"]
        self.assertEqual(data, {
            "contract_version": CONTRACT_VERSION, "operation_id": "op-1", "command": "inspect_installation",
            "status": "succeeded", "error": None,
            "data": {"keenetic": keenetic, "proxy": proxy, "geodata": EXPECTED_GEODATA, "xray_process": EXPECTED_PROCESS},
        })
        # Общий сценарий читает те же источники по одному разу; сравнение выше прочитало их ещё раз.
        self.assertEqual(self.sources.calls, ((2, 2, 2, 2), (2, 2, 2, LIST_NAMES * 2), 1, 1))
        self.assertEqual(result.data.geodata.files[1].present, False)
        self.assertEqual(result.data.geodata.references[0].file_status, "present")
        self.assertEqual(result.data.xray_process.state, "running")
        self.assertEqual(result.data.proxy.xkeen.port_53.port_exclude_entry, True)
        self.assertEqual(result.data.keenetic.policy_count, 3)
        self.assert_private(result)

    def test_wrong_command_and_version_do_not_read_sources(self):
        for command, code in (
            ("inspect", "invalid_command"),
            (None, "invalid_command"),
            (InspectKeeneticState(), "invalid_command"),
            (InspectInstallation(contract_version=True), "unsupported_contract_version"),
            (InspectInstallation(contract_version=CONTRACT_VERSION + 1), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                self.assert_failed(self.handler.execute(command), ErrorCategory.INVALID_REQUEST, code)
        self.assertEqual(self.sources.calls, ((0, 0, 0, 0), (0, 0, 0, ()), 0, 0))

    def test_each_source_failure_keeps_its_code_and_stops_reading(self):
        for index, name in enumerate(SOURCES):
            with self.subTest(source=name):
                sources = snapshot_installation_sources()
                configure(sources, name, OSError("Отказ источника: fixture-private 02:00:00:54:00:01 /fixture/ws"))
                result = handler_for(sources).execute(InspectInstallation())
                self.assert_failed(result, ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name])
                self.assertEqual(sources.calls, calls_after_failure(index))

    def test_invalid_source_data_keeps_area_codes_and_domain_reasons(self):
        class DerivedInventory(GeoDatabaseInventory):
            pass

        class DerivedObservation(XrayProcessObservation):
            pass

        tampered_inventory = synthetic_geo_inventory()
        object.__setattr__(tampered_inventory.files[0], "sha256", SYNTHETIC_GEOIP_SHA256.upper())
        incomplete_inventory = synthetic_geo_inventory()
        object.__setattr__(incomplete_inventory, "files", incomplete_inventory.files[:1])
        duplicated_observation = XrayProcessObservation((SYNTHETIC_XRAY_PID,), True)
        object.__setattr__(duplicated_observation, "pids", (SYNTHETIC_XRAY_PID, SYNTHETIC_XRAY_PID))
        typed_observation = XrayProcessObservation((SYNTHETIC_XRAY_PID,), True)
        object.__setattr__(typed_observation, "ready_marker", 1)
        cases = (
            ("policies", None, None),
            ("settings", None, None),
            ("geodata", None, None),
            ("geodata", DerivedInventory(synthetic_geo_inventory().files), None),
            ("geodata", tampered_inventory, "invalid_geo_inventory"),
            ("geodata", incomplete_inventory, "invalid_geo_inventory"),
            ("process", None, None),
            ("process", DerivedObservation((SYNTHETIC_XRAY_PID,), True), None),
            ("process", duplicated_observation, "invalid_xray_process_observation"),
            ("process", typed_observation, "invalid_xray_process_observation"),
            ("process", "fixture-private", None),
        )
        for name, outcome, reason in cases:
            with self.subTest(source=name, outcome=type(outcome).__name__, reason=reason):
                sources = snapshot_installation_sources()
                configure(sources, name, outcome)
                result = handler_for(sources).execute(InspectInstallation())
                self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, INVALID_CODES[name], reason)
                self.assertEqual(sources.calls, calls_after_failure(SOURCES.index(name)))

    def test_assembly_failure_is_reported_without_partial_result(self):
        def broken(*_args):
            raise GeoDataError(GeoDataErrorCode.STATE)

        with patch("keenvpn.application.installation.assemble_geodata_state", broken):
            result = self.execute()
        self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, "installation_inconsistent", "invalid_geodata_state")
        self.assertEqual(self.sources.calls, ALL_READ)

    def test_interruptions_are_not_converted_to_source_failure(self):
        for name in SOURCES:
            for error in (KeyboardInterrupt(), SystemExit()):
                with self.subTest(source=name, error=type(error).__name__):
                    sources = snapshot_installation_sources()
                    configure(sources, name, error)
                    with self.assertRaises(type(error)):
                        handler_for(sources).execute(InspectInstallation())

    def test_unconfigured_source_is_a_test_setup_error(self):
        for name, source_type in (("geodata", InMemoryGeoDatabaseSource), ("process", InMemoryXrayProcessSource)):
            with self.subTest(source=name):
                sources = snapshot_installation_sources()
                arguments = {"geodata": sources.geodata, "process": sources.process, name: source_type()}
                handler = handler_for(type(sources)(sources.keenetic, sources.proxy, **arguments))
                with self.assertRaises(UnconfiguredResponseError):
                    handler.execute(InspectInstallation())
                self.assertEqual(arguments[name].calls, 1)
        with self.assertRaises(AdapterSetupError):
            InMemoryGeoDatabaseSource(OSError).current_geo_databases()
        with self.assertRaises(AdapterSetupError):
            InMemoryXrayProcessSource(OSError).current_xray_process()

    def test_scenario_has_no_terminal_or_external_effects(self):
        with forbid_external_effects():
            self.assertTrue(self.execute().succeeded)
            self.sources.process.outcome = OSError("fixture-private")
            self.assertEqual(self.execute().error.code, "xray_process_unavailable")
            self.sources.geodata.outcome = None
            self.assertEqual(self.execute().error.code, "invalid_geo_databases")
            self.sources.keenetic.runtime.outcome = None
            self.assertEqual(self.execute().error.code, "invalid_keenetic_runtime")

    def test_rendering_is_frozen_and_does_not_reread_sources(self):
        result = self.execute()
        calls = self.sources.calls
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertIn("geoip.dat", str(result.data))
        self.assertEqual(self.sources.calls, calls)
        for assign in (
            lambda: setattr(result.data, "geodata", None),
            lambda: setattr(result.data.geodata.files[0], "present", False),
            lambda: setattr(result.data.geodata.references[0], "file_status", "missing"),
            lambda: setattr(result.data.xray_process, "state", "stopped"),
            lambda: setattr(result.data.proxy.xkeen.port_53, "port_exclude_entry", False),
        ):
            with self.assertRaises(FrozenInstanceError):
                assign()

    def test_process_and_marker_mismatch_is_reported_as_separate_state(self):
        for pids, marker, state, consistent in (
            ((), False, "stopped", True),
            ((), True, "marker_without_process", False),
            ((SYNTHETIC_XRAY_PID,), False, "process_without_marker", False),
            ((SYNTHETIC_XRAY_PID, SYNTHETIC_XRAY_PID + 1), True, "multiple_processes", False),
        ):
            with self.subTest(state=state):
                self.sources.process.outcome = XrayProcessObservation(pids, marker)
                result = self.execute()
                self.assertTrue(result.succeeded)
                self.assertEqual(result.data.xray_process.to_dict(), {
                    "process_count": len(pids), "pids": list(pids), "ready_marker": marker, "state": state,
                    "consistent": consistent,
                })
                self.assert_private(result)

    def test_missing_unknown_and_unsupported_references_are_reported_without_values(self):
        self.sources.geodata.outcome = GeoDatabaseInventory((
            GeoDatabaseFile(GEOIP_FILE_NAME, False),
            GeoDatabaseFile(GEOSITE_FILE_NAME, True, 2289050, "4f" * 32, "fixture-geosite-source", "fixture-release"),
        ))
        self.sources.proxy.xray.outcome = XrayConfigSet((
            ConfigDocument("01_dns.json", json.dumps({"dns": {"servers": [{
                "address": "198.51.100.54", "domains": ["geosite:fixture-set", "domain:fixture-private.example"],
            }], "hosts": {"ext:hosts.dat:fixture-set": "198.51.100.1"}}}).encode()),
            ConfigDocument("05_routing.json", json.dumps({"routing": {"rules": [{
                "type": "field", "ip": ["geoip:ru", "geoip:!ru", "ext:../fixture-private.dat:x", "geoip:"],
                "domain": "geosite:fixture-set@attr", "outboundTag": "direct",
            }]}}).encode()),
        ))
        result = self.execute()
        self.assertTrue(result.succeeded)
        geodata = result.data.geodata.to_dict()
        self.assertEqual([(item["name"], item["present"], item["version"]) for item in geodata["files"]], [
            (GEOIP_FILE_NAME, False, None), (GEOSITE_FILE_NAME, True, "fixture-release"),
        ])
        self.assertEqual([(item["reference_count"], item["set_count"]) for item in geodata["files"]], [(2, 1), (2, 1)])
        self.assertEqual(
            [(item["path"], item["file_name"], item["file_status"], item["negated"], item["attribute_count"])
             for item in geodata["references"]],
            [
                ("dns.servers[0].domains[0]", GEOSITE_FILE_NAME, "present", False, 0),
                ("dns.hosts[0]", "hosts.dat", "unknown", False, 0),
                ("routing.rules[0].ip[0]", GEOIP_FILE_NAME, "missing", False, 0),
                ("routing.rules[0].ip[1]", GEOIP_FILE_NAME, "missing", True, 0),
                ("routing.rules[0].ip[2]", None, "unknown", False, 0),
                ("routing.rules[0].domain[0]", GEOSITE_FILE_NAME, "present", False, 1),
            ],
        )
        self.assertEqual((geodata["present_count"], geodata["missing_count"], geodata["extra_count"]), (1, 1, 0))
        self.assertEqual((geodata["reference_count"], geodata["resolved_count"], geodata["unresolved_count"]), (6, 2, 4))
        self.assertEqual(geodata["unsupported_references"], [{"part": "05_routing.json", "path": "routing.rules[0].ip[3]", "family": "ip"}])
        self.assertEqual(self.sources.calls, ALL_READ)
        self.assert_private(result)

    def test_source_credentials_and_unsafe_version_are_hidden_in_result(self):
        self.sources.geodata.outcome = GeoDatabaseInventory((
            GeoDatabaseFile(
                GEOIP_FILE_NAME, True, 1024, "1c" * 32,
                "https://fixture-user:fixture-password@downloads.example.test/fixture-token/geoip.dat?token=fixture-query#fixture-fragment",
                "release token=fixture-private",
            ),
            GeoDatabaseFile(GEOSITE_FILE_NAME, False, source="/opt/fixture-private/geosite.dat"),
            GeoDatabaseFile("a.dat", True, 1, "ab" * 32, source="opt/../fixture-private/geoip.dat"),
            GeoDatabaseFile("b.dat", True, 1, "ab" * 32, source="data/../../fixture-private/geosite.dat"),
            GeoDatabaseFile("c.dat", True, 1, "ab" * 32, source="fixture-private/geoip.dat"),
        ))
        with forbid_external_effects():
            result = self.execute()
        self.assertTrue(result.succeeded)
        files = result.data.geodata.to_dict()["files"]
        self.assertEqual(
            [(item["source_known"], item["source"], item["version_known"], item["version"]) for item in files],
            [(True, "https://downloads.example.test", True, None), (True, None, False, None)]
            + [(True, None, False, None)] * 3,
        )
        self.assertEqual(result.data.geodata.files[0].source, "https://downloads.example.test")
        self.assert_private(result)

    def test_ignored_xray_aliases_do_not_create_geodata_dependencies(self):
        self.sources.geodata.outcome = GeoDatabaseInventory((
            GeoDatabaseFile(GEOIP_FILE_NAME, False), GeoDatabaseFile(GEOSITE_FILE_NAME, False),
        ))
        self.sources.proxy.xray.outcome = XrayConfigSet((
            ConfigDocument("01_dns.json", json.dumps({"dns": {"servers": [{
                "address": "198.51.100.53", "expectedIPs": ["198.51.100.0/24"], "expectIPs": ["geoip:ru"],
            }]}}).encode()),
            ConfigDocument("05_routing.json", json.dumps({"routing": {"rules": [{
                "type": "field", "sourceIP": ["192.0.2.0/24"], "source": ["geoip:ru"], "outboundTag": "direct",
            }]}}).encode()),
        ))
        result = self.execute()
        self.assertTrue(result.succeeded)
        geodata = result.data.geodata.to_dict()
        self.assertEqual((geodata["reference_count"], geodata["unresolved_count"]), (0, 0))
        self.assertEqual([item["reference_count"] for item in geodata["files"]], [0, 0])
        # Поля конфигурации сохраняются: сводка правила по-прежнему видит оба поля условий.
        self.assertEqual(
            {item.key for item in result.data.proxy.xray.rules[0].conditions}, {"sourceIP", "source"},
        )
        self.assert_private(result)

    def test_extra_file_and_known_version_are_shown_without_update_claims(self):
        self.sources.geodata.outcome = GeoDatabaseInventory((
            GeoDatabaseFile(GEOIP_FILE_NAME, True, 23330258, "1c" * 32, "fixture-geoip-source", "fixture-release"),
            GeoDatabaseFile(GEOSITE_FILE_NAME, True, 10 ** 30, "4f" * 32),
            GeoDatabaseFile("custom.dat", True, 1, "ab" * 32),
        ))
        self.sources.proxy.xray.outcome = routing_config("ext:custom.dat:x", "ext-ip:custom.dat:!y", "geoip:private")
        result = self.execute()
        self.assertTrue(result.succeeded)
        geodata = result.data.geodata.to_dict()
        self.assertEqual([(item["name"], item["version"], item["reference_count"], item["set_count"]) for item in geodata["files"]], [
            (GEOIP_FILE_NAME, "fixture-release", 1, 1), (GEOSITE_FILE_NAME, None, 0, 0), ("custom.dat", None, 2, 2),
        ])
        self.assertEqual(geodata["files"][1]["size"], 10 ** 30)
        self.assertEqual((geodata["present_count"], geodata["missing_count"], geodata["extra_count"]), (3, 0, 1))
        self.assertEqual([item["file_status"] for item in geodata["references"]], ["present", "present", "present"])
        self.assertEqual([item["external"] for item in geodata["references"]], [True, True, False])
        text = json.dumps(geodata, ensure_ascii=False)
        for word in ("update", "обновл", "xkeen"):
            self.assertNotIn(word, text.lower())
        self.assert_private(result)


if __name__ == "__main__":
    unittest.main()
