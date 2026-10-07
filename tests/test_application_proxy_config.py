"""Сценарий чтения конфигурации Xray и XKeen на снимке и управляемых источниках."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.proxy_config import (
    LIST_NAME_MISMATCH, InspectProxyConfig, InspectProxyConfigHandler, ProxyConfigView,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import (
    Port53Facts, XKeenConfig, XKeenConfigError, XKeenConfigErrorCode, XKeenFlag, XKeenInitAssignment,
    XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init,
)
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.in_memory import (
    AdapterSetupError, InMemoryXKeenInitSource, InMemoryXKeenListSource, InMemoryXKeenSettingsSource,
    InMemoryXrayConfigSource, UnconfiguredResponseError,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import snapshot_proxy_sources, snapshot_xkeen_list, snapshot_xkeen_settings


PRIVATE_MARKERS = (
    "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "192.0.2.", "probe.example",
    "127.0.0.1", "/opt/var/log", "1181", "1191", "fixture-private", "Обезличенный", "geoip:", "domain:",
)
PRIVATE_TYPES = (
    ConfigDocument, XrayConfigSet, XKeenSettings, XKeenInitParameters, XKeenInitAssignment, XKeenList,
    XKeenConfig, Port53Facts, XKeenFlag, BaseException,
)
PART_HASHES = {
    "01_log.json": (132, "fa5aa59c390cb3fad7830f6317c328ada1ec90950114f6151afab402f2295db0", ["log"]),
    "02_dns.json": (163, "9b70d7ec42d72cfddcb36e386d552b52205c2f33291a5d6b06ae4e28a301fc0f", ["dns"]),
    "03_inbounds.json": (1575, "54e4fea3d68f6d1020c8ba60f587a52e67d35b0c275a928fe42fb5ed87121f34", ["inbounds"]),
    "04_outbounds.json": (1043, "d40f1ba9c9706e1c4faf31328600cec440cf2e4eeeb3bc826af531b573ccf75b", ["outbounds"]),
    "05_routing.json": (2754, "faab7dacaee75cea7c05a29ed83c69156d07a98545b9589ae7346a7b340dddec", ["routing"]),
    "06_policy.json": (165, "5d5ec11248c5659861a93ab37dce42cd7e58af362709ce90823cb78382b22054", ["policy"]),
    "07_observatory.json": (257, "afd8f6097a1010d84d673aaa6cf2309cd5b2a58f607864231500efc4b08b401b", ["burstObservatory"]),
}


def rule(index, target_kind, target_tag, conditions, inbound_tags=()):
    return {
        "part": "05_routing.json", "index": index, "type": "field", "inbound_tags": list(inbound_tags),
        "inbound_tags_resolved": True, "target_kind": target_kind, "target_tag": target_tag, "target_resolved": True,
        "has_rule_tag": True, "conditions": conditions,
    }


def port_list(name, line_count, comment_count, entry_count, port_count, address_count=None):
    ports = address_count is None
    return {
        "name": name, "line_count": line_count, "blank_count": 0, "comment_count": comment_count,
        "entry_count": entry_count, "port_count": port_count if ports else None, "range_count": 0 if ports else None,
        "address_count": address_count, "invalid_count": 0,
    }


EXPECTED_XRAY = {
    "part_count": 7,
    "parts": [{"name": name, "size": size, "sha256": digest, "sections": sections}
              for name, (size, digest, sections) in PART_HASHES.items()],
    "sections": {sections[0]: [name] for name, (_size, _digest, sections) in PART_HASHES.items()},
    "duplicate_sections": [], "dns_tags": ["dns-local"], "domain_strategies": ["IPOnDemand"],
    "inbounds": [{"part": "03_inbounds.json", "tag": tag, "protocol": "tunnel"}
                 for tag in ("redirect", "tproxy", "force-proxy-redirect", "force-proxy-tproxy")],
    "outbounds": [{"part": "04_outbounds.json", "tag": tag, "protocol": protocol}
                  for tag, protocol in (("trojan-out", "trojan"), ("direct", "freedom"), ("blocked", "blackhole"))],
    "duplicate_inbound_tags": [], "duplicate_outbound_tags": [], "duplicate_balancer_tags": [],
    "rule_count": 8,
    "rules": [
        rule(0, "outbound", "direct", {}, ["dns-local"]),
        rule(1, "outbound", "direct", {"domain": 3}),
        rule(2, "balancer", "vpn-group", {}, ["force-proxy-redirect", "force-proxy-tproxy"]),
        rule(3, "balancer", "vpn-group", {"domain": 2}),
        rule(4, "outbound", "direct", {"domain": 16}),
        rule(5, "outbound", "direct", {"ip": 19}),
        rule(6, "outbound", "direct", {"ip": 1}),
        rule(7, "balancer", "vpn-group", {"network": 1}),
    ],
    "balancers": [{
        "part": "05_routing.json", "tag": "vpn-group", "selector": ["trojan-out"], "selector_match_count": 1,
        "fallback_tag": "blocked", "fallback_resolved": True, "strategy": "leastPing",
    }],
    "observatory_subjects": [{
        "part": "07_observatory.json", "section": "burstObservatory", "selector": "trojan-out", "match_count": 1,
    }],
    "unsupported_paths": [],
}
EXPECTED_XKEEN = {
    "settings": {
        "name": "xkeen.json", "size": 78, "sha256": "daa179d2dd60e90dd00716fec0fa82bb6e4f9f54df3547137e67e2452b20e470",
        "sections": ["xkeen"], "has_xkeen_section": True, "settings_keys": ["verify_downloads", "killswitch"],
        "killswitch": {"status": "present", "value": "on"},
    },
    "init": {
        "assignment_count": 4, "top_level_count": 4, "indented_count": 0, "literal_count": 4, "expression_count": 0,
        "parameter_count": 4, "duplicate_names": [],
        "flags": {
            "start_auto": {"status": "present", "value": "on", "indented_count": 0},
            "proxy_dns": {"status": "present", "value": "off", "indented_count": 0},
            "proxy_router": {"status": "present", "value": "off", "indented_count": 0},
            "ipv6_support": {"status": "present", "value": "on", "indented_count": 0},
        },
    },
    "lists": {
        "port_exclude": port_list("port_exclude.lst", 2, 1, 1, 1),
        "port_proxying": port_list("port_proxying.lst", 1, 1, 0, 0),
        "ip_exclude": port_list("ip_exclude.lst", 1, 1, 0, None, 0),
    },
    "port_53": {
        "port": 53, "port_exclude_entry": True, "port_exclude_range": False, "port_proxying_entry": False,
        "port_proxying_range": False, "proxy_dns": {"status": "present", "value": "off"},
        "proxy_router": {"status": "present", "value": "off"},
    },
}
SOURCES = ("xray", "settings", "init", "port_exclude", "port_proxying", "ip_exclude")
LIST_NAMES = (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING, XKeenListName.IP_EXCLUDE)
UNAVAILABLE_CODES = {
    "xray": "xray_config_unavailable", "settings": "xkeen_settings_unavailable", "init": "xkeen_init_unavailable",
    "port_exclude": "xkeen_port_exclude_unavailable", "port_proxying": "xkeen_port_proxying_unavailable",
    "ip_exclude": "xkeen_ip_exclude_unavailable",
}
INVALID_CODES = {
    "xray": "invalid_xray_config", "settings": "invalid_xkeen_settings", "init": "invalid_xkeen_init",
    "port_exclude": "invalid_xkeen_port_exclude", "port_proxying": "invalid_xkeen_port_proxying",
    "ip_exclude": "invalid_xkeen_ip_exclude",
}


def calls_after_failure(index):
    """Источники после отказавшего не читаются; списки запрашиваются по именам."""
    scalar = tuple(1 if position <= index else 0 for position in range(3))
    lists = tuple(name for position, name in enumerate(LIST_NAMES) if position + 3 <= index)
    return (*scalar, lists)


def configure(sources, name, outcome):
    """Задать ответ или отказ источника по его имени в порядке чтения."""
    if name in LIST_FIELDS:
        sources.lists.set_response(LIST_FIELDS[name], outcome)
    else:
        getattr(sources, name).outcome = outcome


LIST_FIELDS = dict(zip(SOURCES[3:], LIST_NAMES))


def handler_for(sources, **options):
    return InspectProxyConfigHandler(sources.xray, sources.settings, sources.init, sources.lists, **options)


class InspectProxyConfigTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_proxy_sources()
        self.handler = handler_for(self.sources, operation_ids=lambda: "op-1")

    def execute(self, command=None):
        return self.handler.execute(InspectProxyConfig() if command is None else command)

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

    def test_snapshot_config_is_read_once_per_source_in_order(self):
        result = self.execute()
        self.assertEqual(result.to_dict(), {
            "contract_version": CONTRACT_VERSION, "operation_id": "op-1", "command": "inspect_proxy_config",
            "status": "succeeded", "error": None, "data": {"xray": EXPECTED_XRAY, "xkeen": EXPECTED_XKEEN},
        })
        self.assertEqual(self.sources.calls, (1, 1, 1, LIST_NAMES))
        self.assertIs(type(result.data), ProxyConfigView)
        self.assertEqual(result.data.xray.balancers[0].fallback_tag, "blocked")
        self.assertEqual(result.data.xray.rules[4].conditions[0].value_count, 16)
        self.assertEqual(result.data.xkeen.port_53.port_exclude_entry, True)
        self.assertEqual(result.data.xkeen.settings.killswitch.value, "on")
        self.assertEqual([flag.name for flag in result.data.xkeen.init.flags], list(EXPECTED_XKEEN["init"]["flags"]))
        self.assert_private(result)

    def test_wrong_command_and_version_do_not_read_sources(self):
        for command, code in (
            ("inspect", "invalid_command"),
            (None, "invalid_command"),
            (InspectProxyConfig(contract_version=True), "unsupported_contract_version"),
            (InspectProxyConfig(contract_version=CONTRACT_VERSION + 1), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                self.assert_failed(self.handler.execute(command), ErrorCategory.INVALID_REQUEST, code)
        self.assertEqual(self.sources.calls, (0, 0, 0, ()))

    def test_each_source_failure_has_distinct_code_and_stops_reading(self):
        for index, name in enumerate(SOURCES):
            with self.subTest(source=name):
                sources = snapshot_proxy_sources()
                configure(sources, name, OSError("Отказ источника: fixture-private fixture-password /fixture/ws"))
                result = handler_for(sources).execute(InspectProxyConfig())
                self.assert_failed(result, ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name])
                self.assertEqual(sources.calls, calls_after_failure(index))

    def test_invalid_source_data_has_distinct_codes_and_domain_reasons(self):
        class DerivedConfig(XrayConfigSet):
            pass

        class DerivedSettings(XKeenSettings):
            pass

        class DerivedInit(XKeenInitParameters):
            pass

        class DerivedList(XKeenList):
            pass

        tampered_config = snapshot_proxy_sources().xray.outcome
        object.__setattr__(tampered_config.parts[0], "sha256", "0" * 64)
        duplicated_config = snapshot_proxy_sources().xray.outcome
        object.__setattr__(duplicated_config, "parts", duplicated_config.parts[:1] * 2)
        tampered_settings = snapshot_xkeen_settings()
        object.__setattr__(tampered_settings.document, "_snapshot", '{"xkeen": {"note": "fixture-private"}}')
        assignment = XKeenInitAssignment("start_auto", '"on"', 2, False)
        tampered_init = XKeenInitParameters((assignment,))
        object.__setattr__(tampered_init, "assignments", (assignment, assignment))
        renamed_list = snapshot_xkeen_list(XKeenListName.PORT_EXCLUDE)
        object.__setattr__(renamed_list, "name", "fixture-private.lst")
        cases = (
            ("xray", None, None),
            ("xray", DerivedConfig(()), None),
            ("xray", tampered_config, "invalid_config_document"),
            ("xray", duplicated_config, "invalid_xray_parts"),
            ("settings", None, None),
            ("settings", DerivedSettings(snapshot_xkeen_settings().document), None),
            ("settings", tampered_settings, "invalid_config_document"),
            ("init", None, None),
            ("init", DerivedInit(()), None),
            ("init", tampered_init, "invalid_xkeen_init"),
            ("port_exclude", None, None),
            ("port_exclude", DerivedList(XKeenListName.PORT_EXCLUDE, b"53"), None),
            ("port_exclude", renamed_list, "invalid_xkeen_list"),
            ("port_exclude", snapshot_xkeen_list(XKeenListName.PORT_PROXYING), LIST_NAME_MISMATCH),
            ("port_proxying", snapshot_xkeen_list(XKeenListName.PORT_EXCLUDE), LIST_NAME_MISMATCH),
            ("port_proxying", None, None),
            ("ip_exclude", snapshot_xkeen_list(XKeenListName.PORT_EXCLUDE), LIST_NAME_MISMATCH),
            ("ip_exclude", "fixture-private", None),
        )
        for name, outcome, reason in cases:
            with self.subTest(source=name, outcome=type(outcome).__name__, reason=reason):
                sources = snapshot_proxy_sources()
                configure(sources, name, outcome)
                result = handler_for(sources).execute(InspectProxyConfig())
                self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, INVALID_CODES[name], reason)
                self.assertEqual(sources.calls, calls_after_failure(SOURCES.index(name)))

    def test_corrupted_nested_init_assignment_returns_source_error(self):
        for name, value in (
            ("raw", None), ("raw", '"on"\n'), ("name", None), ("name", "bad name"),
            ("line_number", 0), ("line_number", True), ("line_number", "3"), ("indented", None),
        ):
            with self.subTest(field=name, value=value):
                sources = snapshot_proxy_sources()
                object.__setattr__(sources.init.outcome.assignments[0], name, value)
                result = handler_for(sources).execute(InspectProxyConfig())
                self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, "invalid_xkeen_init", "invalid_xkeen_init")
                self.assertEqual(sources.calls, calls_after_failure(SOURCES.index("init")))

    def test_assembly_failure_is_reported_without_partial_result(self):
        def broken(*_args):
            raise XKeenConfigError(XKeenConfigErrorCode.CONFIG)

        with patch("keenvpn.application.proxy_config.assemble_xkeen_config", broken):
            result = self.execute()
        self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, "proxy_config_inconsistent", "invalid_xkeen_config")
        self.assertEqual(self.sources.calls, (1, 1, 1, LIST_NAMES))

    def test_interruptions_are_not_converted_to_source_failure(self):
        for name in SOURCES:
            for error in (KeyboardInterrupt(), SystemExit()):
                with self.subTest(source=name, error=type(error).__name__):
                    sources = snapshot_proxy_sources()
                    configure(sources, name, error)
                    with self.assertRaises(type(error)):
                        handler_for(sources).execute(InspectProxyConfig())

    def test_unconfigured_source_is_a_test_setup_error(self):
        for name, source_type in (
            ("xray", InMemoryXrayConfigSource), ("settings", InMemoryXKeenSettingsSource),
            ("init", InMemoryXKeenInitSource), ("lists", InMemoryXKeenListSource),
        ):
            with self.subTest(source=name):
                sources = {field: getattr(self.sources, field) for field in ("xray", "settings", "init", "lists")}
                sources[name] = source_type()
                handler = InspectProxyConfigHandler(sources["xray"], sources["settings"], sources["init"], sources["lists"])
                with self.assertRaises(UnconfiguredResponseError):
                    handler.execute(InspectProxyConfig())
                self.assertEqual(len(sources[name].calls) if name == "lists" else sources[name].calls, 1)
        with self.assertRaises(AdapterSetupError):
            InMemoryXrayConfigSource(OSError).current_xray_config()
        with self.assertRaises(AdapterSetupError):
            InMemoryXKeenListSource().set_response("port_exclude.lst", None)

    def test_scenario_has_no_terminal_or_external_effects(self):
        with forbid_external_effects():
            self.assertTrue(self.execute().succeeded)
            self.sources.lists.set_response(XKeenListName.IP_EXCLUDE, OSError("fixture-private"))
            self.assertEqual(self.execute().error.code, "xkeen_ip_exclude_unavailable")
            self.sources.init.outcome = None
            self.assertEqual(self.execute().error.code, "invalid_xkeen_init")

    def test_rendering_is_frozen_and_does_not_reread_sources(self):
        result = self.execute()
        calls = self.sources.calls
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertIn("trojan-out", str(result.data))
        self.assertEqual(self.sources.calls, calls)
        with self.assertRaises(FrozenInstanceError):
            result.data.xray = None
        with self.assertRaises(FrozenInstanceError):
            result.data.xray.rules[0].target_tag = "blocked"
        with self.assertRaises(FrozenInstanceError):
            result.data.xkeen.port_53.port_exclude_entry = False

    def test_long_numeric_list_entries_give_structured_result(self):
        long_number = ("1" * 5000).encode()
        for name in (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING):
            with self.subTest(list=name.value):
                sources = snapshot_proxy_sources()
                sources.lists.set_response(name, XKeenList(name, long_number + b"\n53-" + long_number + b"\n"))
                with forbid_external_effects():
                    result = handler_for(sources).execute(InspectProxyConfig())
                self.assertTrue(result.succeeded)
                view = result.data.xkeen.port_exclude if name is XKeenListName.PORT_EXCLUDE else result.data.xkeen.port_proxying
                self.assertEqual((view.entry_count, view.port_count, view.range_count, view.invalid_count), (2, 0, 0, 2))
                self.assert_private(result)

    def test_leading_zero_port_53_entries_are_reported_in_both_lists(self):
        for name, entry_field, range_field in (
            (XKeenListName.PORT_EXCLUDE, "port_exclude_entry", "port_exclude_range"),
            (XKeenListName.PORT_PROXYING, "port_proxying_entry", "port_proxying_range"),
        ):
            with self.subTest(list=name.value):
                sources = snapshot_proxy_sources()
                for item in (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING):
                    sources.lists.set_response(item, XKeenList(item, b""))
                sources.lists.set_response(name, XKeenList(name, b"000053\n000001:000100\n"))
                result = handler_for(sources).execute(InspectProxyConfig())
                self.assertTrue(result.succeeded)
                facts = result.data.xkeen.port_53
                self.assertEqual((getattr(facts, entry_field), getattr(facts, range_field)), (True, True))
                self.assert_private(result)

    def test_synthetic_sources_surface_flags_duplicates_and_ranges(self):
        sources = snapshot_proxy_sources()
        sources.xray.outcome = XrayConfigSet((
            ConfigDocument("a.json", b'{"outbounds": [{"tag": "out", "protocol": "freedom"}], "routing": {"rules": ['
                           b'{"type": "field", "balancerTag": "missing", "domain": ["fixture-private.example"]}]}}'),
            ConfigDocument("b.json", b'{"outbounds": "fixture-private"}'),
        ))
        sources.settings.outcome = XKeenSettings(ConfigDocument("xkeen.json", b'{"xkeen": {"killswitch": "yes"}}'))
        sources.init.outcome = parse_xkeen_init(b'start_auto="on"\nstart_auto="off"\n    proxy_router="on"\nproxy_dns="off"\n    proxy_dns="on"\n')
        sources.lists.set_response(XKeenListName.PORT_EXCLUDE, XKeenList(XKeenListName.PORT_EXCLUDE, b"1:1024\n"))
        sources.lists.set_response(XKeenListName.PORT_PROXYING, XKeenList(XKeenListName.PORT_PROXYING, b"53 # dns\n"))
        result = handler_for(sources, operation_ids=lambda: "op-2").execute(InspectProxyConfig())
        self.assertTrue(result.succeeded)
        data = result.data.to_dict()
        self.assertEqual(data["xray"]["duplicate_sections"], ["outbounds"])
        self.assertEqual(data["xray"]["unsupported_paths"], [{"part": "b.json", "path": "outbounds"}])
        self.assertEqual(data["xray"]["rules"][0]["target_resolved"], False)
        self.assertEqual(data["xray"]["rules"][0]["conditions"], {"domain": 1})
        self.assertEqual(data["xkeen"]["settings"]["killswitch"], {"status": "unexpected", "value": None})
        self.assertEqual(data["xkeen"]["init"]["duplicate_names"], ["proxy_dns", "start_auto"])
        self.assertEqual(data["xkeen"]["init"]["flags"]["start_auto"], {"status": "duplicate", "value": None, "indented_count": 0})
        self.assertEqual(data["xkeen"]["init"]["flags"]["proxy_router"], {"status": "unsupported", "value": None, "indented_count": 1})
        self.assertEqual(data["xkeen"]["init"]["flags"]["proxy_dns"], {"status": "duplicate", "value": None, "indented_count": 1})
        self.assertEqual(data["xkeen"]["port_53"], {
            "port": 53, "port_exclude_entry": False, "port_exclude_range": True, "port_proxying_entry": True,
            "port_proxying_range": False, "proxy_dns": {"status": "duplicate", "value": None},
            "proxy_router": {"status": "unsupported", "value": None},
        })
        self.assertEqual(data["xkeen"]["lists"]["port_exclude"]["range_count"], 1)
        self.assertEqual(data["xkeen"]["lists"]["port_proxying"]["comment_count"], 0)
        self.assert_private(result)


if __name__ == "__main__":
    unittest.main()
