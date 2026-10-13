"""Сценарий импорта правил Xray в модель на снимке и управляемых источниках."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.routing_import import (
    IMPORT_FAILED, ImportRoutingScheme, ImportRoutingSchemeHandler, RoutingSchemeView,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.routing import (
    DomainCondition, GeoDatabase, GeoIPCondition, GeoSiteCondition, IPCondition, RoutingErrorCode, RoutingRule,
    RoutingValidationError, UnknownCondition, UnsupportedRuleCondition,
)
from keenvpn.domain.routing_import import (
    ImportedRuleGroup, RoutingImportError, RoutingImportErrorCode, RoutingScheme, RuleTarget, import_routing_scheme,
)
from keenvpn.domain.routing_policy import FinalRoutingRule, RoutingPolicy
from keenvpn.domain.xkeen_config import XKeenConfig, XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import snapshot_proxy_sources, snapshot_xray_config


# Прогреть стандартные codec IDNA и Punycode: их ленивый импорт не относится к проверяемому коду.
"пример.рф".encode("idna")
"xn--e1afmkfd.xn--p1ai".encode("ascii").decode("idna")

PRIVATE_MARKERS = (
    "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "192.0.2.", "probe.example", "127.0.0.1",
    "/opt/var/log", "1181", "1191", "fixture-private", "Обезличенный", "geoip:", "geosite:", "domain:", "full:",
    '"ru"', "xn--p1ai", "dns-local", "a.example", "^x",
)
PRIVATE_TYPES = (
    ConfigDocument, XrayConfigSet, XKeenSettings, XKeenInitParameters, XKeenList, XKeenConfig, RoutingScheme,
    ImportedRuleGroup, RuleTarget, RoutingPolicy, RoutingRule, FinalRoutingRule, DomainCondition, IPCondition,
    GeoIPCondition, GeoSiteCondition, GeoDatabase, UnknownCondition, UnsupportedRuleCondition, BaseException,
)
SOURCES = ("xray", "settings", "init", "port_exclude", "port_proxying", "ip_exclude")
LIST_NAMES = (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING, XKeenListName.IP_EXCLUDE)
LIST_FIELDS = dict(zip(SOURCES[3:], LIST_NAMES))
UNAVAILABLE_CODES = {
    "xray": "xray_config_unavailable", "settings": "xkeen_settings_unavailable", "init": "xkeen_init_unavailable",
    "port_exclude": "xkeen_port_exclude_unavailable", "port_proxying": "xkeen_port_proxying_unavailable",
    "ip_exclude": "xkeen_ip_exclude_unavailable",
}


def calls_after_failure(index):
    scalar = tuple(1 if position <= index else 0 for position in range(3))
    lists = tuple(name for position, name in enumerate(LIST_NAMES) if position + 3 <= index)
    return (*scalar, lists)


def configure(sources, name, outcome):
    if name in LIST_FIELDS:
        sources.lists.set_response(LIST_FIELDS[name], outcome)
    else:
        getattr(sources, name).outcome = outcome


def handler_for(sources, **options):
    proxy = InspectProxyConfigHandler(sources.xray, sources.settings, sources.init, sources.lists)
    return ImportRoutingSchemeHandler(proxy, **options)


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


class ImportRoutingSchemeTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_proxy_sources()
        self.handler = handler_for(self.sources, operation_ids=lambda: "op-1")

    def execute(self, command=None):
        return self.handler.execute(ImportRoutingScheme() if command is None else command)

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

    def test_snapshot_view_matches_domain_diagnostic_and_reads_each_source_once(self):
        result = self.execute()
        self.assertEqual(result.to_dict(), {
            "contract_version": CONTRACT_VERSION, "operation_id": "op-1", "command": "import_routing_scheme",
            "status": "succeeded", "error": None, "data": import_routing_scheme(snapshot_xray_config()).to_diagnostic(),
        })
        self.assertEqual(self.sources.calls, (1, 1, 1, LIST_NAMES))
        self.assertIs(type(result.data), RoutingSchemeView)
        data = result.data
        self.assertEqual((data.routing_part, data.group_count, data.rule_count, data.final_action), ("05_routing.json", 8, 43, "VPN"))
        self.assertTrue(data.read_only)
        self.assertEqual(data.reasons, ())
        self.assertEqual(data.policy.rule_count, 43)
        self.assertEqual(data.groups[0].reasons, ("unsupported_conditions",))
        self.assertEqual(data.groups[0].unsupported_fields, ("inboundTag",))
        self.assertEqual(data.groups[3].target.fallback_tag, "blocked")
        self.assertEqual(data.groups[3].target.outbound_tags, ("trojan-out",))
        self.assertEqual([item.count for item in data.groups[4].condition_types], [16])
        self.assertEqual(data.groups[7].kind, "final")
        self.assert_private(result)

    def test_wrong_command_and_version_do_not_read_sources(self):
        for command, code in (
            ("import", "invalid_command"), (None, "invalid_command"),
            (ImportRoutingScheme(contract_version=True), "unsupported_contract_version"),
            (ImportRoutingScheme(contract_version=CONTRACT_VERSION + 1), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                self.assert_failed(self.handler.execute(command), ErrorCategory.INVALID_REQUEST, code)
        self.assertEqual(self.sources.calls, (0, 0, 0, ()))

    def test_proxy_source_failures_keep_their_codes_and_stop_reading(self):
        for index, name in enumerate(SOURCES):
            with self.subTest(source=name):
                sources = snapshot_proxy_sources()
                configure(sources, name, OSError("Отказ источника: fixture-private host-01.example"))
                result = handler_for(sources).execute(ImportRoutingScheme())
                self.assert_failed(result, ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name])
                self.assertEqual(sources.calls, calls_after_failure(index))
        sources = snapshot_proxy_sources()
        sources.xray.outcome = None
        self.assert_failed(handler_for(sources).execute(ImportRoutingScheme()), ErrorCategory.INVALID_SOURCE_DATA, "invalid_xray_config")
        self.assertEqual(sources.calls, calls_after_failure(0))
        sources = snapshot_proxy_sources()
        object.__setattr__(sources.settings.outcome.document, "name", "other.json")
        result = handler_for(sources).execute(ImportRoutingScheme())
        self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, "invalid_xkeen_settings", "invalid_xkeen_settings")
        self.assertEqual(sources.calls, calls_after_failure(1))

    def test_import_failure_is_reported_without_partial_result(self):
        for error, reason in (
            (RoutingImportError(RoutingImportErrorCode.CONFIG), "invalid_routing_import_config"),
            (RoutingValidationError(RoutingErrorCode.RULES), "invalid_rules"),
        ):
            with self.subTest(reason=reason), patch("keenvpn.application.routing_import.import_routing_scheme", side_effect=error):
                sources = snapshot_proxy_sources()
                result = handler_for(sources).execute(ImportRoutingScheme())
                self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, IMPORT_FAILED, reason)
                self.assertEqual(sources.calls, (1, 1, 1, LIST_NAMES))

    def test_read_returns_scheme_for_trusted_code(self):
        scheme = self.handler.read()
        self.assertIs(type(scheme), RoutingScheme)
        self.assertEqual(len(scheme.groups), 8)
        self.assertEqual(scheme.groups[1].conditions[1], DomainCondition("host-02.example"))
        self.sources.xray.outcome = OSError("fixture-private")
        self.assertEqual(self.handler.read().code, "xray_config_unavailable")

    def test_synthetic_sources_show_read_only_reasons_in_view(self):
        self.sources.xray.outcome = XrayConfigSet((
            part("04_outbounds.json", {"outbounds": [{"tag": "direct", "protocol": "freedom"}]}),
            part("05_routing.json", {"routing": {"rules": [
                {"type": "field", "domain": ["domain:a.example"], "port": "53", "outboundTag": "direct", "ruleTag": "fixture-rule"},
                {"type": "field", "domain": ["domain:a.example"], "balancerTag": "missing"},
                {"type": "field", "domain": ["regexp:^x", "full:a.example"], "outboundTag": "direct"},
            ]}}),
        ))
        with forbid_external_effects():
            result = self.execute()
        self.assertTrue(result.succeeded)
        data = result.to_dict()["data"]
        self.assertEqual((data["routing_part"], data["group_count"], data["rule_count"], data["final_action"]),
                         ("05_routing.json", 3, 3, None))
        self.assertEqual((data["read_only"], data["reasons"], data["policy"]), (True, ["final_rule_missing"], None))
        first, second, third = data["groups"]
        self.assertEqual((first["reasons"], first["unsupported_fields"], first["fields"], first["has_rule_tag"]),
                         (["unsupported_conditions"], ["port"], ["domain", "port"], True))
        self.assertEqual(first["unknown_field_count"], 0)
        self.assertEqual(first["condition_types"], {"UnsupportedRuleCondition": 1})
        self.assertEqual((second["action"], second["target"]["reasons"], second["target"]["kind"], second["target"]["tag"]),
                         (None, ["target_unresolved"], "balancer", "missing"))
        self.assertEqual(third["value_reasons"], [{"path": "routing.rules[2].domain[0]", "reason": "domain_regexp"}])
        self.assertEqual(third["condition_types"], {"UnknownCondition": 1, "DomainCondition": 1})
        self.assertTrue(third["read_only"] and second["read_only"] and first["read_only"])
        self.assertEqual(self.sources.calls, (1, 1, 1, LIST_NAMES))
        self.assert_private(result)

    def test_view_masks_tags_strategy_and_unknown_field_names(self):
        tag = "https://user:TEST_ONLY_PW@host.example/x"
        self.sources.xray.outcome = XrayConfigSet((
            part("04_outbounds.json", {"outbounds": [{"tag": tag, "protocol": "freedom"}, {"tag": "proxy-a", "protocol": "trojan"}]}),
            part("05_routing.json", {"routing": {
                "rules": [
                    {"domain": ["domain:a.example"], "outboundTag": tag, "/private/TEST_ONLY_KEY": True},
                    {"network": "tcp,udp", "balancerTag": "pool"},
                ],
                "balancers": [{"tag": "pool", "selector": ["proxy-"], "fallbackTag": tag, "strategy": {"type": "TEST_ONLY_STRATEGY"}}],
            }}),
        ))
        with forbid_external_effects():
            result = self.execute()
        self.assertTrue(result.succeeded)
        first, final = result.data.groups
        self.assertEqual((first.unknown_field_count, first.fields, first.target.tag, first.target.tag_known), (1, ("domain",), None, True))
        self.assertEqual((final.target.tag, final.target.outbound_tags, final.target.fallback_tag, final.target.fallback_known),
                         ("pool", ("proxy-a",), None, True))
        self.assertEqual((final.target.strategy, final.target.strategy_known), (None, True))
        text = repr(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in ("TEST_ONLY_PW", "host.example", "/private", "TEST_ONLY_KEY", "TEST_ONLY_STRATEGY"):
            self.assertNotIn(marker, text)
        self.assert_private(result)

    def test_empty_unknown_key_does_not_fail_the_scenario(self):
        document = b'{"routing": {"rules": [{"domain": ["domain:a.example"], "": 1, "outboundTag": "direct"}, ' \
                   b'{"network": "tcp,udp", "outboundTag": "direct"}]}}'
        routing = ConfigDocument("05_routing.json", document)
        self.sources.xray.outcome = XrayConfigSet((
            ConfigDocument("04_outbounds.json", b'{"outbounds": [{"tag": "direct", "protocol": "freedom"}]}'), routing,
        ))
        result = self.execute()
        self.assertTrue(result.succeeded)
        group = result.data.groups[0]
        self.assertEqual((group.fields, group.unknown_field_count, group.reasons, group.read_only),
                         (("domain",), 1, ("unknown_fields",), True))
        self.assertEqual(routing.content, document)
        self.assert_private(result)

    def test_view_hides_address_and_domain_like_tags(self):
        self.sources.xray.outcome = XrayConfigSet((
            part("04_outbounds.json", {"outbounds": [
                {"tag": "198.51.100.7", "protocol": "freedom"}, {"tag": "private.example.test", "protocol": "trojan"},
                {"tag": "proxy-safe", "protocol": "trojan"},
            ]}),
            part("05_routing.json", {"routing": {
                "rules": [
                    {"domain": ["domain:a.example"], "outboundTag": "198.51.100.7"},
                    {"network": "tcp,udp", "balancerTag": "pool"},
                ],
                "balancers": [{"tag": "pool", "selector": ["pr"], "fallbackTag": "198.51.100.7"}],
            }}),
        ))
        result = self.execute()
        self.assertTrue(result.succeeded)
        first, final = result.data.groups
        self.assertEqual((first.target.tag, first.target.tag_known, first.target.outbound_tags), (None, True, (None,)))
        self.assertEqual((final.target.tag, final.target.outbound_tags, final.target.fallback_tag, final.target.fallback_known),
                         ("pool", (None, "proxy-safe"), None, True))
        self.assertEqual((first.action, final.action), ("DIRECT", "VPN"))
        text = repr(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in ("198.51.100.7", "private.example.test", "example.test"):
            self.assertNotIn(marker, text)

    def test_interruptions_are_not_converted_to_source_failure(self):
        for name in SOURCES:
            for error in (KeyboardInterrupt(), SystemExit()):
                with self.subTest(source=name, error=type(error).__name__):
                    sources = snapshot_proxy_sources()
                    configure(sources, name, error)
                    with self.assertRaises(type(error)):
                        handler_for(sources).execute(ImportRoutingScheme())

    def test_scenario_has_no_terminal_or_external_effects(self):
        with forbid_external_effects():
            self.assertTrue(self.execute().succeeded)
            self.sources.xray.outcome = XrayConfigSet(())
            self.assertEqual(self.execute().data.reasons, ("routing_missing",))
            self.sources.lists.set_response(XKeenListName.IP_EXCLUDE, OSError("fixture-private"))
            self.assertEqual(self.execute().error.code, "xkeen_ip_exclude_unavailable")

    def test_rendering_is_frozen_and_does_not_reread_sources(self):
        result = self.execute()
        calls = self.sources.calls
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertIn("vpn-group", str(result.data))
        self.assertEqual(self.sources.calls, calls)
        for model, field in ((result.data, "groups"), (result.data.groups[0], "action"), (result.data.groups[0].target, "tag"),
                             (result.data.policy, "read_only")):
            with self.assertRaises(FrozenInstanceError):
                setattr(model, field, None)


if __name__ == "__main__":
    unittest.main()
