"""Импорт правил Xray в модель: порядок, группы, неизвестные значения, назначения и безопасный вывод."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.routing import (
    DomainCondition, DomainMatch, GeoDatabase, GeoDatabaseKind, GeoIPCondition, GeoSiteCondition, IPCondition,
    RoutingAction, RoutingErrorCode, RoutingRule, RoutingValidationError, UnknownCondition, UnsupportedRuleCondition,
)
from keenvpn.domain.routing_explanation import DomainSource, ExplanationReason, IPSource, RoutingContext, explain_route
from keenvpn.domain.routing_import import (
    ImportReason, ImportedRuleGroup, RoutingImportError, RoutingImportErrorCode, RoutingScheme, RuleGroupKind,
    RuleTarget, ValueReason, _effective_outbounds, _outbound_action, _select_outbounds, import_routing_scheme,
    validate_routing_scheme,
)
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy
from keenvpn.domain.xray_config import RuleTargetKind, XrayConfigSet, validate_xray_config_set
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import snapshot_xray_config


# Прогреть стандартные codec IDNA и Punycode: их ленивый импорт не относится к проверяемому коду.
"пример.рф".encode("idna")
"xn--e1afmkfd.xn--p1ai".encode("ascii").decode("idna")


PRIVATE_MARKERS = (
    "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "192.0.2.", "probe.example",
    "127.0.0.1", "geoip:", "geosite:", "domain:", "full:", '"ru"', "xn--p1ai", "dns-local", "fixture-private",
    "0.0.0.0", "fc00::",
)
DIRECT, VPN, BLOCK = RoutingAction.DIRECT, RoutingAction.VPN, RoutingAction.BLOCK
OUTBOUNDS = [
    {"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"},
    {"tag": "proxy-one", "protocol": "trojan"}, {"tag": "proxy-two", "protocol": "VLESS"},
]
FINAL = {"type": "field", "network": "tcp,udp", "balancerTag": "pool"}
BALANCERS = [{"tag": "pool", "selector": ["proxy-"], "fallbackTag": "blocked", "strategy": {"type": "leastPing"}}]


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


def scheme_for(rules, *, balancers=BALANCERS, outbounds=OUTBOUNDS, extra_parts=()):
    parts = [part("04_outbounds.json", {"outbounds": outbounds})]
    routing = {"rules": rules}
    if balancers is not None:
        routing["balancers"] = balancers
    parts.append(part("05_routing.json", {"routing": routing}))
    parts.extend(extra_parts)
    return import_routing_scheme(XrayConfigSet(tuple(sorted(parts, key=lambda item: item.name))))


def rule(**fields):
    return {"type": "field", **fields}


def final(**target):
    """Правило для остатка трафика в поддержанной форме: только `network` из `tcp` и `udp`."""
    return {"network": "tcp,udp", **target}


def geo(kind, file_name, set_name):
    database = GeoDatabase(kind, file_name)
    return GeoIPCondition(database, set_name) if kind is GeoDatabaseKind.GEOIP else GeoSiteCondition(database, set_name)


class SnapshotRoutingImportTests(unittest.TestCase):
    def setUp(self):
        self.config = snapshot_xray_config()
        with forbid_external_effects():
            self.scheme = import_routing_scheme(self.config)

    def test_groups_keep_file_order_values_and_explicit_actions(self):
        groups = self.scheme.groups
        self.assertEqual(self.scheme.routing_part, "05_routing.json")
        self.assertEqual(self.scheme.routing_parts, ("05_routing.json",))
        self.assertEqual(self.scheme.reasons, ())
        self.assertEqual(
            [(g.index, g.kind.value, [type(c).__name__ for c in g.conditions], g.action, g.read_only, g.reasons) for g in groups],
            [
                (0, "rules", ["UnsupportedRuleCondition"], DIRECT, True, (ImportReason.UNSUPPORTED_CONDITIONS,)),
                (1, "rules", ["DomainCondition"] * 3, DIRECT, False, ()),
                (2, "rules", ["UnsupportedRuleCondition"], VPN, True, (ImportReason.UNSUPPORTED_CONDITIONS,)),
                (3, "rules", ["DomainCondition"] * 2, VPN, False, ()),
                (4, "rules", ["DomainCondition"] * 16, DIRECT, False, ()),
                (5, "rules", ["IPCondition"] * 19, DIRECT, False, ()),
                (6, "rules", ["GeoIPCondition"], DIRECT, False, ()),
                (7, "final", [], VPN, False, ()),
            ],
        )
        self.assertEqual([g.unsupported_fields for g in groups], [("inboundTag",), (), ("inboundTag",), (), (), (), (), ()])
        self.assertEqual([g.fields for g in groups], [
            ("inboundTag",), ("domain",), ("inboundTag",), ("domain",), ("domain",), ("ip",), ("ip",), ("network",),
        ])
        self.assertTrue(all(g.has_rule_tag and g.unknown_fields == () and g.value_reasons == () for g in groups))
        self.assertEqual([g.value_count for g in groups], [0, 3, 0, 2, 16, 19, 1, 0])
        self.assertEqual(groups[0].conditions[0], UnsupportedRuleCondition(("inboundTag",), '{"inboundTag":["dns-local"]}'))
        self.assertEqual(groups[1].conditions, (
            DomainCondition("localhost", DomainMatch.EXACT), DomainCondition("host-02.example"),
            DomainCondition("host-03.example", DomainMatch.EXACT),
        ))
        self.assertEqual([c.value for c in groups[4].conditions[9:14]], ["ru", "host-15.example", "host-16.example", "su", "xn--p1ai"])
        self.assertTrue(all(c.mode is DomainMatch.SUBDOMAINS for c in groups[4].conditions))
        self.assertEqual(groups[5].conditions[0], IPCondition("0.0.0.0/8"))
        self.assertEqual(groups[5].conditions[-1], IPCondition("ff00::/8"))
        self.assertEqual(groups[6].conditions, (geo(GeoDatabaseKind.GEOIP, "geoip.dat", "ru"),))
        self.assertIsNone(groups[6].conditions[0].database.version)
        for index in (2, 3, 7):
            self.assertEqual(groups[index].target, RuleTarget(
                RuleTargetKind.BALANCER, "vpn-group", ("trojan-out",), "blocked", "leastPing", VPN, (),
            ))
        self.assertEqual(groups[0].target, RuleTarget(RuleTargetKind.OUTBOUND, "direct", ("direct",), None, None, DIRECT, ()))

    def test_policy_preserves_group_order_without_protected_or_disabled_rules(self):
        policy = self.scheme.policy
        self.assertIs(type(policy), RoutingPolicy)
        self.assertEqual(policy.rules, tuple(r for g in self.scheme.groups[:-1] for r in g.rules))
        self.assertEqual(len(policy.rules), 43)
        self.assertEqual(policy.final_rule, FinalRoutingRule(VPN))
        self.assertIs(self.scheme.final_action, VPN)
        self.assertTrue(policy.read_only and self.scheme.read_only)
        self.assertTrue(all(r.enabled and not r.protected for r in policy.rules))
        self.assertEqual([r.action for r in policy.rules[:6]], [DIRECT, DIRECT, DIRECT, DIRECT, VPN, VPN])
        self.assertEqual(policy.to_diagnostic(), {
            "rule_count": 43, "active_rule_count": 43, "protected_rule_count": 0, "final_action": "VPN", "read_only": True,
        })
        # Неподдержанное правило в начале останавливает выбор и объяснение, а не подменяется.
        with self.assertRaises(RoutingValidationError) as caught:
            policy.select_first(lambda _condition: MatchResult.NO_MATCH)
        self.assertIs(caught.exception.code, RoutingErrorCode.MATCH_UNKNOWN)
        report = explain_route(policy, RoutingContext(domain="host-02.example", domain_source=DomainSource.DESTINATION))
        self.assertIsNone(report.selection)
        self.assertIs(report.steps[0].reason, ExplanationReason.UNSUPPORTED)
        validate_routing_scheme(self.scheme)

    def test_import_does_not_change_parts_and_exports_each_once(self):
        before = [(p.name, p.content, p.sha256) for p in self.config.parts]
        with patch.object(ConfigDocument, "export", autospec=True, side_effect=ConfigDocument.export) as export:
            scheme = import_routing_scheme(self.config)
        self.assertEqual(export.call_count, len(self.config.parts))
        self.assertEqual([(p.name, p.content, p.sha256) for p in self.config.parts], before)
        validate_xray_config_set(self.config)
        self.assertEqual(scheme.to_diagnostic(), self.scheme.to_diagnostic())
        self.assertEqual(self.config.to_diagnostic(), snapshot_xray_config().to_diagnostic())

    def test_diagnostic_and_repr_hide_values_and_rule_tags(self):
        diagnostic = self.scheme.to_diagnostic()
        self.assertEqual(json.loads(json.dumps(diagnostic)), diagnostic)
        self.assertEqual(
            {key: value for key, value in diagnostic.items() if key != "groups"},
            {
                "routing_part": "05_routing.json", "routing_parts": ["05_routing.json"], "group_count": 8, "rule_count": 43,
                "final_action": "VPN", "read_only": True, "reasons": [],
                "policy": {"rule_count": 43, "active_rule_count": 43, "protected_rule_count": 0, "final_action": "VPN", "read_only": True},
            },
        )
        self.assertEqual(diagnostic["groups"][4], {
            "part": "05_routing.json", "index": 4, "kind": "rules", "condition_count": 16, "condition_types": {"DomainCondition": 16},
            "value_count": 16, "fields": ["domain"], "unsupported_fields": [], "unknown_field_count": 0, "has_rule_tag": True,
            "action": "DIRECT", "read_only": False, "reasons": [], "value_reasons": [],
            "target": {"kind": "outbound", "tag_known": True, "tag": "direct", "outbound_tags": ["direct"],
                       "fallback_known": False, "fallback_tag": None, "strategy_known": False, "strategy": None,
                       "action": "DIRECT", "reasons": []},
        })
        self.assertEqual(diagnostic["groups"][7]["target"], {
            "kind": "balancer", "tag_known": True, "tag": "vpn-group", "outbound_tags": ["trojan-out"],
            "fallback_known": True, "fallback_tag": "blocked", "strategy_known": True, "strategy": "leastPing",
            "action": "VPN", "reasons": [],
        })
        self.assertEqual(diagnostic["groups"][7]["unsupported_fields"], [])
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(self.scheme) + repr(self.scheme.groups)
        text += repr(self.scheme.policy) + repr(self.scheme.policy.rules) + str(self.scheme.groups[0].conditions)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertEqual(repr(self.scheme), "RoutingScheme(groups=8, policy=True)")
        self.assertEqual(repr(self.scheme.groups[6]), "ImportedRuleGroup(part='05_routing.json', index=6, kind=rules)")


class ValueTranslationTests(unittest.TestCase):
    def translate(self, key, values):
        scheme = scheme_for([rule(**{key: values, "outboundTag": "direct"}), FINAL])
        group = scheme.groups[0]
        self.assertEqual(group.reasons, ())
        self.assertEqual(group.value_count, len(values))
        reasons = {item.path.rsplit("[", 1)[1].rstrip("]"): item.reason for item in group.value_reasons}
        return group.conditions, [reasons.get(str(index)) for index in range(len(values))], scheme

    def test_domain_values_follow_parse_domain_rule_order(self):
        values = [
            "domain:a.example", "full:b.example", "regexp:^a", "keyword:x", "dotless:", "plain.example",
            "domain:Upper.example", "domain:a.example.", "domain:пример.рф", "domain:bad..name", "geosite:cn",
            "geosite:cn@ads", "geosite:", "ext:custom.dat:list", "ext-domain:custom.dat:list", "ext:bad", "ext:a:b:c",
            "GEOSITE:cn", "domain:localhost", "full:a.example,b.example",
        ]
        conditions, reasons, scheme = self.translate("domain", values)
        R = ImportReason
        expected = [
            (DomainCondition("a.example"), None), (DomainCondition("b.example", DomainMatch.EXACT), None),
            (UnknownCondition, R.DOMAIN_REGEXP), (UnknownCondition, R.DOMAIN_KEYWORD), (UnknownCondition, R.DOMAIN_DOTLESS),
            (UnknownCondition, R.DOMAIN_PLAIN), (UnknownCondition, R.DOMAIN_NOT_CANONICAL),
            (UnknownCondition, R.DOMAIN_NOT_CANONICAL), (UnknownCondition, R.DOMAIN_NOT_CANONICAL),
            (UnknownCondition, R.DOMAIN_UNSUPPORTED), (geo(GeoDatabaseKind.GEOSITE, "geosite.dat", "cn"), None),
            (UnknownCondition, R.GEOSITE_ATTRIBUTES), (UnknownCondition, R.GEO_REFERENCE_UNSUPPORTED),
            (geo(GeoDatabaseKind.GEOSITE, "custom.dat", "list"), None), (geo(GeoDatabaseKind.GEOSITE, "custom.dat", "list"), None),
            (UnknownCondition, R.GEO_REFERENCE_UNSUPPORTED), (UnknownCondition, R.GEO_REFERENCE_UNSUPPORTED),
            (UnknownCondition, R.DOMAIN_PLAIN), (DomainCondition("localhost"), None),
            (UnknownCondition, R.DOMAIN_UNSUPPORTED),
        ]
        for index, (condition, reason) in enumerate(expected):
            with self.subTest(index=index):
                if condition is UnknownCondition:
                    self.assertEqual(conditions[index], UnknownCondition(conditions[index].family, values[index]))
                    self.assertEqual(conditions[index].family.value, "domain")
                else:
                    self.assertEqual(conditions[index], condition)
                self.assertEqual(reasons[index], reason)
        self.assertEqual(scheme.groups[0].value_reasons[0], ValueReason("routing.rules[0].domain[2]", R.DOMAIN_REGEXP))
        self.assertTrue(scheme.groups[0].read_only and scheme.policy.read_only)

    def test_ip_values_follow_to_cidr_list_order(self):
        values = [
            "192.0.2.0/24", "2001:DB8::1", "192.0.2.1", "192.0.2.1/32", "192.0.2.1/24", "192.0.2.0/024", "geoip:ru",
            "geoip:!ru", "geoip:", "ext:custom.dat:ru", "ext-ip:custom.dat:!ru", "ext:custom.dat:", "example.test",
            "GEOIP:ru", "fe80::1%eth0", "geoip:bad set",
        ]
        conditions, reasons, _scheme = self.translate("ip", values)
        R = ImportReason
        expected = [
            (IPCondition("192.0.2.0/24"), None), (IPCondition("2001:db8::1"), None), (IPCondition("192.0.2.1"), None),
            (IPCondition("192.0.2.1/32"), None), (UnknownCondition, R.IP_UNSUPPORTED), (UnknownCondition, R.IP_UNSUPPORTED),
            (geo(GeoDatabaseKind.GEOIP, "geoip.dat", "ru"), None), (UnknownCondition, R.GEOIP_NEGATED),
            (UnknownCondition, R.GEO_REFERENCE_UNSUPPORTED), (geo(GeoDatabaseKind.GEOIP, "custom.dat", "ru"), None),
            (UnknownCondition, R.GEOIP_NEGATED), (UnknownCondition, R.GEO_REFERENCE_UNSUPPORTED),
            (UnknownCondition, R.IP_UNSUPPORTED), (UnknownCondition, R.IP_UNSUPPORTED), (UnknownCondition, R.IP_UNSUPPORTED),
            (UnknownCondition, R.SET_NAME_UNSUPPORTED),
        ]
        for index, (condition, reason) in enumerate(expected):
            with self.subTest(index=index):
                if condition is UnknownCondition:
                    self.assertEqual(conditions[index], UnknownCondition(conditions[index].family, values[index]))
                    self.assertEqual(conditions[index].family.value, "ip")
                else:
                    self.assertEqual(conditions[index], condition)
                self.assertEqual(reasons[index], reason)
        self.assertNotEqual(conditions[2], conditions[3])

    def test_ipv4_mapped_values_stay_unknown_like_xray_ip_address(self):
        # IPAddress Xray v26.3.27 сводит ::ffff:a.b.c.d к IPv4 и применяет маску IPv4.
        values = ["::ffff:192.0.2.1", "::ffff:c000:201", "::ffff:192.0.2.1/128", "::ffff:0:0/96", "::/0", "::1",
                  "::192.0.2.1", "2001:db8::/32"]
        conditions, reasons, scheme = self.translate("ip", values)
        for index in range(4):
            with self.subTest(value=values[index]):
                self.assertEqual(conditions[index], UnknownCondition(conditions[index].family, values[index]))
                self.assertIs(reasons[index], ImportReason.IP_IPV4_MAPPED)
        self.assertEqual(conditions[4:], (IPCondition("::/0"), IPCondition("::1"), IPCondition("::192.0.2.1"),
                                          IPCondition("2001:db8::/32")))
        self.assertEqual(reasons[4:], [None] * 4)
        self.assertTrue(scheme.groups[0].read_only and scheme.policy.read_only)
        report = explain_route(scheme.policy, RoutingContext(ips=("192.0.2.1",), ip_source=IPSource.DESTINATION,
                                                             domain_source=DomainSource.UNAVAILABLE))
        self.assertIsNone(report.selection)
        self.assertIs(report.steps[0].reason, ExplanationReason.UNSUPPORTED)

    def test_string_list_form_and_domains_field_keep_one_group_in_order(self):
        scheme = scheme_for([
            rule(domain="domain:a.example,domain:b.example", domains=["full:c.example"], outboundTag="direct"),
            rule(domain=["domain:a.example,domain:b.example"], outboundTag="direct"),
            FINAL,
        ])
        first, second = scheme.groups[:2]
        self.assertEqual(first.conditions, (
            DomainCondition("a.example"), DomainCondition("b.example"), DomainCondition("c.example", DomainMatch.EXACT),
        ))
        self.assertEqual((first.fields, first.value_count, first.reasons, first.read_only), (("domain", "domains"), 3, (), False))
        self.assertEqual(second.conditions, (UnknownCondition(second.conditions[0].family, "domain:a.example,domain:b.example"),))
        self.assertEqual(second.value_reasons, (ValueReason("routing.rules[1].domain[0]", ImportReason.DOMAIN_UNSUPPORTED),))
        self.assertEqual(scheme.policy.rules[:3], first.rules)
        self.assertEqual(scheme.policy.rules[3], second.rules[0])
        self.assertEqual(len(scheme.policy.rules), 4)


class GroupTranslationTests(unittest.TestCase):
    def test_fields_outside_the_model_keep_the_whole_rule_as_one_placeholder(self):
        cases = (
            ({"domain": ["domain:a.example"], "ip": ["192.0.2.0/24"]}, (ImportReason.CONDITIONS_COMBINED,), 2),
            ({"domain": ["domain:a.example"], "port": "53"}, (ImportReason.UNSUPPORTED_CONDITIONS,), 1),
            ({"inboundTag": ["lan"], "network": "tcp"}, (ImportReason.UNSUPPORTED_CONDITIONS,), 0),
            ({"domain": ["domain:a.example"], "enabled": False}, (ImportReason.UNKNOWN_FIELDS,), 1),
            ({"Domain": ["domain:a.example"]}, (ImportReason.UNKNOWN_FIELDS, ImportReason.FIELD_CASE_VARIANT), 0),
            ({"domain": None}, (ImportReason.VALUES_INVALID,), 0),
            ({"domain": [7, "domain:a.example"]}, (ImportReason.VALUES_INVALID,), 0),
            ({"domain": 7}, (ImportReason.VALUES_INVALID,), 0),
            ({"domain": []}, (ImportReason.VALUES_EMPTY,), 0),
            ({"domain": ""}, (ImportReason.VALUES_EMPTY,), 1),
            ({"domain": ["domain:a.example", ""]}, (ImportReason.VALUES_EMPTY,), 2),
            ({"ip": [], "domain": ["domain:a.example"]}, (ImportReason.VALUES_EMPTY, ImportReason.CONDITIONS_COMBINED), 1),
            ({"domain": ["domain:a.example"], "sourceIP": None, "comment": "x"},
             (ImportReason.UNSUPPORTED_CONDITIONS, ImportReason.UNKNOWN_FIELDS), 1),
        )
        for fields, reasons, value_count in cases:
            with self.subTest(fields=list(fields)):
                scheme = scheme_for([{**fields, "outboundTag": "direct", "ruleTag": "fixture-rule"}, FINAL])
                group = scheme.groups[0]
                names = tuple(fields)
                self.assertEqual(group.conditions, (UnsupportedRuleCondition(names, json.dumps(fields, separators=(",", ":"))),))
                self.assertEqual((group.reasons, group.value_count, group.fields), (reasons, value_count, names))
                self.assertTrue(group.read_only and group.has_rule_tag)
                self.assertIs(group.action, DIRECT)
                self.assertEqual(scheme.policy.rules, (RoutingRule(group.conditions[0], DIRECT),))
                self.assertTrue(scheme.policy.read_only)
                self.assertEqual(scheme.reasons, ())
                text = json.dumps(group.to_diagnostic()) + repr(group.conditions)
                self.assertNotIn("a.example", text)
                self.assertNotIn("fixture-rule", text)

    def test_empty_unknown_key_keeps_group_read_only_without_failing_import(self):
        config = XrayConfigSet((
            part("04_outbounds.json", {"outbounds": OUTBOUNDS}),
            part("05_routing.json", {"routing": {"rules": [
                {"domain": ["domain:a.example"], "": 1, "outboundTag": "direct"}, {"": None, "outboundTag": "direct"}, FINAL,
            ], "balancers": BALANCERS}}),
        ))
        before = [(item.content, item.sha256) for item in config.parts]
        scheme = import_routing_scheme(config)
        first, second, last = scheme.groups
        self.assertEqual((first.fields, first.unknown_fields, first.reasons), (("domain", ""), ("",), (ImportReason.UNKNOWN_FIELDS,)))
        self.assertEqual(first.conditions, (UnsupportedRuleCondition(("domain", ""), '{"domain":["domain:a.example"],"":1}'),))
        self.assertEqual((second.fields, second.reasons), (("",), (ImportReason.UNKNOWN_FIELDS,)))
        self.assertTrue(first.read_only and second.read_only)
        self.assertIs(last.kind, RuleGroupKind.FINAL)
        self.assertEqual(scheme.groups[0].to_diagnostic()["fields"], ["domain"])
        self.assertEqual(scheme.groups[0].to_diagnostic()["unknown_field_count"], 1)
        self.assertTrue(scheme.policy.read_only)
        validate_routing_scheme(scheme)
        self.assertEqual([(item.content, item.sha256) for item in config.parts], before)

    def test_type_field_is_ignored_like_the_installed_decoder(self):
        scheme = scheme_for([{"type": "chinasites", "domain": ["domain:a.example"], "outboundTag": "direct"},
                             {"domain": ["domain:b.example"], "outboundTag": "direct"}, {"network": "tcp,udp", "outboundTag": "direct"}])
        self.assertEqual([g.reasons for g in scheme.groups], [(), (), ()])
        self.assertEqual([g.fields for g in scheme.groups], [("domain",), ("domain",), ("network",)])
        self.assertEqual([g.has_rule_tag for g in scheme.groups], [False, False, False])
        self.assertIs(scheme.final_action, DIRECT)

    def test_rule_without_conditions_is_not_a_final_rule(self):
        # BuildCondition Xray v26.3.27 отклоняет правило без условий: маршрутизатор не запускается.
        for rules, kinds in (
            ([rule(domain=["domain:a.example"], outboundTag="direct"), {"type": "field", "outboundTag": "direct", "ruleTag": "x"}],
             ["rules", "rules"]),
            ([{"balancerTag": "pool"}, FINAL], ["rules", "final"]),
        ):
            with self.subTest(rules=rules):
                scheme = scheme_for(rules)
                self.assertEqual([g.kind.value for g in scheme.groups], kinds)
                placeholder = next(g for g in scheme.groups if not g.fields)
                self.assertEqual(placeholder.conditions, (UnsupportedRuleCondition((), "{}"),))
                self.assertEqual(placeholder.reasons, (ImportReason.RULE_WITHOUT_CONDITIONS,))
                self.assertTrue(placeholder.read_only)
                self.assertTrue(scheme.read_only)
        self.assertEqual(scheme_for([{"outboundTag": "direct"}]).reasons, (ImportReason.FINAL_RULE_MISSING,))
        self.assertIsNone(scheme_for([{"outboundTag": "direct"}]).policy)

    def test_rule_that_is_not_an_object_is_kept_in_place(self):
        scheme = scheme_for([rule(domain=["domain:a.example"], outboundTag="direct"), "fixture-private", 7, FINAL])
        self.assertEqual([g.kind.value for g in scheme.groups], ["rules", "rules", "rules", "final"])
        for index, snapshot in ((1, '"fixture-private"'), (2, "7")):
            group = scheme.groups[index]
            self.assertEqual(group.conditions, (UnsupportedRuleCondition((), snapshot),))
            self.assertEqual(group.reasons, (ImportReason.RULE_NOT_OBJECT,))
            self.assertEqual(group.target, RuleTarget(RuleTargetKind.NONE, None, (), None, None, None, (ImportReason.RULE_NOT_OBJECT,)))
            self.assertIsNone(group.action)
            self.assertEqual(group.rules, ())
        self.assertIsNone(scheme.policy)
        self.assertEqual(scheme.reasons, (ImportReason.RULE_ACTION_UNRESOLVED,))
        self.assertNotIn("fixture-private", json.dumps(scheme.to_diagnostic()))


class TargetResolutionTests(unittest.TestCase):
    OUTBOUNDS = [
        *OUTBOUNDS, {"tag": "dns-out", "protocol": "dns"}, {"tag": "dup", "protocol": "freedom"},
        {"tag": "dup", "protocol": "blackhole"}, {"tag": "notype"}, {"tag": "twin", "protocol": "trojan"},
        {"tag": "twin", "protocol": "trojan"}, {"protocol": "freedom"}, {"tag": "", "protocol": "freedom"},
    ]
    BALANCERS = [
        *BALANCERS,
        {"tag": "mixed", "selector": ["proxy-one", "direct"]},
        {"tag": "all", "selector": ""},
        {"tag": "prefix", "selector": "proxy-o,none-", "fallbackTag": ""},
        {"tag": "empty", "selector": ["none-"]},
        {"tag": "noselector"},
        {"tag": "dupb", "selector": ["proxy-one"]}, {"tag": "dupb", "selector": ["proxy-one"]},
        {"tag": "nofb", "selector": ["proxy-one"], "fallbackTag": "missing"},
        {"tag": "dupfb", "selector": ["proxy-one"], "fallbackTag": "dup"},
        {"tag": "badsel", "selector": 7},
        {"tag": "badstrategy", "selector": ["proxy-one"], "strategy": "leastPing"},
        {"tag": "badfb", "selector": ["proxy-one"], "fallbackTag": 7},
        {"tag": "unsupported", "selector": ["dns-out"]},
        {"tag": "dupsel", "selector": ["twin"]},
    ]

    def target(self, **fields):
        scheme = scheme_for([rule(domain=["domain:a.example"], **fields), FINAL], balancers=self.BALANCERS, outbounds=self.OUTBOUNDS)
        return scheme.groups[0].target, scheme

    def test_outbound_targets_map_only_explicit_protocols(self):
        R, K = ImportReason, RuleTargetKind
        cases = (
            ({"outboundTag": "direct"}, RuleTarget(K.OUTBOUND, "direct", ("direct",), None, None, DIRECT, ())),
            ({"outboundTag": "blocked"}, RuleTarget(K.OUTBOUND, "blocked", ("blocked",), None, None, BLOCK, ())),
            ({"outboundTag": "proxy-two"}, RuleTarget(K.OUTBOUND, "proxy-two", ("proxy-two",), None, None, VPN, ())),
            ({"outboundTag": "dns-out"}, RuleTarget(K.OUTBOUND, "dns-out", (), None, None, None, (R.OUTBOUND_PROTOCOL_UNSUPPORTED,))),
            ({"outboundTag": "notype"}, RuleTarget(K.OUTBOUND, "notype", (), None, None, None, (R.OUTBOUND_PROTOCOL_UNSUPPORTED,))),
            ({"outboundTag": "missing"}, RuleTarget(K.OUTBOUND, "missing", (), None, None, None, (R.TARGET_UNRESOLVED,))),
            ({"outboundTag": "dup"}, RuleTarget(K.OUTBOUND, "dup", (), None, None, None, (R.TARGET_DUPLICATE,))),
            ({"outboundTag": "direct", "balancerTag": "pool"}, RuleTarget(K.BOTH, None, (), None, None, None, (R.TARGET_AMBIGUOUS,))),
            ({"outboundTag": "", "balancerTag": "pool"}, RuleTarget(K.BALANCER, "pool", ("proxy-one", "proxy-two"), "blocked", "leastPing", VPN, ())),
            ({"outboundTag": None, "balancerTag": "pool"}, RuleTarget(K.BALANCER, "pool", ("proxy-one", "proxy-two"), "blocked", "leastPing", VPN, ())),
            ({}, RuleTarget(K.NONE, None, (), None, None, None, (R.TARGET_MISSING,))),
            ({"outboundTag": ""}, RuleTarget(K.NONE, None, (), None, None, None, (R.TARGET_MISSING,))),
            ({"outboundTag": 5}, RuleTarget(K.NONE, None, (), None, None, None, (R.TARGET_INVALID,))),
            ({"balancerTag": ["pool"]}, RuleTarget(K.NONE, None, (), None, None, None, (R.TARGET_INVALID,))),
        )
        for fields, expected in cases:
            with self.subTest(fields=fields):
                target, scheme = self.target(**fields)
                self.assertEqual(target, expected)
                self.assertEqual(scheme.groups[0].read_only, bool(expected.reasons))
                if expected.action is None:
                    self.assertIsNone(scheme.policy)
                    self.assertEqual(scheme.reasons, (ImportReason.RULE_ACTION_UNRESOLVED,))
                else:
                    self.assertEqual(scheme.reasons, ())
                    self.assertEqual(scheme.policy.rules[0].action, expected.action)

    def test_balancer_targets_keep_selection_and_fallback_without_choosing_a_profile(self):
        R, K = ImportReason, RuleTargetKind
        cases = (
            ("pool", RuleTarget(K.BALANCER, "pool", ("proxy-one", "proxy-two"), "blocked", "leastPing", VPN, ())),
            ("mixed", RuleTarget(K.BALANCER, "mixed", ("direct", "proxy-one"), None, None, None, (R.BALANCER_MIXED,))),
            ("all", RuleTarget(K.BALANCER, "all", ("direct", "blocked", "proxy-one", "proxy-two", "dns-out", "dup", "notype", "twin"),
                               None, None, None, (R.OUTBOUND_PROTOCOL_UNSUPPORTED, R.TARGET_DUPLICATE, R.BALANCER_MIXED))),
            ("prefix", RuleTarget(K.BALANCER, "prefix", ("proxy-one",), None, None, VPN, ())),
            ("empty", RuleTarget(K.BALANCER, "empty", (), None, None, None, (R.BALANCER_EMPTY,))),
            ("noselector", RuleTarget(K.BALANCER, "noselector", (), None, None, None, (R.BALANCER_EMPTY,))),
            ("dupb", RuleTarget(K.BALANCER, "dupb", (), None, None, None, (R.TARGET_DUPLICATE,))),
            ("nofb", RuleTarget(K.BALANCER, "nofb", ("proxy-one",), "missing", None, VPN, (R.FALLBACK_UNRESOLVED,))),
            ("dupfb", RuleTarget(K.BALANCER, "dupfb", ("proxy-one",), "dup", None, None, (R.TARGET_DUPLICATE,))),
            ("badsel", RuleTarget(K.BALANCER, "badsel", (), None, None, None, (R.BALANCER_INVALID, R.BALANCER_EMPTY))),
            ("badstrategy", RuleTarget(K.BALANCER, "badstrategy", ("proxy-one",), None, None, None, (R.BALANCER_INVALID,))),
            ("badfb", RuleTarget(K.BALANCER, "badfb", ("proxy-one",), None, None, None, (R.BALANCER_INVALID,))),
            ("unsupported", RuleTarget(K.BALANCER, "unsupported", ("dns-out",), None, None, None, (R.OUTBOUND_PROTOCOL_UNSUPPORTED,))),
            ("dupsel", RuleTarget(K.BALANCER, "dupsel", ("twin",), None, None, None, (R.TARGET_DUPLICATE,))),
            ("missing", RuleTarget(K.BALANCER, "missing", (), None, None, None, (R.TARGET_UNRESOLVED,))),
        )
        for tag, expected in cases:
            with self.subTest(tag=tag):
                target, scheme = self.target(balancerTag=tag)
                self.assertEqual(target, expected)
                self.assertEqual(scheme.groups[0].read_only, bool(expected.reasons))
        # Группа резервирования остаётся назначением с fallbackTag, а не одним профилем.
        self.assertEqual(self.target(balancerTag="nofb")[1].policy.rules[0].action, VPN)

    def test_outbounds_and_routing_follow_override_of_installed_xray(self):
        first = part("01_first.json", {"outbounds": [{"tag": "x", "protocol": "trojan"}, {"tag": "x", "protocol": "trojan"}],
                                       "routing": {"rules": [rule(domain=["domain:a.example"], outboundTag="x"), final(outboundTag="x")]}})
        second = part("02_second.json", {"outbounds": [{"tag": "x", "protocol": "freedom"}, {"tag": "y", "protocol": "blackhole"},
                                                       {"tag": "y", "protocol": "blackhole"}], "routing": None})
        third_tail = part("03_tail.json", {"outbounds": [{"tag": "z", "protocol": "vless"}, {"tag": "z", "protocol": "trojan"}]})
        fourth = part("04_routing.json", {"routing": {"rules": [
            rule(domain=["domain:a.example"], outboundTag="x"), rule(ip=["192.0.2.1"], outboundTag="y"),
            rule(domain=["domain:b.example"], outboundTag="z"), final(outboundTag="x"),
        ]}})
        with forbid_external_effects():
            scheme = import_routing_scheme(XrayConfigSet((first, second, third_tail, fourth)))
        self.assertEqual((scheme.routing_part, scheme.routing_parts), ("04_routing.json", ("01_first.json", "04_routing.json")))
        self.assertEqual([g.part for g in scheme.groups], ["04_routing.json"] * 4)
        self.assertEqual([g.target.reasons for g in scheme.groups], [
            (ImportReason.TARGET_DUPLICATE,), (ImportReason.TARGET_DUPLICATE,), (), (ImportReason.TARGET_DUPLICATE,),
        ])
        self.assertIs(scheme.groups[2].action, VPN)
        self.assertEqual(scheme.reasons, (ImportReason.FINAL_RULE_UNRESOLVED,))
        single = XrayConfigSet((part("01_first.json", {"outbounds": [{"tag": "x", "protocol": "trojan"}]}),
                                part("02_second.json", {"outbounds": [{"tag": "x", "protocol": "freedom"}, {"tag": "y", "protocol": "vmess"}]}),
                                part("03_tail.json", {"outbounds": [{"tag": "z", "protocol": "socks"}, {"tag": "z", "protocol": "freedom"}]}),
                                part("04_routing.json", {"routing": {"rules": [
                                    rule(domain=["domain:a.example"], outboundTag="x"), rule(domain=["domain:b.example"], outboundTag="y"),
                                    rule(domain=["domain:c.example"], outboundTag="z"), final(outboundTag="x"),
                                ]}})))
        scheme = import_routing_scheme(single)
        self.assertEqual([g.action for g in scheme.groups], [DIRECT, VPN, DIRECT, DIRECT])
        self.assertEqual(scheme.reasons, ())
        self.assertEqual([r.action for r in scheme.policy.rules], [DIRECT, VPN, DIRECT])

    def test_case_variants_of_xray_fields_are_never_resolved_silently(self):
        # JSON-декодер Go принимает ключ без учёта регистра и применяет последний вариант.
        R = ImportReason
        out = {"outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"},
                             {"tag": "proxy-a", "protocol": "trojan"}]}
        rules = {"rules": [rule(domain=["domain:a.example"], outboundTag="direct"), final(outboundTag="direct")]}
        cases = (
            ("routing", (part("04_out.json", out), part("05_a.json", {"routing": rules}),
                         part("06_b.json", {"Routing": {"rules": [final(outboundTag="blocked")]}}))),
            ("ROUTING in one part", (part("04_out.json", out), part("05_a.json", {"routing": rules, "ROUTING": None}))),
            ("outbounds", (part("04_out.json", out), part("05_a.json", {"routing": rules}),
                           part("06_b.json", {"Outbounds": [{"tag": "direct", "protocol": "blackhole"}]}))),
            ("protocol", (part("04_out.json", {"outbounds": [{"tag": "direct", "protocol": "freedom", "Protocol": "blackhole"}]}),
                          part("05_a.json", {"routing": rules}))),
            ("tag", (part("04_out.json", {"outbounds": [{"tag": "direct", "protocol": "freedom", "TAG": "other"}]}),
                     part("05_a.json", {"routing": rules}))),
            ("rules", (part("04_out.json", out), part("05_a.json", {"routing": {**rules, "Rules": []}}))),
            ("balancers", (part("04_out.json", out), part("05_a.json", {"routing": {**rules, "Balancers": []}}))),
        )
        for name, parts in cases:
            with self.subTest(variant=name), forbid_external_effects():
                scheme = import_routing_scheme(XrayConfigSet(parts))
                self.assertIn(R.FIELD_CASE_VARIANT, scheme.reasons)
                self.assertIsNone(scheme.policy)
                self.assertTrue(scheme.read_only)
                self.assertEqual(scheme.to_diagnostic()["policy"], None)
        # Балансировщик с вариантом поля: действие группы не определяется.
        scheme = scheme_for([rule(domain=["domain:a.example"], balancerTag="pool"), FINAL],
                            balancers=[{"tag": "pool", "selector": ["proxy-"], "Selector": ["direct"]}])
        self.assertEqual(scheme.groups[0].target.reasons, (R.FIELD_CASE_VARIANT,))
        self.assertIsNone(scheme.groups[0].action)
        self.assertIn(R.FIELD_CASE_VARIANT, scheme.reasons)
        self.assertIsNone(scheme.policy)
        # Вариант тега назначения в правиле: назначение не выбирается.
        scheme = scheme_for([{"domain": ["domain:a.example"], "outboundTag": "direct", "OutboundTag": "blocked"}, FINAL])
        group = scheme.groups[0]
        self.assertEqual(group.target, RuleTarget(RuleTargetKind.NONE, None, (), None, None, None, (R.FIELD_CASE_VARIANT,)))
        self.assertEqual(group.reasons, (R.UNKNOWN_FIELDS, R.FIELD_CASE_VARIANT))
        self.assertEqual(scheme.reasons, (R.RULE_ACTION_UNRESOLVED,))
        # Ключ, не совпадающий ни с одним полем, вариантом регистра не считается.
        scheme = scheme_for([rule(domain=["domain:a.example"], outboundTag="direct"), FINAL],
                            outbounds=[*OUTBOUNDS, {"tag": "x", "protocol": "freedom", "Comment": "x"}])
        self.assertEqual(scheme.reasons, ())
        self.assertIsNotNone(scheme.policy)

    def test_chained_outbounds_have_no_action(self):
        R, K = ImportReason, RuleTargetKind
        chains = (
            {"proxySettings": {"tag": "proxy-a"}},
            {"proxySettings": {"tag": "proxy-a", "transportLayer": True}},
            {"streamSettings": {"sockopt": {"dialerProxy": "proxy-a", "mark": 255}}},
            {"proxySettings": "proxy-a"}, {"proxySettings": {"tag": 7}}, {"proxySettings": {"Tag": "proxy-a"}},
            {"streamSettings": {"SockOpt": {"dialerProxy": "proxy-a"}}}, {"streamSettings": {"sockopt": {"DialerProxy": "x"}}},
            {"streamSettings": "x"}, {"streamSettings": {"sockopt": []}}, {"streamSettings": {"sockopt": {"dialerProxy": 7}}},
        )
        for chain in chains:
            with self.subTest(chain=chain):
                outbounds = [{"tag": "chained", "protocol": "freedom", **chain}, {"tag": "proxy-a", "protocol": "trojan"}]
                scheme = scheme_for([rule(domain=["domain:a.example"], outboundTag="chained"), final(balancerTag="pool")],
                                    outbounds=outbounds, balancers=[{"tag": "pool", "selector": ["chained", "proxy-a"]}])
                self.assertEqual(scheme.groups[0].target,
                                 RuleTarget(K.OUTBOUND, "chained", (), None, None, None, (R.OUTBOUND_CHAINED,)))
                self.assertEqual(scheme.groups[1].target.reasons, (R.OUTBOUND_CHAINED,))
                self.assertIsNone(scheme.groups[1].action)
                self.assertIsNone(scheme.policy)
                self.assertTrue(scheme.read_only)
        # Обычные sockopt без dialerProxy и пустые значения цепочкой не считаются, как на снимке.
        for settings in (
            {"streamSettings": {"sockopt": {"mark": 255, "domainStrategy": "UseIPv4v6"}}},
            {"proxySettings": {"tag": ""}}, {"proxySettings": None}, {"streamSettings": {"sockopt": {"dialerProxy": ""}}},
            {"streamSettings": {"sockopt": None}}, {"streamSettings": None},
        ):
            with self.subTest(settings=settings):
                scheme = scheme_for([final(outboundTag="direct")], outbounds=[{"tag": "direct", "protocol": "freedom", **settings}])
                self.assertIs(scheme.final_action, DIRECT)
                self.assertEqual(scheme.reasons, ())
        scheme = scheme_for([final(outboundTag="direct")],
                            outbounds=[{"tag": "direct", "protocol": "freedom", "ProxySettings": {"tag": "proxy-a"}}])
        self.assertEqual(scheme.reasons, (R.FIELD_CASE_VARIANT,))
        self.assertIsNone(scheme.policy)

    def test_routing_section_states_and_unsupported_structures(self):
        R = ImportReason
        routing_rules = {"rules": [rule(domain=["domain:a.example"], outboundTag="direct"), final(outboundTag="direct")]}
        base = part("04_outbounds.json", {"outbounds": OUTBOUNDS})
        cases = (
            ((part("05_a.json", {"routing": routing_rules}), part("06_b.json", {"routing": None})), "05_a.json", 2, ()),
            ((part("05_a.json", {"routing": routing_rules}), part("06_b.json", {"routing": {}})), "06_b.json", 0, (R.FINAL_RULE_MISSING,)),
            ((part("05_a.json", {"routing": routing_rules}), part("06_b.json", {"routing": {"rules": None}})), "06_b.json", 0, (R.FINAL_RULE_MISSING,)),
            ((part("05_a.json", {"routing": "fixture-private"}),), "05_a.json", 0, (R.ROUTING_UNSUPPORTED,)),
            ((part("05_a.json", {"routing": {"rules": "fixture-private"}}),), "05_a.json", 0, (R.RULES_UNSUPPORTED,)),
            ((part("05_a.json", {"routing": {"rules": [], "balancers": "x"}}),), "05_a.json", 0, (R.BALANCERS_UNSUPPORTED, R.FINAL_RULE_MISSING)),
            ((part("05_a.json", {"routing": {"rules": [final(outboundTag="direct")], "balancers": [{"selector": ["x"]}, "y"]}}),), "05_a.json", 1, (R.BALANCERS_UNSUPPORTED,)),
            ((), None, 0, (R.ROUTING_MISSING,)),
        )
        for parts, routing_part, group_count, reasons in cases:
            with self.subTest(parts=[p.name for p in parts], reasons=reasons):
                scheme = import_routing_scheme(XrayConfigSet((base, *parts)))
                self.assertEqual((scheme.routing_part, len(scheme.groups), scheme.reasons), (routing_part, group_count, reasons))
                self.assertEqual(scheme.policy is not None, reasons in ((), (R.BALANCERS_UNSUPPORTED,)))
                self.assertTrue(scheme.read_only or not reasons)
                self.assertNotIn("fixture-private", json.dumps(scheme.to_diagnostic()))
        for outbounds in ("fixture-private", [{"tag": "direct", "protocol": "freedom"}, "fixture-private"]):
            with self.subTest(outbounds=type(outbounds).__name__):
                scheme = import_routing_scheme(XrayConfigSet((
                    part("04_outbounds.json", {"outbounds": outbounds}), part("05_routing.json", {"routing": routing_rules}),
                )))
                self.assertIn(R.OUTBOUNDS_UNSUPPORTED, scheme.reasons)
                self.assertEqual(scheme.groups[0].action, None if type(outbounds) is str else DIRECT)


class FinalRuleTests(unittest.TestCase):
    def test_final_rule_is_taken_only_in_supported_forms(self):
        first = rule(domain=["domain:a.example"], outboundTag="direct")
        for last, final, reasons in (
            ({"network": "tcp,udp", "outboundTag": "direct"}, DIRECT, ()),
            ({"type": "field", "network": ["tcp", "udp"], "balancerTag": "pool"}, VPN, ()),
            ({"outboundTag": "direct"}, None, (ImportReason.FINAL_RULE_MISSING,)),
            ({"type": "field", "balancerTag": "pool"}, None, (ImportReason.FINAL_RULE_MISSING,)),
            ({"network": "tcp,udp", "outboundTag": "blocked"}, BLOCK, ()),
            ({"network": ["UDP", "tcp", "tcp"], "outboundTag": "direct"}, DIRECT, ()),
            ({"network": "udp,TCP", "ruleTag": "fixture-rule", "outboundTag": "direct"}, DIRECT, ()),
            ({"network": "tcp", "outboundTag": "direct"}, None, (ImportReason.FINAL_RULE_MISSING,)),
            ({"network": "tcp, udp", "outboundTag": "direct"}, None, (ImportReason.FINAL_RULE_MISSING,)),
            ({"network": 7, "outboundTag": "direct"}, None, (ImportReason.FINAL_RULE_MISSING,)),
            ({"network": "tcp,udp", "port": "443", "outboundTag": "direct"}, None, (ImportReason.FINAL_RULE_MISSING,)),
            ({"domain": ["domain:b.example"], "outboundTag": "direct"}, None, (ImportReason.FINAL_RULE_MISSING,)),
            ({"domain": [], "outboundTag": "direct"}, None, (ImportReason.FINAL_RULE_MISSING,)),
            ({"network": "tcp,udp", "outboundTag": "missing"}, None, (ImportReason.FINAL_RULE_UNRESOLVED,)),
            ({"network": "tcp,udp"}, None, (ImportReason.FINAL_RULE_UNRESOLVED,)),
        ):
            with self.subTest(last=last):
                scheme = scheme_for([first, last])
                group = scheme.groups[-1]
                self.assertEqual((scheme.final_action, scheme.reasons), (final, reasons))
                if reasons == ():
                    self.assertIs(group.kind, RuleGroupKind.FINAL)
                    self.assertEqual((group.conditions, group.unsupported_fields, group.read_only), ((), (), False))
                    self.assertEqual(scheme.policy, RoutingPolicy(scheme.groups[0].rules, FinalRoutingRule(final)))
                    self.assertFalse(scheme.read_only)
                else:
                    self.assertIsNone(scheme.policy)
                    self.assertTrue(scheme.read_only)
                self.assertEqual(scheme.final_group, group if reasons != (ImportReason.FINAL_RULE_MISSING,) else None)
        self.assertEqual(scheme_for([]).reasons, (ImportReason.FINAL_RULE_MISSING,))
        self.assertEqual(scheme_for([]).groups, ())

    def test_catch_all_before_the_end_is_kept_in_place_as_read_only(self):
        scheme = scheme_for([
            {"outboundTag": "direct"}, rule(network="tcp,udp", outboundTag="blocked"),
            rule(domain=["domain:a.example"], outboundTag="direct"), FINAL,
        ])
        self.assertEqual([g.kind.value for g in scheme.groups], ["rules", "rules", "rules", "final"])
        self.assertEqual(scheme.groups[0].conditions, (UnsupportedRuleCondition((), "{}"),))
        self.assertEqual(scheme.groups[1].conditions, (UnsupportedRuleCondition(("network",), '{"network":"tcp,udp"}'),))
        self.assertEqual([g.reasons for g in scheme.groups[:2]],
                         [(ImportReason.RULE_WITHOUT_CONDITIONS,), (ImportReason.CATCH_ALL_NOT_LAST,)])
        self.assertEqual([g.unsupported_fields for g in scheme.groups], [(), (), (), ()])
        self.assertEqual([r.action for r in scheme.policy.rules], [DIRECT, BLOCK, DIRECT])
        self.assertTrue(scheme.policy.read_only)
        self.assertEqual(scheme.reasons, ())


class ValidationAndSafetyTests(unittest.TestCase):
    def setUp(self):
        self.scheme = scheme_for([rule(domain=["domain:a.example", "regexp:x"], outboundTag="direct"),
                                  rule(ip=["geoip:ru"], balancerTag="pool"), FINAL])

    def assert_rejected(self, code, function, *args, **kwargs):
        with self.assertRaises(RoutingImportError) as caught:
            function(*args, **kwargs)
        self.assertIs(caught.exception.code, code)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception

    def test_rebuilt_models_detect_tampering_and_foreign_types(self):
        s_conditions, s_rules = object(), object()
        validate_routing_scheme(self.scheme)
        for broken in (None, "fixture-private", self.scheme.groups):
            self.assert_rejected(RoutingImportErrorCode.SCHEME, validate_routing_scheme, broken)

        class Derived(RoutingScheme):
            pass

        self.assert_rejected(RoutingImportErrorCode.SCHEME, validate_routing_scheme, Derived(None, (), (), None, ()))
        GROUP, TARGET, SCHEME = RoutingImportErrorCode.GROUP, RoutingImportErrorCode.TARGET, RoutingImportErrorCode.SCHEME
        tampering = (
            (lambda s: s.groups[0].conditions[0], "value", "A.EXAMPLE", SCHEME),
            (lambda s: s.groups[0].conditions[1], "reference", "", GROUP),
            (lambda s: s.groups[1].conditions[0].database, "reference", "", GROUP),
            (lambda s: s.groups[1].conditions[0], "set_name", "bad set", GROUP),
            (lambda s: s.groups[0].target, "action", None, TARGET),
            (lambda s: s.groups[0].target, "outbound_tags", ("direct", "blocked"), TARGET),
            (lambda s: s.groups[1].target, "tag", None, TARGET),
            (lambda s: s.groups[0], "value_count", True, GROUP),
            (lambda s: s.groups[0], "reasons", ("x",), GROUP),
            (lambda s: s.groups[0], "part", "other.json", SCHEME),
            (lambda s: s.groups[2], "conditions", s_conditions, GROUP),
            (lambda s: s.groups[2], "kind", RuleGroupKind.RULES, GROUP),
            (lambda s: s.policy, "final_rule", FinalRoutingRule(BLOCK), SCHEME),
            (lambda s: s.policy, "rules", s_rules, SCHEME),
            (lambda s: s, "routing_part", "other.json", SCHEME),
            (lambda s: s, "routing_parts", (), SCHEME),
            (lambda s: s, "policy", RoutingPolicy((), FinalRoutingRule(DIRECT)), SCHEME),
            (lambda s: s, "reasons", (ImportReason.ROUTING_MISSING, ImportReason.ROUTING_MISSING), SCHEME),
        )
        for locate, field, value, code in tampering:
            with self.subTest(field=field, code=code.value):
                scheme = scheme_for([rule(domain=["domain:a.example", "regexp:x"], outboundTag="direct"),
                                     rule(ip=["geoip:ru"], balancerTag="pool"), FINAL])
                if value is s_conditions:
                    value = scheme.groups[0].conditions
                elif value is s_rules:
                    value = scheme.policy.rules[:1]
                object.__setattr__(locate(scheme), field, value)
                self.assert_rejected(code, validate_routing_scheme, scheme)

    def test_policy_fields_are_rebuilt_not_compared_by_equality(self):
        # str-Enum равен строке, а bool — числу: такие подмены должны давать доменный отказ.
        GROUP, SCHEME = RoutingImportErrorCode.GROUP, RoutingImportErrorCode.SCHEME
        tampering = (
            (lambda s: s.policy.final_rule, "action", "DIRECT", True, SCHEME),
            (lambda s: s.policy.rules[0], "action", "DIRECT", True, SCHEME),
            (lambda s: s.policy.rules[0], "enabled", 1, True, SCHEME),
            (lambda s: s.policy.rules[0], "protected", 0, True, SCHEME),
            (lambda s: s.policy, "rules", None, False, SCHEME),
            (lambda s: s.policy, "final_rule", "DIRECT", False, SCHEME),
            # Условие общее у группы и политики: его подмену находит уже проверка группы.
            (lambda s: s.policy.rules[0].condition, "mode", "subdomains", True, GROUP),
        )
        for locate, field, value, equal, code in tampering:
            with self.subTest(field=field, value=value):
                scheme = scheme_for([rule(domain=["domain:a.example"], outboundTag="direct"), final(outboundTag="direct")])
                self.assertIs(scheme.final_action, DIRECT)
                target = locate(scheme)
                self.assertEqual(getattr(target, field) == value, equal)
                object.__setattr__(target, field, value)
                self.assert_rejected(code, validate_routing_scheme, scheme)

    def test_constructors_reject_inconsistent_models(self):
        target = RuleTarget(RuleTargetKind.OUTBOUND, "direct", ("direct",), None, None, DIRECT, ())
        condition = DomainCondition("a.example")
        group_args = ("05_routing.json", 0, RuleGroupKind.RULES, (condition,), target, ("domain",), (), (), 1, False, (), ())
        self.assertEqual(ImportedRuleGroup(*group_args).rules, (RoutingRule(condition, DIRECT),))
        changes = (
            {0: "../x.json"}, {1: -1}, {1: True}, {2: "rules"}, {3: (condition, "x")}, {3: [condition]}, {4: None},
            {5: ("domain", "domain")}, {5: ("domain", 7)}, {6: ("ip",)}, {6: ("",)}, {7: ("port",)}, {8: -1}, {8: 1.0}, {9: 1},
            {10: ("x",)}, {10: (ImportReason.DOMAIN_PLAIN, ImportReason.DOMAIN_PLAIN)}, {11: (("path", "x"),)},
            {2: RuleGroupKind.FINAL}, {3: ()},
        )
        for change in changes:
            args = list(group_args)
            for position, value in change.items():
                args[position] = value
            with self.subTest(change=change):
                self.assert_rejected(RoutingImportErrorCode.GROUP, ImportedRuleGroup, *args)
        for args in (
            ("outbound", "direct", (), None, None, DIRECT, ()), (RuleTargetKind.OUTBOUND, "", (), None, None, DIRECT, ()),
            (RuleTargetKind.OUTBOUND, "direct", ["direct"], None, None, DIRECT, ()),
            (RuleTargetKind.BALANCER, "pool", ("x",), "", None, VPN, ()), (RuleTargetKind.BALANCER, "pool", ("x",), None, 7, VPN, ()),
            (RuleTargetKind.OUTBOUND, "direct", ("direct",), None, None, "DIRECT", ()),
            (RuleTargetKind.OUTBOUND, "direct", (), None, None, None, ()),
            (RuleTargetKind.OUTBOUND, "direct", (), None, None, None, ("x",)),
        ):
            with self.subTest(target=args):
                self.assert_rejected(RoutingImportErrorCode.TARGET, RuleTarget, *args)
        for args in (("", ImportReason.DOMAIN_PLAIN), ("a\n", ImportReason.DOMAIN_PLAIN), ("path", "domain_plain")):
            self.assert_rejected(RoutingImportErrorCode.GROUP, ValueReason, *args)
        self.assert_rejected(RoutingImportErrorCode.CONFIG, import_routing_scheme, "fixture-private")
        self.assert_rejected(RoutingImportErrorCode.CONFIG, import_routing_scheme, snapshot_xray_config().parts)

    def test_errors_are_detached_and_messages_are_fixed(self):
        try:
            raise ValueError("fixture-private-context")
        except ValueError:
            error = self.assert_rejected(RoutingImportErrorCode.CONFIG, import_routing_scheme, None)
        self.assertNotIn("fixture-private", str(error) + repr(error))
        for code in RoutingImportErrorCode:
            self.assertTrue(str(RoutingImportError(code)))

    def test_models_are_immutable(self):
        for model, field in (
            (self.scheme, "policy"), (self.scheme.groups[0], "conditions"), (self.scheme.groups[0].target, "action"),
            (self.scheme.groups[0].value_reasons[0], "reason"),
        ):
            with self.assertRaises(FrozenInstanceError):
                setattr(model, field, None)

    def test_long_and_unusual_values_do_not_raise(self):
        huge = "1" * 5000
        scheme = scheme_for([
            rule(domain=["domain:" + "a" * 5000, "full:" + "b." * 3000, "x" * 5000], outboundTag="direct"),
            rule(ip=[f"192.0.2.0/{huge}", huge, f"geoip:{huge}", "0" * 5000], outboundTag="direct"),
            rule(port=huge, domain=["domain:a.example"], outboundTag="direct"),
            final(outboundTag="direct"),
        ])
        self.assertEqual([len(g.conditions) for g in scheme.groups], [3, 4, 1, 0])
        self.assertEqual([len(g.value_reasons) for g in scheme.groups[:2]], [3, 3])
        self.assertIs(type(scheme.groups[1].conditions[2]), GeoIPCondition)
        self.assertNotIn(huge, json.dumps(scheme.to_diagnostic()))
        validate_routing_scheme(scheme)

    def test_resolution_is_linear_and_reuses_balancer_selection(self):
        rules = [rule(domain=["domain:a.example"], balancerTag="pool") for _ in range(50)] + [FINAL]
        with patch("keenvpn.domain.routing_import._select_outbounds", wraps=_select_outbounds) as select:
            scheme = scheme_for(rules)
        self.assertEqual(select.call_count, 1)
        self.assertEqual(len(scheme.policy.rules), 50)
        timings = []
        for size in (2000, 8000):
            outbounds = [{"tag": f"out-{index}", "protocol": "freedom"} for index in range(size)]
            rules = [rule(domain=["domain:a.example"], outboundTag=f"out-{index}") for index in range(size)] + [final(outboundTag="out-0")]
            best = None
            for _attempt in range(3):
                started = time.perf_counter()
                scheme = scheme_for(rules, outbounds=outbounds, balancers=None)
                elapsed = time.perf_counter() - started
                best = elapsed if best is None else min(best, elapsed)
            self.assertEqual(len(scheme.policy.rules), size)
            timings.append(best)
        # При квадратичной стоимости четырёхкратный рост дал бы примерно шестнадцатикратное время.
        self.assertLess(timings[1], timings[0] * 10 + 0.1)

    def test_diagnostic_masks_tags_strategy_and_unknown_field_names(self):
        private = ("TEST_ONLY_PW", "user:", "host.example", "/private", "TEST_ONLY_KEY", "TEST_ONLY_STRATEGY", "198.51.100.7")
        outbounds = [
            {"tag": "https://user:TEST_ONLY_PW@host.example/x", "protocol": "freedom"},
            {"tag": "proxy-safe", "protocol": "trojan"}, {"tag": "proxy 198.51.100.7", "protocol": "trojan"},
            {"tag": "fb/private", "protocol": "blackhole"},
        ]
        balancers = [{"tag": "pool:TEST_ONLY_PW", "selector": ["proxy"], "fallbackTag": "fb/private",
                      "strategy": {"type": "TEST_ONLY_STRATEGY"}}]
        scheme = scheme_for([
            rule(domain=["domain:a.example"], outboundTag="https://user:TEST_ONLY_PW@host.example/x",
                 **{"/private/TEST_ONLY_KEY": 1, "comment": "x"}),
            rule(domain=["domain:b.example"], balancerTag="pool:TEST_ONLY_PW"),
            final(outboundTag="proxy-safe"),
        ], outbounds=outbounds, balancers=balancers)
        first, second, last = scheme.groups
        # Доверенный код получает исходные значения без изменений.
        self.assertEqual(first.target.tag, "https://user:TEST_ONLY_PW@host.example/x")
        self.assertEqual(first.unknown_fields, ("/private/TEST_ONLY_KEY", "comment"))
        self.assertEqual(second.target.strategy, "TEST_ONLY_STRATEGY")
        diagnostic = scheme.to_diagnostic()
        self.assertEqual(diagnostic["groups"][0]["fields"], ["domain"])
        self.assertEqual(diagnostic["groups"][0]["unknown_field_count"], 2)
        self.assertEqual(diagnostic["groups"][0]["target"], {
            "kind": "outbound", "tag_known": True, "tag": None, "outbound_tags": [None], "fallback_known": False,
            "fallback_tag": None, "strategy_known": False, "strategy": None, "action": "DIRECT", "reasons": [],
        })
        self.assertEqual(diagnostic["groups"][1]["target"], {
            "kind": "balancer", "tag_known": True, "tag": None, "outbound_tags": ["proxy-safe", None],
            "fallback_known": True, "fallback_tag": None, "strategy_known": True, "strategy": None,
            "action": "VPN", "reasons": [],
        })
        self.assertEqual(diagnostic["groups"][2]["target"]["tag"], "proxy-safe")
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(scheme) + repr(scheme.groups)
        text += "".join(repr(group.target) for group in scheme.groups) + str(last.target)
        for marker in private:
            self.assertNotIn(marker, text)
        self.assertEqual(repr(first.target), "RuleTarget(kind=outbound, action=DIRECT)")

    def test_safe_identifier_and_strategy_formats(self):
        from keenvpn.domain.routing_import import safe_identifier, safe_strategy
        for value in ("direct", "trojan-out", "vpn_group-1+x", "A" * 128, "2001", "TEST_ONLY_SECRET_65"):
            # Последнее значение — известное ограничение: секрет без разделителей форматом не отличить от тега.
            self.assertEqual(safe_identifier(value), value)
        for value in (None, 7, "", "-x", "a b", "a/b", "a:b", "user@host", "a\nb", "A" * 129, "тег", "a\x00",
                      "198.51.100.7", "private.example.test", "vpn.group", "2001:db8::1", "::1", "0.0.0.0"):
            self.assertIsNone(safe_identifier(value))
        for value in ("random", "leastPing", "RoundRobin", "leastload"):
            self.assertEqual(safe_strategy(value), value)
        for value in (None, "", "leastPing2", "https://x", 7):
            self.assertIsNone(safe_strategy(value))

    def test_outbound_merge_matches_override_reference(self):
        # Прямая реализация Config.Override Xray v26.3.27 со списком: эталон для небольших данных.
        def reference(documents):
            effective = []
            for position, (name, document) in enumerate(documents):
                if "outbounds" not in document:
                    continue
                entries = [(item.get("tag", ""), item["protocol"]) for item in document["outbounds"] or []]
                if position == 0:
                    effective = entries
                    continue
                prepends = []
                for entry in entries:
                    index = next((i for i, old in enumerate(effective) if old[0] == entry[0]), None)
                    if index is not None:
                        effective[index] = entry
                    elif "tail" in name.lower():
                        effective.append(entry)
                    else:
                        prepends.append(entry)
                effective = prepends + effective
            return effective

        protocols = ("freedom", "blackhole", "trojan")
        random = __import__("random").Random(65)
        for case in range(300):
            documents = []
            for position in range(random.randint(1, 5)):
                name = f"{position:02d}_{random.choice(('part', 'tail', 'TAIL-x', 'x'))}.json"
                if random.random() < 0.2:
                    documents.append((name, {"log": {}}))
                    continue
                outbounds = []
                for _ in range(random.randint(0, 5)):
                    item = {"protocol": random.choice(protocols)}
                    if random.random() < 0.9:
                        item["tag"] = random.choice(("a", "b", "c", "d", ""))
                    outbounds.append(item)
                documents.append((name, {"outbounds": outbounds if outbounds or random.random() < 0.5 else None}))
            with self.subTest(case=case):
                merged, supported, variant = _effective_outbounds(documents)
                self.assertTrue(supported)
                self.assertFalse(variant)
                expected = [(tag, _outbound_action(protocol)) for tag, protocol in reference(documents)]
                self.assertEqual([(entry.tag, entry.action) for entry in merged], expected)

    def test_outbound_merge_cost_is_linear_for_many_parts(self):
        # Детерминированно: число выполненных строк кода модуля, без измерения времени.
        def executed_lines(documents):
            count = 0
            module_file = _effective_outbounds.__code__.co_filename

            def tracer(frame, event, _arg):
                nonlocal count
                if frame.f_code.co_filename != module_file:
                    return None
                if event == "line":
                    count += 1
                return tracer

            sys.settrace(tracer)
            try:
                _effective_outbounds(documents)
            finally:
                sys.settrace(None)
            return count

        def documents(size):
            # Непересекающиеся теги в двух обычных частях, части по одному outbound и часть tail с заменами.
            parts = [("01.json", {"outbounds": [{"tag": f"a{i}", "protocol": "freedom"} for i in range(size)]}),
                     ("02.json", {"outbounds": [{"tag": f"b{i}", "protocol": "trojan"} for i in range(size)]})]
            parts += [(f"03_{i:05d}.json", {"outbounds": [{"tag": f"c{i}", "protocol": "freedom"}]}) for i in range(size)]
            parts.append(("04_tail.json", {"outbounds": [{"tag": f"a{i}", "protocol": "blackhole"} for i in range(size)]}))
            return parts

        small, large = executed_lines(documents(200)), executed_lines(documents(800))
        # Линейная стоимость даёт отношение около 4, квадратичная — около 16.
        self.assertLess(large, small * 5)

    def test_import_has_no_file_network_process_or_terminal_io(self):
        config = snapshot_xray_config()
        with forbid_external_effects():
            scheme = import_routing_scheme(config)
            scheme.to_diagnostic()
            validate_routing_scheme(scheme)
            scheme_for([rule(domain=["domain:a.example"], balancerTag="pool"), FINAL]).to_diagnostic()


if __name__ == "__main__":
    unittest.main()
