"""Конфигурация Xray: части снимка, структурная сводка и отсутствие секретов в выводе."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.config_document import ConfigDocument, ConfigDocumentError, ConfigDocumentErrorCode
from keenvpn.domain.routing import ConditionFamily
from keenvpn.domain.xray_config import (
    RuleListValue, TagRepeat, TagRepeats, XrayConfigError, XrayConfigErrorCode, XrayConfigSet, _duplicates,
    decode_string_list, rule_list_values, summarize_xray_config, tag_repeats, validate_xray_config_set,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_MARKERS, UNSAFE_PART_NAME, unsafe_xray_config
from tests.support.snapshot import load_xray_snapshot_files, snapshot_xray_config


# Значения снимка и искусственных частей, которые не должны попадать в вывод.
PRIVATE_MARKERS = (
    "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "192.0.2.", "probe.example",
    "127.0.0.1", "/opt/var/log", "1181", "1191", "fixture-private", "geoip:ru", "domain:ru",
)
SECRET_OUTBOUND = {
    "tag": "vless-out", "protocol": "vless",
    "settings": {"vnext": [{"address": "fixture-private-host.example", "port": 443, "users": [
        {"id": "fixture-private-uuid", "flow": "xtls-rprx-vision"},
    ]}]},
    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
        "serverName": "fixture-private-sni", "publicKey": "fixture-private-public-key", "shortId": "fixture-private-short",
    }},
}


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


class SnapshotXrayConfigTests(unittest.TestCase):
    def test_snapshot_summary_has_tags_protocols_references_and_no_values(self):
        files = load_xray_snapshot_files()
        with forbid_external_effects():
            config = XrayConfigSet(tuple(ConfigDocument(name, files[name]) for name in sorted(files)))
            diagnostic = config.to_diagnostic()
        self.assertEqual(config.part_names, tuple(sorted(files)))
        self.assertEqual(diagnostic["part_count"], 7)
        self.assertEqual(
            [item["name"] for item in diagnostic["parts"]],
            ["01_log.json", "02_dns.json", "03_inbounds.json", "04_outbounds.json", "05_routing.json",
             "06_policy.json", "07_observatory.json"],
        )
        self.assertEqual(diagnostic["sections"]["routing"], ["05_routing.json"])
        self.assertEqual(diagnostic["duplicate_sections"], [])
        self.assertEqual(diagnostic["dns_tags"], ["dns-local"])
        self.assertEqual(diagnostic["domain_strategies"], ["IPOnDemand"])
        self.assertEqual(
            [(item["tag"], item["protocol"]) for item in diagnostic["inbounds"]],
            [("redirect", "tunnel"), ("tproxy", "tunnel"), ("force-proxy-redirect", "tunnel"),
             ("force-proxy-tproxy", "tunnel")],
        )
        self.assertEqual(
            [(item["tag"], item["protocol"]) for item in diagnostic["outbounds"]],
            [("trojan-out", "trojan"), ("direct", "freedom"), ("blocked", "blackhole")],
        )
        self.assertEqual(diagnostic["rule_count"], 8)
        self.assertEqual(
            [(rule["target_kind"], rule["target_tag"], rule["conditions"]) for rule in diagnostic["rules"]],
            [("outbound", "direct", {}), ("outbound", "direct", {"domain": 3}), ("balancer", "vpn-group", {}),
             ("balancer", "vpn-group", {"domain": 2}), ("outbound", "direct", {"domain": 16}),
             ("outbound", "direct", {"ip": 19}), ("outbound", "direct", {"ip": 1}),
             ("balancer", "vpn-group", {"network": 1})],
        )
        self.assertEqual(diagnostic["rules"][0]["inbound_tags"], ["dns-local"])
        self.assertEqual(diagnostic["rules"][2]["inbound_tags"], ["force-proxy-redirect", "force-proxy-tproxy"])
        self.assertTrue(all(rule["inbound_tags_resolved"] and rule["target_resolved"] for rule in diagnostic["rules"]))
        self.assertTrue(all(rule["has_rule_tag"] and rule["type"] == "field" for rule in diagnostic["rules"]))
        self.assertEqual(diagnostic["balancers"], [{
            "part": "05_routing.json", "index": 0, "tag_known": True, "tag": "vpn-group", "selector": ["trojan-out"],
            "selector_match_count": 1, "fallback_known": True, "fallback_tag": "blocked", "fallback_resolved": True,
            "fallback_position": {"part": "04_outbounds.json", "index": 2}, "strategy_known": True,
            "strategy": "leastPing",
        }])
        # Позиции целей: outbound `direct` — второй в своей части, балансировщик `vpn-group` — единственный.
        self.assertEqual(
            [rule["target_position"] for rule in diagnostic["rules"]],
            [{"part": "04_outbounds.json", "index": 1} if rule["target_kind"] == "outbound"
             else {"part": "05_routing.json", "index": 0} for rule in diagnostic["rules"]],
        )
        self.assertTrue(all(
            rule["type_known"] and rule["target_tag_known"] and rule["unknown_condition_count"] == 0
            for rule in diagnostic["rules"]
        ))
        self.assertEqual([item["index"] for item in diagnostic["inbounds"]], [0, 1, 2, 3])
        self.assertTrue(all(item["tag_known"] and item["protocol_known"] for item in diagnostic["inbounds"] + diagnostic["outbounds"]))
        self.assertEqual([item["unknown_section_count"] for item in diagnostic["parts"]], [0] * 7)
        self.assertEqual(diagnostic["observatory_subjects"], [{
            "part": "07_observatory.json", "section": "burstObservatory", "selector": "trojan-out", "match_count": 1,
        }])
        for key in ("duplicate_inbound_tags", "duplicate_outbound_tags", "duplicate_balancer_tags", "unsupported_paths"):
            self.assertEqual(diagnostic[key], [])
        self.assertEqual(json.loads(json.dumps(diagnostic)), diagnostic)
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(config) + repr(config.parts)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertEqual(repr(config), "XrayConfigSet(parts=7)")

    def test_support_builds_the_same_set_and_validation_passes(self):
        config = snapshot_xray_config()
        validate_xray_config_set(config)
        self.assertEqual(config.part_names, tuple(sorted(load_xray_snapshot_files())))
        self.assertEqual(config.to_diagnostic(), snapshot_xray_config().to_diagnostic())

    def test_summary_exports_each_part_once(self):
        config = snapshot_xray_config()
        with patch.object(ConfigDocument, "export", autospec=True, side_effect=ConfigDocument.export) as export:
            summarize_xray_config(config.parts)
        self.assertEqual(export.call_count, len(config.parts))

    def test_snapshot_rule_list_values_keep_order_and_stay_out_of_summary(self):
        config = snapshot_xray_config()
        with forbid_external_effects():
            values = config.rule_list_values()
        self.assertEqual(values, rule_list_values(config.parts))
        self.assertEqual(len(values), 41)
        self.assertTrue(all(type(value) is RuleListValue and value.part == "05_routing.json" for value in values))
        self.assertEqual([value.path for value in values[:3]], [f"routing.rules[1].domain[{index}]" for index in range(3)])
        self.assertEqual(
            [(value.path, value.family, value.qualified) for value in values[-2:]],
            [("routing.rules[6].ip[0]", ConditionFamily.IP, True), ("routing.rules[7].network[0]", ConditionFamily.IP, True)]
            if False else [("routing.rules[5].ip[18]", ConditionFamily.IP, True), ("routing.rules[6].ip[0]", ConditionFamily.IP, True)],
        )
        self.assertEqual(values[-1].value, "geoip:ru")
        self.assertEqual(sum(value.family is ConditionFamily.DOMAIN for value in values), 21)
        self.assertNotIn("geoip:ru", repr(values))
        self.assertNotIn("geoip:ru", json.dumps(config.to_diagnostic()))


class SyntheticXrayConfigTests(unittest.TestCase):
    def test_scalar_stringlist_resolves_routing_like_array_form(self):
        cases = (
            ("lan", ["lan"], True, "proxy", ["proxy"], 2),
            ("lan,missing-in", ["lan", "missing-in"], False, "proxy,direct", ["proxy", "direct"], 3),
            ("lan,, missing-in", ["lan", "", " missing-in"], False, "proxy,, direct", ["proxy", "", " direct"], 3),
            ("", [""], False, "", [""], 3),
        )
        for scalar_inbound, inbound_tags, resolved, scalar_selector, selectors, matches in cases:
            for inbound, selector in ((scalar_inbound, scalar_selector), (inbound_tags, selectors)):
                with self.subTest(inbound=inbound, selector=selector), forbid_external_effects():
                    config = XrayConfigSet((part("01_routing.json", {
                        "inbounds": [{"tag": "lan"}],
                        "outbounds": [{"tag": tag} for tag in ("proxy-one", "proxy-two", "direct")],
                        "routing": {
                            "rules": [{"type": "field", "inboundTag": inbound, "outboundTag": "direct"}],
                            "balancers": [{"tag": "pool", "selector": selector}],
                        },
                    }),))
                    before = config.parts[0].content
                    diagnostic = config.to_diagnostic()
                    # Пустой и начинающийся с пробела элемент скрываются проверкой формата; пустой селектор остаётся пустым.
                    self.assertEqual(
                        diagnostic["rules"][0]["inbound_tags"],
                        [tag if tag in ("lan", "missing-in") else None for tag in inbound_tags],
                    )
                    self.assertEqual(diagnostic["rules"][0]["inbound_tags_resolved"], resolved)
                    self.assertEqual(
                        diagnostic["balancers"][0]["selector"],
                        [item if item in ("proxy", "direct", "") else None for item in selectors],
                    )
                    self.assertEqual(diagnostic["balancers"][0]["selector_match_count"], matches)
                    self.assertEqual(diagnostic["unsupported_paths"], [])
                    self.assertEqual(config.parts[0].content, before)

    def test_plain_string_arrays_do_not_expand_scalar_stringlist_form(self):
        config = XrayConfigSet((part("01_routing.json", {
            "inbounds": [{"tag": "lan"}], "outbounds": [{"tag": "proxy-one"}, {"tag": "direct"}],
            "routing": {
                "rules": [{"type": "field", "inboundTag": ["lan,missing-in"], "outboundTag": "direct"}],
                "balancers": [{"tag": "pool", "selector": ["proxy,direct"]}],
            },
            "observatory": {"subjectSelector": "proxy"}, "burstObservatory": {"subjectSelector": "proxy"},
        }),))
        with forbid_external_effects():
            diagnostic = config.to_diagnostic()
        # Элемент с запятой не делится и не проходит проверку формата: разрешимость считается по исходному значению.
        self.assertEqual(diagnostic["rules"][0]["inbound_tags"], [None])
        self.assertFalse(diagnostic["rules"][0]["inbound_tags_resolved"])
        self.assertEqual(diagnostic["balancers"][0]["selector"], [None])
        self.assertEqual(diagnostic["balancers"][0]["selector_match_count"], 0)
        self.assertEqual(diagnostic["observatory_subjects"], [])
        self.assertEqual(diagnostic["unsupported_paths"], [
            {"part": "01_routing.json", "path": "observatory.subjectSelector"},
            {"part": "01_routing.json", "path": "burstObservatory.subjectSelector"},
        ])

    def test_unresolved_references_duplicates_and_unsupported_structures_are_reported(self):
        parts = (
            part("01_a.json", {"inbounds": [
                {"tag": "in-a", "protocol": "tunnel"}, "fixture-private", {"tag": 5, "protocol": None},
                {"protocol": "dokodemo-door"},
            ], "dns": {"tag": "dns-a"}, "observatory": {"subjectSelector": ["out-"]}}),
            part("02_b.json", {"inbounds": {"tag": "in-b"}, "dns": "fixture-private", "outbounds": [
                {"tag": "out-a", "protocol": "freedom"}, {"tag": "out-a", "protocol": "blackhole"}, SECRET_OUTBOUND,
            ]}),
            part("03_c.json", {"routing": {"domainStrategy": "AsIs", "rules": [
                {"type": "field", "inboundTag": ["in-a", "missing-in"], "outboundTag": "out-a", "domain": ["d1", "d2"]},
                {"type": "field", "outboundTag": "missing-out", "balancerTag": "group", "ruleTag": "fixture-private"},
                {"type": "field", "balancerTag": "group", "network": "tcp", "port": "53"},
                {"type": "field", "balancerTag": "missing-group", "ip": "fixture-private-ip"},
                {"type": "field", "inboundTag": 7, "protocol": ["bittorrent"]},
                "fixture-private", {"type": 7, "ip": []},
            ], "balancers": [
                {"tag": "group", "selector": ["out-", "none-"], "fallbackTag": "missing", "strategy": {"type": "random"}},
                {"tag": "group", "selector": 7, "strategy": "leastPing"},
                {"selector": []},
                "fixture-private",
            ]}, "burstObservatory": {"subjectSelector": "out-a"}, "observatory": []}),
            part("04_d.json", {"routing": [], "outbounds": [{"tag": "out-b", "protocol": "freedom"}]}),
        )
        with forbid_external_effects():
            diagnostic = XrayConfigSet(parts).to_diagnostic()
        self.assertEqual(diagnostic["sections"], {
            "inbounds": ["01_a.json", "02_b.json"], "dns": ["01_a.json", "02_b.json"], "observatory": ["01_a.json", "03_c.json"],
            "outbounds": ["02_b.json", "04_d.json"], "routing": ["03_c.json", "04_d.json"], "burstObservatory": ["03_c.json"],
        })
        self.assertEqual(diagnostic["duplicate_sections"], ["inbounds", "dns", "observatory", "outbounds", "routing"])
        self.assertEqual(diagnostic["dns_tags"], ["dns-a"])
        self.assertEqual(diagnostic["domain_strategies"], ["AsIs"])
        self.assertEqual(diagnostic["inbounds"], [
            {"part": "01_a.json", "index": 0, "tag_known": True, "tag": "in-a", "protocol_known": True, "protocol": "tunnel"},
            {"part": "01_a.json", "index": 2, "tag_known": False, "tag": None, "protocol_known": False, "protocol": None},
            {"part": "01_a.json", "index": 3, "tag_known": False, "tag": None, "protocol_known": True,
             "protocol": "dokodemo-door"},
        ])
        self.assertEqual(
            [(item["part"], item["tag"], item["protocol"]) for item in diagnostic["outbounds"]],
            [("02_b.json", "out-a", "freedom"), ("02_b.json", "out-a", "blackhole"), ("02_b.json", "vless-out", "vless"),
             ("04_d.json", "out-b", "freedom")],
        )
        self.assertEqual(diagnostic["duplicate_inbound_tags"], [])
        self.assertEqual(diagnostic["duplicate_outbound_tags"], ["out-a"])
        self.assertEqual(diagnostic["duplicate_balancer_tags"], ["group"])
        self.assertEqual(diagnostic["rule_count"], 6)
        self.assertEqual([
            (rule["index"], rule["type"], rule["inbound_tags"], rule["inbound_tags_resolved"], rule["target_kind"],
             rule["target_tag"], rule["target_resolved"], rule["has_rule_tag"], rule["conditions"])
            for rule in diagnostic["rules"]
        ], [
            (0, "field", ["in-a", "missing-in"], False, "outbound", "out-a", True, False, {"domain": 2}),
            (1, "field", [], True, "both", None, False, True, {}),
            (2, "field", [], True, "balancer", "group", True, False, {"network": 1, "port": 1}),
            (3, "field", [], True, "balancer", "missing-group", False, False, {"ip": 1}),
            (4, "field", [], True, "none", None, False, False, {"protocol": 1}),
            (6, None, [], True, "none", None, False, False, {"ip": 0}),
        ])
        self.assertTrue(all(rule["part"] == "03_c.json" and rule["unknown_condition_count"] == 0 for rule in diagnostic["rules"]))
        # Повтор тега `out-a` и `group` оставляет ссылку разрешённой, но без позиции; `type` не строка — `type_known` ложно.
        self.assertEqual([rule["target_position"] for rule in diagnostic["rules"]], [None] * 6)
        self.assertEqual([rule["type_known"] for rule in diagnostic["rules"]], [True] * 5 + [False])
        self.assertEqual([rule["target_tag_known"] for rule in diagnostic["rules"]], [True, False, True, True, False, False])
        self.assertEqual(diagnostic["balancers"], [
            {"part": "03_c.json", "index": 0, "tag_known": True, "tag": "group", "selector": ["out-", "none-"],
             "selector_match_count": 3, "fallback_known": True, "fallback_tag": "missing", "fallback_resolved": False,
             "fallback_position": None, "strategy_known": True, "strategy": "random"},
            {"part": "03_c.json", "index": 1, "tag_known": True, "tag": "group", "selector": [], "selector_match_count": 0,
             "fallback_known": False, "fallback_tag": None, "fallback_resolved": None, "fallback_position": None,
             "strategy_known": False, "strategy": None},
            {"part": "03_c.json", "index": 2, "tag_known": False, "tag": None, "selector": [], "selector_match_count": 0,
             "fallback_known": False, "fallback_tag": None, "fallback_resolved": None, "fallback_position": None,
             "strategy_known": False, "strategy": None},
        ])
        self.assertEqual(diagnostic["observatory_subjects"], [
            {"part": "01_a.json", "section": "observatory", "selector": "out-", "match_count": 3},
        ])
        self.assertEqual(diagnostic["unsupported_paths"], [
            {"part": "01_a.json", "path": "inbounds[1]"},
            {"part": "01_a.json", "path": "inbounds[2].tag"},
            {"part": "01_a.json", "path": "inbounds[2].protocol"},
            {"part": "02_b.json", "path": "inbounds"},
            {"part": "02_b.json", "path": "dns"},
            {"part": "03_c.json", "path": "routing.rules[4].inboundTag"},
            {"part": "03_c.json", "path": "routing.rules[5]"},
            {"part": "03_c.json", "path": "routing.rules[6].type"},
            {"part": "03_c.json", "path": "routing.balancers[1].selector"},
            {"part": "03_c.json", "path": "routing.balancers[1].strategy"},
            {"part": "03_c.json", "path": "routing.balancers[3]"},
            {"part": "03_c.json", "path": "burstObservatory.subjectSelector"},
            {"part": "03_c.json", "path": "observatory"},
            {"part": "04_d.json", "path": "routing"},
        ])
        text = json.dumps(diagnostic, ensure_ascii=False)
        self.assertNotIn("fixture-private", text)
        for secret in ("d1", "d2", "bittorrent", "random-" , "53"):
            self.assertNotIn(f'"{secret}"', text)
        self.assertEqual(json.loads(json.dumps(diagnostic)), diagnostic)

    def test_rule_list_values_follow_xray_field_types(self):
        config = XrayConfigSet((
            part("01_dns.json", {"dns": {"tag": "dns-a", "servers": [
                "198.51.100.53",
                {"address": "198.51.100.54", "domains": ["geosite:cn", "domain:a.example"], "expectIPs": "geoip:cn,geoip:!private",
                 "expectedIPs": ["geoip:us"], "unexpectedIPs": ["*"]},
                {"address": "198.51.100.55", "domains": "geosite:cn", "expectIPs": 7},
                7,
            ], "hosts": {"geosite:fixture": "127.0.0.1", "a.example": ["127.0.0.1"]}}}),
            part("02_hosts.json", {"dns": {"servers": {"address": "x"}, "hosts": []}}),
            part("03_routing.json", {"routing": {"rules": [
                {"type": "field", "domain": "geosite:ru@attr,ext-domain:a.dat:b", "domains": ["x.example"],
                 "ip": ["geoip:ru", "198.51.100.0/24"], "sourceIP": "ext-ip:s.dat:x",
                 "localIP": ["geoip:private"], "inboundTag": "in-a", "outboundTag": "direct"},
                {"type": "field", "domain": 7, "ip": [5, "geoip:us"], "outboundTag": "direct"},
            ]}}),
        ))
        with forbid_external_effects():
            values = config.rule_list_values()
            diagnostic = config.to_diagnostic()
        dns, routing = "01_dns.json", "03_routing.json"
        self.assertEqual([(value.part, value.path, value.family.value, value.qualified, value.value) for value in values], [
            (dns, "dns.servers[1].domains[0]", "domain", True, "geosite:cn"),
            (dns, "dns.servers[1].domains[1]", "domain", True, "domain:a.example"),
            (dns, "dns.servers[1].expectedIPs[0]", "ip", True, "geoip:us"),
            (dns, "dns.servers[1].unexpectedIPs[0]", "ip", True, "*"),
            (dns, "dns.hosts[0]", "domain", False, "geosite:fixture"),
            (dns, "dns.hosts[1]", "domain", False, "a.example"),
            (routing, "routing.rules[0].domain[0]", "domain", True, "geosite:ru@attr"),
            (routing, "routing.rules[0].domain[1]", "domain", True, "ext-domain:a.dat:b"),
            (routing, "routing.rules[0].domains[0]", "domain", True, "x.example"),
            (routing, "routing.rules[0].ip[0]", "ip", True, "geoip:ru"),
            (routing, "routing.rules[0].ip[1]", "ip", True, "198.51.100.0/24"),
            (routing, "routing.rules[0].sourceIP[0]", "ip", True, "ext-ip:s.dat:x"),
            (routing, "routing.rules[0].localIP[0]", "ip", True, "geoip:private"),
            (routing, "routing.rules[1].ip[1]", "ip", True, "geoip:us"),
        ])
        self.assertEqual(diagnostic["dns_tags"], ["dns-a"])
        self.assertEqual(diagnostic["unsupported_paths"], [
            {"part": dns, "path": "dns.servers[2].domains"},
            {"part": dns, "path": "dns.servers[2].expectIPs"},
            {"part": dns, "path": "dns.servers[3]"},
            {"part": "02_hosts.json", "path": "dns.servers"},
            {"part": "02_hosts.json", "path": "dns.hosts"},
            {"part": routing, "path": "routing.rules[1].domain"},
            {"part": routing, "path": "routing.rules[1].ip[0]"},
        ])
        self.assertEqual(diagnostic["rules"][0]["conditions"], {"domain": 1, "domains": 1, "ip": 2, "sourceIP": 1, "localIP": 1})
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(values)
        for private in ("geosite:", "geoip:", "a.example", "x.example", "198.51.100", "127.0.0.1"):
            self.assertNotIn(private, text)
        self.assertEqual(repr(values[0]), "RuleListValue(part='01_dns.json', path='dns.servers[1].domains[0]', family=domain)")
        self.assertEqual(XrayConfigSet(()).rule_list_values(), ())

    def test_rule_list_values_select_aliases_like_xray(self):
        # Xray v26.3.27: `source` действует только без `sourceIP` или при `null`;
        # `expectIPs` — только при отсутствующем, `null` или пустом `expectedIPs`.
        rule_cases = (
            ({"source": ["geoip:a"]}, ["source"]),
            ({"sourceIP": ["geoip:b"], "source": ["geoip:a"]}, ["sourceIP"]),
            ({"source": ["geoip:a"], "sourceIP": ["geoip:b"]}, ["sourceIP"]),
            ({"sourceIP": None, "source": ["geoip:a"]}, ["source"]),
            ({"sourceIP": [], "source": ["geoip:a"]}, []),
            ({"sourceIP": "", "source": ["geoip:a"]}, ["sourceIP"]),
            ({"sourceIP": "geoip:b"}, ["sourceIP"]),
            ({"domain": ["geosite:a"], "domains": ["geosite:b"]}, ["domain", "domains"]),
        )
        for fields, expected in rule_cases:
            with self.subTest(rule=fields):
                rule = {"type": "field", **fields, "outboundTag": "direct"}
                config = XrayConfigSet((part("01_routing.json", {"routing": {"rules": [rule]}}),))
                with forbid_external_effects():
                    values = config.rule_list_values()
                    diagnostic = config.to_diagnostic()
                self.assertEqual([value.path.split(".")[-1].split("[")[0] for value in values], expected)
                self.assertEqual(diagnostic["unsupported_paths"], [])
                # Поля конфигурации и счётчики условий сохраняются как в файле.
                self.assertEqual(set(diagnostic["rules"][0]["conditions"]), set(fields))
        dns_cases = (
            ({"expectIPs": ["geoip:a"]}, ["expectIPs"]),
            ({"expectedIPs": ["geoip:b"], "expectIPs": ["geoip:a"]}, ["expectedIPs"]),
            ({"expectIPs": "geoip:a", "expectedIPs": "geoip:b"}, ["expectedIPs"]),
            ({"expectedIPs": None, "expectIPs": ["geoip:a"]}, ["expectIPs"]),
            ({"expectedIPs": [], "expectIPs": ["geoip:a"]}, ["expectIPs"]),
            ({"expectedIPs": "", "expectIPs": ["geoip:a"]}, ["expectedIPs"]),
            ({"expectedIPs": ["geoip:b"], "unexpectedIPs": ["geoip:c"], "expectIPs": ["geoip:a"]}, ["expectedIPs", "unexpectedIPs"]),
        )
        for fields, expected in dns_cases:
            with self.subTest(dns=fields):
                config = XrayConfigSet((part("01_dns.json", {"dns": {"servers": [{"address": "198.51.100.53", **fields}]}}),))
                with forbid_external_effects():
                    values = config.rule_list_values()
                    diagnostic = config.to_diagnostic()
                self.assertEqual([value.path.split(".")[-1].split("[")[0] for value in values], expected)
                self.assertEqual(diagnostic["unsupported_paths"], [])

    def test_decode_string_list_follows_xray_decoder(self):
        for value, expected in (
            ("a,b", ("a", "b")), ("", ("",)), ("a,, b", ("a", "", " b")), (["a,b"], ("a,b",)), ([], ()),
            (["a", "b"], ("a", "b")), (None, None), (7, None), (["a", 7], None), ({"a": 1}, None), (True, None),
            (("a",), None),
        ):
            with self.subTest(value=value):
                self.assertEqual(decode_string_list(value), expected)

    def test_duplicate_tags_keep_order_without_repeats_in_linear_time(self):
        outbounds = [{"tag": tag, "protocol": "freedom"} for tag in ("b", "a", "b", "c", "a", "b", "a")]
        diagnostic = XrayConfigSet((part("01_out.json", {"outbounds": outbounds}),)).to_diagnostic()
        self.assertEqual(diagnostic["duplicate_outbound_tags"], ["b", "a"])
        # Каждый из множества тегов повторяется дважды: проверки «уже найден» не должны идти по списку.
        timings = []
        for size in (4000, 16000):
            tags = [f"out-{index}" for index in range(size)]
            config = XrayConfigSet((part("01_out.json", {"outbounds": [{"tag": tag} for tag in tags * 2]}),))
            with patch("keenvpn.domain.xray_config._duplicates", wraps=_duplicates) as wrapped:
                started = time.perf_counter()
                result = config.to_diagnostic()["duplicate_outbound_tags"]
                timings.append(time.perf_counter() - started)
            self.assertEqual(result, tags)
            self.assertEqual(wrapped.call_count, 3)
        # При квадратичной стоимости четырёхкратный рост дал бы примерно шестнадцатикратное время.
        self.assertLess(timings[1], timings[0] * 10 + 0.05)

    def test_empty_set_and_rejections(self):
        with forbid_external_effects():
            empty = XrayConfigSet(())
        diagnostic = empty.to_diagnostic()
        self.assertEqual((diagnostic["part_count"], diagnostic["parts"], diagnostic["rule_count"]), (0, [], 0))
        self.assertEqual(diagnostic["sections"], {})
        validate_xray_config_set(empty)
        log = part("01_log.json", {"log": {}})
        for parts in ([log], (log, log), (log, part("01_log.json", {"dns": {}})), (log, None), ("fixture-private",)):
            with self.subTest(parts=type(parts).__name__), self.assertRaises(XrayConfigError) as caught:
                XrayConfigSet(parts)
            self.assertIs(caught.exception.code, XrayConfigErrorCode.PARTS)
            self.assertNotIn("fixture-private", str(caught.exception))

    def test_validation_detects_tampering_and_foreign_types(self):
        class Derived(XrayConfigSet):
            pass

        config = XrayConfigSet((part("01_log.json", {"log": {}}), part("02_dns.json", {"dns": {}})))
        validate_xray_config_set(config)
        for broken in (Derived(()), None, config.parts):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(XrayConfigError) as caught:
                validate_xray_config_set(broken)
            self.assertIs(caught.exception.code, XrayConfigErrorCode.CONFIG)
        duplicated = XrayConfigSet(config.parts)
        object.__setattr__(duplicated, "parts", (config.parts[0], config.parts[0]))
        with self.assertRaises(XrayConfigError) as caught:
            validate_xray_config_set(duplicated)
        self.assertIs(caught.exception.code, XrayConfigErrorCode.PARTS)
        tampered = XrayConfigSet(config.parts)
        object.__setattr__(tampered.parts[1], "sha256", "0" * 64)
        with self.assertRaises(ConfigDocumentError) as caught:
            validate_xray_config_set(tampered)
        self.assertIs(caught.exception.code, ConfigDocumentErrorCode.DOCUMENT)
        with self.assertRaises(FrozenInstanceError):
            config.parts = ()

    def test_errors_are_detached_from_foreign_context(self):
        try:
            raise ValueError("fixture-private-context")
        except ValueError:
            with self.assertRaises(XrayConfigError) as caught:
                XrayConfigSet(("fixture-private",))
        error = caught.exception
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn("fixture-private", str(error) + repr(error))


class EmptyTargetTagTests(unittest.TestCase):
    """Регрессия GitHub review 76-R09: пустые `outboundTag`, `balancerTag` и `fallbackTag` — отсутствующие значения, как в Xray."""

    def diagnostic(self, rule, fallback=None):
        balancer = {"tag": "g", "selector": ["proxy-"]}
        if fallback is not None:
            balancer["fallbackTag"] = fallback
        document = {
            "outbounds": [{"tag": "", "protocol": "freedom"}, {"tag": "proxy-a", "protocol": "trojan"}],
            "routing": {"rules": [{"type": "field", "network": "tcp", **rule}], "balancers": [balancer, {"tag": "", "selector": ["x"]}]},
        }
        return XrayConfigSet((part("05_routing.json", document),)).to_diagnostic()

    def test_empty_rule_targets_are_absent(self):
        for rule, kind, tag_known, resolved in (
            ({"outboundTag": ""}, "none", False, False),
            ({"balancerTag": ""}, "none", False, False),
            ({"outboundTag": "", "balancerTag": ""}, "none", False, False),
            ({"outboundTag": "", "balancerTag": "g"}, "balancer", True, True),
            ({"outboundTag": "proxy-a", "balancerTag": ""}, "outbound", True, True),
            ({"outboundTag": "proxy-a", "balancerTag": "g"}, "both", False, False),
        ):
            with self.subTest(rule=rule):
                item = self.diagnostic(rule)["rules"][0]
                self.assertEqual((item["target_kind"], item["target_tag_known"], item["target_resolved"]), (kind, tag_known, resolved))

    def test_empty_fallback_tag_is_not_set(self):
        balancer = self.diagnostic({"balancerTag": "g"}, fallback="")["balancers"][0]
        self.assertEqual(
            (balancer["fallback_known"], balancer["fallback_tag"], balancer["fallback_resolved"], balancer["fallback_position"]),
            (False, None, None, None),
        )
        self.assertEqual(self.diagnostic({"balancerTag": "g"}, fallback="")["unsupported_paths"], [])
        self.assertTrue(self.diagnostic({"balancerTag": "g"}, fallback="proxy-a")["balancers"][0]["fallback_resolved"])


class DnsServerTagTests(unittest.TestCase):
    """Регрессия review 76-R03: тег отдельного DNS-сервера разрешает ссылку `inboundTag`, в сводку не входит."""

    def summary(self, servers, inbound_tag):
        document = {
            "outbounds": [{"tag": "direct-out", "protocol": "freedom"}],
            "dns": {"tag": "dns-local", "servers": servers},
            "routing": {"rules": [{"type": "field", "inboundTag": [inbound_tag], "outboundTag": "direct-out"}]},
        }
        return XrayConfigSet((part("04_test.json", document),)).to_diagnostic()

    def test_server_tag_resolves_an_inbound_reference_without_being_shown(self):
        servers = [{"address": "198.51.100.1", "tag": "fixture-private"}, "198.51.100.2", {"address": "198.51.100.3"}]
        diagnostic = self.summary(servers, "fixture-private")
        self.assertTrue(diagnostic["rules"][0]["inbound_tags_resolved"])
        self.assertEqual(diagnostic["dns_tags"], ["dns-local"])
        self.assertEqual(diagnostic["unsupported_paths"], [])
        self.assertNotIn("fixture-private", json.dumps({**diagnostic, "rules": [{**diagnostic["rules"][0], "inbound_tags": []}]}))
        self.assertTrue(self.summary(servers, "dns-local")["rules"][0]["inbound_tags_resolved"])

    def test_missing_empty_or_non_string_server_tag_does_not_resolve(self):
        self.assertFalse(self.summary([{"address": "198.51.100.1"}], "dns-upstream")["rules"][0]["inbound_tags_resolved"])
        # Регрессия повторного review 76-R05: пустой тег сервера равен отсутствующему — запросы несут общий `dns.tag`.
        for servers in ([{"address": "198.51.100.1", "tag": ""}], [{"address": "198.51.100.1"}]):
            with self.subTest(servers=servers):
                diagnostic = self.summary(servers, "")
                self.assertFalse(diagnostic["rules"][0]["inbound_tags_resolved"])
                self.assertEqual(diagnostic["unsupported_paths"], [])
                self.assertTrue(self.summary(servers, "dns-local")["rules"][0]["inbound_tags_resolved"])
        diagnostic = self.summary([{"address": "198.51.100.1", "tag": 7}], "7")
        self.assertFalse(diagnostic["rules"][0]["inbound_tags_resolved"])
        self.assertEqual(diagnostic["unsupported_paths"], [{"part": "04_test.json", "path": "dns.servers[0].tag"}])


class TagRepeatsTests(unittest.TestCase):
    """Повторы тегов раздельно внутри частей и между частями по исходным значениям; для доверенного кода."""

    def test_repeats_within_and_between_parts_are_separated_in_order(self):
        parts = (
            part("01_in.json", {"inbounds": [{"tag": "lan"}, {"tag": "lan"}, {"tag": "wan"}]}),
            part("04_out.json", {"outbounds": [{"tag": "proxy"}, {"tag": "direct"}, {"tag": 7}, {}],
                                 "routing": {"balancers": [{"tag": "group"}]}}),
            part("05_tail.json", {"outbounds": [{"tag": "direct"}, {"tag": "fixture-private"}, {"tag": "fixture-private"}],
                                  "routing": {"balancers": [{"tag": "group"}]}}),
        )
        repeats = tag_repeats(parts)
        self.assertIsInstance(repeats, TagRepeats)
        self.assertEqual(
            [(item.section, item.tag, item.parts) for item in repeats.within_parts],
            [("inbounds", "lan", ("01_in.json", "01_in.json")),
             ("outbounds", "fixture-private", ("05_tail.json", "05_tail.json"))],
        )
        self.assertEqual(
            [(item.section, item.tag, item.parts) for item in repeats.between_parts],
            [("outbounds", "direct", ("04_out.json", "05_tail.json")),
             ("balancers", "group", ("04_out.json", "05_tail.json"))],
        )
        # Значение тега приватно: repr показывает только секцию и число частей.
        self.assertEqual(repr(repeats.within_parts[1]), "TagRepeat(section='outbounds', parts=2)")
        self.assertNotIn("fixture-private", repr(repeats))
        self.assertEqual(tag_repeats(()), TagRepeats((), ()))
        self.assertEqual(tag_repeats(snapshot_xray_config().parts), TagRepeats((), ()))

    def test_tag_in_both_lists_and_non_string_or_empty_tags_are_ignored(self):
        # Регрессия review 76-R04: пустой тег — отсутствие имени, повтором не считается ни внутри части, ни между частями.
        parts = (
            part("01_a.json", {"outbounds": [{"tag": "x"}, {"tag": "x"}, {"tag": None}, {"tag": ["x"]}, {"tag": ""}, {"tag": ""}],
                               "inbounds": [{"tag": ""}, {"tag": ""}, {}]}),
            part("02_b.json", {"outbounds": [{"tag": "x"}, {"tag": None}, {"tag": ""}], "inbounds": [{"tag": ""}]}),
        )
        repeats = tag_repeats(parts)
        self.assertEqual([(item.tag, item.parts) for item in repeats.within_parts], [("x", ("01_a.json", "01_a.json", "02_b.json"))])
        self.assertEqual([(item.tag, item.parts) for item in repeats.between_parts], [("x", ("01_a.json", "01_a.json", "02_b.json"))])
        with self.assertRaises(FrozenInstanceError):
            repeats.within_parts[0].tag = "y"


class UnsafeIdentifierSummaryTests(unittest.TestCase):
    """Строки из конфигурации выводятся только после проверки формата или по списку известных значений Xray."""

    def test_unsafe_tags_strategies_protocols_and_names_are_hidden_with_known_flags_and_positions(self):
        config = unsafe_xray_config()
        with forbid_external_effects():
            diagnostic = config.to_diagnostic()
        part = UNSAFE_PART_NAME
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(config) + repr(config.parts)
        for marker in UNSAFE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertEqual(json.loads(json.dumps(diagnostic)), diagnostic)
        self.assertEqual(diagnostic["part_count"], 1)
        self.assertEqual(diagnostic["parts"][0]["sections"], ["log", "inbounds", "outbounds", "dns", "routing", "observatory"])
        self.assertEqual(diagnostic["parts"][0]["unknown_section_count"], 1)
        self.assertEqual(set(diagnostic["parts"][0]), {"name", "size", "sha256", "sections", "unknown_section_count"})
        self.assertEqual(set(diagnostic["sections"]), {"log", "inbounds", "outbounds", "dns", "routing", "observatory"})
        self.assertEqual(diagnostic["duplicate_sections"], [])
        self.assertEqual(diagnostic["dns_tags"], [None])
        self.assertEqual(diagnostic["domain_strategies"], [None])

        def endpoint(index, tag, protocol):
            return {
                "part": part, "index": index, "tag_known": True, "tag": tag, "protocol_known": True, "protocol": protocol,
            }

        self.assertEqual(diagnostic["inbounds"], [
            endpoint(0, None, None), endpoint(1, "lan", "tunnel"), endpoint(2, None, None),
        ])
        self.assertEqual(diagnostic["outbounds"], [
            endpoint(0, None, None), endpoint(1, "proxy-safe", "trojan"), endpoint(2, None, None),
            endpoint(3, None, "freedom"), endpoint(4, None, "freedom"),
        ])
        self.assertEqual(diagnostic["duplicate_inbound_tags"], [])
        self.assertEqual(diagnostic["duplicate_outbound_tags"], [None])
        self.assertEqual(diagnostic["duplicate_balancer_tags"], [])
        self.assertEqual(diagnostic["rule_count"], 3)
        self.assertEqual(diagnostic["rules"], [
            {
                "part": part, "index": 0, "type_known": True, "type": None, "inbound_tags": [None, "lan"],
                "inbound_tags_resolved": True, "target_kind": "outbound", "target_tag_known": True, "target_tag": None,
                "target_resolved": True, "target_position": None, "has_rule_tag": False,
                "conditions": {"domain": 1}, "unknown_condition_count": 1,
            },
            {
                "part": part, "index": 1, "type_known": True, "type": "field", "inbound_tags": [],
                "inbound_tags_resolved": True, "target_kind": "balancer", "target_tag_known": True, "target_tag": None,
                "target_resolved": True, "target_position": {"part": part, "index": 0}, "has_rule_tag": False,
                "conditions": {}, "unknown_condition_count": 2,
            },
            {
                "part": part, "index": 2, "type_known": True, "type": "field", "inbound_tags": [],
                "inbound_tags_resolved": True, "target_kind": "outbound", "target_tag_known": True,
                "target_tag": "proxy-safe", "target_resolved": True, "target_position": {"part": part, "index": 1},
                "has_rule_tag": False, "conditions": {"network": 1}, "unknown_condition_count": 0,
            },
        ])
        self.assertEqual(diagnostic["balancers"], [
            {
                "part": part, "index": 0, "tag_known": True, "tag": None, "selector": [None, "proxy-", ""],
                "selector_match_count": 5, "fallback_known": True, "fallback_tag": None, "fallback_resolved": True,
                "fallback_position": {"part": part, "index": 3}, "strategy_known": True, "strategy": None,
            },
            {
                "part": part, "index": 1, "tag_known": True, "tag": "pool", "selector": [""],
                "selector_match_count": 5, "fallback_known": True, "fallback_tag": "proxy-safe", "fallback_resolved": True,
                "fallback_position": {"part": part, "index": 1}, "strategy_known": True, "strategy": "leastPing",
            },
        ])
        self.assertEqual(diagnostic["observatory_subjects"], [
            {"part": part, "section": "observatory", "selector": None, "match_count": 0},
            {"part": part, "section": "observatory", "selector": "proxy-", "match_count": 1},
        ])
        self.assertEqual(diagnostic["unsupported_paths"], [])
        self.assertEqual(config.parts[0].content, unsafe_xray_config().parts[0].content)


if __name__ == "__main__":
    unittest.main()
