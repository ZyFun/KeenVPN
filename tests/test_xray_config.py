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
from keenvpn.domain.xray_config import (
    XrayConfigError, XrayConfigErrorCode, XrayConfigSet, _duplicates, summarize_xray_config, validate_xray_config_set,
)
from tests.support.isolation import forbid_external_effects
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
            "part": "05_routing.json", "tag": "vpn-group", "selector": ["trojan-out"], "selector_match_count": 1,
            "fallback_tag": "blocked", "fallback_resolved": True, "strategy": "leastPing",
        }])
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


class SyntheticXrayConfigTests(unittest.TestCase):
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
                {"type": "field", "inboundTag": "in-a", "protocol": ["bittorrent"]},
                "fixture-private", {"type": 7, "ip": []},
            ], "balancers": [
                {"tag": "group", "selector": ["out-", "none-"], "fallbackTag": "missing", "strategy": {"type": "random"}},
                {"tag": "group", "selector": "out-a", "strategy": "leastPing"},
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
            {"part": "01_a.json", "tag": "in-a", "protocol": "tunnel"},
            {"part": "01_a.json", "tag": None, "protocol": None},
            {"part": "01_a.json", "tag": None, "protocol": "dokodemo-door"},
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
        self.assertTrue(all(rule["part"] == "03_c.json" for rule in diagnostic["rules"]))
        self.assertEqual(diagnostic["balancers"], [
            {"part": "03_c.json", "tag": "group", "selector": ["out-", "none-"], "selector_match_count": 3,
             "fallback_tag": "missing", "fallback_resolved": False, "strategy": "random"},
            {"part": "03_c.json", "tag": "group", "selector": [], "selector_match_count": 0,
             "fallback_tag": None, "fallback_resolved": None, "strategy": None},
            {"part": "03_c.json", "tag": None, "selector": [], "selector_match_count": 0,
             "fallback_tag": None, "fallback_resolved": None, "strategy": None},
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


if __name__ == "__main__":
    unittest.main()
