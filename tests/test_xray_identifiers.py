"""Общая проверка формата идентификаторов Xray и списки известных значений установленной версии."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain import routing_import
from keenvpn.domain.xray_identifiers import (
    BALANCER_STRATEGIES, DOMAIN_STRATEGIES, INBOUND_PROTOCOLS, OUTBOUND_PROTOCOLS, RULE_TYPES, XRAY_RULE_CONDITION_FIELDS,
    XRAY_SECTIONS, XRAY_VERSION, known_condition_field, known_section, safe_domain_strategy, safe_identifier,
    safe_inbound_protocol, safe_outbound_protocol, safe_rule_type, safe_selector, safe_strategy,
)
from tests.support.privacy import UNSAFE_IDENTIFIERS


class KnownValueListTests(unittest.TestCase):
    """Списки зафиксированы по исходникам тега Xray-core, указанного в `XRAY_VERSION`."""

    def test_lists_match_xray_sources_of_the_pinned_version(self):
        self.assertEqual(XRAY_VERSION, "v26.3.27")
        # infra/conf/router.go: BalancingRule.Build, strings.ToLower(r.Strategy.Type).
        self.assertEqual(BALANCER_STRATEGIES, frozenset({"random", "leastping", "roundrobin", "leastload"}))
        # infra/conf/router.go: getDomainStrategy, strings.ToLower; остальное Xray считает AsIs.
        self.assertEqual(DOMAIN_STRATEGIES, frozenset({"asis", "ipifnonmatch", "ipondemand"}))
        # infra/conf/xray.go: inboundConfigLoader и outboundConfigLoader; infra/conf/loader.go: LoadWithID, strings.ToLower.
        self.assertEqual(INBOUND_PROTOCOLS, frozenset({
            "tunnel", "dokodemo-door", "http", "shadowsocks", "mixed", "socks", "vless", "vmess", "trojan", "wireguard",
            "hysteria", "tun",
        }))
        self.assertEqual(OUTBOUND_PROTOCOLS, frozenset({
            "block", "blackhole", "loopback", "direct", "freedom", "http", "shadowsocks", "socks", "vless", "vmess",
            "trojan", "hysteria", "dns", "wireguard",
        }))
        # Декодер `parseRule` поле `type` не читает; документированное значение одно.
        self.assertEqual(RULE_TYPES, frozenset({"field"}))
        # infra/conf/router.go: json-теги RawFieldRule без служебных ruleTag, outboundTag, balancerTag.
        self.assertEqual(XRAY_RULE_CONDITION_FIELDS, frozenset({
            "domain", "domains", "ip", "port", "network", "sourceIP", "source", "sourcePort", "user", "vlessRoute",
            "inboundTag", "protocol", "attrs", "localIP", "localPort", "process", "webhook",
        }))
        # infra/conf/xray.go: json-теги структуры Config.
        self.assertEqual(XRAY_SECTIONS, frozenset({
            "log", "api", "dns", "routing", "policy", "inbounds", "outbounds", "transport", "stats", "reverse", "fakeDns",
            "metrics", "observatory", "burstObservatory", "version",
        }))
        self.assertTrue(routing_import.DIRECT_OUTBOUND_PROTOCOLS | routing_import.BLOCK_OUTBOUND_PROTOCOLS
                        | routing_import.VPN_OUTBOUND_PROTOCOLS <= OUTBOUND_PROTOCOLS)

    def test_import_module_keeps_the_shared_names(self):
        self.assertIs(routing_import.safe_identifier, safe_identifier)
        self.assertIs(routing_import.safe_strategy, safe_strategy)
        self.assertIs(routing_import.BALANCER_STRATEGIES, BALANCER_STRATEGIES)
        self.assertIs(routing_import.XRAY_RULE_CONDITION_FIELDS, XRAY_RULE_CONDITION_FIELDS)


class SafeValueTests(unittest.TestCase):
    def test_safe_identifier_accepts_only_technical_identifiers(self):
        for value in ("direct", "trojan-out", "vpn_group-1+x", "A" * 128, "2001", "TEST_ONLY_SECRET_235"):
            # Последнее значение — известное ограничение: секрет без разделителей форматом не отличить от тега.
            self.assertEqual(safe_identifier(value), value)
        for value in (None, 7, True, "", "-x", "a b", "a/b", "a:b", "user@host", "a\nb", "A" * 129, "тег", "a\x00",
                      "198.51.100.7", "private.example.test", "vpn.group", "2001:db8::1", "::1", "0.0.0.0", b"tag"):
            self.assertIsNone(safe_identifier(value))
        for value in UNSAFE_IDENTIFIERS.values():
            self.assertIsNone(safe_identifier(value))

        class Tag(str):
            pass

        self.assertIsNone(safe_identifier(Tag("direct")))

    def test_safe_selector_keeps_only_the_empty_selector(self):
        self.assertEqual(safe_selector(""), "")
        self.assertEqual(safe_selector("proxy-"), "proxy-")
        for value in (" ", None, 0, False, "a b", "198.51.100.7"):
            self.assertIsNone(safe_selector(value))

    def test_known_values_are_compared_like_xray_loaders(self):
        for value in ("random", "leastPing", "RoundRobin", "LEASTLOAD"):
            self.assertEqual(safe_strategy(value), value)
        for value in ("AsIs", "IPIfNonMatch", "ipondemand"):
            self.assertEqual(safe_domain_strategy(value), value)
        for value in ("tunnel", "Dokodemo-Door", "VLESS"):
            self.assertEqual(safe_inbound_protocol(value), value)
        for value in ("freedom", "Blackhole", "TROJAN", "direct", "block"):
            self.assertEqual(safe_outbound_protocol(value), value)
        self.assertEqual(safe_rule_type("field"), "field")
        for check in (safe_strategy, safe_domain_strategy, safe_inbound_protocol, safe_outbound_protocol, safe_rule_type):
            for value in (None, "", 7, True, "https://x", "leastPing2", "UseIP", "Field", "FIELD", "loopback-", *UNSAFE_IDENTIFIERS.values()):
                with self.subTest(check=check.__name__, value=value):
                    self.assertIsNone(check(value))
        # Протоколы inbound и outbound — разные списки загрузчика.
        self.assertIsNone(safe_inbound_protocol("freedom"))
        self.assertIsNone(safe_outbound_protocol("tunnel"))
        self.assertIsNone(safe_rule_type("field "))
        # Не-ASCII строка скрывается, даже если `lower()` сводит её к известному имени (знак Кельвина U+212A → `k`).
        self.assertEqual("soc\u212as".lower(), "socks")
        self.assertIsNone(safe_inbound_protocol("soc\u212as"))
        self.assertIsNone(safe_outbound_protocol("bloc\u212a"))
        self.assertIsNone(safe_strategy("leastp\u0130ng"))
        self.assertEqual(safe_outbound_protocol("SOCKS"), "SOCKS")

    def test_section_and_condition_field_names_are_exact(self):
        self.assertTrue(known_section("routing") and known_section("fakeDns") and known_section("burstObservatory"))
        for name in ("Routing", "fakedns", "FakeDNS", "", None, 7, "private.example.test", "dnsx"):
            self.assertFalse(known_section(name))
        self.assertTrue(known_condition_field("sourceIP") and known_condition_field("domain"))
        for name in ("sourceip", "SourceIP", "ruleTag", "outboundTag", "balancerTag", "type", "localOS", "", None, 7):
            self.assertFalse(known_condition_field(name))


if __name__ == "__main__":
    unittest.main()
