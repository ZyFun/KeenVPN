"""Проверки обезличенных фикстур; без исполнения конфигов и обращения к роутеру."""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent / "fixtures" / "router_snapshot"
FILES = {
    "keenetic.json", "xkeen.json",
    "xray/01_log.json", "xray/02_dns.json", "xray/03_inbounds.json",
    "xray/04_outbounds.json", "xray/05_routing.json", "xray/06_policy.json",
    "xray/07_observatory.json",
}
SCHEMA_KEYS = frozenset("""
    ip/policy ip/hotspot known/host show/ip/hotspot dns-proxy ip/name-server ipv6 opkg
    description permit enabled interface no policy host auto-register access deny disable
    mac priority conform name hostname ip ip6 registered active id schedule
    traffic-shape rx tx mode rebind-protect auto intercept enable https upstream
    url format filter assign preset subnet Default bind slaac prefix length number
    disk initrc path settings xkeen verify_downloads killswitch init_flags start_auto
    proxy_dns proxy_router ipv6_support lists port_exclude.lst port_proxying.lst
    ip_exclude.lst log error loglevel dnsLog dns servers address port queryStrategy
    tag inbounds listen protocol followRedirect network sniffing destOverride routeOnly
    streamSettings sockopt tproxy outbounds password security tlsSettings serverName
    fingerprint allowInsecure wsSettings mark domainStrategy routing rules type
    inboundTag outboundTag ruleTag domain balancerTag balancers selector fallbackTag
    strategy levels 0 handshake connIdle uplinkOnly downlinkOnly burstObservatory
    subjectSelector pingConfig destination interval sampling timeout httpMethod
""".split())
LITERALS = frozenset("""
    Bridge0 Bridge1 GigabitEthernet1 WifiMaster1/WifiStation0
    permit deny disable strict dnsm yandex-base on off mac
    none warning UseIP UseIPv4v6 IPOnDemand dns-local redirect tproxy
    force-proxy-redirect force-proxy-tproxy tunnel tcp udp tcp,udp http quic ws tls
    firefox trojan-out trojan direct freedom blocked blackhole field vpn-group
    leastPing HEAD 15s 5s 0 geoip:ru domain:ru domain:su domain:xn--p1ai full:localhost
    /opt/etc/init.d/rc.unslung /opt/var/log/xray/error.log /fixture/ws
    fixture-interface fixture-password-not-a-credential
    00000000-0000-4000-8000-000000000054:/
""".split()) | {""}
SPECIAL_NETWORKS = frozenset("""
    0.0.0.0 0.0.0.0/8 :: ::/128 127.0.0.1 127.0.0.0/8 ::1/128
    10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24
    192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.51.100.0/24
    203.0.113.0/24 224.0.0.0/4 255.255.255.255/32 fc00::/7 fe80::/10 ff00::/8
""".split())
LIST_COMMENT = "# Обезличенный снимок: исходные комментарии опущены.\n"


def strict_json(text):
    """Не скрывать дубли ключей и нестандартные NaN/Infinity."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Повтор JSON-ключа")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("Недопустимая JSON-константа")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)


def safe_string(value):
    """Разрешить только рассмотренные технические и искусственные значения."""
    if value in LITERALS | SPECIAL_NETWORKS | {LIST_COMMENT, LIST_COMMENT + "53\n"}:
        return True
    patterns = (
        r"Policy(?:10|20|30)", r"device-\d{2}",
        r"fixture-(?:policy-\d+|rule-\d{2}|schedule)",
        r"02:00:00:54:00:[0-9a-f]{2}",
        r"(?:(?:domain|full):)?host-\d{2}\.example",
        r"https://dns-\d+\.example/dns-query", r"https://probe\.example/check",
    )
    if any(re.fullmatch(pattern, value) for pattern in patterns):
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address in ipaddress.ip_network("192.0.2.0/24") or address in ipaddress.ip_network("2001:db8:54::/64")


def assert_safe_values(value):
    """Не выводить неизвестное значение даже при провале проверки приватности."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in SCHEMA_KEYS and not re.fullmatch(r"Policy(?:10|20|30)|device-\d{2}", key):
                raise ValueError("Неизвестный ключ: требуется проверка обезличивания")
            assert_safe_values(child)
    elif isinstance(value, list):
        for child in value:
            assert_safe_values(child)
    elif isinstance(value, str) and not safe_string(value):
        raise ValueError("Неизвестная строка: требуется проверка обезличивания")


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = {name: strict_json((ROOT / name).read_text()) for name in FILES}
        # Не допустить вывода персональных строк последующими assertEqual/diff.
        for value in cls.data.values():
            assert_safe_values(value)

    def test_inventory_and_revisions(self):
        """Не читать пути вне набора и замечать даже изменение порядка JSON-массивов."""
        manifest = strict_json((ROOT / "manifest.json").read_text())
        self.assertEqual(manifest["format_version"], 1)
        self.assertEqual(manifest["kind"], "anonymized-config-projection")
        self.assertEqual(set(manifest["files"]), FILES)
        actual = {str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file()}
        self.assertEqual(actual, FILES | {"manifest.json", "README.md"})
        self.assertFalse(any(p.is_symlink() for p in ROOT.rglob("*")))
        for name, digest in manifest["files"].items():
            with self.subTest(file=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_no_unreviewed_strings_or_personal_identifiers(self):
        """Проверить также ключи реестра устройств, а не только поля password."""
        for name, value in self.data.items():
            with self.subTest(file=name):
                assert_safe_values(value)

    def test_privacy_guard_rejects_injected_values_without_echoing_them(self):
        """Искусственные адреса, имя, секрет и неизвестный ключ не проходят защиту."""
        cases = [
            {"password": "TEST_SECRET_NOT_FOR_FIXTURES"},
            {"mac": "de:ad:be:ef:00:01"},
            {"address": "198.51.100.42"},
            {"name": "Example Person"},
            {"domain": ["full:example.net"]},
            {"Example Person": {"mac": "02:00:00:54:00:01"}},
        ]
        for index, case in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError) as error:
                assert_safe_values(case)
            self.assertNotIn("TEST_SECRET", str(error.exception))

    def test_strict_json_rejects_ambiguous_input(self):
        """Проверка снимка не должна молча принимать потерю ключа или не-JSON."""
        for content in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                strict_json(content)

    def test_device_identity_and_policy_references(self):
        """Регистрация, настройки и runtime описывают одни и те же объекты."""
        native = self.data["keenetic.json"]
        policies = native["ip/policy"]
        registrations = native["known/host"]
        configured = native["ip/hotspot"]["host"]
        observed = native["show/ip/hotspot"]["host"]
        expected_macs = {entry["mac"] for entry in registrations.values()}
        self.assertEqual(len(expected_macs), len(registrations))
        for entries in (configured, observed):
            self.assertEqual({entry["mac"] for entry in entries}, expected_macs)
            self.assertEqual(len(entries), len(expected_macs))
            for entry in entries:
                if entry.get("policy"):
                    self.assertIn(entry["policy"], policies)
        for entry in native["ip/hotspot"]["policy"]:
            if "policy" in entry:
                self.assertIn(entry["policy"], policies)
        by_mac = {entry["mac"]: name for name, entry in registrations.items()}
        for entry in observed:
            self.assertEqual(entry["name"], by_mac[entry["mac"]])
        for policy in policies.values():
            self.assertIsInstance(policy["permit"], list)
        for entry in configured:
            if "permit" in entry:
                self.assertIsInstance(entry["permit"], bool)

    def test_distinct_assignment_states_survive_anonymization(self):
        """Наследование, отсутствие назначения и запрет не становятся DIRECT."""
        native = self.data["keenetic.json"]
        entries = native["ip/hotspot"]["host"]
        runtime = {entry["mac"]: entry for entry in native["show/ip/hotspot"]["host"]}
        inherited = [entry for entry in entries if entry.get("conform") is True]
        unassigned = [entry for entry in entries if "policy" not in entry and "conform" not in entry and entry["access"] != "deny"]
        blocked = [entry for entry in entries if entry["access"] == "deny"]
        self.assertTrue(inherited and unassigned and blocked)
        segment_policy = native["ip/hotspot"]["policy"][0]["policy"]
        for entry in inherited:
            self.assertNotIn("policy", entry)
            self.assertEqual(runtime[entry["mac"]]["policy"], segment_policy)
        for entry in unassigned + blocked:
            self.assertEqual(runtime[entry["mac"]]["policy"], "")
        for entry in blocked:
            self.assertTrue(entry["deny"])
            self.assertEqual(runtime[entry["mac"]]["access"], "deny")
        self.assertTrue(any("priority" in entry and "policy" in entry for entry in entries))

    def test_xray_references_and_transport_are_consistent(self):
        """Обезличивание не ломает ссылки между правилами, выходами и транспортом."""
        inbound_entries = self.data["xray/03_inbounds.json"]["inbounds"]
        inbounds = {entry["tag"] for entry in inbound_entries}
        self.assertEqual(len(inbounds), len(inbound_entries))
        inbounds.add(self.data["xray/02_dns.json"]["dns"]["tag"])
        outbounds = {entry["tag"]: entry for entry in self.data["xray/04_outbounds.json"]["outbounds"]}
        self.assertEqual(len(outbounds), len(self.data["xray/04_outbounds.json"]["outbounds"]))
        routing = self.data["xray/05_routing.json"]["routing"]
        balancers = {entry["tag"]: entry for entry in routing["balancers"]}
        self.assertEqual(len(balancers), len(routing["balancers"]))
        for rule in routing["rules"]:
            self.assertLessEqual(set(rule.get("inboundTag", [])), inbounds)
            self.assertEqual(sum(key in rule for key in ("outboundTag", "balancerTag")), 1)
            if "outboundTag" in rule:
                self.assertIn(rule["outboundTag"], outbounds)
            else:
                self.assertIn(rule["balancerTag"], balancers)
        selectors = list(self.data["xray/07_observatory.json"]["burstObservatory"]["subjectSelector"])
        for group in balancers.values():
            self.assertIn(group["fallbackTag"], outbounds)
            self.assertEqual(outbounds[group["fallbackTag"]]["protocol"], "blackhole")
            selectors.extend(group["selector"])
        for selector in selectors:
            self.assertTrue(any(tag.startswith(selector) for tag in outbounds))
        for outbound in outbounds.values():
            if outbound["protocol"] != "trojan":
                continue
            stream = outbound["streamSettings"]
            server = outbound["settings"]["servers"][0]
            self.assertEqual(server["address"], stream["tlsSettings"]["serverName"])
            self.assertEqual(server["address"], stream["wsSettings"]["host"])
            self.assertFalse(stream["tlsSettings"]["allowInsecure"])
        final_rule = routing["rules"][-1]
        self.assertEqual(set(final_rule), {"type", "network", "ruleTag", "balancerTag"})

    def test_dns_layers_and_port_lists_are_distinct(self):
        """Не терять сочетание native DNS и исключения существующей установки."""
        native = self.data["keenetic.json"]
        xkeen = self.data["xkeen.json"]
        self.assertTrue(native["dns-proxy"]["intercept"]["enable"])
        self.assertEqual(xkeen["init_flags"]["proxy_dns"], "off")
        self.assertEqual(xkeen["init_flags"]["proxy_router"], "off")
        values = {name: [line for line in text.splitlines() if line and not line.startswith("#")]
                  for name, text in xkeen["lists"].items()}
        self.assertEqual(values["port_exclude.lst"], ["53"])
        self.assertEqual(values["port_proxying.lst"], [])
        self.assertEqual(values["ip_exclude.lst"], [])
        self.assertEqual(xkeen["settings"]["xkeen"]["killswitch"], "on")


if __name__ == "__main__":
    unittest.main()
