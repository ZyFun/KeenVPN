"""Семантический ключ правила и привязка записей метаданных к правилам: в памяти, без Xray и роутера."""

from dataclasses import replace
import json
from pathlib import Path
import sys
import traceback
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain import rule_binding as module
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.manager_metadata import (
    ManagerMetadata, ManagerMetadataError, RuleKey, RuleRecord, UnknownFields, decode_manager_metadata,
    encode_manager_metadata,
)
from keenvpn.domain.routing import (
    ConditionFamily, DomainCondition, DomainMatch, GeoDatabase, GeoDatabaseKind, GeoIPCondition, GeoSiteCondition,
    IPCondition, RoutingAction, RoutingRule, UnknownCondition, UnsupportedRuleCondition,
)
from keenvpn.domain.routing_import import import_routing_scheme
from keenvpn.domain.routing_policy import FinalRoutingRule, RoutingPolicy
from keenvpn.domain.rule_binding import (
    BindingReason, BoundRule, RuleBinding, RuleBindingError, RuleBindingErrorCode, UnboundRecord, bind_routing_scheme,
    bind_rule_records, rule_key, scheme_rules,
)
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import snapshot_xray_config


# Прогреть codec IDNA до запрета внешних эффектов: его ленивый импорт не относится к проверяемому коду.
"пример.рф".encode("idna")

ID_A = "0000abcd-0000-4000-8000-0000000000a1"
ID_B = "0000abcd-0000-4000-8000-0000000000b2"
ID_C = "0000abcd-0000-4000-8000-0000000000c3"
ID_D = "0000abcd-0000-4000-8000-0000000000d4"
ID_E = "0000abcd-0000-4000-8000-0000000000e5"
NAME_MARKER = "TEST_ONLY_PRIVATE_NAME"
PRIVATE_MARKERS = (
    NAME_MARKER, "example.test", "198.51.100", "2001:db8", "geoip.dat", "geosite.dat", '"ru"', "private-cat",
    "regexp:", "subdomains:", "exact:", "port",
)
GEOIP = GeoDatabase(GeoDatabaseKind.GEOIP, "geoip.dat")
GEOSITE = GeoDatabase(GeoDatabaseKind.GEOSITE, "geosite.dat")


def rule(condition, action=RoutingAction.VPN, **fields):
    return RoutingRule(condition, action, **fields)


def record(rule_id, source_rule, name=None, **extra):
    return RuleRecord(rule_id, name, rule_key(source_rule), UnknownFields(extra) if extra else UnknownFields())


def domain(value, mode=DomainMatch.SUBDOMAINS, action=RoutingAction.VPN):
    return rule(DomainCondition(value, mode), action)


class KeyTests(unittest.TestCase):
    def test_key_per_condition_type_uses_canonical_model_values(self):
        unsupported = UnsupportedRuleCondition(("port", "network"), '{"network":"tcp","port":"53"}')
        cases = (
            (domain("Example.TEST."), ("domain", "subdomains:example.test", "VPN")),
            (domain("static.example.test", DomainMatch.EXACT, RoutingAction.DIRECT), ("domain", "exact:static.example.test", "DIRECT")),
            (domain("пример.рф"), ("domain", "subdomains:xn--e1afmkfd.xn--p1ai", "VPN")),
            (rule(IPCondition("198.51.100.7"), RoutingAction.BLOCK), ("ip", "198.51.100.7", "BLOCK")),
            (rule(IPCondition("2001:DB8:0000::/32")), ("ip", "2001:db8::/32", "VPN")),
            (rule(GeoIPCondition(GEOIP, "ru"), RoutingAction.DIRECT), ("geoip", "geoip.dat:ru", "DIRECT")),
            (rule(GeoSiteCondition(GEOSITE, "private-cat")), ("geosite", "geosite.dat:private-cat", "VPN")),
            (rule(UnknownCondition(ConditionFamily.DOMAIN, "regexp:^x")), ("unknown", "domain:regexp:^x", "VPN")),
            (rule(unsupported, RoutingAction.DIRECT), ("unsupported", unsupported.snapshot, "DIRECT")),
        )
        for source, (condition, value, action) in cases:
            with self.subTest(condition=condition):
                key = rule_key(source)
                self.assertIs(type(key), RuleKey)
                self.assertEqual((key.condition, key.value, key.action), (condition, value, RoutingAction(action)))
                self.assertIs(type(key.action), RoutingAction)
                self.assertEqual(len(key.extra), 0)

    def test_unsupported_key_does_not_depend_on_json_key_order(self):
        # Регрессия 238-R01: перестановка полей правила Xray меняла ключ привязки.
        ordered = {"type": "field", "port": "53", "network": "tcp", "attrs": {"b": [1, {"y": 2, "x": 1}], "a": 0}, "outboundTag": "direct"}
        shuffled = {"outboundTag": "direct", "attrs": {"a": 0, "b": [1, {"x": 1, "y": 2}]}, "network": "tcp", "port": "53", "type": "field"}
        reordered_array = {"type": "field", "port": "53", "network": "tcp", "attrs": {"b": [{"x": 1, "y": 2}, 1], "a": 0}, "outboundTag": "direct"}
        keys = {}
        for name, item in (("ordered", ordered), ("shuffled", shuffled), ("array", reordered_array)):
            scheme = import_routing_scheme(_config([item, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"}]))
            rule = scheme_rules(scheme)[0]
            self.assertIs(type(rule.condition), UnsupportedRuleCondition)
            keys[name] = rule_key(rule)
        self.assertEqual(keys["ordered"], keys["shuffled"])
        self.assertNotEqual(keys["ordered"], keys["array"])
        self.assertEqual(keys["ordered"].value, '{"attrs":{"a":0,"b":[1,{"x":1,"y":2}]},"network":"tcp","port":"53"}')
        # Исходный снимок условия не меняется.
        snapshot = scheme_rules(import_routing_scheme(_config([shuffled, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"}])))[0].condition.snapshot
        self.assertEqual(list(json.loads(snapshot)), ["attrs", "network", "port"])
        self.assertEqual(snapshot, '{"attrs":{"a":0,"b":[1,{"x":1,"y":2}]},"network":"tcp","port":"53"}')
        # Запись с ключом в прежнем порядке полей сопоставляется так же.
        record = RuleRecord(ID_A, NAME_MARKER, RuleKey("unsupported", '{"port":"53","network":"tcp","attrs":{"b":[1,{"y":2,"x":1}],"a":0}}', RoutingAction.DIRECT))
        binding = bind_rule_records((scheme_rules(import_routing_scheme(_config([shuffled, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"}])))[0],), (record,))
        self.assertEqual((binding.rules[0].record, binding.rules[0].rule.name), (record, NAME_MARKER))
        # Два правила, различающиеся только порядком полей, — неоднозначность, а не два разных правила.
        scheme = import_routing_scheme(_config([ordered, shuffled, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"}]))
        binding = bind_routing_scheme(scheme, (record,))
        self.assertEqual([item.reason for item in binding.rules], [BindingReason.RULE_DUPLICATE, BindingReason.RULE_DUPLICATE])
        self.assertEqual([item.reason for item in binding.unbound_records], [BindingReason.RULE_DUPLICATE])
        # Не-JSON значение ключа записи и JSON, который не кодируется обратно (238-R03), сопоставляются как есть.
        rule = scheme_rules(import_routing_scheme(_config([ordered, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"}])))[0]
        for index, value in enumerate(("not json", "NaN", '{"port":1e999}', "[Infinity]", "-Infinity", '{"a":' + "[" * 200 + "]" * 200 + "}")):
            with self.subTest(value=value[:12]):
                odd = RuleRecord(f"0000abcd-0000-4000-8000-0000000000{index:02x}", "Странная", RuleKey("unsupported", value, RoutingAction.DIRECT))
                binding = bind_rule_records((rule,), (odd,))
                self.assertEqual(binding.rules[0].reason, BindingReason.RECORD_MISSING)
                self.assertEqual(binding.unbound_records[0].reason, BindingReason.RULE_MISSING)

    def test_duplicate_keys_in_record_snapshot_never_match_a_rule(self):
        # Регрессия 238-R04: json.loads молча оставлял последний из повторяющихся ключей,
        # и запись {"port":"80","port":"443"} привязывалась к правилу {"port":"443"}.
        scheme = import_routing_scheme(_config([
            {"type": "field", "port": "443", "outboundTag": "direct"},
            {"type": "field", "attrs": {"x": 1}, "network": "tcp", "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ]))
        port_rule, nested_rule = scheme_rules(scheme)
        self.assertEqual(rule_key(port_rule).value, '{"port":"443"}')
        duplicates = (
            (ID_A, port_rule, '{"port":"80","port":"443"}'),
            (ID_B, port_rule, '{"port":"443","port":"443"}'),
            (ID_C, nested_rule, '{"attrs":{"x":0,"x":1},"network":"tcp"}'),
        )
        for rule_id, rule, snapshot in duplicates:
            with self.subTest(snapshot=snapshot):
                record = RuleRecord(rule_id, NAME_MARKER, RuleKey("unsupported", snapshot, RoutingAction.DIRECT))
                binding = bind_routing_scheme(scheme, (record,))
                self.assertEqual([item.reason for item in binding.rules], [BindingReason.RECORD_MISSING] * 2)
                self.assertEqual([(item.record.rule_id, item.reason) for item in binding.unbound_records], [(rule_id, BindingReason.RULE_MISSING)])
                self.assertEqual({item.rule.name for item in binding.rules}, {None})
        # Та же запись без повтора ключей привязывается, как и раньше.
        record = RuleRecord(ID_D, NAME_MARKER, RuleKey("unsupported", '{"port":"443"}', RoutingAction.DIRECT))
        binding = bind_routing_scheme(scheme, (record,))
        self.assertEqual((binding.rules[0].record, binding.rules[0].rule.name), (record, NAME_MARKER))

    def test_key_ignores_identity_state_protection_and_database_metadata(self):
        base = rule(GeoIPCondition(GEOIP, "ru"), RoutingAction.DIRECT)
        variants = (
            replace(base, rule_id=ID_A, name=NAME_MARKER),
            replace(base, enabled=False),
            replace(base, protected=True),
            rule(GeoIPCondition(GeoDatabase(GeoDatabaseKind.GEOIP, "geoip.dat", "src", "v2", "ab" * 32), "ru"), RoutingAction.DIRECT),
        )
        for variant in variants:
            self.assertEqual(rule_key(variant), rule_key(base))
        self.assertNotEqual(rule_key(base), rule_key(rule(GeoIPCondition(GEOIP, "ru"), RoutingAction.VPN)))
        self.assertNotEqual(rule_key(domain("example.test")), rule_key(domain("example.test", DomainMatch.EXACT)))
        self.assertNotEqual(rule_key(rule(GeoIPCondition(GEOIP, "ru"))), rule_key(rule(GeoSiteCondition(GEOSITE, "ru"))))

    def test_key_rejects_foreign_input_without_leaking_values(self):
        class Fake:
            condition = DomainCondition("example.test")
            action = RoutingAction.VPN
            rule_id = name = None

        for value in (None, "domain", Fake(), FinalRoutingRule(RoutingAction.VPN)):
            with self.assertRaises(RuleBindingError) as raised:
                rule_key(value)
            self.assertIs(raised.exception.code, RuleBindingErrorCode.RULES)
            self.assertIsNone(raised.exception.__context__)
            self.assertNotIn("example.test", str(raised.exception) + repr(raised.exception))

    def test_key_round_trips_through_metadata_file(self):
        rules = (domain("example.test"), rule(IPCondition("198.51.100.0/24"), RoutingAction.DIRECT))
        metadata = ManagerMetadata(rules=tuple(record(rule_id, item) for rule_id, item in zip((ID_A, ID_B), rules)))
        stored = decode_manager_metadata(encode_manager_metadata(metadata)).metadata
        self.assertEqual([item.key for item in stored.rules], [rule_key(item) for item in rules])


class BindingTestCase(unittest.TestCase):
    def setUp(self):
        self.work = domain("work.example.test", action=RoutingAction.DIRECT)
        self.static = domain("static.example.test", DomainMatch.EXACT, RoutingAction.DIRECT)
        self.net = rule(IPCondition("198.51.100.0/24"), RoutingAction.DIRECT)
        self.geo = rule(GeoIPCondition(GEOIP, "ru"), RoutingAction.DIRECT)
        self.blocked = rule(IPCondition("2001:db8::/32"), RoutingAction.BLOCK)
        self.rules = (self.work, self.static, self.net, self.geo, self.blocked)
        self.records = (
            record(ID_A, self.work, NAME_MARKER), record(ID_B, self.static), record(ID_C, self.net, "Сеть"),
            record(ID_D, self.geo, "Россия", note="x"), record(ID_E, self.blocked),
        )
        self.final = FinalRoutingRule(RoutingAction.VPN)

    def assert_bound(self, binding, expected):
        """Ожидания в форме {index: (rule_id | None, reason | None)}."""
        actual = {item.index: (None if item.record is None else item.record.rule_id, item.reason) for item in binding.rules}
        self.assertEqual(actual, expected)
        for item in binding.rules:
            self.assertIs(item.rule.rule_id, None if item.record is None else item.record.rule_id)
            self.assertEqual(item.rule.name, None if item.record is None else item.record.name)
            self.assertEqual(item.bound, item.record is not None)

    def assert_unbound(self, binding, expected):
        actual = {item.record.rule_id: item.reason for item in binding.unbound_records}
        self.assertEqual(actual, expected)


class BindingTests(BindingTestCase):
    def test_every_record_binds_its_rule_and_identity_is_applied(self):
        policy = RoutingPolicy(self.rules, self.final)
        binding = bind_rule_records(self.rules, self.records, policy)
        self.assert_bound(binding, {0: (ID_A, None), 1: (ID_B, None), 2: (ID_C, None), 3: (ID_D, None), 4: (ID_E, None)})
        self.assert_unbound(binding, {})
        self.assertEqual([item.name for item in binding.bound_rules], [NAME_MARKER, None, "Сеть", "Россия", None])
        self.assertEqual([item.condition for item in binding.bound_rules], [item.condition for item in self.rules])
        self.assertEqual(binding.policy, RoutingPolicy(binding.bound_rules, self.final))
        self.assertEqual(binding.policy.index_of(ID_D), 3)
        self.assertEqual(binding.policy.to_diagnostic()["identified_rule_count"], 5)
        self.assertEqual((binding.bound_rule_count, binding.record_count), (5, 5))
        diagnostic = binding.to_diagnostic()
        self.assertEqual(
            {key: diagnostic[key] for key in ("rule_count", "bound_rule_count", "named_rule_count", "unbound_rule_count", "record_count", "unbound_record_count")},
            {"rule_count": 5, "bound_rule_count": 5, "named_rule_count": 3, "unbound_rule_count": 0, "record_count": 5, "unbound_record_count": 0},
        )
        self.assertEqual(diagnostic["rules"][0], {
            "index": 0, "binding": "bound", "condition_type": "DomainCondition", "action": "DIRECT", "read_only": False,
            "enabled": True, "protected": False, "has_id": True, "rule_id": ID_A, "has_name": True,
            "name_length": len(NAME_MARKER), "parameters": "<скрыто>",
        })
        self.assertEqual(diagnostic["policy"]["named_rule_count"], 3)

    def test_binding_survives_moves_insertions_deletions_and_regrouping(self):
        extra = domain("new.example.test", action=RoutingAction.DIRECT)
        cases = {
            "moved": ((self.blocked, self.geo, self.work, self.net, self.static), {0: ID_E, 1: ID_D, 2: ID_A, 3: ID_C, 4: ID_B}),
            "inserted": ((self.work, extra, self.static, self.net, self.geo, self.blocked), {0: ID_A, 1: None, 2: ID_B, 3: ID_C, 4: ID_D, 5: ID_E}),
            "deleted": ((self.work, self.net, self.blocked), {0: ID_A, 1: ID_C, 2: ID_E}),
        }
        for name, (rules, expected) in cases.items():
            with self.subTest(name):
                binding = bind_rule_records(rules, self.records)
                self.assert_bound(binding, {
                    index: (rule_id, None if rule_id else BindingReason.RECORD_MISSING) for index, rule_id in expected.items()
                })
                missing = {ID_A, ID_B, ID_C, ID_D, ID_E} - set(expected.values())
                self.assert_unbound(binding, {rule_id: BindingReason.RULE_MISSING for rule_id in missing})
                self.assertIsNone(binding.policy)

    def test_regrouping_in_xray_keeps_binding_when_action_is_the_same(self):
        before = _config([
            {"type": "field", "domain": ["domain:work.example.test", "full:static.example.test"], "outboundTag": "direct"},
            {"type": "field", "ip": ["198.51.100.0/24"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ])
        after = _config([
            {"type": "field", "ip": ["198.51.100.0/24"], "outboundTag": "direct"},
            {"type": "field", "domain": ["full:static.example.test"], "outboundTag": "direct"},
            {"type": "field", "domain": ["domain:work.example.test"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ])
        records = tuple(
            record(rule_id, item, name) for rule_id, item, name
            in zip((ID_A, ID_B, ID_C), scheme_rules(import_routing_scheme(before)), (NAME_MARKER, None, "Сеть"))
        )
        binding = bind_routing_scheme(import_routing_scheme(after), records)
        self.assert_bound(binding, {0: (ID_C, None), 1: (ID_B, None), 2: (ID_A, None)})
        self.assertEqual([item.rule.name for item in binding.rules], ["Сеть", None, NAME_MARKER])
        self.assertIsNotNone(binding.policy)
        self.assertEqual(binding.policy.index_of(ID_A), 2)
        # Тот же домен, но другой outbound с другим действием — другое правило.
        changed = _config([
            {"type": "field", "domain": ["domain:work.example.test"], "outboundTag": "proxy-out"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ])
        binding = bind_routing_scheme(import_routing_scheme(changed), records)
        self.assert_bound(binding, {0: (None, BindingReason.RECORD_MISSING)})
        self.assert_unbound(binding, {ID_A: BindingReason.RULE_MISSING, ID_B: BindingReason.RULE_MISSING, ID_C: BindingReason.RULE_MISSING})

    def test_manual_edit_of_value_or_action_unbinds_only_that_rule(self):
        edited_value = (self.work, domain("static2.example.test", DomainMatch.EXACT, RoutingAction.DIRECT), self.net, self.geo, self.blocked)
        edited_action = (self.work, self.static, self.net, rule(GeoIPCondition(GEOIP, "ru"), RoutingAction.VPN), self.blocked)
        for name, rules, index, lost in (("value", edited_value, 1, ID_B), ("action", edited_action, 3, ID_D)):
            with self.subTest(name):
                binding = bind_rule_records(rules, self.records)
                expected = {0: (ID_A, None), 1: (ID_B, None), 2: (ID_C, None), 3: (ID_D, None), 4: (ID_E, None)}
                expected[index] = (None, BindingReason.RECORD_MISSING)
                self.assert_bound(binding, expected)
                self.assert_unbound(binding, {lost: BindingReason.RULE_MISSING})

    def test_duplicate_rule_keys_bind_nothing_even_with_a_record(self):
        rules = (self.work, self.static, self.work, self.net)
        binding = bind_rule_records(rules, self.records)
        self.assert_bound(binding, {
            0: (None, BindingReason.RULE_DUPLICATE), 1: (ID_B, None), 2: (None, BindingReason.RULE_DUPLICATE), 3: (ID_C, None),
        })
        self.assert_unbound(binding, {
            ID_A: BindingReason.RULE_DUPLICATE, ID_D: BindingReason.RULE_MISSING, ID_E: BindingReason.RULE_MISSING,
        })
        # Два одинаковых правила без записи — тоже неоднозначность, а не два кандидата на новый ID.
        binding = bind_rule_records((self.geo, self.geo), ())
        self.assert_bound(binding, {0: (None, BindingReason.RULE_DUPLICATE), 1: (None, BindingReason.RULE_DUPLICATE)})

    def test_duplicate_record_keys_bind_nothing_and_keep_both_records(self):
        records = (*self.records, record(ID_E.replace("e5", "e6"), self.work, "Второе"))
        binding = bind_rule_records(self.rules, records)
        expected = {0: (None, BindingReason.RECORD_DUPLICATE), 1: (ID_B, None), 2: (ID_C, None), 3: (ID_D, None), 4: (ID_E, None)}
        self.assert_bound(binding, expected)
        self.assert_unbound(binding, {ID_A: BindingReason.RECORD_DUPLICATE, ID_E.replace("e5", "e6"): BindingReason.RECORD_DUPLICATE})
        self.assertEqual(binding.record_count, 6)
        # Дубли записей без правила остаются дублями, а не осиротевшими.
        binding = bind_rule_records((self.net,), (records[0], records[-1]))
        self.assert_unbound(binding, {ID_A: BindingReason.RECORD_DUPLICATE, ID_E.replace("e5", "e6"): BindingReason.RECORD_DUPLICATE})

    def test_records_without_rules_are_kept_and_counted(self):
        binding = bind_rule_records((self.work,), self.records)
        self.assert_bound(binding, {0: (ID_A, None)})
        self.assert_unbound(binding, {ID_B: BindingReason.RULE_MISSING, ID_C: BindingReason.RULE_MISSING, ID_D: BindingReason.RULE_MISSING, ID_E: BindingReason.RULE_MISSING})
        self.assertEqual([item.record for item in binding.unbound_records], list(self.records[1:]))
        self.assertEqual(binding.to_diagnostic()["unbound_records"][2], {
            "rule_id": ID_D, "has_name": True, "name_length": len("Россия"), "reason": "rule_missing",
        })
        empty = bind_rule_records((), self.records)
        self.assertEqual((empty.rules, len(empty.unbound_records), empty.record_count), ((), 5, 5))
        none = bind_rule_records(self.rules, ())
        self.assertEqual({item.reason for item in none.rules}, {BindingReason.RECORD_MISSING})
        self.assertEqual((none.record_count, none.unbound_records), (0, ()))

    def test_record_unknown_fields_do_not_affect_matching(self):
        records = (record(ID_A, self.work, extra_a=1), RuleRecord(ID_B, None, RuleKey("domain", "exact:static.example.test", RoutingAction.DIRECT, UnknownFields({"hint": "x"}))))
        binding = bind_rule_records(self.rules[:2], records)
        self.assert_bound(binding, {0: (ID_A, None), 1: (ID_B, None)})

    def test_snapshot_rules_bind_without_policy(self):
        scheme = import_routing_scheme(snapshot_xray_config())
        rules = scheme_rules(scheme)
        self.assertEqual(len(rules), 40)
        self.assertIsNone(scheme.policy)
        binding = bind_routing_scheme(scheme, ())
        self.assertEqual({item.reason for item in binding.rules}, {BindingReason.RECORD_MISSING})
        records = tuple(record(f"0000abcd-0000-4000-8000-0000000000{index:02x}", item) for index, item in enumerate(rules))
        binding = bind_routing_scheme(scheme, records)
        self.assertEqual(binding.bound_rule_count, 40)
        self.assertIsNone(binding.policy)
        self.assertEqual([item.rule.condition for item in binding.rules], [item.condition for item in rules])

    def test_scheme_with_policy_gives_policy_with_identity(self):
        scheme = import_routing_scheme(_config([
            {"type": "field", "domain": ["domain:work.example.test"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ]))
        records = (record(ID_A, scheme_rules(scheme)[0], NAME_MARKER),)
        binding = bind_routing_scheme(scheme, records)
        self.assertEqual(binding.policy.rules[0].rule_id, ID_A)
        self.assertEqual(binding.policy.final_rule, scheme.policy.final_rule)
        self.assertEqual(binding.to_diagnostic()["policy"]["identified_rule_count"], 1)

    def test_cost_is_linear_in_rules_and_records(self):
        def executed_lines(count):
            rules = tuple(rule(IPCondition(f"198.51.{index // 256}.{index % 256}"), RoutingAction.DIRECT) for index in range(count))
            records = tuple(
                record(f"0000abcd-0000-4000-8000-{index:012x}", rules[index]) for index in range(0, count, 2)
            ) + tuple(record(f"0000abcd-0000-4000-9000-{index:012x}", domain(f"n{index}.example.test")) for index in range(count // 2))
            lines = 0

            def tracer(frame, event, _arg):
                nonlocal lines
                if frame.f_code.co_filename != module.__file__:
                    return None
                if event == "line":
                    lines += 1
                return tracer

            sys.settrace(tracer)
            try:
                bind_rule_records(rules, records).to_diagnostic()
            finally:
                sys.settrace(None)
            return lines

        small, large = executed_lines(200), executed_lines(800)
        # Линейная стоимость даёт отношение около 4, квадратичная — около 16.
        self.assertLess(large, small * 5)


def _part(name, document):
    return ConfigDocument(name, json.dumps(document).encode("utf-8"))


def _config(rules):
    return XrayConfigSet((
        _part("04_outbounds.json", {"outbounds": [
            {"tag": "proxy-out", "protocol": "trojan"}, {"tag": "direct", "protocol": "freedom"},
        ]}),
        _part("05_routing.json", {"routing": {"rules": rules}}),
    ))


class ValidationTests(BindingTestCase):
    def assert_error(self, code, function, *args):
        with self.assertRaises(RuleBindingError) as raised:
            function(*args)
        self.assertIs(raised.exception.code, code)
        self.assertIsNone(raised.exception.__context__)
        self.assertIsNone(raised.exception.__cause__)
        return raised.exception

    def test_inputs_are_checked(self):
        identified = replace(self.work, rule_id=ID_A)
        named = replace(self.work, name=NAME_MARKER)
        self.assert_error(RuleBindingErrorCode.RULES, bind_rule_records, (identified,), ())
        self.assert_error(RuleBindingErrorCode.RULES, bind_rule_records, (named,), ())
        self.assert_error(RuleBindingErrorCode.RULES, bind_rule_records, (self.final,), ())
        self.assert_error(RuleBindingErrorCode.RULES, bind_rule_records, None, ())
        self.assert_error(RuleBindingErrorCode.RECORDS, bind_rule_records, self.rules, (self.records[0], record(ID_A, self.net)))
        self.assert_error(RuleBindingErrorCode.RECORDS, bind_rule_records, self.rules, (self.records[0], "record"))
        self.assert_error(RuleBindingErrorCode.RECORDS, bind_rule_records, self.rules, None)
        other = RoutingPolicy((self.work,), self.final)
        self.assert_error(RuleBindingErrorCode.RULES, bind_rule_records, self.rules, self.records, other)
        self.assert_error(RuleBindingErrorCode.RULES, bind_rule_records, self.rules, self.records, "policy")
        self.assert_error(RuleBindingErrorCode.SCHEME, scheme_rules, RoutingPolicy(self.rules, self.final))
        self.assert_error(RuleBindingErrorCode.SCHEME, bind_routing_scheme, None, ())

    def test_result_models_reject_inconsistent_parts(self):
        bound = BoundRule(0, replace(self.work, rule_id=ID_A, name=NAME_MARKER), self.records[0], None)
        unbound = UnboundRecord(self.records[1], BindingReason.RULE_MISSING)
        cases = (
            (BoundRule, (-1, self.work, None, BindingReason.RECORD_MISSING)),
            (BoundRule, (0, self.work, None, None)),
            (BoundRule, (0, self.work, self.records[0], None)),
            (BoundRule, (0, replace(self.work, rule_id=ID_B), self.records[0], None)),
            (BoundRule, (0, replace(self.work, rule_id=ID_A), None, BindingReason.RECORD_MISSING)),
            (BoundRule, (0, self.work, None, BindingReason.RULE_MISSING)),
            (BoundRule, (0, self.work, self.records[0], BindingReason.RECORD_MISSING)),
            (UnboundRecord, (self.records[0], BindingReason.RECORD_MISSING)),
            (UnboundRecord, ("record", BindingReason.RULE_MISSING)),
            (RuleBinding, ((bound, bound), (), None)),
            (RuleBinding, ((bound,), (UnboundRecord(self.records[0], BindingReason.RULE_MISSING),), None)),
            (RuleBinding, ((bound,), (unbound,), RoutingPolicy((self.work,), self.final))),
            (RuleBinding, ([bound], (unbound,), None)),
            (RuleBinding, ((bound,), [unbound], None)),
        )
        for factory, args in cases:
            with self.subTest(factory=factory.__name__, args=len(args)):
                self.assert_error(RuleBindingErrorCode.BINDING, factory, *args)
        RuleBinding((bound,), (unbound,), RoutingPolicy((bound.rule,), self.final))

    def test_errors_and_output_hide_names_and_values(self):
        binding = bind_rule_records(self.rules, self.records)
        text = repr(binding) + str(binding) + repr(binding.rules) + repr(binding.unbound_records)
        text += json.dumps(binding.to_diagnostic(), ensure_ascii=False) + repr(binding.policy)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertIn(ID_A, json.dumps(binding.to_diagnostic()))
        self.assertEqual(repr(binding), "RuleBinding(rules=5, bound=5, unbound_records=0)")
        error = self.assert_error(RuleBindingErrorCode.RULES, bind_rule_records, (replace(self.work, name=NAME_MARKER),), self.records)
        rendered = "".join(traceback.format_exception(error)) + str(error) + repr(vars(error))
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, rendered)

    def test_binding_needs_no_io(self):
        scheme = import_routing_scheme(snapshot_xray_config())
        with forbid_external_effects():
            binding = bind_routing_scheme(scheme, (record(ID_A, scheme_rules(scheme)[3], "x"),))
            binding.to_diagnostic()
            bind_rule_records(self.rules, self.records, RoutingPolicy(self.rules, self.final)).to_diagnostic()


if __name__ == "__main__":
    unittest.main()
