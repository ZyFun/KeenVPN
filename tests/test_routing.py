"""Проверки модели маршрутов без файлов геобаз, сети и реального роутера."""

import builtins
import contextlib
from dataclasses import FrozenInstanceError, asdict
import io
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import traceback
import unittest
from unittest.mock import patch
import urllib.request


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.routing import (
    ConditionFamily,
    DomainCondition,
    DomainMatch,
    GeoDatabase,
    GeoDatabaseKind,
    GeoIPCondition,
    GeoSiteCondition,
    IPCondition,
    RoutingAction,
    RoutingErrorCode,
    RoutingRule,
    RoutingValidationError,
    UnknownCondition,
)


class RoutingTestCase(unittest.TestCase):
    def assert_invalid(self, code, constructor, *args, **kwargs):
        with self.assertRaises(RoutingValidationError) as raised:
            constructor(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        self.assertIsNone(raised.exception.__context__)
        return raised.exception


class DomainConditionTests(RoutingTestCase):
    def test_exact_and_subdomain_conditions_are_distinct(self):
        exact = DomainCondition("EXAMPLE.TEST.", DomainMatch.EXACT)
        subtree = DomainCondition("example.test", DomainMatch.SUBDOMAINS)
        self.assertEqual(exact.value, "example.test")
        self.assertEqual(subtree.value, "example.test")
        self.assertNotEqual(exact, subtree)
        self.assertEqual(DomainCondition("example.test").mode, DomainMatch.SUBDOMAINS)

    def test_idna_unicode_and_ascii_forms_are_equivalent(self):
        unicode = DomainCondition("ПРИМЕР.РФ")
        ascii = DomainCondition("xn--e1afmkfd.xn--p1ai")
        self.assertEqual(unicode, ascii)
        self.assertEqual(unicode.display_name, "пример.рф")
        self.assertEqual(DomainCondition("пример。рф．"), unicode)
        self.assertEqual(DomainCondition("и\u0306.рф"), DomainCondition("й.рф"))

    def test_domain_zones_include_subdomains_without_becoming_geo_sets(self):
        zones = [DomainCondition(zone) for zone in ("ru", "su", "рф")]
        self.assertEqual([zone.value for zone in zones], ["ru", "su", "xn--p1ai"])
        self.assertTrue(all(zone.mode is DomainMatch.SUBDOMAINS for zone in zones))
        self.assertEqual(zones[-1].display_name, "рф")

    def test_invalid_names_do_not_expand_into_valid_domains(self):
        for value in (
            None, 123, b"example.test", "", ".", "example..test", ".example.test",
            "example.test..", " example.test", "example.test\n", "example test",
            "https://example.test/path", "example.test/path", "example.test:443",
            "user@example.test", "*.example.test", "domain:example.test", "full:example.test",
            "regexp:.*", "example%2etest", "-example.test", "example-.test", "_service.test",
            "192.0.2.1", "2001:db8::1", "[2001:db8::1]", "\ud800.test", "a\x00.test",
            "xn--.test", "xn--a.test", "a" * 64 + ".test", ".".join(["a" * 63] * 4),
        ):
            with self.subTest(value_type=type(value).__name__):
                self.assert_invalid(RoutingErrorCode.DOMAIN, DomainCondition, value)

    def test_lossy_idna_mapping_is_rejected(self):
        for value in ("faß.test", "a\u200db.test", "ｅxample.test", "exam\u00adple.test"):
            self.assert_invalid(RoutingErrorCode.DOMAIN, DomainCondition, value)

    def test_dns_name_length_boundaries(self):
        value = ".".join(["a" * 63] * 3 + ["b" * 61])
        self.assertEqual(len(value), 253)
        self.assertEqual(DomainCondition(value + ".").value, value)
        self.assert_invalid(RoutingErrorCode.DOMAIN, DomainCondition, value + "b")

    def test_unknown_match_mode_is_not_defaulted(self):
        for mode in (None, "exact", "substring", True):
            self.assert_invalid(RoutingErrorCode.DOMAIN_MATCH, DomainCondition, "example.test", mode)


class IPConditionTests(RoutingTestCase):
    def test_ipv4_and_ipv6_addresses_and_networks(self):
        for source, expected in (
            ("192.0.2.1", "192.0.2.1"), ("192.0.2.0/24", "192.0.2.0/24"),
            ("2001:0DB8:0000::1", "2001:db8::1"), ("2001:DB8::/32", "2001:db8::/32"),
            ("192.0.2.1/32", "192.0.2.1/32"), ("2001:db8::1/128", "2001:db8::1/128"),
            ("0.0.0.0/0", "0.0.0.0/0"), ("::/0", "::/0"),
        ):
            with self.subTest(source=source):
                self.assertEqual(IPCondition(source).value, expected)

    def test_invalid_networks_do_not_broaden_or_resolve(self):
        for value in (
            None, 123, True, b"192.0.2.1", "", "example.test", "192.0.2.256", "192.0.2.01",
            "192.0.2.1/24", "2001:db8::1/32", "192.0.2.0/33", "::/129", "::/-1",
            "192.0.2.0/255.255.255.0", "192.0.2.0/024", "192.0.2.0/+24", "::/0/0",
            "192.0.2.1:443", "[2001:db8::1]", "fe80::1%eth0", "fe80::%eth0/64",
            " 192.0.2.1", "192.0.2.1\n", "geoip:ru", "!192.0.2.0/24",
        ):
            with self.subTest(value_type=type(value).__name__):
                self.assert_invalid(RoutingErrorCode.IP, IPCondition, value)

    def test_address_and_explicit_host_network_stay_distinct(self):
        self.assertNotEqual(IPCondition("192.0.2.1"), IPCondition("192.0.2.1/32"))


class GeoConditionTests(RoutingTestCase):
    def test_metadata_is_explicit_and_does_not_guess_version_from_filename(self):
        database = GeoDatabase(GeoDatabaseKind.GEOSITE, "geosite-20990101.dat")
        self.assertIsNone(database.source)
        self.assertIsNone(database.version)
        self.assertIsNone(database.sha256)
        self.assertEqual(database.reference, "geosite-20990101.dat")
        database = GeoDatabase(
            GeoDatabaseKind.GEOSITE, "sites-test", "https://data.example.test/sets",
            "test-release", "AB" * 32,
        )
        self.assertEqual(database.source, "https://data.example.test/sets")
        self.assertEqual(database.version, "test-release")
        self.assertEqual(database.sha256, "ab" * 32)

    def test_domains_ip_countries_and_geosite_remain_independent(self):
        domain = DomainCondition("ru")
        geoip = GeoIPCondition(GeoDatabase(GeoDatabaseKind.GEOIP, "ip-test"), "ru")
        geosite = GeoSiteCondition(GeoDatabase(GeoDatabaseKind.GEOSITE, "sites-test"), "ru")
        self.assertEqual(len({domain, geoip, geosite}), 3)
        self.assertEqual(geoip.database.reference, "ip-test")
        self.assertEqual(geosite.database.reference, "sites-test")

    def test_set_name_is_preserved_without_claiming_catalog_membership(self):
        for kind, constructor in (
            (GeoDatabaseKind.GEOIP, GeoIPCondition),
            (GeoDatabaseKind.GEOSITE, GeoSiteCondition),
        ):
            database = GeoDatabase(kind, "custom-test-database")
            for name in ("ru", "private", "TEST-unknown", "category-!test", "test@attribute"):
                condition = constructor(database, name)
                self.assertEqual(condition.set_name, name)
                self.assertIs(condition.database, database)

    def test_wrong_database_kind_is_rejected(self):
        self.assert_invalid(
            RoutingErrorCode.DATABASE_KIND, GeoSiteCondition,
            GeoDatabase(GeoDatabaseKind.GEOIP, "ip-test"), "ru",
        )
        self.assert_invalid(
            RoutingErrorCode.DATABASE_KIND, GeoIPCondition,
            GeoDatabase(GeoDatabaseKind.GEOSITE, "sites-test"), "ru",
        )
        self.assert_invalid(RoutingErrorCode.DATABASE, GeoIPCondition, "geoip.dat", "ru")

    def test_invalid_metadata_has_no_fabricated_defaults(self):
        for changes in (
            {"reference": ""}, {"reference": "\n"}, {"source": ""}, {"source": 1},
            {"version": ""}, {"version": "test\nrelease"}, {"sha256": ""},
            {"sha256": "a" * 63}, {"sha256": "g" * 64}, {"sha256": 123},
        ):
            kwargs = {"kind": GeoDatabaseKind.GEOIP, "reference": "ip-test", **changes}
            self.assert_invalid(RoutingErrorCode.DATABASE, GeoDatabase, **kwargs)
        self.assert_invalid(RoutingErrorCode.DATABASE_KIND, GeoDatabase, "geoip", "ip-test")

    def test_invalid_set_names_are_not_replaced(self):
        for kind, constructor in (
            (GeoDatabaseKind.GEOIP, GeoIPCondition), (GeoDatabaseKind.GEOSITE, GeoSiteCondition),
        ):
            database = GeoDatabase(kind, "test-database")
            for name in (None, "", " ", "geoip:ru", "../test", "test\nset", "test set", 123):
                self.assert_invalid(RoutingErrorCode.SET_NAME, constructor, database, name)


class RoutingRuleTests(RoutingTestCase):
    def test_all_known_conditions_support_each_explicit_action(self):
        conditions = (
            DomainCondition("example.test", DomainMatch.EXACT),
            DomainCondition("example.test", DomainMatch.SUBDOMAINS),
            IPCondition("192.0.2.0/24"),
            GeoIPCondition(GeoDatabase(GeoDatabaseKind.GEOIP, "ip-test"), "ru"),
            GeoSiteCondition(GeoDatabase(GeoDatabaseKind.GEOSITE, "sites-test"), "test-set"),
        )
        for condition in conditions:
            for action in RoutingAction:
                rule = RoutingRule(condition, action)
                self.assertIs(rule.condition, condition)
                self.assertIs(rule.action, action)
                self.assertFalse(rule.read_only)
                self.assertEqual(rule.to_diagnostic()["action"], action.value)

    def test_unknown_imported_references_preserve_exact_text_and_family(self):
        for reference in (
            "ext:Custom-20990101.dat:Unknown@attribute", "geosite:FUTURE/format",
            "geoip:!XX", "regexp:.*\\.example\\.test$", "  unexpected\nvalue\x00 ",
        ):
            for family in ConditionFamily:
                condition = UnknownCondition(family, reference)
                for action in RoutingAction:
                    rule = RoutingRule(condition, action)
                    self.assertEqual(rule.condition.reference, reference)
                    self.assertEqual(rule.condition.family, family)
                    self.assertTrue(rule.read_only)
                    self.assertTrue(rule.to_diagnostic()["read_only"])
                    restored = UnknownCondition(**asdict(condition))
                    self.assertEqual(restored, condition)

    def test_unknown_reference_does_not_become_a_normal_domain(self):
        unknown = UnknownCondition(ConditionFamily.DOMAIN, "domain:ru")
        self.assertNotEqual(unknown, DomainCondition("ru"))
        self.assertTrue(RoutingRule(unknown, RoutingAction.DIRECT).read_only)

    def test_empty_or_wrong_conditions_and_actions_are_rejected(self):
        for condition in (None, "example.test", [], {"domain": "example.test"}):
            self.assert_invalid(RoutingErrorCode.CONDITION, RoutingRule, condition, RoutingAction.DIRECT)
        for action in (None, "DIRECT", "VPN_OR_DIRECT", True):
            self.assert_invalid(RoutingErrorCode.ACTION, RoutingRule, DomainCondition("example.test"), action)
        for family, reference in (("domain", "test"), (None, "test"), (ConditionFamily.IP, ""), (ConditionFamily.IP, 1)):
            self.assert_invalid(RoutingErrorCode.REFERENCE, UnknownCondition, family, reference)

    def test_models_are_immutable(self):
        database = GeoDatabase(GeoDatabaseKind.GEOIP, "ip-test")
        condition = GeoIPCondition(database, "ru")
        rule = RoutingRule(condition, RoutingAction.VPN)
        for value, field in (
            (database, "reference"), (condition, "set_name"), (rule, "action"),
            (DomainCondition("example.test"), "value"), (IPCondition("192.0.2.1"), "value"),
            (UnknownCondition(ConditionFamily.IP, "unknown"), "reference"),
        ):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field, "changed")


class RoutingPrivacyTests(RoutingTestCase):
    def test_repr_logging_and_diagnostics_hide_arbitrary_field_values(self):
        marker = "TEST_ONLY_PRIVATE_MARKER"
        database = GeoDatabase(GeoDatabaseKind.GEOSITE, marker, marker, marker, "cd" * 32)
        values = (
            database, GeoSiteCondition(database, marker), DomainCondition(marker.replace("_", "-") + ".test"),
            IPCondition("192.0.2.17"), UnknownCondition(ConditionFamily.IP, marker),
        )
        stream = io.StringIO()
        logger = logging.Logger("routing-test")
        logger.addHandler(logging.StreamHandler(stream))
        for value in values:
            logger.warning("%s / %r", value, value)
            if isinstance(value, GeoDatabase):
                continue
            rule = RoutingRule(value, RoutingAction.VPN)
            logger.warning("%s / %r / %s", rule, rule, json.dumps(rule.to_diagnostic()))
        output = stream.getvalue()
        for private in (marker, "test-only-private-marker", "192.0.2.17", "cd" * 32):
            self.assertNotIn(private, output)

    def test_validation_errors_do_not_include_input_or_internal_exception(self):
        marker = "TEST_ONLY_PRIVATE_MARKER"
        cases = (
            (DomainCondition, ("https://" + marker + ".test",), RoutingErrorCode.DOMAIN),
            (IPCondition, (marker,), RoutingErrorCode.IP),
            (GeoDatabase, (GeoDatabaseKind.GEOIP, "test", None, None, marker), RoutingErrorCode.DATABASE),
            (RoutingRule, (DomainCondition("example.test"), marker), RoutingErrorCode.ACTION),
        )
        for constructor, args, code in cases:
            error = self.assert_invalid(code, constructor, *args)
            rendered = "".join(traceback.format_exception(error)) + str(error) + repr(error) + repr(vars(error))
            self.assertNotIn(marker, rendered)
            self.assertIsNone(error.__cause__)

    def test_error_inside_external_except_hides_external_message_in_standard_traceback(self):
        marker = "TEST_ONLY_EXTERNAL_SECRET"
        try:
            raise ValueError(marker)
        except ValueError:
            try:
                IPCondition("invalid")
            except RoutingValidationError as error:
                self.assertNotIn(marker, "".join(traceback.format_exception(error)))
            else:
                self.fail("Ожидался отказ на некорректный IP")

    def test_model_creation_has_no_io_dns_process_or_terminal_calls(self):
        # Прогреть только стандартный codec, чтобы проверять именно модель.
        "пример.рф".encode("idna")
        calls = (
            (builtins, "open"), (builtins, "input"), (builtins, "eval"), (builtins, "exec"),
            (io, "open"), (os, "open"), (os, "system"), (os, "popen"),
            (subprocess, "Popen"), (socket, "socket"), (socket, "getaddrinfo"),
            (urllib.request, "urlopen"),
        )
        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            for owner, name in calls:
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError("Запрещён побочный эффект")))
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(output))
            for condition in (
                DomainCondition("пример.рф"), IPCondition("2001:db8::/32"),
                GeoIPCondition(GeoDatabase(GeoDatabaseKind.GEOIP, "missing-test.dat"), "ru"),
                GeoSiteCondition(GeoDatabase(GeoDatabaseKind.GEOSITE, "$(id);`id`"), "test-set"),
                UnknownCondition(ConditionFamily.DOMAIN, "$(id);__import__('os').system('id')"),
            ):
                RoutingRule(condition, RoutingAction.VPN).to_diagnostic()
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
