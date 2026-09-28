"""Статические сценарии на искусственных адресах и управляемых геоданных."""

import builtins
import contextlib
from dataclasses import FrozenInstanceError, replace
import gc
import io
import itertools
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import traceback
import unittest
from unittest.mock import Mock, patch
import weakref


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.routing import (
    ConditionFamily, DomainCondition, DomainMatch, GeoDatabase, GeoDatabaseKind,
    GeoIPCondition, GeoSiteCondition, IPCondition, RoutingAction,
    RoutingErrorCode, RoutingRule, RoutingValidationError, UnknownCondition,
)
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy
from keenvpn.domain.routing_explanation import (
    DomainSource, ExplanationReason, GeoMatch, IPSource,
    RouteExplanation, RoutingContext, explain_route,
)


class RoutingExplanationTests(unittest.TestCase):
    def setUp(self):
        self.ip_database = GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip", version="ip-v1", sha256="ab" * 32)
        self.site_database = GeoDatabase(GeoDatabaseKind.GEOSITE, "fixture-site", version="site-v2")
        self.geoip = RoutingRule(GeoIPCondition(self.ip_database, "ru"), RoutingAction.DIRECT)
        self.geosite = RoutingRule(GeoSiteCondition(self.site_database, "test-services"), RoutingAction.BLOCK)
        self.domain = RoutingRule(DomainCondition("example.test"), RoutingAction.VPN)
        self.ip = RoutingRule(IPCondition("192.0.2.0/24"), RoutingAction.DIRECT)
        self.context = RoutingContext(
            domain="example.test", domain_source=DomainSource.DESTINATION,
            ips=("192.0.2.10",), ip_source=IPSource.DNS,
        )

    def policy(self, *rules, final=RoutingAction.BLOCK):
        return RoutingPolicy(rules, FinalRoutingRule(final))

    def assert_invalid(self, code, function, *args, **kwargs):
        with self.assertRaises(RoutingValidationError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_exact_subdomain_boundary_case_trailing_dot_and_idna(self):
        cases = (
            ("EXAMPLE.TEST.", "example.test", DomainMatch.EXACT, True),
            ("sub.example.test", "example.test", DomainMatch.EXACT, False),
            ("sub.example.test", "example.test", DomainMatch.SUBDOMAINS, True),
            ("notexample.test", "example.test", DomainMatch.SUBDOMAINS, False),
            ("example.test.invalid", "example.test", DomainMatch.SUBDOMAINS, False),
            ("ПРИМЕР.РФ.", "рф", DomainMatch.SUBDOMAINS, True),
            ("пример.рф", "xn--e1afmkfd.xn--p1ai", DomainMatch.EXACT, True),
        )
        for query, value, mode, matches in cases:
            with self.subTest(query=query, mode=mode):
                rule = RoutingRule(DomainCondition(value, mode), RoutingAction.VPN)
                context = RoutingContext(domain=query, domain_source=DomainSource.DESTINATION)
                report = explain_route(self.policy(rule), context)
                self.assertEqual(report.selection.index, 0 if matches else 1)
                self.assertEqual(report.steps[0].result, MatchResult.MATCH if matches else MatchResult.NO_MATCH)
                self.assertIs(report.steps[0].reason, ExplanationReason.DOMAIN)

    def test_ipv4_ipv6_exact_network_and_any_dns_address(self):
        cases = (
            ("192.0.2.10", ("192.0.2.10",), True),
            ("192.0.2.10", ("192.0.2.11",), False),
            ("192.0.2.0/24", ("198.51.100.1", "192.0.2.255"), True),
            ("192.0.2.0/24", ("2001:db8::1",), False),
            ("2001:db8::/32", ("192.0.2.10", "2001:DB8::2"), True),
            ("2001:db8::1", ("2001:db8::2",), False),
            ("2001:db8::1", ("2001:db8::1",), True),
            ("0.0.0.0/0", ("192.0.2.10",), True),
            ("::/0", ("2001:db8::1",), True),
        )
        for value, ips, matches in cases:
            with self.subTest(value=value, ips=ips):
                rule = RoutingRule(IPCondition(value), RoutingAction.VPN)
                context = RoutingContext(ips=ips, ip_source=IPSource.DNS)
                report = explain_route(self.policy(rule), context)
                self.assertEqual(report.selection.index, 0 if matches else 1)

    def test_first_rule_wins_even_if_later_rule_also_matches(self):
        for rules in ((self.domain, self.ip), (self.ip, self.domain)):
            report = explain_route(self.policy(*rules), self.context)
            self.assertIs(report.selection.rule, rules[0])
            self.assertEqual(len(report.steps), 1)

    def test_zone_geoip_country_and_geosite_are_independent(self):
        # Искусственный домен .ru имеет адрес вне набора ru, но входит в GeoSite.
        context = replace(self.context, domain="service.example.ru")
        zone = RoutingRule(DomainCondition("ru"), RoutingAction.VPN)

        def fixture(condition, values):
            if isinstance(condition, GeoIPCondition):
                self.assertEqual(values, ("192.0.2.10",))
                self.assertEqual(condition.set_name, "ru")
                return GeoMatch(MatchResult.NO_MATCH, self.ip_database)
            self.assertEqual(values, ("service.example.ru",))
            self.assertEqual(condition.set_name, "test-services")
            return GeoMatch(MatchResult.MATCH, self.site_database)

        source = Mock(side_effect=fixture)
        report = explain_route(self.policy(self.geoip, self.geosite, zone), context, geo_matcher=source)
        self.assertIs(report.selection.rule, self.geosite)
        self.assertEqual([s.database.version for s in report.steps], ["ip-v1", "site-v2"])
        self.assertEqual(source.call_count, 2)
        source.reset_mock()
        earlier = explain_route(self.policy(zone, self.geoip, self.geosite), context, geo_matcher=source)
        self.assertIs(earlier.selection.rule, zone)
        source.assert_not_called()
        self.assertIsNone(earlier.steps[0].database)

    def test_country_can_match_without_country_domain_zone(self):
        source = Mock(return_value=GeoMatch(MatchResult.MATCH, self.ip_database))
        zone = RoutingRule(DomainCondition("ru"), RoutingAction.BLOCK)
        report = explain_route(self.policy(zone, self.geoip), self.context, geo_matcher=source)
        self.assertIs(report.steps[0].result, MatchResult.NO_MATCH)
        self.assertIs(report.selection.rule, self.geoip)

    def test_unknown_domain_stops_but_explicit_unavailability_skips_domain_rules(self):
        for rule in (self.domain, self.geosite):
            source = Mock(side_effect=AssertionError("Имя неизвестно или отсутствует"))
            for domain_source, expected in (
                (DomainSource.UNKNOWN, MatchResult.UNKNOWN),
                (DomainSource.UNAVAILABLE, MatchResult.NO_MATCH),
            ):
                context = RoutingContext(domain_source=domain_source, ips=("192.0.2.10",), ip_source=IPSource.DESTINATION)
                report = explain_route(self.policy(rule, self.ip), context, geo_matcher=source)
                self.assertIs(report.steps[0].result, expected)
                if expected is MatchResult.UNKNOWN:
                    self.assertIsNone(report.selection)
                    self.assertEqual(len(report.steps), 1)
                else:
                    self.assertIs(report.selection.rule, self.ip)
            source.assert_not_called()

    def test_sniffing_name_is_an_explicit_assumption(self):
        context = replace(self.context, domain_source=DomainSource.SNIFFING, ip_source=IPSource.DESTINATION)
        report = explain_route(self.policy(self.domain), context)
        self.assertIs(report.selection.rule, self.domain)
        self.assertIn("sniffing", report.assumptions[2])
        self.assertEqual(report.to_diagnostic()["context"]["domain_source"], "sniffing")

    def test_unknown_ips_stop_but_explicit_unavailability_skips_ip_rules(self):
        for rule in (self.ip, self.geoip):
            source = Mock(side_effect=AssertionError("Адреса неизвестны или отсутствуют"))
            unknown = replace(self.context, ips=None, ip_source=IPSource.UNKNOWN)
            report = explain_route(self.policy(rule, self.domain), unknown, geo_matcher=source)
            self.assertIsNone(report.selection)
            self.assertIs(report.steps[0].reason, ExplanationReason.IP_UNKNOWN)
            absent = replace(unknown, ips=(), ip_source=IPSource.UNAVAILABLE)
            report = explain_route(self.policy(rule, self.domain), absent, geo_matcher=source)
            self.assertIs(report.selection.rule, self.domain)
            self.assertIs(report.steps[0].reason, ExplanationReason.IP_UNAVAILABLE)
            source.assert_not_called()

    def test_missing_geodata_is_not_inferred_from_metadata(self):
        for rule in (self.geoip, self.geosite):
            report = explain_route(self.policy(rule, self.domain), self.context)
            self.assertIsNone(report.selection)
            self.assertIs(report.steps[0].reason, ExplanationReason.GEODATA_MISSING)
            self.assertIsNone(report.steps[0].database)

    def test_geodata_unknown_stops_even_with_direct_final(self):
        for rule in (self.geoip, self.geosite):
            source = Mock(return_value=GeoMatch(MatchResult.UNKNOWN, rule.condition.database))
            report = explain_route(self.policy(rule, self.domain, final=RoutingAction.DIRECT), self.context, geo_matcher=source)
            self.assertIsNone(report.selection)
            self.assertIs(report.steps[0].reason, ExplanationReason.GEODATA_UNKNOWN)
            self.assertIs(report.steps[0].database, rule.condition.database)
            self.assertEqual(len(report.steps), 1)

    def test_provider_receives_complete_normalized_input_and_set(self):
        ips = ["198.51.100.1", "2001:DB8::1"]
        context = replace(self.context, ips=ips)
        ips.clear()
        source = Mock(return_value=GeoMatch(MatchResult.NO_MATCH, self.ip_database))
        explain_route(self.policy(self.geoip), context, geo_matcher=source)
        source.assert_called_once_with(self.geoip.condition, ("198.51.100.1", "2001:db8::1"))

    def test_unknown_metadata_can_be_refined_and_actual_revision_is_retained(self):
        database = GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip")
        rule = RoutingRule(GeoIPCondition(database, "ru"), RoutingAction.VPN)
        source = Mock(return_value=GeoMatch(MatchResult.MATCH, self.ip_database))
        report = explain_route(self.policy(rule), self.context, geo_matcher=source)
        self.assertIs(report.steps[0].database, self.ip_database)
        self.assertIsNone(database.version)

    def test_unknown_database_version_remains_unknown(self):
        database = GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip")
        rule = RoutingRule(GeoIPCondition(database, "ru"), RoutingAction.VPN)
        report = explain_route(self.policy(rule), self.context, geo_matcher=lambda c, v: GeoMatch(MatchResult.MATCH, database))
        self.assertIsNone(report.steps[0].database.version)
        self.assertFalse(report.steps[0].to_diagnostic()["database_version_known"])

    def test_mismatched_database_identity_or_known_metadata_is_rejected(self):
        expected = replace(self.ip_database, source="fixture-source")
        rule = replace(self.geoip, condition=GeoIPCondition(expected, "ru"))
        changes = (
            {"kind": GeoDatabaseKind.GEOSITE}, {"reference": "other"},
            {"source": "other"}, {"source": None}, {"version": "ip-v2"},
            {"version": None}, {"sha256": "cd" * 32}, {"sha256": None},
        )
        for change in changes:
            for result in MatchResult:
                source = Mock(return_value=GeoMatch(result, replace(expected, **change)))
                self.assert_invalid(RoutingErrorCode.GEODATA_MISMATCH, explain_route, self.policy(rule), self.context, geo_matcher=source)

    def test_all_geo_results_agree_with_existing_first_match_selection(self):
        rules = (self.geoip, self.geosite, self.geoip)
        policy = self.policy(*rules)
        for results in itertools.product(MatchResult, repeat=3):
            expected_matcher = Mock(side_effect=results)
            iterator = iter(results)
            source = Mock(side_effect=lambda c, v: GeoMatch(next(iterator), c.database))
            report = explain_route(policy, self.context, geo_matcher=source)
            if report.selection is None:
                self.assert_invalid(RoutingErrorCode.MATCH_UNKNOWN, policy.select_first, expected_matcher)
            else:
                self.assertEqual(report.selection, policy.select_first(expected_matcher))
            self.assertEqual(source.call_count, expected_matcher.call_count)

    def test_disabled_and_protected_rules_preserve_indices_and_stop_order(self):
        protected = replace(self.ip, protected=True)
        unknown = RoutingRule(UnknownCondition(ConditionFamily.DOMAIN, "ext:fixture:unknown"), RoutingAction.DIRECT, enabled=False)
        policy = self.policy(protected, unknown, self.domain)
        context = replace(self.context, ips=("198.51.100.1",))
        report = explain_route(policy, context)
        self.assertEqual(report.selection.index, 2)
        self.assertEqual([s.index for s in report.steps], [0, 1, 2])
        self.assertIs(report.steps[0].rule, protected)
        self.assertIs(report.steps[1].reason, ExplanationReason.DISABLED)
        self.assertIsNone(report.steps[1].result)
        self.assertIs(policy.rules[1], unknown)
        report = explain_route(policy, self.context)
        self.assertEqual(len(report.steps), 1)
        self.assertIs(report.selection.rule, protected)

    def test_unknown_import_stops_only_if_reached_and_is_never_sent_to_source(self):
        unknown = RoutingRule(UnknownCondition(ConditionFamily.IP, "ext:fixture:unknown"), RoutingAction.VPN)
        source = Mock(side_effect=AssertionError("Неизвестный импорт не передаётся источнику"))
        report = explain_route(self.policy(unknown, self.domain), self.context, geo_matcher=source)
        self.assertIsNone(report.selection)
        self.assertIs(report.steps[0].reason, ExplanationReason.UNSUPPORTED)
        report = explain_route(self.policy(self.domain, unknown), self.context, geo_matcher=source)
        self.assertIs(report.selection.rule, self.domain)
        source.assert_not_called()

    def test_explicit_final_for_empty_disabled_and_all_nonmatching_policies(self):
        for action in RoutingAction:
            for rules in ((), (replace(self.domain, enabled=False),), (replace(self.domain, condition=DomainCondition("other.test")),)):
                report = explain_route(self.policy(*rules, final=action), self.context)
                self.assertTrue(report.selection.is_final)
                self.assertIs(report.selection.action, action)
                self.assertEqual(report.selection.index, len(rules))
                self.assertIs(report.steps[-1].reason, ExplanationReason.FINAL)

    def test_invalid_context_types_and_inconsistent_assumptions_are_rejected(self):
        cases = (
            {"domain_source": "destination"}, {"ip_source": "dns"},
            {"domain": "example.test"},
            {"domain": "example.test", "domain_source": DomainSource.UNAVAILABLE},
            {"ips": ()}, {"ip_source": IPSource.DNS},
            {"ips": (), "ip_source": IPSource.DNS},
            {"ips": ("192.0.2.1",), "ip_source": IPSource.UNAVAILABLE},
            {"ips": (), "ip_source": IPSource.DESTINATION},
            {"ips": ("192.0.2.1", "192.0.2.2"), "ip_source": IPSource.DESTINATION},
            {"ips": "192.0.2.1", "ip_source": IPSource.DNS},
            {"ips": ("192.0.2.0/24",), "ip_source": IPSource.DNS},
            {"ips": (True,), "ip_source": IPSource.DNS},
            {"ips": iter(("192.0.2.1",)), "ip_source": IPSource.DNS},
        )
        for values in cases:
            self.assert_invalid(RoutingErrorCode.CONTEXT, RoutingContext, **values)
        for value in (None, "https://example.test/", "192.0.2.1", "bad name"):
            self.assert_invalid(RoutingErrorCode.DOMAIN, RoutingContext, domain=value, domain_source=DomainSource.DESTINATION)
        for value in ("2001:db8::1%en0", "bad address", "192.0.2.1:443"):
            self.assert_invalid(RoutingErrorCode.IP, RoutingContext, ips=(value,), ip_source=IPSource.DNS)

    def test_invalid_provider_inputs_and_outputs_do_not_become_matches(self):
        self.assert_invalid(RoutingErrorCode.RULES, explain_route, None, self.context)
        self.assert_invalid(RoutingErrorCode.CONTEXT, explain_route, self.policy(), None)
        for source in (False, {}, "source"):
            self.assert_invalid(RoutingErrorCode.MATCHER, explain_route, self.policy(self.geoip), self.context, geo_matcher=source)
        for value in (None, True, False, "match", MatchResult.MATCH, {"result": "match"}):
            self.assert_invalid(RoutingErrorCode.GEODATA_RESULT, explain_route, self.policy(self.geoip), self.context, geo_matcher=Mock(return_value=value))
        for value in (None, True, "match"):
            self.assert_invalid(RoutingErrorCode.GEODATA_RESULT, GeoMatch, value, self.ip_database)
        self.assert_invalid(RoutingErrorCode.GEODATA_RESULT, GeoMatch, MatchResult.MATCH, None)

    def test_provider_error_never_falls_back_and_detaches_exception_chain(self):
        marker = "SYNTHETIC_" + "PRIVATE_ERROR"

        def source(condition, values):
            try:
                raise ValueError(marker)
            except ValueError as cause:
                error = RuntimeError(marker)
                error.add_note(marker)
                raise error from cause

        for action in RoutingAction:
            try:
                raise ValueError(marker)
            except ValueError:
                error = self.assert_invalid(RoutingErrorCode.MATCHER, explain_route, self.policy(self.geoip, final=action), self.context, geo_matcher=source)
            self.assertIsNone(error.__context__)
            self.assertIsNone(error.__cause__)
            self.assertFalse(hasattr(error, "__notes__"))
            self.assertNotIn(marker, "".join(traceback.format_exception(error)))
        for interrupt in (KeyboardInterrupt, SystemExit):
            with self.assertRaises(interrupt):
                explain_route(self.policy(self.geoip), self.context, geo_matcher=Mock(side_effect=interrupt))

    def test_provider_traceback_payload_is_not_retained_by_new_error(self):
        class Payload:
            pass

        references = []
        errors = []

        def source(condition, values):
            payload = Payload()
            references.append(weakref.ref(payload))
            raise ValueError("Синтетический отказ")

        try:
            explain_route(self.policy(self.geoip), self.context, geo_matcher=source)
        except RoutingValidationError as error:
            errors.append(error)
        self.assertEqual(len(errors), 1)
        self.assertIsNotNone(errors[0].__traceback__)
        gc.collect()
        self.assertIsNone(references[0]())

    def test_safe_output_masks_input_and_all_arbitrary_database_fields(self):
        marker = "synthetic-private"
        database = GeoDatabase(GeoDatabaseKind.GEOSITE, marker, source=marker, version=marker)
        rule = RoutingRule(GeoSiteCondition(database, marker), RoutingAction.VPN)
        context = RoutingContext(domain=marker + ".test", domain_source=DomainSource.SNIFFING, ips=("192.0.2.99",), ip_source=IPSource.DNS)
        evidence = GeoMatch(MatchResult.MATCH, database)
        report = explain_route(self.policy(rule), context, geo_matcher=lambda c, v: evidence)
        stream = io.StringIO()
        logger = logging.Logger("static-explanation-test")
        logger.addHandler(logging.StreamHandler(stream))
        for model in (context, evidence, report, *report.steps):
            logger.warning("%r %s", model, model)
        logger.warning("%s", json.dumps(report.to_diagnostic(), ensure_ascii=False))
        self.assertNotIn(marker, stream.getvalue())
        self.assertNotIn("192.0.2.99", stream.getvalue())
        self.assertEqual(report.steps[0].database.version, marker)
        self.assertTrue(report.to_diagnostic()["preliminary"])
        self.assertIn("не доказывает", report.assumptions[0])

    def test_unknown_reference_and_validation_traceback_are_safe(self):
        marker = "SYNTHETIC_" + "PRIVATE_VALUE"
        unknown = RoutingRule(UnknownCondition(ConditionFamily.DOMAIN, marker + "\n"), RoutingAction.VPN)
        report = explain_route(self.policy(unknown), self.context)
        self.assertNotIn(marker, json.dumps(report.to_diagnostic()))
        try:
            raise ValueError(marker)
        except ValueError:
            error = self.assert_invalid(RoutingErrorCode.DOMAIN, RoutingContext, domain=marker, domain_source=DomainSource.SNIFFING)
        self.assertNotIn(marker, "".join(traceback.format_exception(error)))

    def test_context_and_results_are_immutable(self):
        report = explain_route(self.policy(self.domain), self.context)
        evidence = GeoMatch(MatchResult.MATCH, self.ip_database)
        for model, field, value in (
            (self.context, "domain", "other.test"), (self.context, "ips", ()),
            (evidence, "result", MatchResult.NO_MATCH), (report, "selection", None),
            (report, "steps", ()), (report.steps[0], "index", 4),
        ):
            with self.assertRaises(FrozenInstanceError):
                setattr(model, field, value)

    def test_result_constructors_reject_untyped_diagnostic_fields_and_snapshot_lists(self):
        report = explain_route(self.policy(self.domain), self.context)
        marker = "SYNTHETIC_" + "PRIVATE_RESULT"
        for change in (
            {"index": marker}, {"index": True}, {"index": -1}, {"rule": marker},
            {"result": marker}, {"reason": marker}, {"database": marker},
        ):
            error = self.assert_invalid(RoutingErrorCode.EXPLANATION, replace, report.steps[0], **change)
            self.assertNotIn(marker, str(error))
        for change in (
            {"context": marker}, {"steps": marker}, {"steps": [marker]},
            {"steps": []}, {"selection": marker},
        ):
            self.assert_invalid(RoutingErrorCode.EXPLANATION, replace, report, **change)
        steps = list(report.steps)
        snapshot = RouteExplanation(self.context, steps, report.selection)
        steps.clear()
        self.assertEqual(snapshot.steps, report.steps)

    def test_pure_scenario_has_no_file_network_process_or_terminal_io(self):
        calls = (
            (builtins, "open"), (builtins, "input"), (builtins, "eval"), (builtins, "exec"),
            (io, "open"), (os, "open"), (os, "system"), (os, "popen"),
            (subprocess, "Popen"), (socket, "socket"), (socket, "getaddrinfo"),
        )
        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            for owner, name in calls:
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError("Запрещён побочный эффект")))
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(output))
            context = replace(self.context, domain="другой.рф", ips=("2001:db8::1",))
            report = explain_route(self.policy(self.domain, self.ip, self.geoip, self.geosite), context, geo_matcher=lambda c, v: GeoMatch(MatchResult.NO_MATCH, c.database))
            self.assertTrue(report.selection.is_final)
            report.to_diagnostic()
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
