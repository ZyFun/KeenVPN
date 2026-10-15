"""Сценарии application с управляемыми ответами без роутера и внешнего I/O."""

from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import traceback
import types
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.manager_metadata_files import METADATA_FILE_NAME, ManagerMetadataFiles
from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.connections import InspectConnectionLink, InspectConnectionLinkHandler
from keenvpn.application.contract import ErrorCategory
from keenvpn.application.ports import (
    ConnectionLinkRejected, LinkRejection, ManagerMetadataStoreError, MetadataStoreFailure,
)
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler
from keenvpn.domain.connection import SecretValue, TrojanConnection
from keenvpn.domain.manager_metadata import (
    METADATA_FORMAT, HistoryLimits, ManagerMetadata, ManagerMetadataError, RoleLocation, StoragePlacement,
    StorageRoles, StorageVariant, StoredManagerMetadata, TrackedValue, UnknownFields, ValueState,
    encode_manager_metadata, metadata_revision,
)
from keenvpn.domain.routing import (
    DomainCondition, GeoDatabase, GeoDatabaseKind, GeoIPCondition, GeoSiteCondition,
    RoutingAction, RoutingRule, RoutingValidationError,
)
from keenvpn.domain.routing_explanation import DomainSource, GeoMatch, IPSource
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName
from tests.support.in_memory import (
    AdapterSetupError, GeoDataCall, InMemoryConnectionLinkParser, InMemoryGeoDatabaseSource, InMemoryGeoDataSource,
    InMemoryManagerMetadataStore, InMemoryRoutingPolicySource, InMemoryStoragePlacementSource,
    InMemoryXKeenInitSource, InMemoryXKeenListSource, InMemoryXKeenSettingsSource, InMemoryXrayConfigSource,
    InMemoryXrayProcessSource, UnconfiguredResponseError,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import frame_locals, reachable


DOMAIN = "private.example.test"
IPS = ("192.0.2.10", "2001:db8::10")
SECRET = "TEST_ONLY_MEMORY_PASSWORD"
LINK = f"trojan://{SECRET}@vpn.example.test:443?security=tls&type=ws&path=%2Ftest"
ADAPTER_MODULE = "/tests/support/in_memory.py"


class InMemoryScenarioTests(unittest.TestCase):
    def setUp(self):
        self.ip_database = GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip", version="ip-v1")
        self.site_database = GeoDatabase(GeoDatabaseKind.GEOSITE, "fixture-site", version="site-v1")
        self.ip_condition = GeoIPCondition(self.ip_database, "test-set")
        self.site_condition = GeoSiteCondition(self.site_database, "test-set")
        self.policy = RoutingPolicy((
            RoutingRule(self.ip_condition, RoutingAction.BLOCK),
            RoutingRule(self.site_condition, RoutingAction.VPN),
        ), FinalRoutingRule(RoutingAction.DIRECT))
        self.policies = InMemoryRoutingPolicySource(self.policy)
        self.geodata = InMemoryGeoDataSource()
        self.handler = ExplainRouteHandler(self.policies, self.geodata)
        self.command = ExplainRoute(
            domain=DOMAIN, domain_source=DomainSource.DESTINATION, ips=IPS, ip_source=IPSource.DNS,
        )

    def respond(self, ip_result, site_result):
        self.geodata.set_response(self.ip_condition, IPS, GeoMatch(ip_result, self.ip_database))
        self.geodata.set_response(self.site_condition, (DOMAIN,), GeoMatch(site_result, self.site_database))

    def assert_failed(self, result, category, code):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertIs(result.error.category, category)
        self.assertEqual(result.error.code, code)

    def test_two_geodata_queries_choose_vpn_in_order(self):
        self.respond(MatchResult.NO_MATCH, MatchResult.MATCH)
        result = self.handler.execute(self.command)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.selection.action, "VPN")
        self.assertFalse(result.data.selection.is_final)
        self.assertEqual(self.policies.calls, 1)
        self.assertEqual(self.geodata.calls, (
            GeoDataCall(self.ip_condition, IPS), GeoDataCall(self.site_condition, (DOMAIN,)),
        ))

    def test_direct_requires_explicit_no_match_for_both_queries(self):
        self.respond(MatchResult.NO_MATCH, MatchResult.NO_MATCH)
        result = self.handler.execute(self.command)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.selection.action, "DIRECT")
        self.assertTrue(result.data.selection.is_final)
        self.assertEqual(len(self.geodata.calls), 2)

    def test_second_query_failures_are_not_masked_by_final_direct(self):
        self.geodata.set_response(self.ip_condition, IPS, GeoMatch(MatchResult.NO_MATCH, self.ip_database))
        mismatch = GeoMatch(MatchResult.MATCH, replace(self.site_database, version="site-v2"))
        for outcome, category, code in (
            (OSError("Искусственный отказ источника."), ErrorCategory.SOURCE_FAILED, "rule_matcher_failed"),
            (None, ErrorCategory.INVALID_SOURCE_DATA, "invalid_geodata_result"),
            (mismatch, ErrorCategory.INVALID_SOURCE_DATA, "geodata_database_mismatch"),
        ):
            with self.subTest(code=code):
                self.geodata.set_response(self.site_condition, (DOMAIN,), outcome)
                self.assert_failed(self.handler.execute(self.command), category, code)
                self.assertEqual(self.geodata.calls[-1], GeoDataCall(self.site_condition, (DOMAIN,)))
        unconfigured = InMemoryGeoDataSource()
        unconfigured.set_response(self.ip_condition, IPS, GeoMatch(MatchResult.NO_MATCH, self.ip_database))
        with self.assertRaises(UnconfiguredResponseError):
            ExplainRouteHandler(self.policies, unconfigured).execute(self.command)
        self.assertEqual(len(unconfigured.calls), 2)

    def test_unknown_stops_before_next_query_and_final_direct(self):
        self.geodata.set_response(self.ip_condition, IPS, GeoMatch(MatchResult.UNKNOWN, self.ip_database))
        result = self.handler.execute(self.command)
        self.assertTrue(result.succeeded)
        self.assertIsNone(result.data.selection)
        self.assertEqual(result.data.steps[-1].reason_code, "geodata_unknown")
        self.assertEqual(self.geodata.calls, (GeoDataCall(self.ip_condition, IPS),))

    def test_match_stops_before_unconfigured_later_query(self):
        self.geodata.set_response(self.ip_condition, IPS, GeoMatch(MatchResult.MATCH, self.ip_database))
        result = self.handler.execute(self.command)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.selection.action, "BLOCK")
        self.assertEqual(len(self.geodata.calls), 1)

    def test_missing_response_is_setup_error_not_source_failure(self):
        # Ошибка подготовки теста не становится source_failed и не маскирует настроенный отказ.
        with self.assertRaises(UnconfiguredResponseError):
            self.handler.execute(self.command)
        self.assertEqual(self.geodata.calls, (GeoDataCall(self.ip_condition, IPS),))
        with self.assertRaises(UnconfiguredResponseError):
            ExplainRouteHandler(InMemoryRoutingPolicySource()).execute(self.command)
        with self.assertRaises(UnconfiguredResponseError):
            InspectConnectionLinkHandler(InMemoryConnectionLinkParser()).execute(
                InspectConnectionLink(SecretValue(LINK)),
            )

    def test_exception_class_is_setup_error_not_data(self):
        cases = (
            lambda: ExplainRouteHandler(InMemoryRoutingPolicySource(OSError)).execute(self.command),
            lambda: InspectConnectionLinkHandler(InMemoryConnectionLinkParser(KeyboardInterrupt)).execute(
                InspectConnectionLink(SecretValue(LINK)),
            ),
            lambda: self.geodata.set_response(self.ip_condition, IPS, KeyboardInterrupt)
            or self.handler.execute(self.command),
        )
        for index, run in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(AdapterSetupError):
                run()

    def test_changed_answers_and_policy_are_read_on_each_execution(self):
        self.respond(MatchResult.NO_MATCH, MatchResult.MATCH)
        for _ in range(2):
            self.assertEqual(self.handler.execute(self.command).data.selection.action, "VPN")
        self.geodata.set_response(self.ip_condition, IPS, OSError("Искусственный отказ источника."))
        self.assert_failed(self.handler.execute(self.command), ErrorCategory.SOURCE_FAILED, "rule_matcher_failed")
        self.respond(MatchResult.NO_MATCH, MatchResult.NO_MATCH)
        self.assertEqual(self.handler.execute(self.command).data.selection.action, "DIRECT")
        self.policies.outcome = RoutingPolicy((), FinalRoutingRule(RoutingAction.BLOCK))
        self.assertEqual(self.handler.execute(self.command).data.selection.action, "BLOCK")
        self.assertEqual(self.policies.calls, 5)
        self.assertEqual(len(self.geodata.calls), 7)

    def test_query_key_keeps_database_set_and_all_values_distinct(self):
        self.respond(MatchResult.NO_MATCH, MatchResult.MATCH)
        different_queries = [
            (self.ip_condition, (IPS[0],)),
            (self.ip_condition, tuple(reversed(IPS))),
            (self.ip_condition, ("192.0.2.11", IPS[1])),
            (replace(self.ip_condition, set_name="other-set"), IPS),
            (self.site_condition, IPS),
            # Совпадают база, набор и значения; отличается только тип условия.
            (GeoSiteCondition(replace(self.ip_database, kind=GeoDatabaseKind.GEOSITE), "test-set"), IPS),
        ]
        for field, value in (
            ("reference", "another-db"), ("version", "ip-v2"),
            ("source", "fixture-source"), ("sha256", "a" * 64),
        ):
            database = replace(self.ip_database, **{field: value})
            different_queries.append((replace(self.ip_condition, database=database), IPS))
        for index, (condition, values) in enumerate(different_queries):
            with self.subTest(query=index), self.assertRaises(UnconfiguredResponseError):
                self.geodata.match(condition, values)
        # Равный запрос из других объектов даёт тот же настроенный ответ.
        equal_condition = GeoIPCondition(replace(self.ip_database), "test-set")
        self.assertIs(self.geodata.match(equal_condition, tuple(list(IPS))).result, MatchResult.NO_MATCH)

    def test_response_key_uses_canonical_values_and_rejects_malformed_keys(self):
        raw_ips = ("192.0.2.10", "2001:DB8:0:0::10")
        raw_domain = "Private.Example.TEST."
        self.geodata.set_response(self.ip_condition, raw_ips, GeoMatch(MatchResult.NO_MATCH, self.ip_database))
        self.geodata.set_response(self.site_condition, (raw_domain,), GeoMatch(MatchResult.MATCH, self.site_database))
        command = ExplainRoute(
            domain=raw_domain, domain_source=DomainSource.DESTINATION, ips=raw_ips, ip_source=IPSource.DNS,
        )
        self.assertEqual(self.handler.execute(command).data.selection.action, "VPN")
        self.assertEqual([call.values for call in self.geodata.calls], [IPS, (DOMAIN,)])
        for condition, values, error in (
            (self.ip_condition, IPS[0], TypeError),
            (self.ip_condition, list(IPS), TypeError),
            (self.ip_condition, (IPS[0], 1), TypeError),
            (DomainCondition(DOMAIN), (DOMAIN,), TypeError),
            (self.ip_condition, ("192.0.2.0/24",), RoutingValidationError),
            (self.site_condition, ("http://bad/",), RoutingValidationError),
        ):
            with self.subTest(values=type(values).__name__, error=error.__name__), self.assertRaises(error):
                self.geodata.set_response(condition, values, GeoMatch(MatchResult.MATCH, self.ip_database))

    def test_explicit_none_is_invalid_data_not_a_missing_response(self):
        self.geodata.set_response(self.ip_condition, IPS, None)
        self.assert_failed(self.handler.execute(self.command), ErrorCategory.INVALID_SOURCE_DATA, "invalid_geodata_result")
        self.policies.outcome = None
        self.assert_failed(self.handler.execute(self.command), ErrorCategory.INVALID_SOURCE_DATA, "invalid_routing_policy")
        self.assert_failed(
            InspectConnectionLinkHandler(InMemoryConnectionLinkParser(None)).execute(InspectConnectionLink(SecretValue(LINK))),
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_connection_model",
        )

    def test_instances_and_call_snapshots_are_isolated(self):
        self.respond(MatchResult.NO_MATCH, MatchResult.MATCH)
        self.handler.execute(self.command)
        previous = self.geodata.calls
        self.handler.execute(self.command)
        self.assertEqual(len(previous), 2)
        self.assertEqual(len(self.geodata.calls), 4)
        with self.assertRaises(FrozenInstanceError):
            previous[0].values = ()
        other = InMemoryGeoDataSource()
        with self.assertRaises(UnconfiguredResponseError):
            other.match(self.ip_condition, IPS)
        self.assertEqual(len(other.calls), 1)
        self.assertEqual(len(self.geodata.calls), 4)
        self.assertEqual(InMemoryRoutingPolicySource().calls, 0)
        self.assertEqual(InMemoryConnectionLinkParser().calls, 0)

    def test_parser_answer_rejection_failure_and_recovery(self):
        connection = TrojanLinkParser().parse(LINK)
        parser = InMemoryConnectionLinkParser(connection)
        handler = InspectConnectionLinkHandler(parser, operation_ids=lambda: "test-operation")
        command = InspectConnectionLink(SecretValue(LINK))
        expected = InspectConnectionLinkHandler(TrojanLinkParser(), operation_ids=lambda: "test-operation").execute(command)
        self.assertEqual(handler.execute(command).to_dict(), expected.to_dict())
        for rejection, category in (
            (LinkRejection.INVALID, ErrorCategory.INVALID_INPUT),
            (LinkRejection.UNSUPPORTED, ErrorCategory.UNSUPPORTED),
        ):
            parser.outcome = ConnectionLinkRejected(rejection, "test_rejection", "Искусственный отказ.")
            self.assert_failed(handler.execute(command), category, "test_rejection")
        parser.outcome = OSError("Искусственный отказ парсера.")
        self.assert_failed(handler.execute(command), ErrorCategory.SOURCE_FAILED, "connection_parser_failed")
        parser.outcome = connection
        self.assertEqual(handler.execute(command).to_dict(), expected.to_dict())
        self.assertEqual(parser.calls, 5)

    def test_interrupts_propagate_through_each_port(self):
        for exception in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception=exception.__name__):
                parser = InMemoryConnectionLinkParser(exception())
                with self.assertRaises(exception):
                    InspectConnectionLinkHandler(parser).execute(InspectConnectionLink(SecretValue(LINK)))
                policies = InMemoryRoutingPolicySource(exception())
                with self.assertRaises(exception):
                    ExplainRouteHandler(policies).execute(self.command)
                self.geodata.set_response(self.ip_condition, IPS, exception())
                with self.assertRaises(exception):
                    self.handler.execute(self.command)
                self.assertEqual((parser.calls, policies.calls), (1, 1))
        self.assertEqual(len(self.geodata.calls), 2)

    def test_representations_and_results_hide_configured_data_and_failures(self):
        parser = InMemoryConnectionLinkParser(TrojanLinkParser().parse(LINK))
        parser_handler = InspectConnectionLinkHandler(parser)
        link_command = InspectConnectionLink(SecretValue(LINK))
        self.respond(MatchResult.NO_MATCH, MatchResult.MATCH)
        text = repr(parser) + repr(self.policies) + repr(self.geodata)
        with forbid_external_effects():
            results = [parser_handler.execute(link_command), self.handler.execute(self.command)]
            parser.outcome = OSError(LINK)
            self.geodata.set_response(self.ip_condition, IPS, OSError(f"{DOMAIN} {IPS!r}"))
            results += [parser_handler.execute(link_command), self.handler.execute(self.command)]
        self.assertTrue(results[0].succeeded)
        self.assertEqual(results[1].data.selection.action, "VPN")
        # Отказы действительно произошли: иначе проверка скрытия их текста была бы пустой.
        self.assert_failed(results[2], ErrorCategory.SOURCE_FAILED, "connection_parser_failed")
        self.assert_failed(results[3], ErrorCategory.SOURCE_FAILED, "rule_matcher_failed")
        text += repr(parser) + repr(self.policies) + repr(self.geodata) + repr(self.geodata.calls)
        for result in results:
            text += repr(result) + json.dumps(result.to_dict(), ensure_ascii=False)
            self.assertFalse(any(
                isinstance(item, (BaseException, SecretValue, TrojanConnection)) for item in reachable(result)
            ))
        for value in (LINK, SECRET, DOMAIN, *IPS, "fixture-ip", "ip-v1", "fixture-site", "site-v1", "test-set"):
            self.assertNotIn(value, text)

    def test_parser_keeps_no_link_in_fields_or_adapter_frames(self):
        parser = InMemoryConnectionLinkParser()
        try:
            parser.parse(LINK)
        except UnconfiguredResponseError as error:
            unconfigured = error
        else:
            self.fail("Ожидался отказ без настроенного ответа.")
        for locals_repr in frame_locals(unconfigured, ADAPTER_MODULE):
            self.assertNotIn(SECRET, locals_repr)

        failure = OSError("Искусственный отказ парсера.")
        parser.outcome = failure
        handler = InspectConnectionLinkHandler(parser)
        command = InspectConnectionLink(SecretValue(LINK))
        try:
            raise KeyError("Искусственное исключение вызывающего кода.")
        except KeyError:
            handler.execute(command)
        for _ in range(3):
            handler.execute(command)
        # Повторяемый отказ не копит кадры прошлых вызовов и не хранит чужой __context__.
        self.assertIsNone(failure.__context__)
        self.assertEqual(
            [frame.name for frame in traceback.extract_tb(failure.__traceback__)],
            ["execute", "parse", "_respond", "_resolve"],
        )
        for locals_repr in frame_locals(failure, ADAPTER_MODULE):
            self.assertNotIn(SECRET, locals_repr)
        self.assertNotIn(SECRET, repr(vars(parser)))
        self.assertEqual(parser.calls, 5)

    def test_replacing_failure_releases_its_frames_and_context(self):
        self.respond(MatchResult.NO_MATCH, MatchResult.MATCH)
        parser = InMemoryConnectionLinkParser()
        link_handler = InspectConnectionLinkHandler(parser)
        policies = InMemoryRoutingPolicySource()
        route_handler = ExplainRouteHandler(policies, self.geodata)
        ports = (
            (
                lambda outcome: setattr(parser, "outcome", outcome),
                lambda: link_handler.execute(InspectConnectionLink(SecretValue(LINK))),
                TrojanLinkParser().parse(LINK),
            ),
            (lambda outcome: setattr(policies, "outcome", outcome), lambda: route_handler.execute(self.command), self.policy),
            (
                lambda outcome: self.geodata.set_response(self.ip_condition, IPS, outcome),
                lambda: self.handler.execute(self.command),
                GeoMatch(MatchResult.NO_MATCH, self.ip_database),
            ),
        )
        for index, (configure, run, success) in enumerate(ports):
            with self.subTest(port=index):
                failure = OSError("Искусственный отказ.")
                configure(failure)
                try:
                    raise KeyError("Искусственное исключение вызывающего кода.")
                except KeyError:
                    self.assertFalse(run().succeeded)
                # До замены отказ удерживает кадры вызова: иначе проверка ниже была бы пустой.
                self.assertIsNotNone(failure.__traceback__)
                self.assertIsNotNone(failure.__context__)
                configure(success)
                self.assertIsNone(failure.__traceback__)
                self.assertIsNone(failure.__context__)
                self.assertFalse(any(
                    isinstance(item, (types.FrameType, SecretValue)) for item in reachable(failure)
                ))
                self.assertTrue(run().succeeded)

    def test_scenarios_have_no_terminal_file_network_or_process_effects(self):
        connection = TrojanLinkParser().parse(LINK)
        parser = InMemoryConnectionLinkParser(connection)
        handler = InspectConnectionLinkHandler(parser)
        command = InspectConnectionLink(SecretValue(LINK))
        self.respond(MatchResult.NO_MATCH, MatchResult.MATCH)
        with forbid_external_effects():
            self.assertTrue(self.handler.execute(self.command).succeeded)
            self.assertTrue(handler.execute(command).succeeded)
            parser.outcome = OSError("Искусственный отказ.")
            self.assertFalse(handler.execute(command).succeeded)
            self.geodata.set_response(self.ip_condition, IPS, OSError("Искусственный отказ."))
            self.assertFalse(self.handler.execute(self.command).succeeded)


class ProxyConfigSourceTests(unittest.TestCase):
    def test_list_source_answers_by_exact_name_and_records_calls(self):
        source = InMemoryXKeenListSource()
        exclude = XKeenList(XKeenListName.PORT_EXCLUDE, b"53\n")
        source.set_response(XKeenListName.PORT_EXCLUDE, exclude)
        self.assertIs(source.current_xkeen_list(XKeenListName.PORT_EXCLUDE), exclude)
        with self.assertRaises(UnconfiguredResponseError):
            source.current_xkeen_list(XKeenListName.PORT_PROXYING)
        self.assertEqual(source.calls, (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING))
        previous = source.calls
        source.current_xkeen_list(XKeenListName.PORT_EXCLUDE)
        self.assertEqual(len(previous), 2)
        self.assertEqual(len(source.calls), 3)
        for name in ("port_exclude.lst", None):
            with self.subTest(name=name), self.assertRaises(AdapterSetupError):
                source.set_response(name, exclude)
        source.set_response(XKeenListName.IP_EXCLUDE, OSError)
        with self.assertRaises(AdapterSetupError):
            source.current_xkeen_list(XKeenListName.IP_EXCLUDE)
        self.assertNotIn("53", repr(source))
        self.assertEqual(repr(source), "InMemoryXKeenListSource(calls=4, responses=2)")

    def test_scalar_sources_start_without_calls_and_release_replaced_failures(self):
        for source_type, method in (
            (InMemoryXrayConfigSource, "current_xray_config"),
            (InMemoryXKeenSettingsSource, "current_xkeen_settings"),
            (InMemoryXKeenInitSource, "current_xkeen_init"),
            (InMemoryGeoDatabaseSource, "current_geo_databases"),
            (InMemoryXrayProcessSource, "current_xray_process"),
        ):
            with self.subTest(source=source_type.__name__):
                source = source_type()
                self.assertEqual(source.calls, 0)
                with self.assertRaises(UnconfiguredResponseError):
                    getattr(source, method)()
                failure = OSError("Искусственный отказ.")
                source.outcome = failure
                # assertRaises очищает traceback пойманного исключения: ловим его вручную.
                try:
                    raise KeyError("Искусственное исключение вызывающего кода.")
                except KeyError:
                    try:
                        getattr(source, method)()
                    except OSError as caught:
                        self.assertIs(caught, failure)
                    else:
                        self.fail("Ожидался настроенный отказ источника.")
                self.assertIsNotNone(failure.__traceback__)
                self.assertIsNotNone(failure.__context__)
                source.outcome = None
                self.assertIsNone(failure.__traceback__)
                self.assertIsNone(failure.__context__)
                self.assertFalse(any(isinstance(item, types.FrameType) for item in reachable(failure)))
                self.assertEqual(source.calls, 2)
        lists = InMemoryXKeenListSource()
        failure = OSError("Искусственный отказ списка.")
        lists.set_response(XKeenListName.PORT_EXCLUDE, failure)
        try:
            lists.current_xkeen_list(XKeenListName.PORT_EXCLUDE)
        except OSError as caught:
            self.assertIs(caught, failure)
        else:
            self.fail("Ожидался настроенный отказ списка.")
        self.assertIsNotNone(failure.__traceback__)
        lists.set_response(XKeenListName.PORT_EXCLUDE, XKeenList(XKeenListName.PORT_EXCLUDE, b""))
        self.assertIsNone(failure.__traceback__)


STORAGE_ID = "0000abcd-0000-4000-8000-00000000000a"
STORAGE_PATH = "/tmp/mnt/test-data/keenvpn-private"


def stored_metadata(variant: StorageVariant = StorageVariant.SIMPLE) -> ManagerMetadata:
    known = lambda value: TrackedValue(ValueState.KNOWN, value)
    data = RoleLocation(ValueState.KNOWN, known(STORAGE_ID), known(STORAGE_PATH), True)
    roles = StorageRoles(data, RoleLocation(ValueState.UNKNOWN), RoleLocation(ValueState.ABSENT))
    limits = HistoryLimits(known(1024), TrackedValue(ValueState.ABSENT))
    return ManagerMetadata(StoragePlacement(known(variant), roles, limits), UnknownFields({"note": "private-note"}))


class ManagerMetadataAdapterTests(unittest.TestCase):
    def test_placement_source_answers_counts_and_releases_failures(self):
        placement = stored_metadata().storage
        source = InMemoryStoragePlacementSource()
        with self.assertRaises(UnconfiguredResponseError):
            source.current_storage_placement()
        source.outcome = placement
        self.assertIs(source.current_storage_placement(), placement)
        failure = OSError("Искусственный отказ " + STORAGE_PATH)
        source.outcome = failure
        # assertRaises очищает traceback пойманного исключения: ловим его вручную.
        try:
            source.current_storage_placement()
        except OSError as caught:
            self.assertIs(caught, failure)
        else:
            self.fail("Ожидался настроенный отказ источника.")
        self.assertIsNotNone(failure.__traceback__)
        source.outcome = placement
        self.assertIsNone(failure.__traceback__)
        self.assertEqual(source.calls, 3)
        self.assertNotIn(STORAGE_PATH, repr(source))

    def test_store_reads_writes_and_compares_revisions_with_standard_codec(self):
        store = InMemoryManagerMetadataStore()
        self.assertIsNone(store.read_metadata())
        first, second = stored_metadata(), stored_metadata(StorageVariant.EXTENDED)
        revision = store.write_metadata(first, None)
        self.assertEqual(store.content, encode_manager_metadata(first))
        self.assertEqual(revision, metadata_revision(store.content))
        stored = store.read_metadata()
        self.assertIsInstance(stored, StoredManagerMetadata)
        self.assertEqual(stored.revision, revision)
        content = store.content
        self.assertEqual(store.write_metadata(first, revision), revision)
        self.assertIs(store.content, content)
        self.assertEqual(store.publications, 1)
        for expected in (None, "0" * 64):
            with self.assertRaises(ManagerMetadataStoreError) as caught:
                store.write_metadata(second, expected)
            self.assertEqual((caught.exception.failure, caught.exception.reason), (MetadataStoreFailure.CONFLICT, None))
            self.assertIsNone(caught.exception.__context__)
        self.assertIs(store.content, content)
        self.assertNotEqual(store.write_metadata(second, revision), revision)
        self.assertEqual(store.publications, 2)
        self.assertEqual([call.expected_revision for call in store.write_calls], [None, revision, None, "0" * 64, revision])
        self.assertIsInstance(store.write_calls, tuple)

    def test_store_rejects_invalid_model_and_keeps_invalid_file(self):
        store = InMemoryManagerMetadataStore()
        broken = ManagerMetadata()
        object.__setattr__(broken, "storage", "garbage")
        with self.assertRaises(ManagerMetadataError):
            store.write_metadata(broken, None)
        self.assertIsNone(store.content)
        store.content = b"{"
        for call in (store.read_metadata, lambda: store.write_metadata(stored_metadata(), None)):
            with self.assertRaises(ManagerMetadataStoreError) as caught:
                call()
            self.assertEqual(
                (caught.exception.failure, caught.exception.reason),
                (MetadataStoreFailure.INVALID, "invalid_metadata_json"),
            )
            self.assertIsNone(caught.exception.__context__)
        self.assertEqual(store.content, b"{")

    def test_store_failures_publication_and_last_moment_change(self):
        store = InMemoryManagerMetadataStore()
        busy = ManagerMetadataStoreError(MetadataStoreFailure.BUSY)
        store.write_failure = busy
        with self.assertRaises(ManagerMetadataStoreError):
            store.write_metadata(stored_metadata(), None)
        self.assertIsNone(store.content)
        store.write_failure = ManagerMetadataStoreError(MetadataStoreFailure.WRITE_UNCONFIRMED, reason="io_error")
        store.publish_before_failure = True
        with self.assertRaises(ManagerMetadataStoreError):
            store.write_metadata(stored_metadata(), None)
        self.assertEqual(store.content, encode_manager_metadata(stored_metadata()))
        revision = metadata_revision(store.content)
        # Повтор с теми же байтами тоже отказывает без изменения: как подтверждение fsync.
        with self.assertRaises(ManagerMetadataStoreError):
            store.write_metadata(stored_metadata(), revision)
        self.assertEqual(store.publications, 1)
        store.write_failure = None
        external = encode_manager_metadata(stored_metadata(StorageVariant.EXTENDED))
        store.before_revision_check = lambda: setattr(store, "content", external)
        with self.assertRaises(ManagerMetadataStoreError) as caught:
            store.write_metadata(stored_metadata(), revision)
        self.assertEqual(caught.exception.failure, MetadataStoreFailure.CONFLICT)
        self.assertIs(store.content, external)
        store.read_failure = ManagerMetadataStoreError(MetadataStoreFailure.UNAVAILABLE, reason="io_error")
        with self.assertRaises(ManagerMetadataStoreError):
            store.read_metadata()
        self.assertEqual(store.read_calls, 1)

    def test_store_setup_errors_and_hidden_representations(self):
        for value in ("text", bytearray(b"{}"), 1):
            with self.subTest(content=type(value).__name__), self.assertRaises(AdapterSetupError):
                InMemoryManagerMetadataStore(value)
        store = InMemoryManagerMetadataStore(encode_manager_metadata(stored_metadata()))
        for outcome in (OSError, "отказ", 1):
            with self.subTest(failure=repr(outcome)):
                with self.assertRaises(AdapterSetupError):
                    store.read_failure = outcome
                with self.assertRaises(AdapterSetupError):
                    store.write_failure = outcome
        store.write_metadata(stored_metadata(), metadata_revision(store.content))
        text = repr(store) + repr(store.write_calls)
        for marker in (STORAGE_ID, STORAGE_PATH, "private-note", "simple"):
            self.assertNotIn(marker, text)


class ManagerMetadataStoreParityTests(unittest.TestCase):
    """Одна последовательность на хранилище в памяти и на файловом хранилище даёт одинаковые ответы."""

    def setUp(self):
        # Реальный путь: на macOS временный каталог находится за ссылкой /var.
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-parity-")))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "parent").mkdir()

    def run_sequence(self, store, set_content, get_content):
        first, second = stored_metadata(), stored_metadata(StorageVariant.EXTENDED)
        first_revision = metadata_revision(encode_manager_metadata(first))
        second_revision = metadata_revision(encode_manager_metadata(second))
        broken = ManagerMetadata()
        object.__setattr__(broken, "storage", "garbage")
        compact = json.dumps(json.loads(encode_manager_metadata(second)), separators=(",", ":")).encode("ascii")
        version_two = json.dumps({"format": METADATA_FORMAT, "schema_version": 2}).encode("ascii")
        steps = (
            lambda: store.read_metadata(),
            lambda: store.write_metadata(first, "0" * 64),
            lambda: store.write_metadata(first, None),
            lambda: store.read_metadata(),
            lambda: store.write_metadata(first, None),
            lambda: store.write_metadata(first, first_revision),
            lambda: store.write_metadata(second, first_revision),
            lambda: store.write_metadata(first, first_revision),
            lambda: store.write_metadata(broken, second_revision),
            lambda: set_content(compact),
            lambda: store.read_metadata(),
            lambda: store.write_metadata(second, second_revision),
            lambda: store.write_metadata(second, metadata_revision(compact)),
            lambda: store.read_metadata(),
            lambda: set_content(b"{"),
            lambda: store.read_metadata(),
            lambda: store.write_metadata(first, second_revision),
            lambda: set_content(version_two),
            lambda: store.read_metadata(),
            lambda: store.write_metadata(first, metadata_revision(version_two)),
        )
        outcomes = []
        for step in steps:
            try:
                value = step()
            except ManagerMetadataStoreError as error:
                value = ("store", error.failure.value, error.reason)
            except ManagerMetadataError as error:
                value = ("model", error.code.value)
            if isinstance(value, StoredManagerMetadata):
                value = ("stored", value.revision, encode_manager_metadata(value.metadata))
            outcomes.append((value, get_content()))
        return outcomes

    def test_in_memory_store_matches_file_store(self):
        memory = InMemoryManagerMetadataStore()
        directory = self.root / "parent" / "keenvpn"
        file = directory / METADATA_FILE_NAME

        def set_file(content):
            descriptor = os.open(file, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            try:
                os.write(descriptor, content)
            finally:
                os.close(descriptor)

        expected = self.run_sequence(
            ManagerMetadataFiles(str(directory)), set_file, lambda: file.read_bytes() if file.exists() else None,
        )
        actual = self.run_sequence(memory, lambda content: setattr(memory, "content", content), lambda: memory.content)
        self.assertEqual(actual, expected)
        # Последовательность покрывает отсутствие файла, конфликт, совпадение, замену и отказы.
        kinds = {value[0] if isinstance(value, tuple) else type(value).__name__ for value, _ in expected}
        self.assertEqual(kinds, {"NoneType", "store", "str", "stored", "model"})


class ForbidExternalEffectsTests(unittest.TestCase):
    def test_reports_swallowed_calls_and_terminal_output(self):
        def swallowed(effect):
            def run():
                try:
                    effect()
                except AssertionError:
                    # Так ведёт себя сценарий, перехватывающий `except Exception`.
                    pass
            return run

        def then_raises(run):
            def raising():
                run()
                raise ValueError("Искусственный ожидаемый отказ сценария.")
            return raising

        for name, run in (
            ("os.stat", swallowed(lambda: os.stat("."))),
            ("os.listdir", swallowed(lambda: os.listdir("."))),
            ("print", swallowed(lambda: print("вывод"))),
            ("stdout", lambda: sys.stdout.write("вывод")),
        ):
            with self.subTest(effect=name), self.assertRaises(AssertionError):
                with forbid_external_effects():
                    run()
            # Ожидаемое исключение сценария не скрывает нарушение от внешнего assertRaises.
            with self.subTest(effect=name, raises=True), self.assertRaises(AssertionError) as caught:
                with forbid_external_effects():
                    then_raises(run)()
            self.assertIsInstance(caught.exception.__context__, ValueError)

    def test_block_exception_without_effects_propagates_unchanged(self):
        expected = ValueError("Искусственный ожидаемый отказ сценария.")
        with self.assertRaises(ValueError) as caught:
            with forbid_external_effects():
                raise expected
        self.assertIs(caught.exception, expected)


if __name__ == "__main__":
    unittest.main()
