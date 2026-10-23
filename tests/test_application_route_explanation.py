"""Объяснение маршрута по импортированной схеме: строка назначения, четыре итога, идентичность и отказы.

Сценарий проверяется на обезличенном снимке, искусственных частях Xray
в памяти, хранилище метаданных в памяти и управляемом источнике геоданных.
Роутер, active configs Xray и XKeen, сеть и процессы не используются.
"""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application import routing_import as routing_import_module
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory, ErrorDetail, NextStepCode
from keenvpn.application.ports import ManagerMetadataStoreError, MetadataStoreFailure
from keenvpn.application.proxy_config import InspectProxyConfigHandler, XrayPositionView
from keenvpn.application.routing import (
    INCONSISTENT, OUTCOME_LABELS, STEP_RESULT_LABELS, ExplainRoute, ExplainRouteHandler, RouteExplanationView,
    RouteOutcome, RouteSchemeView, RouteSelectionView, RouteStepView,
)
from keenvpn.application.routing_import import ImportRoutingSchemeHandler, RuleTargetView
from keenvpn.application.routing_rules import ListRoutingRules, ListRoutingRulesHandler, MetadataState, TargetPositionState
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.manager_metadata import ManagerMetadata, RuleRecord, UnknownFields, encode_manager_metadata
from keenvpn.domain.routing import (
    DomainCondition, GeoDatabase, GeoDatabaseKind, GeoIPCondition, IPCondition, RoutingAction, RoutingRule,
    RoutingValidationError,
)
from keenvpn.domain.routing_explanation import DomainSource, GeoMatch, IPSource
from keenvpn.domain.routing_import import RoutingImportError, RoutingImportErrorCode, RoutingScheme, import_routing_scheme
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy
from keenvpn.domain.rule_binding import RuleBinding, RuleBindingError, RuleBindingErrorCode, rule_key, scheme_rules
from keenvpn.domain.xkeen_config import XKeenListName
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.in_memory import InMemoryGeoDataSource, InMemoryManagerMetadataStore, InMemoryRoutingPolicySource
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_IDENTIFIERS, UNSAFE_MARKERS, reachable
from tests.support.snapshot import snapshot_proxy_sources, snapshot_xray_config


# Кодек IDNA импортируется при первом обращении: прогреваем его до запрета внешних эффектов.
"пример.рф".encode("idna")

NAME_MARKER = "TEST_ONLY_PRIVATE_NAME"
ENTERED = ("sub.example.test", "blocked.example.test", "service.another.test", "198.51.100.7", "2001:db8::7", "exact.example.test")
"""Вводимые значения: ни одно не достижимо из результата и не входит в его repr, str и JSON."""
CONDITION_MARKERS = ("example.test", "198.51.100.0", "geoip:", "geoip.dat", '"ru"', "another.test", "fixture-rule", "host-0", "192.0.2.")
PRIVATE_TYPES = (
    ConfigDocument, XrayConfigSet, RoutingScheme, RoutingPolicy, RoutingRule, DomainCondition, IPCondition,
    GeoIPCondition, RuleBinding, ManagerMetadata, RuleRecord, UnknownFields, BaseException, bytes,
)
SOURCES = ("xray", "settings", "init", "port_exclude", "port_proxying", "ip_exclude")
LIST_NAMES = dict(zip(SOURCES[3:], (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING, XKeenListName.IP_EXCLUDE)))
UNAVAILABLE_CODES = {
    "xray": "xray_config_unavailable", "settings": "xkeen_settings_unavailable", "init": "xkeen_init_unavailable",
    "port_exclude": "xkeen_port_exclude_unavailable", "port_proxying": "xkeen_port_proxying_unavailable",
    "ip_exclude": "xkeen_ip_exclude_unavailable",
}
DIRECT_POSITION = XrayPositionView("04_outbounds.json", 1)
BLOCK_POSITION = XrayPositionView("04_outbounds.json", 2)
PROXY_POSITION = XrayPositionView("04_outbounds.json", 0)


def fixed_id(index: int) -> str:
    """Искусственный UUID с номером; реальным правилам не соответствует."""
    return f"0000abcd-0000-4000-8000-ffff{index:08x}"


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


def artificial_xray(final_tag: str = "proxy-out", outbound_tag: str = "direct") -> XrayConfigSet:
    """Части Xray с собираемой политикой: BLOCK по домену, DIRECT по доменам, подсети и GeoIP, финальный VPN."""
    return XrayConfigSet((
        part("04_outbounds.json", {"outbounds": [
            {"tag": "proxy-out", "protocol": "trojan"}, {"tag": outbound_tag, "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ]}),
        part("05_routing.json", {"routing": {"rules": [
            {"type": "field", "domain": ["domain:blocked.example.test"], "outboundTag": "block"},
            {"type": "field", "domain": ["full:exact.example.test", "domain:example.test"], "outboundTag": outbound_tag},
            {"type": "field", "ip": ["198.51.100.0/24"], "outboundTag": outbound_tag},
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": outbound_tag},
            {"type": "field", "network": "tcp,udp", "outboundTag": final_tag},
        ]}}),
    ))


def configure(sources, name, outcome):
    if name in LIST_NAMES:
        sources.lists.set_response(LIST_NAMES[name], outcome)
    else:
        getattr(sources, name).outcome = outcome


def strings_outside_names(value, key=None):
    """Все строки JSON-представления, кроме значений под ключом `name`."""
    if isinstance(value, dict):
        return [text for item_key, item in value.items() for text in strings_outside_names(item, item_key)]
    if isinstance(value, list):
        return [text for item in value for text in strings_outside_names(item, key)]
    return [value] if isinstance(value, str) and key != "name" else []


class ImportedExplanationCase(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_proxy_sources()
        self.sources.xray.outcome = artificial_xray()
        self.store = InMemoryManagerMetadataStore()
        self.geodata = InMemoryGeoDataSource()
        proxy = InspectProxyConfigHandler(
            self.sources.xray, self.sources.settings, self.sources.init, self.sources.lists, operation_ids=lambda: "op",
        )
        self.routing = ImportRoutingSchemeHandler(proxy, operation_ids=lambda: "op")

    def handler(self, store=..., geodata=None):
        return ExplainRouteHandler.from_import(
            self.routing, self.store if store is ... else store, geodata, operation_ids=lambda: "op-explain",
        )

    def explain(self, destination, *, store=..., geodata=None):
        return self.handler(store, geodata).execute(ExplainRoute(destination=destination))

    def scheme(self) -> RoutingScheme:
        return import_routing_scheme(self.sources.xray.outcome)

    def geoip_condition(self):
        return self.scheme().groups[3].conditions[0]

    def assert_private(self, result, entered=ENTERED):
        dumped = result.to_dict()
        text = repr(result) + str(result) + json.dumps(dumped, ensure_ascii=False)
        for marker in (*entered, *CONDITION_MARKERS):
            self.assertNotIn(marker, text, marker)
        for item in strings_outside_names(dumped):
            self.assertNotIn(NAME_MARKER, item)
        for item in reachable(result):
            if isinstance(item, str):
                for marker in (*entered, *CONDITION_MARKERS):
                    self.assertNotIn(marker, item)
        self.assertFalse([type(item).__name__ for item in reachable(result) if isinstance(item, PRIVATE_TYPES)])
        self.assertEqual(self.store.write_calls, ())

    def assert_failed(self, result, category, code, reason=None, step=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertEqual((result.error.category, result.error.code, result.error.reason), (category, code, reason))
        if step is not None:
            self.assertIs(result.error.next_step.code, step)
        self.assert_private(result)

    def assert_succeeded(self, result, outcome):
        self.assertTrue(result.succeeded, result.error)
        self.assertEqual(result.command, "explain_route")
        self.assertIs(result.data.outcome, outcome)
        self.assertEqual(result.to_dict()["data"]["outcome"], outcome.value)
        self.assert_private(result)
        return result.data


class DestinationOutcomeTests(ImportedExplanationCase):
    def test_domain_selects_a_rule_with_group_offset_and_target_position(self):
        with forbid_external_effects():
            data = self.assert_succeeded(self.explain("sub.example.test"), RouteOutcome.RULE)
        self.assertEqual((data.domain_source, data.ip_source, data.ip_count), ("destination", "unknown", None))
        self.assertEqual([(step.index, step.group_index, step.offset, step.result) for step in data.steps],
                         [(0, 0, 0, "no_match"), (1, 1, 0, "no_match"), (2, 1, 1, "match")])
        self.assertEqual([step.reason_code for step in data.steps], ["domain", "domain", "domain"])
        selection = data.selection
        self.assertEqual((selection.index, selection.action, selection.is_final), (2, "DIRECT", False))
        self.assertEqual((selection.group_index, selection.offset), (1, 1))
        self.assertEqual((selection.has_id, selection.rule_id, selection.has_name, selection.name), (False, None, False, None))
        self.assertIs(type(selection.target), RuleTargetView)
        self.assertEqual((selection.target.kind, selection.target.tag, selection.target.action), ("outbound", "direct", "DIRECT"))
        self.assertIs(selection.target_position_state, TargetPositionState.RESOLVED)
        self.assertEqual(selection.target_position, DIRECT_POSITION)
        self.assertEqual(data.scheme, RouteSchemeView("05_routing.json", False, (), 5, 5, True))
        self.assertIs(data.metadata_state, MetadataState.ABSENT)
        self.assertIsNone(data.metadata_error)

    def test_exact_and_blocked_names_select_their_rules(self):
        data = self.assert_succeeded(self.explain("exact.example.test"), RouteOutcome.RULE)
        self.assertEqual((data.selection.index, data.selection.offset, data.selection.action), (1, 0, "DIRECT"))
        data = self.assert_succeeded(self.explain("blocked.example.test"), RouteOutcome.RULE)
        self.assertEqual((data.selection.index, data.selection.group_index, data.selection.action), (0, 0, "BLOCK"))
        self.assertEqual(data.selection.target_position, BLOCK_POSITION)
        self.assertEqual(len(data.steps), 1)

    def test_single_address_stops_on_the_first_domain_rule_as_unknown(self):
        data = self.assert_succeeded(self.explain("198.51.100.7"), RouteOutcome.UNKNOWN)
        self.assertEqual((data.domain_source, data.ip_source, data.ip_count), ("unknown", "destination", 1))
        self.assertIsNone(data.selection)
        self.assertEqual([(step.result, step.reason_code) for step in data.steps], [("unknown", "domain_unknown")])
        self.assertEqual(data.steps[0].action, "BLOCK")

    def test_domain_with_addresses_reaches_ip_rules(self):
        data = self.assert_succeeded(self.explain("service.another.test 198.51.100.7"), RouteOutcome.RULE)
        self.assertEqual((data.ip_source, data.ip_count), ("dns", 1))
        self.assertEqual([step.reason_code for step in data.steps], ["domain", "domain", "domain", "ip"])
        self.assertEqual((data.selection.index, data.selection.group_index, data.selection.offset), (3, 2, 0))
        self.assertEqual(data.selection.target_position, DIRECT_POSITION)

    def test_geodata_missing_is_unknown_never_direct(self):
        data = self.assert_succeeded(self.explain("service.another.test 2001:db8::7"), RouteOutcome.UNKNOWN)
        last = data.steps[-1]
        self.assertEqual((last.index, last.group_index, last.condition_type, last.result, last.reason_code),
                         (4, 3, "GeoIPCondition", "unknown", "geodata_missing"))
        self.assertIsNone(data.selection)
        self.assertEqual(self.geodata.calls, ())

    def test_geodata_answers_select_rule_or_final(self):
        condition = self.geoip_condition()
        values = ("2001:db8::7",)
        self.geodata.set_response(condition, values, GeoMatch(MatchResult.MATCH, condition.database))
        data = self.assert_succeeded(self.explain("service.another.test 2001:db8::7", geodata=self.geodata), RouteOutcome.RULE)
        self.assertEqual((data.selection.index, data.selection.group_index, data.selection.action), (4, 3, "DIRECT"))
        self.assertEqual((data.steps[-1].database_kind, data.steps[-1].database_version_known), ("geoip", False))

        self.geodata.set_response(condition, values, GeoMatch(MatchResult.NO_MATCH, condition.database))
        data = self.assert_succeeded(self.explain("service.another.test 2001:db8::7", geodata=self.geodata), RouteOutcome.FINAL)
        selection = data.selection
        self.assertEqual((selection.index, selection.action, selection.is_final, selection.group_index, selection.offset),
                         (5, "VPN", True, 4, None))
        self.assertEqual((selection.target.kind, selection.target.tag), ("outbound", "proxy-out"))
        self.assertEqual(selection.target_position, PROXY_POSITION)
        self.assertEqual((data.steps[-1].condition_type, data.steps[-1].reason_code, data.steps[-1].result), (None, "final", "match"))
        self.assertEqual(len(self.geodata.calls), 2)

        self.geodata.set_response(condition, values, GeoMatch(MatchResult.UNKNOWN, condition.database))
        data = self.assert_succeeded(self.explain("service.another.test 2001:db8::7", geodata=self.geodata), RouteOutcome.UNKNOWN)
        self.assertEqual(data.steps[-1].reason_code, "geodata_unknown")

    def test_geodata_failures_keep_their_codes(self):
        condition = self.geoip_condition()
        values = ("2001:db8::7",)
        other = GeoDatabase(GeoDatabaseKind.GEOIP, "geoip.dat", version="other")
        cases = (
            (OSError("отказ 2001:db8::7"), ErrorCategory.SOURCE_FAILED, "rule_matcher_failed", NextStepCode.CHECK_SOURCE),
            (GeoMatch(MatchResult.MATCH, GeoDatabase(GeoDatabaseKind.GEOIP, "another.dat")), ErrorCategory.INVALID_SOURCE_DATA,
             "geodata_database_mismatch", NextStepCode.INSPECT_SOURCE_DATA),
            ("2001:db8::7", ErrorCategory.INVALID_SOURCE_DATA, "invalid_geodata_result", NextStepCode.INSPECT_SOURCE_DATA),
        )
        del other
        for outcome, category, code, step in cases:
            with self.subTest(code=code):
                self.geodata.set_response(condition, values, outcome)
                result = self.explain("service.another.test 2001:db8::7", geodata=self.geodata)
                self.assert_failed(result, category, code, step=step)
                self.assertFalse(any(isinstance(item, BaseException) for item in reachable(result)))

    def test_snapshot_policy_is_absent_and_rules_are_not_checked(self):
        self.sources.xray.outcome = snapshot_xray_config()
        with forbid_external_effects():
            data = self.assert_succeeded(self.explain("sub.example.test"), RouteOutcome.POLICY_ABSENT)
        self.assertEqual(data.steps, ())
        self.assertIsNone(data.selection)
        self.assertEqual(len(data.assumptions), 5)
        self.assertEqual((data.domain_source, data.ip_source, data.ip_count), ("destination", "unknown", None))
        scheme = data.scheme
        self.assertEqual((scheme.routing_part, scheme.read_only, scheme.reasons, scheme.group_count, scheme.policy_present),
                         ("05_routing.json", True, ("final_rule_unresolved",), 8, False))
        self.assertEqual(scheme.rule_count, sum(len(group.rules) for group in self.scheme().groups))
        self.assertIs(data.metadata_state, MetadataState.ABSENT)
        self.assertEqual(self.geodata.calls, ())

    def test_policy_absent_for_unreadable_routing_is_not_a_failure(self):
        self.sources.xray.outcome = XrayConfigSet((part("05_routing.json", {"routing": 5}),))
        data = self.assert_succeeded(self.explain("198.51.100.7"), RouteOutcome.POLICY_ABSENT)
        self.assertIn("routing_unsupported", data.scheme.reasons)
        self.assertEqual((data.scheme.group_count, data.scheme.rule_count), (0, 0))


class IdentityTests(ImportedExplanationCase):
    def records(self, names=()):
        rules = scheme_rules(self.scheme())
        records = [RuleRecord(fixed_id(number), None, rule_key(rule)) for number, rule in enumerate(rules)]
        for index, name in names:
            records[index] = RuleRecord(records[index].rule_id, name, records[index].key)
        return tuple(records)

    def stored(self, records):
        self.store.content = encode_manager_metadata(ManagerMetadata(None, UnknownFields(), rules=records))

    def test_present_metadata_adds_ids_and_names_to_steps_and_selection_without_write(self):
        self.stored(self.records(names=((2, NAME_MARKER), (0, "Блокировка"))))
        with forbid_external_effects():
            data = self.assert_succeeded(self.explain("sub.example.test"), RouteOutcome.RULE)
        self.assertIs(data.metadata_state, MetadataState.PRESENT)
        self.assertEqual([(step.has_id, step.rule_id, step.has_name, step.name) for step in data.steps], [
            (True, fixed_id(0), True, "Блокировка"), (True, fixed_id(1), False, None), (True, fixed_id(2), True, NAME_MARKER),
        ])
        selection = data.selection
        self.assertEqual((selection.has_id, selection.rule_id, selection.has_name, selection.name),
                         (True, fixed_id(2), True, NAME_MARKER))
        dumped = data.to_dict()
        self.assertEqual(dumped["selection"]["name"], NAME_MARKER)
        self.assertEqual(dumped["steps"][2]["rule_id"], fixed_id(2))
        self.assertEqual(self.store.read_calls, 1)
        # Такой же список правил даёт ту же идентичность для тех же позиций.
        listing = ListRoutingRulesHandler(self.routing, self.store).execute(ListRoutingRules()).data
        self.assertEqual(listing.groups[1].rules[1].rule_id, fixed_id(2))
        self.assertEqual(listing.groups[1].rules[1].name, NAME_MARKER)

    def test_final_rule_has_no_identity_even_with_metadata(self):
        self.stored(self.records())
        condition = self.geoip_condition()
        self.geodata.set_response(condition, ("2001:db8::7",), GeoMatch(MatchResult.NO_MATCH, condition.database))
        data = self.assert_succeeded(self.explain("service.another.test 2001:db8::7", geodata=self.geodata), RouteOutcome.FINAL)
        self.assertEqual((data.selection.has_id, data.selection.rule_id, data.selection.has_name, data.selection.name),
                         (False, None, False, None))
        self.assertTrue(all(step.has_id for step in data.steps[:-1]))
        self.assertFalse(data.steps[-1].has_id)

    def test_store_states_keep_the_explanation(self):
        with forbid_external_effects():
            data = self.assert_succeeded(self.explain("sub.example.test", store=None), RouteOutcome.RULE)
        self.assertIs(data.metadata_state, MetadataState.NOT_CONNECTED)
        self.assertIsNone(data.metadata_error)
        self.assertFalse(any(step.has_id for step in data.steps))

        failing = InMemoryManagerMetadataStore()
        failing.read_failure = ManagerMetadataStoreError(MetadataStoreFailure.BUSY)
        data = self.assert_succeeded(self.explain("sub.example.test", store=failing), RouteOutcome.RULE)
        self.assertIs(data.metadata_state, MetadataState.FAILED)
        self.assertEqual((data.metadata_error.category, data.metadata_error.code), (ErrorCategory.SOURCE_FAILED, "metadata_store_busy"))
        self.assertIs(data.metadata_error.next_step.code, NextStepCode.RETRY_LATER)
        self.assertEqual(data.selection.index, 2)
        self.assertEqual(data.to_dict()["metadata_error"]["code"], "metadata_store_busy")

        self.stored(())
        data = self.assert_succeeded(self.explain("sub.example.test"), RouteOutcome.RULE)
        self.assertIs(data.metadata_state, MetadataState.PRESENT)
        self.assertFalse(data.selection.has_id)

    def test_policy_absent_still_reports_metadata_state(self):
        self.sources.xray.outcome = snapshot_xray_config()
        self.stored(self.records())
        data = self.assert_succeeded(self.explain("sub.example.test"), RouteOutcome.POLICY_ABSENT)
        self.assertIs(data.metadata_state, MetadataState.PRESENT)
        failing = InMemoryManagerMetadataStore()
        failing.read_failure = ManagerMetadataStoreError(MetadataStoreFailure.UNSAFE)
        data = self.assert_succeeded(self.explain("sub.example.test", store=failing), RouteOutcome.POLICY_ABSENT)
        self.assertIs(data.metadata_state, MetadataState.FAILED)
        self.assertEqual(data.metadata_error.code, "metadata_store_unsafe")

    def test_binding_failure_is_reported_with_its_reason(self):
        self.stored(())
        with patch("keenvpn.application.routing_rules.bind_routing_scheme",
                   side_effect=RuleBindingError(RuleBindingErrorCode.RECORDS)):
            self.assert_failed(self.explain("sub.example.test"), ErrorCategory.INVALID_SOURCE_DATA, "rule_binding_failed",
                               "invalid_binding_records", step=NextStepCode.INSPECT_SOURCE_DATA)


class FailureTests(ImportedExplanationCase):
    def test_invalid_destination_is_input_error_before_any_reading(self):
        for destination in ("", "   ", "a b", "198.51.100.0/24", "http://example.test", "-bad", "2001:db8::7%eth0",
                            "x" * 1025, "example.test " + " ".join(f"198.51.100.{n}" for n in range(17))):
            with self.subTest(destination=destination[:30]):
                result = self.explain(destination)
                self.assert_failed(result, ErrorCategory.INVALID_INPUT, "invalid_destination", step=NextStepCode.RETRY_INPUT)
                self.assertNotIn(destination.strip()[:8] or "никогда", json.dumps(result.to_dict(), ensure_ascii=False)
                                 if destination.strip() else "")
        self.assertEqual(self.sources.calls, (0, 0, 0, ()))
        self.assertEqual(self.store.read_calls, 0)

    def test_typed_assumptions_still_work_over_the_import(self):
        command = ExplainRoute(domain="sub.example.test", domain_source=DomainSource.DESTINATION)
        data = self.assert_succeeded(self.handler().execute(command), RouteOutcome.RULE)
        self.assertEqual(data.selection.index, 2)
        bad = ExplainRoute(domain="http://bad/", domain_source=DomainSource.DESTINATION)
        self.assert_failed(self.handler().execute(bad), ErrorCategory.INVALID_INPUT, "invalid_domain", step=NextStepCode.RETRY_INPUT)

    def test_malformed_commands_do_not_read_sources(self):
        commands = (
            None, ListRoutingRules(), ExplainRoute(destination=b"example.test"), ExplainRoute(destination=5),
            ExplainRoute(destination="example.test", domain="example.test", domain_source=DomainSource.DESTINATION),
            ExplainRoute(destination="example.test", ips=("198.51.100.7",), ip_source=IPSource.DESTINATION),
            ExplainRoute(destination="example.test", domain_source=DomainSource.UNAVAILABLE),
            ExplainRoute(destination="example.test", ip_source=IPSource.UNAVAILABLE, ips=()),
            ExplainRoute(domain_source="destination"),
        )
        for command in commands:
            with self.subTest(command=repr(command)):
                self.assert_failed(self.handler().execute(command), ErrorCategory.INVALID_REQUEST, "invalid_command")
        self.assert_failed(
            self.handler().execute(ExplainRoute(destination="example.test", contract_version=CONTRACT_VERSION + 1)),
            ErrorCategory.INVALID_REQUEST, "unsupported_contract_version",
        )
        self.assertEqual(self.sources.calls, (0, 0, 0, ()))
        self.assertNotIn("example.test", repr(ExplainRoute(destination="example.test")))

    def test_proxy_source_failures_and_import_failure_keep_their_codes(self):
        for name in SOURCES:
            with self.subTest(source=name):
                self.setUp()
                configure(self.sources, name, OSError("/opt/etc/xray/configs: fixture-password"))
                self.assert_failed(self.explain("sub.example.test"), ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name],
                                   step=NextStepCode.CHECK_SOURCE)
                self.assertEqual(self.store.read_calls, 0)
        self.setUp()
        self.sources.xray.outcome = None
        self.assert_failed(self.explain("sub.example.test"), ErrorCategory.INVALID_SOURCE_DATA, "invalid_xray_config")
        self.setUp()
        with patch.object(routing_import_module, "import_routing_scheme",
                          side_effect=RoutingImportError(RoutingImportErrorCode.CONFIG)):
            self.assert_failed(self.explain("sub.example.test"), ErrorCategory.INVALID_SOURCE_DATA, "routing_import_failed",
                               RoutingImportErrorCode.CONFIG.value)

    def test_inconsistent_scheme_is_a_source_data_failure(self):
        reading_module = sys.modules["keenvpn.application.routing"]
        with patch.object(reading_module, "_rule_positions", side_effect=TypeError("несогласовано")):
            self.assert_failed(self.explain("sub.example.test"), ErrorCategory.INVALID_SOURCE_DATA, INCONSISTENT,
                               step=NextStepCode.INSPECT_SOURCE_DATA)

    def test_interrupts_propagate(self):
        for error in (KeyboardInterrupt(), SystemExit()):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                self.sources.xray.outcome = error
                with self.assertRaises(type(error)):
                    self.explain("sub.example.test")
                self.setUp()
                self.store.read_failure = error
                with self.assertRaises(type(error)):
                    self.explain("sub.example.test")

    def test_from_import_checks_its_handler(self):
        with self.assertRaises(TypeError):
            ExplainRouteHandler.from_import(self.routing.proxy, self.store)

    def test_unsafe_tags_are_hidden_but_positions_stay(self):
        unsafe = UNSAFE_IDENTIFIERS["domain"]
        self.sources.xray.outcome = artificial_xray(outbound_tag=unsafe)
        data = self.assert_succeeded(self.explain("sub.example.test"), RouteOutcome.RULE)
        self.assertEqual((data.selection.target.tag_known, data.selection.target.tag), (True, None))
        self.assertEqual(data.selection.target_position, DIRECT_POSITION)
        text = json.dumps(data.to_dict(), ensure_ascii=False)
        for marker in UNSAFE_MARKERS:
            self.assertNotIn(marker, text)

    def test_results_are_frozen_and_rendered_without_new_calls(self):
        data = self.assert_succeeded(self.explain("sub.example.test"), RouteOutcome.RULE)
        calls = self.sources.calls
        for target, field in ((data, "outcome"), (data.selection, "index"), (data.steps[0], "result"), (data.scheme, "reasons")):
            with self.assertRaises(FrozenInstanceError):
                setattr(target, field, None)
        json.loads(json.dumps(data.to_dict(), ensure_ascii=False))
        self.assertEqual(self.sources.calls, calls)


class PortPathTests(unittest.TestCase):
    """Прежний конструктор поверх порта: строка назначения разбирается так же, новые поля пустые."""

    def setUp(self):
        self.policy = RoutingPolicy((
            RoutingRule(DomainCondition("example.test"), RoutingAction.VPN, rule_id=fixed_id(7), name=NAME_MARKER),
            RoutingRule(IPCondition("198.51.100.0/24"), RoutingAction.DIRECT),
        ), FinalRoutingRule(RoutingAction.BLOCK))
        self.policies = InMemoryRoutingPolicySource(self.policy)
        self.handler = ExplainRouteHandler(self.policies, operation_ids=lambda: "op")

    def test_destination_over_the_port_keeps_scheme_fields_empty(self):
        result = self.handler.execute(ExplainRoute(destination="sub.example.test"))
        self.assertTrue(result.succeeded)
        data = result.data
        self.assertIs(data.outcome, RouteOutcome.RULE)
        self.assertEqual((data.scheme, data.metadata_state, data.metadata_error), (None, None, None))
        selection = data.selection
        self.assertEqual((selection.group_index, selection.offset, selection.target, selection.target_position_state),
                         (None, None, None, None))
        self.assertEqual((selection.has_id, selection.rule_id, selection.name), (True, fixed_id(7), NAME_MARKER))
        self.assertEqual(data.steps[0].rule_id, fixed_id(7))
        dumped = result.to_dict()["data"]
        self.assertEqual(dumped["outcome"], "rule")
        self.assertEqual(dumped["selection"]["target"], None)
        self.assertNotIn("sub.example.test", json.dumps(dumped, ensure_ascii=False))

    def test_final_and_unknown_outcomes_over_the_port(self):
        final = self.handler.execute(ExplainRoute(destination="other.test 203.0.113.7")).data
        self.assertIs(final.outcome, RouteOutcome.FINAL)
        self.assertEqual((final.selection.index, final.selection.action, final.selection.is_final), (2, "BLOCK", True))
        unknown = self.handler.execute(ExplainRoute(destination="203.0.113.7")).data
        self.assertIs(unknown.outcome, RouteOutcome.UNKNOWN)
        self.assertIsNone(unknown.selection)
        self.assertEqual(self.policies.calls, 2)

    def test_port_failures_keep_their_codes(self):
        self.policies.outcome = OSError("нет файла")
        result = self.handler.execute(ExplainRoute(destination="sub.example.test"))
        self.assertEqual((result.error.category, result.error.code), (ErrorCategory.SOURCE_FAILED, "routing_policy_unavailable"))
        self.policies.outcome = {"rules": "sub.example.test"}
        result = self.handler.execute(ExplainRoute(destination="sub.example.test"))
        self.assertEqual((result.error.category, result.error.code), (ErrorCategory.INVALID_SOURCE_DATA, "invalid_routing_policy"))
        self.assertNotIn("sub.example.test", json.dumps(result.to_dict(), ensure_ascii=False))


class ViewInvariantTests(unittest.TestCase):
    def step(self, **changes):
        values = {
            "index": 0, "condition_type": "DomainCondition", "enabled": True, "protected": False, "action": "VPN",
            "result": "match", "reason_code": "domain", "reason": "Текст.", "database_kind": None,
            "database_version_known": False,
        }
        return RouteStepView(**{**values, **changes})

    def selection(self, **changes):
        return RouteSelectionView(**{"index": 0, "action": "VPN", "is_final": False, **changes})

    def view(self, **changes):
        values = {
            "preliminary": True, "domain_source": "destination", "ip_source": "unknown", "ip_count": None,
            "assumptions": ("Текст.",), "steps": (self.step(),), "selection": self.selection(), "outcome": RouteOutcome.RULE,
        }
        return RouteExplanationView(**{**values, **changes})

    def test_step_and_selection_check_identity_and_positions(self):
        self.step(group_index=2, offset=1, has_id=True, rule_id=fixed_id(1), has_name=True, name="Имя")
        for changes in (
            {"has_id": True}, {"rule_id": fixed_id(1)}, {"has_name": True}, {"name": "Имя"}, {"has_name": True, "name": " Имя"},
            {"has_id": True, "rule_id": "НЕ-UUID"}, {"offset": 1}, {"group_index": -1}, {"group_index": True}, {"index": -1},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(TypeError):
                    self.step(**changes)
        target = RuleTargetView("outbound", True, "direct", ("direct",), False, None, False, None, "DIRECT", ())
        self.selection(group_index=1, offset=0, target=target, target_position_state=TargetPositionState.AMBIGUOUS)
        self.selection(is_final=True, group_index=4, target=target, target_position_state=TargetPositionState.RESOLVED,
                       target_position=DIRECT_POSITION)
        for changes in (
            {"is_final": True, "offset": 0}, {"target": target}, {"target_position_state": TargetPositionState.RESOLVED},
            {"target": target, "target_position_state": TargetPositionState.RESOLVED},
            {"target": target, "target_position_state": TargetPositionState.AMBIGUOUS, "target_position": DIRECT_POSITION},
            {"target": target, "target_position_state": "resolved", "target_position": DIRECT_POSITION},
            {"action": 1}, {"is_final": 1},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(TypeError):
                    self.selection(**changes)

    def test_view_checks_outcome_against_selection_steps_and_scheme(self):
        scheme = RouteSchemeView("05_routing.json", True, ("final_rule_unresolved",), 8, 40, False)
        assembled = RouteSchemeView("05_routing.json", False, (), 5, 5, True)
        error = ErrorDetail(ErrorCategory.SOURCE_FAILED, "metadata_store_busy", "Занято.")
        self.view(outcome=RouteOutcome.POLICY_ABSENT, steps=(), selection=None, scheme=scheme, metadata_state=MetadataState.ABSENT)
        self.view(outcome=RouteOutcome.UNKNOWN, selection=None)
        self.view(outcome=RouteOutcome.FINAL, selection=self.selection(is_final=True))
        self.view(scheme=assembled, metadata_state=MetadataState.FAILED, metadata_error=error)
        for changes in (
            {"outcome": RouteOutcome.UNKNOWN}, {"outcome": "rule"}, {"outcome": RouteOutcome.FINAL},
            {"selection": None}, {"selection": None, "outcome": RouteOutcome.UNKNOWN, "steps": ()},
            {"outcome": RouteOutcome.POLICY_ABSENT, "steps": (), "selection": None},
            {"outcome": RouteOutcome.POLICY_ABSENT, "steps": (), "selection": None, "scheme": assembled,
             "metadata_state": MetadataState.ABSENT},
            {"outcome": RouteOutcome.POLICY_ABSENT, "selection": None, "scheme": scheme, "metadata_state": MetadataState.ABSENT},
            {"scheme": assembled}, {"metadata_state": MetadataState.ABSENT}, {"scheme": assembled, "metadata_state": MetadataState.FAILED},
            {"scheme": assembled, "metadata_state": MetadataState.ABSENT, "metadata_error": error},
            {"preliminary": False}, {"assumptions": ["Текст."]}, {"ip_count": -1},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(TypeError):
                    self.view(**changes)
        with self.assertRaises(TypeError):
            RouteSchemeView("05_routing.json", True, ["x"], 8, 40, False)

    def test_catalogs_cover_every_outcome_and_result(self):
        self.assertEqual(set(OUTCOME_LABELS), {item.value for item in RouteOutcome})
        self.assertEqual(set(STEP_RESULT_LABELS), {item.value for item in MatchResult})
        with self.assertRaises(TypeError):
            OUTCOME_LABELS["x"] = "y"

    def test_to_dict_lists_every_field_and_round_trips(self):
        target = RuleTargetView("outbound", True, "direct", ("direct",), False, None, False, None, "DIRECT", ())
        view = self.view(
            selection=self.selection(group_index=1, offset=0, target=target, target_position_state=TargetPositionState.RESOLVED,
                                     target_position=DIRECT_POSITION),
            scheme=RouteSchemeView("05_routing.json", False, (), 5, 5, True), metadata_state=MetadataState.PRESENT,
        )
        dumped = view.to_dict()
        self.assertEqual(list(dumped), [
            "preliminary", "domain_source", "ip_source", "ip_count", "assumptions", "steps", "selection", "outcome", "scheme",
            "metadata_state", "metadata_error",
        ])
        self.assertEqual(list(dumped["steps"][0]), list(RouteStepView.__dataclass_fields__))
        self.assertEqual(list(dumped["selection"]), list(RouteSelectionView.__dataclass_fields__))
        self.assertEqual(dumped["selection"]["target"]["outbound_tags"], ["direct"])
        self.assertEqual(dumped["selection"]["target_position"], {"part": "04_outbounds.json", "index": 1})
        self.assertEqual((dumped["metadata_state"], dumped["scheme"]["reasons"]), ("present", []))
        self.assertEqual(json.loads(json.dumps(dumped, ensure_ascii=False)), dumped)


if __name__ == "__main__":
    unittest.main()
