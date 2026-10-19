"""Правила с названиями и идентификаторами из метаданных: просмотр без записи и явное присвоение ID.

Сценарии проверяются на обезличенном снимке, управляемых источниках
и хранилище в памяти, а также с настоящим файловым хранилищем во временном
каталоге. Роутер, active configs Xray и XKeen, сеть и процессы не используются.
"""

from dataclasses import FrozenInstanceError
import errno
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.manager_metadata_files import METADATA_FILE_NAME, ManagerMetadataFiles
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.manager_metadata import InspectManagerMetadata, InspectManagerMetadataHandler
from keenvpn.application.ports import ManagerMetadataStoreError, MetadataStoreFailure as Failure, MetadataStoreReason as Reason
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.routing_import import ImportRoutingScheme, ImportRoutingSchemeHandler
from keenvpn.application.routing_rules import (
    AssignRuleIdentifiers, AssignRuleIdentifiersHandler, InspectRoutingRules, InspectRoutingRulesHandler,
    RoutingRulesView, RuleIdentityAssignmentOutcome, RuleIdentityAssignmentView, RuleIdentityView, new_rule_id,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.manager_metadata import (
    MAX_METADATA_SIZE, ManagerMetadata, ManagerMetadataErrorCode, RuleKey, RuleRecord, StoredManagerMetadata,
    UnknownFields, decode_manager_metadata, encode_manager_metadata, metadata_revision,
)
from keenvpn.domain.routing import DomainCondition, IPCondition, RoutingAction, RoutingRule, UnknownCondition
from keenvpn.domain.routing_import import ImportedRuleGroup, RoutingScheme, import_routing_scheme
from keenvpn.domain.routing_policy import RoutingPolicy
from keenvpn.domain.rule_binding import RuleBinding, bind_routing_scheme, rule_key, scheme_rules
from keenvpn.domain.xkeen_config import XKeenListName
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.in_memory import InMemoryManagerMetadataStore
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import snapshot_proxy_sources, snapshot_xray_config, synthetic_storage_placement


"пример.рф".encode("idna")

NAME_MARKER = "TEST_ONLY_PRIVATE_NAME"
PRIVATE_MARKERS = (
    "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "192.0.2.", "probe.example", "127.0.0.1",
    "/opt/var/log", "fixture-private", "Обезличенный", "geoip:", "geosite:", "domain:", "full:", '"ru"', "xn--p1ai",
    "dns-local", "a.example", "^x", NAME_MARKER, "subdomains:", "exact:", "geoip.dat", "/tmp/mnt", "test-storage",
    "private-note", "Сирота", "Последнее", "Удалённое",
)
_DEFAULT = object()
PRIVATE_TYPES = (
    ConfigDocument, XrayConfigSet, RoutingScheme, ImportedRuleGroup, RoutingPolicy, RoutingRule, DomainCondition,
    IPCondition, UnknownCondition, RuleBinding, ManagerMetadata, StoredManagerMetadata, RuleRecord, RuleKey,
    UnknownFields, BaseException, bytes,
)
SOURCES = ("xray", "settings", "init", "port_exclude", "port_proxying", "ip_exclude")
LIST_NAMES = (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING, XKeenListName.IP_EXCLUDE)
LIST_FIELDS = dict(zip(SOURCES[3:], LIST_NAMES))
UNAVAILABLE_CODES = {
    "xray": "xray_config_unavailable", "settings": "xkeen_settings_unavailable", "init": "xkeen_init_unavailable",
    "port_exclude": "xkeen_port_exclude_unavailable", "port_proxying": "xkeen_port_proxying_unavailable",
    "ip_exclude": "xkeen_ip_exclude_unavailable",
}
CATEGORIES = {
    Failure.UNAVAILABLE: ErrorCategory.SOURCE_FAILED, Failure.UNSAFE: ErrorCategory.SOURCE_FAILED,
    Failure.BUSY: ErrorCategory.SOURCE_FAILED, Failure.CONFLICT: ErrorCategory.SOURCE_FAILED,
    Failure.INVALID: ErrorCategory.INVALID_SOURCE_DATA, Failure.WRITE_FAILED: ErrorCategory.SOURCE_FAILED,
    Failure.WRITE_UNCONFIRMED: ErrorCategory.SOURCE_FAILED,
}
REASONS = {
    Failure.UNAVAILABLE: Reason.IO_ERROR.value, Failure.UNSAFE: Reason.REPLACED.value, Failure.BUSY: None,
    Failure.CONFLICT: None, Failure.INVALID: ManagerMetadataErrorCode.JSON.value,
    Failure.WRITE_FAILED: Reason.NO_SPACE.value, Failure.WRITE_UNCONFIRMED: Reason.IO_ERROR.value,
}


def fixed_id(index: int) -> str:
    """Искусственный UUID с номером; реальным правилам не соответствует."""
    return f"0000abcd-0000-4000-8000-ffff{index:08x}"


def id_factory(start: int = 0):
    counter = iter(range(start, start + 10_000))
    return lambda: fixed_id(next(counter))


def snapshot_rules():
    return scheme_rules(import_routing_scheme(snapshot_xray_config()))


def record(rule_id, rule, name=None, **extra):
    return RuleRecord(rule_id, name, rule_key(rule), UnknownFields(extra) if extra else UnknownFields())


def stored_bytes(rules=None, storage=None, **extra) -> bytes:
    return encode_manager_metadata(ManagerMetadata(storage, UnknownFields(extra), rules=rules))


def configure(sources, name, outcome):
    if name in LIST_FIELDS:
        sources.lists.set_response(LIST_FIELDS[name], outcome)
    else:
        getattr(sources, name).outcome = outcome


def routing_handler(sources):
    proxy = InspectProxyConfigHandler(sources.xray, sources.settings, sources.init, sources.lists, operation_ids=lambda: "op")
    return ImportRoutingSchemeHandler(proxy, operation_ids=lambda: "op")


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


def artificial_config(rules):
    return XrayConfigSet((
        part("04_outbounds.json", {"outbounds": [
            {"tag": "proxy-out", "protocol": "trojan"}, {"tag": "direct", "protocol": "freedom"},
        ]}),
        part("05_routing.json", {"routing": {"rules": rules}}),
    ))


class ScenarioCase(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_proxy_sources()
        self.store = InMemoryManagerMetadataStore()
        self.routing = routing_handler(self.sources)
        self.inspect = InspectRoutingRulesHandler(self.routing, self.store, operation_ids=lambda: "op-rules")
        self.assign = AssignRuleIdentifiersHandler(
            self.routing, self.store, rule_ids=id_factory(), operation_ids=lambda: "op-assign",
        )

    def run_inspect(self, command=_DEFAULT):
        return self.inspect.execute(InspectRoutingRules() if command is _DEFAULT else command)

    def run_assign(self, command=_DEFAULT):
        return self.assign.execute(AssignRuleIdentifiers() if command is _DEFAULT else command)

    def assert_private(self, result):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        if self.store.content is not None:
            self.assertNotIn(metadata_revision(self.store.content), text)
        self.assertFalse([type(item).__name__ for item in reachable(result) if isinstance(item, PRIVATE_TYPES)])

    def assert_failed(self, result, category, code, reason=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertEqual((result.error.category, result.error.code, result.error.reason), (category, code, reason))
        self.assert_private(result)

    def expected_view(self, records, stored):
        scheme = import_routing_scheme(snapshot_xray_config())
        return RoutingRulesView.from_binding(scheme, bind_routing_scheme(scheme, records), stored)


class InspectRoutingRulesTests(ScenarioCase):
    def test_without_metadata_every_rule_is_unidentified_and_nothing_is_written(self):
        result = self.run_inspect()
        self.assertTrue(result.succeeded)
        self.assertIs(type(result.data), RoutingRulesView)
        data = result.data
        self.assertEqual(result.to_dict()["command"], "inspect_routing_rules")
        self.assertEqual(
            (data.routing_part, data.metadata_present, data.scheme_read_only, data.policy_present),
            ("05_routing.json", False, True, False),
        )
        self.assertEqual(
            (data.rule_count, data.bound_rule_count, data.named_rule_count, data.unbound_rule_count),
            (40, 0, 0, 40),
        )
        self.assertEqual((data.record_count, data.unbound_record_count, data.unbound_records), (None, 0, ()))
        self.assertEqual({item.binding for item in data.rules}, {"record_missing"})
        self.assertEqual({(item.has_id, item.rule_id, item.has_name, item.name_length) for item in data.rules}, {(False, None, False, None)})
        self.assertEqual(data.to_dict(), self.expected_view((), None).to_dict())
        self.assertEqual(self.sources.calls, (1, 1, 1, LIST_NAMES))
        self.assertEqual((self.store.read_calls, self.store.write_calls, self.store.content), (1, (), None))
        self.assert_private(result)

    def test_positions_follow_groups_and_rules_of_the_scheme(self):
        scheme = import_routing_scheme(snapshot_xray_config())
        expected = [
            (group.part, group.index, offset, type(rule.condition).__name__, rule.action.value, rule.read_only)
            for group in scheme.groups for offset, rule in enumerate(group.rules)
        ]
        data = self.run_inspect().data
        actual = [
            (item.part, item.group_index, item.offset, item.condition_type, item.action, item.read_only) for item in data.rules
        ]
        self.assertEqual(actual, expected)
        self.assertEqual([item.index for item in data.rules], list(range(40)))
        # Группы без определённого действия (в снимке — 2, 3 и финальная 7) правил не дают.
        self.assertEqual({item.group_index for item in data.rules}, {0, 1, 4, 5, 6})

    def test_records_are_bound_with_names_and_ids_without_write(self):
        rules = snapshot_rules()
        records = (
            record(fixed_id(1), rules[0], NAME_MARKER), record(fixed_id(2), rules[5]),
            record(fixed_id(3), rules[39], "Последнее", note="private-note"),
            record(fixed_id(4), RoutingRule(DomainCondition("gone.example.test"), RoutingAction.DIRECT), "Удалённое"),
        )
        self.store.content = stored_bytes(records, synthetic_storage_placement(), **{"private-note": 1})
        result = self.run_inspect()
        data = result.data
        self.assertEqual((data.metadata_present, data.record_count, data.unbound_record_count), (True, 4, 1))
        self.assertEqual((data.bound_rule_count, data.named_rule_count, data.unbound_rule_count), (3, 2, 37))
        self.assertEqual(
            [(item.index, item.rule_id, item.has_name, item.name_length, item.binding) for item in data.rules if item.has_id],
            [(0, fixed_id(1), True, len(NAME_MARKER), "bound"), (5, fixed_id(2), False, None, "bound"), (39, fixed_id(3), True, 9, "bound")],
        )
        self.assertEqual(data.unbound_records, (data.unbound_records[0],))
        self.assertEqual(
            (data.unbound_records[0].rule_id, data.unbound_records[0].has_name, data.unbound_records[0].name_length, data.unbound_records[0].reason),
            (fixed_id(4), True, 9, "rule_missing"),
        )
        self.assertEqual(data.to_dict(), self.expected_view(records, decode_manager_metadata(self.store.content)).to_dict())
        self.assertEqual((self.store.write_calls, self.store.publications), ((), 0))
        self.assert_private(result)

    def test_unencodable_unsupported_key_in_record_does_not_crash_either_command(self):
        # Регрессия 238-R03: NaN и переполнение числа внутри строкового значения ключа роняли оба сценария.
        for index, value in enumerate(("NaN", '{"port":1e999}', "[Infinity]")):
            with self.subTest(value=value):
                self.setUp()
                odd = RuleRecord(fixed_id(900 + index), "Сирота", RuleKey("unsupported", value, RoutingAction.DIRECT))
                self.store.content = stored_bytes((odd,))
                content = self.store.content
                inspected = self.run_inspect()
                self.assertTrue(inspected.succeeded)
                self.assertEqual([(item.rule_id, item.reason) for item in inspected.data.unbound_records], [(fixed_id(900 + index), "rule_missing")])
                self.assertEqual(inspected.data.unbound_rule_count, 40)
                assigned = self.run_assign()
                self.assertTrue(assigned.succeeded)
                self.assertEqual((assigned.data.outcome, assigned.data.assigned_count), ("created", 40))
                stored = decode_manager_metadata(self.store.content).metadata
                self.assertEqual(stored.rules[0], odd)
                self.assertEqual(len(stored.rules), 41)
                self.assert_private(inspected)
                self.assertNotEqual(self.store.content, content)
                self.assertEqual(self.run_assign().data.outcome, "unchanged")

    def test_file_without_rules_section_and_empty_section_are_distinguished(self):
        self.store.content = stored_bytes(None, synthetic_storage_placement())
        data = self.run_inspect().data
        self.assertEqual((data.metadata_present, data.record_count), (True, None))
        self.store.content = stored_bytes(())
        data = self.run_inspect().data
        self.assertEqual((data.metadata_present, data.record_count), (True, 0))
        self.assertEqual(self.store.write_calls, ())

    def test_ambiguous_keys_bind_nothing_and_are_reported(self):
        rules = snapshot_rules()
        records = (record(fixed_id(1), rules[3], "A"), record(fixed_id(2), rules[3], "B"))
        self.store.content = stored_bytes(records)
        data = self.run_inspect().data
        self.assertEqual(data.rules[3].binding, "record_duplicate")
        self.assertEqual([(item.rule_id, item.reason) for item in data.unbound_records], [(fixed_id(1), "record_duplicate"), (fixed_id(2), "record_duplicate")])
        duplicated = artificial_config([
            {"type": "field", "domain": ["domain:dup.example.test"], "outboundTag": "direct"},
            {"type": "field", "domain": ["domain:dup.example.test"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ])
        self.sources.xray.outcome = duplicated
        same = scheme_rules(import_routing_scheme(duplicated))[0]
        self.store.content = stored_bytes((record(fixed_id(5), same, "Дубль"),))
        data = self.run_inspect().data
        self.assertEqual([item.binding for item in data.rules], ["rule_duplicate", "rule_duplicate"])
        self.assertEqual([(item.rule_id, item.reason) for item in data.unbound_records], [(fixed_id(5), "rule_duplicate")])
        self.assertTrue(data.policy_present)
        self.assertEqual(self.store.write_calls, ())

    def test_proxy_source_failures_keep_their_codes_and_stop_before_store(self):
        for index, name in enumerate(SOURCES):
            with self.subTest(source=name):
                self.setUp()
                configure(self.sources, name, OSError("fixture-private"))
                self.assert_failed(self.run_inspect(), ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name])
                self.assertEqual(self.store.read_calls, 0)
        self.setUp()
        self.sources.xray.outcome = None
        self.assert_failed(self.run_inspect(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_xray_config")
        self.assertEqual(self.store.read_calls, 0)

    def test_store_failures_and_invalid_answers_are_reported_without_partial_result(self):
        for failure in Failure:
            with self.subTest(failure=failure.value):
                self.store.read_failure = ManagerMetadataStoreError(failure, reason=REASONS[failure])
                self.assert_failed(self.run_inspect(), CATEGORIES[failure], failure.value, REASONS[failure])
        self.store.read_failure = OSError(errno.EIO, "Искусственный отказ", "/tmp/mnt/private")
        self.assert_failed(self.run_inspect(), ErrorCategory.SOURCE_FAILED, "metadata_store_failed")
        self.store.read_failure = None
        self.store.content = b"{broken"
        self.assert_failed(self.run_inspect(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_metadata", "invalid_metadata_json")
        self.store.content = None
        for answer in ({}, "x", ManagerMetadata()):
            with self.subTest(answer=type(answer).__name__):
                with patch.object(self.store, "read_metadata", return_value=answer):
                    self.assert_failed(self.run_inspect(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_metadata_store_result")
        self.assertEqual(self.store.write_calls, ())

    def test_invalid_command_or_version_does_not_read_sources(self):
        for command in (None, ImportRoutingScheme(), AssignRuleIdentifiers()):
            self.assert_failed(self.run_inspect(command), ErrorCategory.INVALID_REQUEST, "invalid_command")
        self.assert_failed(
            self.run_inspect(InspectRoutingRules(contract_version=CONTRACT_VERSION + 1)),
            ErrorCategory.INVALID_REQUEST, "unsupported_contract_version",
        )
        self.assertEqual((self.sources.calls, self.store.read_calls), ((0, 0, 0, ()), 0))

    def test_interrupts_propagate(self):
        for error in (KeyboardInterrupt(), SystemExit()):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                self.store.read_failure = error
                with self.assertRaises(type(error)):
                    self.run_inspect()
                self.setUp()
                configure(self.sources, "xray", error)
                with self.assertRaises(type(error)):
                    self.run_inspect()

    def test_no_terminal_file_network_or_process_effects(self):
        self.store.content = stored_bytes((record(fixed_id(1), snapshot_rules()[0], NAME_MARKER),))
        with forbid_external_effects():
            self.assertTrue(self.run_inspect().succeeded)
            self.store.content = None
            self.assertEqual(self.run_inspect().data.record_count, None)

    def test_results_are_frozen_and_rendered_without_new_calls(self):
        result = self.run_inspect()
        calls = (self.sources.calls, self.store.read_calls)
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertEqual((self.sources.calls, self.store.read_calls), calls)
        for model, field in ((result.data, "rules"), (result.data.rules[0], "rule_id")):
            with self.assertRaises(FrozenInstanceError):
                setattr(model, field, None)
        self.assertIs(type(result.data.rules[0]), RuleIdentityView)


class AssignRuleIdentifiersTests(ScenarioCase):
    def test_first_assignment_writes_ids_for_every_rule_and_repeat_writes_nothing(self):
        result = self.run_assign()
        self.assertTrue(result.succeeded)
        self.assertIs(type(result.data), RuleIdentityAssignmentView)
        self.assertEqual(result.to_dict()["command"], "assign_rule_identifiers")
        self.assertEqual((result.data.outcome, result.data.assigned_count), (RuleIdentityAssignmentOutcome.CREATED.value, 40))
        rules = result.data.rules
        self.assertEqual((rules.metadata_present, rules.record_count, rules.bound_rule_count, rules.named_rule_count), (True, 40, 40, 0))
        self.assertEqual([item.rule_id for item in rules.rules], [fixed_id(index) for index in range(40)])
        self.assertEqual({item.binding for item in rules.rules}, {"bound"})
        stored = decode_manager_metadata(self.store.content).metadata
        self.assertIsNone(stored.storage)
        self.assertEqual([record.rule_id for record in stored.rules], [fixed_id(index) for index in range(40)])
        self.assertEqual({record.name for record in stored.rules}, {None})
        self.assertEqual([record.key for record in stored.rules], [rule_key(rule) for rule in snapshot_rules()])
        self.assertEqual([call.expected_revision for call in self.store.write_calls], [None])
        self.assertEqual(rules.to_dict(), self.expected_view(stored.rules, decode_manager_metadata(self.store.content)).to_dict())
        self.assert_private(result)
        content = self.store.content
        for _ in range(3):
            again = self.run_assign()
            self.assertEqual((again.data.outcome, again.data.assigned_count), ("unchanged", 0))
            self.assertEqual(again.data.rules.to_dict(), rules.to_dict())
        self.assertEqual((len(self.store.write_calls), self.store.publications, self.store.content), (1, 1, content))
        inspected = self.run_inspect().data
        self.assertEqual(inspected.to_dict(), rules.to_dict())

    def test_assignment_keeps_existing_records_and_adds_only_missing_ones_in_rule_order(self):
        rules = snapshot_rules()
        existing = (
            record(fixed_id(901), rules[5], NAME_MARKER, note="private-note"),
            record(fixed_id(902), RoutingRule(IPCondition("198.51.100.9"), RoutingAction.BLOCK), "Сирота"),
            record(fixed_id(903), rules[7], "A"), record(fixed_id(904), rules[7], "B"),
        )
        self.store.content = stored_bytes(existing, synthetic_storage_placement(), **{"future-section": [1]})
        before = decode_manager_metadata(self.store.content)
        result = self.run_assign()
        self.assertEqual((result.data.outcome, result.data.assigned_count), ("created", 38))
        stored = decode_manager_metadata(self.store.content).metadata
        self.assertEqual(stored.rules[:4], existing)
        self.assertEqual(stored.storage, before.metadata.storage)
        self.assertEqual(stored.extra, before.metadata.extra)
        self.assertEqual([record.rule_id for record in stored.rules[4:]], [fixed_id(index) for index in range(38)])
        self.assertEqual([record.key for record in stored.rules[4:]], [rule_key(rule) for index, rule in enumerate(rules) if index not in (5, 7)])
        self.assertEqual([call.expected_revision for call in self.store.write_calls], [before.revision])
        view = result.data.rules
        self.assertEqual((view.rules[5].rule_id, view.rules[5].name_length), (fixed_id(901), len(NAME_MARKER)))
        self.assertEqual((view.rules[7].binding, view.rules[7].has_id), ("record_duplicate", False))
        self.assertEqual([(item.rule_id, item.reason) for item in view.unbound_records], [
            (fixed_id(902), "rule_missing"), (fixed_id(903), "record_duplicate"), (fixed_id(904), "record_duplicate"),
        ])
        self.assertEqual((view.bound_rule_count, view.unbound_rule_count, view.record_count), (39, 1, 42))
        self.assert_private(result)
        again = self.run_assign()
        self.assertEqual((again.data.outcome, self.store.publications), ("unchanged", 1))

    def test_nothing_to_assign_creates_no_file_and_no_section(self):
        self.sources.xray.outcome = artificial_config([
            {"type": "field", "inboundTag": ["dns-in"], "outboundTag": "missing"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ])
        result = self.run_assign()
        self.assertEqual((result.data.outcome, result.data.assigned_count, result.data.rules.rule_count), ("unchanged", 0, 0))
        self.assertEqual((self.store.write_calls, self.store.content), ((), None))
        self.store.content = stored_bytes(None, synthetic_storage_placement(), **{"private-note": 1})
        content = self.store.content
        result = self.run_assign()
        self.assertEqual((result.data.outcome, result.data.rules.record_count, result.data.rules.metadata_present), ("unchanged", None, True))
        self.assertEqual((self.store.write_calls, self.store.content), ((), content))

    def test_non_canonical_file_with_same_records_is_unchanged_without_rewrite(self):
        rules = snapshot_rules()
        records = tuple(record(fixed_id(index), rule) for index, rule in enumerate(rules))
        canonical = json.loads(stored_bytes(records))
        reordered = {"rules": canonical["rules"], "schema_version": 1, "format": canonical["format"]}
        self.store.content = json.dumps(reordered, ensure_ascii=False).encode("utf-8")
        content = self.store.content
        result = self.run_assign()
        self.assertEqual(result.data.outcome, "unchanged")
        self.assertEqual((self.store.write_calls, self.store.content), ((), content))

    def test_rule_id_factory_failures_are_reported_without_write(self):
        rules = snapshot_rules()
        self.store.content = stored_bytes((record(fixed_id(901), rules[0]),))
        content = self.store.content
        cases = {
            "uppercase": lambda: fixed_id(1).upper(),
            "braced": lambda: "{" + fixed_id(1) + "}",
            "uuid_object": lambda: uuid.UUID(fixed_id(1)),
            "empty": lambda: "",
            "existing": lambda: fixed_id(901),
            "repeated": lambda: fixed_id(1),
            "raising": _raising_factory,
        }
        for name, factory in cases.items():
            with self.subTest(name):
                handler = AssignRuleIdentifiersHandler(self.routing, self.store, rule_ids=factory, operation_ids=lambda: "op")
                self.assert_failed(handler.execute(AssignRuleIdentifiers()), ErrorCategory.INVALID_SOURCE_DATA, "rule_id_generation_failed")
                self.assertEqual((self.store.write_calls, self.store.content), ((), content))
        generated = [new_rule_id() for _ in range(3)]
        self.assertTrue(all(len(value) == 36 and value == value.lower() and uuid.UUID(value).version == 4 for value in generated))
        self.assertEqual(len(set(generated)), 3)

    def test_each_store_write_failure_is_reported_and_never_succeeds(self):
        for failure in Failure:
            with self.subTest(failure=failure.value):
                self.setUp()
                self.store.write_failure = ManagerMetadataStoreError(failure, reason=REASONS[failure])
                self.assert_failed(self.run_assign(), CATEGORIES[failure], failure.value, REASONS[failure])
                self.assertEqual((len(self.store.write_calls), self.store.content), (1, None))
        self.setUp()
        self.store.write_failure = RuntimeError("fixture-private")
        self.assert_failed(self.run_assign(), ErrorCategory.SOURCE_FAILED, "metadata_store_failed")
        self.setUp()
        self.store.read_failure = ManagerMetadataStoreError(Failure.BUSY)
        self.assert_failed(self.run_assign(), ErrorCategory.SOURCE_FAILED, "metadata_store_busy")
        self.assertEqual(self.store.write_calls, ())

    def test_unconfirmed_write_is_failure_and_repeat_reports_unchanged(self):
        self.store.write_failure = ManagerMetadataStoreError(Failure.WRITE_UNCONFIRMED, reason=Reason.IO_ERROR.value)
        self.store.publish_before_failure = True
        self.assert_failed(self.run_assign(), ErrorCategory.SOURCE_FAILED, "metadata_write_unconfirmed", "io_error")
        self.assertEqual(self.store.publications, 1)
        self.store.write_failure = None
        again = self.run_assign()
        self.assertEqual((again.data.outcome, len(self.store.write_calls), self.store.publications), ("unchanged", 1, 1))

    def test_external_change_just_before_revision_check_is_conflict_without_overwrite(self):
        self.store.content = stored_bytes(None, synthetic_storage_placement())
        foreign = stored_bytes(None, synthetic_storage_placement(), **{"edited": True})

        def edit():
            self.store.content = foreign

        self.store.before_revision_check = edit
        self.assert_failed(self.run_assign(), ErrorCategory.SOURCE_FAILED, "metadata_revision_conflict")
        self.assertEqual((self.store.content, self.store.publications), (foreign, 0))

    def test_store_revision_not_matching_candidate_is_invalid_result(self):
        for answer in ("ab" * 32, None, 1):
            with self.subTest(answer=repr(answer)):
                self.setUp()
                with patch.object(self.store, "write_metadata", return_value=answer):
                    self.assert_failed(self.run_assign(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_metadata_store_result")

    def test_candidate_over_size_limit_is_inconsistent_without_write(self):
        filler = "x" * (MAX_METADATA_SIZE - 2000)
        self.store.content = json.dumps({"format": "keenvpn-manager-metadata", "schema_version": 1, "big": filler}).encode("ascii")
        self.assert_failed(self.run_assign(), ErrorCategory.INVALID_SOURCE_DATA, "manager_metadata_inconsistent", "invalid_metadata_content")
        self.assertEqual(self.store.write_calls, ())

    def test_compact_file_whose_formatted_copy_exceeds_the_limit_is_unchanged_when_nothing_is_missing(self):
        # Регрессия 238-R02: без новых записей документ кодировался с отступами и превышал предел.
        rules = snapshot_rules()
        records = tuple(record(fixed_id(index), rule) for index, rule in enumerate(rules))
        document = json.loads(stored_bytes(records))
        document["big"] = [0] * 160_000
        compact = json.dumps(document, separators=(",", ":")).encode("ascii")
        self.assertLess(len(compact), MAX_METADATA_SIZE)
        self.assertGreater(len(json.dumps(document, indent=2)), MAX_METADATA_SIZE)
        self.store.content = compact
        self.assertTrue(self.run_inspect().succeeded)
        result = self.run_assign()
        self.assertTrue(result.succeeded)
        self.assertEqual((result.data.outcome, result.data.assigned_count, result.data.rules.bound_rule_count), ("unchanged", 0, 40))
        self.assertEqual((self.store.write_calls, self.store.content), ((), compact))
        # С недостающей записью тот же файл по-прежнему не кодируется в пределах формата: отказ без записи.
        document["rules"] = document["rules"][:-1]
        self.store.content = json.dumps(document, separators=(",", ":")).encode("ascii")
        handler = AssignRuleIdentifiersHandler(self.routing, self.store, rule_ids=id_factory(100), operation_ids=lambda: "op")
        self.assert_failed(handler.execute(AssignRuleIdentifiers()), ErrorCategory.INVALID_SOURCE_DATA, "manager_metadata_inconsistent", "invalid_metadata_content")
        self.assertEqual(self.store.write_calls, ())

    def test_proxy_failures_import_failure_and_invalid_command_stop_before_store(self):
        configure(self.sources, "init", OSError("fixture-private"))
        self.assert_failed(self.run_assign(), ErrorCategory.SOURCE_FAILED, "xkeen_init_unavailable")
        self.assertEqual((self.store.read_calls, self.store.write_calls), (0, ()))
        for command in (None, InspectRoutingRules()):
            self.assert_failed(self.run_assign(command), ErrorCategory.INVALID_REQUEST, "invalid_command")
        self.assert_failed(self.run_assign(AssignRuleIdentifiers(contract_version=2)), ErrorCategory.INVALID_REQUEST, "unsupported_contract_version")
        # Отказ init остановил чтение до списков; неверные команды источники не читали.
        self.assertEqual(self.sources.calls, (1, 1, 1, ()))

    def test_interrupts_propagate_and_no_external_effects(self):
        self.store.write_failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_assign()
        self.setUp()
        with forbid_external_effects():
            self.assertEqual(self.run_assign().data.outcome, "created")
            self.assertEqual(self.run_assign().data.outcome, "unchanged")
            self.assertEqual(self.run_inspect().data.bound_rule_count, 40)

    def test_results_are_frozen_and_rendered_without_new_calls(self):
        result = self.run_assign()
        calls = (self.sources.calls, self.store.read_calls, len(self.store.write_calls))
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertEqual((self.sources.calls, self.store.read_calls, len(self.store.write_calls)), calls)
        with self.assertRaises(FrozenInstanceError):
            result.data.outcome = "x"


def _raising_factory():
    raise RuntimeError("fixture-private")


class FileStoreIntegrationTests(unittest.TestCase):
    """Сценарии с настоящим `ManagerMetadataFiles` во временном каталоге: просмотр не создаёт файл."""

    def setUp(self):
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-rules-")))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "state").mkdir()
        self.directory = self.root / "state" / "keenvpn"
        self.store = ManagerMetadataFiles(str(self.directory))
        self.sources = snapshot_proxy_sources()
        routing = routing_handler(self.sources)
        self.inspect = InspectRoutingRulesHandler(routing, self.store)
        self.assign = AssignRuleIdentifiersHandler(routing, self.store, rule_ids=id_factory())

    def tree(self):
        return sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))

    def test_inspection_never_creates_metadata_and_assignment_writes_once(self):
        for _ in range(2):
            result = self.inspect.execute(InspectRoutingRules())
            self.assertTrue(result.succeeded)
            self.assertEqual((result.data.metadata_present, result.data.unbound_rule_count), (False, 40))
        self.assertEqual(self.tree(), ["state"])
        created = self.assign.execute(AssignRuleIdentifiers())
        self.assertEqual((created.data.outcome, created.data.assigned_count), ("created", 40))
        file = self.directory / METADATA_FILE_NAME
        self.assertEqual(self.tree(), ["state", "state/keenvpn", str(file.relative_to(self.root))])
        state = (file.stat().st_ino, file.stat().st_mtime_ns, file.read_bytes())
        for _ in range(2):
            again = self.assign.execute(AssignRuleIdentifiers())
            self.assertEqual(again.data.outcome, "unchanged")
        self.assertEqual((file.stat().st_ino, file.stat().st_mtime_ns, file.read_bytes()), state)
        inspected = self.inspect.execute(InspectRoutingRules()).data
        self.assertEqual((inspected.metadata_present, inspected.bound_rule_count, inspected.record_count), (True, 40, 40))
        self.assertEqual([item.rule_id for item in inspected.rules], [fixed_id(index) for index in range(40)])
        status = InspectManagerMetadataHandler(self.store).execute(InspectManagerMetadata()).data
        self.assertEqual(status.metadata.to_dict()["rules"], {"record_count": 40, "named_record_count": 0})
        self.assertEqual(decode_manager_metadata(file.read_bytes()).metadata.storage, None)

    def test_corrupted_file_is_not_overwritten_by_assignment(self):
        self.directory.mkdir(mode=0o700)
        file = self.directory / METADATA_FILE_NAME
        file.write_bytes(b"{broken")
        file.chmod(0o600)
        result = self.assign.execute(AssignRuleIdentifiers())
        self.assertEqual((result.error.code, result.error.reason), ("invalid_stored_metadata", "invalid_metadata_json"))
        self.assertEqual(file.read_bytes(), b"{broken")


if __name__ == "__main__":
    unittest.main()
