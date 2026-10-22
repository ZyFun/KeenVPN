"""Список правил для меню: группы в фактическом порядке с идентичностью из метаданных, когда она доступна.

Сценарий проверяется на обезличенном снимке, управляемых источниках
и хранилище в памяти. Роутер, active configs Xray и XKeen, сеть и процессы не используются.
"""

from dataclasses import FrozenInstanceError, replace
import errno
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application import routing_import as routing_import_module
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory, ErrorDetail
from keenvpn.application.manager_metadata import InspectManagerMetadata
from keenvpn.application.ports import ManagerMetadataStoreError, MetadataStoreFailure as Failure, MetadataStoreReason as Reason
from keenvpn.application.proxy_config import InspectProxyConfigHandler, XrayPositionView
from keenvpn.application.routing_import import ImportRoutingScheme, ImportRoutingSchemeHandler, RoutingSchemeView
from keenvpn.application.routing_rules import (
    AssignRuleIdentifiers, InspectRoutingRules, ListRoutingRules, ListRoutingRulesHandler, MetadataState,
    RuleGroupIdentityView, RuleIdentitySummaryView, RuleListEntryView, RuleListView, TargetPositionState,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.manager_metadata import (
    ManagerMetadata, ManagerMetadataErrorCode, RuleKey, RuleRecord, StoredManagerMetadata, UnknownFields,
    encode_manager_metadata, metadata_revision,
)
from keenvpn.domain.routing import DomainCondition, IPCondition, RoutingAction, RoutingRule, UnknownCondition
from keenvpn.domain.routing_import import ImportedRuleGroup, RoutingImportError, RoutingImportErrorCode, RoutingScheme, import_routing_scheme
from keenvpn.domain.routing_policy import RoutingPolicy
from keenvpn.domain.rule_binding import RuleBinding, RuleBindingError, RuleBindingErrorCode, rule_key, scheme_rules
from keenvpn.domain.xkeen_config import XKeenListName
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.in_memory import InMemoryManagerMetadataStore
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import snapshot_proxy_sources, snapshot_xray_config, synthetic_storage_placement


"пример.рф".encode("idna")

NAME_MARKER = "TEST_ONLY_PRIVATE_NAME"
SECOND_NAME = "Второе название"
PRIVATE_MARKERS = (
    "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "192.0.2.", "probe.example", "127.0.0.1",
    "/opt/var/log", "fixture-private", "Обезличенный", "geoip:", "geosite:", "domain:", '"ru"', "xn--p1ai",
    "dns-local", "a.example", "^x", "subdomains:", "exact:", "geoip.dat", "/tmp/mnt", "test-storage",
    "private-note", "Сирота", "Удалённое",
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
# Группы снимка: индекс правила Xray → число правил модели; группы без определённого действия правил не дают.
SNAPSHOT_RULE_COUNTS = [1, 3, 0, 0, 16, 19, 1, 0]
DIRECT_POSITION = XrayPositionView("04_outbounds.json", 1)
BALANCER_POSITION = XrayPositionView("05_routing.json", 0)


def fixed_id(index: int) -> str:
    """Искусственный UUID с номером; реальным правилам не соответствует."""
    return f"0000abcd-0000-4000-8000-ffff{index:08x}"


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


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


def strings_outside_names(value, key=None):
    """Все строки JSON-представления, кроме значений под ключом `name`."""
    if isinstance(value, dict):
        return [text for item_key, item in value.items() for text in strings_outside_names(item, item_key)]
    if isinstance(value, list):
        return [text for item in value for text in strings_outside_names(item, key)]
    return [value] if isinstance(value, str) and key != "name" else []


class ScenarioCase(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_proxy_sources()
        self.store = InMemoryManagerMetadataStore()
        proxy = InspectProxyConfigHandler(
            self.sources.xray, self.sources.settings, self.sources.init, self.sources.lists, operation_ids=lambda: "op",
        )
        self.routing = ImportRoutingSchemeHandler(proxy, operation_ids=lambda: "op")
        self.handler = ListRoutingRulesHandler(self.routing, self.store, operation_ids=lambda: "op-list")

    def run_list(self, command=_DEFAULT, store=_DEFAULT):
        handler = self.handler
        if store is not _DEFAULT:
            handler = ListRoutingRulesHandler(self.routing, store, operation_ids=lambda: "op-list")
        return handler.execute(ListRoutingRules() if command is _DEFAULT else command)

    def assert_private(self, result):
        dumped = result.to_dict()
        text = repr(result) + str(result) + json.dumps(dumped, ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        # Название — пользовательский текст: оно допустимо только в поле `name` правила.
        for item in strings_outside_names(dumped):
            self.assertNotIn(NAME_MARKER, item)
            self.assertNotIn(SECOND_NAME, item)
        if self.store.content is not None:
            self.assertNotIn(metadata_revision(self.store.content), text)
        self.assertFalse([type(item).__name__ for item in reachable(result) if isinstance(item, PRIVATE_TYPES)])
        self.assertEqual(self.store.write_calls, ())

    def assert_failed(self, result, category, code, reason=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertEqual((result.error.category, result.error.code, result.error.reason), (category, code, reason))
        self.assert_private(result)

    def assert_groups_follow_the_scheme(self, data):
        scheme = import_routing_scheme(snapshot_xray_config())
        self.assertEqual(data.scheme, RoutingSchemeView.from_scheme(scheme))
        self.assertEqual([group.index for group in data.groups], [group.index for group in scheme.groups])
        self.assertEqual([group.rule_count for group in data.groups], SNAPSHOT_RULE_COUNTS)
        self.assertEqual({group.target_position_state for group in data.groups}, {TargetPositionState.RESOLVED})
        self.assertEqual(
            [group.target_position for group in data.groups],
            [DIRECT_POSITION, DIRECT_POSITION, BALANCER_POSITION, BALANCER_POSITION, DIRECT_POSITION, DIRECT_POSITION,
             DIRECT_POSITION, BALANCER_POSITION],
        )


class ListRoutingRulesTests(ScenarioCase):
    def test_without_store_the_list_is_shown_without_identity(self):
        with forbid_external_effects():
            result = self.run_list(store=None)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.to_dict()["command"], "list_routing_rules")
        data = result.data
        self.assertIs(type(data), RuleListView)
        self.assertEqual((data.metadata_state, data.metadata_error, data.identity), (MetadataState.NOT_CONNECTED, None, None))
        self.assertTrue(all(group.rules is None for group in data.groups))
        self.assert_groups_follow_the_scheme(data)
        self.assertEqual(self.sources.calls, (1, 1, 1, LIST_NAMES))
        self.assertEqual(self.store.read_calls, 0)
        dumped = data.to_dict()
        self.assertEqual(dumped["metadata_state"], "not_connected")
        self.assertEqual(dumped["groups"][0], {
            "index": 0, "rule_count": 1, "target_position_state": "resolved",
            "target_position": {"part": "04_outbounds.json", "index": 1}, "rules": None,
        })
        self.assert_private(result)

    def test_absent_metadata_marks_every_rule_as_unassigned_without_write(self):
        result = self.run_list()
        data = result.data
        self.assertEqual((data.metadata_state, data.metadata_error), (MetadataState.ABSENT, None))
        self.assertEqual(data.identity, RuleIdentitySummaryView(0, 0, 40, None, 0))
        self.assert_groups_follow_the_scheme(data)
        rules = [item for group in data.groups for item in group.rules]
        self.assertEqual([item.index for item in rules], list(range(40)))
        self.assertEqual({(item.binding, item.has_id, item.rule_id, item.has_name, item.name) for item in rules},
                         {("record_missing", False, None, False, None)})
        self.assertEqual([[item.offset for item in group.rules] for group in data.groups],
                         [list(range(count)) for count in SNAPSHOT_RULE_COUNTS])
        self.assertEqual((self.store.read_calls, self.store.content), (1, None))
        self.assert_private(result)

    def test_present_metadata_binds_names_and_ids_by_group_without_write(self):
        rules = snapshot_rules()
        records = (
            record(fixed_id(1), rules[0], NAME_MARKER), record(fixed_id(2), rules[1]),
            record(fixed_id(3), rules[39], SECOND_NAME, note="private-note"),
            record(fixed_id(4), RoutingRule(DomainCondition("gone.example.test"), RoutingAction.DIRECT), "Удалённое"),
        )
        self.store.content = stored_bytes(records, synthetic_storage_placement(), **{"private-note": 1})
        result = self.run_list()
        data = result.data
        self.assertEqual((data.metadata_state, data.metadata_error), (MetadataState.PRESENT, None))
        self.assertEqual(data.identity, RuleIdentitySummaryView(3, 2, 37, 4, 1))
        self.assert_groups_follow_the_scheme(data)
        first = data.groups[0].rules[0]
        self.assertEqual(first, RuleListEntryView(0, 0, "UnsupportedRuleCondition", "DIRECT", True, True, fixed_id(1), True, NAME_MARKER, "bound"))
        second = data.groups[1].rules[0]
        self.assertEqual((second.index, second.offset, second.rule_id, second.has_name, second.name, second.binding),
                         (1, 0, fixed_id(2), False, None, "bound"))
        last = data.groups[6].rules[0]
        self.assertEqual((last.index, last.rule_id, last.name, last.binding), (39, fixed_id(3), SECOND_NAME, "bound"))
        unbound = [item for group in data.groups for item in group.rules if item.binding != "bound"]
        self.assertEqual(len(unbound), 37)
        self.assertEqual({(item.binding, item.has_id, item.name) for item in unbound}, {("record_missing", False, None)})
        dumped = data.to_dict()
        self.assertEqual(dumped["identity"], {
            "bound_rule_count": 3, "named_rule_count": 2, "unbound_rule_count": 37, "record_count": 4,
            "unbound_record_count": 1,
        })
        self.assertEqual(dumped["groups"][0]["rules"][0]["name"], NAME_MARKER)
        self.assertEqual(json.loads(json.dumps(dumped, ensure_ascii=False)), dumped)
        self.assertEqual((self.sources.calls, self.store.read_calls), ((1, 1, 1, LIST_NAMES), 1))
        self.assert_private(result)

    def test_file_without_rules_section_and_empty_section_are_distinguished(self):
        self.store.content = stored_bytes(None, synthetic_storage_placement())
        data = self.run_list().data
        self.assertEqual((data.metadata_state, data.identity.record_count), (MetadataState.PRESENT, None))
        self.store.content = stored_bytes(())
        data = self.run_list().data
        self.assertEqual((data.metadata_state, data.identity.record_count), (MetadataState.PRESENT, 0))
        self.assertEqual(self.store.write_calls, ())

    def test_store_failures_keep_the_list_and_describe_the_failure_with_a_step(self):
        cases = [(ManagerMetadataStoreError(failure, reason=REASONS[failure]), CATEGORIES[failure], failure.value, REASONS[failure])
                 for failure in Failure]
        cases.append((OSError(errno.EIO, "Искусственный отказ", "/tmp/mnt/private"), ErrorCategory.SOURCE_FAILED,
                      "metadata_store_failed", None))
        for error, category, code, reason in cases:
            with self.subTest(code=code):
                self.setUp()
                self.store.read_failure = error
                result = self.run_list()
                self.assertTrue(result.succeeded)
                data = result.data
                self.assertIs(data.metadata_state, MetadataState.FAILED)
                self.assertIs(type(data.metadata_error), ErrorDetail)
                self.assertEqual((data.metadata_error.category, data.metadata_error.code, data.metadata_error.reason),
                                 (category, code, reason))
                self.assertIsNotNone(data.metadata_error.next_step)
                self.assertIsNone(data.identity)
                self.assertTrue(all(group.rules is None for group in data.groups))
                self.assert_groups_follow_the_scheme(data)
                self.assertEqual(data.to_dict()["metadata_error"]["code"], code)
                self.assert_private(result)
        self.setUp()
        self.store.content = b"{broken"
        data = self.run_list().data
        self.assertEqual((data.metadata_state, data.metadata_error.code, data.metadata_error.reason),
                         (MetadataState.FAILED, "invalid_stored_metadata", "invalid_metadata_json"))
        self.store.content = None
        for answer in ({}, "x", ManagerMetadata()):
            with self.subTest(answer=type(answer).__name__):
                with patch.object(self.store, "read_metadata", return_value=answer):
                    data = self.run_list().data
                self.assertEqual((data.metadata_state, data.metadata_error.code),
                                 (MetadataState.FAILED, "invalid_metadata_store_result"))
        self.assertEqual(self.store.write_calls, ())

    def test_binding_failure_is_reported_with_its_reason(self):
        self.store.content = stored_bytes(())
        with patch("keenvpn.application.routing_rules.bind_routing_scheme",
                   side_effect=RuleBindingError(RuleBindingErrorCode.RECORDS)):
            self.assert_failed(self.run_list(), ErrorCategory.INVALID_SOURCE_DATA, "rule_binding_failed",
                               "invalid_binding_records")

    def test_proxy_source_failures_and_import_failure_stop_before_store(self):
        for name in SOURCES:
            with self.subTest(source=name):
                self.setUp()
                configure(self.sources, name, OSError("fixture-private"))
                self.assert_failed(self.run_list(), ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name])
                self.assertEqual(self.store.read_calls, 0)
        self.setUp()
        self.sources.xray.outcome = None
        self.assert_failed(self.run_list(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_xray_config")
        self.setUp()
        with patch.object(routing_import_module, "import_routing_scheme",
                          side_effect=RoutingImportError(RoutingImportErrorCode.CONFIG)):
            self.assert_failed(self.run_list(), ErrorCategory.INVALID_SOURCE_DATA, "routing_import_failed",
                               RoutingImportErrorCode.CONFIG.value)
        self.assertEqual(self.store.read_calls, 0)

    def test_invalid_command_or_version_does_not_read_sources(self):
        for command in (None, ImportRoutingScheme(), InspectRoutingRules(), AssignRuleIdentifiers(), InspectManagerMetadata()):
            with self.subTest(command=type(command).__name__):
                self.assert_failed(self.run_list(command), ErrorCategory.INVALID_REQUEST, "invalid_command")
        self.assert_failed(
            self.run_list(ListRoutingRules(contract_version=CONTRACT_VERSION + 1)),
            ErrorCategory.INVALID_REQUEST, "unsupported_contract_version",
        )
        self.assertEqual((self.sources.calls, self.store.read_calls), ((0, 0, 0, ()), 0))

    def test_interrupts_propagate(self):
        for error in (KeyboardInterrupt(), SystemExit()):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                self.store.read_failure = error
                with self.assertRaises(type(error)):
                    self.run_list()
                self.setUp()
                configure(self.sources, "xray", error)
                with self.assertRaises(type(error)):
                    self.run_list()

    def test_no_terminal_file_network_or_process_effects(self):
        self.store.content = stored_bytes((record(fixed_id(1), snapshot_rules()[0], NAME_MARKER),))
        with forbid_external_effects():
            self.assertTrue(self.run_list().succeeded)
            self.store.read_failure = ManagerMetadataStoreError(Failure.BUSY)
            self.assertIs(self.run_list().data.metadata_state, MetadataState.FAILED)
            self.assertIs(self.run_list(store=None).data.metadata_state, MetadataState.NOT_CONNECTED)

    def test_results_are_frozen_and_rendered_without_new_calls(self):
        self.store.content = stored_bytes((record(fixed_id(1), snapshot_rules()[0], NAME_MARKER),))
        result = self.run_list()
        calls = (self.sources.calls, self.store.read_calls)
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertEqual((self.sources.calls, self.store.read_calls), calls)
        for model, field in (
            (result.data, "groups"), (result.data.groups[0], "rules"), (result.data.groups[0].rules[0], "name"),
            (result.data.identity, "bound_rule_count"),
        ):
            with self.assertRaises(FrozenInstanceError):
                setattr(model, field, None)


class TargetPositionTests(ScenarioCase):
    """Позиция назначения берётся из структурной сводки тех же моделей; ничего не выбирается по первому."""

    def groups(self, outbounds, rules):
        self.sources.xray.outcome = XrayConfigSet((
            part("04_outbounds.json", {"outbounds": outbounds}),
            part("05_routing.json", {"routing": {"rules": rules, "balancers": [
                {"tag": "pool", "selector": ["proxy-"], "fallbackTag": "direct", "strategy": {"type": "random"}},
            ]}}),
        ))
        result = self.run_list()
        self.assertTrue(result.succeeded, result.error)
        self.assert_private(result)
        return [(group.target_position_state, group.target_position) for group in result.data.groups]

    def test_each_state_is_derived_from_the_summary(self):
        outbounds = [
            {"tag": "proxy-out", "protocol": "trojan"}, {"tag": "direct", "protocol": "freedom"},
            {"tag": "direct", "protocol": "freedom"},
        ]
        rules = [
            {"type": "field", "domain": ["domain:one.example.test"], "outboundTag": "proxy-out"},
            {"type": "field", "domain": ["domain:two.example.test"], "balancerTag": "pool"},
            {"type": "field", "domain": ["domain:three.example.test"], "outboundTag": "direct"},
            {"type": "field", "domain": ["domain:four.example.test"], "outboundTag": "missing"},
            {"type": "field", "domain": ["domain:five.example.test"]},
            {"type": "field", "domain": ["domain:six.example.test"], "outboundTag": "proxy-out", "balancerTag": "pool"},
            5,
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ]
        self.assertEqual(self.groups(outbounds, rules), [
            (TargetPositionState.RESOLVED, XrayPositionView("04_outbounds.json", 0)),
            (TargetPositionState.RESOLVED, XrayPositionView("05_routing.json", 0)),
            (TargetPositionState.AMBIGUOUS, None),
            (TargetPositionState.UNRESOLVED, None),
            (TargetPositionState.ABSENT, None),
            (TargetPositionState.UNSUPPORTED, None),
            (TargetPositionState.UNAVAILABLE, None),
            (TargetPositionState.RESOLVED, XrayPositionView("04_outbounds.json", 0)),
        ])

    def test_hidden_target_tag_still_gets_its_position(self):
        outbounds = [{"tag": "private.example.test", "protocol": "trojan"}, {"tag": "direct", "protocol": "freedom"}]
        rules = [
            {"type": "field", "domain": ["domain:one.example.test"], "outboundTag": "private.example.test"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]
        self.assertEqual(self.groups(outbounds, rules), [
            (TargetPositionState.RESOLVED, XrayPositionView("04_outbounds.json", 0)),
            (TargetPositionState.RESOLVED, XrayPositionView("04_outbounds.json", 1)),
        ])


class ViewInvariantTests(unittest.TestCase):
    def entry(self, **changes):
        values = {
            "index": 3, "offset": 1, "condition_type": "DomainCondition", "action": "VPN", "read_only": False,
            "has_id": True, "rule_id": fixed_id(7), "has_name": True, "name": "Рабочее правило", "binding": "bound",
        }
        values.update(changes)
        return RuleListEntryView(**values)

    def test_entry_checks_name_id_and_binding_consistency(self):
        self.assertEqual(self.entry().name, "Рабочее правило")
        self.assertEqual(self.entry(has_name=False, name=None).name, None)
        self.assertEqual(self.entry(has_id=False, rule_id=None, binding="record_missing").binding, "record_missing")
        for changes in (
            {"has_name": True, "name": None}, {"has_name": False, "name": "x"}, {"name": ""}, {"name": " x"},
            {"name": "a\x1bb"}, {"name": "a\nb"}, {"name": "x" * 65}, {"name": b"x"},
            {"has_id": False, "rule_id": fixed_id(1)}, {"rule_id": fixed_id(1).upper()}, {"rule_id": "x"},
            {"has_id": True, "rule_id": None}, {"binding": "record_missing"},
            {"has_id": False, "rule_id": None, "binding": "bound"}, {"index": -1}, {"offset": True},
            {"read_only": 1}, {"condition_type": None}, {"action": RoutingAction.VPN},
        ):
            with self.subTest(changes=changes), self.assertRaises(TypeError):
                self.entry(**changes)

    def test_group_checks_rules_and_target_position(self):
        rules = (self.entry(offset=0), self.entry(offset=1))
        group = RuleGroupIdentityView(2, 2, TargetPositionState.RESOLVED, DIRECT_POSITION, rules)
        self.assertEqual(group.rules, rules)
        self.assertIsNone(RuleGroupIdentityView(2, 2, TargetPositionState.ABSENT, None, None).rules)
        for arguments in (
            (2, 2, TargetPositionState.RESOLVED, None, rules), (2, 2, TargetPositionState.ABSENT, DIRECT_POSITION, rules),
            (2, 1, TargetPositionState.RESOLVED, DIRECT_POSITION, rules), (2, 2, "resolved", DIRECT_POSITION, rules),
            (2, 2, TargetPositionState.RESOLVED, DIRECT_POSITION, list(rules)),
            (2, 2, TargetPositionState.RESOLVED, DIRECT_POSITION, (rules[1], rules[0])),
            (-1, 2, TargetPositionState.RESOLVED, DIRECT_POSITION, rules),
        ):
            with self.subTest(arguments=arguments[:4]), self.assertRaises(TypeError):
                RuleGroupIdentityView(*arguments)

    def test_summary_and_list_check_their_consistency(self):
        self.assertEqual(RuleIdentitySummaryView(1, 1, 0, None, 0).record_count, None)
        for arguments in ((1, 2, 0, None, 0), (1, 1, -1, None, 0), (1, 1, 0, -1, 0), (True, 0, 0, None, 0)):
            with self.subTest(arguments=arguments), self.assertRaises(TypeError):
                RuleIdentitySummaryView(*arguments)
        scheme = RoutingSchemeView.from_scheme(import_routing_scheme(snapshot_xray_config()))
        groups = tuple(
            RuleGroupIdentityView(group.index, count, TargetPositionState.ABSENT, None, None)
            for group, count in zip(scheme.groups, SNAPSHOT_RULE_COUNTS)
        )
        error = ErrorDetail(ErrorCategory.SOURCE_FAILED, "metadata_store_busy", "Хранилище занято.")
        self.assertIs(type(RuleListView(scheme, MetadataState.NOT_CONNECTED, None, None, groups)), RuleListView)
        self.assertIs(RuleListView(scheme, MetadataState.FAILED, error, None, groups).metadata_error, error)
        bound_groups = tuple(replace(group, rules=tuple(self.entry(offset=offset, index=offset, has_id=False, rule_id=None, has_name=False, name=None, binding="record_missing") for offset in range(group.rule_count))) for group in groups)
        identity = RuleIdentitySummaryView(0, 0, 40, None, 0)
        self.assertIs(RuleListView(scheme, MetadataState.ABSENT, None, identity, bound_groups).identity, identity)
        for arguments in (
            (scheme, MetadataState.NOT_CONNECTED, error, None, groups),
            (scheme, MetadataState.FAILED, None, None, groups),
            (scheme, MetadataState.ABSENT, None, None, bound_groups),
            (scheme, MetadataState.ABSENT, None, identity, groups),
            (scheme, MetadataState.NOT_CONNECTED, None, identity, groups),
            (scheme, "absent", None, identity, bound_groups),
            (scheme, MetadataState.NOT_CONNECTED, None, None, groups[:-1]),
            (scheme, MetadataState.NOT_CONNECTED, None, None, (replace(groups[0], index=9), *groups[1:])),
            (scheme, MetadataState.NOT_CONNECTED, None, None, list(groups)),
            (None, MetadataState.NOT_CONNECTED, None, None, groups),
        ):
            with self.subTest(state=arguments[1]), self.assertRaises(TypeError):
                RuleListView(*arguments)


if __name__ == "__main__":
    unittest.main()
