"""Название и стабильный идентификатор правила: метаданные менеджера в памяти, без Xray и роутера."""

import builtins
import contextlib
from dataclasses import replace
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
import uuid


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.routing import (
    MAX_RULE_NAME_LENGTH, ConditionFamily, DomainCondition, IPCondition, RoutingAction, RoutingErrorCode,
    RoutingRule, RoutingValidationError, UnknownCondition, valid_rule_id, valid_rule_name,
)
from keenvpn.domain.routing_import import RoutingImportError, RoutingImportErrorCode, import_routing_scheme, validate_routing_scheme
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.snapshot import snapshot_xray_config


ID_A = "0000abcd-0000-4000-8000-0000000000a1"
ID_B = "0000abcd-0000-4000-8000-0000000000b2"
ID_C = "0000abcd-0000-4000-8000-0000000000c3"
ID_FREE = "0000abcd-0000-4000-8000-0000000000ff"
"""Искусственные UUID; реальным правилам не соответствуют."""
NAME_MARKER = "TEST_ONLY_PRIVATE_NAME"


class _Text(str):
    """Подкласс строки: модель требует именно `str`."""


class RuleIdentityTestCase(unittest.TestCase):
    def setUp(self):
        self.service = RoutingRule(
            IPCondition("198.51.100.0/24"), RoutingAction.DIRECT, protected=True, rule_id=ID_A, name="Служебное",
        )
        self.named = RoutingRule(DomainCondition("example.test"), RoutingAction.VPN, rule_id=ID_B, name="Рабочий сервис")
        self.plain = RoutingRule(IPCondition("2001:db8::/32"), RoutingAction.BLOCK)
        self.disabled = RoutingRule(DomainCondition("off.example.test"), RoutingAction.VPN, enabled=False, rule_id=ID_C)
        self.final = FinalRoutingRule(RoutingAction.BLOCK)
        self.policy = RoutingPolicy((self.service, self.named, self.plain, self.disabled), self.final)

    def assert_invalid(self, code, function, *args, **kwargs):
        with self.assertRaises(RoutingValidationError) as raised:
            function(*args, **kwargs)
        self.assertIs(raised.exception.code, code)
        return raised.exception

    def identities(self, policy):
        return [(rule.rule_id, rule.name) for rule in policy.rules]


class RuleNameValidationTests(RuleIdentityTestCase):
    def test_name_and_id_are_absent_by_default(self):
        rule = RoutingRule(DomainCondition("example.test"), RoutingAction.VPN)
        self.assertIsNone(rule.rule_id)
        self.assertIsNone(rule.name)
        self.assertEqual(rule, RoutingRule(DomainCondition("example.test"), RoutingAction.VPN, rule_id=None, name=None))
        with self.assertRaises(TypeError):
            RoutingRule(DomainCondition("example.test"), RoutingAction.VPN, True, False, ID_A)

    def test_name_accepts_printable_unicode_within_the_limit(self):
        self.assertEqual(MAX_RULE_NAME_LENGTH, 64)
        for name in (
            "a", "Рабочий сервис напрямую", "example.org → VPN", "x" * MAX_RULE_NAME_LENGTH,
            "😀" * MAX_RULE_NAME_LENGTH, "a  b", "Zoë / résumé #1", "名前", "é" + "́",
        ):
            self.assertTrue(valid_rule_name(name), name)
            rule = RoutingRule(self.named.condition, RoutingAction.VPN, name=name)
            self.assertEqual(rule.name, name)
            self.assertLessEqual(len(name.encode("utf-8")), 4 * MAX_RULE_NAME_LENGTH)

    def test_name_rejects_empty_long_unprintable_and_padded_values(self):
        for name in (
            "", "x" * (MAX_RULE_NAME_LENGTH + 1), "😀" * (MAX_RULE_NAME_LENGTH + 1), " имя", "имя ", "\tимя", "имя\n",
            "a\tb", "a\nb", "a\rb", "a\x00b", "a\x1b[31mb", "a b", "a​b", "a‮b", "a﻿b",
            "a b", " ", " ", "a\udc80b", _Text("имя"), b"name", 1, 1.5, True, [], {}, object(),
        ):
            self.assertFalse(valid_rule_name(name), repr(name))
            self.assert_invalid(RoutingErrorCode.RULE_NAME, RoutingRule, self.named.condition, RoutingAction.VPN, name=name)
            self.assert_invalid(RoutingErrorCode.RULE_NAME, self.policy.with_name, 1, name)

    def test_name_does_not_relax_condition_action_or_state_checks(self):
        self.assert_invalid(RoutingErrorCode.CONDITION, RoutingRule, "example.test", RoutingAction.VPN, name="имя")
        self.assert_invalid(RoutingErrorCode.ACTION, RoutingRule, self.named.condition, "VPN", name="имя")
        self.assert_invalid(RoutingErrorCode.RULE_STATE, RoutingRule, self.named.condition, RoutingAction.VPN, enabled=1, name="имя")
        self.assert_invalid(
            RoutingErrorCode.PROTECTED_RULE, RoutingRule, self.named.condition, RoutingAction.VPN,
            enabled=False, protected=True, name="имя",
        )

    def test_duplicate_names_are_allowed_because_the_identifier_is_the_id(self):
        twin = RoutingRule(IPCondition("203.0.113.0/24"), RoutingAction.VPN, rule_id=ID_FREE, name=self.named.name)
        policy = RoutingPolicy((self.service, self.named, twin), self.final)
        self.assertEqual([rule.name for rule in policy.rules[1:]], [self.named.name, self.named.name])
        renamed = policy.with_name(0, self.named.name)
        self.assertEqual(sum(rule.name == self.named.name for rule in renamed.rules), 3)


class RuleIdValidationTests(RuleIdentityTestCase):
    def test_id_accepts_only_lowercase_canonical_uuid_text(self):
        generated = str(uuid.uuid4())
        for value in (ID_A, generated, "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"):
            self.assertTrue(valid_rule_id(value), value)
            self.assertEqual(RoutingRule(self.plain.condition, RoutingAction.BLOCK, rule_id=value).rule_id, value)
        for value in (
            ID_A.upper(), "{" + ID_A + "}", "urn:uuid:" + ID_A, ID_A.replace("-", ""), ID_A[:-1], ID_A + "0",
            " " + ID_A, ID_A + "\n", "", "0000abcd-0000-4000-8000-0000000000g1", uuid.UUID(ID_A), ID_A.encode("ascii"),
            _Text(ID_A), 1, True, [], object(),
        ):
            self.assertFalse(valid_rule_id(value), repr(value))
            self.assert_invalid(RoutingErrorCode.RULE_ID, RoutingRule, self.plain.condition, RoutingAction.BLOCK, rule_id=value)

    def test_ids_must_be_unique_within_the_policy(self):
        for duplicate in (
            RoutingRule(IPCondition("203.0.113.0/24"), RoutingAction.VPN, rule_id=ID_B),
            RoutingRule(IPCondition("203.0.113.0/24"), RoutingAction.VPN, rule_id=ID_B, enabled=False),
            RoutingRule(IPCondition("203.0.113.0/24"), RoutingAction.VPN, rule_id=ID_A),
            RoutingRule(self.named.condition, self.named.action, rule_id=ID_C, name="другое"),
        ):
            self.assert_invalid(RoutingErrorCode.DUPLICATE_RULE_ID, RoutingPolicy, (*self.policy.rules, duplicate), self.final)
            self.assert_invalid(RoutingErrorCode.DUPLICATE_RULE_ID, self.policy.insert, 4, duplicate)
        # Повтор самого объекта тоже повтор идентификатора.
        self.assert_invalid(RoutingErrorCode.DUPLICATE_RULE_ID, RoutingPolicy, (self.named, self.named), self.final)
        self.assertEqual(self.identities(self.policy), [(ID_A, "Служебное"), (ID_B, "Рабочий сервис"), (None, None), (ID_C, None)])

    def test_rules_without_id_may_repeat_and_mix_with_identified_rules(self):
        anonymous = RoutingRule(IPCondition("203.0.113.0/24"), RoutingAction.VPN)
        policy = RoutingPolicy((self.service, anonymous, anonymous, self.plain, self.named), self.final)
        self.assertEqual(len(policy.rules), 5)
        self.assertEqual(policy.to_diagnostic()["identified_rule_count"], 2)
        self.assertEqual(policy.to_diagnostic()["named_rule_count"], 2)

    def test_index_of_finds_rules_by_id_and_validates_the_format(self):
        self.assertEqual(self.policy.index_of(ID_A), 0)
        self.assertEqual(self.policy.index_of(ID_B), 1)
        self.assertEqual(self.policy.index_of(ID_C), 3)
        self.assertIsNone(self.policy.index_of(ID_FREE))
        for value in (ID_A.upper(), "", None, 1, uuid.UUID(ID_A)):
            self.assert_invalid(RoutingErrorCode.RULE_ID, self.policy.index_of, value)


class IdentityStabilityTests(RuleIdentityTestCase):
    def test_operations_keep_ids_and_names_of_untouched_rules(self):
        inserted = RoutingRule(IPCondition("203.0.113.0/24"), RoutingAction.VPN, rule_id=ID_FREE, name="Новое")
        operations = (
            ("move", self.policy.move(2, 1), [(ID_A, "Служебное"), (None, None), (ID_B, "Рабочий сервис"), (ID_C, None)]),
            ("move back", self.policy.move(1, 3), [(ID_A, "Служебное"), (None, None), (ID_C, None), (ID_B, "Рабочий сервис")]),
            ("disable", self.policy.with_enabled(1, False), self.identities(self.policy)),
            ("enable", self.policy.with_enabled(3, True), self.identities(self.policy)),
            ("final", self.policy.with_final_action(RoutingAction.DIRECT), self.identities(self.policy)),
            ("insert", self.policy.insert(2, inserted), [(ID_A, "Служебное"), (ID_B, "Рабочий сервис"), (ID_FREE, "Новое"), (None, None), (ID_C, None)]),
            ("remove", self.policy.remove(2), [(ID_A, "Служебное"), (ID_B, "Рабочий сервис"), (ID_C, None)]),
            ("rename", self.policy.with_name(2, "Подсеть"), [(ID_A, "Служебное"), (ID_B, "Рабочий сервис"), (None, "Подсеть"), (ID_C, None)]),
        )
        for label, changed, expected in operations:
            with self.subTest(label):
                self.assertEqual(self.identities(changed), expected)
                self.assertEqual(changed.index_of(ID_B), expected.index((ID_B, "Рабочий сервис")))
        self.assertEqual(self.identities(self.policy), [(ID_A, "Служебное"), (ID_B, "Рабочий сервис"), (None, None), (ID_C, None)])

    def test_moved_disabled_and_renamed_rules_keep_their_id(self):
        moved = self.policy.move(1, 2)
        self.assertEqual(moved.index_of(ID_B), 2)
        self.assertIs(moved.rules[2], self.named)
        disabled = self.policy.with_enabled(1, False)
        self.assertEqual((disabled.rules[1].rule_id, disabled.rules[1].name, disabled.rules[1].enabled), (ID_B, "Рабочий сервис", False))
        self.assertIs(disabled.rules[1].condition, self.named.condition)
        restored = disabled.with_enabled(1, True)
        self.assertEqual(restored, self.policy)
        renamed = self.policy.with_name(1, "Переименовано")
        self.assertEqual(renamed.index_of(ID_B), 1)
        self.assertEqual(renamed.with_name(1, "Рабочий сервис"), self.policy)
        chained = self.policy.move(1, 2).with_enabled(2, False).with_final_action(RoutingAction.VPN).with_name(2, "Цепочка")
        self.assertEqual(chained.rules[2].rule_id, ID_B)
        self.assertEqual(chained.rules[2].name, "Цепочка")
        self.assertFalse(chained.rules[2].enabled)
        self.assertIs(chained.rules[2].condition, self.named.condition)

    def test_selection_and_explanation_indexes_refer_to_identified_rules(self):
        selection = self.policy.select_first(lambda condition: MatchResult.MATCH if condition is self.named.condition else MatchResult.NO_MATCH)
        self.assertEqual(selection.index, self.policy.index_of(ID_B))
        self.assertIs(selection.rule, self.named)


class RenameTests(RuleIdentityTestCase):
    def test_rename_returns_new_model_and_changes_only_the_name(self):
        renamed = self.policy.with_name(2, "Подсеть")
        self.assertIsNot(renamed, self.policy)
        self.assertEqual(self.policy.rules[2].name, None)
        self.assertEqual(renamed.rules[2].name, "Подсеть")
        changed = renamed.rules[2]
        self.assertIs(changed.condition, self.plain.condition)
        self.assertIs(changed.action, self.plain.action)
        self.assertIs(changed.enabled, self.plain.enabled)
        self.assertIs(changed.protected, self.plain.protected)
        self.assertIsNone(changed.rule_id)
        self.assertEqual(renamed.rules[:2] + renamed.rules[3:], self.policy.rules[:2] + self.policy.rules[3:])
        self.assertIs(renamed.final_rule, self.policy.final_rule)
        self.assertEqual(renamed.ordered_rules[-1], self.final)
        self.assertEqual(renamed.active_rules, (self.service, self.named, changed, self.final))

    def test_rename_clears_the_name_with_none(self):
        cleared = self.policy.with_name(1, None)
        self.assertIsNone(cleared.rules[1].name)
        self.assertEqual(cleared.rules[1].rule_id, ID_B)
        self.assertEqual(cleared.with_name(1, "Рабочий сервис"), self.policy)

    def test_rename_is_allowed_for_protected_rules_without_touching_protection(self):
        renamed = self.policy.with_name(0, "Локальная сеть")
        self.assertTrue(renamed.rules[0].protected)
        self.assertTrue(renamed.rules[0].enabled)
        self.assertEqual(renamed.rules[0].rule_id, ID_A)
        self.assertEqual(renamed.protected_rule_count, 1)
        self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, renamed.with_enabled, 0, False)
        self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, renamed.remove, 0)
        self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, renamed.move, 0, 1)
        self.assert_invalid(RoutingErrorCode.PROTECTED_ORDER, renamed.insert, 0, self.plain)
        # Переименование не делает служебное правило редактируемым и не снимает защиту.
        self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, RoutingRule, self.service.condition, RoutingAction.DIRECT, protected=True, enabled=False, name="x")

    def test_rename_is_allowed_in_read_only_policy_while_priority_edits_stay_blocked(self):
        unknown = RoutingRule(UnknownCondition(ConditionFamily.DOMAIN, "ext:Custom.dat:unknown"), RoutingAction.VPN, rule_id=ID_FREE)
        policy = RoutingPolicy((self.service, unknown, self.named), self.final)
        self.assertTrue(policy.read_only)
        renamed = policy.with_name(1, "Импортировано как есть").with_name(2, "Сервис")
        self.assertEqual([rule.name for rule in renamed.rules], ["Служебное", "Импортировано как есть", "Сервис"])
        self.assertEqual(renamed.rules[1].condition.reference, "ext:Custom.dat:unknown")
        self.assertTrue(renamed.read_only)
        for function, args in (
            (renamed.insert, (2, self.plain)), (renamed.move, (1, 2)), (renamed.remove, (2,)),
            (renamed.with_enabled, (2, False)), (renamed.with_final_action, (RoutingAction.DIRECT,)),
        ):
            self.assert_invalid(RoutingErrorCode.READ_ONLY, function, *args)

    def test_rename_validates_index_and_leaves_the_model_unchanged_on_failure(self):
        for index in (-1, 4, 5, True, 1.0, "1", None):
            self.assert_invalid(RoutingErrorCode.POSITION, self.policy.with_name, index, "имя")
        self.assert_invalid(RoutingErrorCode.RULE_NAME, self.policy.with_name, 1, "")
        self.assertEqual(self.identities(self.policy), [(ID_A, "Служебное"), (ID_B, "Рабочий сервис"), (None, None), (ID_C, None)])
        self.assert_invalid(RoutingErrorCode.RULE_NAME, replace, self.named, name=" ")
        self.assert_invalid(RoutingErrorCode.RULE_ID, replace, self.named, rule_id=ID_B.upper())


def _part(name, document):
    return ConfigDocument(name, json.dumps(document).encode("utf-8"))


def _artificial_config():
    """Искусственные части с поддержанным финальным правилом; реальные файлы читает адаптер роутера."""
    return XrayConfigSet((
        _part("04_outbounds.json", {"outbounds": [
            {"tag": "proxy-out", "protocol": "trojan"}, {"tag": "direct", "protocol": "freedom"},
        ]}),
        _part("05_routing.json", {"routing": {"rules": [
            {"type": "field", "ruleTag": "named-in-xray", "domain": ["domain:example.test", "full:static.example.test"], "outboundTag": "direct"},
            {"type": "field", "ip": ["198.51.100.0/24"], "outboundTag": "proxy-out"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
        ]}}),
    ))


class ImportWithoutNamesTests(RuleIdentityTestCase):
    def test_import_assigns_neither_names_nor_ids(self):
        for config in (_artificial_config(), snapshot_xray_config()):
            before = [(part.name, part.sha256) for part in config.parts]
            scheme = import_routing_scheme(config)
            rules = [rule for group in scheme.groups for rule in group.rules]
            self.assertTrue(rules)
            self.assertEqual({(rule.rule_id, rule.name) for rule in rules}, {(None, None)})
            if scheme.policy is not None:
                self.assertEqual({(rule.rule_id, rule.name) for rule in scheme.policy.rules}, {(None, None)})
                self.assertEqual(scheme.policy.to_diagnostic()["identified_rule_count"], 0)
                self.assertEqual(scheme.policy.to_diagnostic()["named_rule_count"], 0)
            validate_routing_scheme(scheme)
            self.assertEqual([(part.name, part.sha256) for part in config.parts], before)
        scheme = import_routing_scheme(_artificial_config())
        self.assertIsNotNone(scheme.policy)
        self.assertTrue(scheme.groups[0].has_rule_tag)
        self.assertNotIn("named-in-xray", json.dumps(scheme.to_diagnostic()))

    def test_scheme_whose_policy_carries_identity_is_rejected_by_revalidation(self):
        scheme = import_routing_scheme(_artificial_config())
        for index, changes in ((0, {"rule_id": ID_A}), (2, {"name": "Подсеть"})):
            rules = list(scheme.policy.rules)
            rules[index] = replace(rules[index], **changes)
            # Конструктор схемы повторяет ту же проверку, что validate_routing_scheme.
            with self.assertRaises(RoutingImportError) as raised:
                replace(scheme, policy=RoutingPolicy(tuple(rules), scheme.policy.final_rule))
            self.assertIs(raised.exception.code, RoutingImportErrorCode.SCHEME)
            self.assertIsNone(raised.exception.__context__)

    def test_revalidation_rebuilds_rules_and_rejects_corrupted_identity_fields(self):
        scheme = import_routing_scheme(_artificial_config())
        for field_name, value in (("name", " "), ("name", "x" * (MAX_RULE_NAME_LENGTH + 1)), ("rule_id", ID_A.upper()), ("rule_id", 1)):
            rule = scheme.policy.rules[0]
            object.__setattr__(rule, field_name, value)
            try:
                with self.assertRaises(RoutingImportError) as raised:
                    validate_routing_scheme(scheme)
                self.assertIs(raised.exception.code, RoutingImportErrorCode.SCHEME)
                self.assertIsNone(raised.exception.__context__)
            finally:
                object.__setattr__(rule, field_name, None)
        validate_routing_scheme(scheme)


class IdentityPrivacyTests(RuleIdentityTestCase):
    def test_name_is_hidden_in_repr_diagnostics_and_logs_while_id_is_shown(self):
        rule = RoutingRule(DomainCondition("example.test"), RoutingAction.VPN, rule_id=ID_B, name=NAME_MARKER)
        policy = RoutingPolicy((self.service, rule), self.final)
        stream = io.StringIO()
        logger = logging.Logger("routing-identity-test")
        logger.addHandler(logging.StreamHandler(stream))
        for model in (rule, policy, policy.with_name(1, NAME_MARKER + "2"), policy.select_first(lambda _: MatchResult.NO_MATCH)):
            logger.warning("%s / %r / %s", model, model, json.dumps(model.to_diagnostic(), ensure_ascii=False))
        output = stream.getvalue()
        self.assertNotIn(NAME_MARKER, output)
        self.assertNotIn("Служебное", output)
        self.assertIn(ID_B, output)
        self.assertEqual(rule.to_diagnostic(), {
            "condition_type": "DomainCondition", "action": "VPN", "read_only": False, "enabled": True, "protected": False,
            "has_id": True, "rule_id": ID_B, "has_name": True, "name_length": len(NAME_MARKER), "parameters": "<скрыто>",
        })
        self.assertEqual(self.plain.to_diagnostic()["has_id"], False)
        self.assertEqual(self.plain.to_diagnostic()["rule_id"], None)
        self.assertEqual(self.plain.to_diagnostic()["has_name"], False)
        self.assertEqual(self.plain.to_diagnostic()["name_length"], None)
        self.assertEqual(policy.to_diagnostic(), {
            "rule_count": 2, "active_rule_count": 2, "protected_rule_count": 1,
            "identified_rule_count": 2, "named_rule_count": 2, "final_action": "BLOCK", "read_only": False,
        })

    def test_name_length_counts_code_points_not_bytes(self):
        rule = RoutingRule(self.plain.condition, RoutingAction.BLOCK, name="😀" * 3 + "é" + "́")
        self.assertEqual(rule.to_diagnostic()["name_length"], 5)

    def test_validation_errors_do_not_include_the_name_or_the_id(self):
        cases = (
            (RoutingRule, (self.plain.condition, RoutingAction.BLOCK), {"name": NAME_MARKER + "\n"}, RoutingErrorCode.RULE_NAME),
            (RoutingRule, (self.plain.condition, RoutingAction.BLOCK), {"name": " " + NAME_MARKER}, RoutingErrorCode.RULE_NAME),
            (RoutingRule, (self.plain.condition, RoutingAction.BLOCK), {"rule_id": NAME_MARKER}, RoutingErrorCode.RULE_ID),
            (self.policy.with_name, (1, NAME_MARKER + "\x00"), {}, RoutingErrorCode.RULE_NAME),
            (self.policy.index_of, (NAME_MARKER,), {}, RoutingErrorCode.RULE_ID),
            (RoutingPolicy, ((self.named, replace(self.plain, rule_id=ID_B, name=NAME_MARKER)), self.final), {}, RoutingErrorCode.DUPLICATE_RULE_ID),
        )
        for function, args, kwargs, code in cases:
            error = self.assert_invalid(code, function, *args, **kwargs)
            rendered = "".join(traceback.format_exception(error)) + str(error) + repr(error) + repr(vars(error))
            self.assertNotIn(NAME_MARKER, rendered)
            self.assertNotIn(ID_B, rendered)
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)

    def test_identity_operations_have_no_io_or_terminal_output(self):
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
            policy = self.policy.with_name(2, "Подсеть").move(2, 1).with_enabled(3, True)
            self.assertEqual(policy.index_of(ID_C), 3)
            self.assertEqual(policy.to_diagnostic()["named_rule_count"], 3)
            self.assertFalse(valid_rule_name(" "))
            self.assertTrue(valid_rule_id(ID_FREE))
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
