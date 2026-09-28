"""Защита служебного блока и отключение правил в памяти, без Xray и роутера."""

import builtins
import contextlib
from dataclasses import FrozenInstanceError
import io
import itertools
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import traceback
import unittest
from unittest.mock import Mock, patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.routing import (
    ConditionFamily, DomainCondition, GeoDatabase, GeoDatabaseKind,
    GeoSiteCondition, IPCondition, RoutingAction, RoutingErrorCode,
    RoutingRule, RoutingValidationError, UnknownCondition,
)
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy


class RoutingRuleStateTests(unittest.TestCase):
    def setUp(self):
        self.service = RoutingRule(
            IPCondition("192.0.2.0/24"), RoutingAction.DIRECT, protected=True,
        )
        self.other_service = RoutingRule(
            DomainCondition("service.example.test"), RoutingAction.VPN, protected=True,
        )
        self.user = RoutingRule(DomainCondition("example.test"), RoutingAction.BLOCK)
        self.disabled = RoutingRule(
            IPCondition("2001:db8::/32"), RoutingAction.VPN, enabled=False,
        )
        self.final = FinalRoutingRule(RoutingAction.BLOCK)
        self.policy = RoutingPolicy(
            (self.service, self.other_service, self.user, self.disabled), self.final,
        )

    def assert_invalid(self, code, function, *args, **kwargs):
        with self.assertRaises(RoutingValidationError) as raised:
            function(*args, **kwargs)
        self.assertIs(raised.exception.code, code)
        return raised.exception

    def test_existing_rules_are_enabled_and_unprotected_by_default(self):
        self.assertTrue(self.user.enabled)
        self.assertFalse(self.user.protected)
        for action in RoutingAction:
            for enabled in (True, False):
                rule = RoutingRule(self.user.condition, action, enabled=enabled)
                self.assertIs(rule.enabled, enabled)
                self.assertIs(rule.action, action)
                self.assertIs(rule.condition, self.user.condition)

    def test_flags_require_actual_booleans_without_coercion(self):
        class UnexpectedTruthValue:
            def __bool__(self):
                raise AssertionError("Нельзя вычислять истинность произвольного объекта")

        for value in (None, 0, 1, "false", "true", [], {}, UnexpectedTruthValue()):
            for name in ("enabled", "protected"):
                self.assert_invalid(
                    RoutingErrorCode.RULE_STATE, RoutingRule,
                    self.user.condition, self.user.action, **{name: value},
                )
            self.assert_invalid(RoutingErrorCode.RULE_STATE, self.policy.with_enabled, 2, value)
        with self.assertRaises(TypeError):
            RoutingRule(self.user.condition, self.user.action, False)

    def test_disabled_rule_still_validates_condition_and_action(self):
        self.assert_invalid(
            RoutingErrorCode.CONDITION, RoutingRule, "private", RoutingAction.VPN, enabled=False,
        )
        self.assert_invalid(
            RoutingErrorCode.ACTION, RoutingRule, self.user.condition, "VPN", enabled=False,
        )

    def test_service_cannot_be_created_disabled(self):
        for action in RoutingAction:
            self.assert_invalid(
                RoutingErrorCode.PROTECTED_RULE, RoutingRule,
                self.service.condition, action, enabled=False, protected=True,
            )

    def test_state_is_immutable_and_included_in_equality(self):
        disabled = RoutingRule(self.user.condition, self.user.action, enabled=False)
        protected = RoutingRule(self.user.condition, self.user.action, protected=True)
        self.assertNotEqual(self.user, disabled)
        self.assertNotEqual(self.user, protected)
        for name, value in (("enabled", False), ("protected", True)):
            with self.assertRaises(FrozenInstanceError):
                setattr(self.user, name, value)

    def test_constructor_requires_service_prefix_without_sorting(self):
        for flags in itertools.product((False, True), repeat=4):
            rules = [RoutingRule(self.user.condition, self.user.action, protected=f) for f in flags]
            original = tuple(rules)
            prefix_length = next((i for i, flag in enumerate(flags) if not flag), len(flags))
            if any(flags[prefix_length:]):
                self.assert_invalid(RoutingErrorCode.PROTECTED_ORDER, RoutingPolicy, rules, self.final)
            else:
                policy = RoutingPolicy(rules, self.final)
                self.assertEqual(policy.rules, original)
                self.assertEqual(policy.protected_rule_count, prefix_length)
                rules.clear()
                self.assertEqual(policy.rules, original)
                continue
            self.assertEqual(tuple(rules), original)
        self.assert_invalid(
            RoutingErrorCode.PROTECTED_ORDER, RoutingPolicy, (self.disabled, self.service), self.final,
        )

    def test_editor_cannot_remove_toggle_or_move_service_even_to_same_position(self):
        for index in (0, 1):
            self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, self.policy.remove, index)
            for enabled in (False, True):
                self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, self.policy.with_enabled, index, enabled)
            for target in range(4):
                self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, self.policy.move, index, target)
        self.assertEqual(self.policy.rules, (self.service, self.other_service, self.user, self.disabled))

    def test_user_cannot_be_inserted_or_moved_above_service(self):
        for index in (0, 1):
            for rule in (self.user, self.disabled):
                self.assert_invalid(RoutingErrorCode.PROTECTED_ORDER, self.policy.insert, index, rule)
            for source in (2, 3):
                self.assert_invalid(RoutingErrorCode.PROTECTED_ORDER, self.policy.move, source, index)

    def test_editor_cannot_create_service_rule(self):
        for index in range(5):
            self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, self.policy.insert, index, self.service)
        empty = RoutingPolicy((), self.final)
        self.assert_invalid(RoutingErrorCode.PROTECTED_RULE, empty.insert, 0, self.service)

    def test_user_edits_preserve_service_objects_and_order(self):
        for index in (2, 3, 4):
            inserted = self.policy.insert(index, self.user)
            self.assertIs(inserted.rules[index], self.user)
            self.assertEqual(inserted.rules[:index] + inserted.rules[index + 1:], self.policy.rules)
        for source, target in itertools.product((2, 3), repeat=2):
            changed = self.policy.move(source, target)
            self.assertIs(changed.rules[target], self.policy.rules[source])
            self.assertEqual(changed.rules[:2], self.policy.rules[:2])
            self.assertIs(changed.rules[0], self.service)
            self.assertIs(changed.rules[1], self.other_service)
            self.assertIs(changed.final_rule, self.final)
        for index in (2, 3):
            changed = self.policy.remove(index)
            self.assertEqual(changed.rules, self.policy.rules[:index] + self.policy.rules[index + 1:])
        for action in RoutingAction:
            changed = self.policy.with_final_action(action)
            self.assertEqual(changed.rules, self.policy.rules)
            self.assertIs(changed.final_rule.action, action)

    def test_service_only_policy_can_add_users_after_prefix(self):
        policy = RoutingPolicy((self.service, self.other_service), self.final)
        self.assertFalse(policy.read_only)
        self.assertEqual(policy.active_rules, policy.ordered_rules)
        changed = policy.insert(2, self.user).with_enabled(2, False)
        self.assertEqual(changed.active_rules, policy.ordered_rules)
        self.assertEqual(changed.remove(2), policy)

    def test_toggle_preserves_condition_action_and_stored_position(self):
        original = self.policy.rules
        changed = self.policy.with_enabled(2, False)
        self.assertEqual(changed.active_rules, (self.service, self.other_service, self.final))
        self.assertEqual(len(changed.rules), len(original))
        self.assertIs(changed.rules[2].condition, self.user.condition)
        self.assertIs(changed.rules[2].action, self.user.action)
        self.assertEqual(changed.rules[:2], original[:2])
        self.assertIs(changed.rules[3], self.disabled)
        self.assertEqual(changed.with_enabled(2, True), self.policy)
        self.assertEqual(changed.with_enabled(2, False), changed)
        self.assertEqual(self.policy.rules, original)
        self.assertTrue(self.policy.rules[2].enabled)

    def test_disabled_rule_can_move_then_reenable_at_explicit_new_position(self):
        changed = self.policy.move(3, 2)
        self.assertIs(changed.rules[2], self.disabled)
        self.assertNotIn(self.disabled, changed.active_rules)
        enabled = changed.with_enabled(2, True)
        self.assertIs(enabled.rules[2].condition, self.disabled.condition)
        self.assertTrue(enabled.rules[2].enabled)
        self.assertEqual(enabled.active_rules, enabled.ordered_rules)
        self.assertIs(enabled.rules[3], self.user)

    def test_duplicate_conditions_keep_independent_state_and_order(self):
        policy = RoutingPolicy((self.user, self.user), self.final)
        changed = policy.with_enabled(0, False)
        self.assertFalse(changed.rules[0].enabled)
        self.assertIs(changed.rules[1], self.user)
        selected = changed.select_first(lambda _: MatchResult.MATCH)
        self.assertEqual(selected.index, 1)
        self.assertIs(selected.rule, self.user)
        self.assertEqual(changed.with_enabled(0, True), policy)

    def test_all_enable_combinations_filter_active_list_and_matcher_calls(self):
        conditions = (DomainCondition("a.test"), IPCondition("198.51.100.1"), DomainCondition("b.test"))
        for flags in itertools.product((False, True), repeat=3):
            rules = tuple(RoutingRule(c, RoutingAction.VPN, enabled=f) for c, f in zip(conditions, flags))
            policy = RoutingPolicy((self.service, *rules), self.final)
            active = tuple(rule for rule in policy.rules if rule.enabled)
            self.assertEqual(policy.active_rules, (*active, self.final))
            self.assertEqual(policy.ordered_rules, (*policy.rules, self.final))
            matcher = Mock(return_value=MatchResult.NO_MATCH)
            selected = policy.select_first(matcher)
            self.assertEqual([call.args[0] for call in matcher.call_args_list], [r.condition for r in active])
            self.assertTrue(selected.is_final)
            self.assertEqual(selected.index, len(policy.rules))
            self.assertIs(selected.rule, self.final)

    def test_service_first_match_prevents_user_override(self):
        matcher = Mock(return_value=MatchResult.MATCH)
        selected = self.policy.select_first(matcher)
        self.assertIs(selected.rule, self.service)
        self.assertEqual(selected.index, 0)
        matcher.assert_called_once_with(self.service.condition)

    def test_disabled_is_skipped_before_first_match_with_stored_index(self):
        policy = RoutingPolicy((self.disabled, self.user, self.service_as_user()), self.final)
        matcher = Mock(return_value=MatchResult.MATCH)
        selected = policy.select_first(matcher)
        self.assertIs(selected.rule, self.user)
        self.assertEqual(selected.index, 1)
        matcher.assert_called_once_with(self.user.condition)

    def service_as_user(self):
        return RoutingRule(self.service.condition, self.service.action)

    def test_all_disabled_rules_choose_explicit_final_without_source_calls(self):
        for action in RoutingAction:
            policy = RoutingPolicy((self.disabled, self.disabled), FinalRoutingRule(action))
            matcher = Mock(side_effect=AssertionError("Отключённое условие нельзя вычислять"))
            selected = policy.select_first(matcher)
            self.assertEqual(policy.active_rules, (policy.final_rule,))
            self.assertEqual(selected.index, 2)
            self.assertIs(selected.action, action)
            matcher.assert_not_called()

    def test_unknown_disabled_is_preserved_but_never_evaluated(self):
        original = "  ext:Custom-test.dat:Unknown@attribute\n"
        unknown = RoutingRule(UnknownCondition(ConditionFamily.DOMAIN, original), RoutingAction.VPN, enabled=False)
        policy = RoutingPolicy((unknown, self.user), self.final)
        self.assertTrue(policy.read_only)
        self.assertEqual(policy.active_rules, (self.user, self.final))
        self.assertEqual(policy.ordered_rules, (unknown, self.user, self.final))
        self.assertEqual(unknown.condition.reference, original)
        matcher = Mock(return_value=MatchResult.MATCH)
        self.assertIs(policy.select_first(matcher).rule, self.user)
        matcher.assert_called_once_with(self.user.condition)
        for function, args in (
            (policy.with_enabled, (0, True)), (policy.with_enabled, (1, False)),
            (policy.insert, (0, self.disabled)), (policy.move, (1, 0)),
            (policy.remove, (0,)), (policy.with_final_action, (RoutingAction.DIRECT,)),
        ):
            self.assert_invalid(RoutingErrorCode.READ_ONLY, function, *args)

    def test_unknown_enabled_is_not_silently_filtered_or_replaced_by_final(self):
        unknown = RoutingRule(UnknownCondition(ConditionFamily.IP, "ext:Test.dat:unknown"), RoutingAction.VPN)
        policy = RoutingPolicy((self.disabled, unknown), self.final)
        self.assertEqual(policy.active_rules, (unknown, self.final))
        matcher = Mock(return_value=MatchResult.MATCH)
        self.assert_invalid(RoutingErrorCode.MATCH_UNKNOWN, policy.select_first, matcher)
        matcher.assert_not_called()

    def test_skipping_disabled_does_not_hide_failure_of_next_enabled_rule(self):
        policy = RoutingPolicy((self.disabled, self.user), self.final)
        for result, code in ((MatchResult.UNKNOWN, RoutingErrorCode.MATCH_UNKNOWN), (True, RoutingErrorCode.MATCH_RESULT)):
            matcher = Mock(return_value=result)
            self.assert_invalid(code, policy.select_first, matcher)
            matcher.assert_called_once_with(self.user.condition)
        matcher = Mock(side_effect=OSError("Синтетический отказ"))
        self.assert_invalid(RoutingErrorCode.MATCHER, policy.select_first, matcher)
        matcher.assert_called_once_with(self.user.condition)

    def test_toggle_validates_indices_and_cannot_disable_final(self):
        for index in (-1, True, False, 2.0, "2", None, len(self.policy.rules), 100):
            self.assert_invalid(RoutingErrorCode.POSITION, self.policy.with_enabled, index, False)
        empty = RoutingPolicy((), self.final)
        self.assert_invalid(RoutingErrorCode.POSITION, empty.with_enabled, 0, False)
        self.assertEqual(empty.active_rules, (self.final,))

    def test_safe_diagnostics_describe_state_without_values(self):
        marker = "SYNTHETIC_" + "PRIVATE_METADATA"
        condition = GeoSiteCondition(GeoDatabase(GeoDatabaseKind.GEOSITE, marker), marker)
        service = RoutingRule(condition, RoutingAction.VPN, protected=True)
        disabled = RoutingRule(condition, RoutingAction.DIRECT, enabled=False)
        policy = RoutingPolicy((service, disabled), self.final)
        output = io.StringIO()
        for model in (service, disabled, policy):
            print(str(model), repr(model), json.dumps(model.to_diagnostic()), file=output)
        for flag in ("enabled", "protected"):
            error = self.assert_invalid(
                RoutingErrorCode.RULE_STATE, RoutingRule, condition, RoutingAction.VPN, **{flag: marker},
            )
            print(str(error), repr(error), traceback.format_exception(error), file=output)
        self.assertNotIn(marker, output.getvalue())
        self.assertTrue(service.to_diagnostic()["protected"])
        self.assertFalse(disabled.to_diagnostic()["enabled"])
        self.assertEqual(policy.to_diagnostic(), {
            "rule_count": 2, "active_rule_count": 1, "protected_rule_count": 1,
            "final_action": "BLOCK", "read_only": False,
        })

    def test_state_operations_have_no_io_or_terminal_output(self):
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
            rule = RoutingRule(self.disabled.condition, self.disabled.action, enabled=False)
            policy = self.policy.insert(4, rule).with_enabled(2, False).move(4, 2)
            self.assertEqual(policy.active_rules, (self.service, self.other_service, self.final))
            changed = policy.with_enabled(2, True).remove(3)
            self.assertEqual(changed.protected_rule_count, 2)
            self.assertTrue(changed.select_first(lambda _: MatchResult.NO_MATCH).is_final)
            changed.to_diagnostic()
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
