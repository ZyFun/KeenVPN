"""Проверки приоритетов с управляемым источником совпадений, без роутера."""

import builtins
import contextlib
from dataclasses import FrozenInstanceError
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


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.routing import (
    ConditionFamily, DomainCondition, GeoDatabase, GeoDatabaseKind,
    GeoIPCondition, GeoSiteCondition, IPCondition, RoutingAction,
    RoutingErrorCode, RoutingRule, RoutingValidationError, UnknownCondition,
)
from keenvpn.domain.routing_policy import (
    FinalRoutingRule, MatchResult, RoutingPolicy, RoutingSelection,
)


class RoutingPolicyTests(unittest.TestCase):
    def setUp(self):
        self.domain = RoutingRule(DomainCondition("example.test"), RoutingAction.VPN)
        self.ip = RoutingRule(IPCondition("192.0.2.0/24"), RoutingAction.BLOCK)
        self.geoip = RoutingRule(
            GeoIPCondition(GeoDatabase(GeoDatabaseKind.GEOIP, "ip-test"), "ru"),
            RoutingAction.DIRECT,
        )
        self.geosite = RoutingRule(
            GeoSiteCondition(GeoDatabase(GeoDatabaseKind.GEOSITE, "site-test"), "test"),
            RoutingAction.VPN,
        )
        self.final = FinalRoutingRule(RoutingAction.BLOCK)
        self.policy = RoutingPolicy((self.geoip, self.ip, self.domain), self.final)

    def assert_invalid(self, code, function, *args):
        with self.assertRaises(RoutingValidationError) as raised:
            function(*args)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_explicit_final_action_is_required_and_is_not_defaulted(self):
        for action in RoutingAction:
            policy = RoutingPolicy((), FinalRoutingRule(action))
            matcher = Mock(side_effect=AssertionError("Финальное правило не имеет условия"))
            selected = policy.select_first(matcher)
            self.assertEqual(selected.index, 0)
            self.assertIs(selected.rule, policy.final_rule)
            self.assertIs(selected.action, action)
            self.assertTrue(selected.is_final)
            matcher.assert_not_called()
        with self.assertRaises(TypeError):
            RoutingPolicy(())
        with self.assertRaises(TypeError):
            FinalRoutingRule()
        for action in (None, "DIRECT", True):
            self.assert_invalid(RoutingErrorCode.ACTION, FinalRoutingRule, action)

    def test_missing_duplicate_or_misplaced_final_rule_is_rejected(self):
        for final in (None, RoutingAction.DIRECT, self.domain, (self.final, self.final)):
            self.assert_invalid(RoutingErrorCode.FINAL_RULE, RoutingPolicy, (), final)
        for rules in ((self.final,), (self.final, self.domain), (self.final, self.final)):
            self.assert_invalid(RoutingErrorCode.RULES, RoutingPolicy, rules, self.final)
        self.assert_invalid(RoutingErrorCode.RULES, self.policy.insert, 0, self.final)
        self.assert_invalid(RoutingErrorCode.RULES, self.policy.insert, 3, self.final)

    def test_rules_are_validated_without_consuming_arbitrary_iterables(self):
        for rules in (None, "rules", {self.domain}, iter((self.domain,)), (None,), ("private",)):
            self.assert_invalid(RoutingErrorCode.RULES, RoutingPolicy, rules, self.final)
        self.assert_invalid(RoutingErrorCode.RULES, self.policy.insert, 0, "private")

    def test_input_order_duplicates_and_list_snapshot_are_preserved(self):
        original = [self.geoip, self.domain, self.domain]
        policy = RoutingPolicy(original, self.final)
        original.clear()
        self.assertEqual(policy.rules, (self.geoip, self.domain, self.domain))
        self.assertEqual(policy.ordered_rules, (*policy.rules, self.final))
        self.assertFalse(policy.read_only)

    def test_all_move_positions_preserve_other_priorities_and_pin_final(self):
        original = self.policy.rules
        for source, target in itertools.product(range(len(original)), repeat=2):
            with self.subTest(source=source, target=target):
                moved = self.policy.move(source, target)
                self.assertIs(moved.rules[target], original[source])
                self.assertEqual(
                    moved.rules[:target] + moved.rules[target + 1:],
                    original[:source] + original[source + 1:],
                )
                self.assertEqual(len(moved.rules), len(original))
                self.assertIs(moved.ordered_rules[-1], self.final)
                self.assertEqual(self.policy.rules, original)

    def test_insert_positions_are_before_rules_or_before_final(self):
        for index in range(4):
            inserted = self.policy.insert(index, self.geosite)
            self.assertIs(inserted.rules[index], self.geosite)
            self.assertEqual(inserted.rules[:index] + inserted.rules[index + 1:], self.policy.rules)
            self.assertIs(inserted.ordered_rules[-1], self.final)
        empty = RoutingPolicy((), self.final)
        self.assertEqual(empty.insert(0, self.domain).ordered_rules, (self.domain, self.final))

    def test_remove_preserves_order_and_can_leave_only_final(self):
        for index in range(3):
            removed = self.policy.remove(index)
            self.assertEqual(removed.rules, self.policy.rules[:index] + self.policy.rules[index + 1:])
            self.assertIs(removed.ordered_rules[-1], self.final)
        empty = RoutingPolicy((self.domain,), self.final).remove(0)
        self.assertEqual(empty.ordered_rules, (self.final,))
        self.assert_invalid(RoutingErrorCode.POSITION, empty.remove, 0)
        self.assert_invalid(RoutingErrorCode.POSITION, empty.move, 0, 0)

    def test_final_cannot_be_moved_removed_or_followed_by_an_insert(self):
        final_index = len(self.policy.rules)
        self.assert_invalid(RoutingErrorCode.POSITION, self.policy.move, final_index, 0)
        self.assert_invalid(RoutingErrorCode.POSITION, self.policy.move, 0, final_index)
        self.assert_invalid(RoutingErrorCode.POSITION, self.policy.remove, final_index)
        self.assert_invalid(RoutingErrorCode.POSITION, self.policy.insert, final_index + 1, self.domain)
        self.assertEqual(self.policy.ordered_rules[-1], self.final)

    def test_negative_boolean_and_noninteger_positions_are_rejected(self):
        for index in (-1, -10, 100, True, False, 0.0, "0", None):
            self.assert_invalid(RoutingErrorCode.POSITION, self.policy.insert, index, self.domain)
            self.assert_invalid(RoutingErrorCode.POSITION, self.policy.remove, index)
            self.assert_invalid(RoutingErrorCode.POSITION, self.policy.move, index, 0)
            self.assert_invalid(RoutingErrorCode.POSITION, self.policy.move, 0, index)

    def test_final_action_changes_only_explicitly_and_keeps_positions(self):
        for action in RoutingAction:
            changed = self.policy.with_final_action(action)
            self.assertEqual(changed.rules, self.policy.rules)
            self.assertIs(changed.final_rule.action, action)
            self.assertEqual(changed.ordered_rules[-1], FinalRoutingRule(action))
        self.assertIs(self.policy.final_rule, self.final)
        for action in (None, "DIRECT", False):
            self.assert_invalid(RoutingErrorCode.ACTION, self.policy.with_final_action, action)

    def test_first_match_depends_on_order_for_every_condition_kind(self):
        # Источник подтверждает совпадение всех условий для одного сценария.
        # Движение домена перед GeoIP должно изменить выбранное действие.
        rules = (self.geoip, self.domain, self.ip, self.geosite)
        for order in itertools.permutations(rules):
            policy = RoutingPolicy(order, self.final)
            matcher = Mock(return_value=MatchResult.MATCH)
            selected = policy.select_first(matcher)
            self.assertIs(selected.rule, order[0])
            self.assertIs(selected.action, order[0].action)
            self.assertEqual(selected.index, 0)
            self.assertFalse(selected.is_final)
            matcher.assert_called_once_with(order[0].condition)
        self.assertIs(self.policy.select_first(lambda _: MatchResult.MATCH).action, RoutingAction.DIRECT)
        moved = self.policy.move(2, 0)
        self.assertIs(moved.select_first(lambda _: MatchResult.MATCH).action, RoutingAction.VPN)

    def test_all_match_combinations_stop_at_first_match_or_unknown(self):
        for results in itertools.product(MatchResult, repeat=3):
            with self.subTest(results=results):
                stop = next((i for i, result in enumerate(results) if result is not MatchResult.NO_MATCH), 3)
                matcher = Mock(side_effect=results)
                if stop < 3 and results[stop] is MatchResult.UNKNOWN:
                    self.assert_invalid(RoutingErrorCode.MATCH_UNKNOWN, self.policy.select_first, matcher)
                else:
                    selected = self.policy.select_first(matcher)
                    self.assertEqual(selected.index, stop)
                    self.assertIs(selected.rule, self.policy.ordered_rules[stop])
                    self.assertEqual(selected.is_final, stop == 3)
                self.assertEqual(matcher.call_count, min(stop + 1, 3))

    def test_final_is_selected_only_after_every_known_nonmatch(self):
        for action in RoutingAction:
            policy = self.policy.with_final_action(action)
            matcher = Mock(return_value=MatchResult.NO_MATCH)
            selected = policy.select_first(matcher)
            self.assertEqual(selected.to_diagnostic(), {"index": 3, "action": action.value, "is_final": True})
            self.assertEqual([call.args[0] for call in matcher.call_args_list], [r.condition for r in policy.rules])

    def test_invalid_match_results_are_not_coerced_to_truth_values(self):
        for result in (None, True, False, 0, 1, "match", [], object()):
            matcher = Mock(return_value=result)
            self.assert_invalid(RoutingErrorCode.MATCH_RESULT, self.policy.select_first, matcher)
            self.assertEqual(matcher.call_count, 1)

    def test_source_errors_stop_selection_without_final_fallback(self):
        for action in RoutingAction:
            policy = self.policy.with_final_action(action)
            matcher = Mock(side_effect=OSError("Синтетический отказ источника"))
            self.assert_invalid(RoutingErrorCode.MATCHER, policy.select_first, matcher)
            self.assertEqual(matcher.call_count, 1)
        for matcher in (None, {}, MatchResult.MATCH):
            self.assert_invalid(RoutingErrorCode.MATCHER, self.policy.select_first, matcher)
        with self.assertRaises(KeyboardInterrupt):
            self.policy.select_first(Mock(side_effect=KeyboardInterrupt))

    def test_unknown_imported_rule_stops_only_when_reached(self):
        unknown = RoutingRule(UnknownCondition(ConditionFamily.DOMAIN, "ext:Test.dat:unknown"), RoutingAction.VPN)
        for rules in ((unknown, self.domain), (self.domain, unknown)):
            policy = RoutingPolicy(rules, self.final)
            matcher = Mock(return_value=MatchResult.NO_MATCH)
            self.assert_invalid(RoutingErrorCode.MATCH_UNKNOWN, policy.select_first, matcher)
            self.assertEqual(matcher.call_count, rules.index(unknown))
            self.assertIs(policy.rules[rules.index(unknown)], unknown)
        policy = RoutingPolicy((self.domain, unknown), self.final)
        matcher = Mock(return_value=MatchResult.MATCH)
        self.assertIs(policy.select_first(matcher).rule, self.domain)
        matcher.assert_called_once_with(self.domain.condition)

    def test_unknown_import_freezes_priority_edits_without_discarding_data(self):
        unknown = RoutingRule(UnknownCondition(ConditionFamily.IP, "  ext:Custom.dat:unknown\n"), RoutingAction.DIRECT)
        policy = RoutingPolicy((self.domain, unknown), self.final)
        self.assertTrue(policy.read_only)
        for function, args in (
            (policy.insert, (0, self.ip)), (policy.move, (0, 1)),
            (policy.move, (1, 0)), (policy.remove, (0,)), (policy.remove, (1,)),
            (policy.with_final_action, (RoutingAction.DIRECT,)),
        ):
            self.assert_invalid(RoutingErrorCode.READ_ONLY, function, *args)
        self.assertEqual(policy.ordered_rules, (self.domain, unknown, self.final))
        self.assertEqual(unknown.condition.reference, "  ext:Custom.dat:unknown\n")

    def test_models_are_immutable_and_selection_validates_its_shape(self):
        selected = self.policy.select_first(lambda _: MatchResult.MATCH)
        for model, field, value in (
            (self.policy, "rules", ()), (self.policy, "final_rule", None),
            (self.final, "action", RoutingAction.DIRECT), (selected, "index", 100),
            (selected, "rule", self.ip),
        ):
            with self.assertRaises(FrozenInstanceError):
                setattr(model, field, value)
        for index in (-1, True, "0"):
            self.assert_invalid(RoutingErrorCode.POSITION, RoutingSelection, index, self.final)
        self.assert_invalid(RoutingErrorCode.RULES, RoutingSelection, 0, None)

    def test_output_does_not_disclose_conditions_or_matcher_error(self):
        marker = "SYNTHETIC_" + "PRIVATE_VALUE"
        rule = RoutingRule(GeoSiteCondition(GeoDatabase(GeoDatabaseKind.GEOSITE, marker), marker), RoutingAction.VPN)
        policy = RoutingPolicy((rule,), self.final)
        selected = policy.select_first(lambda _: MatchResult.MATCH)
        stream = io.StringIO()
        logger = logging.Logger("routing-policy-test")
        logger.addHandler(logging.StreamHandler(stream))
        for model in (policy, selected):
            logger.warning("%s %r %s", model, model, json.dumps(model.to_diagnostic()))
        matcher = Mock(side_effect=ValueError(marker))
        error = self.assert_invalid(RoutingErrorCode.MATCHER, policy.select_first, matcher)
        logger.warning("%s %r %s", error, error, traceback.format_exception(error))
        self.assertNotIn(marker, stream.getvalue())
        self.assertEqual(vars(error), {"code": RoutingErrorCode.MATCHER})

    def test_validation_inside_external_exception_hides_context_text(self):
        marker = "SYNTHETIC_" + "EXTERNAL_CONTEXT"
        try:
            raise ValueError(marker)
        except ValueError:
            for function, args in (
                (RoutingPolicy, (None, self.final)), (FinalRoutingRule, (marker,)),
                (self.policy.move, (-1, 0)), (self.policy.select_first, (None,)),
                (self.policy.select_first, (lambda _: MatchResult.UNKNOWN,)),
            ):
                with self.assertRaises(RoutingValidationError) as raised:
                    function(*args)
                self.assertNotIn(marker, "".join(traceback.format_exception(raised.exception)))

    def test_operations_with_pure_matcher_have_no_io_or_terminal_output(self):
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
            policy = RoutingPolicy(self.policy.rules, self.final)
            policy = policy.insert(0, self.geosite).move(0, 3).remove(1)
            policy = policy.with_final_action(RoutingAction.VPN)
            selection = policy.select_first(lambda _: MatchResult.NO_MATCH)
            self.assertTrue(selection.is_final)
            policy.to_diagnostic()
            selection.to_diagnostic()
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
