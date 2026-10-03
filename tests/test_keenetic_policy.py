"""Модель политик Keenetic: формат ID, точное сопоставление описаний и блокировка неоднозначности."""

from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.keenetic_policy import (
    KeeneticPolicy, KeeneticPolicyError, KeeneticPolicyErrorCode, KeeneticPolicySet,
    PolicyResolution, PolicyResolutionOutcome, resolve_policy, validate_policy_description,
)
from tests.support.snapshot import snapshot_policies


# Искусственные описания; реальные метки роутера в тесты не копируются.
TARGET = "xkeen"
OTHER = "NoVPN"


def ambiguous_set():
    """Две политики с одинаковым описанием и одна с другим, в порядке источника."""
    return KeeneticPolicySet((
        KeeneticPolicy("Policy1", TARGET), KeeneticPolicy("Policy2", TARGET), KeeneticPolicy("Policy3", OTHER),
    ))


class KeeneticPolicyModelTests(unittest.TestCase):
    def assert_error(self, code, callable_, *args, **kwargs):
        with self.assertRaises(KeeneticPolicyError) as caught:
            callable_(*args, **kwargs)
        self.assertIs(caught.exception.code, code)
        return caught.exception

    def test_policy_id_accepts_router_identifiers_and_rejects_free_text(self):
        for policy_id in ("Policy0", "Policy10", "KeenVPN47_260918", "a", "x.y-z_1", "P" * 64):
            with self.subTest(policy_id=policy_id):
                self.assertEqual(KeeneticPolicy(policy_id).policy_id, policy_id)
        for policy_id in (
            "", " Policy1", "Policy 1", "-Policy", ".x", "_x", "Политика", "Policy/1", "Policy\n1",
            "P" * 65, None, 1, True, b"Policy1",
        ):
            with self.subTest(policy_id=policy_id):
                self.assert_error(KeeneticPolicyErrorCode.POLICY_ID, KeeneticPolicy, policy_id)

    def test_description_is_optional_text_and_hidden_in_repr(self):
        for description in (None, TARGET, "Без VPN", "", "Policy 2 (дом)"):
            with self.subTest(description=description):
                policy = KeeneticPolicy("Policy2", description)
                self.assertEqual(policy.description, description)
                self.assertEqual(repr(policy), "KeeneticPolicy(<скрыто>)")
        for description in (1, b"xkeen", ["xkeen"]):
            with self.subTest(description=description):
                self.assert_error(KeeneticPolicyErrorCode.DESCRIPTION, KeeneticPolicy, "Policy2", description)
        policy = KeeneticPolicy("Policy2", TARGET)
        with self.assertRaises(FrozenInstanceError):
            policy.description = OTHER

    def test_policy_set_keeps_source_order_and_rejects_duplicates_and_foreign_items(self):
        policies = KeeneticPolicySet([KeeneticPolicy("Policy2", TARGET), KeeneticPolicy("Policy0", OTHER)])
        self.assertIsInstance(policies.policies, tuple)
        self.assertEqual(policies.policy_ids, ("Policy2", "Policy0"))
        self.assertEqual(len(policies), 2)
        self.assertEqual(repr(policies), "KeeneticPolicySet(policies=2)")
        self.assertEqual(len(KeeneticPolicySet(())), 0)

        class DerivedPolicy(KeeneticPolicy):
            pass

        self.assert_error(
            KeeneticPolicyErrorCode.DUPLICATE_POLICY_ID, KeeneticPolicySet,
            (KeeneticPolicy("Policy2", TARGET), KeeneticPolicy("Policy2", OTHER)),
        )
        for item in ({"policy_id": "Policy2"}, "Policy2", None, DerivedPolicy("Policy2", TARGET)):
            with self.subTest(item=type(item).__name__):
                self.assert_error(KeeneticPolicyErrorCode.POLICY, KeeneticPolicySet, (item,))
        for policies in (None, "Policy2", {KeeneticPolicy("Policy2")}, KeeneticPolicy("Policy2")):
            with self.subTest(policies=type(policies).__name__):
                self.assert_error(KeeneticPolicyErrorCode.POLICIES, KeeneticPolicySet, policies)

    def test_description_validation_boundaries(self):
        for description in ("x", "x" * 256, "Без VPN", "👨‍💻 Работа", "\U0002ebf0", "a b"):
            with self.subTest(description=description):
                self.assertIsNone(validate_policy_description(description))
        for description in ("", "   ", "x" * 257, "a\x00b", "a\tb", "a b", "a b", "\ud800", None, 1, b"x"):
            with self.subTest(description=description):
                self.assert_error(KeeneticPolicyErrorCode.DESCRIPTION, validate_policy_description, description)

    def test_errors_are_detached_from_active_exception_and_keep_static_text(self):
        try:
            raise ValueError("private-context-" + TARGET)
        except ValueError:
            error = self.assert_error(KeeneticPolicyErrorCode.POLICY_ID, KeeneticPolicy, "bad id " + TARGET)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn(TARGET, str(error))
        self.assertEqual(str(error), "Идентификатор политики имеет недопустимый формат.")


class ResolvePolicyTests(unittest.TestCase):
    def assert_error(self, code, **kwargs):
        with self.assertRaises(KeeneticPolicyError) as caught:
            resolve_policy(**kwargs)
        self.assertIs(caught.exception.code, code)
        return caught.exception

    def test_single_match_in_snapshot_resolves_dynamically(self):
        policies = snapshot_policies()
        self.assertEqual(policies.policy_ids, ("Policy10", "Policy20", "Policy30"))
        for description, expected in (("fixture-policy-3", "Policy30"), ("fixture-policy-1", "Policy10")):
            with self.subTest(description=description):
                resolution = resolve_policy(policies, description)
                self.assertIs(resolution.outcome, PolicyResolutionOutcome.RESOLVED)
                self.assertTrue(resolution.resolved)
                self.assertEqual(resolution.policy_id, expected)
                self.assertEqual(resolution.candidates, (expected,))
                self.assertEqual(resolution.policy_count, 3)
                self.assertFalse(resolution.selected_by_user)
                self.assertEqual(resolution.to_diagnostic(), {
                    "outcome": "resolved", "policy_id": expected, "candidates": [expected],
                    "policy_count": 3, "selected_by_user": False,
                })

    def test_missing_policy_is_reported_without_default(self):
        for policies, count in ((snapshot_policies(), 3), (KeeneticPolicySet(()), 0)):
            with self.subTest(count=count):
                resolution = resolve_policy(policies, TARGET)
                self.assertIs(resolution.outcome, PolicyResolutionOutcome.MISSING)
                self.assertFalse(resolution.resolved)
                self.assertIsNone(resolution.policy_id)
                self.assertEqual(resolution.candidates, ())
                self.assertEqual(resolution.policy_count, count)
                self.assertEqual(repr(resolution), "PolicyResolution(outcome=missing, candidates=0)")

    def test_matching_is_exact_without_case_whitespace_or_unicode_normalization(self):
        policies = KeeneticPolicySet((
            KeeneticPolicy("Policy1", TARGET), KeeneticPolicy("Policy2", "Café"), KeeneticPolicy("Policy3", None),
        ))
        for description in ("XKeen", "xkeen ", " xkeen", "Café", "cafe"):
            with self.subTest(description=description):
                resolution = resolve_policy(policies, description)
                self.assertIs(resolution.outcome, PolicyResolutionOutcome.MISSING)
                self.assertEqual(resolution.candidates, ())
        self.assertEqual(resolve_policy(policies, "Café").policy_id, "Policy2")

    def test_ambiguous_descriptions_block_without_choosing_first(self):
        resolution = resolve_policy(ambiguous_set(), TARGET)
        self.assertIs(resolution.outcome, PolicyResolutionOutcome.AMBIGUOUS)
        self.assertFalse(resolution.resolved)
        self.assertIsNone(resolution.policy_id)
        self.assertEqual(resolution.candidates, ("Policy1", "Policy2"))
        self.assertEqual(resolution.policy_count, 3)
        self.assertFalse(resolution.selected_by_user)
        self.assertEqual(repr(resolution), "PolicyResolution(outcome=ambiguous, candidates=2)")
        reversed_set = KeeneticPolicySet(tuple(reversed(ambiguous_set().policies)))
        self.assertEqual(resolve_policy(reversed_set, TARGET).candidates, ("Policy2", "Policy1"))

    def test_explicit_selection_is_accepted_only_from_current_candidates(self):
        policies = ambiguous_set()
        for selected in ("Policy1", "Policy2"):
            with self.subTest(selected=selected):
                resolution = resolve_policy(policies, TARGET, selected_policy_id=selected)
                self.assertIs(resolution.outcome, PolicyResolutionOutcome.RESOLVED)
                self.assertEqual(resolution.policy_id, selected)
                self.assertEqual(resolution.candidates, ("Policy1", "Policy2"))
                self.assertTrue(resolution.selected_by_user)
        for selected in ("Policy3", "Policy9"):
            with self.subTest(selected=selected):
                error = self.assert_error(
                    KeeneticPolicyErrorCode.SELECTION_MISMATCH,
                    policies=policies, description=TARGET, selected_policy_id=selected,
                )
                self.assertNotIn(selected, str(error))
                self.assertNotIn(TARGET, str(error))

    def test_selection_with_single_or_no_candidate(self):
        policies = KeeneticPolicySet((KeeneticPolicy("Policy1", TARGET), KeeneticPolicy("Policy3", OTHER)))
        confirmed = resolve_policy(policies, TARGET, selected_policy_id="Policy1")
        self.assertIs(confirmed.outcome, PolicyResolutionOutcome.RESOLVED)
        self.assertEqual(confirmed.policy_id, "Policy1")
        self.assertTrue(confirmed.selected_by_user)
        self.assert_error(
            KeeneticPolicyErrorCode.SELECTION_MISMATCH,
            policies=policies, description=TARGET, selected_policy_id="Policy3",
        )
        # Политика отсутствует: выбор не рассматривается и ничего не подставляет.
        missing = resolve_policy(policies, "absent", selected_policy_id="Policy3")
        self.assertIs(missing.outcome, PolicyResolutionOutcome.MISSING)
        self.assertIsNone(missing.policy_id)
        self.assertFalse(missing.selected_by_user)

    def test_invalid_arguments_are_rejected_before_matching(self):
        policies = ambiguous_set()
        for description in ("", "   ", "a\x00b", "x" * 257, "a b", None, 1):
            with self.subTest(description=description):
                self.assert_error(KeeneticPolicyErrorCode.DESCRIPTION, policies=policies, description=description)
        for selected in ("", "bad id", "Политика", "-x", 1, True):
            with self.subTest(selected=selected):
                self.assert_error(
                    KeeneticPolicyErrorCode.POLICY_ID,
                    policies=policies, description=TARGET, selected_policy_id=selected,
                )

        class DerivedSet(KeeneticPolicySet):
            pass

        for candidate in (None, policies.policies, list(policies.policies), DerivedSet(policies.policies)):
            with self.subTest(policies=type(candidate).__name__):
                self.assert_error(KeeneticPolicyErrorCode.POLICIES, policies=candidate, description=TARGET)

    def test_resolution_invariants_reject_inconsistent_states(self):
        resolved, missing, ambiguous = PolicyResolutionOutcome
        valid = PolicyResolution(resolved, "Policy1", ("Policy1",), 3)
        self.assertTrue(valid.resolved)
        self.assertTrue(PolicyResolution(resolved, "Policy2", ("Policy1", "Policy2"), 3, True).selected_by_user)
        for arguments in (
            (resolved, None, ("Policy1",), 3, False),
            (resolved, "Policy2", ("Policy1",), 3, False),
            (resolved, "Policy1", ("Policy1", "Policy2"), 3, False),
            (missing, None, ("Policy1",), 3, False),
            (missing, "Policy1", (), 3, False),
            (missing, None, (), 3, True),
            (ambiguous, None, ("Policy1",), 3, False),
            (ambiguous, "Policy1", ("Policy1", "Policy2"), 3, False),
            (ambiguous, None, ("Policy1", "Policy2"), 3, True),
            (ambiguous, None, ("Policy1", "Policy1"), 3, False),
            (resolved, "Policy1", ["Policy1"], 3, False),
            (resolved, "Policy1", ("Policy1",), 0, False),
            (resolved, "Policy1", ("Policy1",), True, False),
            (resolved, "Policy1", ("Policy1",), 3, 1),
            ("resolved", "Policy1", ("Policy1",), 3, False),
            (resolved, "bad id", ("bad id",), 3, False),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(KeeneticPolicyError) as caught:
                PolicyResolution(*arguments)
            self.assertIs(caught.exception.code, KeeneticPolicyErrorCode.RESOLUTION)

    def test_resolution_rejects_object_equal_to_candidate_id(self):
        class ForgedId:
            def __eq__(self, other):
                return other == "Policy1"

        with self.assertRaises(KeeneticPolicyError) as caught:
            PolicyResolution(PolicyResolutionOutcome.RESOLVED, ForgedId(), ("Policy1",), 1)
        self.assertIs(caught.exception.code, KeeneticPolicyErrorCode.RESOLUTION)


if __name__ == "__main__":
    unittest.main()
