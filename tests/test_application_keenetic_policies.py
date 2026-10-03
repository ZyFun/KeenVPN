"""Сценарий определения ID политики Keenetic на снимке и управляемом источнике."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.keenetic_policies import ResolveKeeneticPolicy, ResolveKeeneticPolicyHandler
from keenvpn.domain.keenetic_policy import (
    KeeneticPolicy, KeeneticPolicyError, KeeneticPolicySet, PolicyResolution,
)
from tests.support.in_memory import (
    AdapterSetupError, InMemoryKeeneticPolicySource, UnconfiguredResponseError,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import load_keenetic_snapshot, policies_from_rci, snapshot_policies


# Описания снимка искусственные, но в результат они попадать не должны.
DESCRIPTION = "fixture-policy-3"
PRIVATE_MARKERS = ("fixture-policy", "ОПИСАНИЕ-ТЕСТ")


def ambiguous_set():
    return KeeneticPolicySet((
        KeeneticPolicy("Policy1", DESCRIPTION), KeeneticPolicy("Policy2", DESCRIPTION),
        KeeneticPolicy("Policy3", "fixture-policy-0"),
    ))


class ResolveKeeneticPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policies = snapshot_policies()
        self.source = InMemoryKeeneticPolicySource(self.policies)
        self.handler = ResolveKeeneticPolicyHandler(self.source, operation_ids=lambda: "op-1")

    def execute(self, command=None):
        return self.handler.execute(command if command is not None else ResolveKeeneticPolicy(DESCRIPTION))

    def assert_private(self, result):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertFalse(any(isinstance(value, (
            KeeneticPolicy, KeeneticPolicySet, PolicyResolution, BaseException,
        )) for value in reachable(result)))

    def assert_failed(self, result, category, code, reason=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertIs(result.error.category, category)
        self.assertEqual(result.error.code, code)
        self.assertEqual(result.error.reason, reason)
        self.assert_private(result)

    def test_single_match_from_snapshot_is_resolved_dynamically(self):
        result = self.execute()
        self.assertEqual(result.to_dict(), {
            "operation_id": "op-1", "command": "resolve_keenetic_policy",
            "contract_version": CONTRACT_VERSION, "status": "succeeded", "error": None,
            "data": {
                "outcome": "resolved", "policy_id": "Policy30", "candidates": ["Policy30"],
                "policy_count": 3, "selected_by_user": False,
            },
        })
        self.assertEqual(self.source.calls, 1)
        self.assert_private(result)
        self.assertIs(self.source.current_policies(), self.policies)
        self.assertEqual(self.policies.policy_ids, ("Policy10", "Policy20", "Policy30"))

    def test_missing_and_ambiguous_are_outcomes_without_default_id(self):
        missing = self.execute(ResolveKeeneticPolicy("ОПИСАНИЕ-ТЕСТ"))
        self.assertTrue(missing.succeeded)
        self.assertIsNone(missing.error)
        self.assertEqual(missing.data.to_dict(), {
            "outcome": "missing", "policy_id": None, "candidates": [], "policy_count": 3,
            "selected_by_user": False,
        })
        self.assert_private(missing)

        self.source.outcome = ambiguous_set()
        ambiguous = self.execute()
        self.assertTrue(ambiguous.succeeded)
        self.assertEqual(ambiguous.data.to_dict(), {
            "outcome": "ambiguous", "policy_id": None, "candidates": ["Policy1", "Policy2"],
            "policy_count": 3, "selected_by_user": False,
        })
        self.assert_private(ambiguous)
        self.assertEqual(self.source.calls, 2)

    def test_ambiguity_is_resolved_only_by_explicit_selection_from_current_candidates(self):
        self.source.outcome = ambiguous_set()
        confirmed = self.execute(ResolveKeeneticPolicy(DESCRIPTION, selected_policy_id="Policy2"))
        self.assertTrue(confirmed.succeeded)
        self.assertEqual(confirmed.data.outcome, "resolved")
        self.assertEqual(confirmed.data.policy_id, "Policy2")
        self.assertEqual(confirmed.data.candidates, ("Policy1", "Policy2"))
        self.assertTrue(confirmed.data.selected_by_user)
        self.assert_private(confirmed)

        for selected in ("Policy3", "Policy9"):
            with self.subTest(selected=selected):
                result = self.execute(ResolveKeeneticPolicy(DESCRIPTION, selected_policy_id=selected))
                self.assert_failed(result, ErrorCategory.INVALID_INPUT, "policy_selection_mismatch")
                self.assertNotIn(selected, json.dumps(result.to_dict()))

        # Состояние изменилось: прежний выбор устарел и не подставляется.
        self.source.outcome = KeeneticPolicySet((
            KeeneticPolicy("Policy1", DESCRIPTION), KeeneticPolicy("Policy2", "fixture-policy-0"),
        ))
        stale = self.execute(ResolveKeeneticPolicy(DESCRIPTION, selected_policy_id="Policy2"))
        self.assert_failed(stale, ErrorCategory.INVALID_INPUT, "policy_selection_mismatch")
        current = self.execute(ResolveKeeneticPolicy(DESCRIPTION, selected_policy_id="Policy1"))
        self.assertEqual(current.data.outcome, "resolved")
        self.assertTrue(current.data.selected_by_user)
        self.assertEqual(self.source.calls, 5)

    def test_wrong_command_and_version_do_not_read_source(self):
        for command, code in (
            (DESCRIPTION, "invalid_command"),
            (ResolveKeeneticPolicy(1), "invalid_command"),
            (ResolveKeeneticPolicy(b"xkeen"), "invalid_command"),
            (ResolveKeeneticPolicy(None), "invalid_command"),
            (ResolveKeeneticPolicy(DESCRIPTION, selected_policy_id=1), "invalid_command"),
            (ResolveKeeneticPolicy(DESCRIPTION, contract_version=True), "unsupported_contract_version"),
            (ResolveKeeneticPolicy(DESCRIPTION, contract_version=CONTRACT_VERSION + 1), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                result = self.execute(command)
                self.assert_failed(result, ErrorCategory.INVALID_REQUEST, code)
        self.assertEqual(self.source.calls, 0)

    def test_invalid_description_and_selection_format_do_not_read_source(self):
        for description in ("", "   ", "a\x00b", "x" * 257, "a b"):
            with self.subTest(description=description):
                result = self.execute(ResolveKeeneticPolicy(description))
                self.assert_failed(result, ErrorCategory.INVALID_INPUT, "invalid_policy_description")
        for selected in ("", "bad id", "Политика", "-x", "P" * 65):
            with self.subTest(selected=selected):
                result = self.execute(ResolveKeeneticPolicy(DESCRIPTION, selected_policy_id=selected))
                self.assert_failed(result, ErrorCategory.INVALID_INPUT, "invalid_policy_id")
        self.assertEqual(self.source.calls, 0)

    def test_source_failure_and_invalid_data_have_distinct_results(self):
        class DerivedSet(KeeneticPolicySet):
            pass

        class SetLike:
            @property
            def policies(self):
                raise AssertionError("Поля объекта другого типа не должны читаться.")

        self.source.outcome = OSError("Отказ источника: " + DESCRIPTION)
        self.assert_failed(self.execute(), ErrorCategory.SOURCE_FAILED, "keenetic_policies_unavailable")
        for outcome in (
            None, {"Policy30": {"description": DESCRIPTION}}, self.policies.policies,
            list(self.policies.policies), DerivedSet(self.policies.policies), SetLike(),
        ):
            with self.subTest(outcome=type(outcome).__name__):
                self.source.outcome = outcome
                self.assert_failed(self.execute(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_keenetic_policies")

    def test_corrupted_source_model_is_rejected_with_domain_reason(self):
        broken_id = KeeneticPolicy("Policy9", DESCRIPTION)
        object.__setattr__(broken_id, "policy_id", "bad id")
        broken_description = KeeneticPolicy("Policy9", DESCRIPTION)
        object.__setattr__(broken_description, "description", 1)
        for field, value, reason in (
            ("policies", list(self.policies.policies), "invalid_policies"),
            ("policies", self.policies.policies + ({"policy_id": "Policy9"},), "invalid_policy"),
            ("policies", self.policies.policies + (self.policies.policies[0],), "duplicate_policy_id"),
            ("policies", (broken_id,), "invalid_policy_id"),
            ("policies", (broken_description,), "invalid_policy_description"),
        ):
            with self.subTest(reason=reason):
                policies = snapshot_policies()
                object.__setattr__(policies, field, value)
                self.source.outcome = policies
                self.assert_failed(
                    self.execute(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_keenetic_policies", reason,
                )

    def test_interruptions_are_not_converted_to_source_failure(self):
        for error in (KeyboardInterrupt(), SystemExit()):
            self.source.outcome = error
            with self.assertRaises(type(error)):
                self.execute()

    def test_scenario_has_no_terminal_or_external_effects(self):
        with forbid_external_effects():
            self.assertEqual(self.execute().data.outcome, "resolved")
            self.assertEqual(self.execute(ResolveKeeneticPolicy("ОПИСАНИЕ-ТЕСТ")).data.outcome, "missing")
            self.source.outcome = ambiguous_set()
            self.assertEqual(self.execute().data.outcome, "ambiguous")
            self.source.outcome = OSError(DESCRIPTION)
            self.assertEqual(self.execute().error.code, "keenetic_policies_unavailable")

    def test_rendering_is_frozen_and_does_not_reread_source(self):
        result = self.execute()
        calls = self.source.calls
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertIn("resolved", str(result.data))
        self.assertEqual(self.source.calls, calls)
        with self.assertRaises(FrozenInstanceError):
            result.data.policy_id = "Policy10"

    def test_command_repr_hides_description_and_is_frozen(self):
        command = ResolveKeeneticPolicy("ОПИСАНИЕ-ТЕСТ", selected_policy_id="Policy30")
        self.assertNotIn("ОПИСАНИЕ-ТЕСТ", repr(command) + str(command))
        with self.assertRaises(FrozenInstanceError):
            command.description = DESCRIPTION


class InMemoryKeeneticPolicySourceTests(unittest.TestCase):
    def test_unconfigured_response_is_a_test_setup_error(self):
        source = InMemoryKeeneticPolicySource()
        with self.assertRaises(UnconfiguredResponseError):
            source.current_policies()
        with self.assertRaises(UnconfiguredResponseError):
            ResolveKeeneticPolicyHandler(source).execute(ResolveKeeneticPolicy(DESCRIPTION))
        self.assertEqual(source.calls, 2)
        source.outcome = OSError
        with self.assertRaises(AdapterSetupError):
            source.current_policies()

    def test_replaced_failure_releases_frames_and_repr_hides_policies(self):
        source = InMemoryKeeneticPolicySource(OSError(DESCRIPTION))
        error = source.outcome
        ResolveKeeneticPolicyHandler(source).execute(ResolveKeeneticPolicy(DESCRIPTION))
        self.assertIsNotNone(error.__traceback__)
        source.outcome = snapshot_policies()
        self.assertIsNone(error.__traceback__)
        self.assertNotIn(DESCRIPTION, repr(source))
        self.assertEqual(repr(source), "InMemoryKeeneticPolicySource(calls=1)")


class SnapshotPoliciesTests(unittest.TestCase):
    def test_snapshot_projection_keeps_order_ids_and_descriptions(self):
        payload = load_keenetic_snapshot()["ip/policy"]
        policies = policies_from_rci(payload)
        self.assertEqual(policies.policy_ids, tuple(payload))
        self.assertEqual(
            tuple(policy.description for policy in policies.policies),
            tuple(entry["description"] for entry in payload.values()),
        )

    def test_projection_keeps_missing_description_as_none_and_rejects_foreign_values(self):
        policies = policies_from_rci({"PolicyA": {"permit": []}, "PolicyB": {"description": "x"}})
        self.assertEqual(tuple(policy.description for policy in policies.policies), (None, "x"))
        for payload in (
            {"bad id": {"description": "x"}},
            {"PolicyA": {"description": 1}},
            {"PolicyA": {"description": "x"}, "PolicyB": {"description": "x"}, "PolicyA2": {}},
        ):
            with self.subTest(payload=tuple(payload)):
                if "PolicyA2" in payload:
                    self.assertEqual(len(policies_from_rci(payload)), 3)
                else:
                    with self.assertRaises(KeeneticPolicyError):
                        policies_from_rci(payload)


if __name__ == "__main__":
    unittest.main()
