"""Преобразование ответов RCI снимка в модели без обращения к роутеру."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.keenetic_rci import (
    HOTSPOT_RUNTIME_RESOURCE, HOTSPOT_SETTINGS_RESOURCE, POLICIES_RESOURCE, REGISTRATIONS_RESOURCE,
    hotspot_runtime_from_rci, hotspot_settings_from_rci, policies_from_rci, registrations_from_rci,
)
from keenvpn.domain.keenetic_native import (
    KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticNativeError, KeeneticNativeErrorCode,
    KeeneticRegistrations,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicyError, KeeneticPolicyErrorCode, KeeneticPolicySet
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import load_keenetic_snapshot


class KeeneticRciTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = load_keenetic_snapshot()
        self.before = deepcopy(self.snapshot)

    def test_resource_names_match_snapshot_keys(self):
        for resource in (POLICIES_RESOURCE, HOTSPOT_SETTINGS_RESOURCE, REGISTRATIONS_RESOURCE, HOTSPOT_RUNTIME_RESOURCE):
            self.assertIn(resource, self.snapshot)

    def test_snapshot_resources_become_models_without_mutation(self):
        with forbid_external_effects():
            policies = policies_from_rci(self.snapshot[POLICIES_RESOURCE])
            hotspot = hotspot_settings_from_rci(self.snapshot[HOTSPOT_SETTINGS_RESOURCE])
            registrations = registrations_from_rci(self.snapshot[REGISTRATIONS_RESOURCE])
            runtime = hotspot_runtime_from_rci(self.snapshot[HOTSPOT_RUNTIME_RESOURCE])
        self.assertEqual(self.snapshot, self.before)
        self.assertIs(type(policies), KeeneticPolicySet)
        self.assertEqual(policies.policy_ids, tuple(self.before[POLICIES_RESOURCE]))
        self.assertEqual(
            [policy.description for policy in policies.policies],
            [entry["description"] for entry in self.before[POLICIES_RESOURCE].values()],
        )
        self.assertIs(type(hotspot), KeeneticHotspotSettings)
        self.assertEqual(hotspot.export(), self.before[HOTSPOT_SETTINGS_RESOURCE])
        self.assertEqual(len(hotspot.segment_assignments), 2)
        self.assertIs(type(registrations), KeeneticRegistrations)
        self.assertEqual(registrations.export(), self.before[REGISTRATIONS_RESOURCE])
        self.assertIs(type(runtime), KeeneticHotspotRuntime)
        self.assertEqual(runtime.export(), self.before[HOTSPOT_RUNTIME_RESOURCE])
        self.assertEqual(runtime.to_diagnostic()["active_count"], 12)

    def test_policies_keep_missing_description_and_reject_foreign_payloads(self):
        policies = policies_from_rci({"PolicyA": {"permit": []}, "PolicyB": {"description": "x"}})
        self.assertEqual([policy.description for policy in policies.policies], [None, "x"])
        for payload, code in (
            (None, KeeneticPolicyErrorCode.POLICIES),
            ([{"description": "x"}], KeeneticPolicyErrorCode.POLICIES),
            ({"PolicyA": "x"}, KeeneticPolicyErrorCode.POLICIES),
            ({"bad id": {"description": "x"}}, KeeneticPolicyErrorCode.POLICY_ID),
            ({"PolicyA": {"description": 1}}, KeeneticPolicyErrorCode.DESCRIPTION),
        ):
            with self.subTest(payload=type(payload).__name__), self.assertRaises(KeeneticPolicyError) as caught:
                policies_from_rci(payload)
            self.assertIs(caught.exception.code, code)

    def test_policy_rejection_is_detached_from_foreign_context(self):
        # Ошибка типа payload не должна удерживать активное чужое исключение.
        for payload in (None, [{"description": "x"}], {"PolicyA": "x"}):
            with self.subTest(payload=type(payload).__name__):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(KeeneticPolicyError) as caught:
                        policies_from_rci(payload)
                error = caught.exception
                self.assertIs(error.code, KeeneticPolicyErrorCode.POLICIES)
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertNotIn("fixture-private", str(error) + repr(error))

    def test_other_resources_reject_foreign_payloads_with_model_codes(self):
        for function, code in (
            (hotspot_settings_from_rci, KeeneticNativeErrorCode.HOTSPOT_SETTINGS),
            (registrations_from_rci, KeeneticNativeErrorCode.REGISTRATIONS),
            (hotspot_runtime_from_rci, KeeneticNativeErrorCode.HOTSPOT_RUNTIME),
        ):
            for payload in (None, [], "fixture-private"):
                with self.subTest(function=function.__name__, payload=type(payload).__name__):
                    with self.assertRaises(KeeneticNativeError) as caught:
                        function(payload)
                    self.assertIs(caught.exception.code, code)
                    self.assertNotIn("fixture-private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
