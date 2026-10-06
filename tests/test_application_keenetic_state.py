"""Сценарий чтения состояния Keenetic на снимке и управляемых источниках."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.keenetic_state import (
    InspectKeeneticState, InspectKeeneticStateHandler, KeeneticStateView,
)
from keenvpn.domain.keenetic_device import DeviceIdentity, KeeneticDevice, KeeneticDeviceInventory
from keenvpn.domain.keenetic_native import (
    KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticNativeError, KeeneticNativeErrorCode,
    KeeneticNativeState, KeeneticRegistrations, KeeneticSegmentAssignment,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet, PolicyResolution
from tests.support.in_memory import (
    AdapterSetupError, InMemoryKeeneticHotspotRuntimeSource, InMemoryKeeneticHotspotSettingsSource,
    InMemoryKeeneticPolicySource, InMemoryKeeneticRegistrationSource, UnconfiguredResponseError,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import snapshot_keenetic_sources


PRIVATE_MARKERS = (
    "02:00:00:54", "02:00:00:00", "device-", "192.0.2.", "2001:db8", "fixture-policy",
    "fixture-interface", "fixture-private",
)
PRIVATE_TYPES = (
    KeeneticPolicy, KeeneticPolicySet, PolicyResolution, KeeneticDevice, KeeneticDeviceInventory, DeviceIdentity,
    KeeneticHotspotSettings, KeeneticRegistrations, KeeneticHotspotRuntime, KeeneticSegmentAssignment,
    KeeneticNativeState, BaseException,
)
EXPECTED_DATA = {
    "policy_count": 3, "policy_ids": ["Policy10", "Policy20", "Policy30"],
    "segments": [
        {"segment_id": "Bridge0", "assignment": "explicit", "policy_id": "Policy10",
         "access_denied": False, "read_only": False},
        {"segment_id": "Bridge1", "assignment": "unassigned", "policy_id": None,
         "access_denied": True, "read_only": False},
    ],
    "segment_missing_policy_count": 0,
    "devices": {
        "record_count": 19, "distinct_mac_count": 19, "online_count": 12, "offline_count": 7, "unknown_count": 0,
        "observation_mismatch_count": 0, "explicit_count": 15, "inherit_count": 2, "unassigned_count": 2,
        "unknown_assignment_count": 0, "access_denied_count": 1, "read_only_count": 0,
        "with_registration_count": 19, "with_observation_count": 19, "ambiguous_observation_count": 0,
        "missing_policy_count": 0,
    },
    "registrations": {
        "registration_count": 19, "distinct_mac_count": 19, "duplicate_mac_count": 0, "unresolvable_count": 0,
        "without_device_count": 0,
    },
    "runtime": {
        "record_count": 19, "distinct_mac_count": 19, "duplicate_mac_count": 0, "unresolvable_count": 0,
        "active_count": 12, "registered_count": 19, "without_device_count": 0,
    },
}
SOURCES = ("policies", "hotspot", "registrations", "runtime")
UNAVAILABLE_CODES = {
    "policies": "keenetic_policies_unavailable", "hotspot": "keenetic_hotspot_unavailable",
    "registrations": "keenetic_registrations_unavailable", "runtime": "keenetic_runtime_unavailable",
}
INVALID_CODES = {
    "policies": "invalid_keenetic_policies", "hotspot": "invalid_keenetic_hotspot",
    "registrations": "invalid_keenetic_registrations", "runtime": "invalid_keenetic_runtime",
}


def calls_after_failure(index):
    """Источники после отказавшего не читаются."""
    return tuple(1 if position <= index else 0 for position in range(len(SOURCES)))


class InspectKeeneticStateTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_keenetic_sources()
        self.handler = InspectKeeneticStateHandler(
            self.sources.policies, self.sources.hotspot, self.sources.registrations, self.sources.runtime,
            operation_ids=lambda: "op-1",
        )

    def execute(self, command=None):
        return self.handler.execute(InspectKeeneticState() if command is None else command)

    def assert_private(self, result):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertFalse(any(isinstance(value, PRIVATE_TYPES) for value in reachable(result)))

    def assert_failed(self, result, category, code, reason=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertIs(result.error.category, category)
        self.assertEqual(result.error.code, code)
        self.assertEqual(result.error.reason, reason)
        self.assert_private(result)

    def test_snapshot_state_is_read_once_per_source_in_order(self):
        result = self.execute()
        self.assertEqual(result.to_dict(), {
            "contract_version": CONTRACT_VERSION, "operation_id": "op-1", "command": "inspect_keenetic_state",
            "status": "succeeded", "error": None, "data": EXPECTED_DATA,
        })
        self.assertEqual(self.sources.calls, (1, 1, 1, 1))
        self.assertIs(type(result.data), KeeneticStateView)
        self.assertEqual(result.data.segments[1].access_denied, True)
        self.assertEqual(result.data.devices.explicit_count, 15)
        self.assert_private(result)

    def test_wrong_command_and_version_do_not_read_sources(self):
        for command, code in (
            ("inspect", "invalid_command"),
            (None, "invalid_command"),
            (InspectKeeneticState(contract_version=True), "unsupported_contract_version"),
            (InspectKeeneticState(contract_version=CONTRACT_VERSION + 1), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                result = self.handler.execute(command)
                self.assert_failed(result, ErrorCategory.INVALID_REQUEST, code)
        self.assertEqual(self.sources.calls, (0, 0, 0, 0))

    def test_each_source_failure_has_distinct_code_and_stops_reading(self):
        for index, name in enumerate(SOURCES):
            with self.subTest(source=name):
                sources = snapshot_keenetic_sources()
                getattr(sources, name).outcome = OSError("Отказ источника: fixture-private 02:00:00:54:00:01")
                handler = InspectKeeneticStateHandler(
                    sources.policies, sources.hotspot, sources.registrations, sources.runtime,
                )
                result = handler.execute(InspectKeeneticState())
                self.assert_failed(result, ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name])
                self.assertEqual(sources.calls, calls_after_failure(index))

    def test_invalid_source_data_has_distinct_codes_and_domain_reasons(self):
        class DerivedSettings(KeeneticHotspotSettings):
            pass

        class DerivedRegistrations(KeeneticRegistrations):
            pass

        class DerivedRuntime(KeeneticHotspotRuntime):
            pass

        tampered_settings = snapshot_keenetic_sources().hotspot.outcome
        object.__setattr__(tampered_settings, "_snapshot", json.dumps({"host": [{"mac": "fixture-private-mac"}]}))
        typed_settings = KeeneticHotspotSettings({"policy": [{"interface": "Bridge1", "deny": True}]})
        object.__setattr__(
            typed_settings, "segment_assignments",
            (KeeneticSegmentAssignment({"interface": "Bridge1", "deny": 1}),),
        )
        tampered_registrations = snapshot_keenetic_sources().registrations.outcome
        object.__setattr__(tampered_registrations, "_snapshot", json.dumps({"fixture-private-name": "x"}))
        tampered_runtime = snapshot_keenetic_sources().runtime.outcome
        object.__setattr__(tampered_runtime, "_snapshot", json.dumps({"host": "fixture-private"}))
        cases = (
            ("policies", None, None),
            ("policies", {"Policy30": {"description": "fixture-policy-3"}}, None),
            ("hotspot", None, None),
            ("hotspot", {"host": []}, None),
            ("hotspot", DerivedSettings({}), None),
            ("hotspot", tampered_settings, "invalid_device_mac"),
            ("hotspot", typed_settings, "invalid_hotspot_settings"),
            ("registrations", None, None),
            ("registrations", DerivedRegistrations({}), None),
            ("registrations", tampered_registrations, "invalid_registrations"),
            ("runtime", None, None),
            ("runtime", DerivedRuntime({}), None),
            ("runtime", tampered_runtime, "invalid_hotspot_runtime"),
        )
        for name, outcome, reason in cases:
            with self.subTest(source=name, outcome=type(outcome).__name__, reason=reason):
                sources = snapshot_keenetic_sources()
                getattr(sources, name).outcome = outcome
                handler = InspectKeeneticStateHandler(
                    sources.policies, sources.hotspot, sources.registrations, sources.runtime,
                )
                result = handler.execute(InspectKeeneticState())
                self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, INVALID_CODES[name], reason)
                self.assertEqual(sources.calls, calls_after_failure(SOURCES.index(name)))

    def test_assembly_failure_is_reported_without_partial_result(self):
        def broken(*_args):
            raise KeeneticNativeError(KeeneticNativeErrorCode.STATE)

        with patch("keenvpn.application.keenetic_state.assemble_keenetic_state", broken):
            result = self.execute()
        self.assert_failed(
            result, ErrorCategory.INVALID_SOURCE_DATA, "keenetic_state_inconsistent", "invalid_native_state",
        )
        self.assertEqual(self.sources.calls, (1, 1, 1, 1))

    def test_interruptions_are_not_converted_to_source_failure(self):
        for name in SOURCES:
            for error in (KeyboardInterrupt(), SystemExit()):
                with self.subTest(source=name, error=type(error).__name__):
                    sources = snapshot_keenetic_sources()
                    getattr(sources, name).outcome = error
                    handler = InspectKeeneticStateHandler(
                        sources.policies, sources.hotspot, sources.registrations, sources.runtime,
                    )
                    with self.assertRaises(type(error)):
                        handler.execute(InspectKeeneticState())

    def test_unconfigured_source_is_a_test_setup_error(self):
        for name, source_type in (
            ("hotspot", InMemoryKeeneticHotspotSettingsSource),
            ("registrations", InMemoryKeeneticRegistrationSource),
            ("runtime", InMemoryKeeneticHotspotRuntimeSource),
        ):
            with self.subTest(source=name):
                sources = {field: getattr(self.sources, field) for field in SOURCES}
                sources[name] = source_type()
                handler = InspectKeeneticStateHandler(
                    sources["policies"], sources["hotspot"], sources["registrations"], sources["runtime"],
                )
                with self.assertRaises(UnconfiguredResponseError):
                    handler.execute(InspectKeeneticState())
                self.assertEqual(sources[name].calls, 1)
        with self.assertRaises(AdapterSetupError):
            InMemoryKeeneticPolicySource(OSError).current_policies()

    def test_scenario_has_no_terminal_or_external_effects(self):
        with forbid_external_effects():
            self.assertTrue(self.execute().succeeded)
            self.sources.runtime.outcome = OSError("fixture-private")
            self.assertEqual(self.execute().error.code, "keenetic_runtime_unavailable")
            self.sources.runtime.outcome = None
            self.assertEqual(self.execute().error.code, "invalid_keenetic_runtime")

    def test_rendering_is_frozen_and_does_not_reread_sources(self):
        result = self.execute()
        calls = self.sources.calls
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertIn("Policy10", str(result.data))
        self.assertEqual(self.sources.calls, calls)
        with self.assertRaises(FrozenInstanceError):
            result.data.policy_count = 0
        with self.assertRaises(FrozenInstanceError):
            result.data.devices.record_count = 0
        with self.assertRaises(FrozenInstanceError):
            result.data.segments[0].policy_id = "Policy20"

    def test_synthetic_sources_surface_unmatched_and_missing_policies(self):
        mac_a, mac_b, mac_c = "02:00:00:00:00:a1", "02:00:00:00:00:b2", "02:00:00:00:00:c3"
        handler = InspectKeeneticStateHandler(
            InMemoryKeeneticPolicySource(KeeneticPolicySet((KeeneticPolicy("Policy7", "fixture-private-vpn"),))),
            InMemoryKeeneticHotspotSettingsSource(KeeneticHotspotSettings({
                "host": [{"mac": mac_a, "policy": "Policy9"}, {"mac": mac_b, "access": "deny", "deny": True}],
                "policy": [{"interface": "Bridge0", "policy": "Policy7"}, {"interface": "Bridge1", "access": "deny"}],
            })),
            InMemoryKeeneticRegistrationSource(KeeneticRegistrations({
                "fixture-private-name-a": {"mac": mac_a.upper()}, "fixture-private-name-c": {"mac": mac_c},
            })),
            InMemoryKeeneticHotspotRuntimeSource(KeeneticHotspotRuntime({"host": [
                {"mac": mac_a, "active": True}, {"mac": mac_a, "active": False}, {"mac": mac_c, "active": True},
            ]})),
            operation_ids=lambda: "op-2",
        )
        result = handler.execute(InspectKeeneticState())
        self.assertTrue(result.succeeded)
        data = result.data.to_dict()
        self.assertEqual(data["policy_ids"], ["Policy7"])
        self.assertEqual([segment["policy_id"] for segment in data["segments"]], ["Policy7", None])
        self.assertEqual(data["segment_missing_policy_count"], 0)
        self.assertEqual(data["devices"]["missing_policy_count"], 1)
        self.assertEqual(data["devices"]["ambiguous_observation_count"], 1)
        self.assertEqual(data["devices"]["with_observation_count"], 0)
        self.assertEqual(data["devices"]["with_registration_count"], 1)
        self.assertEqual(data["devices"]["access_denied_count"], 1)
        self.assertEqual(data["registrations"]["without_device_count"], 1)
        self.assertEqual(data["runtime"]["without_device_count"], 1)
        self.assertEqual(data["runtime"]["duplicate_mac_count"], 1)
        self.assert_private(result)


if __name__ == "__main__":
    unittest.main()
