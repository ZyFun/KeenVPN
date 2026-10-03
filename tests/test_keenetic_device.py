"""Сохранность записей устройства при локальной смене назначения политики."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.keenetic_device import (
    DevicePolicyAssignment, DevicePolicyMode, KeeneticDevice, KeeneticDeviceError, KeeneticDeviceErrorCode,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet, resolve_policy
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import load_keenetic_snapshot, policies_from_rci


MAC = "02:00:00:00:00:Ab"
POLICIES = KeeneticPolicySet((KeeneticPolicy("Policy17", "vpn"), KeeneticPolicy("Policy42", "direct")))
TARGETS = (
    DevicePolicyAssignment(DevicePolicyMode.EXPLICIT, "Policy17"),
    DevicePolicyAssignment(DevicePolicyMode.INHERIT),
    DevicePolicyAssignment(DevicePolicyMode.UNASSIGNED),
)


def record():
    """Только искусственные данные, включая неизвестные вложенные поля."""
    return {
        "mac": MAC, "access": "deny", "deny": True, "priority": 6,
        "name": "Тестовое устройство 📱", "ip": "192.0.2.17", "schedule": "Тестовое расписание",
        "traffic-shape": {"rx": 7, "tx": 9, "schedule": "fixture-shape"},
        "extension": {
            "empty": [], "null": None, "ordered": [3, 1, 2], "flag": False, "ratio": -0.0,
            "имя 🧪": ["Café", "Cafe\u0301", "й", "и\u0306", "👨‍💻"],
        },
    }


def without_assignment(settings):
    return {key: value for key, value in settings.items() if key not in ("policy", "conform")}


class KeeneticDeviceTests(unittest.TestCase):
    def assert_error(self, code, function, *args, **kwargs):
        with self.assertRaises(KeeneticDeviceError) as caught:
            function(*args, **kwargs)
        self.assertIs(caught.exception.code, code)
        return caught.exception

    def test_round_trip_preserves_types_values_order_and_missing_fields(self):
        original = record()
        details = {
            "name": "Тестовое имя 📱", "ip6": ["2001:db8::17"], "reserved": {"ip": "192.0.2.17"},
            "registration": {"Тестовый клиент 🧪 Cafe\u0301": {"mac": MAC}},
        }
        with forbid_external_effects():
            device = KeeneticDevice(original, details=details)
            exported = device.export()
        self.assertEqual(exported, {"settings": original, "details": details})
        self.assertEqual(json.dumps(exported), json.dumps({"settings": original, "details": details}))
        self.assertNotIn("policy", exported["settings"])
        self.assertNotIn("conform", exported["settings"])
        self.assertNotIn("permit", exported["settings"])
        with forbid_external_effects():
            updated = device.with_assignment(TARGETS[0], policies=POLICIES)
        expected = {"settings": {**original, "policy": "Policy17"}, "details": details}
        self.assertEqual(updated.export(), expected)
        self.assertEqual(json.dumps(updated.export()), json.dumps(expected))
        self.assertEqual(device.export(), {"settings": original, "details": details})

    def test_input_and_export_are_isolated_deeply(self):
        original, details = record(), {"nested": {"values": ["fixture-name"]}}
        expected = deepcopy({"settings": original, "details": details})
        device = KeeneticDevice(original, details=details)
        original["extension"]["ordered"].append(99)
        details["nested"]["values"].clear()
        exported = device.export()
        exported["settings"]["traffic-shape"]["rx"] = 100
        exported["details"]["nested"]["values"].append("changed")
        self.assertEqual(device.export(), expected)
        with self.assertRaises(FrozenInstanceError):
            device._snapshot = "{}"

    def test_assignment_modes_use_only_saved_settings(self):
        for fields, mode in (
            ({}, DevicePolicyMode.UNASSIGNED),
            ({"policy": ""}, DevicePolicyMode.UNASSIGNED),
            ({"conform": False}, DevicePolicyMode.UNASSIGNED),
            ({"policy": "", "conform": False}, DevicePolicyMode.UNASSIGNED),
            ({"conform": True}, DevicePolicyMode.INHERIT),
            ({"policy": "", "conform": True}, DevicePolicyMode.INHERIT),
            ({"policy": "Policy42"}, DevicePolicyMode.EXPLICIT),
            ({"policy": "Policy42", "conform": False}, DevicePolicyMode.EXPLICIT),
        ):
            with self.subTest(fields=fields):
                original = {"mac": MAC, **fields}
                device = KeeneticDevice(original, details={"runtime": {"policy": "Policy17", "active": True}})
                self.assertIs(device.assignment.mode, mode)
                self.assertFalse(device.read_only)
                # Повтор сохраняет пустые строки и явный false без нормализации.
                same = device.with_assignment(device.assignment, policies=POLICIES)
                self.assertIs(same, device)
                self.assertEqual(same.export()["settings"], original)

    def test_all_transitions_preserve_deny_and_every_unrelated_field(self):
        for initial in ({}, {"conform": True}, {"policy": "Policy42"}):
            for target in TARGETS:
                with self.subTest(initial=initial, target=target):
                    original = {**record(), **initial}
                    details = {"registration": {"Тестовый клиент 🧪 Cafe\u0301": {"mac": MAC}}, "ip": "192.0.2.17"}
                    with forbid_external_effects():
                        device = KeeneticDevice(original, details=details)
                        updated = device.with_assignment(target, policies=POLICIES)
                    result = updated.export()
                    self.assertEqual(updated.assignment, target)
                    self.assertEqual(without_assignment(result["settings"]), without_assignment(original))
                    self.assertEqual(result["details"], details)
                    self.assertEqual(result["settings"]["access"], "deny")
                    self.assertIs(result["settings"]["deny"], True)
                    self.assertNotIn("permit", result["settings"])
                    self.assertTrue(updated.to_diagnostic()["access_denied"])
                    self.assertEqual(device.export(), {"settings": original, "details": details})

    def test_permit_and_absent_access_fields_are_not_added_or_removed(self):
        for access in (
            {}, {"access": "permit", "permit": True}, {"deny": True}, {"access": "deny"},
            {"access": "permit"}, {"deny": False}, {"permit": False},
            {"access": "deny", "permit": False}, {"access": "permit", "deny": False},
        ):
            with self.subTest(access=access):
                device = KeeneticDevice({"mac": MAC, **access})
                changed = device.with_assignment(TARGETS[0], policies=POLICIES)
                self.assertEqual(without_assignment(changed.export()["settings"]), {"mac": MAC, **access})

    def test_unknown_and_conflicting_states_are_lossless_read_only(self):
        for fields in (
            {"policy": "Policy17", "conform": True}, {"policy": None}, {"policy": True},
            {"policy": "unknown id"}, {"conform": "true"}, {"conform": None}, {"conform": 1},
            {"access": "future-mode"}, {"access": None}, {"access": ["deny"]},
            {"access": "deny", "permit": True}, {"access": "permit", "deny": True},
            {"access": "deny", "deny": False}, {"access": "permit", "permit": False},
            {"deny": True, "permit": True}, {"deny": "true"}, {"permit": 1},
        ):
            with self.subTest(fields=fields):
                original = {"mac": MAC, **fields}
                device = KeeneticDevice(original)
                self.assertTrue(device.read_only)
                self.assertEqual(device.export()["settings"], original)
                for target in TARGETS:
                    self.assert_error(KeeneticDeviceErrorCode.READ_ONLY, device.with_assignment, target, policies=POLICIES)
                self.assertEqual(device.export()["settings"], original)

    def test_target_policy_must_exist_even_on_noop(self):
        device = KeeneticDevice({"mac": MAC, "policy": "Policy17"})
        for policies in (KeeneticPolicySet(()), KeeneticPolicySet((KeeneticPolicy("Policy99"),))):
            self.assert_error(KeeneticDeviceErrorCode.POLICY_MISSING, device.with_assignment, TARGETS[0], policies=policies)
        missing = DevicePolicyAssignment(DevicePolicyMode.EXPLICIT, "Policy99")
        self.assert_error(KeeneticDeviceErrorCode.POLICY_MISSING, device.with_assignment, missing, policies=POLICIES)

    def test_invalid_or_corrupted_policy_set_is_not_a_successful_fallback(self):
        device = KeeneticDevice(record())
        corrupted = KeeneticPolicySet((KeeneticPolicy("Policy17"),))
        object.__setattr__(corrupted.policies[0], "policy_id", "invalid id")
        for policies in (None, [], POLICIES.policies, corrupted):
            for target in TARGETS:
                with self.subTest(policies=type(policies).__name__, target=target):
                    self.assert_error(KeeneticDeviceErrorCode.POLICIES, device.with_assignment, target, policies=policies)

    def test_assignment_validation_and_read_only_target(self):
        for mode, policy_id in (
            ("explicit", "Policy17"), (None, None), (DevicePolicyMode.EXPLICIT, None),
            (DevicePolicyMode.EXPLICIT, ""), (DevicePolicyMode.EXPLICIT, "bad id"),
            (DevicePolicyMode.INHERIT, "Policy17"), (DevicePolicyMode.UNASSIGNED, "Policy17"),
            (DevicePolicyMode.UNKNOWN, "Policy17"),
        ):
            self.assert_error(KeeneticDeviceErrorCode.ASSIGNMENT, DevicePolicyAssignment, mode, policy_id)
        device = KeeneticDevice(record())
        corrupted = DevicePolicyAssignment(DevicePolicyMode.EXPLICIT, "Policy17")
        object.__setattr__(corrupted, "policy_id", "bad id")
        for target in (None, "Policy17", {"policy_id": "Policy17"}, DevicePolicyAssignment(DevicePolicyMode.UNKNOWN), corrupted):
            self.assert_error(KeeneticDeviceErrorCode.ASSIGNMENT, device.with_assignment, target, policies=POLICIES)

    def test_invalid_mac_is_rejected_without_normalization(self):
        for mac in (None, "", "02:00:00:00:00", "02-00-00-00-00-01", "02:00:00:00:00:01\n", 17):
            self.assert_error(KeeneticDeviceErrorCode.MAC, KeeneticDevice, {"mac": mac})
        self.assert_error(KeeneticDeviceErrorCode.MAC, KeeneticDevice, {})
        self.assertEqual(KeeneticDevice({"mac": MAC}).export()["settings"]["mac"], MAC)

    def test_unsupported_data_and_cycles_fail_with_static_error(self):
        class Foreign:
            def __str__(self):
                raise AssertionError("Нельзя преобразовывать неизвестный объект в строку.")

        cycle = []
        cycle.append(cycle)
        for value in (
            Foreign(), b"private", {1: "private"}, ("private",), {"private"},
            float("nan"), float("inf"), cycle, 10 ** 5000,
        ):
            with self.subTest(value_type=type(value).__name__):
                error = self.assert_error(KeeneticDeviceErrorCode.DATA, KeeneticDevice, {"mac": MAC, "unknown": value})
                self.assertNotIn("private", str(error))
        for settings in ([], None, "private"):
            self.assert_error(KeeneticDeviceErrorCode.DATA, KeeneticDevice, settings)
        self.assert_error(KeeneticDeviceErrorCode.DATA, KeeneticDevice, record(), details=[])

    def test_foreign_container_and_scalar_subclasses_are_not_evaluated(self):
        class ForeignDict(dict):
            def items(self):
                raise AssertionError("Нельзя вызывать хук словаря.")

        class ForeignStr(str):
            def __str__(self):
                raise AssertionError("Нельзя вызывать хук строки.")

        class ForeignInt(int):
            def __int__(self):
                raise AssertionError("Нельзя вызывать хук числа.")

        for value in (ForeignDict(private=True), ForeignStr("private"), ForeignInt(7)):
            self.assert_error(KeeneticDeviceErrorCode.DATA, KeeneticDevice, {"mac": MAC, "unknown": value})
        self.assert_error(KeeneticDeviceErrorCode.DATA, KeeneticDevice, ForeignDict(mac=MAC))
        self.assert_error(KeeneticDeviceErrorCode.DATA, KeeneticDevice, {"mac": MAC}, details=ForeignDict())
        self.assert_error(KeeneticDeviceErrorCode.DATA, KeeneticDevice, {"mac": MAC, ForeignStr("private"): 7})

    def test_repr_diagnostics_and_errors_do_not_disclose_private_data(self):
        settings = {**record(), "name": "fixture-private-name", "unknown-private-key": "fixture-private-secret"}
        device = KeeneticDevice(settings, details={"private": "fixture-private-detail"})
        diagnostic = device.to_diagnostic()
        self.assertEqual(diagnostic, {"assignment": "unassigned", "read_only": False, "access_denied": True})
        reachable_result = reachable(diagnostic)
        for value in (MAC, "192.0.2.17", "fixture-private-name", "fixture-private-secret", "fixture-private-detail"):
            self.assertNotIn(value, repr(device))
            self.assertNotIn(value, json.dumps(diagnostic))
            self.assertNotIn(value, [item for item in reachable_result if type(item) is str])
        try:
            raise ValueError("fixture-private-context")
        except ValueError:
            error = self.assert_error(KeeneticDeviceErrorCode.MAC, KeeneticDevice, {"mac": "fixture-private-mac"})
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn("fixture-private", repr(error))

    def test_snapshot_all_devices_keep_registration_observation_and_unknown_fields(self):
        snapshot = load_keenetic_snapshot()
        before = deepcopy(snapshot)
        policies = policies_from_rci(snapshot["ip/policy"])
        # Используем принятый контракт динамического определения policy ID.
        resolved = resolve_policy(policies, "fixture-policy-3")
        target = DevicePolicyAssignment(DevicePolicyMode.EXPLICIT, resolved.policy_id)
        denied = inherited = unassigned = offline = 0
        for settings in snapshot["ip/hotspot"]["host"]:
            mac = settings["mac"]
            details = {
                "registration": {name: entry for name, entry in snapshot["known/host"].items() if entry["mac"] == mac},
                "observation": next(entry for entry in snapshot["show/ip/hotspot"]["host"] if entry["mac"] == mac),
            }
            with forbid_external_effects():
                device = KeeneticDevice(settings, details=details)
                updated = device.with_assignment(target, policies=policies)
            denied += device.to_diagnostic()["access_denied"]
            inherited += device.assignment.mode is DevicePolicyMode.INHERIT
            unassigned += device.assignment.mode is DevicePolicyMode.UNASSIGNED
            offline += not details["observation"]["active"]
            self.assertEqual(updated.assignment, target)
            self.assertEqual(updated.export()["details"], details)
            self.assertEqual(without_assignment(updated.export()["settings"]), without_assignment(settings))
            self.assertEqual(device.export(), {"settings": settings, "details": details})
        self.assertEqual((len(snapshot["ip/hotspot"]["host"]), denied, inherited, unassigned, offline), (19, 1, 2, 2, 7))
        self.assertEqual(snapshot, before)


if __name__ == "__main__":
    unittest.main()
