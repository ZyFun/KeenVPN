"""Раздельный учёт MAC, наблюдений и безопасный выбор записи устройства."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.keenetic_device import (
    DeviceIdentity, DevicePolicyAssignment, DevicePolicyMode, DevicePresence,
    KeeneticDevice, KeeneticDeviceError, KeeneticDeviceErrorCode, KeeneticDeviceInventory,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import load_keenetic_snapshot


OLD_MAC = "02:00:00:00:00:Ab"
NEW_MAC = "02:00:00:00:00:Cd"
WIRED_MAC = "00:00:5e:00:53:01"
POLICIES = KeeneticPolicySet((KeeneticPolicy("Policy17"), KeeneticPolicy("Policy42")))


def device(mac, active, *, policy=None, interface="Bridge0", access="deny"):
    """Искусственные записи с намеренно одинаковыми именем и IP."""
    settings = {"mac": mac, "access": access, "priority": 6, "extension": {"values": [3, 1]}}
    if policy is not None:
        settings["policy"] = policy
    return KeeneticDevice(settings, details={"observation": {
        "mac": mac, "active": active, "name": "fixture-same-name", "ip": "192.0.2.17",
        "registered": policy is not None, "interface": {"id": interface},
    }})


class KeeneticDeviceIdentityTests(unittest.TestCase):
    def assert_error(self, code, function, *args):
        with self.assertRaises(KeeneticDeviceError) as caught:
            function(*args)
        self.assertIs(caught.exception.code, code)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception

    def test_private_mac_offline_record_and_other_interface_remain_separate(self):
        with forbid_external_effects():
            old = device(OLD_MAC, False, policy="Policy17")
            new = device(NEW_MAC, True, access="permit")
            wired = device(WIRED_MAC, True, policy="Policy42")
            inventory = KeeneticDeviceInventory((old, new, wired))
            before = [item.export() for item in inventory.devices]
            selected = inventory.select(NEW_MAC.lower())
            changed = selected.with_assignment(
                DevicePolicyAssignment(DevicePolicyMode.EXPLICIT, "Policy42"), policies=POLICIES,
            )
        self.assertEqual(len({item.identity for item in inventory.devices}), 3)
        self.assertIs(inventory.select(OLD_MAC), old)
        self.assertIs(selected, new)
        self.assertIs(inventory.select(WIRED_MAC), wired)
        self.assertIs(new.assignment.mode, DevicePolicyMode.UNASSIGNED)
        self.assertEqual(old.assignment.policy_id, "Policy17")
        self.assertTrue(old.to_diagnostic()["access_denied"])
        self.assertFalse(new.to_diagnostic()["access_denied"])
        self.assertIs(old.export()["details"]["observation"]["registered"], True)
        self.assertIs(new.export()["details"]["observation"]["registered"], False)
        self.assertEqual(changed.assignment.policy_id, "Policy42")
        self.assertEqual(changed.identity, new.identity)
        self.assertEqual(changed.export()["details"], new.export()["details"])
        self.assertEqual(changed.export()["settings"], {**before[1]["settings"], "policy": "Policy42"})
        self.assertEqual([item.export() for item in inventory.devices], before)
        self.assertEqual(inventory.to_diagnostic(), {
            "record_count": 3, "distinct_mac_count": 3,
            "online_count": 2, "offline_count": 1, "unknown_count": 0,
            "observation_mismatch_count": 0,
        })

    def test_identity_ignores_case_and_observation_but_preserves_original_mac(self):
        old = device(OLD_MAC, False)
        moved = device(OLD_MAC.lower(), True, interface="Bridge1")
        data = moved.export()
        data["details"]["observation"].update(name="fixture-renamed", ip="192.0.2.18")
        moved = KeeneticDevice(data["settings"], details=data["details"])
        self.assertEqual(old.identity, moved.identity)
        self.assertEqual(hash(old.identity), hash(moved.identity))
        self.assertEqual(old.export()["settings"]["mac"], OLD_MAC)
        self.assertEqual(old.observed_interface_id, "Bridge0")
        self.assertEqual(moved.observed_interface_id, "Bridge1")
        self.assertNotEqual(old.presence, moved.presence)
        self.assertNotEqual(old.identity, device(NEW_MAC, False).identity)
        with self.assertRaises(FrozenInstanceError):
            old.identity.mac = NEW_MAC

    def test_missing_or_invalid_observation_is_unknown_not_offline(self):
        for observation in (None, [], {}, {"active": False}, {"mac": NEW_MAC, "active": False}):
            with self.subTest(observation=observation):
                details = {"active": False, "interface": {"id": "Bridge0"}, "observation": observation}
                record = KeeneticDevice({"mac": OLD_MAC}, details=details)
                self.assertIs(record.presence, DevicePresence.UNKNOWN)
                self.assertIsNone(record.observed_interface_id)
                self.assertEqual(record.export()["details"], details)
        self.assertIs(KeeneticDevice({"mac": OLD_MAC}).presence, DevicePresence.UNKNOWN)

    def test_only_boolean_activity_of_matching_mac_is_used(self):
        for active, expected in (
            (False, DevicePresence.OFFLINE), (True, DevicePresence.ONLINE),
            (0, DevicePresence.UNKNOWN), (1, DevicePresence.UNKNOWN),
            ("false", DevicePresence.UNKNOWN), (None, DevicePresence.UNKNOWN),
        ):
            with self.subTest(active=active):
                record = device(OLD_MAC, active)
                data = record.export()
                data["details"]["observation"]["mac"] = OLD_MAC.lower()
                record = KeeneticDevice(data["settings"], details=data["details"])
                self.assertIs(record.presence, expected)
                self.assertEqual(record.observed_interface_id, "Bridge0")
                self.assertTrue(record.to_diagnostic()["access_denied"])
                self.assertEqual(record.export(), data)

    def test_observation_mismatch_is_visible_without_disclosing_or_changing_data(self):
        cases = (
            ({}, False, DevicePresence.UNKNOWN),
            ({"observation": None}, False, DevicePresence.UNKNOWN),
            ({"observation": []}, False, DevicePresence.UNKNOWN),
            ({"observation": {"active": False}}, False, DevicePresence.UNKNOWN),
            ({"observation": {"mac": None}}, False, DevicePresence.UNKNOWN),
            ({"observation": {"mac": 7}}, False, DevicePresence.UNKNOWN),
            ({"observation": {"mac": OLD_MAC.lower(), "active": False}}, False, DevicePresence.OFFLINE),
            ({"observation": {"mac": OLD_MAC, "active": True}}, False, DevicePresence.ONLINE),
            ({"observation": {"mac": NEW_MAC, "active": False}}, True, DevicePresence.UNKNOWN),
            ({"observation": {"mac": "fixture-invalid-mac", "active": True}}, True, DevicePresence.UNKNOWN),
        )
        records = []
        with forbid_external_effects():
            for details, mismatch, presence in cases:
                record = KeeneticDevice({"mac": OLD_MAC}, details=details)
                records.append(record)
                self.assertIs(record.to_diagnostic()["observation_mismatch"], mismatch)
                self.assertIs(record.presence, presence)
                self.assertIsNone(record.observed_interface_id)
                self.assertFalse(record.read_only)
                self.assertEqual(record.export(), {"settings": {"mac": OLD_MAC}, "details": details})
                changed = record.with_assignment(
                    DevicePolicyAssignment(DevicePolicyMode.EXPLICIT, "Policy17"), policies=POLICIES,
                )
                self.assertIs(changed.to_diagnostic()["observation_mismatch"], mismatch)
                self.assertEqual(changed.export()["details"], details)
            diagnostic = KeeneticDeviceInventory(tuple(records)).to_diagnostic()
        self.assertEqual(diagnostic["observation_mismatch_count"], 2)
        self.assertEqual(diagnostic["unknown_count"], 8)
        output = json.dumps([record.to_diagnostic() for record in records]) + json.dumps(diagnostic)
        for private in (OLD_MAC, OLD_MAC.lower(), NEW_MAC, "fixture-invalid-mac"):
            self.assertNotIn(private, output)

    def test_interface_is_preserved_without_guessing_client_connection_type(self):
        for interface, expected in (
            ({"id": "Bridge0", "extension": [1]}, "Bridge0"),
            ({"id": "fixture-private-interface"}, "fixture-private-interface"),
            ({"id": ""}, None), ({"id": "  "}, None), ({"id": 7}, None),
            ({"name": "Ethernet"}, None), ("Ethernet", None), (None, None),
        ):
            with self.subTest(interface=interface):
                details = {"observation": {"mac": OLD_MAC, "active": False, "interface": interface}}
                record = KeeneticDevice({"mac": OLD_MAC}, details=details)
                self.assertEqual(record.observed_interface_id, expected)
                self.assertIs(record.presence, DevicePresence.OFFLINE)
                self.assertEqual(record.export()["details"], details)

    def test_duplicate_mac_is_ambiguous_even_with_single_online_record(self):
        offline, online = device(OLD_MAC, False), device(OLD_MAC.lower(), True, interface="Bridge1")
        another = device(NEW_MAC, True)
        for records in ((offline, online, another), (online, offline, another), (offline, offline, another)):
            with self.subTest(first_active=records[0].presence), forbid_external_effects():
                inventory = KeeneticDeviceInventory(records)
                self.assertEqual(inventory.devices, records)
                self.assert_error(KeeneticDeviceErrorCode.AMBIGUOUS, inventory.select, OLD_MAC)
                self.assertIs(inventory.select(NEW_MAC), another)
                self.assertEqual(inventory.to_diagnostic()["distinct_mac_count"], 2)

    def test_missing_mac_never_falls_back_to_name_ip_or_other_record(self):
        for records in ((), (device(OLD_MAC, True),)):
            inventory = KeeneticDeviceInventory(records)
            self.assert_error(KeeneticDeviceErrorCode.MISSING, inventory.select, NEW_MAC)
            for value in ("fixture-same-name", "192.0.2.17", None, OLD_MAC + "\n", 1):
                self.assert_error(KeeneticDeviceErrorCode.MAC, inventory.select, value)
        self.assertEqual(KeeneticDeviceInventory(()).to_diagnostic(), {
            "record_count": 0, "distinct_mac_count": 0,
            "online_count": 0, "offline_count": 0, "unknown_count": 0,
            "observation_mismatch_count": 0,
        })

    def test_diagnostic_counts_keep_unknown_separate_from_offline(self):
        inventory = KeeneticDeviceInventory((
            device(OLD_MAC, False), device(NEW_MAC, True), KeeneticDevice({"mac": WIRED_MAC}),
        ))
        self.assertEqual(inventory.to_diagnostic(), {
            "record_count": 3, "distinct_mac_count": 3,
            "online_count": 1, "offline_count": 1, "unknown_count": 1,
            "observation_mismatch_count": 0,
        })

    def test_foreign_types_are_rejected_without_hooks(self):
        class ForeignTuple(tuple):
            def __iter__(self):
                raise AssertionError("Нельзя обращаться к чужому контейнеру.")

        class ForeignDevice(KeeneticDevice):
            @property
            def identity(self):
                raise AssertionError("Нельзя обращаться к чужой модели.")

        class ForeignStr(str):
            def lower(self):
                raise AssertionError("Нельзя обращаться к чужой строке.")

        for records in (None, [], (None,), ForeignTuple(()), (ForeignDevice({"mac": OLD_MAC}),)):
            self.assert_error(KeeneticDeviceErrorCode.INVENTORY, KeeneticDeviceInventory, records)
        self.assert_error(KeeneticDeviceErrorCode.MAC, DeviceIdentity, ForeignStr(OLD_MAC))

    def test_diagnostics_and_error_chains_do_not_disclose_private_data(self):
        record = device(OLD_MAC, False, interface="fixture-private-interface")
        inventory = KeeneticDeviceInventory((record,))
        output = repr(record.identity) + repr(inventory) + json.dumps(inventory.to_diagnostic())
        for marker in (OLD_MAC, OLD_MAC.lower(), "fixture-same-name", "192.0.2.17", "fixture-private-interface"):
            self.assertNotIn(marker, output)
        for records, selected, code in (
            ((), OLD_MAC, KeeneticDeviceErrorCode.MISSING),
            ((record, record), OLD_MAC, KeeneticDeviceErrorCode.AMBIGUOUS),
            ((record,), "fixture-private-input", KeeneticDeviceErrorCode.MAC),
        ):
            try:
                raise ValueError("fixture-private-context")
            except ValueError:
                error = self.assert_error(code, KeeneticDeviceInventory(records).select, selected)
            self.assertNotIn("fixture-private", str(error))
            self.assertNotIn(OLD_MAC, str(error))

    def test_snapshot_preserves_all_records_including_offline(self):
        snapshot = load_keenetic_snapshot()
        before = deepcopy(snapshot)
        records = tuple(KeeneticDevice(settings, details={"observation": next(
            row for row in snapshot["show/ip/hotspot"]["host"] if row["mac"] == settings["mac"]
        )}) for settings in snapshot["ip/hotspot"]["host"])
        with forbid_external_effects():
            inventory = KeeneticDeviceInventory(records)
            self.assertEqual(inventory.to_diagnostic(), {
                "record_count": 19, "distinct_mac_count": 19,
                "online_count": 12, "offline_count": 7, "unknown_count": 0,
                "observation_mismatch_count": 0,
            })
            for record in records:
                self.assertIs(inventory.select(record.identity.mac), record)
                observation = record.export()["details"]["observation"]
                self.assertEqual(record.observed_interface_id, observation.get("interface", {}).get("id"))
        self.assertEqual(snapshot, before)
        self.assertEqual([item.export()["settings"] for item in inventory.devices], snapshot["ip/hotspot"]["host"])


if __name__ == "__main__":
    unittest.main()
