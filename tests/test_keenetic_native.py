"""Прочитанное состояние Keenetic: раздельные источники, сопоставление по MAC и безопасный вывод."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.keenetic_device import (
    DeviceIdentity, DevicePolicyMode, DevicePresence, KeeneticDevice, KeeneticDeviceError, KeeneticDeviceErrorCode,
    KeeneticDeviceInventory,
)
from keenvpn.domain.keenetic_native import (
    KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticNativeError, KeeneticNativeErrorCode,
    KeeneticNativeState, KeeneticRegistrations, KeeneticSegmentAssignment, SegmentPolicyMode,
    assemble_keenetic_state, validate_hotspot_runtime, validate_hotspot_settings, validate_keenetic_state,
    validate_registrations,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import (
    load_keenetic_snapshot, policies_from_rci, snapshot_hotspot_runtime, snapshot_hotspot_settings,
    snapshot_registrations,
)


# Строки снимка и искусственных записей, которые не должны попадать в вывод.
PRIVATE_MARKERS = (
    "02:00:00:54", "02:00:00:00", "device-", "192.0.2.", "2001:db8", "fixture-policy",
    "fixture-interface", "fixture-private",
)
MAC_A = "02:00:00:00:00:A1"
MAC_B = "02:00:00:00:00:b2"
MAC_C = "02:00:00:00:00:c3"
POLICIES = KeeneticPolicySet((
    KeeneticPolicy("Policy7", "fixture-private-vpn"), KeeneticPolicy("Policy8", "fixture-private-direct"),
))


def hotspot(*hosts, segments=()):
    return KeeneticHotspotSettings({"host": list(hosts), "policy": list(segments), "auto-register": {"disable": False}})


def registrations(**entries):
    return KeeneticRegistrations(dict(entries))


def runtime(*entries):
    return KeeneticHotspotRuntime({"host": list(entries)})


def observation(mac, **fields):
    return {"mac": mac, "ip": "192.0.2.77", "name": "fixture-private-observed", "active": True, **fields}


class SnapshotAssemblyTests(unittest.TestCase):
    def assert_private(self, text):
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)

    def test_snapshot_sources_are_matched_by_mac_without_merging(self):
        snapshot = load_keenetic_snapshot()
        before = deepcopy(snapshot)
        policies = policies_from_rci(snapshot["ip/policy"])
        # Фикстура читается заранее: сама сборка не должна обращаться к файлам.
        hotspot, registrations, runtime = snapshot_hotspot_settings(), snapshot_registrations(), snapshot_hotspot_runtime()
        with forbid_external_effects():
            state = assemble_keenetic_state(policies, hotspot, registrations, runtime)
            diagnostic = state.to_diagnostic()
        self.assertEqual(snapshot, before)
        self.assertEqual(len(state.devices.devices), len(snapshot["ip/hotspot"]["host"]))
        for device, settings in zip(state.devices.devices, snapshot["ip/hotspot"]["host"], strict=True):
            mac = settings["mac"]
            expected_details = {
                "registration": {name: entry for name, entry in snapshot["known/host"].items() if entry["mac"] == mac},
                "observation": next(entry for entry in snapshot["show/ip/hotspot"]["host"] if entry["mac"] == mac),
            }
            self.assertEqual(device.export(), {"settings": settings, "details": expected_details})
        self.assertEqual(
            [segment.export() for segment in state.segments], snapshot["ip/hotspot"]["policy"],
        )
        self.assertEqual(state.registrations_without_device, ())
        self.assertEqual(state.runtime_without_device, ())
        self.assertEqual(state.ambiguous_observations, ())
        self.assertEqual(diagnostic, {
            "policy_count": 3, "policy_ids": ["Policy10", "Policy20", "Policy30"],
            "segments": [
                {"segment_id": "Bridge0", "assignment": "explicit", "policy_id": "Policy10",
                 "access_denied": False, "read_only": False},
                {"segment_id": "Bridge1", "assignment": "unassigned", "policy_id": None,
                 "access_denied": True, "read_only": False},
            ],
            "segment_missing_policy_count": 0,
            "devices": {
                "record_count": 19, "distinct_mac_count": 19, "online_count": 12, "offline_count": 7,
                "unknown_count": 0, "observation_mismatch_count": 0, "explicit_count": 15, "inherit_count": 2,
                "unassigned_count": 2, "unknown_assignment_count": 0, "access_denied_count": 1,
                "read_only_count": 0, "with_registration_count": 19, "with_observation_count": 19,
                "ambiguous_observation_count": 0, "missing_policy_count": 0,
            },
            "registrations": {
                "registration_count": 19, "distinct_mac_count": 19, "duplicate_mac_count": 0,
                "unresolvable_count": 0, "without_device_count": 0,
            },
            "runtime": {
                "record_count": 19, "distinct_mac_count": 19, "duplicate_mac_count": 0, "unresolvable_count": 0,
                "active_count": 12, "registered_count": 19, "without_device_count": 0,
            },
        })
        self.assertEqual(json.loads(json.dumps(diagnostic)), diagnostic)
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(state) + repr(state.hotspot)
        text += repr(state.registrations) + repr(state.runtime) + repr(state.segments)
        self.assert_private(text)
        self.assertEqual(repr(state), "KeeneticNativeState(policies=3, records=19, segments=2)")

    def test_segment_assignment_is_not_segment_composition(self):
        # Состав сегмента не выводится по наблюдаемому интерфейсу записей.
        state = assemble_keenetic_state(
            policies_from_rci(load_keenetic_snapshot()["ip/policy"]), snapshot_hotspot_settings(),
            snapshot_registrations(), snapshot_hotspot_runtime(),
        )
        self.assertFalse(any(hasattr(segment, "devices") for segment in state.segments))
        observed = {device.observed_interface_id for device in state.devices.devices}
        self.assertEqual(observed, {"Bridge0", None})
        self.assertEqual([segment.segment_id for segment in state.segments], ["Bridge0", "Bridge1"])


class SegmentAssignmentTests(unittest.TestCase):
    def assert_error(self, code, function, *args):
        with self.assertRaises(KeeneticNativeError) as caught:
            function(*args)
        self.assertIs(caught.exception.code, code)
        return caught.exception

    def test_modes_access_and_read_only_are_separate(self):
        cases = (
            ({"interface": "Bridge0", "policy": "Policy7"}, SegmentPolicyMode.EXPLICIT, "Policy7", False, False),
            ({"interface": "Bridge1", "access": "deny"}, SegmentPolicyMode.UNASSIGNED, None, True, False),
            ({"interface": "Bridge2"}, SegmentPolicyMode.UNASSIGNED, None, False, False),
            ({"interface": "Bridge3", "policy": ""}, SegmentPolicyMode.UNASSIGNED, None, False, False),
            ({"interface": "Bridge4", "policy": "bad id"}, SegmentPolicyMode.UNKNOWN, None, False, True),
            ({"interface": "Bridge5", "policy": 7}, SegmentPolicyMode.UNKNOWN, None, False, True),
            ({"interface": "Bridge6", "access": "maybe"}, SegmentPolicyMode.UNASSIGNED, None, False, True),
            ({"interface": "Bridge7", "deny": True}, SegmentPolicyMode.UNASSIGNED, None, True, False),
            ({"interface": "Bridge8", "access": "deny", "deny": False}, SegmentPolicyMode.UNASSIGNED, None, True, True),
            ({"interface": "Bridge9", "policy": "Policy7", "access": "deny"}, SegmentPolicyMode.EXPLICIT, "Policy7", True, False),
        )
        for settings, mode, policy_id, denied, read_only in cases:
            with self.subTest(settings=settings):
                assignment = KeeneticSegmentAssignment(settings)
                self.assertIs(assignment.mode, mode)
                self.assertEqual(assignment.policy_id, policy_id)
                self.assertEqual(assignment.access_denied, denied)
                self.assertEqual(assignment.read_only, read_only)
                self.assertEqual(assignment.to_diagnostic(), {
                    "segment_id": settings["interface"], "assignment": mode.value, "policy_id": policy_id,
                    "access_denied": denied, "read_only": read_only,
                })
                self.assertEqual(assignment.export(), settings)

    def test_export_is_isolated_and_repr_hides_identifiers(self):
        settings = {"interface": "Bridge0", "policy": "Policy7", "extension": {"ordered": [3, 1, 2], "flag": None}}
        assignment = KeeneticSegmentAssignment(settings)
        settings["extension"]["ordered"].append(9)
        exported = assignment.export()
        exported["policy"] = "Policy8"
        self.assertEqual(assignment.export(), {
            "interface": "Bridge0", "policy": "Policy7", "extension": {"ordered": [3, 1, 2], "flag": None},
        })
        self.assertEqual(repr(assignment), "KeeneticSegmentAssignment(<скрыто>)")
        self.assertNotIn("Bridge0", repr(assignment) + str(assignment))
        with self.assertRaises(FrozenInstanceError):
            assignment._snapshot = "{}"

    def test_rejects_missing_interface_and_unsupported_data(self):
        for settings in (
            {}, {"interface": ""}, {"interface": "bad id"}, {"interface": 5}, {"interface": None},
            "Bridge0", ["Bridge0"], {"interface": "Bridge0", "weird": {1: 2}},
            {"interface": "Bridge0", "ratio": float("nan")}, {"interface": "Bridge0", "value": object()},
        ):
            with self.subTest(settings=type(settings).__name__):
                error = self.assert_error(KeeneticNativeErrorCode.SEGMENT_ASSIGNMENT, KeeneticSegmentAssignment, settings)
                self.assertNotIn("Bridge0", str(error))
                self.assertNotIn("bad id", str(error))


class HotspotSettingsTests(unittest.TestCase):
    def test_keeps_unknown_fields_and_exposes_records_and_segments(self):
        document = {
            "policy": [{"interface": "Bridge0", "policy": "Policy7"}, {"interface": "Bridge1", "access": "deny"}],
            "host": [{"mac": MAC_A, "policy": "Policy7"}, {"mac": MAC_B, "conform": True, "name": "fixture-private-host"}],
            "auto-register": {"disable": False},
            "unknown": {"nested": [None, 1.5, "fixture-private-value"]},
        }
        before = deepcopy(document)
        with forbid_external_effects():
            settings = KeeneticHotspotSettings(document)
        document["host"].clear()
        self.assertEqual(settings.export(), before)
        self.assertEqual(settings.host_settings, tuple(before["host"]))
        self.assertEqual([item.export() for item in settings.segment_assignments], before["policy"])
        self.assertEqual(settings.to_diagnostic(), {
            "host_record_count": 2, "segment_count": 2, "segment_explicit_count": 1, "segment_unassigned_count": 1,
            "segment_unknown_count": 0, "segment_denied_count": 1,
        })
        self.assertEqual(repr(settings), "KeeneticHotspotSettings(hosts=2, segments=2)")
        self.assertNotIn("fixture-private", repr(settings) + json.dumps(settings.to_diagnostic()))
        validate_hotspot_settings(settings)
        empty = KeeneticHotspotSettings({})
        self.assertEqual((empty.host_settings, empty.segment_assignments), ((), ()))

    def test_rejects_unsupported_structure_and_propagates_record_errors(self):
        for document, error, code in (
            ({"host": {"mac": MAC_A}}, KeeneticNativeError, KeeneticNativeErrorCode.HOTSPOT_SETTINGS),
            ({"host": [MAC_A]}, KeeneticNativeError, KeeneticNativeErrorCode.HOTSPOT_SETTINGS),
            ({"policy": {"interface": "Bridge0"}}, KeeneticNativeError, KeeneticNativeErrorCode.HOTSPOT_SETTINGS),
            ([{"mac": MAC_A}], KeeneticNativeError, KeeneticNativeErrorCode.HOTSPOT_SETTINGS),
            ({"host": [{"mac": "fixture-private-mac"}]}, KeeneticDeviceError, KeeneticDeviceErrorCode.MAC),
            ({"host": [{"name": "fixture-private-host"}]}, KeeneticDeviceError, KeeneticDeviceErrorCode.MAC),
            ({"policy": [{"policy": "Policy7"}]}, KeeneticNativeError, KeeneticNativeErrorCode.SEGMENT_ASSIGNMENT),
        ):
            with self.subTest(document=document), self.assertRaises(error) as caught:
                KeeneticHotspotSettings(document)
            self.assertIs(caught.exception.code, code)
            self.assertNotIn("fixture-private", str(caught.exception))

    def test_validation_detects_tampered_snapshot_and_foreign_types(self):
        class Derived(KeeneticHotspotSettings):
            pass

        settings = hotspot({"mac": MAC_A})
        for broken in (Derived({"host": [{"mac": MAC_A}]}), {"host": []}, None):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(KeeneticNativeError) as caught:
                validate_hotspot_settings(broken)
            self.assertIs(caught.exception.code, KeeneticNativeErrorCode.HOTSPOT_SETTINGS)
        object.__setattr__(settings, "_snapshot", json.dumps({"host": [{"mac": "fixture-private-mac"}]}))
        with self.assertRaises(KeeneticDeviceError):
            validate_hotspot_settings(settings)
        mismatched = hotspot({"mac": MAC_A}, segments=({"interface": "Bridge0"},))
        object.__setattr__(mismatched, "segment_assignments", ())
        with self.assertRaises(KeeneticNativeError) as caught:
            validate_hotspot_settings(mismatched)
        self.assertIs(caught.exception.code, KeeneticNativeErrorCode.HOTSPOT_SETTINGS)
        # JSON-типы различаются: true и 1, false и 0 не считаются одинаковыми назначениями.
        for original, substituted in ((True, 1), (False, 0), (1, True), (0, False)):
            with self.subTest(original=original, substituted=substituted):
                typed = hotspot(segments=({"interface": "Bridge1", "deny": original},))
                object.__setattr__(
                    typed, "segment_assignments",
                    (KeeneticSegmentAssignment({"interface": "Bridge1", "deny": substituted}),),
                )
                with self.assertRaises(KeeneticNativeError) as caught:
                    validate_hotspot_settings(typed)
                self.assertIs(caught.exception.code, KeeneticNativeErrorCode.HOTSPOT_SETTINGS)


class RegistrationsAndRuntimeTests(unittest.TestCase):
    def test_registrations_resolve_only_valid_macs_and_hide_names(self):
        document = {
            "fixture-private-name-1": {"mac": MAC_A},
            "fixture-private-name-2": {"mac": MAC_A.lower(), "extra": True},
            "fixture-private-name-3": {"mac": "fixture-private-mac"},
            "fixture-private-name-4": {},
            "fixture-private-name-5": {"mac": MAC_C},
        }
        before = deepcopy(document)
        with forbid_external_effects():
            model = KeeneticRegistrations(document)
        document.clear()
        self.assertEqual(model.export(), before)
        self.assertEqual(model.identities, (DeviceIdentity(MAC_A), DeviceIdentity(MAC_A), DeviceIdentity(MAC_C)))
        matched = model.for_identity(DeviceIdentity(MAC_A.lower()))
        self.assertEqual(matched, {name: before[name] for name in ("fixture-private-name-1", "fixture-private-name-2")})
        matched["fixture-private-name-1"]["mac"] = MAC_B
        self.assertEqual(model.export(), before)
        self.assertEqual(model.for_identity(DeviceIdentity(MAC_B)), {})
        self.assertEqual(model.to_diagnostic(), {
            "registration_count": 5, "distinct_mac_count": 2, "duplicate_mac_count": 1, "unresolvable_count": 2,
        })
        self.assertEqual(repr(model), "KeeneticRegistrations(count=5)")
        validate_registrations(model)
        for document, code in (
            ({"fixture-private-name": MAC_A}, KeeneticNativeErrorCode.REGISTRATIONS),
            ([{"mac": MAC_A}], KeeneticNativeErrorCode.REGISTRATIONS),
        ):
            with self.subTest(document=document), self.assertRaises(KeeneticNativeError) as caught:
                KeeneticRegistrations(document)
            self.assertIs(caught.exception.code, code)
            self.assertNotIn("fixture-private", str(caught.exception))
        with self.assertRaises(KeeneticNativeError):
            model.for_identity(MAC_A)
        object.__setattr__(model, "_snapshot", json.dumps({"fixture-private-name": []}))
        with self.assertRaises(KeeneticNativeError):
            validate_registrations(model)

    def test_runtime_counts_lookup_and_rejections(self):
        entries = [
            observation(MAC_A), observation(MAC_A.lower(), active=False),
            observation(MAC_B, active="yes", registered=True), {"mac": "fixture-private-mac", "active": True},
            {"name": "fixture-private-nameless", "active": True},
        ]
        before = deepcopy(entries)
        with forbid_external_effects():
            model = KeeneticHotspotRuntime({"host": entries, "extra": "fixture-private-value"})
        entries.clear()
        self.assertEqual(model.observations, tuple(before))
        self.assertEqual(model.identities, (DeviceIdentity(MAC_A), DeviceIdentity(MAC_A), DeviceIdentity(MAC_B)))
        self.assertEqual(model.for_identity(DeviceIdentity(MAC_A)), (before[0], before[1]))
        self.assertEqual(model.for_identity(DeviceIdentity(MAC_C)), ())
        self.assertEqual(model.to_diagnostic(), {
            "record_count": 5, "distinct_mac_count": 2, "duplicate_mac_count": 1, "unresolvable_count": 2,
            "active_count": 3, "registered_count": 1,
        })
        self.assertEqual(repr(model), "KeeneticHotspotRuntime(count=5)")
        self.assertNotIn("fixture-private", repr(model) + json.dumps(model.to_diagnostic()))
        validate_hotspot_runtime(model)
        self.assertEqual(KeeneticHotspotRuntime({}).observations, ())
        for document in ({"host": {"mac": MAC_A}}, {"host": [MAC_A]}, [observation(MAC_A)], None):
            with self.subTest(document=type(document).__name__), self.assertRaises(KeeneticNativeError) as caught:
                KeeneticHotspotRuntime(document)
            self.assertIs(caught.exception.code, KeeneticNativeErrorCode.HOTSPOT_RUNTIME)
        with self.assertRaises(KeeneticNativeError):
            model.for_identity(MAC_A)
        object.__setattr__(model, "_snapshot", json.dumps({"host": "fixture-private"}))
        with self.assertRaises(KeeneticNativeError):
            validate_hotspot_runtime(model)


class AssemblyTests(unittest.TestCase):
    def build(self):
        hosts = hotspot(
            {"mac": MAC_A, "policy": "Policy7", "priority": 3},
            {"mac": MAC_B, "policy": "Policy9", "access": "deny", "deny": True},
            segments=({"interface": "Bridge0", "policy": "Policy9"}, {"interface": "Bridge1", "access": "deny"}),
        )
        known = registrations(**{
            "fixture-private-name-a": {"mac": MAC_A.lower()},
            "fixture-private-name-c": {"mac": MAC_C},
            # Одинаковое имя с другим MAC не объединяет записи.
            "fixture-private-name-a2": {"mac": MAC_C.upper()},
        })
        observed = runtime(observation(MAC_A), observation(MAC_A.lower(), active=False), observation(MAC_C))
        return hosts, known, observed

    def test_unmatched_and_ambiguous_records_are_reported_not_merged(self):
        hosts, known, observed = self.build()
        with forbid_external_effects():
            state = assemble_keenetic_state(POLICIES, hosts, known, observed)
            diagnostic = state.to_diagnostic()
        first, second = state.devices.devices
        self.assertEqual(first.export()["details"], {"registration": {"fixture-private-name-a": {"mac": MAC_A.lower()}}})
        self.assertIs(first.presence, DevicePresence.UNKNOWN)
        self.assertEqual(second.export()["details"], {})
        self.assertEqual(second.export()["settings"], hosts.host_settings[1])
        self.assertEqual(state.ambiguous_observations, (DeviceIdentity(MAC_A),))
        self.assertEqual(state.registrations_without_device, (DeviceIdentity(MAC_C),))
        self.assertEqual(state.runtime_without_device, (DeviceIdentity(MAC_C),))
        self.assertEqual([segment.policy_id for segment in state.segments], ["Policy9", None])
        self.assertEqual(diagnostic["segment_missing_policy_count"], 1)
        self.assertEqual(diagnostic["devices"], {
            "record_count": 2, "distinct_mac_count": 2, "online_count": 0, "offline_count": 0, "unknown_count": 2,
            "observation_mismatch_count": 0, "explicit_count": 2, "inherit_count": 0, "unassigned_count": 0,
            "unknown_assignment_count": 0, "access_denied_count": 1, "read_only_count": 0,
            "with_registration_count": 1, "with_observation_count": 0, "ambiguous_observation_count": 1,
            "missing_policy_count": 1,
        })
        self.assertEqual(diagnostic["registrations"], {
            "registration_count": 3, "distinct_mac_count": 2, "duplicate_mac_count": 1, "unresolvable_count": 0,
            "without_device_count": 1,
        })
        self.assertEqual(diagnostic["runtime"], {
            "record_count": 3, "distinct_mac_count": 2, "duplicate_mac_count": 1, "unresolvable_count": 0,
            "active_count": 2, "registered_count": 0, "without_device_count": 1,
        })
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(state)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertFalse(any(isinstance(item, (KeeneticDevice, DeviceIdentity)) for item in reachable(diagnostic)))

    def test_single_observation_and_unassigned_policy_keep_existing_semantics(self):
        hosts = hotspot({"mac": MAC_A}, {"mac": MAC_B, "conform": True})
        state = assemble_keenetic_state(POLICIES, hosts, registrations(), runtime(observation(MAC_A.lower())))
        first, second = state.devices.devices
        self.assertEqual(first.export()["details"]["observation"], observation(MAC_A.lower()))
        self.assertIs(first.presence, DevicePresence.ONLINE)
        self.assertIs(first.assignment.mode, DevicePolicyMode.UNASSIGNED)
        self.assertIs(second.assignment.mode, DevicePolicyMode.INHERIT)
        self.assertIs(second.presence, DevicePresence.UNKNOWN)
        self.assertEqual(state.to_diagnostic()["devices"]["unassigned_count"], 1)
        self.assertEqual(state.segments, ())

    def test_state_rejects_inconsistent_fields_and_wrong_types(self):
        hosts, known, observed = self.build()
        state = assemble_keenetic_state(POLICIES, hosts, known, observed)
        validate_keenetic_state(state)
        swapped = KeeneticDeviceInventory(tuple(reversed(state.devices.devices)))
        for field_name, value, code in (
            ("devices", swapped, KeeneticNativeErrorCode.STATE),
            ("devices", KeeneticDeviceInventory(state.devices.devices[:1]), KeeneticNativeErrorCode.STATE),
            ("devices", state.devices.devices, KeeneticNativeErrorCode.STATE),
            ("registrations_without_device", (), KeeneticNativeErrorCode.STATE),
            ("runtime_without_device", [DeviceIdentity(MAC_C)], KeeneticNativeErrorCode.STATE),
            ("ambiguous_observations", (DeviceIdentity(MAC_B),), KeeneticNativeErrorCode.STATE),
            ("policies", POLICIES.policies, KeeneticNativeErrorCode.POLICIES),
            ("hotspot", hosts.export(), KeeneticNativeErrorCode.HOTSPOT_SETTINGS),
            ("registrations", known.export(), KeeneticNativeErrorCode.REGISTRATIONS),
            ("runtime", observed.export(), KeeneticNativeErrorCode.HOTSPOT_RUNTIME),
        ):
            with self.subTest(field=field_name, value=type(value).__name__):
                fields = {name: getattr(state, name) for name in state.__dataclass_fields__}
                fields[field_name] = value
                with self.assertRaises(KeeneticNativeError) as caught:
                    KeeneticNativeState(**fields)
                self.assertIs(caught.exception.code, code)
        # Запись с deny: 1 вместо deny: true не проходит как та же запись.
        for original, substituted in ((True, 1), (False, 0)):
            with self.subTest(original=original, substituted=substituted):
                typed_hosts = hotspot({"mac": MAC_A, "deny": original})
                typed_state = assemble_keenetic_state(POLICIES, typed_hosts, registrations(), runtime())
                fields = {name: getattr(typed_state, name) for name in typed_state.__dataclass_fields__}
                fields["devices"] = KeeneticDeviceInventory((KeeneticDevice({"mac": MAC_A, "deny": substituted}),))
                with self.assertRaises(KeeneticNativeError) as caught:
                    KeeneticNativeState(**fields)
                self.assertIs(caught.exception.code, KeeneticNativeErrorCode.STATE)
        corrupted = assemble_keenetic_state(POLICIES, hosts, known, observed)
        object.__setattr__(corrupted, "ambiguous_observations", ())
        with self.assertRaises(KeeneticNativeError) as caught:
            validate_keenetic_state(corrupted)
        self.assertIs(caught.exception.code, KeeneticNativeErrorCode.STATE)
        broken_policies = KeeneticPolicySet(POLICIES.policies)
        object.__setattr__(broken_policies, "policies", POLICIES.policies + (POLICIES.policies[0],))
        for arguments, code in (
            ((broken_policies, hosts, known, observed), KeeneticNativeErrorCode.POLICIES),
            ((None, hosts, known, observed), KeeneticNativeErrorCode.POLICIES),
            ((POLICIES, None, known, observed), KeeneticNativeErrorCode.HOTSPOT_SETTINGS),
            ((POLICIES, hosts, None, observed), KeeneticNativeErrorCode.REGISTRATIONS),
            ((POLICIES, hosts, known, None), KeeneticNativeErrorCode.HOTSPOT_RUNTIME),
        ):
            with self.subTest(code=code), self.assertRaises(KeeneticNativeError) as caught:
                assemble_keenetic_state(*arguments)
            self.assertIs(caught.exception.code, code)
        with self.assertRaises(FrozenInstanceError):
            state.devices = swapped

    def test_assembly_parses_each_source_a_bounded_number_of_times(self):
        """Число разборов источников не растёт с числом записей: сопоставление линейно."""
        measurements = []
        for size in (20, 40):
            macs = [f"02:00:00:00:{index >> 8:02x}:{index & 255:02x}" for index in range(size)]
            hosts = hotspot(*({"mac": mac} for mac in macs))
            known = registrations(**{f"fixture-private-{index}": {"mac": mac} for index, mac in enumerate(macs)})
            observed = runtime(*(observation(mac) for mac in macs))
            with (
                patch.object(KeeneticRegistrations, "export", autospec=True, side_effect=KeeneticRegistrations.export) as reg,
                patch.object(KeeneticHotspotRuntime, "export", autospec=True, side_effect=KeeneticHotspotRuntime.export) as run,
                forbid_external_effects(),
            ):
                state = assemble_keenetic_state(POLICIES, hosts, known, observed)
            self.assertEqual(state.to_diagnostic()["devices"]["with_observation_count"], size)
            measurements.append((reg.call_count, run.call_count))
        self.assertEqual(measurements[0], measurements[1])
        self.assertGreater(measurements[0][0], 0)

    def test_errors_are_detached_from_foreign_context_and_hide_values(self):
        for function, argument in (
            (KeeneticSegmentAssignment, {"interface": "fixture-private interface"}),
            (KeeneticHotspotSettings, {"host": "fixture-private"}),
            (KeeneticRegistrations, {"fixture-private-name": "fixture-private"}),
            (KeeneticHotspotRuntime, {"host": "fixture-private"}),
        ):
            with self.subTest(function=function.__name__):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(KeeneticNativeError) as caught:
                        function(argument)
                error = caught.exception
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertNotIn("fixture-private", str(error) + repr(error))


if __name__ == "__main__":
    unittest.main()
