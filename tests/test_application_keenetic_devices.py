"""Список устройств Keenetic для меню на снимке и управляемых источниках.

Сценарий проверяется без роутера: имена хостов, адреса, MAC и описания политик
не должны достигать результата, имена регистраций допустимы только в своих полях.
"""

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.keenetic_devices import (
    ASSIGNMENT_LABELS, MAX_DEVICE_NAME_LENGTH, PRESENCE_LABELS, PRESENCE_REASON_LABELS, SEGMENT_MATCH_LABELS,
    DeviceCountsView, DeviceEntryView, DeviceListView, ListKeeneticDevices, ListKeeneticDevicesHandler,
    PresenceReason, SegmentMatch, valid_device_name,
)
from keenvpn.application.keenetic_state import (
    InspectKeeneticState, InspectKeeneticStateHandler, KeeneticSegmentView, KeeneticStateView,
)
from keenvpn.domain.keenetic_device import DeviceIdentity, DevicePolicyMode, DevicePresence, KeeneticDevice, KeeneticDeviceInventory
from keenvpn.domain.keenetic_native import (
    KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticNativeState, KeeneticRegistrations, KeeneticSegmentAssignment,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet, PolicyResolution
from tests.support.in_memory import (
    InMemoryKeeneticHotspotRuntimeSource, InMemoryKeeneticHotspotSettingsSource, InMemoryKeeneticPolicySource,
    InMemoryKeeneticRegistrationSource,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import snapshot_keenetic_sources


NAME_MARKER = "TEST_ONLY_DEVICE_NAME"
SECOND_NAME = "Второе имя устройства"
HOSTNAME = "private-host.example.test"
PRIVATE_MARKERS = (
    "02:00:00:54", "02:00:00:00", "192.0.2.", "2001:db8", "198.51.100", "fixture-policy", "fixture-interface",
    "fixture-private", HOSTNAME, "TEST_HOSTNAME", "orphan", "privatehost", "Bridge9",
)
NAME_FIELDS = frozenset({"name", "registration_names"})
PRIVATE_TYPES = (
    KeeneticPolicy, KeeneticPolicySet, PolicyResolution, KeeneticDevice, KeeneticDeviceInventory, DeviceIdentity,
    KeeneticHotspotSettings, KeeneticRegistrations, KeeneticHotspotRuntime, KeeneticSegmentAssignment,
    KeeneticNativeState, BaseException,
)
SOURCES = ("policies", "hotspot", "registrations", "runtime")
UNAVAILABLE_CODES = {
    "policies": "keenetic_policies_unavailable", "hotspot": "keenetic_hotspot_unavailable",
    "registrations": "keenetic_registrations_unavailable", "runtime": "keenetic_runtime_unavailable",
}
INVALID_CODES = {
    "policies": "invalid_keenetic_policies", "hotspot": "invalid_keenetic_hotspot",
    "registrations": "invalid_keenetic_registrations", "runtime": "invalid_keenetic_runtime",
}
# Записи снимка в порядке `ip/hotspot.host`: назначение, ID политики, online, наблюдаемый интерфейс.
SNAPSHOT_DEVICES = [
    ("explicit", "Policy10", "online", "Bridge0"), ("explicit", "Policy10", "online", "Bridge0"),
    ("explicit", "Policy10", "offline", None), ("explicit", "Policy10", "online", "Bridge0"),
    ("explicit", "Policy10", "online", "Bridge0"), ("unassigned", None, "offline", None),
    ("explicit", "Policy10", "offline", None), ("unassigned", None, "online", "Bridge0"),
    ("explicit", "Policy30", "offline", None), ("explicit", "Policy10", "offline", None),
    ("explicit", "Policy30", "online", "Bridge0"), ("inherit", None, "online", "Bridge0"),
    ("explicit", "Policy10", "online", "Bridge0"), ("explicit", "Policy10", "online", "Bridge0"),
    ("inherit", None, "online", "Bridge0"), ("explicit", "Policy30", "offline", None),
    ("explicit", "Policy30", "offline", "Bridge0"), ("explicit", "Policy10", "online", "Bridge0"),
    ("explicit", "Policy30", "online", "Bridge0"),
]
BRIDGE0 = KeeneticSegmentView("Bridge0", "explicit", "Policy10", False, False)
BRIDGE1 = KeeneticSegmentView("Bridge1", "unassigned", None, True, False)
SNAPSHOT_COUNTS = {
    "record_count": 19, "distinct_mac_count": 19, "duplicate_mac_count": 0, "online_count": 12, "offline_count": 7,
    "unknown_count": 0, "explicit_count": 15, "inherit_count": 2, "unassigned_count": 2, "unknown_assignment_count": 0,
    "missing_policy_count": 0, "access_denied_count": 1, "read_only_count": 0, "hidden_name_count": 0,
    "ambiguous_observation_count": 0, "registrations_without_device_count": 0, "runtime_without_device_count": 0,
}

MAC_A, MAC_B, MAC_C, MAC_E, MAC_F, MAC_Z = (f"02:00:00:00:00:{suffix}" for suffix in ("a1", "b2", "c3", "e5", "f6", "ff"))
_DEFAULT = object()


def strings_outside_names(value, key=None):
    """Все строки JSON-представления, кроме значений под полями имён."""
    if isinstance(value, dict):
        return [text for item_key, item in value.items() for text in strings_outside_names(item, item_key)]
    if isinstance(value, list):
        return [text for item in value for text in strings_outside_names(item, key)]
    return [value] if isinstance(value, str) and key not in NAME_FIELDS else []


def calls_after_failure(index):
    return tuple(1 if position <= index else 0 for position in range(len(SOURCES)))


def synthetic_sources():
    """Искусственные источники: имена регистраций отличаются от имён хостов, адреса только документальные.

    Записи: A — явная отсутствующая политика, MAC повторяется с D, единственное наблюдение
    поэтому неоднозначно; B — запрет доступа без регистрации, наблюдаемый интерфейс с двумя
    назначениями сегмента; C — наследование, две регистрации (вторая скрыта пробелами),
    признак активности строкой, интерфейс без назначения; D — повтор MAC A без наблюдения;
    E — явная политика из списка, имя регистрации с управляющим символом, offline в Bridge0;
    F — неизвестное назначение, интерфейс недопустимого формата.
    """
    hotspot = KeeneticHotspotSettings({
        "host": [
            {"mac": MAC_A, "policy": "Policy9"},
            {"mac": MAC_B, "access": "deny", "deny": True},
            {"mac": MAC_C, "conform": True},
            {"mac": MAC_A.upper(), "policy": "Policy7"},
            {"mac": MAC_E, "policy": "Policy7", "priority": 2},
            {"mac": MAC_F, "policy": 5},
        ],
        "policy": [
            {"interface": "Bridge0", "policy": "Policy7"},
            {"interface": "Bridge1", "access": "deny"},
            {"interface": "Bridge1", "policy": "Policy7"},
        ],
    })
    registrations = KeeneticRegistrations({
        NAME_MARKER: {"mac": MAC_A},
        SECOND_NAME: {"mac": MAC_C},
        " в пробелах ": {"mac": MAC_C.upper()},
        "имя\x1bс ESC": {"mac": MAC_E},
        "orphan": {"mac": MAC_Z},
    })
    runtime = KeeneticHotspotRuntime({"host": [
        {"mac": MAC_A, "active": True, "hostname": "TEST_HOSTNAME", "interface": {"id": "Bridge0"}},
        {"mac": MAC_B, "active": True, "hostname": HOSTNAME, "ip": "198.51.100.7", "ip6": ["2001:db8::7"],
         "interface": {"id": "Bridge1", "name": "fixture-interface"}},
        {"mac": MAC_C, "active": "yes", "interface": {"id": "Bridge9"}},
        {"mac": MAC_E, "active": False, "interface": {"id": "Bridge0"}},
        {"mac": MAC_F, "active": True, "interface": {"id": "Bridge 0"}},
        {"mac": MAC_Z, "active": True, "hostname": "orphan-host"},
    ]})
    return (
        InMemoryKeeneticPolicySource(KeeneticPolicySet((KeeneticPolicy("Policy7", "fixture-private-vpn"),))),
        InMemoryKeeneticHotspotSettingsSource(hotspot),
        InMemoryKeeneticRegistrationSource(registrations),
        InMemoryKeeneticHotspotRuntimeSource(runtime),
    )


class ScenarioCase(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_keenetic_sources()
        self.handler = self.build(
            self.sources.policies, self.sources.hotspot, self.sources.registrations, self.sources.runtime,
        )

    @staticmethod
    def build(policies, hotspot, registrations, runtime):
        keenetic = InspectKeeneticStateHandler(policies, hotspot, registrations, runtime, operation_ids=lambda: "op")
        return ListKeeneticDevicesHandler(keenetic, operation_ids=lambda: "op-devices")

    def execute(self, command=_DEFAULT):
        return self.handler.execute(ListKeeneticDevices() if command is _DEFAULT else command)

    def assert_private(self, result):
        dumped = result.to_dict()
        text = repr(result) + str(result) + json.dumps(dumped, ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        for item in strings_outside_names(dumped):
            for marker in ("device-", NAME_MARKER, SECOND_NAME, "пробелах", "ESC"):
                self.assertNotIn(marker, item)
        self.assertFalse([type(item).__name__ for item in reachable(result) if isinstance(item, PRIVATE_TYPES)])

    def assert_failed(self, result, category, code, reason=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertEqual((result.error.category, result.error.code, result.error.reason), (category, code, reason))
        self.assert_private(result)


class ListKeeneticDevicesTests(ScenarioCase):
    def test_snapshot_lists_records_in_source_order_with_registration_names(self):
        with forbid_external_effects():
            result = self.execute()
        self.assertTrue(result.succeeded, result.error)
        self.assertEqual(result.to_dict()["command"], "list_keenetic_devices")
        self.assertEqual(self.sources.calls, (1, 1, 1, 1))
        data = result.data
        self.assertIs(type(data), DeviceListView)
        self.assertEqual((data.policy_count, data.policy_ids), (3, ("Policy10", "Policy20", "Policy30")))
        self.assertEqual(data.segments, (BRIDGE0, BRIDGE1))
        self.assertEqual(data.segment_missing_policy_count, 0)
        self.assertEqual(len(data.devices), 19)
        self.assertEqual([item.position for item in data.devices], list(range(19)))
        self.assertEqual([item.name for item in data.devices], [f"device-{number:02d}" for number in range(1, 20)])
        self.assertTrue(all(item.name_known and item.registration_count == 1 for item in data.devices))
        self.assertEqual(
            [(item.assignment, item.policy_id, item.presence, item.observed_interface_id) for item in data.devices],
            SNAPSHOT_DEVICES,
        )
        self.assertEqual({item.policy_present for item in data.devices if item.assignment == "explicit"}, {True})
        self.assertEqual({item.policy_present for item in data.devices if item.assignment != "explicit"}, {None})
        self.assertEqual({item.presence_reason for item in data.devices}, {None})
        self.assertEqual([item.access_denied for item in data.devices].count(True), 1)
        self.assertTrue(data.devices[5].access_denied)
        self.assertFalse(any(item.read_only or item.mac_duplicate for item in data.devices))
        for item in data.devices:
            with self.subTest(position=item.position):
                if item.observed_interface_id is None:
                    self.assertEqual((item.observed_interface_known, item.segment_match, item.segment),
                                     (False, SegmentMatch.NOT_OBSERVED.value, None))
                else:
                    self.assertEqual((item.observed_interface_known, item.segment_match, item.segment),
                                     (True, SegmentMatch.MATCHED.value, BRIDGE0))
        self.assertEqual(data.counts, DeviceCountsView(**SNAPSHOT_COUNTS))
        self.assert_private(result)

    def test_to_dict_is_json_compatible_and_keeps_names_only_in_name_fields(self):
        result = self.execute()
        dumped = result.data.to_dict()
        self.assertEqual(json.loads(json.dumps(dumped, ensure_ascii=False)), dumped)
        self.assertEqual(set(dumped), {"policy_count", "policy_ids", "segments", "segment_missing_policy_count", "counts", "devices"})
        self.assertEqual(dumped["segments"][1], {
            "segment_id": "Bridge1", "assignment": "unassigned", "policy_id": None, "access_denied": True, "read_only": False,
        })
        self.assertEqual(dumped["counts"], SNAPSHOT_COUNTS)
        self.assertEqual(dumped["devices"][0], {
            "position": 0, "registration_count": 1, "registration_names": ["device-01"], "name_known": True,
            "name": "device-01", "assignment": "explicit", "policy_id": "Policy10", "policy_present": True,
            "presence": "online", "presence_reason": None, "access_denied": False, "read_only": False,
            "mac_duplicate": False, "observed_interface_known": True, "observed_interface_id": "Bridge0",
            "segment_match": "matched",
            "segment": {"segment_id": "Bridge0", "assignment": "explicit", "policy_id": "Policy10",
                        "access_denied": False, "read_only": False},
        })
        self.assertEqual(dumped["devices"][2]["segment"], None)
        self.assertEqual(dumped["devices"][2]["segment_match"], "not_observed")
        self.assert_private(result)

    def test_synthetic_sources_show_each_state_without_hosts_addresses_or_macs(self):
        handler = self.build(*synthetic_sources())
        with forbid_external_effects():
            result = handler.execute(ListKeeneticDevices())
        self.assertTrue(result.succeeded, result.error)
        data = result.data
        a, b, c, d, e, f = data.devices
        self.assertEqual((a.name_known, a.name, a.registration_count), (True, NAME_MARKER, 1))
        self.assertEqual((a.assignment, a.policy_id, a.policy_present), ("explicit", "Policy9", False))
        self.assertEqual((a.presence, a.presence_reason), ("unknown", PresenceReason.AMBIGUOUS_OBSERVATION.value))
        self.assertEqual((a.mac_duplicate, a.observed_interface_known, a.segment_match), (True, False, "not_observed"))

        self.assertEqual((b.name_known, b.name, b.registration_count, b.registration_names), (False, None, 0, ()))
        self.assertEqual((b.assignment, b.policy_id, b.policy_present, b.access_denied), ("unassigned", None, None, True))
        self.assertEqual((b.presence, b.presence_reason), ("online", None))
        self.assertEqual((b.observed_interface_known, b.observed_interface_id), (True, "Bridge1"))
        self.assertEqual((b.segment_match, b.segment), (SegmentMatch.AMBIGUOUS.value, None))

        self.assertEqual((c.name_known, c.name, c.registration_count), (False, None, 2))
        self.assertEqual(c.registration_names, (SECOND_NAME, None))
        self.assertEqual((c.assignment, c.presence, c.presence_reason), ("inherit", "unknown", PresenceReason.ACTIVE_UNKNOWN.value))
        # Интерфейс без назначения сегмента известен, но не показывается: наблюдение не подтверждено настройками.
        self.assertEqual((c.observed_interface_known, c.observed_interface_id, c.segment_match, c.segment),
                         (True, None, SegmentMatch.UNASSIGNED.value, None))

        self.assertEqual((d.registration_count, d.name_known, d.name), (1, True, NAME_MARKER))
        self.assertEqual((d.assignment, d.policy_id, d.policy_present, d.mac_duplicate), ("explicit", "Policy7", True, True))
        self.assertEqual((d.presence, d.presence_reason), ("unknown", PresenceReason.AMBIGUOUS_OBSERVATION.value))

        self.assertEqual((e.name_known, e.name, e.registration_names), (True, None, (None,)))
        self.assertEqual((e.presence, e.presence_reason, e.observed_interface_id), ("offline", None, "Bridge0"))
        self.assertEqual((e.segment_match, e.segment), ("matched", KeeneticSegmentView("Bridge0", "explicit", "Policy7", False, False)))

        self.assertEqual((f.assignment, f.policy_id, f.policy_present, f.read_only), ("unknown", None, None, True))
        self.assertEqual((f.observed_interface_known, f.observed_interface_id, f.segment_match), (True, None, SegmentMatch.UNASSIGNED.value))

        self.assertEqual(data.counts, DeviceCountsView(
            record_count=6, distinct_mac_count=5, duplicate_mac_count=2, online_count=2, offline_count=1,
            unknown_count=3, explicit_count=3, inherit_count=1, unassigned_count=1, unknown_assignment_count=1,
            missing_policy_count=1, access_denied_count=1, read_only_count=1, hidden_name_count=2,
            ambiguous_observation_count=2, registrations_without_device_count=1, runtime_without_device_count=1,
        ))
        self.assertEqual(data.segments, (
            KeeneticSegmentView("Bridge0", "explicit", "Policy7", False, False),
            KeeneticSegmentView("Bridge1", "unassigned", None, True, False),
            KeeneticSegmentView("Bridge1", "explicit", "Policy7", False, False),
        ))
        self.assert_private(result)

    def test_observed_interface_shaped_like_mac_address_or_host_is_hidden(self):
        # Регрессия review 75-R01: runtime может подставить в `interface.id` MAC, адрес или имя хоста.
        values = {
            "a1": MAC_A, "b2": "198.51.100.7", "c3": "2001:db8::7", "d4": "privatehost.example.test",
            "e5": "Bridge0",
        }
        hosts = [{"mac": f"02:00:00:00:00:{suffix}", "policy": "Policy7"} for suffix in values]
        runtime = [
            {"mac": f"02:00:00:00:00:{suffix}", "active": True, "interface": {"id": value}}
            for suffix, value in values.items()
        ]
        handler = self.build(
            InMemoryKeeneticPolicySource(KeeneticPolicySet((KeeneticPolicy("Policy7", "fixture-private-vpn"),))),
            InMemoryKeeneticHotspotSettingsSource(KeeneticHotspotSettings({
                "host": hosts, "policy": [{"interface": "Bridge0", "policy": "Policy7"}],
            })),
            InMemoryKeeneticRegistrationSource(KeeneticRegistrations({})),
            InMemoryKeeneticHotspotRuntimeSource(KeeneticHotspotRuntime({"host": runtime})),
        )
        result = handler.execute(ListKeeneticDevices())
        self.assertTrue(result.succeeded, result.error)
        hidden, bridge = result.data.devices[:4], result.data.devices[4]
        self.assertEqual(
            {(item.observed_interface_known, item.observed_interface_id, item.segment_match) for item in hidden},
            {(True, None, SegmentMatch.UNASSIGNED.value)},
        )
        self.assertEqual((bridge.observed_interface_id, bridge.segment_match), ("Bridge0", SegmentMatch.MATCHED.value))
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for value in (MAC_A, "198.51.100.7", "2001:db8::7", "privatehost.example.test", "privatehost"):
            self.assertNotIn(value, text)
        self.assert_private(result)

    def test_view_matches_the_state_view_of_the_same_sources(self):
        data = self.execute().data
        state = InspectKeeneticStateHandler(
            self.sources.policies, self.sources.hotspot, self.sources.registrations, self.sources.runtime,
        ).execute(InspectKeeneticState()).data
        self.assertIs(type(state), KeeneticStateView)
        self.assertEqual((data.policy_ids, data.segments, data.segment_missing_policy_count),
                         (state.policy_ids, state.segments, state.segment_missing_policy_count))
        self.assertEqual(
            (data.counts.record_count, data.counts.online_count, data.counts.offline_count, data.counts.unknown_count,
             data.counts.explicit_count, data.counts.inherit_count, data.counts.unassigned_count,
             data.counts.access_denied_count, data.counts.missing_policy_count),
            (state.devices.record_count, state.devices.online_count, state.devices.offline_count,
             state.devices.unknown_count, state.devices.explicit_count, state.devices.inherit_count,
             state.devices.unassigned_count, state.devices.access_denied_count, state.devices.missing_policy_count),
        )

    def test_each_source_failure_keeps_its_code_and_stops_reading(self):
        for index, name in enumerate(SOURCES):
            with self.subTest(source=name):
                sources = snapshot_keenetic_sources()
                getattr(sources, name).outcome = OSError(f"Отказ источника: fixture-private {HOSTNAME} 02:00:00:54:00:01")
                handler = self.build(sources.policies, sources.hotspot, sources.registrations, sources.runtime)
                self.assert_failed(handler.execute(ListKeeneticDevices()), ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name])
                self.assertEqual(sources.calls, calls_after_failure(index))
        for name in SOURCES:
            with self.subTest(source=name, outcome="None"):
                sources = snapshot_keenetic_sources()
                getattr(sources, name).outcome = None
                handler = self.build(sources.policies, sources.hotspot, sources.registrations, sources.runtime)
                self.assert_failed(handler.execute(ListKeeneticDevices()), ErrorCategory.INVALID_SOURCE_DATA, INVALID_CODES[name])

    def test_inconsistent_list_is_reported_without_partial_result(self):
        with patch.object(DeviceListView, "from_state", side_effect=TypeError("fixture-private")):
            result = self.execute()
        self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, "device_list_inconsistent")
        self.assertIsNotNone(result.error.next_step)
        self.assertEqual(self.sources.calls, (1, 1, 1, 1))

    def test_wrong_command_and_version_do_not_read_sources(self):
        for command in (None, "list", InspectKeeneticState()):
            with self.subTest(command=type(command).__name__):
                self.assert_failed(self.execute(command), ErrorCategory.INVALID_REQUEST, "invalid_command")
        for version in (True, CONTRACT_VERSION + 1):
            with self.subTest(version=version):
                self.assert_failed(
                    self.execute(ListKeeneticDevices(contract_version=version)),
                    ErrorCategory.INVALID_REQUEST, "unsupported_contract_version",
                )
        self.assertEqual(self.sources.calls, (0, 0, 0, 0))

    def test_interruptions_are_not_converted_to_source_failure(self):
        for name in SOURCES:
            for error in (KeyboardInterrupt(), SystemExit()):
                with self.subTest(source=name, error=type(error).__name__):
                    sources = snapshot_keenetic_sources()
                    getattr(sources, name).outcome = error
                    handler = self.build(sources.policies, sources.hotspot, sources.registrations, sources.runtime)
                    with self.assertRaises(type(error)):
                        handler.execute(ListKeeneticDevices())

    def test_rendering_is_frozen_and_does_not_reread_sources(self):
        result = self.execute()
        calls = self.sources.calls
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertIn("Policy10", str(result.data))
        self.assertEqual(self.sources.calls, calls)
        for model, field in (
            (result.data, "devices"), (result.data.devices[0], "name"), (result.data.counts, "record_count"),
            (result.data.segments[0], "policy_id"),
        ):
            with self.assertRaises(FrozenInstanceError):
                setattr(model, field, None)


class ViewInvariantTests(unittest.TestCase):
    def entry(self, **changes):
        values = {
            "position": 3, "registration_count": 1, "registration_names": ("Телефон",), "name_known": True,
            "name": "Телефон", "assignment": "explicit", "policy_id": "Policy7", "policy_present": True,
            "presence": "online", "presence_reason": None, "access_denied": False, "read_only": False,
            "mac_duplicate": False, "observed_interface_known": True, "observed_interface_id": "Bridge0",
            "segment_match": "matched", "segment": KeeneticSegmentView("Bridge0", "explicit", "Policy7", False, False),
        }
        values.update(changes)
        return DeviceEntryView(**values)

    def test_name_rule_matches_the_rule_name_limits(self):
        self.assertTrue(valid_device_name("Телефон 1"))
        self.assertTrue(valid_device_name("x" * MAX_DEVICE_NAME_LENGTH))
        for value in ("", " x", "x ", "a\x1bb", "a\nb", "x" * (MAX_DEVICE_NAME_LENGTH + 1), b"x", None, 7):
            with self.subTest(value=value):
                self.assertFalse(valid_device_name(value))

    def test_entry_checks_names_assignment_presence_and_segment_consistency(self):
        self.assertEqual(self.entry().name, "Телефон")
        several = self.entry(registration_count=2, registration_names=("a", None), name_known=False, name=None)
        self.assertEqual(several.registration_names, ("a", None))
        none = self.entry(registration_count=0, registration_names=(), name_known=False, name=None)
        self.assertEqual(none.name, None)
        hidden = self.entry(registration_names=(None,), name=None)
        self.assertEqual((hidden.name_known, hidden.name), (True, None))
        inherit = self.entry(assignment="inherit", policy_id=None, policy_present=None)
        self.assertEqual(inherit.policy_present, None)
        unknown = self.entry(presence="unknown", presence_reason="no_observation", observed_interface_known=False,
                             observed_interface_id=None, segment_match="not_observed", segment=None)
        self.assertEqual(unknown.segment, None)
        for changes in (
            {"position": -1}, {"position": True}, {"registration_count": 2}, {"registration_names": ["Телефон"]},
            {"registration_names": (" x",)}, {"name_known": False}, {"name": "Другое"}, {"name": None},
            {"registration_count": 0, "registration_names": (), "name_known": True, "name": None},
            {"assignment": "direct"}, {"assignment": DevicePolicyMode.EXPLICIT}, {"policy_id": None},
            {"policy_id": "bad id"}, {"policy_present": None}, {"assignment": "inherit", "policy_present": None},
            {"assignment": "unassigned", "policy_id": None}, {"presence": "active"}, {"presence": DevicePresence.ONLINE},
            {"presence_reason": "no_observation"}, {"presence": "unknown"}, {"presence": "unknown", "presence_reason": "lost"},
            {"access_denied": 1}, {"read_only": None}, {"mac_duplicate": "no"},
            {"observed_interface_known": False}, {"observed_interface_id": None},
            {"observed_interface_id": "Bridge 0"}, {"observed_interface_id": "x" * 129}, {"segment_match": "found"},
            {"segment_match": "unassigned", "segment": None}, {"segment_match": "ambiguous", "segment": None, "observed_interface_id": None},
            {"segment_match": SegmentMatch.MATCHED}, {"segment": None}, {"segment_match": "unassigned"},
            {"observed_interface_known": False, "observed_interface_id": None, "segment_match": "unassigned", "segment": None},
            {"segment": {"segment_id": "Bridge0"}},
        ):
            with self.subTest(changes=changes), self.assertRaises(TypeError):
                self.entry(**changes)

    def test_counts_and_list_check_their_consistency(self):
        counts = DeviceCountsView(**SNAPSHOT_COUNTS)
        for field in SNAPSHOT_COUNTS:
            with self.subTest(field=field), self.assertRaises(TypeError):
                replace(counts, **{field: -1})
            with self.subTest(field=field, value="bool"), self.assertRaises(TypeError):
                replace(counts, **{field: True})
        entry = self.entry(position=0)
        counts = DeviceCountsView(
            record_count=1, distinct_mac_count=1, duplicate_mac_count=0, online_count=1, offline_count=0, unknown_count=0,
            explicit_count=1, inherit_count=0, unassigned_count=0, unknown_assignment_count=0, missing_policy_count=0,
            access_denied_count=0, read_only_count=0, hidden_name_count=0, ambiguous_observation_count=0,
            registrations_without_device_count=0, runtime_without_device_count=0,
        )
        segments = (entry.segment,)
        view = DeviceListView(1, ("Policy7",), segments, 0, counts, (entry,))
        self.assertEqual(view.devices, (entry,))
        self.assertEqual(DeviceListView(0, (), (), 0, replace(counts, record_count=0, distinct_mac_count=0, online_count=0, explicit_count=0), ()).devices, ())
        for arguments in (
            (1, ["Policy7"], segments, 0, counts, (entry,)),
            (2, ("Policy7",), segments, 0, counts, (entry,)),
            (1, ("Policy7",), list(segments), 0, counts, (entry,)),
            (1, ("Policy7",), segments, -1, counts, (entry,)),
            (1, ("Policy7",), segments, 0, None, (entry,)),
            (1, ("Policy7",), segments, 0, counts, [entry]),
            (1, ("Policy7",), segments, 0, counts, (self.entry(position=1),)),
            (1, ("Policy7",), segments, 0, replace(counts, online_count=0, unknown_count=1), (entry,)),
            (1, ("Policy7",), segments, 0, replace(counts, record_count=2), (entry,)),
            (1, ("Policy9",), segments, 0, counts, (entry,)),
            (1, ("Policy7",), segments, 0, counts, (self.entry(position=0, policy_present=False),)),
            (1, ("Policy7",), (), 0, counts, (entry,)),
            # Показанный интерфейс обязан быть ID одного из назначений сегментов списка.
            (1, ("Policy7",), segments, 0, counts, (self.entry(position=0, observed_interface_id="Bridge9", segment_match="ambiguous", segment=None),)),
        ):
            with self.subTest(arguments=arguments[:2] + arguments[3:4]), self.assertRaises(TypeError):
                DeviceListView(*arguments)
        with self.assertRaises(TypeError):
            DeviceListView.from_state(None)

    def test_labels_cover_every_value_of_their_catalogs(self):
        self.assertEqual(set(ASSIGNMENT_LABELS), {mode.value for mode in DevicePolicyMode})
        self.assertEqual(set(PRESENCE_LABELS), {presence.value for presence in DevicePresence})
        self.assertEqual(set(PRESENCE_REASON_LABELS), {reason.value for reason in PresenceReason})
        self.assertEqual(set(SEGMENT_MATCH_LABELS), {match.value for match in SegmentMatch})
        for catalog in (ASSIGNMENT_LABELS, PRESENCE_LABELS, PRESENCE_REASON_LABELS, SEGMENT_MATCH_LABELS):
            self.assertTrue(all(label.isprintable() and label for label in catalog.values()))
            with self.assertRaises(TypeError):
                catalog["x"] = "y"


if __name__ == "__main__":
    unittest.main()
