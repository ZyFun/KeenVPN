"""Режимы выбранного сегмента без записи политик, I/O и объединения MAC."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.keenetic_device import (
    DeviceIdentity, DevicePolicyMode, KeeneticDevice, KeeneticDeviceError,
    KeeneticDeviceErrorCode, KeeneticDeviceInventory,
)
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet, resolve_policy
from keenvpn.domain.keenetic_segment import (
    KeeneticSegment, KeeneticSegmentError, KeeneticSegmentErrorCode,
    SegmentSelection, SegmentSelectionMode, preview_segment_selection,
)
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import load_keenetic_snapshot, policies_from_rci


FIRST = "02:00:00:00:00:AB"
SECOND = "02:00:00:00:00:CD"
THIRD = "00:00:5e:00:53:01"
POLICIES = KeeneticPolicySet((
    KeeneticPolicy("Policy17", "fixture-vpn"), KeeneticPolicy("Policy42", "fixture-direct"),
    KeeneticPolicy("Policy93", "fixture-other"),
))


def device(mac, *, assignment=None, active=False, access="deny"):
    """Несвязанные данные намеренно одинаковы у разных MAC."""
    settings = {
        "mac": mac, "name": "fixture-name", "ip": "192.0.2.11",
        "priority": 6, "schedule": "fixture-schedule", "extension": {"order": [3, 1]},
        **({"access": access} if access is not None else {}),
        **(assignment or {}),
    }
    return KeeneticDevice(settings, details={"observation": {
        "mac": mac, "name": "fixture-name", "active": active, "interface": {"id": "fixture-interface"},
    }})


def segment(*records, segment_id="Bridge7", policy_id=None):
    return KeeneticSegment(segment_id, KeeneticDeviceInventory(records), policy_id)


def preview(source, mode, *, selected=(), excluded=(), **kwargs):
    selection = SegmentSelection(
        source.segment_id, mode,
        tuple(DeviceIdentity(mac) for mac in selected), tuple(DeviceIdentity(mac) for mac in excluded),
    )
    return preview_segment_selection(
        source, selection, policies=kwargs.get("policies", POLICIES),
        vpn_policy_id=kwargs.get("vpn_policy_id", "Policy17"),
        direct_policy_id=kwargs.get("direct_policy_id", "Policy42"),
    )


class KeeneticSegmentTests(unittest.TestCase):
    def assert_error(self, error_type, code, function, *args, **kwargs):
        with self.assertRaises(error_type) as caught, forbid_external_effects():
            function(*args, **kwargs)
        self.assertIs(caught.exception.code, code)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception

    def test_selected_only_changes_selected_mac_and_uses_direct_default(self):
        old = device(FIRST, assignment={"conform": True})
        new = device(SECOND, active=True)
        wired = device(THIRD, assignment={"policy": "Policy93"})
        source = segment(old, new, wired)
        before = [item.export() for item in source.devices.devices]
        with forbid_external_effects():
            result = preview(source, SegmentSelectionMode.SELECTED_ONLY, selected=(SECOND.lower(),))
            self.assertEqual(result.policy_for(FIRST), "Policy42")
            self.assertEqual(result.policy_for(SECOND), "Policy17")
            self.assertEqual(result.policy_for(THIRD), "Policy93")
        self.assertEqual(result.new_device_mode, "direct")
        self.assertEqual(result.default_policy_id, "Policy42")
        self.assertEqual(result.changed_devices, (DeviceIdentity(SECOND),))
        self.assertIs(result.after.devices.select(FIRST), old)
        self.assertIs(result.after.devices.select(THIRD), wired)
        changed = result.after.devices.select(SECOND)
        self.assertEqual(changed.export()["settings"], {**before[1]["settings"], "policy": "Policy17"})
        self.assertEqual(changed.export()["details"], before[1]["details"])
        self.assertEqual([item.export() for item in source.devices.devices], before)

    def test_whole_segment_preserves_individual_policies_and_unassigned(self):
        records = (
            device(FIRST, assignment={"policy": "Policy42"}),
            device(SECOND, assignment={"conform": True}), device(THIRD),
        )
        with forbid_external_effects():
            result = preview(segment(*records), SegmentSelectionMode.WHOLE_SEGMENT)
            self.assertEqual(result.policy_for(FIRST), "Policy42")
            self.assertEqual(result.policy_for(SECOND), "Policy17")
            self.assertIsNone(result.policy_for(THIRD))
        self.assertEqual(result.after.devices.devices, records)
        self.assertEqual(result.changed_devices, ())
        self.assertEqual(result.new_device_mode, "vpn")
        self.assertEqual(result.to_diagnostic(), {
            "mode": "whole_segment", "new_device_mode": "vpn", "record_count": 3,
            "default_changed": None,
            "changed_device_count": 0, "preserved_explicit_count": 1,
            "conflicting_explicit_count": 1,
            "unresolved_device_count": 1, "access_denied_count": 3,
        })

    def test_exclusion_gets_explicit_direct_even_for_offline_denied_record(self):
        excluded = device(FIRST, assignment={"conform": True})
        inherits = device(SECOND, assignment={"conform": True}, active=True)
        individual = device(THIRD, assignment={"policy": "Policy93"})
        with forbid_external_effects():
            result = preview(segment(excluded, inherits, individual), SegmentSelectionMode.EXCEPT_SELECTED, excluded=(FIRST,))
            changed = result.after.devices.select(FIRST)
            self.assertEqual(result.policy_for(FIRST), "Policy42")
            self.assertEqual(result.policy_for(SECOND), "Policy17")
            self.assertEqual(result.policy_for(THIRD), "Policy93")
        expected = excluded.export()
        expected["settings"].pop("conform")
        expected["settings"]["policy"] = "Policy42"
        self.assertEqual(changed.export(), expected)
        self.assertTrue(changed.to_diagnostic()["access_denied"])
        self.assertEqual(result.new_device_mode, "vpn")
        self.assertEqual(result.changed_devices, (DeviceIdentity(FIRST),))

    def test_default_change_is_visible_without_individual_changes(self):
        for mode, before_policy, after_policy in (
            (SegmentSelectionMode.WHOLE_SEGMENT, "Policy42", "Policy17"),
            (SegmentSelectionMode.EXCEPT_SELECTED, "Policy42", "Policy17"),
            (SegmentSelectionMode.SELECTED_ONLY, "Policy17", "Policy42"),
        ):
            source = segment(device(FIRST, assignment={"conform": True}), policy_id=before_policy)
            with self.subTest(mode=mode), forbid_external_effects():
                result = preview(source, mode)
                self.assertEqual(result.changed_devices, ())
                self.assertNotEqual(result.before, result.after)
                self.assertEqual(result.before_default_policy_id, before_policy)
                self.assertEqual(result.after.policy_id, after_policy)
                self.assertIs(result.default_changed, True)
                self.assertIs(result.to_diagnostic()["default_changed"], True)
                self.assertEqual(result.policy_for(FIRST), after_policy)
                repeated = preview(result.after, mode)
                self.assertEqual(repeated.before, repeated.after)
                self.assertIs(repeated.default_changed, False)
            self.assertEqual(source.policy_id, before_policy)

    def test_unknown_default_remains_unknown_and_empty_segment_can_change_default(self):
        for previous, expected in ((None, None), ("Policy42", True), ("Policy17", False)):
            with self.subTest(previous=previous), forbid_external_effects():
                result = preview(segment(policy_id=previous), SegmentSelectionMode.WHOLE_SEGMENT)
                self.assertEqual(result.before_default_policy_id, previous)
                self.assertIs(result.default_changed, expected)
                self.assertIs(result.to_diagnostic()["default_changed"], expected)
                self.assertEqual(result.after.policy_id, "Policy17")
                self.assertEqual(result.changed_devices, ())

    def test_current_segment_policy_is_validated_without_fallback(self):
        for value in ("", "Policy17\n", 3, False):
            self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.SEGMENT, segment, policy_id=value)
        source = segment(policy_id="PolicyGone")
        for mode in SegmentSelectionMode:
            self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.POLICY_MISSING, preview, source, mode)
        damaged = segment(policy_id="Policy17")
        object.__setattr__(damaged, "policy_id", "fixture-invalid\n")
        self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.SEGMENT,
                          preview, damaged, SegmentSelectionMode.WHOLE_SEGMENT)

    def test_denied_count_distinguishes_mixed_records_and_preserves_both_deny_forms(self):
        source = segment(
            device(FIRST, access="deny"), device(SECOND, access="permit"),
            device(THIRD, access=None, assignment={"deny": True}),
            device("02:00:00:00:00:EF", access=None, assignment={"deny": False}),
        )
        before = [item.export() for item in source.devices.devices]
        self.assertEqual(sum(item.to_diagnostic()["access_denied"] for item in source.devices.devices), 2)
        for mode, choices in (
            (SegmentSelectionMode.SELECTED_ONLY, {"selected": (FIRST, THIRD)}),
            (SegmentSelectionMode.EXCEPT_SELECTED, {"excluded": (FIRST, THIRD)}),
            (SegmentSelectionMode.WHOLE_SEGMENT, {}),
        ):
            with self.subTest(mode=mode), forbid_external_effects():
                result = preview(source, mode, **choices)
                self.assertEqual(result.to_diagnostic()["record_count"], 4)
                self.assertEqual(result.to_diagnostic()["access_denied_count"], 2)
                for original, updated in zip(before, result.after.devices.devices):
                    settings = updated.export()["settings"]
                    for key in ("access", "deny", "permit"):
                        self.assertEqual(key in settings, key in original["settings"])
                        self.assertEqual(settings.get(key), original["settings"].get(key))
        self.assertEqual([item.export() for item in source.devices.devices], before)

    def test_other_segments_cannot_be_selected_or_modified(self):
        home = segment(device(FIRST, assignment={"conform": True}))
        guest = segment(device(SECOND, assignment={"policy": "Policy93"}), segment_id="Bridge8")
        before = guest.devices.select(SECOND).export()
        for mode in SegmentSelectionMode:
            with forbid_external_effects():
                preview(home, mode)
            self.assertEqual(guest.devices.select(SECOND).export(), before)
        self.assert_error(
            KeeneticSegmentError, KeeneticSegmentErrorCode.SCOPE_MISMATCH,
            preview_segment_selection, home, SegmentSelection(guest.segment_id, SegmentSelectionMode.WHOLE_SEGMENT),
            policies=POLICIES, vpn_policy_id="Policy17", direct_policy_id="Policy42",
        )
        for mode, field in (
            (SegmentSelectionMode.SELECTED_ONLY, "selected"), (SegmentSelectionMode.EXCEPT_SELECTED, "excluded"),
        ):
            self.assert_error(KeeneticDeviceError, KeeneticDeviceErrorCode.MISSING, preview, home, mode, **{field: (SECOND,)})

    def test_empty_segment_and_empty_choices_show_new_device_behavior(self):
        for mode, policy, new_mode in (
            (SegmentSelectionMode.SELECTED_ONLY, "Policy42", "direct"),
            (SegmentSelectionMode.WHOLE_SEGMENT, "Policy17", "vpn"),
            (SegmentSelectionMode.EXCEPT_SELECTED, "Policy17", "vpn"),
        ):
            with self.subTest(mode=mode), forbid_external_effects():
                result = preview(segment(), mode)
                self.assertEqual(result.default_policy_id, policy)
                self.assertEqual(result.new_device_mode, new_mode)
                self.assertEqual(result.to_diagnostic()["record_count"], 0)
            self.assert_error(KeeneticDeviceError, KeeneticDeviceErrorCode.MISSING, result.policy_for, FIRST)

    def test_current_unassigned_unknown_and_missing_policy_are_not_direct_fallback(self):
        for assignment in ({}, {"policy": ""}, {"conform": False}, {"policy": "PolicyGone"},
                           {"policy": "Policy17", "conform": True}, {"access": "fixture-unknown"}):
            record = device(FIRST, assignment=assignment)
            for mode in SegmentSelectionMode:
                with self.subTest(assignment=assignment, mode=mode), forbid_external_effects():
                    result = preview(segment(record), mode)
                    self.assertIs(result.after.devices.select(FIRST), record)
                    self.assertIsNone(result.policy_for(FIRST))
                    self.assertEqual(result.to_diagnostic()["unresolved_device_count"], 1)

    def test_explicit_vpn_outside_selection_is_preserved_and_visible(self):
        record = device(FIRST, assignment={"policy": "Policy17"})
        result = preview(segment(record), SegmentSelectionMode.SELECTED_ONLY)
        self.assertIs(result.after.devices.select(FIRST), record)
        self.assertEqual(result.policy_for(FIRST), "Policy17")
        self.assertEqual(result.to_diagnostic()["preserved_explicit_count"], 1)

    def test_individual_deviations_are_separate_from_default_and_explicit_choice(self):
        for mode, target, default, choices in (
            (SegmentSelectionMode.SELECTED_ONLY, "Policy17", "Policy42", {"selected": (FIRST,)}),
            (SegmentSelectionMode.EXCEPT_SELECTED, "Policy42", "Policy17", {"excluded": (FIRST,)}),
        ):
            # Выбранная запись уже имеет нужное назначение: это не конфликт.
            source = segment(device(FIRST, assignment={"policy": target}),
                             device(SECOND, assignment={"policy": target}),
                             device(THIRD, assignment={"policy": default}))
            with self.subTest(mode=mode), forbid_external_effects():
                result = preview(source, mode, **choices)
                self.assertEqual(result.changed_devices, ())
                self.assertEqual(result.conflicting_devices, (DeviceIdentity(SECOND),))
                self.assertEqual(result.to_diagnostic()["conflicting_explicit_count"], 1)
                self.assertEqual(result.to_diagnostic()["preserved_explicit_count"], 3)
                self.assertEqual(result.after.devices, source.devices)

    def test_third_policy_is_deviation_but_unknown_assignment_is_not(self):
        source = segment(device(FIRST, assignment={"policy": "Policy93"}),
                         device(SECOND, assignment={"policy": "PolicyGone"}),
                         device(THIRD, assignment={"conform": True}))
        for mode in SegmentSelectionMode:
            with self.subTest(mode=mode), forbid_external_effects():
                result = preview(source, mode)
                self.assertEqual(result.conflicting_devices, (DeviceIdentity(FIRST),))
                self.assertEqual(result.to_diagnostic()["conflicting_explicit_count"], 1)
                self.assertEqual(result.to_diagnostic()["unresolved_device_count"], 1)
                self.assertEqual(result.to_diagnostic()["preserved_explicit_count"], 2)
                self.assertNotIn(FIRST.lower(), json.dumps(result.to_diagnostic()))

    def test_read_only_selection_fails_without_partial_result_or_source_mutation(self):
        for mode, field in ((SegmentSelectionMode.SELECTED_ONLY, "selected"), (SegmentSelectionMode.EXCEPT_SELECTED, "excluded")):
            source = segment(device(FIRST), device(SECOND, assignment={"access": "fixture-unknown"}))
            before = [item.export() for item in source.devices.devices]
            self.assert_error(KeeneticDeviceError, KeeneticDeviceErrorCode.READ_ONLY, preview, source, mode, **{field: (FIRST, SECOND)})
            self.assertEqual([item.export() for item in source.devices.devices], before)

    def test_duplicate_mac_never_prefers_online_record_even_without_overrides(self):
        source = segment(device(FIRST), device(FIRST.lower(), active=True))
        for mode in SegmentSelectionMode:
            self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.DUPLICATE_DEVICE, preview, source, mode)

    def test_lists_are_unambiguous_and_match_mode(self):
        first = DeviceIdentity(FIRST)
        for mode, selected, excluded in (
            ("selected_only", (), ()), (None, (), ()),
            (SegmentSelectionMode.WHOLE_SEGMENT, (first,), ()),
            (SegmentSelectionMode.WHOLE_SEGMENT, (), (first,)),
            (SegmentSelectionMode.SELECTED_ONLY, (), (first,)),
            (SegmentSelectionMode.EXCEPT_SELECTED, (first,), ()),
            (SegmentSelectionMode.SELECTED_ONLY, (first, DeviceIdentity(FIRST.lower())), ()),
            (SegmentSelectionMode.EXCEPT_SELECTED, (), (first, first)),
            (SegmentSelectionMode.SELECTED_ONLY, [first], ()),
            (SegmentSelectionMode.SELECTED_ONLY, (FIRST,), ()),
        ):
            self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.SELECTION,
                              SegmentSelection, "Bridge7", mode, selected, excluded)

    def test_policy_roles_are_dynamic_distinct_and_present_without_fallback(self):
        source = segment(device(FIRST, assignment={"conform": True}))
        for vpn, direct in ((None, "Policy42"), ("PolicyMissing", "Policy42"), ("Policy17", None),
                            ("Policy17", "PolicyMissing"), ("Policy17", "Policy17"), ("Policy17\n", "Policy42")):
            self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.POLICY_TARGET,
                              preview, source, SegmentSelectionMode.WHOLE_SEGMENT, vpn_policy_id=vpn, direct_policy_id=direct)
        self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.POLICY_TARGET,
                          preview, source, SegmentSelectionMode.WHOLE_SEGMENT, policies=KeeneticPolicySet(()))
        for vpn, direct in (("Policy17", "Policy42"), ("Policy93", "Policy17")):
            result = preview(source, SegmentSelectionMode.EXCEPT_SELECTED, excluded=(FIRST,), vpn_policy_id=vpn, direct_policy_id=direct)
            self.assertEqual(result.default_policy_id, vpn)
            self.assertEqual(result.policy_for(FIRST), direct)

    def test_invalid_or_damaged_policy_list_is_rejected(self):
        damaged = KeeneticPolicySet((KeeneticPolicy("Policy17"), KeeneticPolicy("Policy42")))
        object.__setattr__(damaged.policies[0], "policy_id", "fixture-invalid-id\n")
        for policies in (None, (), damaged):
            self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.POLICIES,
                              preview, segment(), SegmentSelectionMode.WHOLE_SEGMENT, policies=policies)

    def test_repeated_preview_is_idempotent_and_mode_change_keeps_explicit_choices(self):
        source = segment(device(FIRST, assignment={"conform": True}), device(SECOND, assignment={"conform": True}))
        first = preview(source, SegmentSelectionMode.EXCEPT_SELECTED, excluded=(FIRST,))
        second = preview(first.after, SegmentSelectionMode.EXCEPT_SELECTED, excluded=(FIRST,))
        whole = preview(second.after, SegmentSelectionMode.WHOLE_SEGMENT)
        self.assertEqual(second.changed_devices, ())
        self.assertEqual(first.after, second.after)
        self.assertEqual(whole.policy_for(FIRST), "Policy42")
        self.assertEqual(whole.policy_for(SECOND), "Policy17")
        chosen = preview(whole.after, SegmentSelectionMode.SELECTED_ONLY, selected=(FIRST,))
        self.assertEqual(chosen.policy_for(FIRST), "Policy17")
        self.assertEqual(chosen.policy_for(SECOND), "Policy42")

    def test_source_order_not_selection_order_is_preserved(self):
        source = segment(device(FIRST), device(SECOND), device(THIRD))
        result = preview(source, SegmentSelectionMode.SELECTED_ONLY, selected=(THIRD, FIRST))
        self.assertEqual(tuple(item.identity for item in result.after.devices.devices), tuple(item.identity for item in source.devices.devices))
        self.assertEqual(result.changed_devices, (DeviceIdentity(FIRST), DeviceIdentity(THIRD)))

    def test_models_and_export_are_isolated(self):
        source = segment(device(FIRST))
        result = preview(source, SegmentSelectionMode.SELECTED_ONLY, selected=(FIRST,))
        data = result.after.devices.select(FIRST).export()
        data["settings"]["extension"]["order"].clear()
        self.assertEqual(result.after.devices.select(FIRST).export()["settings"]["extension"]["order"], [3, 1])
        self.assertIs(source.devices.select(FIRST).assignment.mode, DevicePolicyMode.UNASSIGNED)
        with self.assertRaises(FrozenInstanceError):
            result.default_policy_id = "Policy93"
        with self.assertRaises(FrozenInstanceError):
            source.segment_id = "Bridge8"

    def test_direct_preview_construction_rejects_inconsistent_fields(self):
        first, second = device(FIRST), device(SECOND)
        source = segment(first, second, policy_id="Policy42")
        result = preview(source, SegmentSelectionMode.SELECTED_ONLY, selected=(FIRST,))
        self.assertEqual(replace(result), result)
        invalid_fields = (
            {"selection": None}, {"before": None}, {"after": None},
            {"selection": SegmentSelection("Bridge8", SegmentSelectionMode.SELECTED_ONLY)},
            {"after": replace(result.after, segment_id="Bridge8")},
            {"after": replace(result.after, policy_id=None)},
            {"after": replace(result.after, policy_id="Policy93")},
            {"before": replace(result.before, policy_id="PolicyGone")},
            {"default_policy_id": "NotAPolicy\n"}, {"default_policy_id": "PolicyGone"},
            {"policy_ids": ()}, {"policy_ids": list(result.policy_ids)},
            {"policy_ids": result.policy_ids + ("Policy17",)}, {"policy_ids": (None,)},
            {"changed_devices": ()}, {"changed_devices": (DeviceIdentity(THIRD),)},
            {"changed_devices": result.changed_devices * 2}, {"changed_devices": [DeviceIdentity(FIRST)]},
            {"changed_devices": (FIRST,)},
            {"after": segment(second, first, policy_id="Policy42")},
            {"after": segment(first, policy_id="Policy42")},
            {"before": segment(first, first, policy_id="Policy42"),
             "after": segment(first, first, policy_id="Policy42")},
            {"selection": SegmentSelection("Bridge7", SegmentSelectionMode.SELECTED_ONLY, (DeviceIdentity(THIRD),))},
            {"selection": SegmentSelection("Bridge7", SegmentSelectionMode.SELECTED_ONLY)},
        )
        for fields in invalid_fields:
            with self.subTest(fields=tuple(fields)):
                self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.PREVIEW, replace, result, **fields)

    def test_preview_rejects_missing_or_wrong_explicit_override(self):
        for mode, field, target in (
            (SegmentSelectionMode.SELECTED_ONLY, "selected", "Policy17"),
            (SegmentSelectionMode.EXCEPT_SELECTED, "excluded", "Policy42"),
        ):
            source = segment(device(FIRST))
            result = preview(source, mode, **{field: (FIRST,)})
            for assignment in (None, {"conform": True}, {"policy": "Policy93"}):
                with self.subTest(mode=mode, assignment=assignment):
                    record = device(FIRST, assignment=assignment)
                    after = replace(result.after, devices=KeeneticDeviceInventory((record,)))
                    changed = () if record == source.devices.devices[0] else (DeviceIdentity(FIRST),)
                    self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.PREVIEW,
                                      replace, result, after=after, changed_devices=changed)
            repeated = preview(segment(device(FIRST, assignment={"policy": target})), mode, **{field: (FIRST,)})
            self.assertEqual(repeated.changed_devices, ())
            self.assertEqual(replace(repeated), repeated)

    def test_preview_validation_rejects_foreign_hooks_and_detaches_errors(self):
        class ForeignStr(str):
            def __eq__(self, other):
                raise AssertionError("Чужое сравнение запрещено.")

        class ForeignTuple(tuple):
            def __iter__(self):
                raise AssertionError("Чужая итерация запрещена.")

        result = preview(segment(), SegmentSelectionMode.WHOLE_SEGMENT)
        for fields in ({"default_policy_id": ForeignStr("Policy17")},
                       {"vpn_policy_id": ForeignStr("Policy17")},
                       {"direct_policy_id": ForeignStr("Policy42")},
                       {"policy_ids": ForeignTuple(result.policy_ids)},
                       {"changed_devices": ForeignTuple()},
                       {"selection": replace(result.selection, segment_id="fixture-private-segment")}):
            try:
                raise ValueError("fixture-private-context")
            except ValueError:
                error = self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.PREVIEW, replace, result, **fields)
            self.assertNotIn("fixture-private", repr(error))

    def test_preview_rejects_unrelated_changes_to_selected_record(self):
        for mode, field in ((SegmentSelectionMode.SELECTED_ONLY, "selected"),
                            (SegmentSelectionMode.EXCEPT_SELECTED, "excluded")):
            result = preview(segment(device(FIRST)), mode, **{field: (FIRST,)})
            for section, key, value in (
                ("settings", "access", "permit"), ("settings", "name", "fixture-changed"),
                ("settings", "extension", {}), ("details", "observation", {}),
            ):
                with self.subTest(mode=mode, section=section, key=key):
                    data = result.after.devices.devices[0].export()
                    data[section][key] = value
                    changed = KeeneticDevice(data["settings"], details=data["details"])
                    after = replace(result.after, devices=KeeneticDeviceInventory((changed,)))
                    self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.PREVIEW,
                                      replace, result, after=after)

    def test_preview_rejects_invalid_roles_and_default_for_mode(self):
        for mode in SegmentSelectionMode:
            result = preview(segment(), mode)
            for fields in (
                {"vpn_policy_id": None}, {"direct_policy_id": "PolicyGone"},
                {"vpn_policy_id": "Policy42"}, {"direct_policy_id": "Policy17"},
                {"vpn_policy_id": "Policy42", "direct_policy_id": "Policy17"},
            ):
                with self.subTest(mode=mode, fields=fields):
                    self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.PREVIEW,
                                      replace, result, **fields)

    def test_foreign_types_do_not_call_custom_hooks(self):
        class ForeignStr(str):
            def __eq__(self, other):
                raise AssertionError("Чужое сравнение запрещено.")

        class ForeignTuple(tuple):
            def __iter__(self):
                raise AssertionError("Чужая итерация запрещена.")

        for value in (None, "", "Bridge7\n", "Bridge7; command", "x" * 129, ForeignStr("Bridge7")):
            self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.SEGMENT, segment, segment_id=value)
        self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.SELECTION,
                          SegmentSelection, "Bridge7", SegmentSelectionMode.SELECTED_ONLY, ForeignTuple())
        for field in ("vpn_policy_id", "direct_policy_id"):
            self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.POLICY_TARGET,
                              preview, segment(), SegmentSelectionMode.WHOLE_SEGMENT, **{field: ForeignStr("Policy17")})
        for source, selection, code in (
            (None, SegmentSelection("Bridge7", SegmentSelectionMode.WHOLE_SEGMENT), KeeneticSegmentErrorCode.SEGMENT),
            (segment(), None, KeeneticSegmentErrorCode.SELECTION),
        ):
            self.assert_error(KeeneticSegmentError, code, preview_segment_selection, source, selection,
                              policies=POLICIES, vpn_policy_id="Policy17", direct_policy_id="Policy42")

    def test_safe_diagnostics_and_errors_hide_private_data_and_exception_context(self):
        source = segment(device(FIRST), segment_id="fixture-private-segment")
        result = preview(source, SegmentSelectionMode.SELECTED_ONLY, selected=(FIRST,))
        output = repr(source) + repr(result.selection) + repr(result) + json.dumps(result.to_diagnostic())
        for marker in (FIRST, FIRST.lower(), "fixture-name", "192.0.2.11", "fixture-schedule", "fixture-interface",
                       "fixture-private-segment", "Policy17", "Policy42"):
            self.assertNotIn(marker, output)
        try:
            raise ValueError("fixture-private-exception")
        except ValueError:
            error = self.assert_error(KeeneticSegmentError, KeeneticSegmentErrorCode.POLICY_TARGET,
                                      preview, source, SegmentSelectionMode.WHOLE_SEGMENT, vpn_policy_id="fixture-private-policy")
        self.assertNotIn("fixture-private", repr(error))

    def test_snapshot_round_trip_and_dynamic_resolution(self):
        snapshot = load_keenetic_snapshot()
        before = deepcopy(snapshot)
        records = tuple(KeeneticDevice(row) for row in snapshot["ip/hotspot"]["host"])
        # Синтетическое распределение известных записей; это не импорт RCI-сегментов.
        chosen_segment, other_segment = segment(*records[:4]), segment(*records[4:], segment_id="Bridge8")
        policies = policies_from_rci(snapshot["ip/policy"])
        vpn = resolve_policy(policies, "fixture-policy-3").policy_id
        direct = resolve_policy(policies, "fixture-policy-1").policy_id
        with forbid_external_effects():
            result = preview(chosen_segment, SegmentSelectionMode.SELECTED_ONLY,
                             selected=(records[0].identity.mac,), policies=policies,
                             vpn_policy_id=vpn, direct_policy_id=direct)
        self.assertEqual(snapshot, before)
        self.assertEqual(result.default_policy_id, direct)
        self.assertEqual(result.policy_for(records[0].identity.mac), vpn)
        self.assertEqual(result.after.devices.devices[1:], records[1:4])
        self.assertEqual([result.policy_for(row.identity.mac) for row in records[1:4]], ["Policy10"] * 3)
        self.assertEqual(result.to_diagnostic()["preserved_explicit_count"], 3)
        self.assertEqual(result.to_diagnostic()["unresolved_device_count"], 0)
        self.assertEqual([row.export()["settings"] for row in other_segment.devices.devices], before["ip/hotspot"]["host"][4:])

    def test_bulk_preview_and_diagnostics_scale_linearly_in_record_count(self):
        measurements = []
        original_export = KeeneticDevice.export
        for size in (10, 20):
            source = segment(*(device(f"02:00:00:00:00:{index:02x}") for index in range(size)))
            selected = tuple(item.identity.mac for item in source.devices.devices)
            calls = [0]

            def counted_export(record):
                calls[0] += 1
                return original_export(record)

            with forbid_external_effects(), patch.object(KeeneticDevice, "export", counted_export):
                result = preview(source, SegmentSelectionMode.SELECTED_ONLY, selected=selected)
                preview_calls = calls[0]
                calls[0] = 0
                self.assertEqual(result.to_diagnostic()["changed_device_count"], size)
                diagnostic_calls = calls[0]
                calls[0] = 0
                self.assertEqual(result.conflicting_devices, ())
                conflict_calls = calls[0]
            measurements.append((preview_calls, diagnostic_calls, conflict_calls))
        for small, large in zip(*measurements):
            self.assertGreater(small, 0)
            self.assertLessEqual(large, small * 2 + 2)


if __name__ == "__main__":
    unittest.main()
