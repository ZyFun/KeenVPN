"""Сквозное сравнение приватных снимков на портах в памяти."""

from dataclasses import replace
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.draft_diff import CompareDraft, CompareDraftHandler, DraftDiffSnapshot
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure, RouterReadError, RouterReadFailure, StoreReason
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.draft_session import DraftSessionErrorCode
from keenvpn.domain.keenetic_native import KeeneticHotspotSettings
from keenvpn.domain.manager_metadata import UnknownFields
from keenvpn.domain.source_baseline import (
    BaselineSource as Source, FingerprintState as State, SourceBaseline, SourceBaselineError,
    SourceBaselineErrorCode, SourceFingerprint,
)
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.in_memory import InMemoryDraftSessionStore
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_IDENTIFIERS, UNSAFE_MARKERS, reachable
from tests.test_application_draft_baseline_check import FIRST_ID, SECOND_ID, OPERATION, HookedFingerprints, draft_bytes, token


PART = "TEST_private.json"
MAC = "02:00:00:00:00:11"
PASSWORD = UNSAFE_IDENTIFIERS["uri"]
SERVICE = {"type": "field", "inboundTag": ["TEST_service"], "outboundTag": "TEST_service"}
RULE = {"outboundTag": "TEST_proxy", "domain": ["example.test"]}


def xray(*parts):
    return XrayConfigSet(tuple(ConfigDocument(name, raw) for name, raw in parts))


def proxy(password=PASSWORD, rules=(SERVICE, RULE), **extra):
    return {"api": {"tag": "TEST_service"}, "routing": {"rules": list(rules)},
            "outbounds": [{"tag": "TEST_proxy", "settings": {"servers": [{"password": password}]}}], **extra}


def config(document):
    return xray((PART, json.dumps(document).encode()))


def fingerprints(snapshot):
    """Независимый расчёт по байтам источников, как при фиксации раздела baseline."""
    result = []
    for source in Source:
        value = getattr(snapshot, source.value)
        if value is None:
            result.append(SourceFingerprint(source, State.ABSENT))
        elif source is Source.XRAY_CONFIGS:
            parts = tuple(sorted((p.name, hashlib.sha256(p.content).hexdigest()) for p in value.parts))
            result.append(SourceFingerprint(source, State.PRESENT, parts=parts))
        else:
            if source is Source.KEENETIC_HOTSPOT_SETTINGS:
                value = value.export()
            if type(value) is dict:
                value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            result.append(SourceFingerprint(source, State.PRESENT, sha256=hashlib.sha256(value).hexdigest()))
    return tuple(result)


class DraftDiffTests(unittest.TestCase):
    def setUp(self):
        self.original = DraftDiffSnapshot(
            xray_configs=config(proxy()), xkeen_settings=b'{"xkeen":{"killswitch":true}}',
            xkeen_init=b'# TEST_private_init\nproxy_dns="on"\n', xkeen_port_exclude=b"53\n",
            xkeen_port_proxying=b"443\n", xkeen_ip_exclude=b"198.51.100.7\n",
            keenetic_policies={"TEST_policy": {"permit": ["TEST_first", "TEST_second"], "TEST_unknown": True}},
            keenetic_hotspot_settings=KeeneticHotspotSettings({"host": [{"mac": MAC}], "TEST_extra": [1, 2]}),
        )
        self.baseline = SourceBaseline(fingerprints(self.original))
        self.raw = draft_bytes(self.baseline)
        self.store = InMemoryDraftSessionStore(self.raw)
        self.sources = HookedFingerprints()
        for item in self.baseline.fingerprints:
            self.sources.set_response(item.source, item)
        self.handler = CompareDraftHandler(self.store, self.sources, operation_ids=lambda: OPERATION)

    def run_diff(self, candidate=None, **fields):
        params = dict(original=self.original, candidate=self.original if candidate is None else candidate,
                      draft_id=FIRST_ID, expected_revision=token(self.raw))
        command = CompareDraft(**(params | fields))
        with forbid_external_effects():
            result = self.handler.execute(command)
        self.assertEqual((self.store.create_calls, self.store.remove_calls, self.store.confirm_calls), ((), (), 0))
        public = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        markers = (*UNSAFE_MARKERS, "TEST_", PART, MAC, token(self.raw), FIRST_ID)
        hashes = [item.sha256 for item in self.baseline.fingerprints if item.sha256]
        for marker in (*markers, *hashes):
            self.assertNotIn(marker, public)
            self.assertNotIn(marker, repr(command))
        private_types = (bytes, BaseException, ConfigDocument, XrayConfigSet, DraftDiffSnapshot, SourceFingerprint)
        self.assertFalse(any(isinstance(item, private_types) for item in reachable(result)))
        return result

    def entries(self, candidate, **fields):
        result = self.run_diff(candidate, **fields)
        self.assertTrue(result.succeeded, result.error)
        return [(e.source, e.area, e.operation.value, e.part, e.position) for e in result.data.entries]

    def reject(self, result, code):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertEqual(result.error.code, code)
        self.assertIsNotNone(result.error.next_step)

    def test_identical_and_native_object_key_order(self):
        reordered = {"TEST_policy": {"TEST_unknown": True, "permit": ["TEST_first", "TEST_second"]}}
        self.assertEqual(self.entries(replace(self.original, keenetic_policies=reordered)), [])
        self.assertEqual(self.sources.calls, tuple(Source))
        self.assertEqual(self.store.content, self.raw)

    def test_secret_only_change_and_untouched_service_fields(self):
        candidate = replace(self.original, xray_configs=config(proxy("TEST_new_password")))
        self.assertEqual(self.entries(candidate), [(Source.XRAY_CONFIGS, "credentials", "changed", 0, 0)])
        self.assertEqual(self.original.xray_configs.parts[0].content, config(proxy()).parts[0].content)

    def test_changed_rule_order_and_native_arrays(self):
        hotspot = self.original.keenetic_hotspot_settings.export() | {"TEST_extra": [2, 1]}
        policies = {"TEST_policy": {"permit": ["TEST_second", "TEST_first"], "TEST_unknown": True}}
        candidate = replace(self.original, xray_configs=config(proxy(rules=(RULE, SERVICE))),
                            keenetic_policies=policies, keenetic_hotspot_settings=KeeneticHotspotSettings(hotspot))
        self.assertEqual(self.entries(candidate), [
            (Source.XRAY_CONFIGS, "routing_rules", "reordered", 0, None),
            (Source.KEENETIC_POLICIES, "permit", "reordered", 0, None),
            (Source.KEENETIC_HOTSPOT_SETTINGS, "other_fields", "changed", None, None)])

    def test_renamed_and_added_files_keep_names_private(self):
        content = self.original.xray_configs.parts[0].content
        candidate = replace(self.original, xray_configs=xray(("00_TEST_new.json", b"{}"), ("01_TEST_copy.json", content)))
        self.assertEqual(self.entries(candidate), [(Source.XRAY_CONFIGS, "part", "added", 0, None),
                                                  (Source.XRAY_CONFIGS, "part", "added", 1, None),
                                                  (Source.XRAY_CONFIGS, "part", "removed", 0, None)])

    def test_representation_null_and_unknown_values_survive(self):
        raw = self.original.xray_configs.parts[0].content
        for candidate, area, operation in (
            (xray((PART, b"// TEST_comment\n" + raw)), "representation", "changed"),
            (config(proxy(TEST_private=None)), "other_fields", "changed"),
            (config(proxy() | {"routing": {"rules": [SERVICE, RULE], "domainStrategy": None}}), "domain_strategy", "added"),
        ):
            self.assertEqual(self.entries(replace(self.original, xray_configs=candidate)),
                             [(Source.XRAY_CONFIGS, area, operation, 0, None)])

    def test_xkeen_files_and_absent_vs_empty(self):
        candidate = replace(self.original, xkeen_settings=b'{"xkeen":null}', xkeen_init=b"# TEST_secret\n",
                            xkeen_port_exclude=b"", xkeen_port_proxying=None, xkeen_ip_exclude=b"198.51.100.7 # TEST_\n")
        self.assertEqual(self.entries(candidate), [(Source.XKEEN_SETTINGS, "killswitch", "removed", None, None),
            (Source.XKEEN_SETTINGS, "xkeen_flags", "changed", None, None),
            (Source.XKEEN_INIT, "proxy_dns", "changed", None, None),
            (Source.XKEEN_INIT, "file", "changed", None, None),
            (Source.XKEEN_PORT_EXCLUDE, "list_entries", "removed", None, 0),
            (Source.XKEEN_PORT_PROXYING, "source", "removed", None, None),
            (Source.XKEEN_IP_EXCLUDE, "representation", "changed", None, None)])
        self.original = replace(self.original, xray_configs=None, xkeen_init=None)
        records = fingerprints(self.original)
        self.raw = draft_bytes(SourceBaseline(records))
        self.store.content = self.raw
        for item in records:
            self.sources.set_response(item.source, item)
        self.assertEqual(self.entries(replace(self.original, xray_configs=xray(), xkeen_init=b"")), [
            (Source.XRAY_CONFIGS, "source", "added", None, None), (Source.XKEEN_INIT, "source", "added", None, None)])

    def test_native_types_and_device_identifiers_are_private(self):
        candidate = replace(self.original, keenetic_policies={"TEST_policy": {
            "permit": ["TEST_first", "TEST_second"], "TEST_unknown": 1}},
            keenetic_hotspot_settings=KeeneticHotspotSettings({"host": [{"mac": MAC, "name": PASSWORD}], "TEST_extra": [1, 2]}))
        self.assertEqual(self.entries(candidate), [(Source.KEENETIC_POLICIES, "other_fields", "changed", 0, None),
                                                  (Source.KEENETIC_HOTSPOT_SETTINGS, "hosts", "changed", None, 0)])

    def test_wrong_original_or_unknown_baseline_never_yields_empty_diff(self):
        other = replace(self.original, xkeen_init=None)
        result = self.run_diff(other, original=other)
        self.reject(result, "diff_original_mismatch")
        self.assertEqual(result.error.next_step.code.value, "inspect_source_data")
        self.assertEqual(result.error.conflicts, ())
        self.assertEqual(self.sources.calls, tuple(Source))
        for baseline in (None, SourceBaseline(self.baseline.fingerprints[:-1]),
                         SourceBaseline(self.baseline.fingerprints, UnknownFields({"TEST_future": {}}))):
            self.raw = draft_bytes(baseline)
            self.store.content = self.raw
            self.reject(self.run_diff(), "draft_baseline_changed")

    def test_reread_original_reports_the_changed_live_source(self):
        reread = replace(self.original, xkeen_port_exclude=b"443\n")
        for item in fingerprints(reread):
            self.sources.set_response(item.source, item)
        result = self.run_diff(reread, original=reread)
        self.reject(result, "draft_baseline_changed")
        self.assertEqual(result.error.next_step.code.value, "recreate_draft")
        self.assertEqual([(item.source, item.found.value) for item in result.error.conflicts],
                         [(Source.XKEEN_PORT_EXCLUDE, "changed")])

    def test_wrong_original_propagates_read_failure_and_session_conflict(self):
        wrong = replace(self.original, xkeen_init=None)
        self.sources.set_response(Source.XKEEN_SETTINGS, RouterReadError(RouterReadFailure.IO_ERROR))
        self.reject(self.run_diff(original=wrong), "draft_baseline_unavailable")
        self.sources.hooks[Source.XKEEN_INIT] = lambda: setattr(self.store, "content", None)
        self.reject(self.run_diff(original=wrong), "draft_revision_conflict")

    def test_read_failure_and_source_conflict_have_no_partial_data(self):
        source = Source.XKEEN_SETTINGS
        self.sources.set_response(source, SourceFingerprint(source, State.ABSENT))
        self.reject(self.run_diff(), "draft_baseline_changed")
        self.sources.set_response(source, RouterReadError(RouterReadFailure.IO_ERROR))
        self.reject(self.run_diff(), "draft_baseline_unavailable")
        self.sources.set_response(source, ValueError(PASSWORD))
        self.reject(self.run_diff(), "draft_baseline_unavailable")

    def test_session_concurrently_replaced_or_removed(self):
        for replacement in (None, draft_bytes(self.baseline, SECOND_ID)):
            self.store.content = self.raw
            self.sources.hooks[Source.XKEEN_INIT] = lambda: setattr(self.store, "content", replacement)
            self.reject(self.run_diff(), "draft_revision_conflict")
        self.store.content = self.raw
        self.reject(self.run_diff(expected_revision="0" * 32), "draft_revision_conflict")
        self.reject(self.run_diff(draft_id=SECOND_ID), "draft_mismatch")

    def test_reject_incomplete_wrong_types_and_tampered_documents(self):
        self.reject(self.run_diff(original={}), "invalid_diff_snapshot")
        for fields in ({"xkeen_init": "TEST_init"}, {"xray_configs": {}}, {"xkeen_settings": b"{"},
                       {"keenetic_policies": {"TEST_key": object()}}, {"keenetic_hotspot_settings": {}}):
            self.reject(self.run_diff(replace(self.original, **fields)), "invalid_diff_snapshot")
        for attribute in ("sha256", "_snapshot"):
            x = config(proxy())
            part = x.parts[0]
            object.__setattr__(part, attribute, type("Text", (str,), {})(getattr(part, attribute)))
            self.reject(self.run_diff(replace(self.original, xray_configs=x)), "invalid_diff_snapshot")
        bad = replace(self.original)
        object.__delattr__(bad, "xkeen_init")
        self.reject(self.run_diff(bad), "invalid_diff_snapshot")

    def test_damaged_command_is_rejected_without_throwing(self):
        for field in ("contract_version", "draft_id", "expected_revision", "candidate", "original"):
            command = CompareDraft(draft_id=FIRST_ID, expected_revision=token(self.raw),
                                   original=self.original, candidate=self.original)
            object.__delattr__(command, field)
            with self.subTest(field=field), forbid_external_effects():
                result = self.handler.execute(command)
            self.assertFalse(result.succeeded)
            self.assertIsNone(result.data)

    def test_output_limit_is_inclusive_no_truncation(self):
        for size in (256, 257):
            # Одна исходная запись и размер изменённого списка дают ровно size операций.
            candidate = replace(self.original, xkeen_port_exclude=b"1\n" * size)
            result = self.run_diff(candidate)
            if size == 256:
                self.assertEqual(len(result.data.entries), size)
            else:
                self.reject(result, "diff_entry_limit")

    def test_damaged_exception_code_cannot_escape_source(self):
        class Impostor(StrEnum):
            PRIVATE = "TEST_private_exception"

        error = SourceBaselineError(SourceBaselineErrorCode.SOURCE)
        error.code = Impostor.PRIVATE
        self.sources.set_response(Source.XKEEN_INIT, error)
        result = self.run_diff()
        self.reject(result, "invalid_draft_baseline_source")
        self.assertIsNone(result.error.reason)

    def test_only_registered_enum_members_are_observed(self):
        class Trap:
            @property
            def __class__(self):
                raise RuntimeError("TEST_private_class")

        def impostor(kind):
            value = str.__new__(kind, "TEST_private_enum")
            value._name_, value._value_ = "TEST_private_name", "TEST_private_enum"
            return value

        for raw in (Trap(), impostor(SourceBaselineErrorCode)):
            error = SourceBaselineError(SourceBaselineErrorCode.STATE)
            error.code = raw
            self.sources.set_response(Source.XKEEN_INIT, error)
            self.reject(self.run_diff(), "invalid_draft_baseline_source")
        error = RouterReadError(RouterReadFailure.IO_ERROR)
        error.failure = impostor(RouterReadFailure)
        self.sources.set_response(Source.XKEEN_INIT, error)
        self.reject(self.run_diff(), "draft_baseline_unavailable")
        bad = SourceFingerprint(Source.XKEEN_INIT, State.ABSENT)
        object.__setattr__(bad, "state", impostor(State))
        object.__setattr__(bad, "sha256", "0" * 64)
        self.sources.set_response(Source.XKEEN_INIT, bad)
        self.reject(self.run_diff(), "invalid_draft_baseline_source")
        bad_error = DraftSessionStoreError(DraftStoreFailure.CONFLICT)
        bad_error.failure = impostor(DraftStoreFailure)
        self.store.read_failure = bad_error
        self.reject(self.run_diff(), "draft_store_failed")

    def test_xray_colliding_keys_preserve_order_alongside_other_changes(self):
        left = {"outboundTag": "TEST_direct", "OutboundTag": "TEST_block"}
        right = dict(reversed(left.items()))
        self.original = replace(self.original, xray_configs=config(proxy(rules=(left,))))
        self.use_original()
        for extra in ({}, {"dns": {}}):
            candidate = replace(self.original, xray_configs=config(proxy(rules=(right,), **extra)))
            entries = self.entries(candidate)
            self.assertIn((Source.XRAY_CONFIGS, "routing_rules", "changed", 0, 0), entries)
            self.assertFalse(any(entry[1] == "representation" for entry in entries))

    def use_original(self):
        self.baseline = SourceBaseline(fingerprints(self.original))
        self.raw = draft_bytes(self.baseline)
        self.store.content = self.raw
        for item in self.baseline.fingerprints:
            self.sources.set_response(item.source, item)

    def test_changes_across_unchanged_rule_keep_both_positions(self):
        candidate = replace(self.original, xray_configs=config(proxy(rules=(RULE, {"port": 443}))))
        self.assertEqual(self.entries(candidate), [
            (Source.XRAY_CONFIGS, "routing_rules", "removed", 0, 0),
            (Source.XRAY_CONFIGS, "routing_rules", "added", 0, 1)])

    def test_nested_hotspot_snapshot_checked_before_deserialization(self):
        calls = []
        class PrivateBytes(bytes):
            def decode(self, *args, **kwargs):
                calls.append(True)
                return super().decode(*args, **kwargs)

        hotspot = KeeneticHotspotSettings({"policy": [{"interface": "TEST_segment"}]})
        item = hotspot.segment_assignments[0]
        object.__setattr__(item, "_snapshot", PrivateBytes(item._snapshot.encode()))
        self.reject(self.run_diff(replace(self.original, keenetic_hotspot_settings=hotspot)), "invalid_diff_snapshot")
        self.assertEqual(calls, [])
        hotspot = KeeneticHotspotSettings({"auto-register": False})
        object.__setattr__(hotspot, "_snapshot", '{"auto-register":true,"auto-register":false}')
        self.reject(self.run_diff(replace(self.original, keenetic_hotspot_settings=hotspot)), "invalid_diff_snapshot")

    def test_bad_list_encoding_always_invalid_even_if_equal_or_new(self):
        for field in ("xkeen_port_proxying", "xkeen_port_exclude", "xkeen_ip_exclude"):
            for before in (None, b"", b"\xff"):
                original = replace(self.original, **{field: before})
                candidate = replace(self.original, **{field: b"\xff"})
                self.raw = draft_bytes(SourceBaseline(fingerprints(original)))
                self.store.content = self.raw
                for item in fingerprints(original):
                    self.sources.set_response(item.source, item)
                with self.subTest(field=field, before=before):
                    self.reject(self.run_diff(candidate, original=original), "invalid_diff_snapshot")

    def test_error_type_and_reason_comparisons_do_not_invoke_user_hooks(self):
        class TrapMeta(type):
            def __eq__(cls, other):
                raise RuntimeError("TEST_metaclass")

        class SourceError(SourceBaselineError, metaclass=TrapMeta):
            pass

        class Reason(metaclass=TrapMeta):
            pass

        self.sources.set_response(Source.XKEEN_INIT, SourceError(SourceBaselineErrorCode.STATE))
        self.reject(self.run_diff(), "invalid_draft_baseline_source")
        self.store.read_failure = DraftSessionStoreError(DraftStoreFailure.INVALID, reason=Reason())
        result = self.run_diff()
        self.reject(result, "invalid_stored_draft")
        self.assertIsNone(result.error.reason)

    def test_native_nested_mapping_never_runs_its_methods(self):
        calls = []
        class ScalarMeta(type):
            def __eq__(cls, other):
                return other is str

        class Foreign(dict, metaclass=ScalarMeta):
            def items(self):
                calls.append(True)
                return super().items()

        policies = {"TEST_policy": Foreign(self.original.keenetic_policies["TEST_policy"])}
        self.reject(self.run_diff(replace(self.original, keenetic_policies=policies)), "invalid_diff_snapshot")
        self.assertEqual(calls, [])

    def test_unregistered_store_reason_cannot_expose_exception_chain(self):
        for kind, failure, expected in (
            (StoreReason, DraftStoreFailure.UNSAFE, "draft_store_unsafe"),
            (DraftSessionErrorCode, DraftStoreFailure.INVALID, "invalid_stored_draft"),
        ):
            reason = str.__new__(kind, "TEST_fake")
            error = DraftSessionStoreError(failure, reason=reason)
            error.__cause__ = OSError("TEST_private_original_location")
            self.store.read_failure = error
            with self.subTest(kind=kind.__name__):
                result = self.run_diff()
                self.reject(result, expected)
                self.assertIsNone(result.error.reason)

    def test_init_protective_flags_comment_and_mixed_change(self):
        for name in ("start_auto", "proxy_dns", "proxy_router", "ipv6_support"):
            raw = f'{name}="on"\r\n'.encode()
            self.original = replace(self.original, xkeen_init=raw)
            self.use_original()
            changed = raw.replace(b'"on"', b'"off"')
            flag = (Source.XKEEN_INIT, name, "changed", None, None)
            file = (Source.XKEEN_INIT, "file", "changed", None, None)
            for payload, expected in ((changed, [flag]), (raw+b"# TEST_note", [file]),
                                      (changed+b"# TEST_note", [flag, file]), (b"\xff", [file])):
                with self.subTest(name=name, expected=expected):
                    self.assertEqual(self.entries(replace(self.original, xkeen_init=payload)), expected)

    def test_killswitch_distinct_from_unrelated_settings(self):
        for section, area in (({"killswitch": False}, "killswitch"),
                              ({"killswitch": True, "verify_downloads": False}, "other_fields")):
            settings = json.dumps({"xkeen": section}).encode()
            self.assertEqual(self.entries(replace(self.original, xkeen_settings=settings)),
                             [(Source.XKEEN_SETTINGS, area, "changed", None, None)])

    def test_protected_flags_remain_visible_when_whole_source_disappears(self):
        changes = self.entries(replace(self.original, xkeen_init=None, xkeen_settings=None))
        self.assertIn((Source.XKEEN_SETTINGS, "killswitch", "removed", None, None), changes)
        self.assertIn((Source.XKEEN_INIT, "proxy_dns", "changed", None, None), changes)

    def test_unsupported_private_init_expressions_are_compared_without_evaluation(self):
        self.original = replace(self.original, xkeen_init=b'proxy_dns="$TEST_before"\n')
        self.use_original()
        changes = self.entries(replace(self.original, xkeen_init=b'proxy_dns="$TEST_after"\n'))
        self.assertEqual(changes, [(Source.XKEEN_INIT, "proxy_dns", "changed", None, None),
                                   (Source.XKEEN_INIT, "file", "changed", None, None)])

    def test_each_private_policy_has_its_own_ordinal(self):
        policy = {"permit": ["TEST_first", "TEST_second"]}
        policies = {"TEST_b": policy, "TEST_a": policy}
        self.original = replace(self.original, keenetic_policies=policies)
        self.use_original()
        for index, key in enumerate(sorted(policies)):
            changed = policies | {key: {"permit": list(reversed(policy["permit"]))}}
            changes = self.entries(replace(self.original, keenetic_policies=changed))
            self.assertEqual(changes, [(Source.KEENETIC_POLICIES, "permit", "reordered", index, None)])

    def test_policy_removed_uses_original_ordinal_while_candidate_insertions_shift_indices(self):
        policies = {"TEST_a": {}, "TEST_c": {"permit": [1, 2]}, "TEST_e": {}}
        self.original = replace(self.original, keenetic_policies=policies)
        self.use_original()
        changed = {"TEST_a": {}, "TEST_b": {}, "TEST_c": {"permit": [1]}, "TEST_d": {}}
        changes = self.entries(replace(self.original, keenetic_policies=changed))
        self.assertEqual(changes, [
            (Source.KEENETIC_POLICIES, "policy", "added", 1, None),
            (Source.KEENETIC_POLICIES, "permit", "removed", 1, 1),
            (Source.KEENETIC_POLICIES, "policy", "added", 3, None),
            (Source.KEENETIC_POLICIES, "policy", "removed", 2, None)])

    def test_incomplete_baseline_conflicts_describe_live_sources_only(self):
        self.raw = draft_bytes(SourceBaseline(self.baseline.fingerprints[:-1]))
        self.store.content = self.raw
        other = replace(self.original, xkeen_init=None)
        result = self.run_diff(original=other)
        self.reject(result, "draft_baseline_changed")
        self.assertEqual([entry.source for entry in result.error.conflicts], [Source.KEENETIC_HOTSPOT_SETTINGS])
        self.assertEqual(self.sources.calls, tuple(Source))

    def test_nested_removal_uses_original_part_and_outer_position_after_insertions(self):
        anchor = {"tag": "TEST_anchor"}
        endpoint = {"tag": "TEST_target", "settings": {"servers": [{"port": 443, "password": PASSWORD}]}}
        self.original = replace(self.original, xray_configs=config({"outbounds": [anchor, endpoint]}))
        self.use_original()
        updated = {"tag": "TEST_target", "settings": {"servers": [{"port": 443}]}}
        changed = {"outbounds": [{"tag": "TEST_inserted"}, anchor, updated]}
        parts = xray(("00_TEST_new.json", b"{}"), (PART, json.dumps(changed).encode()))
        self.assertEqual(self.entries(replace(self.original, xray_configs=parts)), [
            (Source.XRAY_CONFIGS, "part", "added", 0, None),
            (Source.XRAY_CONFIGS, "outbounds", "added", 1, 0),
            (Source.XRAY_CONFIGS, "credentials", "removed", 0, 1)])
