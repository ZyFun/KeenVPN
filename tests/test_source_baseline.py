"""Исходные отпечатки источников: канонический хеш native-настроек, модель и сравнение отпечатков, строгий раздел формата."""

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.manager_metadata import UnknownFields
from keenvpn.domain.source_baseline import (
    MAX_BASELINE_PARTS, BaselineSource, FingerprintState, SourceBaseline, SourceBaselineError,
    SourceBaselineErrorCode as Code, SourceFingerprint, export_source_baseline, native_fingerprint,
    parse_source_baseline, rebuild_source_baseline, same_fingerprint, valid_part_name, validate_source_fingerprint,
)
from tests.support.snapshot import load_keenetic_snapshot


SECRET = "TEST_ONLY_PASSWORD"
PRESENT = FingerprintState.PRESENT
ABSENT = FingerprintState.ABSENT
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class Text(str):
    pass


def digest(index: int) -> str:
    return f"{index:064x}"


def file_fingerprint(source: BaselineSource = BaselineSource.XKEEN_SETTINGS, value: str = EMPTY_SHA256):
    return SourceFingerprint(source, PRESENT, sha256=value)


def xray(*names: str) -> SourceFingerprint:
    return SourceFingerprint(
        BaselineSource.XRAY_CONFIGS, PRESENT, parts=tuple((name, digest(index)) for index, name in enumerate(names)),
    )


class ErrorAssertions(unittest.TestCase):
    def assert_error(self, call, code):
        with self.assertRaises(SourceBaselineError) as caught:
            call()
        self.assertIs(caught.exception.code, code)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(SECRET, str(caught.exception) + repr(caught.exception.args))


class NativeFingerprintTests(ErrorAssertions):
    def test_hash_is_sha256_of_sorted_compact_ascii_json(self):
        document = {"b": [2, 1], "a": {"y": "тест", "x": None}}
        expected = hashlib.sha256(b'{"a":{"x":null,"y":"\\u0442\\u0435\\u0441\\u0442"},"b":[2,1]}').hexdigest()
        self.assertEqual(native_fingerprint(document), expected)
        self.assertEqual(native_fingerprint(json.loads(json.dumps(document))), expected)

    def test_key_order_is_not_significant_but_array_order_and_types_are(self):
        policy = {"description": "TEST_policy", "permit": [{"interface": "Bridge0", "enabled": True}, {"no": True}]}
        reordered = {"permit": [{"enabled": True, "interface": "Bridge0"}, {"no": True}], "description": "TEST_policy"}
        self.assertEqual(native_fingerprint(policy), native_fingerprint(reordered))
        for changed in (
            {**policy, "permit": list(reversed(policy["permit"]))},
            {**policy, "permit": [{"interface": "Bridge0", "enabled": 1}, {"no": True}]},
            {**policy, "description": "TEST_policy "},
            {**policy, "extra": None},
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(native_fingerprint(policy), native_fingerprint(changed))

    def test_snapshot_resources_have_stable_distinct_fingerprints(self):
        snapshot = load_keenetic_snapshot()
        policies, hotspot = snapshot["ip/policy"], snapshot["ip/hotspot"]
        self.assertEqual(native_fingerprint(policies), native_fingerprint(load_keenetic_snapshot()["ip/policy"]))
        self.assertNotEqual(native_fingerprint(policies), native_fingerprint(hotspot))
        self.assertEqual(native_fingerprint({}), hashlib.sha256(b"{}").hexdigest())

    def test_unsupported_documents_are_rejected(self):
        nested: object = 1
        for _ in range(70):
            nested = [nested]
        for value in (
            None, [], "{}", {1: "x"}, {"x": float("nan")}, {"x": {1, 2}}, {"x": b"x"}, {"x": nested},
            {"x": object()}, {"x": 10 ** 5000},
        ):
            with self.subTest(value=type(value).__name__):
                self.assert_error(lambda: native_fingerprint(value), Code.NATIVE)


class SourceFingerprintTests(ErrorAssertions):
    def test_present_absent_and_xray_parts(self):
        self.assertEqual(file_fingerprint().sha256, EMPTY_SHA256)
        absent = SourceFingerprint(BaselineSource.XKEEN_INIT, ABSENT)
        self.assertEqual((absent.sha256, absent.parts), (None, None))
        empty_directory = SourceFingerprint(BaselineSource.XRAY_CONFIGS, PRESENT, parts=())
        self.assertEqual(empty_directory.parts, ())
        self.assertNotEqual(empty_directory, SourceFingerprint(BaselineSource.XRAY_CONFIGS, ABSENT))
        self.assertNotEqual(file_fingerprint(), SourceFingerprint(BaselineSource.XKEEN_SETTINGS, ABSENT))
        with self.assertRaises(FrozenInstanceError):
            absent.state = PRESENT

    def test_state_and_digest_must_agree(self):
        for call, code in (
            (lambda: SourceFingerprint(BaselineSource.XKEEN_INIT, ABSENT, sha256=EMPTY_SHA256), Code.STATE),
            (lambda: SourceFingerprint(BaselineSource.XRAY_CONFIGS, ABSENT, parts=()), Code.STATE),
            (lambda: SourceFingerprint(BaselineSource.XKEEN_INIT, PRESENT), Code.DIGEST),
            (lambda: SourceFingerprint(BaselineSource.XKEEN_INIT, PRESENT, parts=()), Code.STATE),
            (lambda: SourceFingerprint(BaselineSource.XRAY_CONFIGS, PRESENT), Code.PARTS),
            (lambda: SourceFingerprint(BaselineSource.XRAY_CONFIGS, PRESENT, EMPTY_SHA256, ()), Code.STATE),
            (lambda: file_fingerprint(value=EMPTY_SHA256.upper()), Code.DIGEST),
            (lambda: file_fingerprint(value=EMPTY_SHA256[:-1]), Code.DIGEST),
            (lambda: file_fingerprint(value=Text(EMPTY_SHA256)), Code.DIGEST),
            (lambda: file_fingerprint(value=SECRET), Code.DIGEST),
        ):
            with self.subTest(code=code.value):
                self.assert_error(call, code)

    def test_source_and_state_require_exact_enums(self):
        self.assert_error(lambda: SourceFingerprint("xkeen_init", ABSENT), Code.SOURCE)
        self.assert_error(lambda: SourceFingerprint(BaselineSource.XKEEN_INIT, "absent"), Code.STATE)
        self.assert_error(lambda: SourceFingerprint(Text("xkeen_init"), ABSENT), Code.SOURCE)

    def test_xray_parts_are_valid_unique_and_ordered(self):
        self.assertEqual(xray("01_log.json", "02_dns.json", "08_failover_api.json").parts[2][0], "08_failover_api.json")
        self.assertEqual(len(xray(*(f"{index:02d}.json" for index in range(MAX_BASELINE_PARTS))).parts), 64)
        for parts, code in (
            (("02_dns.json", "01_log.json"), Code.PARTS),
            (("01_log.json", "01_log.json"), Code.PARTS),
            ((".hidden.json",), Code.PARTS),
            (("dir/01.json",), Code.PARTS),
            (("01_log.txt",), Code.PARTS),
            ((".json",), Code.PARTS),
            (("01\n.json",), Code.PARTS),
            (tuple(f"{index:02d}.json" for index in range(MAX_BASELINE_PARTS + 1)), Code.PARTS),
        ):
            with self.subTest(parts=parts[:2]):
                self.assert_error(lambda: xray(*parts), code)
        for parts, code in (
            ([("01_log.json", EMPTY_SHA256)], Code.PARTS),
            ((["01_log.json", EMPTY_SHA256],), Code.PARTS),
            ((("01_log.json", EMPTY_SHA256, "x"),), Code.PARTS),
            (((Text("01_log.json"), EMPTY_SHA256),), Code.PARTS),
            ((("01_log.json", EMPTY_SHA256.upper()),), Code.DIGEST),
        ):
            with self.subTest(parts=repr(parts)[:40]):
                self.assert_error(lambda: SourceFingerprint(BaselineSource.XRAY_CONFIGS, PRESENT, parts=parts), code)
        self.assertTrue(valid_part_name("01_log.json"))
        self.assertFalse(valid_part_name(Text("01_log.json")))

    def test_repr_and_diagnostic_hide_hashes_and_part_names(self):
        model = xray("01_TEST_secret.json")
        text = repr(model) + str(model) + repr(model.to_diagnostic()) + repr(file_fingerprint(value=digest(7)))
        for hidden in (digest(0), digest(7), "TEST_secret"):
            self.assertNotIn(hidden, text)
        self.assertEqual(repr(model), "SourceFingerprint(source=xray_configs, state=present, parts=1)")
        self.assertEqual(model.to_diagnostic(), {"source": "xray_configs", "state": "present"})

    def test_revalidation_catches_changes_after_creation(self):
        validate_source_fingerprint(xray("01_log.json"))
        for field, value, code in (
            ("sha256", EMPTY_SHA256.upper(), Code.DIGEST),
            ("sha256", Text(EMPTY_SHA256), Code.DIGEST),
            ("state", "present", Code.STATE),
            ("source", "xkeen_settings", Code.SOURCE),
            ("parts", (), Code.STATE),
        ):
            with self.subTest(field=field, value=repr(value)):
                model = file_fingerprint()
                object.__setattr__(model, field, value)
                self.assert_error(lambda: validate_source_fingerprint(model), code)
                self.assertNotIn(EMPTY_SHA256, repr(model))
        broken = file_fingerprint()
        object.__delattr__(broken, "sha256")
        self.assert_error(lambda: validate_source_fingerprint(broken), Code.ENTRY)
        self.assert_error(lambda: validate_source_fingerprint({"source": "xkeen_settings"}), Code.ENTRY)


class SameFingerprintTests(unittest.TestCase):
    def test_same_state_and_hashes_match_and_absent_matches_only_absent(self):
        absent = SourceFingerprint(BaselineSource.XKEEN_SETTINGS, ABSENT)
        self.assertTrue(same_fingerprint(file_fingerprint(), file_fingerprint()))
        self.assertTrue(same_fingerprint(absent, SourceFingerprint(BaselineSource.XKEEN_SETTINGS, ABSENT)))
        self.assertTrue(same_fingerprint(xray("01_log.json", "02_dns.json"), xray("01_log.json", "02_dns.json")))
        self.assertFalse(same_fingerprint(file_fingerprint(), absent))
        self.assertFalse(same_fingerprint(absent, file_fingerprint()))
        # Пустой файл — не отсутствующий, другой хеш — другой файл.
        self.assertFalse(same_fingerprint(file_fingerprint(), file_fingerprint(value=digest(1))))
        self.assertFalse(same_fingerprint(file_fingerprint(), file_fingerprint(BaselineSource.XKEEN_INIT)))

    def test_any_change_of_xray_part_set_differs(self):
        recorded = xray("01_log.json", "02_dns.json")
        renamed = SourceFingerprint(
            BaselineSource.XRAY_CONFIGS, PRESENT, parts=(("01_log.json", digest(0)), ("03_dns.json", digest(1))),
        )
        changed = SourceFingerprint(
            BaselineSource.XRAY_CONFIGS, PRESENT, parts=(("01_log.json", digest(0)), ("02_dns.json", digest(7))),
        )
        empty = SourceFingerprint(BaselineSource.XRAY_CONFIGS, PRESENT, parts=())
        for other in (xray("01_log.json"), xray("01_log.json", "02_dns.json", "03_TEST.json"), renamed, changed, empty):
            with self.subTest(parts=len(other.parts)):
                self.assertFalse(same_fingerprint(recorded, other))
                self.assertFalse(same_fingerprint(other, recorded))
        self.assertTrue(same_fingerprint(empty, SourceFingerprint(BaselineSource.XRAY_CONFIGS, PRESENT, parts=())))

    def test_only_models_are_compared(self):
        for first, second in (
            (file_fingerprint(), file_fingerprint().to_diagnostic()), ({"source": "xkeen_settings"}, file_fingerprint()),
            (None, None),
        ):
            with self.subTest(first=type(first).__name__, second=type(second).__name__), self.assertRaises(TypeError):
                same_fingerprint(first, second)


class SourceBaselineTests(ErrorAssertions):
    def full(self) -> SourceBaseline:
        return SourceBaseline(tuple(
            xray("01_log.json") if source is BaselineSource.XRAY_CONFIGS else file_fingerprint(source, digest(index))
            for index, source in enumerate(BaselineSource)
        ))

    def test_sources_are_unique_and_follow_the_list_order(self):
        baseline = self.full()
        self.assertEqual(tuple(item.source for item in baseline.fingerprints), tuple(BaselineSource))
        self.assertIs(baseline.fingerprint(BaselineSource.XKEEN_INIT).source, BaselineSource.XKEEN_INIT)
        self.assertIsNone(SourceBaseline(()).fingerprint(BaselineSource.XKEEN_INIT))
        with self.assertRaises(TypeError):
            baseline.fingerprint("xkeen_init")
        reversed_order = tuple(reversed(baseline.fingerprints))
        duplicate = (file_fingerprint(), file_fingerprint())
        for value in (reversed_order, duplicate, list(baseline.fingerprints), (file_fingerprint().to_diagnostic(),)):
            with self.subTest(value=repr(value)[:40]):
                self.assert_error(lambda: SourceBaseline(value), Code.BASELINE)
        self.assert_error(lambda: SourceBaseline((), UnknownFields({"xkeen_init": {}})), Code.BASELINE)
        self.assert_error(lambda: SourceBaseline((), {}), Code.BASELINE)

    def test_export_and_parse_round_trip_with_unknown_sources_kept(self):
        baseline = SourceBaseline(self.full().fingerprints, UnknownFields({"zz_future": {"state": "present", "x": 1}}))
        section = export_source_baseline(baseline)
        self.assertEqual(list(section), [source.value for source in BaselineSource] + ["zz_future"])
        self.assertEqual(section["xray_configs"], {"state": "present", "parts": {"01_log.json": digest(0)}})
        self.assertEqual(section["xkeen_settings"], {"state": "present", "sha256": digest(1)})
        parsed = parse_source_baseline(json.loads(json.dumps(section)))
        self.assertEqual(parsed, baseline)
        self.assertEqual(export_source_baseline(parsed), section)

    def test_parsing_orders_sources_and_parts_by_the_list(self):
        section = {
            "keenetic_policies": {"state": "absent"},
            "xray_configs": {"state": "present", "parts": {"02_dns.json": digest(2), "01_log.json": digest(1)}},
        }
        parsed = parse_source_baseline(section)
        self.assertEqual([item.source for item in parsed.fingerprints], [
            BaselineSource.XRAY_CONFIGS, BaselineSource.KEENETIC_POLICIES,
        ])
        self.assertEqual(parsed.fingerprints[0].parts, (("01_log.json", digest(1)), ("02_dns.json", digest(2))))

    def test_strict_parsing_of_known_entries(self):
        for section, code in (
            (None, Code.BASELINE), ([], Code.BASELINE),
            ({"xkeen_init": []}, Code.ENTRY), ({"xkeen_init": {}}, Code.STATE),
            ({"xkeen_init": {"state": "unavailable"}}, Code.STATE),
            ({"xkeen_init": {"state": "Absent"}}, Code.STATE),
            ({"xkeen_init": {"state": "absent", "reason": "missing"}}, Code.ENTRY),
            ({"xkeen_init": {"state": "present"}}, Code.ENTRY),
            ({"xkeen_init": {"state": "present", "sha256": None}}, Code.DIGEST),
            ({"xkeen_init": {"state": "present", "parts": {}}}, Code.ENTRY),
            ({"xray_configs": {"state": "present", "parts": []}}, Code.PARTS),
            ({"xray_configs": {"state": "present", "parts": {"01.json": 1}}}, Code.DIGEST),
            ({"xray_configs": {"state": "present", "parts": {"01.json": SECRET}}}, Code.DIGEST),
            ({"unknown": {"x": float("inf")}}, Code.BASELINE),
        ):
            with self.subTest(section=section):
                self.assert_error(lambda: parse_source_baseline(section), code)

    def test_rebuild_detects_substituted_parts(self):
        baseline = self.full()
        self.assertEqual(rebuild_source_baseline(baseline), baseline)
        object.__setattr__(baseline.fingerprints[1], "sha256", None)
        self.assert_error(lambda: rebuild_source_baseline(baseline), Code.DIGEST)
        self.assert_error(lambda: export_source_baseline(baseline), Code.DIGEST)
        tampered = SourceBaseline(())
        object.__setattr__(tampered, "fingerprints", [])
        self.assert_error(lambda: rebuild_source_baseline(tampered), Code.BASELINE)
        extra = SourceBaseline((), UnknownFields({"zz": 1}))
        object.__setattr__(extra.extra, "_snapshot", "{")
        self.assert_error(lambda: rebuild_source_baseline(extra), Code.BASELINE)
        self.assert_error(lambda: rebuild_source_baseline(file_fingerprint()), Code.BASELINE)

    def test_repr_and_diagnostic_show_only_counts_and_states(self):
        baseline = SourceBaseline(self.full().fingerprints, UnknownFields({SECRET: SECRET}))
        text = repr(baseline) + repr(baseline.to_diagnostic())
        self.assertNotIn(SECRET, text)
        self.assertNotIn(digest(1), text)
        self.assertEqual(repr(baseline), "SourceBaseline(sources=8, unknown_sources=1)")
        self.assertEqual(baseline.to_diagnostic()["unknown_source_count"], 1)
        self.assertEqual(len(baseline.to_diagnostic()["sources"]), len(BaselineSource))


if __name__ == "__main__":
    unittest.main()
