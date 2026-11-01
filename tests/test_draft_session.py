"""Модель сессии черновика: строгий формат, сохранение неизвестных полей, ревизия и безопасное представление."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.draft_session import (
    DRAFT_FORMAT, DRAFT_SCHEMA_VERSION, MAX_DRAFT_SIZE, DraftSession, DraftSessionError,
    DraftSessionErrorCode as Code, StoredDraftSession, decode_draft_session, draft_revision, encode_draft_session,
    format_created_at, valid_created_at, valid_draft_id, validate_draft_session,
)
from keenvpn.domain.manager_metadata import UnknownFields
from keenvpn.domain.source_baseline import (
    BaselineSource, FingerprintState, SourceBaseline, SourceFingerprint, export_source_baseline,
)


DRAFT_ID = "0000abcd-0000-4000-8000-00000000000d"
CREATED_AT = datetime(2026, 11, 1, 2, 14, 16, tzinfo=timezone.utc)
SECRET = "TEST_ONLY_PASSWORD"


def session(extra: dict | None = None) -> DraftSession:
    return DraftSession(DRAFT_ID, CREATED_AT, UnknownFields(extra))


def baseline(**extra) -> SourceBaseline:
    return SourceBaseline((
        SourceFingerprint(BaselineSource.XRAY_CONFIGS, FingerprintState.PRESENT, parts=(("01_log.json", "a" * 64),)),
        SourceFingerprint(BaselineSource.XKEEN_INIT, FingerprintState.ABSENT),
        SourceFingerprint(BaselineSource.KEENETIC_POLICIES, FingerprintState.PRESENT, sha256="b" * 64),
    ), UnknownFields(extra or None))


def document(**changes) -> bytes:
    values = {"format": DRAFT_FORMAT, "schema_version": 1, "draft_id": DRAFT_ID, "created_at": "2026-11-01T02:14:16Z"}
    values.update(changes)
    return json.dumps({key: value for key, value in values.items() if value is not ...}).encode()


class DraftModelTests(unittest.TestCase):
    def assert_error(self, call, code, field=None):
        with self.assertRaises(DraftSessionError) as caught:
            call()
        self.assertIs(caught.exception.code, code)
        self.assertEqual(caught.exception.field, field)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(SECRET, str(caught.exception) + repr(caught.exception.args))
        return caught.exception

    def test_canonical_bytes_round_trip_with_revision(self):
        content = encode_draft_session(session())
        self.assertEqual(content.decode("ascii"), (
            '{\n  "format": "keenvpn-draft-session",\n  "schema_version": 1,\n'
            f'  "draft_id": "{DRAFT_ID}",\n  "created_at": "2026-11-01T02:14:16Z"\n}}\n'
        ))
        stored = decode_draft_session(content)
        self.assertEqual(stored, StoredDraftSession(session(), hashlib.sha256(content).hexdigest()))
        self.assertEqual(draft_revision(content), stored.revision)
        self.assertEqual(encode_draft_session(stored.session), content)
        self.assertEqual(DRAFT_SCHEMA_VERSION, 1)

    def test_unknown_fields_are_kept_after_known_ones_in_original_order(self):
        content = document(**{"zeta": True, "": 1, "Zeta": "1", "nested": {"a": [1, 1.5, None]}})
        stored = decode_draft_session(content)
        extra = stored.session.extra
        self.assertEqual(extra.names, ("zeta", "", "Zeta", "nested"))
        rewritten = json.loads(encode_draft_session(stored.session))
        self.assertEqual(list(rewritten), ["format", "schema_version", "draft_id", "created_at", "zeta", "", "Zeta",
                                           "nested"])
        self.assertIs(rewritten["zeta"], True)
        self.assertEqual(rewritten[""], 1)
        self.assertEqual(rewritten["Zeta"], "1")
        # `true` и `1` различаются: модели с ними не равны.
        self.assertNotEqual(session({"zeta": True}), session({"zeta": 1}))
        self.assertEqual(stored.session.to_diagnostic()["unknown_field_count"], 4)

    def test_known_name_in_unknown_fields_is_rejected(self):
        for name in ("format", "schema_version", "draft_id", "created_at", "baseline"):
            with self.subTest(name=name):
                self.assert_error(lambda: session({name: "x"}), Code.UNKNOWN_FIELDS)

    def test_diagnostic_and_repr_hide_unknown_values(self):
        model = session({"payload": SECRET, SECRET: 1})
        diagnostic = model.to_diagnostic()
        self.assertEqual(diagnostic, {
            "schema_version": 1, "draft_id": DRAFT_ID, "created_at": "2026-11-01T02:14:16Z", "unknown_field_count": 2,
            "baseline": None,
        })
        self.assertNotIn(SECRET, repr(model) + repr(diagnostic) + str(model))
        self.assertIn("UnknownFields(count=2)", repr(model))
        with self.assertRaises(FrozenInstanceError):
            model.draft_id = "x"

    def test_draft_id_format(self):
        for value in (DRAFT_ID, "ffffffff-ffff-ffff-ffff-ffffffffffff"):
            self.assertTrue(valid_draft_id(value))
        class Text(str):
            pass
        for value in (
            DRAFT_ID.upper(), DRAFT_ID.replace("-", ""), "{" + DRAFT_ID + "}", DRAFT_ID + "\n", " " + DRAFT_ID, "",
            Text(DRAFT_ID), None, 1, b"0000abcd-0000-4000-8000-00000000000d",
        ):
            with self.subTest(value=value):
                self.assertFalse(valid_draft_id(value))
                self.assert_error(lambda: DraftSession(value, CREATED_AT), Code.DRAFT_ID, "draft_id")

    def test_created_at_must_be_whole_second_utc(self):
        class Moment(datetime):
            pass
        self.assertTrue(valid_created_at(CREATED_AT))
        for value in (
            CREATED_AT.replace(tzinfo=None), CREATED_AT.astimezone(timezone(timedelta(hours=3))),
            CREATED_AT.replace(microsecond=1),
            CREATED_AT.replace(fold=1), Moment(2026, 11, 1, tzinfo=timezone.utc), "2026-11-01T02:14:16Z", 0, None,
        ):
            with self.subTest(value=value):
                self.assertFalse(valid_created_at(value))
                self.assert_error(lambda: DraftSession(DRAFT_ID, value), Code.CREATED_AT, "created_at")

    def test_created_at_text_is_strict_and_padded(self):
        early = datetime(1, 2, 3, 4, 5, 6, tzinfo=timezone.utc)
        self.assertEqual(format_created_at(early), "0001-02-03T04:05:06Z")
        decoded = decode_draft_session(document(created_at="0001-02-03T04:05:06Z")).session
        self.assertEqual(decoded.created_at, early)
        self.assertEqual(json.loads(encode_draft_session(decoded))["created_at"], "0001-02-03T04:05:06Z")
        for value in (
            "2026-11-01T02:14:16", "2026-11-01T02:14:16z", "2026-11-01T02:14:16+00:00", "2026-11-01 02:14:16Z",
            "2026-11-01T02:14:16.000Z", "2026-02-30T00:00:00Z", "2026-11-01T24:00:00Z", "2026-12-31T23:59:60Z",
            "0000-01-01T00:00:00Z", "2026-1-01T02:14:16Z", "２０２６-11-01T02:14:16Z", "", 1762000000, None,
        ):
            with self.subTest(value=value):
                self.assert_error(lambda: decode_draft_session(document(created_at=value)), Code.CREATED_AT,
                                  "created_at")

    def test_strict_decoding_rejects_damaged_and_foreign_files(self):
        cases = [
            ("text", "not bytes", Code.CONTENT, None),
            ("large", b" " * (MAX_DRAFT_SIZE + 1), Code.CONTENT, None),
            ("utf8", b'{"format": "\xff"}', Code.CONTENT, None),
            ("json", b'{"format": "keenvpn-draft-session",', Code.JSON, None),
            ("comment", b'{"format": "keenvpn-draft-session" // TEST\n}', Code.JSON, None),
            ("duplicate", b'{"format": "keenvpn-draft-session", "format": "keenvpn-draft-session"}', Code.JSON, None),
            ("nan", document(extra=float("nan")), Code.JSON, None),
            ("array", b"[]", Code.JSON, None),
            ("foreign", b'{"xkeen": true}', Code.FORMAT, "format"),
            ("metadata", b'{"format": "keenvpn-manager-metadata", "schema_version": 1}', Code.FORMAT, "format"),
            ("version zero", document(schema_version=0), Code.FORMAT, "schema_version"),
            ("version text", document(schema_version="1"), Code.FORMAT, "schema_version"),
            ("version bool", document(schema_version=True), Code.FORMAT, "schema_version"),
            ("version float", document(schema_version=1.0), Code.FORMAT, "schema_version"),
            ("newer", document(schema_version=2, draft_id=None), Code.SCHEMA_VERSION, "schema_version"),
            ("no id", document(draft_id=...), Code.FORMAT, "draft_id"),
            ("no time", document(created_at=...), Code.FORMAT, "created_at"),
            ("id null", document(draft_id=None), Code.DRAFT_ID, "draft_id"),
            ("id upper", document(draft_id=DRAFT_ID.upper()), Code.DRAFT_ID, "draft_id"),
        ]
        for label, content, code, field in cases:
            with self.subTest(case=label):
                self.assert_error(lambda: decode_draft_session(content), code, field)

    def test_unknown_field_that_cannot_be_kept_is_rejected(self):
        huge = b'{"format": "keenvpn-draft-session", "schema_version": 1, "draft_id": "' + DRAFT_ID.encode() + \
            b'", "created_at": "2026-11-01T02:14:16Z", "number": ' + b"9" * 4000 + b"}"
        self.assertEqual(len(decode_draft_session(huge).session.extra), 1)
        too_huge = huge.replace(b"9" * 4000, b"9" * 5000)
        with self.assertRaises(DraftSessionError) as caught:
            decode_draft_session(too_huge)
        self.assertIn(caught.exception.code, (Code.JSON, Code.UNKNOWN_FIELDS))
        self.assertIsNone(caught.exception.__context__)

    def test_encoding_rejects_file_larger_than_the_limit(self):
        self.assert_error(lambda: encode_draft_session(session({"big": "x" * MAX_DRAFT_SIZE})), Code.CONTENT)

    def test_revalidation_rebuilds_from_exact_types(self):
        class Text(str):
            pass
        valid = session({"note": 1})
        validate_draft_session(valid)
        for attribute, value, code in (
            ("draft_id", Text(DRAFT_ID), Code.DRAFT_ID),
            ("created_at", CREATED_AT.replace(tzinfo=None), Code.CREATED_AT),
            ("extra", {"note": 1}, Code.UNKNOWN_FIELDS),
        ):
            with self.subTest(attribute=attribute):
                broken = session({"note": 1})
                object.__setattr__(broken, attribute, value)
                self.assert_error(lambda: validate_draft_session(broken), code, None if code is Code.UNKNOWN_FIELDS
                                  else attribute)
                self.assert_error(lambda: encode_draft_session(broken), code, None if code is Code.UNKNOWN_FIELDS
                                  else attribute)
        tampered = session({"note": 1})
        object.__setattr__(tampered.extra, "_names", ("other",))
        self.assert_error(lambda: validate_draft_session(tampered), Code.UNKNOWN_FIELDS)
        self.assert_error(lambda: validate_draft_session("session"), Code.SESSION)

    def test_stored_session_requires_model_and_revision(self):
        revision = draft_revision(b"x")
        self.assertEqual(StoredDraftSession(session(), revision).revision, revision)
        self.assert_error(lambda: StoredDraftSession("session", revision), Code.SESSION)
        for value in (revision.upper(), revision[:-1], None, ""):
            with self.subTest(value=value):
                self.assert_error(lambda: StoredDraftSession(session(), value), Code.REVISION)


if __name__ == "__main__":
    unittest.main()


class DraftBaselineSectionTests(unittest.TestCase):
    def assert_error(self, call, code=Code.BASELINE, field="baseline"):
        with self.assertRaises(DraftSessionError) as caught:
            call()
        self.assertEqual((caught.exception.code, caught.exception.field), (code, field))
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_section_follows_known_fields_and_round_trips(self):
        model = DraftSession(DRAFT_ID, CREATED_AT, UnknownFields({"zeta": 1}), baseline())
        content = encode_draft_session(model)
        loaded = json.loads(content)
        self.assertEqual(list(loaded), ["format", "schema_version", "draft_id", "created_at", "baseline", "zeta"])
        self.assertEqual(loaded["baseline"], {
            "xray_configs": {"state": "present", "parts": {"01_log.json": "a" * 64}},
            "xkeen_init": {"state": "absent"},
            "keenetic_policies": {"state": "present", "sha256": "b" * 64},
        })
        stored = decode_draft_session(content)
        self.assertEqual(stored.session, model)
        self.assertEqual(encode_draft_session(stored.session), content)

    def test_draft_without_section_stays_valid(self):
        stored = decode_draft_session(document())
        self.assertIsNone(stored.session.baseline)
        self.assertNotIn(b"baseline", encode_draft_session(stored.session))

    def test_unknown_sources_of_another_version_are_kept(self):
        section = export_source_baseline(baseline())
        section["future_source"] = {"state": "present", "digest": {"x": [1, True]}}
        stored = decode_draft_session(document(baseline=section))
        self.assertEqual(stored.session.baseline.extra.export(), {"future_source": section["future_source"]})
        self.assertEqual(json.loads(encode_draft_session(stored.session))["baseline"], section)
        self.assertEqual(stored.session.to_diagnostic()["baseline"]["unknown_source_count"], 1)

    def test_damaged_section_rejects_the_file(self):
        good = export_source_baseline(baseline())
        for value in (
            None, [], "baseline", {"xkeen_init": None}, {"xkeen_init": {"state": "missing"}},
            {"xkeen_init": {"state": "absent", "sha256": "a" * 64}},
            {"xkeen_settings": {"state": "present"}}, {"xkeen_settings": {"state": "present", "sha256": "A" * 64}},
            {"xkeen_settings": {"state": "present", "sha256": "a" * 64, "size": 1}},
            {"xray_configs": {"state": "present", "sha256": "a" * 64}},
            {"xray_configs": {"state": "present", "parts": [["01_log.json", "a" * 64]]}},
            {"xray_configs": {"state": "present", "parts": {"../01.json": "a" * 64}}},
            {"xray_configs": {"state": "present", "parts": {"01_log.txt": "a" * 64}}},
            {**good, "xkeen_settings": {"state": "present", "sha256": SECRET}},
        ):
            with self.subTest(value=value):
                self.assert_error(lambda: decode_draft_session(document(baseline=value)))

    def test_section_too_deep_for_strict_reading_is_not_written(self):
        deep: object = 1
        for _ in range(63):
            deep = [deep]
        model = DraftSession(DRAFT_ID, CREATED_AT, baseline=baseline(future_source=deep))
        self.assert_error(lambda: encode_draft_session(model))

    def test_diagnostic_and_repr_show_states_without_hashes_and_part_names(self):
        model = DraftSession(DRAFT_ID, CREATED_AT, baseline=baseline())
        diagnostic = model.to_diagnostic()["baseline"]
        self.assertEqual(diagnostic, {"sources": [
            {"source": "xray_configs", "state": "present"}, {"source": "xkeen_init", "state": "absent"},
            {"source": "keenetic_policies", "state": "present"},
        ], "unknown_source_count": 0})
        text = repr(model) + repr(diagnostic) + str(model)
        for hidden in ("a" * 64, "b" * 64, "01_log.json"):
            self.assertNotIn(hidden, text)

    def test_revalidation_rejects_substituted_section(self):
        model = DraftSession(DRAFT_ID, CREATED_AT, baseline=baseline())
        object.__setattr__(model, "baseline", {"xkeen_init": {"state": "absent"}})
        self.assert_error(lambda: validate_draft_session(model))
        self.assert_error(lambda: encode_draft_session(model))
        fingerprint = SourceFingerprint(BaselineSource.XKEEN_INIT, FingerprintState.ABSENT)
        object.__setattr__(fingerprint, "sha256", "c" * 64)
        model = DraftSession(DRAFT_ID, CREATED_AT, baseline=SourceBaseline((fingerprint,)))
        self.assert_error(lambda: validate_draft_session(model))
        self.assert_error(lambda: DraftSession(DRAFT_ID, CREATED_AT, baseline={}))
