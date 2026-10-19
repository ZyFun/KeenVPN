"""Метаданные менеджера: модель, строгий формат, неизвестные поля и безопасное представление."""

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain import manager_metadata
from keenvpn.domain.config_document import MAX_JSON_DEPTH
from keenvpn.domain.manager_metadata import (
    MAX_LIMIT_VALUE, MAX_METADATA_SIZE, METADATA_FORMAT, RULE_KEY_CONDITIONS, HistoryLimits, ManagerMetadata,
    ManagerMetadataError, ManagerMetadataErrorCode as Code, RoleLocation, RuleKey, RuleRecord, StorageRoles,
    StoragePlacement, StorageVariant, StoredManagerMetadata, TrackedValue, UnknownFields, ValueState,
    decode_manager_metadata, encode_manager_metadata, metadata_revision, valid_metadata_revision, valid_storage_id,
    valid_storage_path, validate_manager_metadata,
)
from keenvpn.domain.routing import MAX_RULE_NAME_LENGTH, RoutingAction
from tests.support.isolation import forbid_external_effects


DATA_ID = "0000abcd-0000-4000-8000-00000000000a"
BACKUP_ID = "0000abcd-0000-4000-8000-00000000000c"
DATA_PATH = "/tmp/mnt/test-data/keenvpn-private"
BACKUP_PATH = "/tmp/mnt/test-backup/keenvpn-copies"
LONG_UTF8_PATH = "/" + "/".join(["я" * 120] * 18)
KNOWN, UNKNOWN, ABSENT = ValueState.KNOWN, ValueState.UNKNOWN, ValueState.ABSENT


def known(value):
    return TrackedValue(KNOWN, value)


def location(storage_id=DATA_ID, path=DATA_PATH, verified=True):
    return RoleLocation(KNOWN, known(storage_id), known(path), verified)


def placement(**changes):
    values = {
        "variant": known(StorageVariant.EXTENDED),
        "roles": StorageRoles(location(), RoleLocation(UNKNOWN), location(BACKUP_ID, BACKUP_PATH, False)),
        "history_limits": HistoryLimits(known(256 * 1024 * 1024), TrackedValue(UNKNOWN)),
    }
    values.update(changes)
    return StoragePlacement(**values)


def tracked(state, value=None, **extra):
    document = {"state": state}
    if value is not None:
        document["value"] = value
    document.update(extra)
    return document


def document(**changes):
    """Канонический документ формата с известными значениями всех видов."""
    result = {
        "format": METADATA_FORMAT,
        "schema_version": 1,
        "storage": {
            "variant": tracked("known", "simple"),
            "roles": {
                "data": {"state": "known", "storage_id": tracked("known", DATA_ID),
                         "path": tracked("known", DATA_PATH), "verified": True},
                "history": {"state": "known", "storage_id": tracked("unknown"),
                            "path": tracked("known", DATA_PATH + "/history"), "verified": False},
                "backups": {"state": "absent"},
            },
            "history_limits": {"size_bytes": tracked("known", 1024), "retention_seconds": tracked("absent")},
        },
    }
    result.update(changes)
    return result


def encoded(value) -> bytes:
    return json.dumps(value, ensure_ascii=True).encode("ascii")


def raw(text: str) -> bytes:
    return text.encode("utf-8")


class ModelTests(unittest.TestCase):
    def test_construction_rejects_overlong_utf8_path(self):
        for verified in (False, True):
            with self.subTest(verified=verified):
                with self.assertRaises(ManagerMetadataError) as caught:
                    location(path=LONG_UTF8_PATH, verified=verified)
                self.assertIs(caught.exception.code, Code.PATH)
                self.assertEqual(caught.exception.field, "path")
                self.assertNotIn(LONG_UTF8_PATH, str(caught.exception))

    def test_round_trip_is_canonical_and_revision_is_sha256_of_bytes(self):
        metadata = ManagerMetadata(placement())
        content = encode_manager_metadata(metadata)
        stored = decode_manager_metadata(content)
        self.assertEqual(stored.metadata, metadata)
        self.assertEqual(stored.revision, hashlib.sha256(content).hexdigest())
        self.assertEqual(stored.revision, metadata_revision(content))
        self.assertEqual(encode_manager_metadata(stored.metadata), content)
        self.assertTrue(content.endswith(b"}\n"))
        self.assertEqual(list(json.loads(content)), ["format", "schema_version", "storage"])
        self.assertEqual(decode_manager_metadata(encode_manager_metadata(ManagerMetadata())).metadata, ManagerMetadata())
        self.assertNotIn("storage", json.loads(encode_manager_metadata(ManagerMetadata())))

    def test_unknown_and_absent_are_distinct_at_every_level(self):
        stored = decode_manager_metadata(encoded(document())).metadata
        roles = stored.storage.roles
        self.assertIs(roles.history.state, KNOWN)
        self.assertIs(roles.history.storage_id.state, UNKNOWN)
        self.assertIsNone(roles.history.storage_id.value)
        self.assertIs(roles.backups.state, ABSENT)
        self.assertIs(stored.storage.history_limits.retention_seconds.state, ABSENT)
        self.assertIs(stored.storage.variant.value, StorageVariant.SIMPLE)
        unknown_role = decode_manager_metadata(encoded(document(storage={
            **document()["storage"], "roles": {**document()["storage"]["roles"], "backups": {"state": "unknown"}},
        }))).metadata
        self.assertIs(unknown_role.storage.roles.backups.state, UNKNOWN)
        self.assertNotEqual(unknown_role, stored)
        self.assertNotEqual(encode_manager_metadata(unknown_role), encode_manager_metadata(stored))
        self.assertNotEqual(TrackedValue(UNKNOWN), TrackedValue(ABSENT))
        self.assertNotEqual(RoleLocation(UNKNOWN), RoleLocation(ABSENT))

    def test_unknown_fields_survive_read_and_rewrite_at_every_level(self):
        source = document(**{"": "пустой ключ", "Storage": {"вариант": 1}, "FORMAT": True, "future_rules": [1, 2.5]})
        storage = source["storage"]
        storage[""] = None
        storage["Roles"] = "регистр"
        storage["variant"]["comment"] = {"nested": [True, False, None]}
        storage["variant"]["Value"] = "регистр"
        storage["roles"]["exports"] = {"state": "known"}
        storage["roles"]["data"]["label"] = "BACKUP"
        storage["roles"]["data"]["storage_id"]["kind"] = "ext4"
        storage["roles"]["data"]["path"][""] = 0
        storage["roles"]["backups"]["note"] = "absent role keeps fields"
        storage["history_limits"]["unit"] = "bytes"
        storage["history_limits"]["size_bytes"]["source"] = "detected"
        storage["history_limits"]["retention_seconds"]["STATE"] = "known"
        long_number = int("9" * 4000)
        source["big"] = long_number
        source["text"] = "x" * 100_000
        source["surrogate"] = "\ud800"
        content = json.dumps(source, ensure_ascii=True).encode("ascii")
        stored = decode_manager_metadata(content)
        rewritten = json.loads(encode_manager_metadata(stored.metadata))
        self.assertEqual(rewritten, source)
        self.assertEqual(list(rewritten)[3:], ["", "Storage", "FORMAT", "future_rules", "big", "text", "surrogate"])
        self.assertEqual(list(rewritten["storage"]["roles"]), ["data", "history", "backups", "exports"])
        self.assertEqual(rewritten["big"], long_number)
        self.assertEqual(stored.metadata.to_diagnostic()["unknown_field_count"], 19)
        self.assertEqual(stored.metadata.extra.names, ("", "Storage", "FORMAT", "future_rules", "big", "text", "surrogate"))
        # Повторная запись без изменений даёт те же байты и ту же ревизию.
        again = decode_manager_metadata(encode_manager_metadata(stored.metadata))
        self.assertEqual(encode_manager_metadata(again.metadata), encode_manager_metadata(stored.metadata))

    def test_unknown_field_values_keep_json_types(self):
        first = UnknownFields({"a": True})
        self.assertNotEqual(first, UnknownFields({"a": 1}))
        self.assertNotEqual(UnknownFields({"a": "1"}), UnknownFields({"a": 1}))
        self.assertNotEqual(UnknownFields({"a": 1.0}), UnknownFields({"a": 1}))
        self.assertEqual(first, UnknownFields({"a": True}))
        exported = first.export()
        exported["a"] = False
        self.assertEqual(first.export(), {"a": True})
        self.assertEqual(len(first), 1)
        self.assertEqual(repr(UnknownFields({"секрет": "значение"})), "UnknownFields(count=1)")
        for value in ({1: "a"}, {"a": float("nan")}, {"a": {1, 2}}, ["a"], "a", {"a": 10**5000}):
            with self.subTest(value=type(value).__name__), self.assertRaises(ManagerMetadataError) as caught:
                UnknownFields(value)
            self.assertIs(caught.exception.code, Code.UNKNOWN_FIELDS)

    def test_unknown_fields_cannot_shadow_known_names(self):
        for build in (
            lambda: TrackedValue(UNKNOWN, extra=UnknownFields({"value": 1})),
            lambda: RoleLocation(ABSENT, extra=UnknownFields({"verified": True})),
            lambda: HistoryLimits(TrackedValue(ABSENT), TrackedValue(ABSENT), UnknownFields({"size_bytes": 1})),
            lambda: placement(extra=UnknownFields({"roles": {}})),
            lambda: ManagerMetadata(extra=UnknownFields({"schema_version": 2})),
            lambda: ManagerMetadata(extra=UnknownFields({"format": "x"})),
        ):
            with self.assertRaises(ManagerMetadataError) as caught:
                build()
            self.assertIs(caught.exception.code, Code.UNKNOWN_FIELDS)

    def test_roles_may_share_one_storage_or_use_different_ones(self):
        same = ManagerMetadata(placement(
            variant=known(StorageVariant.SIMPLE),
            roles=StorageRoles(location(), location(path=DATA_PATH + "/history"), location(path=DATA_PATH + "/copies")),
        ))
        separate = ManagerMetadata(placement())
        self.assertEqual(same.to_diagnostic()["storage"]["distinct_storage_count"], 1)
        self.assertEqual(separate.to_diagnostic()["storage"]["distinct_storage_count"], 2)
        for metadata in (same, separate):
            self.assertEqual(decode_manager_metadata(encode_manager_metadata(metadata)).metadata, metadata)

    def test_safe_view_contains_states_and_limits_without_paths_or_identifiers(self):
        metadata = decode_manager_metadata(encoded(document(note="личная заметка"))).metadata
        diagnostic = metadata.to_diagnostic()
        self.assertEqual(diagnostic, {
            "schema_version": 1,
            "storage": {
                "variant_state": "known", "variant": "simple",
                "roles": [
                    {"role": "data", "state": "known", "storage_id_state": "known", "path_state": "known",
                     "verified": True},
                    {"role": "history", "state": "known", "storage_id_state": "unknown", "path_state": "known",
                     "verified": False},
                    {"role": "backups", "state": "absent", "storage_id_state": None, "path_state": None,
                     "verified": None},
                ],
                "distinct_storage_count": 1,
                "history_limits": {"size_state": "known", "size_bytes": 1024, "retention_state": "absent",
                                   "retention_seconds": None},
            },
            "rules": None,
            "unknown_field_count": 1,
        })
        self.assertEqual(
            ManagerMetadata().to_diagnostic(),
            {"schema_version": 1, "storage": None, "rules": None, "unknown_field_count": 0},
        )
        stored = decode_manager_metadata(encoded(document(note="личная заметка")))
        text = repr(stored) + str(stored) + repr(metadata) + json.dumps(diagnostic, ensure_ascii=False)
        for marker in (DATA_ID, DATA_PATH, "test-data", "личная заметка", "note"):
            self.assertNotIn(marker, text)

    def test_models_are_frozen(self):
        value = known(DATA_ID)
        with self.assertRaises(FrozenInstanceError):
            value.value = BACKUP_ID
        with self.assertRaises(FrozenInstanceError):
            ManagerMetadata().storage = None


class FormatTests(unittest.TestCase):
    def assert_rejected(self, content, code, field=None):
        with self.assertRaises(ManagerMetadataError) as caught:
            decode_manager_metadata(content)
        self.assertIs(caught.exception.code, code)
        self.assertEqual(caught.exception.field, field)
        return caught.exception

    def test_decoding_rejects_overlong_utf8_path(self):
        for verified in (False, True):
            with self.subTest(verified=verified):
                source = document()
                source["storage"]["roles"]["data"]["path"]["value"] = LONG_UTF8_PATH
                source["storage"]["roles"]["data"]["verified"] = verified
                error = self.assert_rejected(encoded(source), Code.PATH, "storage.roles.data.path")
                self.assertNotIn(LONG_UTF8_PATH, str(error))

    def test_rejects_non_utf8_oversized_and_non_bytes_content(self):
        for content in ("{}", bytearray(b"{}"), None, b"\xff{}", b'{"a": "\xc3"}'):
            with self.subTest(content=repr(content)):
                self.assert_rejected(content, Code.CONTENT)
        padding = MAX_METADATA_SIZE - len(encoded(document(pad="")))
        self.assertEqual(len(encoded(document(pad="x" * padding))), MAX_METADATA_SIZE)
        decode_manager_metadata(encoded(document(pad="x" * padding)))
        self.assert_rejected(encoded(document(pad="x" * (padding + 1))), Code.CONTENT)
        with self.assertRaises(ManagerMetadataError) as caught:
            encode_manager_metadata(ManagerMetadata(extra=UnknownFields({"pad": "x" * MAX_METADATA_SIZE})))
        self.assertIs(caught.exception.code, Code.CONTENT)

    def test_rejects_non_strict_json(self):
        good = json.dumps(document())
        deep = "[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1)
        cases = {
            "duplicate_top": good[:-1] + ', "format": "%s"}' % METADATA_FORMAT,
            "duplicate_nested": good.replace('"variant": {"state": "known"', '"variant": {"state": "known", "state": "known"'),
            "nan": good[:-1] + ', "x": NaN}',
            "infinity": good[:-1] + ', "x": Infinity}',
            "negative_infinity": good[:-1] + ', "x": -Infinity}',
            "overflow_float": good[:-1] + ', "x": 1e400}',
            "huge_int": good[:-1] + ', "x": %s}' % ("1" * 5000),
            "line_comment": good + " // хвост",
            "block_comment": "/* заголовок */" + good,
            "trailing_comma": good[:-1] + ",}",
            "array": "[]",
            "empty": "",
            "bom": "﻿" + good,
            "too_deep": good[:-1] + ', "x": %s}' % deep,
            "recursion": "[" * 100_000 + "]" * 100_000,
        }
        self.assertNotEqual(cases["duplicate_nested"], good)
        for label, text in cases.items():
            with self.subTest(case=label):
                self.assert_rejected(raw(text), Code.JSON)

    def test_format_marker_and_schema_version_are_checked_first(self):
        base = document()
        for label, changes, code, field in (
            ("no_format", {"format": None}, Code.FORMAT, "format"),
            ("other_format", {"format": "xkeen"}, Code.FORMAT, "format"),
            ("format_case", {"format": METADATA_FORMAT.upper()}, Code.FORMAT, "format"),
            ("no_version", {"schema_version": None}, Code.FORMAT, "schema_version"),
            ("bool_version", {"schema_version": True}, Code.FORMAT, "schema_version"),
            ("text_version", {"schema_version": "1"}, Code.FORMAT, "schema_version"),
            ("float_version", {"schema_version": 1.0}, Code.FORMAT, "schema_version"),
            ("zero_version", {"schema_version": 0}, Code.FORMAT, "schema_version"),
            ("next_version", {"schema_version": 2}, Code.SCHEMA_VERSION, "schema_version"),
            ("huge_version", {"schema_version": 10**30}, Code.SCHEMA_VERSION, "schema_version"),
        ):
            value = {**base, **changes}
            for key in [key for key, item in changes.items() if item is None]:
                del value[key]
            with self.subTest(case=label):
                self.assert_rejected(encoded(value), code, field)
        # Неподдерживаемая версия не разбирается дальше и не мигрирует.
        self.assert_rejected(encoded({"format": METADATA_FORMAT, "schema_version": 2, "storage": "иной формат"}),
                             Code.SCHEMA_VERSION, "schema_version")
        self.assert_rejected(encoded({"format": METADATA_FORMAT, "schema_version": 1, "storage": None}),
                             Code.FORMAT, "storage")
        decode_manager_metadata(encoded({"format": METADATA_FORMAT, "schema_version": 1}))

    def test_rejects_invalid_values_with_field_paths(self):
        def storage_with(path, value):
            result = document()
            target = result["storage"]
            *parents, last = path
            for key in parents:
                target = target[key]
            if value is KeyError:
                del target[last]
            else:
                target[last] = value
            return result

        data = ("roles", "data")
        cases = (
            (data + ("storage_id", "value"), DATA_ID.upper(), Code.STORAGE_ID, "storage.roles.data.storage_id"),
            (data + ("storage_id", "value"), "/dev/sda1", Code.STORAGE_ID, "storage.roles.data.storage_id"),
            (data + ("storage_id", "value"), "ENTWARE", Code.STORAGE_ID, "storage.roles.data.storage_id"),
            (data + ("storage_id", "value"), "", Code.STORAGE_ID, "storage.roles.data.storage_id"),
            (data + ("storage_id", "value"), 1, Code.STORAGE_ID, "storage.roles.data.storage_id"),
            (data + ("path", "value"), "relative/path", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/a/", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "//a", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/a//b", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/a/./b", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/a/../b", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/a\nb", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/a\x1b[31m", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/a\x00b", Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/" + "a" * 256, Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/a" * 2049, Code.PATH, "storage.roles.data.path"),
            (data + ("path", "value"), "/\ud800", Code.PATH, "storage.roles.data.path"),
            (data + ("verified",), 1, Code.VERIFIED, "storage.roles.data.verified"),
            (data + ("verified",), KeyError, Code.FORMAT, "storage.roles.data.verified"),
            (data + ("path",), KeyError, Code.FORMAT, "storage.roles.data.path"),
            (data + ("state",), "maybe", Code.STATE, "storage.roles.data.state"),
            (data + ("state",), "KNOWN", Code.STATE, "storage.roles.data.state"),
            (data + ("state",), KeyError, Code.STATE, "storage.roles.data.state"),
            (data + ("path", "state"), "unknown", Code.FORMAT, "storage.roles.data.path.value"),
            (data + ("path", "value"), KeyError, Code.FORMAT, "storage.roles.data.path.value"),
            (data + ("path", "value"), None, Code.STATE, "storage.roles.data.path.value"),
            (data + ("path",), "/a", Code.FORMAT, "storage.roles.data.path"),
            (("roles", "backups", "path"), tracked("unknown"), Code.FORMAT, "storage.roles.backups.path"),
            (("roles", "backups", "verified"), False, Code.FORMAT, "storage.roles.backups.verified"),
            (("roles", "history", "verified"), True, Code.VERIFIED, "storage.roles.history.verified"),
            (("roles", "history"), KeyError, Code.FORMAT, "storage.roles.history"),
            (("roles",), [], Code.FORMAT, "storage.roles"),
            (("variant", "value"), "network", Code.VARIANT, "storage.variant.value"),
            (("variant", "value"), "Simple", Code.VARIANT, "storage.variant.value"),
            (("variant",), KeyError, Code.FORMAT, "storage.variant"),
            (("history_limits", "size_bytes", "value"), 0, Code.LIMIT, "storage.history_limits.size_bytes"),
            (("history_limits", "size_bytes", "value"), -1, Code.LIMIT, "storage.history_limits.size_bytes"),
            (("history_limits", "size_bytes", "value"), True, Code.LIMIT, "storage.history_limits.size_bytes"),
            (("history_limits", "size_bytes", "value"), 1.5, Code.LIMIT, "storage.history_limits.size_bytes"),
            (("history_limits", "size_bytes", "value"), "1024", Code.LIMIT, "storage.history_limits.size_bytes"),
            (("history_limits", "size_bytes", "value"), MAX_LIMIT_VALUE + 1, Code.LIMIT,
             "storage.history_limits.size_bytes"),
            (("history_limits", "retention_seconds"), KeyError, Code.FORMAT, "storage.history_limits.retention_seconds"),
            (("history_limits",), KeyError, Code.FORMAT, "storage.history_limits"),
        )
        for path, value, code, field in cases:
            with self.subTest(path=path, value=repr(value)[:40]):
                self.assert_rejected(encoded(storage_with(path, value)), code, field)
        limits = decode_manager_metadata(encoded(storage_with(("history_limits", "size_bytes", "value"), MAX_LIMIT_VALUE)))
        self.assertEqual(limits.metadata.storage.history_limits.size_bytes.value, MAX_LIMIT_VALUE)

    def test_errors_are_detached_and_hide_values(self):
        cases = (
            (encoded(document(storage={**document()["storage"], "variant": tracked("known", DATA_PATH)})),
             Code.VARIANT, "storage.variant.value"),
            (b"\xff" + raw(DATA_PATH), Code.CONTENT, None),
            (raw('{"%s": NaN}' % DATA_PATH), Code.JSON, None),
            (encoded({"format": METADATA_FORMAT, "schema_version": 3, DATA_PATH: 1}), Code.SCHEMA_VERSION,
             "schema_version"),
        )
        for content, code, field in cases:
            with self.subTest(code=code.value):
                try:
                    raise RuntimeError("чужая ошибка с " + DATA_PATH)
                except RuntimeError:
                    with self.assertRaises(ManagerMetadataError) as caught:
                        decode_manager_metadata(content)
                error = caught.exception
                self.assertIs(error.code, code)
                self.assertEqual(error.field, field)
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertNotIn(DATA_PATH, str(error) + repr(error.args) + str(error.field))


class ValidationTests(unittest.TestCase):
    def tampered(self, target, name, value):
        object.__setattr__(target, name, value)

    def assert_invalid(self, metadata, code, field=None):
        with self.assertRaises(ManagerMetadataError) as caught:
            validate_manager_metadata(metadata)
        self.assertIs(caught.exception.code, code)
        self.assertEqual(caught.exception.field, field)
        with self.assertRaises(ManagerMetadataError):
            encode_manager_metadata(metadata)

    def test_encoding_rejects_tampered_overlong_utf8_path(self):
        metadata = ManagerMetadata(placement())
        self.tampered(metadata.storage.roles.data.path, "value", LONG_UTF8_PATH)
        self.assert_invalid(metadata, Code.PATH, "storage.roles.data.path")

    def test_valid_models_pass_and_foreign_types_fail(self):
        validate_manager_metadata(ManagerMetadata(placement()))
        validate_manager_metadata(ManagerMetadata())

        class Derived(ManagerMetadata):
            pass

        for value in (None, {}, Derived()):
            with self.subTest(value=type(value).__name__):
                self.assert_invalid(value, Code.METADATA)

    def test_equal_but_differently_typed_values_are_rejected(self):
        cases = []
        metadata = ManagerMetadata(placement())
        self.tampered(metadata.storage.variant, "state", "known")
        cases.append((metadata, Code.STATE, "storage.variant"))
        metadata = ManagerMetadata(placement())
        self.tampered(metadata.storage.variant, "value", "extended")
        cases.append((metadata, Code.VARIANT, "storage.variant"))
        metadata = ManagerMetadata(placement(history_limits=HistoryLimits(known(1), TrackedValue(ABSENT))))
        self.tampered(metadata.storage.history_limits.size_bytes, "value", True)
        cases.append((metadata, Code.LIMIT, "storage.history_limits.size_bytes"))
        metadata = ManagerMetadata(placement())
        self.tampered(metadata.storage.roles.data, "verified", 1)
        cases.append((metadata, Code.VERIFIED, "storage.roles.data.verified"))
        metadata = ManagerMetadata(placement())
        self.tampered(metadata.storage.roles.history, "state", "unknown")
        cases.append((metadata, Code.STATE, "storage.roles.history.state"))
        metadata = ManagerMetadata(placement())
        self.tampered(metadata.storage.roles.data.path, "value", "/a/../b")
        cases.append((metadata, Code.PATH, "storage.roles.data.path"))
        for metadata, code, field in cases:
            with self.subTest(code=code.value, field=field):
                self.assert_invalid(metadata, code, field)

    def test_nested_objects_are_rebuilt_from_their_own_fields(self):
        metadata = ManagerMetadata(placement())
        self.tampered(metadata.storage, "roles", {"data": None})
        self.assert_invalid(metadata, Code.FORMAT, "storage.roles")
        metadata = ManagerMetadata(placement())
        self.tampered(metadata.storage.roles, "backups", RoleLocation(KNOWN, known(BACKUP_ID), known(BACKUP_PATH), False))
        validate_manager_metadata(metadata)
        self.tampered(metadata.storage.roles.backups, "storage_id", TrackedValue(UNKNOWN))
        self.tampered(metadata.storage.roles.backups, "verified", True)
        self.assert_invalid(metadata, Code.VERIFIED, "storage.roles.backups.verified")
        metadata = ManagerMetadata(extra=UnknownFields({"a": 1}))
        self.tampered(metadata.extra, "_snapshot", '{"b":1}')
        self.assert_invalid(metadata, Code.UNKNOWN_FIELDS)
        metadata = ManagerMetadata(extra=UnknownFields({"a": 1}))
        self.tampered(metadata.extra, "_snapshot", "{")
        self.assert_invalid(metadata, Code.METADATA)
        metadata = ManagerMetadata(placement())
        self.tampered(metadata, "storage", "storage")
        self.assert_invalid(metadata, Code.FORMAT, "storage")

    def test_encoding_rejects_unknown_fields_that_exceed_total_depth(self):
        nested: object = 1
        for _ in range(MAX_JSON_DEPTH - 1):
            nested = [nested]
        UnknownFields({"deep": nested})
        ManagerMetadata(extra=UnknownFields({"deep": nested}))
        encode_manager_metadata(ManagerMetadata(extra=UnknownFields({"deep": nested})))
        roles = StorageRoles(location(), RoleLocation(ABSENT, extra=UnknownFields({"deep": nested})), RoleLocation(ABSENT))
        with self.assertRaises(ManagerMetadataError) as caught:
            encode_manager_metadata(ManagerMetadata(placement(roles=roles)))
        self.assertIs(caught.exception.code, Code.UNKNOWN_FIELDS)

    def test_constructor_checks(self):
        for build, code in (
            (lambda: TrackedValue("known", 1), Code.STATE),
            (lambda: TrackedValue(KNOWN), Code.STATE),
            (lambda: TrackedValue(UNKNOWN, 1), Code.STATE),
            (lambda: TrackedValue(ABSENT, extra={}), Code.UNKNOWN_FIELDS),
            (lambda: RoleLocation(KNOWN, known(DATA_ID), known(DATA_PATH), None), Code.VERIFIED),
            (lambda: RoleLocation(KNOWN, known(DATA_ID), TrackedValue(ABSENT), True), Code.VERIFIED),
            (lambda: RoleLocation(KNOWN, known(DATA_ID), None, False), Code.FORMAT),
            (lambda: RoleLocation(UNKNOWN, verified=False), Code.FORMAT),
            (lambda: RoleLocation(KNOWN, known("label"), known(DATA_PATH), False), Code.STORAGE_ID),
            (lambda: StorageRoles(location(), location(), None), Code.FORMAT),
            (lambda: HistoryLimits(known(0), TrackedValue(ABSENT)), Code.LIMIT),
            (lambda: placement(variant=known("simple")), Code.VARIANT),
            (lambda: ManagerMetadata(storage={}), Code.FORMAT),
            (lambda: StoredManagerMetadata(ManagerMetadata(), "A" * 64), Code.REVISION),
            (lambda: StoredManagerMetadata(None, "0" * 64), Code.METADATA),
        ):
            with self.assertRaises(ManagerMetadataError) as caught:
                build()
            self.assertIs(caught.exception.code, code)
        RoleLocation(KNOWN, TrackedValue(UNKNOWN), TrackedValue(UNKNOWN), False)


RULE_ID_A = "0000abcd-0000-4000-8000-0000000000a1"
RULE_ID_B = "0000abcd-0000-4000-8000-0000000000b2"
RULE_NAME = "TEST_PRIVATE_RULE_NAME"
RULE_VALUE = "subdomains:private.example.test"


def rule_key(condition="domain", value=RULE_VALUE, action=RoutingAction.VPN, **extra):
    return RuleKey(condition, value, action, UnknownFields(extra) if extra else UnknownFields())


def rule_record(rule_id=RULE_ID_A, name=RULE_NAME, key=None, **extra):
    return RuleRecord(rule_id, name, rule_key() if key is None else key, UnknownFields(extra) if extra else UnknownFields())


def record_json(rule_id=RULE_ID_A, name=RULE_NAME, key=None, **extra):
    document = {
        "id": rule_id, "name": name,
        "key": {"condition": "domain", "value": RULE_VALUE, "action": "VPN"} if key is None else key,
    }
    document.update(extra)
    return document


class _Text(str):
    """Подкласс строки: формат требует именно `str`."""


class RuleRecordsTests(unittest.TestCase):
    """Необязательный раздел `rules`: формат, неизвестные поля, дубли и безопасный вывод."""

    def assert_rejected(self, content, code, field):
        with self.assertRaises(ManagerMetadataError) as caught:
            decode_manager_metadata(content)
        self.assertIs(caught.exception.code, code)
        self.assertEqual(caught.exception.field, field)
        self.assertIsNone(caught.exception.__context__)
        return caught.exception

    def test_file_without_rules_reads_and_writes_as_before_byte_for_byte(self):
        for source in (document(), {"format": METADATA_FORMAT, "schema_version": 1}):
            with self.subTest(sections=list(source)):
                content = (json.dumps(source, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("ascii")
                stored = decode_manager_metadata(content)
                self.assertIsNone(stored.metadata.rules)
                self.assertEqual(encode_manager_metadata(stored.metadata), content)
                self.assertNotIn("rules", json.loads(encode_manager_metadata(stored.metadata)))
                self.assertEqual(stored.metadata.to_diagnostic()["rules"], None)
        self.assertEqual(ManagerMetadata(placement()).rules, None)
        self.assertEqual(json.loads(encode_manager_metadata(ManagerMetadata(placement()))).get("rules", "absent"), "absent")

    def test_round_trip_keeps_records_order_names_keys_and_schema_version(self):
        records = (
            rule_record(),
            rule_record(RULE_ID_B, None, rule_key("ip", "198.51.100.0/24", RoutingAction.DIRECT)),
        )
        metadata = ManagerMetadata(placement(), rules=records)
        content = encode_manager_metadata(metadata)
        parsed = json.loads(content)
        self.assertEqual(list(parsed), ["format", "schema_version", "storage", "rules"])
        self.assertEqual(parsed["schema_version"], 1)
        self.assertEqual(parsed["rules"], [
            record_json(),
            record_json(RULE_ID_B, None, {"condition": "ip", "value": "198.51.100.0/24", "action": "DIRECT"}),
        ])
        stored = decode_manager_metadata(content)
        self.assertEqual(stored.metadata, metadata)
        self.assertEqual(stored.metadata.rules, records)
        self.assertEqual(encode_manager_metadata(stored.metadata), content)
        empty = encode_manager_metadata(ManagerMetadata(rules=()))
        self.assertEqual(json.loads(empty)["rules"], [])
        self.assertEqual(decode_manager_metadata(empty).metadata.rules, ())
        self.assertNotEqual(decode_manager_metadata(empty).metadata, ManagerMetadata())

    def test_every_key_condition_and_action_round_trips(self):
        records = tuple(
            rule_record(f"0000abcd-0000-4000-8000-0000000000{index:02x}", None, rule_key(condition, f"{condition}-value", action))
            for index, (condition, action) in enumerate(
                (condition, action) for condition in sorted(RULE_KEY_CONDITIONS) for action in RoutingAction
            )
        )
        stored = decode_manager_metadata(encode_manager_metadata(ManagerMetadata(rules=records)))
        self.assertEqual(stored.metadata.rules, records)
        self.assertEqual({record.key.action for record in stored.metadata.rules}, set(RoutingAction))
        self.assertTrue(all(type(record.key.action) is RoutingAction for record in stored.metadata.rules))

    def test_unknown_fields_of_records_and_keys_survive_rewrite(self):
        source = document(rules=[
            record_json(**{"": None, "Id": "регистр", "weight": 1.5, "nested": {"a": [True]}}),
            record_json(RULE_ID_B, None, {"condition": "ip", "value": "2001:db8::/32", "action": "BLOCK", "Value": 0, "hint": "x"}),
        ])
        content = encoded(source)
        stored = decode_manager_metadata(content)
        rewritten = json.loads(encode_manager_metadata(stored.metadata))
        self.assertEqual(rewritten["rules"], source["rules"])
        self.assertEqual(list(rewritten["rules"][0]), ["id", "name", "key", "", "Id", "weight", "nested"])
        self.assertEqual(list(rewritten["rules"][1]["key"]), ["condition", "value", "action", "Value", "hint"])
        self.assertEqual(stored.metadata.rules[0].extra.names, ("", "Id", "weight", "nested"))
        self.assertEqual(stored.metadata.rules[1].key.extra.names, ("Value", "hint"))
        self.assertEqual(stored.metadata.to_diagnostic()["unknown_field_count"], 6)
        again = decode_manager_metadata(encode_manager_metadata(stored.metadata))
        self.assertEqual(encode_manager_metadata(again.metadata), encode_manager_metadata(stored.metadata))

    def test_unknown_fields_cannot_shadow_record_or_key_names(self):
        cases = (
            (lambda: RuleRecord(RULE_ID_A, RULE_NAME, rule_key(), UnknownFields({"id": "x"})), "rules[0]"),
            (lambda: RuleRecord(RULE_ID_A, RULE_NAME, rule_key(), UnknownFields({"key": {}})), "rules[0]"),
            (lambda: RuleKey("domain", RULE_VALUE, RoutingAction.VPN, UnknownFields({"action": "VPN"})), "rules[0].key"),
        )
        for build, _path in cases:
            with self.subTest(path=_path):
                with self.assertRaises(ManagerMetadataError) as caught:
                    build()
                self.assertIs(caught.exception.code, Code.UNKNOWN_FIELDS)
        # Тот же запрет при чтении файла: поле записи с именем известного поля сюда попасть не может,
        # потому что строгий JSON отклоняет дубли ключей; проверяется запись и чтение модели.

    def test_duplicate_record_id_rejects_the_whole_file(self):
        content = encoded(document(rules=[record_json(), record_json(RULE_ID_B, None), record_json(name=None)]))
        self.assert_rejected(content, Code.DUPLICATE_RULE_RECORD_ID, "rules[2].id")
        with self.assertRaises(ManagerMetadataError) as caught:
            ManagerMetadata(rules=(rule_record(), rule_record(name=None)))
        self.assertIs(caught.exception.code, Code.DUPLICATE_RULE_RECORD_ID)
        self.assertEqual(caught.exception.field, "rules[1].id")
        # Одинаковые ключи — не ошибка формата: их разбирает привязка.
        same_key = decode_manager_metadata(encoded(document(rules=[record_json(), record_json(RULE_ID_B, None)])))
        self.assertEqual(len(same_key.metadata.rules), 2)

    def test_rejects_invalid_records_with_field_paths(self):
        cases = (
            ("null_section", None, Code.FORMAT, "rules"),
            ("object_section", {}, Code.FORMAT, "rules"),
            ("record_not_object", [1], Code.FORMAT, "rules[0]"),
            ("missing_id", [{"name": None, "key": record_json()["key"]}], Code.FORMAT, "rules[0].id"),
            ("missing_name", [{"id": RULE_ID_A, "key": record_json()["key"]}], Code.FORMAT, "rules[0].name"),
            ("missing_key", [{"id": RULE_ID_A, "name": None}], Code.FORMAT, "rules[0].key"),
            ("null_id", [record_json(rule_id=None)], Code.RULE_RECORD_ID, "rules[0].id"),
            ("uppercase_id", [record_json(rule_id=RULE_ID_A.upper())], Code.RULE_RECORD_ID, "rules[0].id"),
            ("braced_id", [record_json(rule_id="{" + RULE_ID_A + "}")], Code.RULE_RECORD_ID, "rules[0].id"),
            ("numeric_id", [record_json(rule_id=1)], Code.RULE_RECORD_ID, "rules[0].id"),
            ("empty_name", [record_json(name="")], Code.RULE_RECORD_NAME, "rules[0].name"),
            ("padded_name", [record_json(name=" x")], Code.RULE_RECORD_NAME, "rules[0].name"),
            ("control_name", [record_json(name="a\x1bb")], Code.RULE_RECORD_NAME, "rules[0].name"),
            ("long_name", [record_json(name="x" * (MAX_RULE_NAME_LENGTH + 1))], Code.RULE_RECORD_NAME, "rules[0].name"),
            ("numeric_name", [record_json(name=5)], Code.RULE_RECORD_NAME, "rules[0].name"),
            ("key_not_object", [record_json(key="domain")], Code.FORMAT, "rules[0].key"),
            ("key_missing_value", [record_json(key={"condition": "domain", "action": "VPN"})], Code.FORMAT, "rules[0].key.value"),
            ("key_unknown_condition", [record_json(key={"condition": "port", "value": "53", "action": "VPN"})], Code.RULE_KEY, "rules[0].key"),
            ("key_condition_case", [record_json(key={"condition": "Domain", "value": "x", "action": "VPN"})], Code.RULE_KEY, "rules[0].key"),
            ("key_empty_value", [record_json(key={"condition": "domain", "value": "", "action": "VPN"})], Code.RULE_KEY, "rules[0].key"),
            ("key_numeric_value", [record_json(key={"condition": "ip", "value": 1, "action": "VPN"})], Code.RULE_KEY, "rules[0].key"),
            ("key_action_case", [record_json(key={"condition": "domain", "value": "x", "action": "vpn"})], Code.RULE_KEY, "rules[0].key.action"),
            ("key_action_null", [record_json(key={"condition": "domain", "value": "x", "action": None})], Code.RULE_KEY, "rules[0].key.action"),
            ("second_record_bad", [record_json(), record_json(RULE_ID_B, "")], Code.RULE_RECORD_NAME, "rules[1].name"),
        )
        for name, rules, code, field in cases:
            with self.subTest(name):
                error = self.assert_rejected(encoded(document(rules=rules)), code, field)
                rendered = str(error) + repr(error) + repr(vars(error))
                self.assertNotIn(RULE_NAME, rendered)
                self.assertNotIn("private.example", rendered)

    def test_validation_rebuilds_records_and_rejects_equal_but_differently_typed_values(self):
        metadata = ManagerMetadata(rules=(rule_record(),))
        record = metadata.rules[0]
        cases = (
            (record, "rule_id", _Text(RULE_ID_A), Code.RULE_RECORD_ID),
            (record, "name", _Text(RULE_NAME), Code.RULE_RECORD_NAME),
            (record.key, "action", "VPN", Code.RULE_KEY),
            (record.key, "condition", _Text("domain"), Code.RULE_KEY),
            (record.key, "value", _Text(RULE_VALUE), Code.RULE_KEY),
        )
        for owner, attribute, value, code in cases:
            with self.subTest(attribute=attribute):
                original = getattr(owner, attribute)
                object.__setattr__(owner, attribute, value)
                try:
                    self.assertEqual(getattr(owner, attribute), original)
                    with self.assertRaises(ManagerMetadataError) as caught:
                        validate_manager_metadata(metadata)
                    self.assertIs(caught.exception.code, code)
                    with self.assertRaises(ManagerMetadataError):
                        encode_manager_metadata(metadata)
                finally:
                    object.__setattr__(owner, attribute, original)
        validate_manager_metadata(metadata)
        object.__setattr__(metadata, "rules", [record])
        with self.assertRaises(ManagerMetadataError) as caught:
            validate_manager_metadata(metadata)
        self.assertIs(caught.exception.code, Code.FORMAT)
        self.assertEqual(caught.exception.field, "rules")

    def test_safe_output_hides_names_and_key_values_and_counts_records(self):
        metadata = ManagerMetadata(
            placement(), rules=(rule_record(), rule_record(RULE_ID_B, None, rule_key("ip", "198.51.100.7", RoutingAction.BLOCK), note="x")),
        )
        diagnostic = metadata.to_diagnostic()
        self.assertEqual(diagnostic["rules"], {"record_count": 2, "named_record_count": 1})
        self.assertEqual(diagnostic["unknown_field_count"], 1)
        stored = decode_manager_metadata(encode_manager_metadata(metadata))
        text = (
            repr(metadata) + str(metadata) + repr(stored) + repr(metadata.rules) + repr(metadata.rules[0].key)
            + json.dumps(diagnostic, ensure_ascii=False)
        )
        for marker in (RULE_NAME, "private.example", "subdomains", "198.51.100.7", "note"):
            self.assertNotIn(marker, text)
        self.assertIn(RULE_ID_A, repr(metadata.rules[0]))
        self.assertEqual(repr(metadata.rules[0].key), "RuleKey(condition=domain, action=VPN)")

    def test_records_are_frozen_and_need_no_io(self):
        record = rule_record()
        with self.assertRaises(FrozenInstanceError):
            record.name = "x"
        with self.assertRaises(FrozenInstanceError):
            record.key.value = "x"
        with forbid_external_effects():
            content = encode_manager_metadata(ManagerMetadata(rules=(record,)))
            stored = decode_manager_metadata(content)
            validate_manager_metadata(stored.metadata)
            stored.metadata.to_diagnostic()


class HelperTests(unittest.TestCase):
    def test_storage_path_limit_uses_utf8_bytes_including_separators(self):
        for character in ("a", "я", "😀"):
            width = len(character.encode("utf-8"))
            prefix = ("/" + character * (240 // width)) * 16
            for extra in (-1, 0, 1):
                with self.subTest(character=character, extra=extra):
                    size = manager_metadata.MAX_PATH_LENGTH + extra
                    count, tail = divmod(size - len(prefix.encode("utf-8")) - 1, width)
                    path = prefix + "/" + character * count + "a" * tail
                    self.assertEqual(len(path.encode("utf-8")), size)
                    self.assertTrue(all(len(part.encode("utf-8")) <= manager_metadata.MAX_PATH_COMPONENT
                                        for part in path[1:].split("/")))
                    self.assertEqual(valid_storage_path(path), extra <= 0)

    def test_storage_id_and_path_formats(self):
        self.assertTrue(valid_storage_id(DATA_ID))
        for value in (DATA_ID.upper(), DATA_ID + "\n", "/dev/sda1", "sda1", "ENTWARE", "1234-ABCD", None, 1):
            self.assertFalse(valid_storage_id(value))
        for value in (DATA_PATH, "/opt/var/lib/keenvpn", "/данные пользователя", "/" + "a" * 255, "/a" * 2048):
            self.assertTrue(valid_storage_path(value))
        for value in ("", "/", "a", "/a/", "//a", "/a/.", "/a/..", "/a\tb", "/\ud800", "/" + "я" * 128, None):
            self.assertFalse(valid_storage_path(value))
        self.assertTrue(valid_metadata_revision("0" * 64))
        for value in ("0" * 63, "0" * 65, "G" * 64, "A" * 64, None):
            self.assertFalse(valid_metadata_revision(value))

    def test_decoding_cost_is_linear_in_unknown_fields(self):
        # Детерминированно: число выполненных строк модуля, без измерения времени.
        def executed_lines(count):
            source = document(**{f"extra_{index}": {"nested": [index]} for index in range(count)})
            for role in ("data", "history", "backups"):
                source["storage"]["roles"][role].update({f"field_{index}": index for index in range(count)})
            content = encoded(source)
            lines = 0
            module_file = manager_metadata.__file__

            def tracer(frame, event, _arg):
                nonlocal lines
                if frame.f_code.co_filename != module_file:
                    return None
                if event == "line":
                    lines += 1
                return tracer

            sys.settrace(tracer)
            try:
                stored = decode_manager_metadata(content)
                encode_manager_metadata(stored.metadata)
                stored.metadata.to_diagnostic()
            finally:
                sys.settrace(None)
            return lines

        small, large = executed_lines(200), executed_lines(800)
        # Линейная стоимость даёт отношение около 4, квадратичная — около 16.
        self.assertLess(large, small * 5)

    def test_no_file_network_process_or_terminal_io(self):
        content = encoded(document(extra={"a": [1, 2]}))
        with forbid_external_effects():
            stored = decode_manager_metadata(content)
            validate_manager_metadata(stored.metadata)
            encode_manager_metadata(stored.metadata)
            stored.metadata.to_diagnostic()
            metadata_revision(content)


if __name__ == "__main__":
    unittest.main()
