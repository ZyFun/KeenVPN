"""Первичный импорт обнаруженного размещения и просмотр метаданных менеджера.

Сценарии проверяются на управляемых адаптерах в памяти и с настоящим
файловым хранилищем во временном каталоге. Роутер, active configs Xray
и XKeen, сеть и процессы не используются.
"""

from dataclasses import FrozenInstanceError
import errno
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import manager_metadata_files
from keenvpn.adapters.manager_metadata_files import METADATA_FILE_NAME, ManagerMetadataFiles
from keenvpn.application import manager_metadata as scenarios
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.manager_metadata import (
    ImportStoragePlacement, ImportStoragePlacementHandler, InspectManagerMetadata, InspectManagerMetadataHandler,
    ManagerMetadataStatusView, StoragePlacementImportOutcome, StoragePlacementImportView,
)
from keenvpn.application.ports import (
    ManagerMetadataStoreError, MetadataStoreFailure as Failure, MetadataStoreReason as Reason,
)
from keenvpn.domain import manager_metadata as domain
from keenvpn.domain.manager_metadata import (
    MAX_LIMIT_VALUE, MAX_METADATA_SIZE, METADATA_FORMAT, HistoryLimits, ManagerMetadata, ManagerMetadataErrorCode,
    RoleLocation, RuleKey, RuleRecord, StoragePlacement, StorageRoles, StorageVariant, StoredManagerMetadata,
    TrackedValue, UnknownFields, ValueState, decode_manager_metadata, encode_manager_metadata, metadata_revision,
)
from keenvpn.domain.routing import RoutingAction
from tests.support import in_memory
from tests.support.in_memory import (
    AdapterSetupError, InMemoryManagerMetadataStore, InMemoryStoragePlacementSource, UnconfiguredResponseError,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable


DATA_ID = "0000abcd-0000-4000-8000-00000000000a"
HISTORY_ID = "0000abcd-0000-4000-8000-00000000000b"
BACKUP_ID = "0000abcd-0000-4000-8000-00000000000c"
DATA_PATH = "/tmp/mnt/test-data/keenvpn-private"
HISTORY_PATH = "/tmp/mnt/test-history/keenvpn-history"
BACKUP_PATH = "/tmp/mnt/test-backup/keenvpn-copies"
RULE_ID = "0000abcd-0000-4000-8000-0000000000e1"
PRIVATE_MARKERS = (
    "0000abcd", "/tmp/mnt", "test-data", "test-history", "test-backup", "keenvpn-private", "keenvpn-history",
    "keenvpn-copies", "private-note", "future-section", "secret-extra", "Искусственный", "private-rule-name",
    "private.example", "subdomains:",
)
PRIVATE_TYPES = (
    ManagerMetadata, StoredManagerMetadata, StoragePlacement, StorageRoles, RoleLocation, HistoryLimits, TrackedValue,
    UnknownFields, RuleRecord, RuleKey, BaseException, bytes,
)
KNOWN, UNKNOWN, ABSENT = ValueState.KNOWN, ValueState.UNKNOWN, ValueState.ABSENT
CATEGORIES = {
    Failure.UNAVAILABLE: ErrorCategory.SOURCE_FAILED,
    Failure.UNSAFE: ErrorCategory.SOURCE_FAILED,
    Failure.BUSY: ErrorCategory.SOURCE_FAILED,
    Failure.CONFLICT: ErrorCategory.SOURCE_FAILED,
    Failure.INVALID: ErrorCategory.INVALID_SOURCE_DATA,
    Failure.WRITE_FAILED: ErrorCategory.SOURCE_FAILED,
    Failure.WRITE_UNCONFIRMED: ErrorCategory.SOURCE_FAILED,
}
REASONS = {
    Failure.UNAVAILABLE: Reason.IO_ERROR.value,
    Failure.UNSAFE: Reason.REPLACED.value,
    Failure.BUSY: None,
    Failure.CONFLICT: None,
    Failure.INVALID: ManagerMetadataErrorCode.JSON.value,
    Failure.WRITE_FAILED: Reason.NO_SPACE.value,
    Failure.WRITE_UNCONFIRMED: Reason.IO_ERROR.value,
}


def known(value):
    return TrackedValue(KNOWN, value)


def role(storage_id=DATA_ID, path=DATA_PATH, verified=True):
    return RoleLocation(KNOWN, known(storage_id), known(path), verified)


def placement(variant=StorageVariant.SIMPLE, roles=None, size=None, retention=None, **extra):
    """Размещение по умолчанию: три роли в отдельных каталогах одного раздела."""
    if roles is None:
        roles = StorageRoles(role(), role(path=DATA_PATH + "/history"), role(path=DATA_PATH + "/backups"))
    return StoragePlacement(
        variant if isinstance(variant, TrackedValue) else known(variant), roles,
        HistoryLimits(
            known(256 * 1024 * 1024) if size is None else size,
            known(30 * 24 * 3600) if retention is None else retention,
        ),
        **extra,
    )


def separate_partitions():
    return placement(StorageVariant.EXTENDED, StorageRoles(
        role(), role(HISTORY_ID, HISTORY_PATH), role(BACKUP_ID, BACKUP_PATH, False),
    ))


def partial_placement():
    """Неизвестные и отсутствующие значения всех видов без выбранных значений по умолчанию."""
    data = RoleLocation(KNOWN, TrackedValue(UNKNOWN), known(DATA_PATH), False)
    history = RoleLocation(KNOWN, known(HISTORY_ID), TrackedValue(ABSENT), False)
    return placement(
        TrackedValue(UNKNOWN), StorageRoles(data, history, RoleLocation(ABSENT)),
        size=TrackedValue(ABSENT), retention=TrackedValue(UNKNOWN),
    )


def stored_bytes(storage=None, **extra) -> bytes:
    return encode_manager_metadata(ManagerMetadata(storage, UnknownFields(extra)))


def store_error(failure, reason=None):
    return ManagerMetadataStoreError(failure, reason=reason)


class ScenarioCase(unittest.TestCase):
    def setUp(self):
        self.source = InMemoryStoragePlacementSource(placement())
        self.store = InMemoryManagerMetadataStore()
        self.handler = ImportStoragePlacementHandler(self.source, self.store, operation_ids=lambda: "test-operation")
        self.inspect = InspectManagerMetadataHandler(self.store, operation_ids=lambda: "test-operation")

    def run_import(self):
        return self.handler.execute(ImportStoragePlacement())

    def assert_failure(self, result, category, code, reason=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertEqual(
            (result.error.category, result.error.code, result.error.reason), (category, code, reason),
        )

    def assert_private(self, result):
        text = json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        if self.store.content is not None:
            self.assertNotIn(metadata_revision(self.store.content), text)
        self.assertFalse([type(item).__name__ for item in reachable(result) if isinstance(item, PRIVATE_TYPES)])


class ImportStoragePlacementTests(ScenarioCase):
    def test_first_import_stores_detected_placement_and_limits_as_is(self):
        cases = {
            "simple_one_partition": (placement(), 1),
            "extended_separate_partitions": (separate_partitions(), 3),
            "extended_one_partition": (placement(StorageVariant.EXTENDED), 1),
            "unknown_and_absent_values": (partial_placement(), 1),
            "technical_limit_bounds": (placement(size=known(MAX_LIMIT_VALUE), retention=known(1)), 1),
        }
        for name, (detected, distinct) in cases.items():
            with self.subTest(name):
                self.setUp()
                self.source.outcome = detected
                result = self.run_import()
                self.assertTrue(result.succeeded)
                self.assertIsInstance(result.data, StoragePlacementImportView)
                self.assertEqual(result.data.outcome, StoragePlacementImportOutcome.CREATED.value)
                expected = encode_manager_metadata(ManagerMetadata(detected))
                self.assertEqual(self.store.content, expected)
                self.assertEqual([call.expected_revision for call in self.store.write_calls], [None])
                self.assertEqual((self.source.calls, self.store.read_calls, self.store.publications), (1, 1, 1))
                self.assertEqual(result.data.metadata.to_dict(), ManagerMetadata(detected).to_diagnostic())
                self.assertEqual(result.data.metadata.storage.distinct_storage_count, distinct)
                self.assert_private(result)

    def test_view_keeps_unknown_absent_and_verification_distinct(self):
        self.source.outcome = partial_placement()
        storage = self.run_import().data.metadata.to_dict()["storage"]
        self.assertEqual((storage["variant_state"], storage["variant"]), ("unknown", None))
        self.assertEqual(storage["roles"], [
            {"role": "data", "state": "known", "storage_id_state": "unknown", "path_state": "known",
             "verified": False},
            {"role": "history", "state": "known", "storage_id_state": "known", "path_state": "absent",
             "verified": False},
            {"role": "backups", "state": "absent", "storage_id_state": None, "path_state": None, "verified": None},
        ])
        self.assertEqual(storage["history_limits"], {
            "size_state": "absent", "size_bytes": None, "retention_state": "unknown", "retention_seconds": None,
        })
        self.assertEqual(storage["distinct_storage_count"], 1)

    def test_repeated_import_without_changes_does_not_write(self):
        first = self.run_import()
        content, revision = self.store.content, metadata_revision(self.store.content)
        for _ in range(3):
            result = self.run_import()
            self.assertTrue(result.succeeded)
            self.assertEqual(result.data.outcome, StoragePlacementImportOutcome.UNCHANGED.value)
            self.assertEqual(result.data.metadata, first.data.metadata)
        self.assertIs(self.store.content, content)
        self.assertEqual(metadata_revision(self.store.content), revision)
        self.assertEqual((len(self.store.write_calls), self.store.publications, self.store.read_calls), (1, 1, 4))

    def test_non_canonical_file_with_same_placement_is_unchanged_without_rewrite(self):
        canonical = json.loads(stored_bytes(placement()))
        # Другой порядок ключей и компактная запись: те же данные, другие байты.
        reordered = {"storage": canonical["storage"], "schema_version": 1, "format": METADATA_FORMAT}
        content = json.dumps(reordered, separators=(",", ":")).encode("ascii")
        self.store.content = content
        result = self.run_import()
        self.assertEqual(result.data.outcome, "unchanged")
        self.assertIs(self.store.content, content)
        self.assertEqual(self.store.write_calls, ())

    def test_differing_stored_placement_is_refused_without_write(self):
        base = placement()
        roles = base.roles
        cases = {
            "variant": placement(StorageVariant.EXTENDED),
            "variant_unknown_vs_absent": placement(TrackedValue(UNKNOWN)),
            "storage_id": placement(roles=StorageRoles(role(HISTORY_ID), roles.history, roles.backups)),
            "path": placement(roles=StorageRoles(role(path=DATA_PATH + "-other"), roles.history, roles.backups)),
            "verified": placement(roles=StorageRoles(role(verified=False), roles.history, roles.backups)),
            "role_unknown": placement(roles=StorageRoles(roles.data, roles.history, RoleLocation(UNKNOWN))),
            "role_absent": placement(roles=StorageRoles(roles.data, roles.history, RoleLocation(ABSENT))),
            "size": placement(size=known(256 * 1024 * 1024 + 1)),
            "size_unknown": placement(size=TrackedValue(UNKNOWN)),
            "retention_absent": placement(retention=TrackedValue(ABSENT)),
            "storage_unknown_field": placement(extra=UnknownFields({"secret-extra": 1})),
            "role_unknown_field": placement(roles=StorageRoles(
                RoleLocation(KNOWN, known(DATA_ID), known(DATA_PATH), True, UnknownFields({"secret-extra": True})),
                roles.history, roles.backups,
            )),
        }
        for name, stored in cases.items():
            with self.subTest(name):
                self.setUp()
                content = stored_bytes(stored, note="private-note")
                self.store.content = content
                result = self.run_import()
                self.assert_failure(result, ErrorCategory.UNSUPPORTED, "storage_placement_mismatch")
                self.assertIs(self.store.content, content)
                self.assertEqual((self.store.write_calls, self.store.publications), ((), 0))
                self.assert_private(result)

    def test_unknown_value_is_not_matched_by_absent_value_in_either_direction(self):
        unknown_limits = placement(size=TrackedValue(UNKNOWN))
        absent_limits = placement(size=TrackedValue(ABSENT))
        for stored, detected in ((unknown_limits, absent_limits), (absent_limits, unknown_limits)):
            with self.subTest(stored=stored.history_limits.size_bytes.state.value):
                self.setUp()
                self.store.content = stored_bytes(stored)
                self.source.outcome = detected
                self.assertEqual(self.run_import().error.code, "storage_placement_mismatch")

    def test_storage_is_added_to_existing_file_keeping_unknown_fields(self):
        extra = {
            "future-section": {"rules": [{"id": 1, "flag": True}], "nested": {"value": 1.5}},
            "": "пустое имя", "Storage": {"state": "known"}, "STORAGE": None, "flag": True, "count": 1,
            "big": 10 ** 3999,
        }
        content = stored_bytes(None, **extra)
        self.store.content = content
        result = self.run_import()
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.outcome, "created")
        self.assertEqual([call.expected_revision for call in self.store.write_calls], [metadata_revision(content)])
        written = decode_manager_metadata(self.store.content).metadata
        self.assertEqual(written.extra.export(), extra)
        self.assertEqual(written.extra.names, tuple(extra))
        self.assertEqual(encode_manager_metadata(ManagerMetadata(written.storage)), stored_bytes(placement()))
        self.assertIs(type(written.extra.export()["flag"]), bool)
        self.assertEqual(result.data.metadata.unknown_field_count, len(extra))
        self.assert_private(result)
        repeated = self.run_import()
        self.assertEqual(repeated.data.outcome, "unchanged")
        self.assertEqual(len(self.store.write_calls), 1)

    def test_rules_section_survives_adding_storage_to_existing_file(self):
        # Регрессия: кандидат собирался только из storage и неизвестных полей, известный раздел rules терялся.
        record = RuleRecord(
            RULE_ID, "private-rule-name", RuleKey("domain", "subdomains:private.example.test", RoutingAction.VPN),
            UnknownFields({"future": 1}),
        )
        original = encode_manager_metadata(ManagerMetadata(None, UnknownFields({"future-section": {"a": 1}}), rules=(record,)))
        self.store.content = original
        result = self.run_import()
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.outcome, StoragePlacementImportOutcome.CREATED.value)
        stored = decode_manager_metadata(self.store.content).metadata
        self.assertEqual(stored.rules, (record,))
        self.assertEqual(stored.storage, placement())
        self.assertEqual(stored.extra.names, ("future-section",))
        self.assertEqual(json.loads(self.store.content)["rules"], json.loads(original)["rules"])
        self.assertEqual(result.data.metadata.to_dict()["rules"], {"record_count": 1, "named_record_count": 1})
        self.assertEqual(result.data.metadata.unknown_field_count, 2)
        self.assert_private(result)
        # Повтор: раздел storage совпадает, записи нет, rules нетронуты.
        again = self.run_import()
        self.assertEqual(again.data.outcome, StoragePlacementImportOutcome.UNCHANGED.value)
        self.assertEqual(self.store.publications, 1)
        self.assertEqual(decode_manager_metadata(self.store.content).metadata.rules, (record,))

    def test_corrupted_file_or_other_schema_version_is_not_overwritten(self):
        cases = {
            ManagerMetadataErrorCode.JSON: b'{"format": "keenvpn-manager-metadata",',
            ManagerMetadataErrorCode.SCHEMA_VERSION: json.dumps({"format": METADATA_FORMAT, "schema_version": 2})
            .encode("ascii"),
            ManagerMetadataErrorCode.FORMAT: b'{"private-note": 1}',
            ManagerMetadataErrorCode.CONTENT: b"\xff\xfe",
        }
        for code, content in cases.items():
            with self.subTest(code.value):
                self.setUp()
                self.store.content = content
                result = self.run_import()
                self.assert_failure(result, ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_metadata", code.value)
                self.assertIs(self.store.content, content)
                self.assertEqual(self.store.write_calls, ())
                self.assertEqual(self.source.calls, 1)

    def test_each_store_read_failure_is_reported_separately_without_write(self):
        codes = set()
        for failure in Failure:
            with self.subTest(failure.value):
                self.setUp()
                self.store.read_failure = store_error(failure, REASONS[failure])
                result = self.run_import()
                self.assert_failure(result, CATEGORIES[failure], failure.value, REASONS[failure])
                self.assertEqual((self.store.write_calls, self.store.content), ((), None))
                codes.add(result.error.code)
        self.assertEqual(len(codes), len(Failure))

    def test_each_store_write_failure_is_reported_separately_and_never_succeeds(self):
        for stored in (None, stored_bytes(None, note="private-note")):
            for failure in Failure:
                with self.subTest(stored=stored is not None, failure=failure.value):
                    self.setUp()
                    self.store.content = stored
                    self.store.write_failure = store_error(failure, REASONS[failure])
                    result = self.run_import()
                    self.assert_failure(result, CATEGORIES[failure], failure.value, REASONS[failure])
                    self.assertIs(self.store.content, stored)
                    self.assertEqual((len(self.store.write_calls), self.store.publications), (1, 0))
                    self.assert_private(result)

    def test_unconfirmed_write_is_failure_and_repeat_reports_unchanged_without_write(self):
        self.store.write_failure = store_error(Failure.WRITE_UNCONFIRMED, Reason.IO_ERROR.value)
        self.store.publish_before_failure = True
        result = self.run_import()
        self.assert_failure(result, ErrorCategory.SOURCE_FAILED, "metadata_write_unconfirmed", "io_error")
        self.assertNotEqual(result.error.code, "created")
        # Новый файл виден, но сохранность не подтверждена: результат не успех.
        self.assertEqual(self.store.content, stored_bytes(placement()))
        self.assertEqual(self.store.publications, 1)
        self.store.write_failure = None
        repeated = self.run_import()
        # Повтор видит опубликованный файл и ничего не пишет: unchanged не подтверждает сохранность.
        self.assertEqual(repeated.data.outcome, StoragePlacementImportOutcome.UNCHANGED.value)
        self.assertEqual((len(self.store.write_calls), self.store.publications), (1, 1))

    def test_external_change_just_before_revision_check_is_conflict_without_overwrite(self):
        external = stored_bytes(separate_partitions(), note="private-note")
        for stored in (None, stored_bytes(None, note="private-note")):
            with self.subTest(stored=stored is not None):
                self.setUp()
                self.store.content = stored
                self.store.before_revision_check = lambda: setattr(self.store, "content", external)
                result = self.run_import()
                self.assert_failure(result, ErrorCategory.SOURCE_FAILED, "metadata_revision_conflict")
                self.assertIs(self.store.content, external)
                self.assertEqual(self.store.publications, 0)

    def test_unexpected_store_exceptions_are_not_conflict_or_tampering(self):
        class ConflictSubclass(ManagerMetadataStoreError):
            def __str__(self):
                raise AssertionError("Сценарий вызвал __str__ чужого исключения.")

        substituted = store_error(Failure.UNSAFE, Reason.REPLACED.value)
        object.__setattr__(substituted, "failure", "metadata_revision_conflict")
        missing = ManagerMetadataStoreError.__new__(ManagerMetadataStoreError)
        failures = (
            OSError(errno.EIO, "Искусственный отказ", DATA_PATH), RuntimeError("Искусственный отказ " + DATA_PATH),
            ValueError(DATA_ID), ConflictSubclass(Failure.CONFLICT), substituted, missing,
        )
        for phase in ("read", "write"):
            for error in failures:
                with self.subTest(phase=phase, error=type(error).__name__):
                    self.setUp()
                    setattr(self.store, f"{phase}_failure", error)
                    result = self.run_import()
                    self.assert_failure(result, ErrorCategory.SOURCE_FAILED, "metadata_store_failed")
                    self.assertIsNone(self.store.content)
                    self.assert_private(result)

    def test_store_reasons_are_output_only_from_known_sets(self):
        cases = (
            (Failure.UNAVAILABLE, Reason.PERMISSION_DENIED, "permission_denied"),
            (Failure.UNAVAILABLE, "io_error", "io_error"),
            (Failure.UNAVAILABLE, DATA_PATH, None),
            (Failure.UNAVAILABLE, "invalid_metadata_json", None),
            (Failure.UNSAFE, 123, None),
            (Failure.UNSAFE, b"symlink", None),
            (Failure.INVALID, ManagerMetadataErrorCode.SCHEMA_VERSION, "unsupported_metadata_schema_version"),
            (Failure.INVALID, "io_error", None),
            (Failure.INVALID, "", None),
        )
        for failure, reason, expected in cases:
            with self.subTest(failure=failure.value, reason=repr(reason)[:20]):
                self.setUp()
                self.store.read_failure = store_error(failure, reason)
                self.assert_failure(self.run_import(), CATEGORIES[failure], failure.value, expected)

    def test_invalid_store_answers_are_rejected(self):
        valid = decode_manager_metadata(stored_bytes(placement()))
        broken_metadata = decode_manager_metadata(stored_bytes(placement()))
        object.__setattr__(broken_metadata.metadata.storage.variant, "state", "known")
        broken_revision = decode_manager_metadata(stored_bytes(placement()))
        object.__setattr__(broken_revision, "revision", valid.revision.upper())

        class StoredSubclass(StoredManagerMetadata):
            __slots__ = ()

        for answer in (
            {"storage": None}, "manager-metadata", valid.metadata, broken_metadata, broken_revision,
            StoredSubclass(valid.metadata, valid.revision),
        ):
            with self.subTest(answer=type(answer).__name__):
                self.setUp()
                with patch.object(self.store, "read_metadata", return_value=answer):
                    result = self.run_import()
                self.assert_failure(result, ErrorCategory.INVALID_SOURCE_DATA, "invalid_metadata_store_result")
                self.assertEqual(self.store.write_calls, ())

        expected = metadata_revision(stored_bytes(placement()))

        class RevisionText(str):
            pass

        for answer in (None, expected.encode("ascii"), "0" * 64, expected.upper(), RevisionText(expected)):
            with self.subTest(write_answer=repr(answer)[:16]):
                self.setUp()
                with patch.object(self.store, "write_metadata", return_value=answer):
                    result = self.run_import()
                self.assert_failure(result, ErrorCategory.INVALID_SOURCE_DATA, "invalid_metadata_store_result")

    def test_source_failures_stop_before_store(self):
        class PlacementSubclass(StoragePlacement):
            __slots__ = ()

        corrupted_state = placement()
        object.__setattr__(corrupted_state.variant, "state", "known")
        corrupted_limit = placement()
        object.__setattr__(corrupted_limit.history_limits.size_bytes, "value", True)
        corrupted_path = placement()
        object.__setattr__(corrupted_path.roles.data.path, "value", "relative/path")
        corrupted_type = placement()
        object.__setattr__(corrupted_type, "roles", {"data": None})
        with_role_field = placement(roles=StorageRoles(
            RoleLocation(KNOWN, known(DATA_ID), known(DATA_PATH), True, UnknownFields({"secret-extra": 1})),
            RoleLocation(UNKNOWN), RoleLocation(ABSENT),
        ))
        cases = (
            (OSError("Искусственный отказ " + DATA_PATH), ErrorCategory.SOURCE_FAILED,
             "storage_placement_unavailable", None),
            (None, ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement", None),
            ({"variant": "simple"}, ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement", None),
            (ManagerMetadata(placement()), ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement", None),
            (PlacementSubclass(*(getattr(placement(), name) for name in ("variant", "roles", "history_limits"))),
             ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement", None),
            (corrupted_state, ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement", "invalid_value_state"),
            (corrupted_limit, ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement",
             "invalid_history_limit"),
            (corrupted_path, ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement", "invalid_storage_path"),
            (corrupted_type, ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement",
             "invalid_metadata_format"),
            (placement(extra=UnknownFields({"secret-extra": 1})), ErrorCategory.INVALID_SOURCE_DATA,
             "invalid_storage_placement", "invalid_unknown_fields"),
            (with_role_field, ErrorCategory.INVALID_SOURCE_DATA, "invalid_storage_placement",
             "invalid_unknown_fields"),
        )
        for answer, category, code, reason in cases:
            with self.subTest(answer=type(answer).__name__, reason=reason):
                self.setUp()
                self.source.outcome = answer
                result = self.run_import()
                self.assert_failure(result, category, code, reason)
                self.assertEqual((self.store.read_calls, self.store.write_calls), (0, ()))
                self.assert_private(result)

    def test_merged_metadata_over_size_limit_is_refused_without_write(self):
        padding = "x" * (MAX_METADATA_SIZE - 200)
        content = stored_bytes(None, pad=padding)
        self.assertLessEqual(len(content), MAX_METADATA_SIZE)
        self.store.content = content
        result = self.run_import()
        self.assert_failure(
            result, ErrorCategory.INVALID_SOURCE_DATA, "manager_metadata_inconsistent",
            ManagerMetadataErrorCode.CONTENT.value,
        )
        self.assertIs(self.store.content, content)
        self.assertEqual(self.store.write_calls, ())

    def test_stored_placement_without_canonical_form_is_a_mismatch(self):
        # Компактный файл в пределах размера, канонический с отступами превысил бы его.
        document = json.loads(stored_bytes(placement()))
        document["storage"]["roles"]["data"]["secret-extra"] = [0] * 200_000
        content = json.dumps(document, separators=(",", ":")).encode("ascii")
        self.assertLessEqual(len(content), MAX_METADATA_SIZE)
        self.store.content = content
        self.assert_failure(self.run_import(), ErrorCategory.UNSUPPORTED, "storage_placement_mismatch")
        self.assertIs(self.store.content, content)
        self.assertEqual(self.store.write_calls, ())

    def test_large_unknown_top_level_section_does_not_affect_placement_comparison(self):
        # Компактный файл в пределах размера; с отступами посторонний раздел превысил бы его.
        def compact(storage):
            document = json.loads(stored_bytes(storage))
            document["future-section"] = [0] * 200_000
            return json.dumps(document, separators=(",", ":")).encode("ascii")

        content = compact(placement())
        self.assertLessEqual(len(content), MAX_METADATA_SIZE)
        self.store.content = content
        result = self.run_import()
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.outcome, "unchanged")
        self.assertEqual(result.data.metadata.unknown_field_count, 1)
        self.assertIs(self.store.content, content)
        self.assertEqual(self.store.write_calls, ())

        self.source.outcome = separate_partitions()
        self.assert_failure(self.run_import(), ErrorCategory.UNSUPPORTED, "storage_placement_mismatch")
        self.assertIs(self.store.content, content)

        # Без записанного размещения нужна запись: файл вместе с разделом превысил бы предел.
        self.setUp()
        content = compact(None)
        self.store.content = content
        self.assert_failure(
            self.run_import(), ErrorCategory.INVALID_SOURCE_DATA, "manager_metadata_inconsistent",
            ManagerMetadataErrorCode.CONTENT.value,
        )
        self.assertIs(self.store.content, content)
        self.assertEqual(self.store.write_calls, ())

    def test_invalid_command_or_contract_version_does_not_call_ports(self):
        for command in (None, InspectManagerMetadata(), "import_storage_placement"):
            with self.subTest(command=repr(command)):
                self.assert_failure(self.handler.execute(command), ErrorCategory.INVALID_REQUEST, "invalid_command")
        for version in (CONTRACT_VERSION + 1, 0, True, "1", 1.0):
            with self.subTest(version=repr(version)):
                result = self.handler.execute(ImportStoragePlacement(contract_version=version))
                self.assert_failure(result, ErrorCategory.INVALID_REQUEST, "unsupported_contract_version")
        self.assertEqual((self.source.calls, self.store.read_calls, self.store.write_calls), (0, 0, ()))

    def test_interrupts_and_setup_errors_propagate(self):
        for target, interrupt in (("source", KeyboardInterrupt()), ("read", SystemExit(3)), ("write", KeyboardInterrupt())):
            with self.subTest(target=target):
                self.setUp()
                if target == "source":
                    self.source.outcome = interrupt
                else:
                    setattr(self.store, f"{target}_failure", interrupt)
                with self.assertRaises(type(interrupt)):
                    self.run_import()
                self.assertIsNone(self.store.content)
        self.setUp()
        self.source.outcome = in_memory._UNSET
        with self.assertRaises(UnconfiguredResponseError):
            self.run_import()
        with self.assertRaises(AdapterSetupError):
            self.store.write_failure = OSError
        with self.assertRaises(AdapterSetupError):
            self.store.content = "not bytes"

    def test_results_are_immutable_and_rendered_without_new_calls(self):
        result = self.run_import()
        with self.assertRaises(FrozenInstanceError):
            result.data.outcome = "unchanged"
        with self.assertRaises(FrozenInstanceError):
            result.data.metadata.storage.roles[0].verified = False
        calls = (self.source.calls, self.store.read_calls, len(self.store.write_calls))
        first = json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True)
        self.assertEqual(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True), first)
        self.assertEqual((self.source.calls, self.store.read_calls, len(self.store.write_calls)), calls)
        self.assertEqual(result.to_dict()["command"], "import_storage_placement")

    def test_no_terminal_file_network_or_process_effects(self):
        failing = InMemoryManagerMetadataStore(stored_bytes(None, note="private-note"))
        failing.write_failure = store_error(Failure.WRITE_FAILED, Reason.NO_SPACE.value)
        with forbid_external_effects():
            self.assertEqual(self.run_import().data.outcome, "created")
            self.assertEqual(self.run_import().data.outcome, "unchanged")
            self.assertTrue(self.inspect.execute(InspectManagerMetadata()).data.present)
            result = ImportStoragePlacementHandler(self.source, failing).execute(ImportStoragePlacement())
            self.assertEqual(result.error.code, "metadata_write_failed")
            self.source.outcome = separate_partitions()
            self.assertEqual(self.run_import().error.code, "storage_placement_mismatch")

    def test_import_cost_is_linear_in_stored_unknown_fields(self):
        # Детерминированно: число выполненных строк сценария, домена и адаптера в памяти.
        modules = {scenarios.__file__, domain.__file__, in_memory.__file__}

        def executed_lines(count, *, with_storage, detected):
            extra = {f"future-section-{index}": {"nested": [index, True]} for index in range(count)}
            store = InMemoryManagerMetadataStore(stored_bytes(placement() if with_storage else None, **extra))
            handler = ImportStoragePlacementHandler(InMemoryStoragePlacementSource(detected), store)
            lines = 0

            def tracer(frame, event, _arg):
                nonlocal lines
                if frame.f_code.co_filename not in modules:
                    return None
                if event == "line":
                    lines += 1
                return tracer

            sys.settrace(tracer)
            try:
                result = handler.execute(ImportStoragePlacement())
            finally:
                sys.settrace(None)
            return result, lines

        for name, with_storage, detected, outcome in (
            ("created", False, placement(), "created"),
            ("unchanged", True, placement(), "unchanged"),
            ("mismatch", True, separate_partitions(), None),
        ):
            with self.subTest(name):
                small_result, small = executed_lines(200, with_storage=with_storage, detected=detected)
                large_result, large = executed_lines(800, with_storage=with_storage, detected=detected)
                for result in (small_result, large_result):
                    if outcome is None:
                        self.assertEqual(result.error.code, "storage_placement_mismatch")
                    else:
                        self.assertEqual(result.data.outcome, outcome)
                # Линейная стоимость даёт отношение около 4, квадратичная — около 16.
                self.assertLess(large, small * 5)


class InspectManagerMetadataTests(ScenarioCase):
    def run_inspect(self):
        return self.inspect.execute(InspectManagerMetadata())

    def test_missing_metadata_is_a_state_not_a_failure(self):
        result = self.run_inspect()
        self.assertTrue(result.succeeded)
        self.assertIsInstance(result.data, ManagerMetadataStatusView)
        self.assertEqual(result.to_dict()["data"], {"present": False, "metadata": None})
        self.assertEqual((self.store.read_calls, self.store.write_calls, self.store.content), (1, (), None))
        self.assertEqual(result.to_dict()["command"], "inspect_manager_metadata")

    def test_present_metadata_is_shown_without_paths_ids_or_revision(self):
        self.store.content = stored_bytes(separate_partitions(), note="private-note")
        result = self.run_inspect()
        self.assertEqual(result.data.present, True)
        self.assertEqual(result.to_dict()["data"]["metadata"], {
            "schema_version": 1,
            "storage": {
                "variant_state": "known", "variant": "extended",
                "roles": [
                    {"role": "data", "state": "known", "storage_id_state": "known", "path_state": "known",
                     "verified": True},
                    {"role": "history", "state": "known", "storage_id_state": "known", "path_state": "known",
                     "verified": True},
                    {"role": "backups", "state": "known", "storage_id_state": "known", "path_state": "known",
                     "verified": False},
                ],
                "distinct_storage_count": 3,
                "history_limits": {
                    "size_state": "known", "size_bytes": 256 * 1024 * 1024,
                    "retention_state": "known", "retention_seconds": 30 * 24 * 3600,
                },
            },
            "rules": None,
            "unknown_field_count": 1,
        })
        self.assertEqual(self.store.write_calls, ())
        self.assert_private(result)

    def test_file_without_storage_section_shows_only_unknown_field_count(self):
        self.store.content = stored_bytes(None, **{"future-section": {"a": 1}, "": 2, "private-note": "x"})
        result = self.run_inspect()
        self.assertEqual(result.to_dict()["data"]["metadata"], {
            "schema_version": 1, "storage": None, "rules": None, "unknown_field_count": 3,
        })
        self.assert_private(result)

    def test_store_failures_and_invalid_answers_are_reported_without_partial_result(self):
        for failure in Failure:
            with self.subTest(failure.value):
                self.setUp()
                self.store.read_failure = store_error(failure, REASONS[failure])
                self.assert_failure(self.run_inspect(), CATEGORIES[failure], failure.value, REASONS[failure])
        self.setUp()
        self.store.content = b"[]"
        self.assert_failure(
            self.run_inspect(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_metadata",
            ManagerMetadataErrorCode.JSON.value,
        )
        self.setUp()
        self.store.read_failure = OSError(errno.EIO, "Искусственный отказ", DATA_PATH)
        self.assert_failure(self.run_inspect(), ErrorCategory.SOURCE_FAILED, "metadata_store_failed")
        for answer in ({}, "x", ManagerMetadata()):
            with self.subTest(answer=type(answer).__name__):
                with patch.object(self.store, "read_metadata", return_value=answer):
                    self.assert_failure(
                        self.run_inspect(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_metadata_store_result",
                    )
        self.assertEqual(self.store.write_calls, ())

    def test_invalid_command_and_interrupts(self):
        for command in (None, ImportStoragePlacement()):
            self.assert_failure(self.inspect.execute(command), ErrorCategory.INVALID_REQUEST, "invalid_command")
        result = self.inspect.execute(InspectManagerMetadata(contract_version=CONTRACT_VERSION + 1))
        self.assert_failure(result, ErrorCategory.INVALID_REQUEST, "unsupported_contract_version")
        self.assertEqual(self.store.read_calls, 0)
        self.store.read_failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_inspect()

    def test_no_terminal_file_network_or_process_effects(self):
        self.store.content = stored_bytes(placement())
        with forbid_external_effects():
            self.assertTrue(self.run_inspect().succeeded)
            self.store.content = None
            self.assertFalse(self.run_inspect().data.present)


class CountingStore:
    """Настоящее хранилище с подсчётом записей: проверяет, что повтор не вызывает write_metadata."""

    def __init__(self, store):
        self.store = store
        self.writes = 0

    def read_metadata(self):
        return self.store.read_metadata()

    def write_metadata(self, metadata, expected_revision):
        self.writes += 1
        return self.store.write_metadata(metadata, expected_revision)


class FileStoreIntegrationTests(unittest.TestCase):
    """Сценарий с настоящим `ManagerMetadataFiles` во временном каталоге."""

    def setUp(self):
        # Реальный путь: на macOS временный каталог находится за ссылкой /var.
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-placement-")))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "state").mkdir()
        self.directory = self.root / "state" / "keenvpn"
        self.file = self.directory / METADATA_FILE_NAME
        self.store = CountingStore(ManagerMetadataFiles(str(self.directory)))
        self.source = InMemoryStoragePlacementSource(placement())
        self.handler = ImportStoragePlacementHandler(self.source, self.store)
        # Искусственный каталог active configs рядом: сценарий не должен его трогать.
        self.configs = self.root / "xray-configs"
        self.configs.mkdir()
        self.config = self.configs / "05_routing.json"
        self.config.write_bytes(b'{"routing": {"rules": []}}\n')
        self.config_state = self._state(self.config)

    @staticmethod
    def _state(path):
        info = path.stat()
        return path.read_bytes(), info.st_ino, info.st_mtime_ns, info.st_mode

    def tearDown(self):
        self.assertEqual(self._state(self.config), self.config_state)
        self.assertEqual(sorted(path.name for path in self.configs.iterdir()), ["05_routing.json"])

    def run_import(self):
        return self.handler.execute(ImportStoragePlacement())

    def test_first_import_repeat_without_write_and_mismatch_without_overwrite(self):
        first = self.run_import()
        self.assertEqual(first.data.outcome, "created")
        self.assertEqual(self.file.read_bytes(), stored_bytes(placement()))
        self.assertEqual(self.store.writes, 1)
        state = self._state(self.file)
        revision = metadata_revision(self.file.read_bytes())

        repeated = self.run_import()
        self.assertEqual(repeated.data.outcome, "unchanged")
        self.assertEqual(self.store.writes, 1)
        self.assertEqual(self._state(self.file), state)

        self.source.outcome = separate_partitions()
        mismatch = self.run_import()
        self.assertEqual(mismatch.error.code, "storage_placement_mismatch")
        self.assertEqual(self.store.writes, 1)
        self.assertEqual(self._state(self.file), state)
        self.assertEqual(self.store.read_metadata().revision, revision)

        inspected = InspectManagerMetadataHandler(self.store.store).execute(InspectManagerMetadata())
        self.assertEqual(inspected.data.metadata, first.data.metadata)
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), [METADATA_FILE_NAME])

    def test_storage_is_added_to_file_without_it_keeping_unknown_fields(self):
        extra = {"future-section": {"rules": [1, 2]}, "": None, "Storage": True}
        self.store.store.write_metadata(ManagerMetadata(None, UnknownFields(extra)), None)
        result = self.run_import()
        self.assertEqual(result.data.outcome, "created")
        written = json.loads(self.file.read_bytes())
        self.assertEqual(list(written), ["format", "schema_version", "storage", *extra])
        self.assertEqual({key: written[key] for key in extra}, extra)
        self.assertEqual(self.run_import().data.outcome, "unchanged")
        # Предварительная запись шла напрямую в хранилище, мимо счётчика.
        self.assertEqual(self.store.writes, 1)

    def test_corrupted_file_is_not_overwritten(self):
        self.store.store.write_metadata(ManagerMetadata(), None)
        descriptor = os.open(self.file, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        try:
            os.write(descriptor, b'{"format": ')
        finally:
            os.close(descriptor)
        result = self.run_import()
        self.assertEqual(
            (result.error.code, result.error.reason), ("invalid_stored_metadata", ManagerMetadataErrorCode.JSON.value),
        )
        self.assertEqual(self.file.read_bytes(), b'{"format": ')
        self.assertEqual(self.store.writes, 0)

    def test_unconfirmed_write_then_repeat_without_write(self):
        published = []
        original_replace, original_fsync = os.replace, os.fsync

        def replace(*args, **kwargs):
            original_replace(*args, **kwargs)
            published.append(True)

        def fsync(descriptor):
            if published:
                raise OSError(errno.EIO, "Искусственный отказ fsync")
            return original_fsync(descriptor)

        with patch.object(manager_metadata_files.os, "replace", replace), \
                patch.object(manager_metadata_files.os, "fsync", fsync):
            result = self.run_import()
        self.assertEqual((result.error.code, result.error.reason), ("metadata_write_unconfirmed", "io_error"))
        self.assertEqual(self.file.read_bytes(), stored_bytes(placement()))
        repeated = self.run_import()
        self.assertEqual(repeated.data.outcome, "unchanged")
        self.assertEqual(self.store.writes, 1)


if __name__ == "__main__":
    unittest.main()
