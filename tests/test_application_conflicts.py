"""Записи конфликта в контракте ошибок: модель, сериализация, подписи и совместимость версии 1."""

from dataclasses import FrozenInstanceError
from enum import StrEnum
import json
from pathlib import Path
import sys
from types import MappingProxyType
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import (
    CONFLICT_STATE_LABELS, CONFLICT_SUBJECT_LABELS, CONTRACT_VERSION, UNKNOWN_SOURCE_LABEL, Conflict, ConflictState,
    ConflictSubject, ErrorCategory, ErrorDetail, NextStepCode, failed, revision_conflict,
)
from keenvpn.application.keenetic_policies import POLICIES_UNAVAILABLE
from keenvpn.domain.source_baseline import BaselineSource, FingerprintState


PRESENT, ABSENT, CHANGED, UNKNOWN = ConflictState
DRAFT, METADATA, SOURCE = ConflictSubject


class OtherState(StrEnum):
    """Перечисление с теми же значениями: точный тип нельзя подменить совпадающей строкой."""

    PRESENT = "present"
    ABSENT = "absent"


def error_with(*conflicts: Conflict) -> ErrorDetail:
    return ErrorDetail(ErrorCategory.SOURCE_FAILED, "draft_revision_conflict", "Изменился.", conflicts=conflicts)


class ConflictModelTests(unittest.TestCase):
    def test_allowed_combinations_serialize_to_codes_only(self):
        cases = (
            (Conflict(DRAFT, PRESENT, CHANGED), {"subject": "draft", "source": None, "expected": "present",
                                                 "found": "changed"}),
            (Conflict(DRAFT, ABSENT, PRESENT), {"subject": "draft", "source": None, "expected": "absent",
                                                "found": "present"}),
            (Conflict(METADATA, PRESENT, UNKNOWN), {"subject": "metadata", "source": None, "expected": "present",
                                                    "found": "unknown"}),
            (Conflict(SOURCE, PRESENT, ABSENT, BaselineSource.XKEEN_INIT), {
                "subject": "source", "source": "xkeen_init", "expected": "present", "found": "absent",
            }),
            (Conflict(SOURCE, UNKNOWN, PRESENT, BaselineSource.KEENETIC_POLICIES), {
                "subject": "source", "source": "keenetic_policies", "expected": "unknown", "found": "present",
            }),
            (Conflict(SOURCE, UNKNOWN, UNKNOWN), {"subject": "source", "source": None, "expected": "unknown",
                                                  "found": "unknown"}),
        )
        for conflict, expected in cases:
            with self.subTest(conflict=expected):
                self.assertEqual(conflict.to_dict(), expected)
                self.assertEqual(json.loads(json.dumps(conflict.to_dict())), expected)
        with self.assertRaises(FrozenInstanceError):
            cases[0][0].found = ABSENT

    def test_every_source_state_change_is_expressible(self):
        # Изменился, исчез, появился, не прочитан, не зафиксирован в черновике, неизвестная запись.
        for expected, found in (
            (PRESENT, CHANGED), (PRESENT, ABSENT), (ABSENT, PRESENT), (PRESENT, UNKNOWN), (ABSENT, UNKNOWN),
            (UNKNOWN, PRESENT), (UNKNOWN, ABSENT), (UNKNOWN, UNKNOWN),
        ):
            for source in (*BaselineSource, None):
                with self.subTest(expected=expected.value, found=found.value, source=source):
                    self.assertIs(Conflict(SOURCE, expected, found, source).source, source)

    def test_matches_and_impossible_states_are_rejected(self):
        for subject, expected, found, source in (
            (DRAFT, PRESENT, PRESENT, None), (DRAFT, ABSENT, ABSENT, None),
            (SOURCE, PRESENT, PRESENT, BaselineSource.XRAY_CONFIGS),
            # Ожидаемое не бывает «другой ревизией»; найденная «другая ревизия» — только при ожидаемом объекте.
            (DRAFT, CHANGED, PRESENT, None), (DRAFT, ABSENT, CHANGED, None), (SOURCE, UNKNOWN, CHANGED, None),
            # Источник задаётся только записи источника.
            (DRAFT, PRESENT, CHANGED, BaselineSource.XKEEN_INIT),
            (METADATA, PRESENT, UNKNOWN, BaselineSource.XKEEN_INIT),
        ):
            with self.subTest(subject=subject.value, expected=expected.value, found=found.value, source=source):
                with self.assertRaises(TypeError):
                    Conflict(subject, expected, found, source)

    def test_exact_types_are_required_not_equal_strings(self):
        for arguments in (
            ("draft", PRESENT, CHANGED, None),
            (DRAFT, "present", CHANGED, None),
            (DRAFT, PRESENT, "changed", None),
            (DRAFT, OtherState.PRESENT, CHANGED, None),
            (DRAFT, OtherState.ABSENT, PRESENT, None),
            (DRAFT, FingerprintState.ABSENT, PRESENT, None),
            (SOURCE, PRESENT, ABSENT, "xkeen_init"),
            (SOURCE, PRESENT, ABSENT, FingerprintState.ABSENT),
            (None, PRESENT, CHANGED, None),
        ):
            with self.subTest(arguments=repr(arguments)):
                with self.assertRaises(TypeError):
                    Conflict(*arguments)

    def test_revision_conflict_of_store_reports_only_what_store_knows(self):
        self.assertEqual(revision_conflict(DRAFT, ABSENT), Conflict(DRAFT, ABSENT, PRESENT))
        self.assertEqual(revision_conflict(METADATA, PRESENT), Conflict(METADATA, PRESENT, UNKNOWN))
        for expected in (CHANGED, UNKNOWN, "present", OtherState.PRESENT, None):
            with self.subTest(expected=repr(expected)):
                with self.assertRaises(TypeError):
                    revision_conflict(DRAFT, expected)


class ErrorDetailConflictsTests(unittest.TestCase):
    def test_conflicts_are_optional_and_keep_equality_of_existing_errors(self):
        plain = ErrorDetail(
            ErrorCategory.SOURCE_FAILED, "keenetic_policies_unavailable", "Не удалось прочитать политики Keenetic.",
        )
        self.assertEqual(plain.conflicts, ())
        self.assertEqual(plain, POLICIES_UNAVAILABLE)
        self.assertEqual(plain.to_dict()["conflicts"], [])
        self.assertNotEqual(plain, ErrorDetail(
            plain.category, plain.code, plain.message, conflicts=(Conflict(DRAFT, PRESENT, CHANGED),),
        ))

    def test_conflicts_keep_order_and_serialize_after_next_step(self):
        error = error_with(
            Conflict(SOURCE, PRESENT, CHANGED, BaselineSource.XKEEN_INIT),
            Conflict(SOURCE, ABSENT, PRESENT, BaselineSource.XRAY_CONFIGS),
            Conflict(SOURCE, UNKNOWN, UNKNOWN),
        )
        payload = failed("op", "cmd", error).to_dict()
        self.assertEqual(payload["contract_version"], CONTRACT_VERSION)
        self.assertEqual(list(payload["error"]), ["category", "code", "reason", "message", "next_step", "conflicts"])
        sources = [item["source"] for item in payload["error"]["conflicts"]]
        self.assertEqual(sources, ["xkeen_init", "xray_configs", None])
        self.assertEqual(payload["error"]["next_step"]["code"], NextStepCode.OPEN_VIEW.value)
        self.assertEqual(json.loads(json.dumps(payload, ensure_ascii=False)), payload)

    def test_malformed_conflicts_are_rejected(self):
        conflict = Conflict(DRAFT, PRESENT, CHANGED)
        for conflicts in (
            [conflict], (conflict.to_dict(),), (conflict, conflict),
            (Conflict(SOURCE, PRESENT, ABSENT), Conflict(SOURCE, ABSENT, PRESENT)),
            (Conflict(SOURCE, PRESENT, ABSENT, BaselineSource.XKEEN_INIT),
             Conflict(SOURCE, ABSENT, PRESENT, BaselineSource.XKEEN_INIT)),
            None, "draft",
        ):
            with self.subTest(conflicts=repr(conflicts)):
                with self.assertRaises(TypeError):
                    ErrorDetail(ErrorCategory.SOURCE_FAILED, "draft_revision_conflict", "Текст.", conflicts=conflicts)

    def test_every_object_appears_at_most_once(self):
        # Черновик, метаданные, каждый известный источник и одна запись неизвестных источников.
        conflicts = (
            Conflict(DRAFT, PRESENT, CHANGED), Conflict(METADATA, PRESENT, UNKNOWN),
            *(Conflict(SOURCE, PRESENT, CHANGED, source) for source in BaselineSource),
            Conflict(SOURCE, UNKNOWN, UNKNOWN),
        )
        self.assertEqual(len(error_with(*conflicts).to_dict()["conflicts"]), len(BaselineSource) + 3)

    def test_conflict_carries_no_values_revisions_or_paths(self):
        error = error_with(Conflict(SOURCE, PRESENT, CHANGED, BaselineSource.XKEEN_SETTINGS))
        text = json.dumps(error.to_dict()["conflicts"], ensure_ascii=False) + repr(error.conflicts)
        for fragment in ("sha256", "revision", "/opt", "/tmp", "TEST_"):
            self.assertNotIn(fragment, text)
        self.assertEqual(set(error.to_dict()["conflicts"][0]), {"subject", "source", "expected", "found"})


class ConflictLabelsTests(unittest.TestCase):
    def test_every_subject_and_state_has_one_fixed_printable_label(self):
        self.assertEqual(set(CONFLICT_SUBJECT_LABELS), set(ConflictSubject))
        self.assertEqual(set(CONFLICT_STATE_LABELS), set(ConflictState))
        for label in (*CONFLICT_SUBJECT_LABELS.values(), *CONFLICT_STATE_LABELS.values(), UNKNOWN_SOURCE_LABEL):
            with self.subTest(label=label):
                self.assertTrue(label and label.isprintable())
        self.assertEqual(len(set(CONFLICT_STATE_LABELS.values())), len(ConflictState))

    def test_label_tables_are_read_only(self):
        for table in (CONFLICT_SUBJECT_LABELS, CONFLICT_STATE_LABELS):
            self.assertIs(type(table), MappingProxyType)
            with self.assertRaises(TypeError):
                table[DRAFT] = "другое"


if __name__ == "__main__":
    unittest.main()
