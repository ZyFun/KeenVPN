"""Блокировка устаревшего черновика: повторное чтение источников и сравнение с исходными отпечатками.

Сравнение, общий помощник `check_draft_current` и сценарий проверки
актуальности проверяются на управляемом хранилище черновика и управляемом
источнике отпечатков в памяти. Записи нет ни в одном исходе: применения
в этой версии нет, а помощник, который его будет охранять, ничего
не меняет. Роутер, файлы, сеть и процессы не используются.
"""

from collections.abc import Callable
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import (
    CONTRACT_VERSION, NEXT_STEP_MESSAGES, Conflict, ConflictState as State, ConflictSubject, ErrorCategory, ErrorDetail,
    NextStepCode,
)
from keenvpn.application.draft_session import (
    DRAFT_CHANGED, DRAFT_GONE, CheckDraftBaseline, CheckDraftBaselineHandler, DiscardDraft, DraftBaselineCheckView,
    DraftBaselineOutcome, check_draft_current, draft_revision_token,
)
from keenvpn.application.ports import (
    DraftSessionStoreError, DraftStoreFailure, RouterReadError, RouterReadFailure, SourceFingerprintSource,
)
from keenvpn.application.source_baseline import BASELINE_CHANGED, BASELINE_UNAVAILABLE, compare_baseline
from keenvpn.domain.draft_session import DraftSession, StoredDraftSession, draft_revision, encode_draft_session
from keenvpn.domain.manager_metadata import UnknownFields
from keenvpn.domain.source_baseline import (
    BaselineSource as Source, FingerprintState, SourceBaseline, SourceBaselineError, SourceBaselineErrorCode,
    SourceFingerprint,
)
from keenvpn.interfaces.cli.presenters import present_error
from tests.support.in_memory import InMemoryDraftSessionStore, InMemorySourceFingerprints
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable


FIRST_ID = "0000abcd-0000-4000-8000-00000000000d"
SECOND_ID = "0000abcd-0000-4000-8000-00000000000e"
CREATED_AT = datetime(2026, 11, 1, 2, 14, 16, tzinfo=timezone.utc)
OPERATION = "test-operation"
PRESENT = FingerprintState.PRESENT
ABSENT = FingerprintState.ABSENT
PART = "01_log.json"
OTHER_PART = "02_TEST_dns.json"
PRIVATE_MARKERS = ("TEST_secret-extra", "TEST_private-note", "/opt/etc/TEST_secret", PART, OTHER_PART, "known_host")
PRIVATE_TYPES = (
    DraftSession, StoredDraftSession, UnknownFields, SourceBaseline, SourceFingerprint, BaseException, bytes,
)


def digest(index: int) -> str:
    return f"{index:064x}"


def fingerprint(source: Source, state: FingerprintState = PRESENT, index: int | None = None) -> SourceFingerprint:
    """Искусственный отпечаток; `index` по умолчанию — позиция источника в перечне."""
    if state is ABSENT:
        return SourceFingerprint(source, ABSENT)
    value = digest(list(Source).index(source) + 1 if index is None else index)
    if source is Source.XRAY_CONFIGS:
        return SourceFingerprint(source, PRESENT, parts=((PART, value),))
    return SourceFingerprint(source, PRESENT, sha256=value)


RECORDED = tuple(fingerprint(source, ABSENT if source is Source.XKEEN_INIT else PRESENT) for source in Source)
"""Исходные отпечатки черновика: все источники, init отсутствует."""
BASELINE = SourceBaseline(RECORDED)
DIGESTS = tuple(digest(index) for index in (*range(1, len(Source) + 1), 98, 99))


def baseline_without(*missing: Source, extra: dict[str, object] | None = None) -> SourceBaseline:
    return SourceBaseline(tuple(item for item in RECORDED if item.source not in missing), UnknownFields(extra))


def draft_bytes(baseline: SourceBaseline | None = BASELINE, draft_id: str = FIRST_ID, **extra) -> bytes:
    return encode_draft_session(DraftSession(draft_id, CREATED_AT, UnknownFields(extra or None), baseline))


def token(raw: bytes) -> str:
    """Токен ревизии, который интерфейс получает в представлении черновика с этими байтами."""
    return draft_revision_token(draft_revision(raw))


def conflict(source: Source | None, expected: State, found: State) -> dict[str, object]:
    return {"subject": "source", "source": None if source is None else source.value, "expected": expected.value,
            "found": found.value}


class HookedFingerprints(InMemorySourceFingerprints):
    """Отпечатки в памяти, где чтение выбранного источника сначала выполняет действие теста.

    Так тест имитирует внешнее изменение черновика, пока источники читаются.
    """

    def __init__(self) -> None:
        super().__init__()
        self.hooks: dict[Source, Callable[[], None]] = {}

    def current_fingerprint(self, source: Source) -> SourceFingerprint:
        hook = self.hooks.pop(source, None)
        if hook is not None:
            hook()
        return super().current_fingerprint(source)


def current_fingerprints() -> HookedFingerprints:
    """Текущее состояние, совпадающее с исходными отпечатками."""
    source = HookedFingerprints()
    for item in RECORDED:
        source.set_response(item.source, item)
    return source


class Text(str):
    pass


class CompareBaselineTests(unittest.TestCase):
    def setUp(self):
        self.fingerprints = current_fingerprints()

    def compare(self, baseline: SourceBaseline | None = BASELINE) -> ErrorDetail | None:
        with forbid_external_effects():
            error = compare_baseline(self.fingerprints, baseline)
        # Каждый источник перечня читается ровно один раз и по порядку, в том числе после отказа.
        self.assertEqual(self.fingerprints.calls, tuple(Source))
        return error

    def assert_conflicts(self, error: ErrorDetail, code: str, *expected: dict[str, object]) -> None:
        self.assertIs(type(error), ErrorDetail)
        self.assertEqual(error.code, code)
        self.assertIs(type(error.conflicts), tuple)
        self.assertTrue(all(type(item) is Conflict for item in error.conflicts))
        for item in error.conflicts:
            self.assertIs(item.subject, ConflictSubject.SOURCE)
            self.assertIs(type(item.expected), State)
            self.assertIs(type(item.found), State)
            if item.source is not None:
                self.assertIs(type(item.source), Source)
        self.assertEqual([item.to_dict() for item in error.conflicts], list(expected))
        text = json.dumps(error.to_dict(), ensure_ascii=False) + repr(error)
        for value in (*DIGESTS, *PRIVATE_MARKERS):
            self.assertNotIn(value, text)

    def test_matching_sources_give_no_error_and_absent_matches_absent(self):
        self.assertIsNone(self.compare())
        # Пустой файл и пустой каталог частей совпадают только сами с собой.
        empty = SourceBaseline((
            SourceFingerprint(Source.XRAY_CONFIGS, PRESENT, parts=()), *RECORDED[1:],
        ))
        self.fingerprints = current_fingerprints()
        self.fingerprints.set_response(Source.XRAY_CONFIGS, SourceFingerprint(Source.XRAY_CONFIGS, PRESENT, parts=()))
        self.assertIsNone(self.compare(empty))

    def test_each_transition_gives_its_record(self):
        cases = (
            (Source.XKEEN_SETTINGS, fingerprint(Source.XKEEN_SETTINGS, index=99), State.PRESENT, State.CHANGED),
            (Source.XKEEN_SETTINGS, fingerprint(Source.XKEEN_SETTINGS, ABSENT), State.PRESENT, State.ABSENT),
            (Source.XKEEN_INIT, fingerprint(Source.XKEEN_INIT, index=99), State.ABSENT, State.PRESENT),
            (Source.KEENETIC_POLICIES, fingerprint(Source.KEENETIC_POLICIES, index=99), State.PRESENT, State.CHANGED),
            (Source.XRAY_CONFIGS, fingerprint(Source.XRAY_CONFIGS, ABSENT), State.PRESENT, State.ABSENT),
        )
        for source, found, expected_state, found_state in cases:
            with self.subTest(source=source.value, found=found_state.value):
                self.fingerprints = current_fingerprints()
                self.fingerprints.set_response(source, found)
                error = self.compare()
                self.assert_conflicts(error, "draft_baseline_changed", conflict(source, expected_state, found_state))
                self.assertEqual(
                    (error.category, error.reason, error.message),
                    (ErrorCategory.SOURCE_FAILED, None, BASELINE_CHANGED.message),
                )
                self.assertIs(error.next_step.code, NextStepCode.RECREATE_DRAFT)

    def test_any_change_of_xray_part_set_is_a_change(self):
        recorded = RECORDED[0].parts[0][1]
        for parts in (
            ((PART, recorded), (OTHER_PART, digest(99))),
            (),
            ((OTHER_PART, recorded),),
            ((PART, digest(99)),),
        ):
            with self.subTest(parts=len(parts)):
                self.fingerprints = current_fingerprints()
                self.fingerprints.set_response(Source.XRAY_CONFIGS, SourceFingerprint(Source.XRAY_CONFIGS, PRESENT, parts=parts))
                self.assert_conflicts(
                    self.compare(), "draft_baseline_changed", conflict(Source.XRAY_CONFIGS, State.PRESENT, State.CHANGED),
                )

    def test_all_differences_are_reported_in_source_order(self):
        self.fingerprints.set_response(Source.KEENETIC_HOTSPOT_SETTINGS, fingerprint(Source.KEENETIC_HOTSPOT_SETTINGS, ABSENT))
        self.fingerprints.set_response(Source.XKEEN_INIT, fingerprint(Source.XKEEN_INIT))
        self.fingerprints.set_response(Source.XRAY_CONFIGS, fingerprint(Source.XRAY_CONFIGS, index=99))
        self.assert_conflicts(
            self.compare(), "draft_baseline_changed",
            conflict(Source.XRAY_CONFIGS, State.PRESENT, State.CHANGED),
            conflict(Source.XKEEN_INIT, State.ABSENT, State.PRESENT),
            conflict(Source.KEENETIC_HOTSPOT_SETTINGS, State.PRESENT, State.ABSENT),
        )

    def test_source_missing_from_draft_is_read_and_blocks(self):
        error = self.compare(baseline_without(Source.XKEEN_SETTINGS, Source.XKEEN_INIT))
        self.assert_conflicts(
            error, "draft_baseline_changed",
            conflict(Source.XKEEN_SETTINGS, State.UNKNOWN, State.PRESENT),
            conflict(Source.XKEEN_INIT, State.UNKNOWN, State.ABSENT),
        )
        self.assertIs(error.next_step.code, NextStepCode.RECREATE_DRAFT)

    def test_draft_without_baseline_section_blocks_with_every_source(self):
        error = self.compare(None)
        self.assert_conflicts(error, "draft_baseline_changed", *(
            conflict(item.source, State.UNKNOWN, State.ABSENT if item.state is ABSENT else State.PRESENT)
            for item in RECORDED
        ))

    def test_unknown_records_block_with_one_record_after_known(self):
        extra = {"known_host": {"state": "present", "sha256": digest(98)}, "TEST_secret-extra": {"state": "absent"}}
        error = self.compare(baseline_without(extra=extra))
        self.assert_conflicts(error, "draft_baseline_changed", conflict(None, State.UNKNOWN, State.UNKNOWN))
        self.fingerprints = current_fingerprints()
        self.fingerprints.set_response(Source.XKEEN_IP_EXCLUDE, fingerprint(Source.XKEEN_IP_EXCLUDE, ABSENT))
        self.assert_conflicts(
            self.compare(baseline_without(extra=extra)), "draft_baseline_changed",
            conflict(Source.XKEEN_IP_EXCLUDE, State.PRESENT, State.ABSENT), conflict(None, State.UNKNOWN, State.UNKNOWN),
        )

    def test_unreadable_source_mid_list_is_not_a_match_and_others_are_read(self):
        self.fingerprints.set_response(Source.XKEEN_INIT, RouterReadError(RouterReadFailure.TIMEOUT))
        error = self.compare()
        self.assert_conflicts(error, "draft_baseline_unavailable", conflict(Source.XKEEN_INIT, State.ABSENT, State.UNKNOWN))
        self.assertEqual(
            (error.category, error.reason, error.message, error.next_step.code),
            (ErrorCategory.SOURCE_FAILED, "timeout", BASELINE_UNAVAILABLE.message, NextStepCode.CHECK_SOURCE),
        )

    def test_invalid_fingerprint_is_not_a_match(self):
        cases = (
            (fingerprint(Source.KEENETIC_POLICIES), None),
            (SourceBaselineError(SourceBaselineErrorCode.PARTS), SourceBaselineErrorCode.PARTS.value),
            ("TEST_private-note", None),
        )
        for outcome, reason in cases:
            with self.subTest(reason=reason):
                self.fingerprints = current_fingerprints()
                self.fingerprints.set_response(Source.KEENETIC_HOTSPOT_SETTINGS, outcome)
                error = self.compare()
                self.assert_conflicts(
                    error, "invalid_draft_baseline_source",
                    conflict(Source.KEENETIC_HOTSPOT_SETTINGS, State.PRESENT, State.UNKNOWN),
                )
                self.assertEqual(
                    (error.category, error.reason, error.next_step.code),
                    (ErrorCategory.INVALID_SOURCE_DATA, reason, NextStepCode.INSPECT_SOURCE_DATA),
                )

    def test_unexpected_exception_text_does_not_leak(self):
        self.fingerprints.set_response(Source.XKEEN_SETTINGS, RuntimeError("TEST_private-note /opt/etc/TEST_secret"))
        error = self.compare()
        self.assert_conflicts(
            error, "draft_baseline_unavailable", conflict(Source.XKEEN_SETTINGS, State.PRESENT, State.UNKNOWN),
        )
        self.assertIsNone(error.reason)

    def test_first_read_failure_gives_code_when_only_reads_failed(self):
        self.fingerprints.set_response(Source.XRAY_CONFIGS, RouterReadError(RouterReadFailure.PERMISSION_DENIED))
        self.fingerprints.set_response(Source.KEENETIC_POLICIES, fingerprint(Source.KEENETIC_HOTSPOT_SETTINGS))
        error = self.compare()
        self.assert_conflicts(
            error, "draft_baseline_unavailable",
            conflict(Source.XRAY_CONFIGS, State.PRESENT, State.UNKNOWN),
            conflict(Source.KEENETIC_POLICIES, State.PRESENT, State.UNKNOWN),
        )
        self.assertEqual(error.reason, "permission_denied")

    def test_change_with_read_failure_is_stale_with_all_records(self):
        self.fingerprints.set_response(Source.XKEEN_PORT_EXCLUDE, fingerprint(Source.XKEEN_PORT_EXCLUDE, index=99))
        self.fingerprints.set_response(Source.KEENETIC_POLICIES, RouterReadError(RouterReadFailure.CONNECTION_FAILED))
        error = self.compare()
        self.assert_conflicts(
            error, "draft_baseline_changed",
            conflict(Source.XKEEN_PORT_EXCLUDE, State.PRESENT, State.CHANGED),
            conflict(Source.KEENETIC_POLICIES, State.PRESENT, State.UNKNOWN),
        )
        self.assertIsNone(error.reason)
        self.assertIs(error.next_step.code, NextStepCode.RECREATE_DRAFT)

    def test_unread_source_missing_from_draft_cannot_be_retried_into_a_match(self):
        self.fingerprints.set_response(Source.XKEEN_SETTINGS, RouterReadError(RouterReadFailure.IO_ERROR))
        self.assert_conflicts(
            self.compare(baseline_without(Source.XKEEN_SETTINGS)), "draft_baseline_changed",
            conflict(Source.XKEEN_SETTINGS, State.UNKNOWN, State.UNKNOWN),
        )

    def test_baseline_argument_must_be_a_model(self):
        for value in ({}, RECORDED, BASELINE.to_diagnostic()):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                compare_baseline(self.fingerprints, value)
        self.assertEqual(self.fingerprints.calls, ())


class CheckCase(unittest.TestCase):
    store_changed_by_test = False
    """Тест сам меняет байты черновика во время проверки: сравнивать их с исходными нельзя."""

    def setUp(self):
        self.store = InMemoryDraftSessionStore(draft_bytes())
        self.fingerprints = current_fingerprints()
        self.handler = CheckDraftBaselineHandler(self.store, self.fingerprints, operation_ids=lambda: OPERATION)

    def command(self, draft_id: object = FIRST_ID, expected_revision: object = None) -> CheckDraftBaseline:
        if expected_revision is None:
            expected_revision = token(self.store.content)
        return CheckDraftBaseline(draft_id=draft_id, expected_revision=expected_revision)

    def execute(self, command: object = None):
        before = self.store.content
        command = self.command() if command is None else command
        with forbid_external_effects():
            result = self.handler.execute(command)
        self.assert_nothing_written(before)
        self.assert_private(result)
        return result

    def assert_nothing_written(self, before: bytes | None):
        """Ни одного изменения хранилища: ни создания, ни удаления, ни подтверждения отсутствия."""
        self.assertEqual(
            (self.store.changes, self.store.create_calls, self.store.remove_calls, self.store.confirm_calls),
            (0, (), (), 0),
        )
        if self.store.content is not None and before is not None and not self.store_changed_by_test:
            self.assertEqual(self.store.content, before)

    def assert_private(self, result):
        text = json.dumps(result.to_dict(), ensure_ascii=False) + repr(result)
        for value in (*PRIVATE_MARKERS, *DIGESTS):
            self.assertNotIn(value, text)
        for raw in (draft_bytes(), draft_bytes(draft_id=SECOND_ID), self.store.content):
            if raw is not None:
                self.assertNotIn(draft_revision(raw), text)
                self.assertNotIn(token(raw), text)
        self.assertFalse([type(item).__name__ for item in reachable(result) if isinstance(item, PRIVATE_TYPES)])
        self.assertEqual(result.operation_id, OPERATION)

    def assert_failed(self, result, category, code, reason=None, step=None):
        self.assertFalse(result.succeeded)
        self.assertEqual((result.error.category, result.error.code, result.error.reason), (category, code, reason))
        self.assertEqual(None if result.error.next_step is None else result.error.next_step.code, step)

    def assert_draft_conflict(self, result, expected, found):
        self.assertEqual(result.to_dict()["error"]["conflicts"], [
            {"subject": "draft", "source": None, "expected": expected.value, "found": found.value},
        ])


class CheckDraftBaselineTests(CheckCase):
    def test_current_draft_succeeds_without_writing(self):
        result = self.execute()
        self.assertTrue(result.succeeded)
        self.assertEqual(result.command, "check_draft_baseline")
        self.assertEqual(result.contract_version, CONTRACT_VERSION)
        self.assertEqual(result.data, DraftBaselineCheckView(DraftBaselineOutcome.CURRENT.value, FIRST_ID))
        self.assertIs(type(result.data.outcome), str)
        self.assertEqual(result.to_dict()["data"], {"outcome": "current", "draft_id": FIRST_ID})
        # Два чтения хранилища — до и после источников — и по одному чтению каждого источника.
        self.assertEqual(self.store.read_calls, 2)
        self.assertEqual(self.fingerprints.calls, tuple(Source))
        with self.assertRaises(FrozenInstanceError):
            result.data.outcome = "TEST_private-note"

    def test_stale_draft_is_refused_with_records_and_step(self):
        self.fingerprints.set_response(Source.XKEEN_PORT_PROXYING, fingerprint(Source.XKEEN_PORT_PROXYING, index=99))
        result = self.execute()
        self.assert_failed(
            result, ErrorCategory.SOURCE_FAILED, "draft_baseline_changed", step=NextStepCode.RECREATE_DRAFT,
        )
        self.assertEqual(
            result.to_dict()["error"]["conflicts"], [conflict(Source.XKEEN_PORT_PROXYING, State.PRESENT, State.CHANGED)],
        )
        self.assertEqual(result.error.next_step.message, NEXT_STEP_MESSAGES[NextStepCode.RECREATE_DRAFT])
        self.assertEqual(self.store.read_calls, 2)

    def test_unreadable_source_is_refused_as_read_failure(self):
        self.fingerprints.set_response(Source.KEENETIC_HOTSPOT_SETTINGS, RouterReadError(RouterReadFailure.HTTP_STATUS))
        result = self.execute()
        self.assert_failed(
            result, ErrorCategory.SOURCE_FAILED, "draft_baseline_unavailable", "http_status", NextStepCode.CHECK_SOURCE,
        )
        self.assertEqual(
            result.to_dict()["error"]["conflicts"],
            [conflict(Source.KEENETIC_HOTSPOT_SETTINGS, State.PRESENT, State.UNKNOWN)],
        )

    def test_legacy_draft_without_baseline_is_refused(self):
        self.store.content = draft_bytes(None, **{"TEST_secret-extra": "TEST_private-note"})
        result = self.execute()
        self.assert_failed(
            result, ErrorCategory.SOURCE_FAILED, "draft_baseline_changed", step=NextStepCode.RECREATE_DRAFT,
        )
        self.assertEqual(len(result.error.conflicts), len(Source))
        self.assertTrue(all(item.expected is State.UNKNOWN for item in result.error.conflicts))

    def test_command_format_is_checked_before_any_read(self):
        raw_revision = draft_revision(self.store.content)
        good = token(self.store.content)
        for draft_id, revision in (
            (FIRST_ID.upper(), good), ("TEST_private-note", good), (Text(FIRST_ID), good), (None, good),
            (FIRST_ID, raw_revision), (FIRST_ID, good.upper()), (FIRST_ID, good[:-1]), (FIRST_ID, Text(good)),
            (FIRST_ID, good.encode("ascii")), (FIRST_ID, None), (FIRST_ID, f" {good[1:]}"),
        ):
            with self.subTest(draft_id=repr(draft_id)[:12], revision=repr(revision)[:12]):
                result = self.execute(CheckDraftBaseline(draft_id=draft_id, expected_revision=revision))
                self.assert_failed(result, ErrorCategory.INVALID_REQUEST, "invalid_command")
        self.assertEqual((self.store.read_calls, self.fingerprints.calls), (0, ()))

    def test_wrong_command_type_and_version_are_refused_without_reads(self):
        discard = DiscardDraft(draft_id=FIRST_ID, expected_revision=token(self.store.content))
        self.assert_failed(self.execute(discard), ErrorCategory.INVALID_REQUEST, "invalid_command")
        for version in (2, True, "1"):
            with self.subTest(version=repr(version)):
                command = CheckDraftBaseline(
                    draft_id=FIRST_ID, expected_revision=token(self.store.content), contract_version=version,
                )
                self.assert_failed(
                    self.execute(command), ErrorCategory.INVALID_REQUEST, "unsupported_contract_version",
                    step=NextStepCode.UPDATE_INTERFACE,
                )
        self.assertEqual((self.store.read_calls, self.fingerprints.calls), (0, ()))

    def test_absent_draft_is_a_draft_conflict_without_reading_sources(self):
        command = self.command()
        self.store.content = None
        result = self.execute(command)
        self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_revision_conflict", step=NextStepCode.OPEN_VIEW)
        self.assert_draft_conflict(result, State.PRESENT, State.ABSENT)
        self.assertEqual(result.error, DRAFT_GONE)
        self.assertEqual((self.store.read_calls, self.fingerprints.calls), (1, ()))

    def test_other_draft_or_stale_token_is_refused_without_reading_sources(self):
        result = self.execute(self.command(draft_id=SECOND_ID))
        self.assert_failed(result, ErrorCategory.UNSUPPORTED, "draft_mismatch", step=NextStepCode.OPEN_VIEW)
        self.assert_draft_conflict(result, State.PRESENT, State.CHANGED)
        stale = token(draft_bytes(baseline_without(Source.XKEEN_INIT)))
        result = self.execute(self.command(expected_revision=stale))
        self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_revision_conflict", step=NextStepCode.OPEN_VIEW)
        self.assertEqual(result.error, DRAFT_CHANGED)
        self.assertEqual(self.fingerprints.calls, ())

    def test_store_failures_keep_their_codes(self):
        for failure, code, step in (
            (DraftStoreFailure.BUSY, "draft_store_busy", NextStepCode.RETRY_LATER),
            (DraftStoreFailure.UNSAFE, "draft_store_unsafe", NextStepCode.PRESERVE_FILE),
        ):
            with self.subTest(failure=failure.value):
                self.store.read_failure = DraftSessionStoreError(failure)
                result = self.execute(self.command(expected_revision=token(draft_bytes())))
                self.assert_failed(result, ErrorCategory.SOURCE_FAILED, code, step=step)
                self.assertEqual(result.error.conflicts, ())
        self.store.read_failure = None
        self.store.content = b"{TEST_private-note"
        result = self.execute(self.command(expected_revision=token(draft_bytes())))
        self.assert_failed(
            result, ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_draft", "invalid_draft_json",
            NextStepCode.PRESERVE_FILE,
        )
        self.assertEqual(self.fingerprints.calls, ())


class ConcurrentChangeTests(CheckCase):
    store_changed_by_test = True

    def change_draft_while_reading(self, source: Source, change: Callable[[], None]):
        command = self.command()
        self.fingerprints.hooks[source] = change
        return self.execute(command)

    def test_draft_changed_during_check_is_a_draft_conflict_even_if_sources_match(self):
        def edit():
            self.store.content = draft_bytes(**{"TEST_secret-extra": "TEST_private-note"})

        result = self.change_draft_while_reading(Source.XKEEN_SETTINGS, edit)
        self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_revision_conflict", step=NextStepCode.OPEN_VIEW)
        self.assertEqual(result.error, DRAFT_CHANGED)
        self.assertEqual((self.store.read_calls, self.fingerprints.calls), (2, tuple(Source)))

    def test_draft_change_outranks_source_differences(self):
        self.fingerprints.set_response(Source.XKEEN_INIT, fingerprint(Source.XKEEN_INIT))

        def replace_by_other():
            self.store.content = draft_bytes(draft_id=SECOND_ID)

        result = self.change_draft_while_reading(Source.XRAY_CONFIGS, replace_by_other)
        self.assertEqual(result.error, DRAFT_CHANGED)

    def test_draft_removed_during_check_is_a_draft_conflict(self):
        def remove():
            self.store.content = None

        result = self.change_draft_while_reading(Source.KEENETIC_POLICIES, remove)
        self.assertEqual(result.error, DRAFT_GONE)
        self.assert_draft_conflict(result, State.PRESENT, State.ABSENT)

    def test_store_failure_on_second_read_is_returned(self):
        def fail():
            self.store.read_failure = DraftSessionStoreError(DraftStoreFailure.UNAVAILABLE)

        result = self.change_draft_while_reading(Source.KEENETIC_HOTSPOT_SETTINGS, fail)
        self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_store_unavailable", step=NextStepCode.CHECK_SOURCE)
        self.assertEqual(self.store.read_calls, 2)


class GuardForApplyTests(CheckCase):
    """Помощник, которым будущее применение охраняет запись: запись возможна только после успеха."""

    def apply_if_current(self, writes: list[str], command: CheckDraftBaseline) -> ErrorDetail | None:
        """Тестовый двойник применения: пишет ревизию прочитанного черновика только после успешной проверки."""
        checked = check_draft_current(self.store, self.fingerprints, command.draft_id, command.expected_revision)
        if isinstance(checked, ErrorDetail):
            return checked
        writes.append(checked.revision)
        return None

    def test_current_draft_is_returned_with_revision_from_read(self):
        command = self.command()
        with forbid_external_effects():
            checked = check_draft_current(self.store, self.fingerprints, command.draft_id, command.expected_revision)
        self.assertIs(type(checked), StoredDraftSession)
        self.assertEqual(checked.revision, draft_revision(draft_bytes()))
        self.assertEqual(checked.session.draft_id, FIRST_ID)
        writes: list[str] = []
        self.assertIsNone(self.apply_if_current(writes, command))
        self.assertEqual(writes, [draft_revision(draft_bytes())])

    def test_no_write_over_new_state(self):
        refusals = {
            "changed": lambda: self.fingerprints.set_response(Source.XKEEN_SETTINGS, fingerprint(Source.XKEEN_SETTINGS, index=99)),
            "disappeared": lambda: self.fingerprints.set_response(Source.XRAY_CONFIGS, fingerprint(Source.XRAY_CONFIGS, ABSENT)),
            "appeared": lambda: self.fingerprints.set_response(Source.XKEEN_INIT, fingerprint(Source.XKEEN_INIT)),
            "unreadable": lambda: self.fingerprints.set_response(
                Source.KEENETIC_POLICIES, RouterReadError(RouterReadFailure.TIMEOUT),
            ),
        }
        for name, prepare in refusals.items():
            with self.subTest(case=name):
                self.fingerprints = current_fingerprints()
                prepare()
                writes: list[str] = []
                command = self.command()
                with forbid_external_effects():
                    error = self.apply_if_current(writes, command)
                self.assertIs(type(error), ErrorDetail)
                self.assertTrue(error.conflicts)
                self.assertEqual(writes, [])
                self.assert_nothing_written(draft_bytes())

    def test_guard_checks_format_itself(self):
        writes: list[str] = []
        error = self.apply_if_current(writes, CheckDraftBaseline(draft_id=FIRST_ID, expected_revision="0" * 64))
        self.assertEqual(error.code, "invalid_command")
        self.assertEqual((writes, self.store.read_calls, self.fingerprints.calls), ([], 0, ()))


class StaleDraftPresentationTests(CheckCase):
    def test_cli_shows_records_and_step_from_the_error(self):
        self.store.content = draft_bytes(baseline_without(extra={"known_host": {"state": "absent"}}))
        self.fingerprints.set_response(Source.XKEEN_SETTINGS, fingerprint(Source.XKEEN_SETTINGS, index=99))
        self.fingerprints.set_response(Source.KEENETIC_POLICIES, RouterReadError(RouterReadFailure.TIMEOUT))
        lines = present_error(self.execute().error)
        self.assertEqual(lines, [
            "Отказ: source_failed / draft_baseline_changed",
            f"Причина: {BASELINE_CHANGED.message}",
            "Конфликт: источник xkeen_settings — ожидалось: есть, найдено: другая ревизия",
            "Конфликт: источник keenetic_policies — ожидалось: есть, найдено: не установлено",
            "Конфликт: источник неизвестен этой версии — ожидалось: не установлено, найдено: не установлено",
            f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.RECREATE_DRAFT]}",
        ])


if __name__ == "__main__":
    unittest.main()
