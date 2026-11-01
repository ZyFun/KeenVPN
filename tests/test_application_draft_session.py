"""Создание, просмотр и отмена сессии черновика.

Сценарии проверяются на управляемом хранилище в памяти и с настоящим
файловым хранилищем во временном каталоге. Роутер, active configs Xray
и XKeen, сеть и процессы не используются.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import errno
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.adapters.manager_metadata_files import METADATA_FILE_NAME, ManagerMetadataFiles
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory, NextStepCode
from keenvpn.application.draft_session import (
    BaselineSourceView, CreateDraft, CreateDraftHandler, DiscardDraft, DiscardDraftHandler, DraftBaselineView,
    DraftDiscardView, DraftStatusView, DraftView, InspectDraft, InspectDraftHandler, new_draft_id, utc_now,
)
from keenvpn.application.ports import (
    DraftSessionStoreError, DraftStoreFailure as Failure, RouterReadError, RouterReadFailure, StoreReason as Reason,
)
from keenvpn.domain.draft_session import (
    DraftSession, DraftSessionErrorCode, StoredDraftSession, draft_revision, encode_draft_session, valid_created_at,
    valid_draft_id,
)
from keenvpn.domain.manager_metadata import ManagerMetadata, UnknownFields, encode_manager_metadata
from keenvpn.domain.source_baseline import (
    BaselineSource, FingerprintState, SourceBaseline, SourceBaselineError, SourceBaselineErrorCode, SourceFingerprint,
)
from tests.support.in_memory import AdapterSetupError, InMemoryDraftSessionStore, InMemorySourceFingerprints
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable


FIRST_ID = "0000abcd-0000-4000-8000-00000000000d"
SECOND_ID = "0000abcd-0000-4000-8000-00000000000e"
CREATED_AT = datetime(2026, 11, 1, 2, 14, 16, tzinfo=timezone.utc)
OPERATION = "test-operation"
PRIVATE_MARKERS = ("TEST_secret-extra", "TEST_private-note", "/tmp/mnt", "private-owner")
PRIVATE_TYPES = (
    DraftSession, StoredDraftSession, UnknownFields, SourceBaseline, SourceFingerprint, BaseException, bytes,
)
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
    Failure.INVALID: DraftSessionErrorCode.JSON.value,
    Failure.WRITE_FAILED: Reason.NO_SPACE.value,
    Failure.WRITE_UNCONFIRMED: Reason.IO_ERROR.value,
}
STEPS = {
    Failure.UNAVAILABLE: NextStepCode.CHECK_SOURCE,
    Failure.UNSAFE: NextStepCode.PRESERVE_FILE,
    Failure.BUSY: NextStepCode.RETRY_LATER,
    Failure.CONFLICT: NextStepCode.OPEN_VIEW,
    Failure.INVALID: NextStepCode.PRESERVE_FILE,
    Failure.WRITE_FAILED: NextStepCode.CHECK_SOURCE,
    Failure.WRITE_UNCONFIRMED: NextStepCode.OPEN_VIEW,
}


def session(draft_id: str = FIRST_ID, **extra) -> DraftSession:
    return DraftSession(draft_id, CREATED_AT, UnknownFields(extra or None))


def content(draft_id: str = FIRST_ID, **extra) -> bytes:
    return encode_draft_session(session(draft_id, **extra))


def digest(index: int) -> str:
    return f"{index:064x}"


def baseline_fingerprints() -> tuple[SourceFingerprint, ...]:
    """Искусственные отпечатки всех источников; init отсутствует."""
    items = []
    for index, source in enumerate(BaselineSource, start=1):
        if source is BaselineSource.XRAY_CONFIGS:
            items.append(SourceFingerprint(source, FingerprintState.PRESENT, parts=(("01_log.json", digest(index)),)))
        elif source is BaselineSource.XKEEN_INIT:
            items.append(SourceFingerprint(source, FingerprintState.ABSENT))
        else:
            items.append(SourceFingerprint(source, FingerprintState.PRESENT, sha256=digest(index)))
    return tuple(items)


BASELINE = SourceBaseline(baseline_fingerprints())
BASELINE_VIEW = DraftBaselineView(
    tuple(BaselineSourceView(item.source.value, item.state.value) for item in BASELINE.fingerprints), 0,
)
DIGESTS = tuple(digest(index) for index in range(1, len(BaselineSource) + 1))


def fingerprints() -> InMemorySourceFingerprints:
    source = InMemorySourceFingerprints()
    for item in BASELINE.fingerprints:
        source.set_response(item.source, item)
    return source


def created_content(draft_id: str = FIRST_ID) -> bytes:
    """Байты черновика, который создаёт сценарий: с исходными отпечатками."""
    return encode_draft_session(DraftSession(draft_id, CREATED_AT, baseline=BASELINE))


class Text(str):
    pass


class ScenarioCase(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryDraftSessionStore()
        self.fingerprints = fingerprints()
        self.inspect = InspectDraftHandler(self.store, operation_ids=lambda: OPERATION)
        self.create = CreateDraftHandler(
            self.store, self.fingerprints, operation_ids=lambda: OPERATION, draft_ids=lambda: FIRST_ID,
            clock=lambda: datetime(2026, 11, 1, 5, 14, 16, 999999, tzinfo=timezone(timedelta(hours=3))),
        )
        self.discard = DiscardDraftHandler(self.store, operation_ids=lambda: OPERATION)

    def assert_private(self, result):
        text = json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        if self.store.content is not None:
            self.assertNotIn(draft_revision(self.store.content), text)
        for value in DIGESTS:
            self.assertNotIn(value, text)
        self.assertNotIn("01_log.json", text)
        self.assertFalse([type(item).__name__ for item in reachable(result) if isinstance(item, PRIVATE_TYPES)])
        self.assertEqual(result.operation_id, OPERATION)

    def assert_failed(self, result, category, code, reason=None, step=None):
        self.assertFalse(result.succeeded)
        self.assertEqual((result.error.category, result.error.code, result.error.reason), (category, code, reason))
        self.assertEqual(None if result.error.next_step is None else result.error.next_step.code, step)
        self.assert_private(result)


class InspectDraftTests(ScenarioCase):
    def test_absent_draft_is_a_successful_state(self):
        with forbid_external_effects():
            result = self.inspect.execute(InspectDraft())
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data, DraftStatusView(False, None))
        self.assertEqual(result.to_dict()["data"], {"present": False, "draft": None})
        self.assertEqual((self.store.read_calls, self.store.create_calls, self.store.remove_calls), (1, (), ()))

    def test_present_draft_shows_id_time_and_unknown_count_only(self):
        self.store.content = content(**{"TEST_secret-extra": "TEST_private-note"})
        with forbid_external_effects():
            result = self.inspect.execute(InspectDraft())
        self.assertEqual(result.to_dict()["data"], {"present": True, "draft": {
            "draft_id": FIRST_ID, "created_at": "2026-11-01T02:14:16Z", "unknown_field_count": 1, "baseline": None,
        }})
        self.assert_private(result)
        with self.assertRaises(FrozenInstanceError):
            result.data.present = False

    def test_store_failures_keep_code_category_reason_and_step(self):
        for failure in Failure:
            with self.subTest(failure=failure.value):
                self.store.read_failure = DraftSessionStoreError(failure, reason=REASONS[failure])
                with forbid_external_effects():
                    result = self.inspect.execute(InspectDraft())
                self.assert_failed(result, CATEGORIES[failure], failure.value, REASONS[failure], STEPS[failure])
        self.store.read_failure = DraftSessionStoreError(Failure.UNSAFE, reason=Reason.SYMLINK)
        self.assert_failed(self.inspect.execute(InspectDraft()), ErrorCategory.SOURCE_FAILED, "draft_store_unsafe",
                           "symlink", NextStepCode.PRESERVE_FILE)

    def test_unexpected_failures_and_foreign_reasons_reveal_nothing(self):
        class Subclass(DraftSessionStoreError):
            pass
        plain_code = DraftSessionStoreError(Failure.CONFLICT)
        # Код строкой, а не членом перечисления: сравнение `==` со строкой не должно его пропустить.
        plain_code.failure = "draft_revision_conflict"
        for error in (OSError("/tmp/mnt/private-owner/draft"), Subclass(Failure.CONFLICT), plain_code):
            with self.subTest(error=type(error).__name__):
                self.store.read_failure = error
                self.assert_failed(self.inspect.execute(InspectDraft()), ErrorCategory.SOURCE_FAILED,
                                   "draft_store_failed", step=NextStepCode.OPEN_VIEW)
        for reason in ("/tmp/mnt/private-owner", Text("missing"), "invalid_draft_json", 1):
            with self.subTest(reason=reason):
                self.store.read_failure = DraftSessionStoreError(Failure.UNAVAILABLE, reason=reason)
                result = self.inspect.execute(InspectDraft())
                self.assertEqual((result.error.code, result.error.reason), ("draft_store_unavailable", None))
        self.store.read_failure = DraftSessionStoreError(Failure.INVALID, reason="missing")
        self.assertIsNone(self.inspect.execute(InspectDraft()).error.reason)

    def test_damaged_file_gives_domain_reason_and_preserve_step(self):
        for raw, reason in (
            (b"{", "invalid_draft_json"), (b'{"format": "keenvpn-draft-session", "schema_version": 2}',
                                           "unsupported_draft_schema_version"),
            (encode_manager_metadata(ManagerMetadata()), "invalid_draft_format"),
        ):
            with self.subTest(reason=reason):
                self.store.content = raw
                self.assert_failed(self.inspect.execute(InspectDraft()), ErrorCategory.INVALID_SOURCE_DATA,
                                   "invalid_stored_draft", reason, NextStepCode.PRESERVE_FILE)
                self.assertEqual(self.store.content, raw)

    def test_store_answers_outside_the_contract_are_rejected(self):
        class Stored(StoredDraftSession):
            pass
        stored = StoredDraftSession(session(), draft_revision(content()))
        tampered = session()
        object.__setattr__(tampered, "draft_id", Text(FIRST_ID))
        bad_revision = StoredDraftSession(session(), draft_revision(b"x"))
        object.__setattr__(bad_revision, "revision", Text(bad_revision.revision))
        for answer in ("draft", Stored(session(), stored.revision), bad_revision):
            with self.subTest(answer=type(answer).__name__):
                store = _Answering(answer)
                self.assert_failed(InspectDraftHandler(store, operation_ids=lambda: OPERATION).execute(InspectDraft()),
                                   ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_store_result",
                                   step=NextStepCode.OPEN_VIEW)
        broken = StoredDraftSession(session(), stored.revision)
        object.__setattr__(broken, "session", tampered)
        self.assert_failed(InspectDraftHandler(_Answering(broken), operation_ids=lambda: OPERATION)
                           .execute(InspectDraft()), ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_store_result",
                           step=NextStepCode.OPEN_VIEW)

    def test_invalid_command_and_contract_version(self):
        for handler, command in ((self.inspect, InspectDraft), (self.create, CreateDraft)):
            with self.subTest(command=command.name):
                result = handler.execute(object())
                self.assert_failed(result, ErrorCategory.INVALID_REQUEST, "invalid_command")
                result = handler.execute(command(contract_version=CONTRACT_VERSION + 1))
                self.assert_failed(result, ErrorCategory.INVALID_REQUEST, "unsupported_contract_version",
                                   step=NextStepCode.UPDATE_INTERFACE)
        self.assertEqual((self.store.read_calls, self.store.create_calls), (0, ()))


class _Answering:
    """Хранилище, которое на чтение возвращает заданный объект как есть."""

    def __init__(self, answer):
        self.answer = answer

    def read_draft(self):
        return self.answer

    def create_draft(self, session):
        raise AssertionError("создание не ожидалось")

    def remove_draft(self, expected_revision):
        raise AssertionError("удаление не ожидалось")

    def confirm_draft_absent(self):
        raise AssertionError("подтверждение отсутствия не ожидалось")


class CreateDraftTests(ScenarioCase):
    def test_creates_session_with_new_id_and_utc_second(self):
        with forbid_external_effects():
            result = self.create.execute(CreateDraft())
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data, DraftView(FIRST_ID, "2026-11-01T02:14:16Z", 0, BASELINE_VIEW))
        self.assertEqual(self.store.content, created_content())
        self.assertEqual(self.store.create_calls, (DraftSession(FIRST_ID, CREATED_AT, baseline=BASELINE),))
        self.assert_private(result)
        self.assertEqual(self.inspect.execute(InspectDraft()).data, DraftStatusView(True, result.data))

    def test_default_factories_give_valid_id_and_time(self):
        self.assertTrue(valid_draft_id(new_draft_id()))
        self.assertNotEqual(new_draft_id(), new_draft_id())
        now = utc_now()
        self.assertIs(now.tzinfo, timezone.utc)
        handler = CreateDraftHandler(self.store, fingerprints(), operation_ids=lambda: OPERATION)
        with forbid_external_effects():
            result = handler.execute(CreateDraft())
        self.assertTrue(result.succeeded)
        created = self.store.create_calls[0]
        self.assertTrue(valid_draft_id(created.draft_id) and valid_created_at(created.created_at))
        self.assertLessEqual(abs(created.created_at - now), timedelta(minutes=1))

    def test_existing_draft_is_not_overwritten(self):
        self.store.content = content(SECOND_ID)
        with forbid_external_effects():
            result = self.create.execute(CreateDraft())
        self.assert_failed(result, ErrorCategory.UNSUPPORTED, "draft_exists", step=NextStepCode.OPEN_VIEW)
        self.assertEqual((self.store.content, self.store.create_calls), (content(SECOND_ID), ()))

    def test_read_failure_and_damaged_file_prevent_creation(self):
        self.store.content = b"{"
        self.assert_failed(self.create.execute(CreateDraft()), ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_draft",
                           "invalid_draft_json", NextStepCode.PRESERVE_FILE)
        self.store.content = None
        self.store.read_failure = DraftSessionStoreError(Failure.BUSY)
        self.assert_failed(self.create.execute(CreateDraft()), ErrorCategory.SOURCE_FAILED, "draft_store_busy",
                           step=NextStepCode.RETRY_LATER)
        self.assertEqual(self.store.create_calls, ())

    def test_draft_created_after_read_is_a_conflict(self):
        def appear():
            self.store.content = content(SECOND_ID)
        self.store.before_revision_check = appear
        with forbid_external_effects():
            result = self.create.execute(CreateDraft())
        self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_revision_conflict", step=NextStepCode.OPEN_VIEW)
        self.assertEqual(self.store.content, content(SECOND_ID))

    def test_write_failures_are_not_success(self):
        for failure, published in (
            (Failure.WRITE_FAILED, False), (Failure.UNSAFE, False), (Failure.WRITE_UNCONFIRMED, True),
        ):
            with self.subTest(failure=failure.value):
                self.store.content = None
                self.store.publish_before_failure = published
                self.store.write_failure = DraftSessionStoreError(failure, reason=REASONS[failure])
                result = self.create.execute(CreateDraft())
                self.assert_failed(result, CATEGORIES[failure], failure.value, REASONS[failure], STEPS[failure])
                self.assertEqual(self.store.content, created_content() if published else None)

    def test_revision_not_matching_written_bytes_is_rejected(self):
        for revision in (draft_revision(b"other"), draft_revision(content()), None, Text(draft_revision(created_content()))):
            with self.subTest(revision=revision):
                store = _Creating(revision)
                handler = CreateDraftHandler(store, fingerprints(), operation_ids=lambda: OPERATION,
                                             draft_ids=lambda: FIRST_ID, clock=lambda: CREATED_AT)
                self.assert_failed(handler.execute(CreateDraft()), ErrorCategory.INVALID_SOURCE_DATA,
                                   "invalid_draft_store_result", step=NextStepCode.OPEN_VIEW)


class _Creating(_Answering):
    def __init__(self, revision):
        super().__init__(None)
        self.revision = revision

    def create_draft(self, session):
        return self.revision


class CreateDraftBaselineTests(ScenarioCase):
    def test_every_source_is_read_once_in_order_and_stored_with_the_draft(self):
        with forbid_external_effects():
            result = self.create.execute(CreateDraft())
        self.assertTrue(result.succeeded)
        self.assertEqual(self.fingerprints.calls, tuple(BaselineSource))
        self.assertEqual(self.store.read_draft().session.baseline, BASELINE)
        self.assertEqual(result.to_dict()["data"]["baseline"], {
            "sources": [{"source": item.source.value, "state": item.state.value} for item in BASELINE.fingerprints],
            "unknown_source_count": 0,
        })
        stored = json.loads(self.store.content)["baseline"]
        self.assertEqual(stored["xkeen_init"], {"state": "absent"})
        self.assertEqual(stored["xray_configs"], {"state": "present", "parts": {"01_log.json": digest(1)}})
        self.assert_private(result)

    def test_absent_sources_are_recorded_as_absent_not_as_empty(self):
        for source in BaselineSource:
            self.fingerprints.set_response(source, SourceFingerprint(source, FingerprintState.ABSENT))
        result = self.create.execute(CreateDraft())
        self.assertTrue(result.succeeded)
        self.assertEqual({item.state for item in result.data.baseline.sources}, {"absent"})
        baseline = self.store.read_draft().session.baseline
        self.assertTrue(all(item.sha256 is None and item.parts is None for item in baseline.fingerprints))

    def test_existing_draft_reads_no_sources(self):
        self.store.content = content(SECOND_ID)
        result = self.create.execute(CreateDraft())
        self.assertEqual(result.error.code, "draft_exists")
        self.assertEqual(self.fingerprints.calls, ())

    def test_unavailable_source_stops_reading_and_creates_nothing(self):
        for source, failure in (
            (BaselineSource.XRAY_CONFIGS, RouterReadFailure.UNSAFE),
            (BaselineSource.XKEEN_INIT, RouterReadFailure.CHANGED),
            (BaselineSource.XKEEN_IP_EXCLUDE, RouterReadFailure.PERMISSION_DENIED),
            (BaselineSource.KEENETIC_POLICIES, RouterReadFailure.CONNECTION_FAILED),
            (BaselineSource.KEENETIC_HOTSPOT_SETTINGS, RouterReadFailure.RCI_ERROR),
        ):
            with self.subTest(source=source.value):
                self.fingerprints = fingerprints()
                self.fingerprints.set_response(source, RouterReadError(failure))
                handler = CreateDraftHandler(self.store, self.fingerprints, operation_ids=lambda: OPERATION)
                with forbid_external_effects():
                    result = handler.execute(CreateDraft())
                self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_baseline_unavailable", failure.value,
                                   NextStepCode.CHECK_SOURCE)
                order = tuple(BaselineSource)
                self.assertEqual(self.fingerprints.calls, order[:order.index(source) + 1])
                self.assertEqual((self.store.content, self.store.create_calls), (None, ()))

    def test_other_source_exception_is_unavailable_without_its_text(self):
        self.fingerprints.set_response(BaselineSource.XKEEN_SETTINGS, OSError(2, "TEST_private-note", "/tmp/mnt/x"))
        result = self.create.execute(CreateDraft())
        self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_baseline_unavailable", None,
                           NextStepCode.CHECK_SOURCE)
        self.assertEqual(self.store.create_calls, ())

    def test_model_error_inside_source_is_invalid_source_data_with_domain_code(self):
        self.fingerprints.set_response(
            BaselineSource.KEENETIC_POLICIES, SourceBaselineError(SourceBaselineErrorCode.NATIVE),
        )
        result = self.create.execute(CreateDraft())
        self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_baseline_source",
                           "invalid_native_document", NextStepCode.INSPECT_SOURCE_DATA)
        self.assertEqual(self.store.create_calls, ())

    def test_responses_outside_the_port_contract_are_rejected(self):
        source = BaselineSource.XKEEN_SETTINGS
        valid = BASELINE.fingerprint(source)
        upper = SourceFingerprint(source, FingerprintState.PRESENT, sha256=digest(2))
        object.__setattr__(upper, "sha256", digest(10).upper())
        plain_state = SourceFingerprint(source, FingerprintState.ABSENT)
        object.__setattr__(plain_state, "state", "absent")
        text_digest = SourceFingerprint(source, FingerprintState.PRESENT, sha256=digest(2))
        object.__setattr__(text_digest, "sha256", Text(digest(2)))
        for answer, reason in (
            (None, None), (valid.to_diagnostic(), None), (BASELINE.fingerprint(BaselineSource.XKEEN_INIT), None),
            (upper, "invalid_baseline_digest"), (plain_state, "invalid_baseline_state"),
            (text_digest, "invalid_baseline_digest"),
        ):
            with self.subTest(answer=repr(answer)):
                self.fingerprints.set_response(source, answer)
                result = self.create.execute(CreateDraft())
                self.assert_failed(result, ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_baseline_source", reason,
                                   NextStepCode.INSPECT_SOURCE_DATA)
                self.assertEqual(self.store.create_calls, ())

    def test_unconfigured_source_is_a_test_setup_error_not_a_failure(self):
        empty = InMemorySourceFingerprints()
        handler = CreateDraftHandler(self.store, empty, operation_ids=lambda: OPERATION)
        with self.assertRaises(AdapterSetupError):
            handler.execute(CreateDraft())
        self.assertEqual(self.store.create_calls, ())

    def test_draft_without_baseline_section_is_shown_without_sources(self):
        self.store.content = content()
        data = self.inspect.execute(InspectDraft()).to_dict()["data"]
        self.assertIsNone(data["draft"]["baseline"])


class DiscardDraftTests(ScenarioCase):
    def test_discard_removes_matching_draft_only(self):
        self.store.content = content()
        revision = draft_revision(content())
        with forbid_external_effects():
            result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
        self.assertEqual(result.data, DraftDiscardView("discarded", FIRST_ID))
        self.assertEqual(result.to_dict()["data"], {"outcome": "discarded", "draft_id": FIRST_ID})
        self.assertEqual((self.store.content, self.store.remove_calls), (None, (revision,)))
        self.assert_private(result)

    def test_repeated_discard_confirms_absence_without_removal(self):
        self.store.content = content()
        self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
        self.assertEqual(self.store.confirm_calls, 0)
        with forbid_external_effects():
            result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
        self.assertEqual(result.data, DraftDiscardView("already_absent", FIRST_ID))
        self.assertEqual((len(self.store.remove_calls), self.store.confirm_calls), (1, 1))
        self.assert_private(result)

    def test_repeat_after_unconfirmed_removal_is_not_success_until_confirmed(self):
        self.store.content = content()
        self.store.publish_before_failure = True
        self.store.write_failure = DraftSessionStoreError(Failure.WRITE_UNCONFIRMED, reason=Reason.IO_ERROR.value)
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
                self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_write_unconfirmed", "io_error",
                                   NextStepCode.OPEN_VIEW)
                self.assertIsNone(self.store.content)
        self.assertEqual((len(self.store.remove_calls), self.store.confirm_calls), (1, 1))
        self.store.write_failure = None
        result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
        self.assertEqual(result.data, DraftDiscardView("already_absent", FIRST_ID))
        self.assertEqual(self.store.confirm_calls, 2)

    def test_absence_confirmation_failures_are_not_success(self):
        for failure in (Failure.BUSY, Failure.UNAVAILABLE, Failure.UNSAFE, Failure.WRITE_UNCONFIRMED):
            with self.subTest(failure=failure.value):
                self.store.write_failure = DraftSessionStoreError(failure, reason=REASONS[failure])
                result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
                self.assert_failed(result, CATEGORIES[failure], failure.value, REASONS[failure], STEPS[failure])
        self.assertEqual(self.store.remove_calls, ())

    def test_draft_appearing_before_confirmation_is_a_conflict_without_removal(self):
        def appear():
            self.store.content = content(SECOND_ID)
        self.store.before_revision_check = appear
        with forbid_external_effects():
            result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
        self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_revision_conflict", step=NextStepCode.OPEN_VIEW)
        self.assertEqual((self.store.content, self.store.remove_calls), (content(SECOND_ID), ()))

    def test_other_draft_is_not_removed(self):
        self.store.content = content(SECOND_ID)
        with forbid_external_effects():
            result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
        self.assert_failed(result, ErrorCategory.UNSUPPORTED, "draft_mismatch", step=NextStepCode.OPEN_VIEW)
        self.assertEqual((self.store.content, self.store.remove_calls), (content(SECOND_ID), ()))

    def test_invalid_draft_id_is_an_invalid_command_without_reading(self):
        for value in (FIRST_ID.upper(), Text(FIRST_ID), "", None, 1):
            with self.subTest(value=value):
                result = self.discard.execute(DiscardDraft(draft_id=value))
                self.assert_failed(result, ErrorCategory.INVALID_REQUEST, "invalid_command")
        self.assert_failed(self.discard.execute(object()), ErrorCategory.INVALID_REQUEST, "invalid_command")
        result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID, contract_version=CONTRACT_VERSION + 1))
        self.assert_failed(result, ErrorCategory.INVALID_REQUEST, "unsupported_contract_version",
                           step=NextStepCode.UPDATE_INTERFACE)
        self.assertEqual(self.store.read_calls, 0)

    def test_damaged_file_is_not_removed(self):
        self.store.content = b"{"
        self.assert_failed(self.discard.execute(DiscardDraft(draft_id=FIRST_ID)), ErrorCategory.INVALID_SOURCE_DATA,
                           "invalid_stored_draft", "invalid_draft_json", NextStepCode.PRESERVE_FILE)
        self.assertEqual((self.store.content, self.store.remove_calls), (b"{", ()))

    def test_change_after_read_is_a_conflict_without_removal(self):
        self.store.content = content()
        changed = content(note="TEST_private-note")

        def change():
            self.store.content = changed
        self.store.before_revision_check = change
        with forbid_external_effects():
            result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
        self.assert_failed(result, ErrorCategory.SOURCE_FAILED, "draft_revision_conflict", step=NextStepCode.OPEN_VIEW)
        self.assertEqual(self.store.content, changed)

    def test_remove_failures_are_not_success(self):
        for failure, removed in ((Failure.WRITE_FAILED, False), (Failure.BUSY, False), (Failure.WRITE_UNCONFIRMED, True)):
            with self.subTest(failure=failure.value):
                self.store.content = content()
                self.store.publish_before_failure = removed
                self.store.write_failure = DraftSessionStoreError(failure, reason=REASONS[failure])
                result = self.discard.execute(DiscardDraft(draft_id=FIRST_ID))
                self.assert_failed(result, CATEGORIES[failure], failure.value, REASONS[failure], STEPS[failure])
                self.assertEqual(self.store.content, None if removed else content())

    def test_unexpected_remove_answer_is_rejected(self):
        class Removing(_Answering):
            def remove_draft(self, expected_revision):
                return "removed"
        stored = StoredDraftSession(session(), draft_revision(content()))
        handler = DiscardDraftHandler(Removing(stored), operation_ids=lambda: OPERATION)
        self.assert_failed(handler.execute(DiscardDraft(draft_id=FIRST_ID)), ErrorCategory.INVALID_SOURCE_DATA,
                           "invalid_draft_store_result", step=NextStepCode.OPEN_VIEW)

        class Confirming(_Answering):
            def confirm_draft_absent(self):
                return "confirmed"
        handler = DiscardDraftHandler(Confirming(None), operation_ids=lambda: OPERATION)
        self.assert_failed(handler.execute(DiscardDraft(draft_id=FIRST_ID)), ErrorCategory.INVALID_SOURCE_DATA,
                           "invalid_draft_store_result", step=NextStepCode.OPEN_VIEW)


class InMemoryDoubleTests(unittest.TestCase):
    def test_double_follows_file_store_semantics(self):
        store = InMemoryDraftSessionStore()
        revision = store.create_draft(session())
        self.assertEqual(revision, draft_revision(content()))
        with self.assertRaises(DraftSessionStoreError) as caught:
            store.create_draft(session(SECOND_ID))
        self.assertIs(caught.exception.failure, Failure.CONFLICT)
        self.assertIsNone(caught.exception.__context__)
        with self.assertRaises(DraftSessionStoreError) as caught:
            store.remove_draft(draft_revision(b"other"))
        self.assertIs(caught.exception.failure, Failure.CONFLICT)
        with self.assertRaises(DraftSessionStoreError) as caught:
            store.confirm_draft_absent()
        self.assertIs(caught.exception.failure, Failure.CONFLICT)
        store.remove_draft(revision)
        self.assertIsNone(store.read_draft())
        self.assertIsNone(store.confirm_draft_absent())
        store.content = b"{"
        with self.assertRaises(DraftSessionStoreError) as caught:
            store.confirm_draft_absent()
        self.assertIs(caught.exception.failure, Failure.CONFLICT)
        self.assertEqual((store.changes, store.confirm_calls), (2, 3))
        self.assertNotIn(FIRST_ID, repr(store))
        with self.assertRaises(AdapterSetupError):
            store.content = "text"


class FileStoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-draft-scenario-")))
        self.addCleanup(shutil.rmtree, self.root)
        self.directory = self.root / "data" / "draft"
        self.directory.parent.mkdir()
        self.store = DraftSessionFiles(str(self.directory))
        self.metadata_directory = self.root / "data" / "keenvpn"
        ManagerMetadataFiles(str(self.metadata_directory)).write_metadata(ManagerMetadata(), None)

    def snapshot(self) -> dict[str, bytes | None]:
        return {
            str(path.relative_to(self.root)): None if path.is_dir() else path.read_bytes()
            for path in sorted(self.root.rglob("*"))
        }

    def test_create_inspect_discard_cycle_touches_only_the_draft_file(self):
        before = self.snapshot()
        create = CreateDraftHandler(self.store, fingerprints(), operation_ids=lambda: OPERATION,
                                    draft_ids=lambda: FIRST_ID, clock=lambda: CREATED_AT)
        inspect = InspectDraftHandler(self.store, operation_ids=lambda: OPERATION)
        discard = DiscardDraftHandler(self.store, operation_ids=lambda: OPERATION)
        self.assertEqual(inspect.execute(InspectDraft()).data, DraftStatusView(False, None))
        self.assertFalse(self.directory.exists())

        created = create.execute(CreateDraft())
        self.assertEqual(created.data, DraftView(FIRST_ID, "2026-11-01T02:14:16Z", 0, BASELINE_VIEW))
        self.assertEqual((self.directory / DRAFT_FILE_NAME).read_bytes(), created_content())
        self.assertEqual(create.execute(CreateDraft()).error.code, "draft_exists")
        self.assertEqual(inspect.execute(InspectDraft()).data, DraftStatusView(True, created.data))
        self.assertEqual(discard.execute(DiscardDraft(draft_id=SECOND_ID)).error.code, "draft_mismatch")

        self.assertEqual(discard.execute(DiscardDraft(draft_id=FIRST_ID)).data.outcome, "discarded")
        self.assertEqual(discard.execute(DiscardDraft(draft_id=FIRST_ID)).data.outcome, "already_absent")
        after = self.snapshot()
        # Остался только пустой собственный каталог черновика; метаданные менеджера не тронуты.
        self.assertEqual(after, {**before, "data/draft": None})
        self.assertEqual(os.listdir(self.directory), [])
        self.assertIn(f"data/keenvpn/{METADATA_FILE_NAME}", after)

    def test_repeated_discard_after_unconfirmed_removal_syncs_the_directory(self):
        CreateDraftHandler(self.store, fingerprints(), operation_ids=lambda: OPERATION, draft_ids=lambda: FIRST_ID,
                           clock=lambda: CREATED_AT).execute(CreateDraft())
        discard = DiscardDraftHandler(self.store, operation_ids=lambda: OPERATION)
        original = os.fsync
        synced = []

        def failing_directory_fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                synced.append(descriptor)
                raise OSError(errno.EIO, "test")
            return original(descriptor)

        with patch.object(os, "fsync", failing_directory_fsync):
            for attempt in range(2):
                with self.subTest(attempt=attempt):
                    result = discard.execute(DiscardDraft(draft_id=FIRST_ID))
                    self.assertEqual((result.error.code, result.error.reason), ("draft_write_unconfirmed", "io_error"))
        self.assertEqual(len(synced), 2)
        self.assertFalse((self.directory / DRAFT_FILE_NAME).exists())
        self.assertEqual(discard.execute(DiscardDraft(draft_id=FIRST_ID)).data.outcome, "already_absent")

    def test_damaged_file_on_disk_is_preserved_by_all_scenarios(self):
        self.directory.mkdir(mode=0o700)
        damaged = self.directory / DRAFT_FILE_NAME
        damaged.write_bytes(b'{"format": "keenvpn-draft-session", "TEST_secret-extra": ')
        damaged.chmod(0o600)
        for handler, command in (
            (InspectDraftHandler(self.store, operation_ids=lambda: OPERATION), InspectDraft()),
            (CreateDraftHandler(self.store, fingerprints(), operation_ids=lambda: OPERATION), CreateDraft()),
            (DiscardDraftHandler(self.store, operation_ids=lambda: OPERATION), DiscardDraft(draft_id=FIRST_ID)),
        ):
            with self.subTest(command=command.name):
                result = handler.execute(command)
                self.assertEqual((result.error.code, result.error.reason), ("invalid_stored_draft", "invalid_draft_json"))
                self.assertEqual(result.error.next_step.code, NextStepCode.PRESERVE_FILE)
                self.assertNotIn("TEST_", json.dumps(result.to_dict(), ensure_ascii=False))
                self.assertNotIn(str(self.root), json.dumps(result.to_dict(), ensure_ascii=False))
        self.assertEqual(damaged.read_bytes(), b'{"format": "keenvpn-draft-session", "TEST_secret-extra": ')


if __name__ == "__main__":
    unittest.main()
