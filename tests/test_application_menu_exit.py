"""Решение о выходе из меню при неприменённом черновике.

Сценарий проверяется на управляемом хранилище в памяти и с настоящим
файловым хранилищем во временном каталоге. Роутер, active configs Xray
и XKeen, сеть и процессы не используются.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory, ErrorDetail, NextStepCode
from keenvpn.application.draft_session import draft_revision_token
from keenvpn.application.menu_exit import (
    InspectMenuExit, InspectMenuExitHandler, MenuExitDecision as Decision, MenuExitReason as Reason, MenuExitView,
)
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure as Failure, StoreReason
from keenvpn.domain.draft_session import (
    DraftSession, DraftSessionErrorCode, StoredDraftSession, draft_revision, encode_draft_session,
)
from keenvpn.domain.manager_metadata import UnknownFields
from tests.support.in_memory import InMemoryDraftSessionStore
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable


DRAFT_ID = "0000abcd-0000-4000-8000-00000000000d"
CREATED_AT = datetime(2026, 11, 1, 2, 14, 16, tzinfo=timezone.utc)
OPERATION = "test-operation"
PRIVATE_MARKERS = ("TEST_secret-extra", "TEST_private-note", "/tmp/mnt", DRAFT_ID)
PRIVATE_TYPES = (DraftSession, StoredDraftSession, UnknownFields, BaseException, bytes)
STEPS = {
    Failure.UNAVAILABLE: NextStepCode.CHECK_SOURCE,
    Failure.UNSAFE: NextStepCode.PRESERVE_FILE,
    Failure.BUSY: NextStepCode.RETRY_LATER,
    Failure.CONFLICT: NextStepCode.OPEN_VIEW,
    Failure.INVALID: NextStepCode.PRESERVE_FILE,
    Failure.WRITE_FAILED: NextStepCode.CHECK_SOURCE,
    Failure.WRITE_UNCONFIRMED: NextStepCode.OPEN_VIEW,
}


def content(**extra) -> bytes:
    return encode_draft_session(DraftSession(DRAFT_ID, CREATED_AT, UnknownFields(extra or None)))


def execute(store, command=None):
    handler = InspectMenuExitHandler(store, operation_ids=lambda: OPERATION)
    return handler.execute(InspectMenuExit() if command is None else command)


class ReturningStore(InMemoryDraftSessionStore):
    """Хранилище, которое возвращает из чтения заданный объект вместо ответа по контракту."""

    def __init__(self, answer: object) -> None:
        super().__init__()
        self.answer = answer

    def read_draft(self):
        self.read_calls += 1
        return self.answer


class MenuExitScenarioTests(unittest.TestCase):
    def assert_unchanged(self, store, before):
        self.assertEqual(store.content, before)
        self.assertEqual((store.changes, store.create_calls, store.remove_calls, store.confirm_calls), (0, (), (), 0))

    def assert_private(self, result):
        text = repr(result) + repr(result.to_dict())
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        found = reachable(result)
        for kind in PRIVATE_TYPES:
            self.assertFalse(any(isinstance(item, kind) for item in found), kind.__name__)

    def test_no_draft_allows_exit_after_one_read(self):
        store = InMemoryDraftSessionStore()
        with forbid_external_effects():
            result = execute(store)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.to_dict()["command"], "inspect_menu_exit")
        self.assertEqual(result.data.to_dict(), {
            "decision": "exit", "reason": "no_draft", "draft_created_at": None, "store_error": None,
        })
        self.assertIs(result.data.decision, Decision.EXIT)
        self.assertEqual(store.read_calls, 1)
        self.assert_unchanged(store, None)

    def test_present_draft_asks_with_creation_time_only(self):
        before = content(**{"TEST_secret-extra": "TEST_private-note"})
        store = InMemoryDraftSessionStore(before)
        with forbid_external_effects():
            result = execute(store)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.to_dict(), {
            "decision": "confirm", "reason": "draft_present", "draft_created_at": "2026-11-01T02:14:16Z",
            "store_error": None,
        })
        self.assertIs(result.data.reason, Reason.DRAFT_PRESENT)
        # Ни идентификатора, ни токена ревизии, ни ревизии файла в результате нет.
        text = repr(result.to_dict())
        self.assertNotIn(draft_revision_token(draft_revision(before)), text)
        self.assertNotIn(draft_revision(before), text)
        self.assert_private(result)
        self.assertEqual(store.read_calls, 1)
        self.assert_unchanged(store, before)

    def test_every_store_failure_asks_with_its_code_and_step(self):
        for failure in Failure:
            with self.subTest(failure=failure.value):
                before = content()
                store = InMemoryDraftSessionStore(before)
                store.read_failure = DraftSessionStoreError(failure, reason=StoreReason.IO_ERROR)
                result = execute(store)
                self.assertTrue(result.succeeded)
                view = result.data
                self.assertEqual((view.decision, view.reason, view.draft_created_at), (
                    Decision.CONFIRM, Reason.DRAFT_NOT_CHECKED, None,
                ))
                self.assertEqual(view.store_error.code, failure.value)
                self.assertEqual(view.store_error.next_step.code, STEPS[failure])
                self.assert_private(result)
                self.assert_unchanged(store, before)

    def test_unexpected_store_exception_asks_without_its_text(self):
        store = InMemoryDraftSessionStore(content())
        store.read_failure = OSError("/tmp/mnt/TEST_private-note")
        result = execute(store)
        self.assertEqual(result.data.reason, Reason.DRAFT_NOT_CHECKED)
        self.assertEqual(result.data.store_error.code, "draft_store_failed")
        self.assertIs(result.data.store_error.category, ErrorCategory.SOURCE_FAILED)
        self.assert_private(result)

    def test_corrupted_file_asks_and_is_preserved(self):
        before = b'{"format": "keenvpn-draft-session", TEST_private-note'
        store = InMemoryDraftSessionStore(before)
        result = execute(store)
        error = result.data.store_error
        self.assertEqual((result.data.decision, error.code, error.reason), (
            Decision.CONFIRM, "invalid_stored_draft", DraftSessionErrorCode.JSON.value,
        ))
        self.assertIs(error.category, ErrorCategory.INVALID_SOURCE_DATA)
        self.assertIs(error.next_step.code, NextStepCode.PRESERVE_FILE)
        self.assert_private(result)
        self.assert_unchanged(store, before)

    def test_answer_outside_the_contract_asks(self):
        stored = StoredDraftSession(DraftSession(DRAFT_ID, CREATED_AT), draft_revision(content()))
        broken = StoredDraftSession(DraftSession(DRAFT_ID, CREATED_AT), draft_revision(content()))
        object.__setattr__(broken, "revision", "TEST_private-note")
        for answer in (object(), "draft", broken):
            with self.subTest(answer=type(answer).__name__):
                result = execute(ReturningStore(answer))
                self.assertEqual(result.data.reason, Reason.DRAFT_NOT_CHECKED)
                self.assertEqual(result.data.store_error.code, "invalid_draft_store_result")
                self.assert_private(result)
        self.assertEqual(execute(ReturningStore(stored)).data.reason, Reason.DRAFT_PRESENT)

    def test_unconnected_store_allows_exit_with_its_reason(self):
        result = execute(None)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.to_dict(), {
            "decision": "exit", "reason": "draft_store_not_connected", "draft_created_at": None, "store_error": None,
        })

    def test_interruptions_pass_through(self):
        for interruption in (KeyboardInterrupt, SystemExit):
            with self.subTest(interruption=interruption.__name__):
                store = InMemoryDraftSessionStore(content())
                store.read_failure = interruption()
                with self.assertRaises(interruption):
                    execute(store)

    def test_invalid_command_and_version_are_refused_without_reading(self):
        store = InMemoryDraftSessionStore(content())
        for command, code in (
            (object(), "invalid_command"),
            (InspectMenuExit(contract_version=CONTRACT_VERSION + 1), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                result = execute(store, command)
                self.assertFalse(result.succeeded)
                self.assertEqual(result.error.code, code)
        self.assertEqual(store.read_calls, 0)

    def test_file_store_is_only_read(self):
        root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-menu-exit-")))
        self.addCleanup(shutil.rmtree, root)
        directory = root / "draft"
        files = DraftSessionFiles(str(directory))
        self.assertIs(execute(files).data.reason, Reason.NO_DRAFT)
        self.assertFalse(directory.exists())

        files.create_draft(DraftSession(DRAFT_ID, CREATED_AT))
        path = directory / DRAFT_FILE_NAME
        before = (path.read_bytes(), os.stat(path).st_mtime_ns, sorted(os.listdir(directory)))
        result = execute(files)
        self.assertEqual((result.data.reason, result.data.draft_created_at), (
            Reason.DRAFT_PRESENT, "2026-11-01T02:14:16Z",
        ))
        self.assertEqual((path.read_bytes(), os.stat(path).st_mtime_ns, sorted(os.listdir(directory))), before)
        self.assertNotIn(str(root), repr(result.to_dict()))

        path.write_bytes(b"{}")
        os.chmod(path, 0o600)
        self.assertEqual(execute(files).data.store_error.code, "invalid_stored_draft")
        self.assertEqual(path.read_bytes(), b"{}")


class MenuExitViewTests(unittest.TestCase):
    def test_reason_defines_decision_and_details(self):
        error = ErrorDetail(ErrorCategory.SOURCE_FAILED, "draft_store_unavailable", "Хранилище черновика недоступно.")
        valid = (
            MenuExitView(Decision.EXIT, Reason.NO_DRAFT),
            MenuExitView(Decision.EXIT, Reason.DRAFT_STORE_NOT_CONNECTED),
            MenuExitView(Decision.CONFIRM, Reason.DRAFT_PRESENT, "2026-11-01T02:14:16Z"),
            MenuExitView(Decision.CONFIRM, Reason.DRAFT_NOT_CHECKED, store_error=error),
        )
        self.assertEqual(len(valid), len(Reason))
        for args, kwargs in (
            ((Decision.CONFIRM, Reason.NO_DRAFT), {}),
            ((Decision.EXIT, Reason.DRAFT_PRESENT, "2026-11-01T02:14:16Z"), {}),
            ((Decision.CONFIRM, Reason.DRAFT_PRESENT), {}),
            ((Decision.CONFIRM, Reason.DRAFT_PRESENT, "2026-11-01T02:14:16Z"), {"store_error": error}),
            ((Decision.CONFIRM, Reason.DRAFT_NOT_CHECKED), {}),
            ((Decision.CONFIRM, Reason.DRAFT_NOT_CHECKED, "2026-11-01T02:14:16Z"), {"store_error": error}),
            ((Decision.EXIT, Reason.NO_DRAFT, "2026-11-01T02:14:16Z"), {}),
            ((Decision.EXIT, Reason.DRAFT_STORE_NOT_CONNECTED), {"store_error": error}),
            (("exit", Reason.NO_DRAFT), {}),
            ((Decision.EXIT, "no_draft"), {}),
            ((Decision.CONFIRM, Reason.DRAFT_PRESENT, 1), {}),
            ((Decision.CONFIRM, Reason.DRAFT_NOT_CHECKED), {"store_error": "draft_store_unavailable"}),
        ):
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(TypeError):
                MenuExitView(*args, **kwargs)

    def test_codes_are_stable(self):
        self.assertEqual([item.value for item in Decision], ["exit", "confirm"])
        self.assertEqual(
            [item.value for item in Reason],
            ["no_draft", "draft_present", "draft_not_checked", "draft_store_not_connected"],
        )
        self.assertEqual(InspectMenuExit.name, "inspect_menu_exit")


if __name__ == "__main__":
    unittest.main()
