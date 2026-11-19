"""Выход и подтверждаемая отмена из раздела черновика на локальных хранилищах."""

from dataclasses import replace
from datetime import datetime, timezone
import io
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.application.contract import NEXT_STEP_MESSAGES, ErrorCategory, ErrorDetail, NextStepCode
from keenvpn.application.draft_session import draft_revision_token
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure
from keenvpn.domain.draft_session import DraftSession, draft_revision, encode_draft_session
from keenvpn.domain.manager_metadata import UnknownFields
from keenvpn.interfaces.cli.composition import MenuSources, assemble_main_menu
from keenvpn.interfaces.cli.entrypoints import _run
from keenvpn.interfaces.cli.menu import REASON_MESSAGES, UnavailableReason
from keenvpn.interfaces.cli.terminal import CONFIRMATION_HINT, INPUT_ENDED, LEAVE_LABEL
from tests.support.in_memory import InMemoryDraftSessionStore


DRAFT_ID = "0000abcd-0000-4000-8000-00000000000d"
OTHER_ID = "0000abcd-0000-4000-8000-00000000000e"
SESSION = DraftSession(
    DRAFT_ID, datetime(2026, 11, 2, 7, 15, tzinfo=timezone.utc),
    UnknownFields({"TEST_private_key": "TEST_private_value"}),
)
CONTENT = encode_draft_session(SESSION)
REPLACEMENT = replace(SESSION, draft_id=OTHER_ID)
NEW_REVISION = replace(SESSION, created_at=SESSION.created_at.replace(minute=16))
QUESTION = "Удалить черновик, созданный 2026-11-02 07:15:00 UTC?"
DISCARDED = "Черновик отменён. Настройки не изменились."
SAVED = "При выходе он сохранится без изменений"
OPEN_VIEW = NEXT_STEP_MESSAGES[NextStepCode.OPEN_VIEW]


class ChangingAnswer(io.StringIO):
    """Имитирует другую операцию после показа вопроса, перед чтением подтверждения."""

    def __init__(self, change, on_answer):
        super().__init__("7\n5\n2\n4\n2\n")
        self.change = change
        self.on_answer = on_answer
        self.reads = 0

    def readline(self, size=-1, /):
        self.reads += 1
        if self.reads == 3:
            self.on_answer()
            self.change()
        return super().readline(size)


class DraftMenuActionsTests(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryDraftSessionStore(CONTENT)
        self.stdout = io.StringIO()

    def flow(self, choices, sources=None, *, private=()):
        self.stdout = io.StringIO()
        stderr = io.StringIO()
        if sources is None:
            sources = MenuSources(draft_discard=self.store)
        stdin = io.StringIO(choices) if isinstance(choices, str) else choices
        code = _run(lambda: assemble_main_menu(sources), stdin, self.stdout, stderr)
        self.assertEqual((code, stderr.getvalue()), (0, ""))
        output = self.stdout.getvalue()
        for marker in (DRAFT_ID, OTHER_ID, "TEST_", *private):
            self.assertNotIn(marker, output)
        for session in (SESSION, REPLACEMENT, NEW_REVISION):
            revision = draft_revision(encode_draft_session(session))
            self.assertNotIn(revision, output)
            self.assertNotIn(draft_revision_token(revision), output)
        return output

    def assert_no_mutation(self):
        self.assertEqual(self.store.content, CONTENT)
        self.assertEqual((self.store.changes, self.store.remove_calls, self.store.confirm_calls), (0, (), 0))
        self.assertEqual((self.store.create_calls, self.store.replace_calls), ((), []))

    def assert_conflict(self, output, code):
        self.assertIn(code, output)
        self.assertIn("Конфликт: черновик", output)
        self.assertIn("Следующий шаг: " + OPEN_VIEW, output)
        self.assertNotIn(DISCARDED, output)

    def test_save_and_exit_matches_root_and_decline_keeps_section_open(self):
        root = self.flow("0\n2\n")
        nested = self.flow("7\n4\n\n4\n1\n4\n2\n")
        root_question = root[root.index("Черновик изменений создан"):]
        self.assertEqual(nested.count(root_question), 3)
        self.assertEqual(nested.count("Главное меню KeenVPN / Черновик и применение\n"), 3)
        self.assertIn(SAVED, nested)
        self.assert_no_mutation()

    def test_save_and_exit_without_draft_or_store(self):
        self.store.content = None
        empty = self.flow("7\n4\n")
        disconnected = self.flow("7\n4\n", MenuSources())
        self.assertNotIn(LEAVE_LABEL, empty)
        self.assertNotIn(LEAVE_LABEL, disconnected)
        self.assertIn("Черновик не проверялся: хранилище черновика не подключено.", disconnected)
        self.assertEqual(self.store.changes, 0)

    def test_discard_requires_confirmation_and_returns_to_section(self):
        output = self.flow("7\n5\nTEST_wrong_answer\n2\n5\n4\n")
        self.assertEqual(output.count(QUESTION), 2)
        self.assertIn(CONFIRMATION_HINT, output)
        self.assertIn(DISCARDED, output)
        self.assertIn("Сохранённого черновика нет.", output)
        self.assertNotIn(LEAVE_LABEL, output)
        self.assertIsNone(self.store.content)
        self.assertEqual(self.store.remove_calls, (draft_revision(CONTENT),))
        self.assertEqual(self.store.changes, 1)

    def test_decline_empty_answer_and_eof_keep_session(self):
        output = self.flow("7\n5\n1\n5\n \n5\n")
        self.assertEqual(output.count(QUESTION), 3)
        self.assertIn(INPUT_ENDED, output)
        self.assertNotIn(DISCARDED, output)
        self.assert_no_mutation()

    def test_zero_leaves_discard_question_before_next_menu_choice(self):
        output = self.flow("7\n5\n0\n2\n4\n2\n")
        self.assertIn(REASON_MESSAGES[UnavailableReason.SOURCE_NOT_CONNECTED], output)
        self.assertNotIn(DISCARDED, output)
        self.assert_no_mutation()

    def test_replaced_session_and_stale_revision_are_conflicts(self):
        for updated, code in ((REPLACEMENT, "draft_mismatch"), (NEW_REVISION, "draft_revision_conflict")):
            with self.subTest(code=code):
                self.store.content = CONTENT
                new_content = encode_draft_session(updated)

                def change():
                    self.store.content = new_content

                answer = ChangingAnswer(change, lambda: self.assertIn(QUESTION, self.stdout.getvalue()))
                self.assert_conflict(self.flow(answer), code)
                self.assertEqual(self.store.content, new_content)
                self.assertEqual(self.store.remove_calls, ())

    def test_concurrent_change_at_removal_keeps_updated_session(self):
        changed = encode_draft_session(NEW_REVISION)

        def change():
            self.store.content = changed

        self.store.before_revision_check = change
        self.assert_conflict(self.flow("7\n5\n2\n4\n2\n"), "draft_revision_conflict")
        self.assertEqual(self.store.remove_calls, (draft_revision(CONTENT),))
        self.assertEqual(self.store.content, changed)

    def test_discard_unavailable_without_explicit_capability(self):
        storage_error = ErrorDetail(ErrorCategory.SOURCE_FAILED, "data_placement_unknown", "DATA неизвестна.")
        for sources, reason in (
            (MenuSources(), UnavailableReason.DRAFT_STORE_NOT_CONNECTED),
            (MenuSources(drafts=self.store), UnavailableReason.DRAFT_DISCARD_NOT_CONNECTED),
            (MenuSources(storage_error=storage_error), UnavailableReason.STORAGE_NOT_CONFIRMED),
        ):
            with self.subTest(reason=reason):
                output = self.flow("7\n5\n", sources)
                self.assertIn("5. Отменить черновик [недоступно]", output)
                self.assertIn(REASON_MESSAGES[reason], output)
                self.assertNotIn(QUESTION, output)
                self.assert_no_mutation()

    def test_unavailable_read_and_failed_remove_have_safe_output(self):
        self.store.read_failure = OSError("/private/TEST_private_value")
        output = self.flow("7\n5\n4\n2\n")
        self.assertIn("draft_store_failed", output)
        self.assertNotIn(QUESTION, output)
        self.assert_no_mutation()

        self.store.read_failure = None
        self.store.write_failure = DraftSessionStoreError(DraftStoreFailure.WRITE_FAILED, reason="TEST_private_value")
        output = self.flow("7\n5\n2\n4\n2\n")
        self.assertIn("draft_write_failed", output)
        self.assertIn("Следующий шаг:", output)
        self.assertNotIn(DISCARDED, output)
        self.assertEqual(self.store.content, CONTENT)
        self.assertEqual(self.store.changes, 0)

    def test_file_store_preserves_bytes_on_exit_and_decline_then_removes_only_session(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            store = DraftSessionFiles(str(root / "drafts"))
            session_file = root / "drafts" / DRAFT_FILE_NAME
            unrelated = root / "active.json"
            unrelated.write_bytes(b"TEST_active_configuration")
            revision = store.create_draft(SESSION)
            before = (session_file.read_bytes(), session_file.stat().st_ino)
            sources = MenuSources(draft_discard=store)

            self.flow("7\n5\n\n4\n1\n4\n2\n", sources, private=(str(root),))
            self.assertEqual((session_file.read_bytes(), session_file.stat().st_ino), before)

            answer = ChangingAnswer(
                lambda: store.replace_draft(NEW_REVISION, revision),
                lambda: self.assertIn(QUESTION, self.stdout.getvalue()),
            )
            self.assert_conflict(self.flow(answer, sources, private=(str(root),)), "draft_revision_conflict")
            self.assertEqual(session_file.read_bytes(), encode_draft_session(NEW_REVISION))

            output = self.flow("7\n5\n2\n4\n", sources, private=(str(root),))
            self.assertIn(DISCARDED, output)
            self.assertFalse(session_file.exists())
            self.assertEqual(unrelated.read_bytes(), b"TEST_active_configuration")

    def test_file_store_preserves_corrupt_draft_without_prompting_to_delete(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            store = DraftSessionFiles(str(root / "drafts"))
            store.create_draft(SESSION)
            session_file = root / "drafts" / DRAFT_FILE_NAME
            content = b'{"TEST_private_value"'
            session_file.write_bytes(content)
            output = self.flow("7\n5\n4\n2\n", MenuSources(draft_discard=store), private=(str(root),))
            self.assertIn("invalid_stored_draft", output)
            self.assertIn(LEAVE_LABEL, output)
            self.assertNotIn(QUESTION, output)
            self.assertEqual(session_file.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
