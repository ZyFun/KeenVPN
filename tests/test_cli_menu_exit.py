"""Предупреждение о неприменённом черновике при выходе из `vpn-menu` и `vpn-setup`.

Меню собирается с хранилищем черновика в памяти и выполняется на внедрённых
потоках со сценарным вводом. Роутер, файлы, сеть и процессы не используются.
"""

from datetime import datetime, timezone
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import ErrorCategory, ErrorDetail, Result, failed, succeeded
from keenvpn.application.draft_session import draft_revision_token
from keenvpn.application.menu_exit import MenuExitDecision, MenuExitReason, MenuExitView
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure, StoreReason
from keenvpn.domain.draft_session import DraftSession, draft_revision, encode_draft_session
from keenvpn.domain.manager_metadata import UnknownFields
from keenvpn.interfaces.cli.composition import MenuSources, assemble_main_menu, assemble_setup_menu
from keenvpn.interfaces.cli.entrypoints import (
    EXIT_INTERRUPTED, INTERRUPTED_MESSAGE, _run, vpn_menu, vpn_setup,
)
from keenvpn.interfaces.cli.menu import ExitNotice, Menu, MenuError, MenuItem, MenuNavigator
from keenvpn.interfaces.cli.presenters import (
    DRAFT_KEPT, DRAFT_KEPT_IF_PRESENT, DRAFT_NOT_CHECKED, DRAFT_NOT_CONNECTED, HIDDEN, created_at, present_menu_exit,
)
from keenvpn.interfaces.cli.terminal import (
    EXIT_DEFAULT, EXIT_HINT, INPUT_ENDED, LEAVE_LABEL, LINE_TOO_LONG, MAX_INPUT_LENGTH, STAY_LABEL, run_menu,
)
from keenvpn.interfaces.cli.tree import MAIN_MENU_TITLE, SETUP_MENU_TITLE
from tests.support.in_memory import InMemoryDraftSessionStore
from tests.support.isolation import forbid_external_effects


DRAFT_ID = "0000abcd-0000-4000-8000-00000000000d"
CREATED_AT = datetime(2026, 11, 2, 7, 15, 0, tzinfo=timezone.utc)
OPERATION = "op-1"
PRIVATE_MARKERS = ("TEST_secret-extra", "TEST_private-note", "/tmp/mnt", DRAFT_ID, OPERATION)
DRAFT_LINE = "Черновик изменений создан 2026-11-02 07:15:00 UTC и не применён."
QUESTION = [DRAFT_LINE, DRAFT_KEPT, f"  1. {STAY_LABEL}", f"  2. {LEAVE_LABEL}", EXIT_DEFAULT]
ROOT_LINE = "  1. Состояние и быстрые действия"


def content() -> bytes:
    session = DraftSession(DRAFT_ID, CREATED_AT, UnknownFields({"TEST_secret-extra": "TEST_private-note"}))
    return encode_draft_session(session)


class Interrupting(io.StringIO):
    """Ввод, который после заданных строк прерывается, как при Ctrl+C."""

    def __init__(self, lines: str, after: int) -> None:
        super().__init__(lines)
        self.left = after

    def readline(self, size=-1, /):
        if self.left == 0:
            raise KeyboardInterrupt
        self.left -= 1
        return super().readline(size)


class MenuExitFlowTests(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryDraftSessionStore(content())

    def flow(self, text, *, setup=False, store=...):
        store = self.store if store is ... else store
        sources = MenuSources(drafts=store)
        assemble = assemble_setup_menu if setup else assemble_main_menu
        assembly = assemble(sources, operation_ids=lambda: OPERATION)
        stdout = io.StringIO()
        before = None if store is None else store.content
        with forbid_external_effects():
            code = run_menu(
                MenuNavigator(assembly.menu), assembly.actions, io.StringIO(text), stdout, assembly.header,
                assembly.exit_check,
            )
        output = stdout.getvalue()
        self.assertEqual(code, 0)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, output)
        if store is not None:
            self.assertNotIn(draft_revision_token(draft_revision(content())), output)
            # Выход, отказ от выхода и вопрос ничего не меняют в хранилище.
            self.assertEqual(store.content, before)
            self.assertEqual(
                (store.changes, store.create_calls, store.remove_calls, store.confirm_calls), (0, (), (), 0),
            )
        return output

    def test_exit_without_draft_asks_nothing(self):
        store = InMemoryDraftSessionStore()
        output = self.flow("0\n", store=store)
        self.assertNotIn(STAY_LABEL, output)
        self.assertTrue(output.endswith("  0. Выход\n> "))
        self.assertIn("  Черновик: нет\n", output)
        # Шапка при входе в корень и решение о выходе — по одному чтению.
        self.assertEqual(store.read_calls, 2)

    def test_exit_with_draft_asks_and_leaves_on_two(self):
        output = self.flow("0\n2\n")
        self.assertIn("  Черновик: есть неприменённый\n", output)
        self.assertTrue(output.endswith("  0. Выход\n> \n" + "\n".join(QUESTION) + "\n> "))
        self.assertEqual(self.store.read_calls, 2)

    def test_stay_returns_to_the_root_with_the_same_header(self):
        for answer in ("1", "", "  "):
            with self.subTest(answer=answer):
                store = InMemoryDraftSessionStore(content())
                output = self.flow(f"0\n{answer}\n0\n2\n", store=store)
                self.assertEqual(output.count("\n".join(QUESTION)), 2)
                self.assertEqual(output.count(MAIN_MENU_TITLE + "\n"), 2)
                self.assertEqual(output.count("  Черновик: есть неприменённый\n"), 2)
                # Корень не закрывался: шапка не перечитана, каждый выход читает хранилище заново.
                self.assertEqual(store.read_calls, 3)

    def test_wrong_answer_repeats_the_question(self):
        for answer in ("0", "3", "01", "да", "x" * 10):
            with self.subTest(answer=answer):
                output = self.flow(f"0\n{answer}\n2\n", store=InMemoryDraftSessionStore(content()))
                self.assertIn("\n".join([EXIT_HINT, "", *QUESTION]), output)
                self.assertNotIn(answer + "\n", output.replace("  0. Выход\n", "").replace(ROOT_LINE, ""))

    def test_too_long_answer_is_discarded_and_the_question_repeats(self):
        output = self.flow("0\n" + "2" * (MAX_INPUT_LENGTH + 5) + "\n2\n")
        self.assertIn("\n".join([LINE_TOO_LONG, "", *QUESTION]), output)

    def test_end_of_input_during_the_question_leaves_with_the_draft_kept(self):
        output = self.flow("0\n")
        self.assertTrue(output.endswith("\n".join(QUESTION) + "\n> \n" + INPUT_ENDED + "\n"))

    def test_end_of_input_in_the_menu_warns_without_a_question(self):
        output = self.flow("")
        self.assertTrue(output.endswith("> \n" + "\n".join([DRAFT_LINE, DRAFT_KEPT, INPUT_ENDED]) + "\n"))
        self.assertNotIn(STAY_LABEL, output)
        empty = InMemoryDraftSessionStore()
        self.assertTrue(self.flow("", store=empty).endswith("  0. Выход\n> \n"))

    def test_back_in_a_submenu_is_not_an_exit(self):
        output = self.flow("1\n0\n0\n2\n")
        self.assertEqual(output.count("\n".join(QUESTION)), 1)
        # Две шапки при входе в корень и одно решение о выходе.
        self.assertEqual(self.store.read_calls, 3)

    def test_store_failure_asks_with_the_error_and_without_its_text(self):
        store = InMemoryDraftSessionStore(content())
        store.read_failure = DraftSessionStoreError(DraftStoreFailure.UNAVAILABLE, reason=StoreReason.IO_ERROR)
        output = self.flow("0\n2\n", store=store)
        self.assertIn("\n".join([
            DRAFT_NOT_CHECKED,
            "Отказ: source_failed / draft_store_unavailable",
            "Уточнение: io_error",
            "Причина: Хранилище черновика недоступно.",
        ]), output)
        self.assertIn(DRAFT_KEPT_IF_PRESENT + f"\n  1. {STAY_LABEL}\n", output)
        self.assertIn("  Черновик: не проверено\n", output)
        store = InMemoryDraftSessionStore(content())
        store.read_failure = OSError("/tmp/mnt/TEST_private-note")
        output = self.flow("0\n2\n", store=store)
        self.assertIn("Отказ: source_failed / draft_store_failed", output)

    def test_corrupted_file_asks_and_is_preserved(self):
        damaged = b'{"format": "keenvpn-draft-session", TEST_private-note'
        store = InMemoryDraftSessionStore(damaged)
        output = self.flow("0\n2\n", store=store)
        self.assertIn("Отказ: invalid_source_data / invalid_stored_draft", output)
        self.assertIn(f"  2. {LEAVE_LABEL}\n", output)

    def test_unconnected_store_warns_on_exit_without_a_question(self):
        output = self.flow("0\n", store=None)
        self.assertTrue(output.endswith("  0. Выход\n> " + DRAFT_NOT_CONNECTED + "\n"))
        self.assertIn("  Черновик: не проверено\n", output)
        output = self.flow("", store=None)
        self.assertTrue(output.endswith("> \n" + DRAFT_NOT_CONNECTED + "\n"))

    def test_setup_menu_asks_the_same_question(self):
        output = self.flow("0\n2\n", setup=True)
        self.assertTrue(output.startswith(SETUP_MENU_TITLE + "\n"))
        self.assertTrue(output.endswith("\n".join(QUESTION) + "\n> "))
        # У мастера шапки нет: хранилище читает только решение о выходе.
        self.assertEqual(self.store.read_calls, 1)


class EntrypointExitTests(unittest.TestCase):
    def run_interrupted(self, text, after):
        store = InMemoryDraftSessionStore(content())
        stdout, stderr = io.StringIO(), io.StringIO()
        with forbid_external_effects():
            code = _run(
                lambda: assemble_main_menu(MenuSources(drafts=store), operation_ids=lambda: OPERATION),
                Interrupting(text, after), stdout, stderr,
            )
        self.assertEqual((code, stderr.getvalue()), (EXIT_INTERRUPTED, INTERRUPTED_MESSAGE + "\n"))
        self.assertEqual((store.content, store.changes), (content(), 0))
        return store, stdout.getvalue()

    def test_interrupt_during_the_question_keeps_the_draft(self):
        store, output = self.run_interrupted("0\n", 1)
        self.assertTrue(output.endswith(f"  2. {LEAVE_LABEL}\n{EXIT_DEFAULT}\n> "))
        self.assertEqual(store.read_calls, 2)

    def test_interrupt_in_the_menu_does_not_read_the_store(self):
        store, output = self.run_interrupted("", 0)
        self.assertNotIn(STAY_LABEL, output)
        # Хранилище прочитала только шапка корня.
        self.assertEqual(store.read_calls, 1)

    def test_launch_without_connected_storage_reports_that_draft_was_not_checked(self):
        for entry in (vpn_menu, vpn_setup):
            for text in ("0\n", ""):
                with self.subTest(entry=entry.__name__, text=text):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch("keenvpn.interfaces.cli.entrypoints.router_sources", return_value=MenuSources()), \
                            forbid_external_effects():
                        code = entry([], io.StringIO(text), stdout, stderr)
                    self.assertEqual((code, stderr.getvalue()), (0, ""))
                    self.assertTrue(stdout.getvalue().endswith(DRAFT_NOT_CONNECTED + "\n"))
                    self.assertNotIn(STAY_LABEL, stdout.getvalue())


class ExitPresentationTests(unittest.TestCase):
    def test_notice_follows_the_scenario_decision(self):
        error = ErrorDetail(ErrorCategory.SOURCE_FAILED, "draft_store_busy", "Черновик изменяет другая операция.")
        cases = (
            (MenuExitView(MenuExitDecision.EXIT, MenuExitReason.NO_DRAFT), ExitNotice((), False)),
            (
                MenuExitView(MenuExitDecision.EXIT, MenuExitReason.DRAFT_STORE_NOT_CONNECTED),
                ExitNotice((DRAFT_NOT_CONNECTED,), False),
            ),
            (
                MenuExitView(MenuExitDecision.CONFIRM, MenuExitReason.DRAFT_PRESENT, "2026-11-02T07:15:00Z"),
                ExitNotice((DRAFT_LINE, DRAFT_KEPT), True),
            ),
        )
        for view, notice in cases:
            with self.subTest(reason=view.reason.value):
                self.assertEqual(present_menu_exit(succeeded(OPERATION, "inspect_menu_exit", view)), notice)
        view = MenuExitView(MenuExitDecision.CONFIRM, MenuExitReason.DRAFT_NOT_CHECKED, store_error=error)
        notice = present_menu_exit(succeeded(OPERATION, "inspect_menu_exit", view))
        self.assertTrue(notice.confirm)
        self.assertEqual((notice.lines[0], notice.lines[-1]), (DRAFT_NOT_CHECKED, DRAFT_KEPT_IF_PRESENT))
        self.assertIn("Отказ: source_failed / draft_store_busy", notice.lines)

    def test_failed_scenario_asks_instead_of_leaving_silently(self):
        error = ErrorDetail(ErrorCategory.INVALID_REQUEST, "invalid_command", "Команда не поддерживается.")
        notice = present_menu_exit(failed(OPERATION, "inspect_menu_exit", error))
        self.assertTrue(notice.confirm)
        self.assertEqual((notice.lines[0], notice.lines[-1]), (DRAFT_NOT_CHECKED, DRAFT_KEPT_IF_PRESENT))

    def test_creation_time_outside_the_format_is_hidden(self):
        self.assertEqual(created_at("2026-11-02T07:15:00Z"), "2026-11-02 07:15:00 UTC")
        for value in ("2026-11-02 07:15:00", "/tmp/mnt/TEST_private-note", None, 1, "2026-11-02T07:15:00Z\n"):
            with self.subTest(value=value):
                self.assertEqual(created_at(value), HIDDEN)

    def test_wrong_types_are_refused(self):
        with self.assertRaises(TypeError):
            present_menu_exit(MenuExitView(MenuExitDecision.EXIT, MenuExitReason.NO_DRAFT))
        with self.assertRaises(TypeError):
            present_menu_exit(succeeded(OPERATION, "inspect_menu_exit", object()))
        for lines, confirm in (([], False), (("\x1b[0m",), True), ((), 1)):
            with self.subTest(lines=lines, confirm=confirm), self.assertRaises(MenuError):
                ExitNotice(lines, confirm)

    def test_exit_check_must_return_a_notice(self):
        menu = Menu("TEST_menu", (MenuItem(1, "TEST_item", submenu=Menu("TEST_submenu", ())),))
        for text in ("0\n", ""):
            with self.subTest(text=text), self.assertRaises(MenuError):
                run_menu(MenuNavigator(menu), {}, io.StringIO(text), io.StringIO(), exit_check=lambda: ["строка"])


if __name__ == "__main__":
    unittest.main()
