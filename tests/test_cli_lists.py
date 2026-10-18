"""Списки меню: выбор по номеру, поиск, карточка, отмена, пустой и необычный ввод без терминала и внешних эффектов."""

import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.interfaces.cli import menu as menu_module
from keenvpn.interfaces.cli.composition import MenuAssembly
from keenvpn.interfaces.cli.entrypoints import EXIT_INTERRUPTED, INTERRUPTED_MESSAGE, vpn_menu
from keenvpn.interfaces.cli.menu import (
    MAX_LIST_LINE_LENGTH, SEARCH_TITLE, CardLevel, ListEntry, ListLevel, Menu, MenuAction, MenuError, MenuItem,
    MenuList, MenuNavigator, SelectionKind,
)
from keenvpn.interfaces.cli.search import SearchQuery, normalize, parse_query
from keenvpn.interfaces.cli.terminal import (
    CARD_HINT, EMPTY_LIST, HINT, LINE_TOO_LONG, LIST_HINT, LIST_USAGE, MAX_INPUT_LENGTH, MAX_SHOWN, NO_MATCHES,
    PROMPT, QUERY_HINT, read_line, run_menu,
)
from tests.support.isolation import forbid_external_effects


LABELS = (
    "rules: DomainCondition, действие DIRECT, назначение outbound direct",
    "rules: IPCondition, действие DIRECT, назначение outbound direct",
    "rules: DomainCondition, действие нет, назначение balancer vpn-group",
    "final: действие нет, назначение balancer vpn-group",
    "rules: GeoIPCondition, действие BLOCK, назначение outbound block",
)
SECRET_QUERY = "TEST_ONLY_SECRET_QUERY"


def sample_list(labels=LABELS, header=("Вводная строка списка",)) -> MenuList:
    entries = tuple(
        ListEntry(number, label, (f"Карточка {number}", "Вторая строка карточки"))
        for number, label in enumerate(labels, start=1)
    )
    return MenuList("Элементы", "Элемент", header, entries)


def numbered_list(size: int) -> MenuList:
    return sample_list(tuple(f"элемент группы {number:04d}" for number in range(1, size + 1)), ())


def sample_root() -> Menu:
    return Menu("Корень", (
        MenuItem(1, "Список", action=MenuAction("root.list")),
        MenuItem(2, "Строки", action=MenuAction("root.lines")),
    ))


def run(text: str, source=None, calls=None):
    """Выполнить цикл на строках ввода под запретом внешних эффектов; вернуть код, вывод и навигатор."""
    calls = [] if calls is None else calls
    menu_list = sample_list() if source is None else source

    def list_action():
        calls.append("list")
        return menu_list

    def lines_action():
        calls.append("lines")
        return ["Строка действия"]

    navigator = MenuNavigator(sample_root())
    stdout = io.StringIO()
    with forbid_external_effects():
        code = run_menu(
            navigator, {"root.list": list_action, "root.lines": lines_action}, io.StringIO(text), stdout,
        )
    output = stdout.getvalue()
    return code, output, navigator


class _Lines:
    """Поток, который отдаёт строки, а затем имитирует Ctrl+C; запоминает размеры запросов."""

    def __init__(self, lines):
        self.lines = list(lines)
        self.sizes = []

    def readline(self, size=-1):
        self.sizes.append(size)
        if not self.lines:
            raise KeyboardInterrupt
        return self.lines.pop(0)


class ListModelTests(unittest.TestCase):
    def test_entry_accepts_printable_label_and_card(self):
        entry = ListEntry(1, "rules: DIRECT", ("Строка",))
        self.assertEqual(entry.search_text, normalize("rules: DIRECT"))
        self.assertNotIn("search_text", repr(entry))
        self.assertEqual(ListEntry(999, "x" * MAX_LIST_LINE_LENGTH, ()).number, 999)

    def test_entry_rejects_bad_numbers_labels_and_cards(self):
        for number in (0, 1000, -1, True, "1", 1.0):
            with self.subTest(number=number), self.assertRaises(MenuError):
                ListEntry(number, "строка", ())
        for label in ("", "a\x1bb", "a\nb", "a\tb", "\ud800", "x" * (MAX_LIST_LINE_LENGTH + 1), None, b"x"):
            with self.subTest(label=label), self.assertRaises(MenuError):
                ListEntry(1, label, ())
        for card in (["строка"], ("a\x1b[31m",), ("ok", 1), "строка", None):
            with self.subTest(card=card), self.assertRaises(MenuError):
                ListEntry(1, "строка", card)

    def test_list_requires_titles_printable_header_and_increasing_numbers(self):
        entry = ListEntry(1, "a", ())
        for title, item_name in (("", "Элемент"), ("Элементы", ""), (" Элементы", "Элемент"), ("Э\x1b", "Элемент")):
            with self.subTest(title=title, item_name=item_name), self.assertRaises(MenuError):
                MenuList(title, item_name, (), (entry,))
        for header in (["строка"], ("a\x1b",), None):
            with self.subTest(header=header), self.assertRaises(MenuError):
                MenuList("Элементы", "Элемент", header, (entry,))
        for entries in ([entry], (entry, entry), (ListEntry(2, "b", ()), entry), (entry, "b")):
            with self.subTest(entries=entries), self.assertRaises(MenuError):
                MenuList("Элементы", "Элемент", (), entries)
        self.assertEqual(MenuList("Элементы", "Элемент", (), ()).entries, ())
        self.assertEqual(MenuList("Элементы", "Элемент", (), (entry, ListEntry(5, "b", ()))).entries[1].number, 5)

    def test_levels_check_their_invariants(self):
        source, other = sample_list(), sample_list()
        entries = source.entries
        for found in ((), [entries[0]], (other.entries[0],), (entries[2], entries[0]), (entries[1], entries[1]), ("x",)):
            with self.subTest(found=found), self.assertRaises(MenuError):
                ListLevel(source, found)
        with self.assertRaises(MenuError):
            ListLevel(None)
        self.assertEqual(ListLevel(source, (entries[1], entries[3])).entries, (entries[1], entries[3]))
        # Равный по значению элемент другого списка — не элемент этого списка.
        for entry in (other.entries[0], None):
            with self.subTest(entry=entry), self.assertRaises(MenuError):
                CardLevel(source, entry)
        with self.assertRaises(MenuError):
            CardLevel(None, entries[0])

    def test_list_opens_only_from_menu_and_only_as_menu_list(self):
        navigator = MenuNavigator(sample_root())
        for wrong in (None, ["строка"], sample_root()):
            with self.subTest(wrong=wrong), self.assertRaises(MenuError):
                navigator.open_list(wrong)
        navigator.open_list(sample_list())
        with self.assertRaises(MenuError):
            navigator.open_list(sample_list())
        navigator.select(1)
        with self.assertRaises(MenuError):
            navigator.open_list(sample_list())


class ListNavigationTests(unittest.TestCase):
    def opened(self) -> MenuNavigator:
        navigator = MenuNavigator(sample_root())
        navigator.open_list(sample_list())
        return navigator

    def test_number_opens_card_and_zero_returns_one_level(self):
        navigator = self.opened()
        self.assertEqual(navigator.titles, ("Корень", "Элементы"))
        selection = navigator.select(3)
        self.assertIs(selection.kind, SelectionKind.OPENED)
        self.assertEqual(selection.entry.number, 3)
        self.assertIs(type(navigator.current), CardLevel)
        self.assertEqual(navigator.titles, ("Корень", "Элементы", "Элемент 3"))
        self.assertIs(navigator.select(3).kind, SelectionKind.UNKNOWN)
        self.assertIs(navigator.select(0).kind, SelectionKind.BACK)
        self.assertIs(type(navigator.current), ListLevel)
        self.assertIs(navigator.select(0).kind, SelectionKind.BACK)
        self.assertIs(type(navigator.current), Menu)
        self.assertIs(navigator.select(0).kind, SelectionKind.EXIT)

    def test_unknown_numbers_and_wrong_types_keep_position(self):
        navigator = self.opened()
        for number in (6, 999, -1, True, "1", None):
            with self.subTest(number=number):
                self.assertIs(navigator.select(number).kind, SelectionKind.UNKNOWN)
                self.assertEqual(navigator.depth, 1)

    def test_search_shows_results_replaces_them_and_keeps_them_without_matches(self):
        navigator = self.opened()
        self.assertIs(navigator.search(parse_query("domaincondition")).kind, SelectionKind.FOUND)
        self.assertEqual([entry.number for entry in navigator.current.entries], [1, 3])
        self.assertEqual(navigator.titles, ("Корень", "Элементы", SEARCH_TITLE))
        self.assertEqual(navigator.depth, 2)
        # Новый запрос ищет по всему списку и заменяет результаты, а не уточняет их; слово — подстрока.
        self.assertIs(navigator.search(parse_query("IPCondition")).kind, SelectionKind.FOUND)
        self.assertEqual([entry.number for entry in navigator.current.entries], [2, 5])
        self.assertEqual(navigator.depth, 2)
        self.assertIs(navigator.search(parse_query("probe.example")).kind, SelectionKind.NO_MATCHES)
        self.assertEqual([entry.number for entry in navigator.current.entries], [2, 5])
        # Номер выбирается только из показанного набора и остаётся тем же, что в полном списке.
        self.assertIs(navigator.select(1).kind, SelectionKind.UNKNOWN)
        self.assertIs(navigator.select(5).kind, SelectionKind.OPENED)
        navigator.back()
        self.assertEqual([entry.number for entry in navigator.current.entries], [2, 5])
        navigator.back()
        self.assertFalse(navigator.current.filtered)
        self.assertEqual(len(navigator.current.entries), len(LABELS))
        navigator.back()
        self.assertIs(type(navigator.current), Menu)

    def test_no_matches_on_the_full_list_does_not_open_results(self):
        navigator = self.opened()
        self.assertIs(navigator.search(parse_query("отсутствует")).kind, SelectionKind.NO_MATCHES)
        self.assertEqual(navigator.depth, 1)
        self.assertFalse(navigator.current.filtered)

    def test_reselection_after_return_opens_the_same_card(self):
        navigator = self.opened()
        first = navigator.select(4).entry
        navigator.back()
        self.assertIs(navigator.select(4).entry, first)

    def test_search_requires_open_list_and_parsed_query(self):
        navigator = MenuNavigator(sample_root())
        with self.assertRaises(MenuError):
            navigator.search(parse_query("direct"))
        navigator.open_list(sample_list())
        for query in (None, "direct", ("direct",)):
            with self.subTest(query=query), self.assertRaises(MenuError):
                navigator.search(query)
        navigator.select(1)
        with self.assertRaises(MenuError):
            navigator.search(parse_query("direct"))

    def test_search_cost_is_linear_in_entries(self):
        query = parse_query("элемент 0500")
        for size in (1, 10, 100, 999):
            navigator = MenuNavigator(sample_root())
            navigator.open_list(numbered_list(size))
            checks = []
            normalized = []

            def counted(query, text, original=menu_module.matches):
                checks.append(text)
                return original(query, text)

            def counted_normalize(text, original=menu_module.normalize):
                normalized.append(text)
                return original(text)

            with self.subTest(size=size), patch.object(menu_module, "matches", counted), \
                    patch.object(menu_module, "normalize", counted_normalize):
                navigator.search(query)
                self.assertEqual(len(checks), size)
                self.assertEqual(len(set(map(id, checks))), size)
                # Тексты строк нормализованы при создании списка: поиск их не пересчитывает.
                self.assertEqual(normalized, [])

    def test_navigation_has_no_external_effects(self):
        with forbid_external_effects():
            navigator = self.opened()
            navigator.search(parse_query("direct"))
            navigator.select(1)
            navigator.back()
            navigator.back()
            navigator.back()


class ListLoopTests(unittest.TestCase):
    def test_list_number_card_and_zero_on_each_level(self):
        calls = []
        code, output, navigator = run("1\n3\n0\n0\n0\n", calls=calls)
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertEqual(calls, ["list"])
        self.assertIn("Корень / Элементы\nВводная строка списка\n  1. " + LABELS[0], output)
        self.assertIn(f"{LIST_USAGE}\n  0. Назад\n", output)
        self.assertIn("Корень / Элементы / Элемент 3\nКарточка 3\nВторая строка карточки\n  0. Назад\n", output)
        self.assertEqual(output.count("Корень / Элементы\n"), 2)
        self.assertEqual(output.count("Корень\n"), 2)

    def test_search_found_no_matches_and_return_to_full_list(self):
        code, output, navigator = run(f"1\nDOMAIN\n{SECRET_QUERY}\n3\n0\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(navigator.depth, 0)
        self.assertIn(
            f"Корень / Элементы / {SEARCH_TITLE}\nНайдено: 2 из 5.\n  1. {LABELS[0]}\n  3. {LABELS[2]}\n", output,
        )
        self.assertEqual(output.count(NO_MATCHES), 1)
        # Без совпадений показан прежний набор результатов, затем карточка из него и возврат к нему.
        self.assertEqual(output.count("Найдено: 2 из 5."), 3)
        self.assertIn(f"Корень / Элементы / {SEARCH_TITLE} / Элемент 3\nКарточка 3", output)
        self.assertEqual(output.count("Вводная строка списка"), 2)
        self.assertNotIn(SECRET_QUERY, output)
        self.assertNotIn("DOMAIN", output)

    def test_empty_number_like_and_unknown_input_keep_the_list(self):
        for line in ("", "   ", "01", "00", "1000", "١", "１", "²", "6", "999"):
            with self.subTest(line=line):
                code, output, navigator = run(f"1\n{line}\n0\n0\n")
                self.assertEqual(code, 0)
                self.assertEqual(output.count(LIST_HINT), 1)
                self.assertEqual(output.count("Корень / Элементы\n"), 2)
                self.assertNotIn("Карточка", output)
                self.assertNotIn(SEARCH_TITLE, output)

    def test_bad_queries_give_query_hint_without_echo(self):
        for line in (
            "a" * 65, " ".join(["w"] * 9), f"\x1b[31m{SECRET_QUERY}", f"a\t{SECRET_QUERY}", f"\x9b1m{SECRET_QUERY}",
            f"\u200b{SECRET_QUERY}", "\ud800", "\ue000x", "ﷺ" * 4,
        ):
            with self.subTest(line=line):
                code, output, _ = run(f"1\n{line}\n0\n0\n")
                self.assertEqual(code, 0)
                self.assertEqual(output.count(QUERY_HINT), 1)
                self.assertNotIn(SECRET_QUERY, output)
                self.assertNotIn(SEARCH_TITLE, output)
                self.assertTrue(all(item.isprintable() for item in output.splitlines()))

    def test_card_accepts_only_zero(self):
        code, output, navigator = run("1\n2\n\n1\nтекст\n2\n0\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(output.count(CARD_HINT), 4)
        self.assertEqual(output.count("Корень / Элементы / Элемент 2\n"), 5)
        self.assertNotIn(SEARCH_TITLE, output)

    def test_eof_on_any_list_level_exits_with_zero(self):
        for text in ("1\n", "1\ndirect\n", "1\n3\n", "1\ndirect\n1\n", "1\nnone-found\n"):
            with self.subTest(text=text):
                code, output, _ = run(text)
                self.assertEqual(code, 0)
                self.assertTrue(output.endswith(f"{PROMPT}\n"))

    def test_interrupt_during_search_and_selection_is_not_swallowed(self):
        for lines in (["1\n"], ["1\n", "direct\n"], ["1\n", "3\n"], ["1\n", "direct\n", "1\n"]):
            with self.subTest(lines=lines), self.assertRaises(KeyboardInterrupt):
                with forbid_external_effects():
                    run_menu(MenuNavigator(sample_root()), {"root.list": sample_list}, _Lines(lines), io.StringIO())

    def test_interrupt_during_search_gives_130_at_entrypoint(self):
        assembly = MenuAssembly(sample_root(), {"root.list": sample_list, "root.lines": lambda: ["x"]})
        for lines in (["1\n", "direct\n"], ["1\n", "3\n"]):
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(lines=lines), patch(
                "keenvpn.interfaces.cli.entrypoints.assemble_main_menu", lambda sources: assembly,
            ), forbid_external_effects():
                code = vpn_menu([], _Lines(lines), stdout, stderr)
            self.assertEqual(code, EXIT_INTERRUPTED)
            self.assertEqual(stderr.getvalue(), INTERRUPTED_MESSAGE + "\n")

    def test_long_list_shows_first_entries_and_selects_any_number(self):
        code, output, _ = run("1\n120\n0\nэлемент\n0\n0\n0\n", numbered_list(120))
        self.assertEqual(code, 0)
        self.assertIn(f" {MAX_SHOWN}. элемент группы 0050\n", output)
        self.assertNotIn(" 51. элемент группы", output)
        self.assertIn(f"Показаны первые {MAX_SHOWN} из 120: уточните поиск или введите номер.", output)
        self.assertIn("Корень / Элементы / Элемент 120\nКарточка 120", output)
        self.assertIn("Найдено: 120 из 120.", output)

    def test_empty_list_has_nothing_to_select_or_find(self):
        code, output, _ = run("1\n1\nтекст\n0\n0\n", sample_list((), ()))
        self.assertEqual(code, 0)
        self.assertIn(f"Корень / Элементы\n{EMPTY_LIST}\n{LIST_USAGE}", output)
        self.assertEqual(output.count(LIST_HINT), 1)
        self.assertEqual(output.count(NO_MATCHES), 1)

    def test_returning_never_reruns_the_action(self):
        calls = []
        code, _, _ = run("1\n2\n0\ndirect\n1\n0\n0\n0\n1\n0\n0\n", calls=calls)
        self.assertEqual(code, 0)
        # Список строится один раз на каждый выбор пункта; возвраты, поиск и карточки его не пересобирают.
        self.assertEqual(calls, ["list", "list"])

    def test_line_actions_and_menu_input_keep_their_behaviour(self):
        code, output, _ = run("2\nтекст\n\n0\n")
        self.assertEqual(code, 0)
        self.assertIn("\nСтрока действия\n\nКорень\n", output)
        self.assertEqual(output.count(HINT), 2)


class InputLimitTests(unittest.TestCase):
    def test_overlong_line_is_dropped_whole_and_its_tail_is_not_a_command(self):
        code, output, navigator = run("a" * MAX_INPUT_LENGTH + "1\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(output.count(LINE_TOO_LONG), 1)
        self.assertNotIn("Корень / Элементы", output)
        self.assertEqual(navigator.depth, 0)

    def test_line_at_the_limit_is_processed(self):
        code, output, _ = run("a" * MAX_INPUT_LENGTH + "\n0\n")
        self.assertEqual(code, 0)
        self.assertNotIn(LINE_TOO_LONG, output)
        self.assertEqual(output.count(HINT), 1)

    def test_overlong_line_inside_list_and_at_eof(self):
        code, output, _ = run("1\n" + "1" * (MAX_INPUT_LENGTH * 3) + "\n0\n0\n")
        self.assertEqual(code, 0)
        self.assertEqual(output.count(LINE_TOO_LONG), 1)
        self.assertEqual(output.count("Корень / Элементы\n"), 2)
        self.assertNotIn("Карточка", output)
        code, output, _ = run("x" * (MAX_INPUT_LENGTH + 5))
        self.assertEqual(code, 0)
        self.assertEqual(output.count(LINE_TOO_LONG), 1)

    def test_reads_are_bounded(self):
        stream = _Lines(["a" * (MAX_INPUT_LENGTH + 1), "b" * (MAX_INPUT_LENGTH + 1), "tail\n", "0\n"])
        self.assertEqual(read_line(stream), ("", True))
        self.assertEqual(stream.sizes, [MAX_INPUT_LENGTH + 1] * 3)
        self.assertEqual(read_line(stream), ("0\n", False))
        self.assertEqual(read_line(io.StringIO("")), (None, False))
        self.assertEqual(read_line(io.StringIO("abc")), ("abc", False))


if __name__ == "__main__":
    unittest.main()
