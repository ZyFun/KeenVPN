"""Разбор и нормализация запросов поиска в списках меню: пределы, Unicode, управляющие символы."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.interfaces.cli.search import (
    MAX_QUERY_CHARS, MAX_QUERY_WORDS, SearchQuery, is_number_like, matches, normalize, parse_query,
)
from tests.support.isolation import forbid_external_effects


class NormalizeTests(unittest.TestCase):
    def test_case_width_and_compatibility_forms_collapse(self):
        for text, expected in (
            ("DIRECT", "direct"), ("ДИРЕКТ", "директ"), ("ＤＩＲＥＣＴ", "direct"), ("Straße", "strasse"),
            ("ﬁeld", "field"), ("Ёлка", "ёлка"),
        ):
            with self.subTest(text=text):
                self.assertEqual(normalize(text), expected)
        # Ё и Е — разные буквы: нормализация не объединяет их.
        self.assertNotEqual(normalize("ёлка"), normalize("елка"))


class ParseQueryTests(unittest.TestCase):
    def test_words_are_normalized_and_split_on_spaces(self):
        self.assertEqual(parse_query("direct"), SearchQuery(("direct",)))
        self.assertEqual(parse_query("  DomainCondition   DIRECT \n"), SearchQuery(("domaincondition", "direct")))
        self.assertEqual(parse_query("только просмотр да"), SearchQuery(("только", "просмотр", "да")))
        self.assertEqual(parse_query("ＦＡＬＬＢＡＣＫ"), SearchQuery(("fallback",)))

    def test_character_and_word_limits(self):
        self.assertIsNotNone(parse_query("a" * MAX_QUERY_CHARS))
        self.assertIsNone(parse_query("a" * (MAX_QUERY_CHARS + 1)))
        # 64 символа по 4 байта — 256 байт UTF-8, это наибольший допустимый запрос в байтах.
        widest = "😀" * MAX_QUERY_CHARS
        self.assertEqual(len(widest.encode("utf-8")), 256)
        self.assertIsNotNone(parse_query(widest))
        self.assertIsNone(parse_query(widest + "😀"))
        words = " ".join(["w"] * MAX_QUERY_WORDS)
        self.assertEqual(len(parse_query(words).words), MAX_QUERY_WORDS)
        self.assertIsNone(parse_query(words + " w"))
        # Нормализация может удлинить строку: предел проверяется и после неё.
        self.assertGreater(len(normalize("ﷺ")), 1)
        self.assertIsNone(parse_query("ﷺ" * 4))

    def test_empty_control_and_unprintable_input_is_rejected(self):
        for text in (
            "", " ", "\n", "\x1b[A", "a\x1bb", "a\tb", "\x00", "a\x9bb", "a\u200bb", "a\u00a0b", "\ud800",
            "a\udcffb", "\ue000", "a\x7fb", "строка\nещё", None, b"direct", 7,
        ):
            with self.subTest(text=text):
                self.assertIsNone(parse_query(text))

    def test_query_model_rejects_inconsistent_words(self):
        for words in ((), ("",), ("a b",), ["a"], (1,), ("w",) * (MAX_QUERY_WORDS + 1)):
            with self.subTest(words=words), self.assertRaises(ValueError):
                SearchQuery(words)

    def test_number_like_text_in_any_script(self):
        for text in ("0", "7", "01", "1000", "007", " 12 ", "١", "١٢", "１", "²", "٣\n"):
            with self.subTest(text=text):
                self.assertTrue(is_number_like(text))
        for text in ("", " ", "1 2", "a1", "-1", "+1", "1.0", "1e3", "Ⅻ", None, 1):
            with self.subTest(text=text):
                self.assertFalse(is_number_like(text))


class MatchTests(unittest.TestCase):
    def test_every_word_must_be_a_substring(self):
        text = normalize("rules: условий 3 (DomainCondition 3), действие DIRECT, назначение outbound direct")
        self.assertTrue(matches(parse_query("domain direct"), text))
        self.assertTrue(matches(parse_query("УСЛОВИЙ"), text))
        self.assertTrue(matches(parse_query("cond"), text))
        self.assertFalse(matches(parse_query("domain balancer"), text))
        self.assertFalse(matches(parse_query("probe.example"), text))

    def test_parsing_and_matching_have_no_external_effects(self):
        with forbid_external_effects():
            query = parse_query("Direct")
            self.assertTrue(matches(query, normalize("DIRECT")))
            self.assertTrue(is_number_like("１"))


if __name__ == "__main__":
    unittest.main()
