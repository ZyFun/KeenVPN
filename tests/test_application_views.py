"""Общие помощники представлений: перенос полей по объявлению dataclass."""

from dataclasses import dataclass
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.views import view_dict, view_fields


@dataclass(frozen=True, slots=True)
class _View:
    first: str
    second: int
    third: tuple[int, ...]


class ViewFieldsTests(unittest.TestCase):
    def test_takes_only_declared_fields_in_declaration_order(self):
        values = {"third": (1,), "extra": "лишнее", "first": "a", "second": 2}
        selected = view_fields(_View, values)
        self.assertEqual(list(selected), ["first", "second", "third"])
        self.assertEqual(_View(**selected), _View("a", 2, (1,)))

    def test_missing_declared_field_is_a_programming_error(self):
        with self.assertRaises(KeyError):
            view_fields(_View, {"first": "a", "second": 2})


class ViewDictTests(unittest.TestCase):
    def test_returns_fields_of_slotted_dataclass_without_dict(self):
        view = _View("a", 2, (1, 2))
        self.assertFalse(hasattr(view, "__dict__"))
        self.assertEqual(view_dict(view), {"first": "a", "second": 2, "third": (1, 2)})

    def test_round_trip_keeps_values_and_order(self):
        view = _View("a", 2, (1,))
        self.assertEqual(_View(**view_fields(_View, view_dict(view))), view)
        self.assertEqual(list(view_dict(view)), ["first", "second", "third"])


if __name__ == "__main__":
    unittest.main()
