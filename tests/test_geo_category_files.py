"""Доверенные каталоги категорий из реальных полей тестовых protobuf-сообщений."""

from dataclasses import replace
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.geo_category_files import GeoCategoryFiles
from tests.support.saved_draft import Assets, REVISIONS


class GeoCategoryFilesTests(unittest.TestCase):
    def setUp(self):
        self.assets = Assets()
        self.source = GeoCategoryFiles(self.assets)

    def record(self, data):
        revision = replace(REVISIONS[0], sha256=hashlib.sha256(data).hexdigest())
        self.assets.data[revision.reference] = data
        return revision

    def test_uses_full_list_only_at_matching_digest(self):
        revision = self.record(b"\x0a\x04\x0a\x02RU\x0a\x04\x0a\x02US")
        catalog, = self.source.read_catalogs((revision,))
        self.assertEqual(catalog.categories, frozenset({"RU", "US"}))
        self.assertEqual(self.source.read_catalogs((replace(revision, sha256="0" * 64),)), ())

    def test_malformed_geodata_returns_no_membership_claim(self):
        for data in (
            b"", b"\x0a\x06\x0a\x02RU", b"\x0a\x04\x0a\x03RU", b"\x0a\x02\x0a\x00",
            b"\x0a\x08\x0a\x02RU\x0a\x02US", b"\x0a\x04\x0a\x02RU" * 2, b"\x0a" + b"\xff" * 10,
            b"\x0a\x04\x0a\x02ru", b"\x0a\x06\x10\x01\x0a\x02RU", b"\x10\x01\x0a\x04\x0a\x02RU",
            b"\x0a\x05\x0a\x82\x00RU",
        ):
            with self.subTest():
                catalog, = self.source.read_catalogs((self.record(data),))
                self.assertIsNone(catalog.categories)
