"""Преобразование наблюдений каталога геобаз в модели без обращения к роутеру."""

import hashlib
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.geodata_files import (
    XRAY_ASSET_DIRECTORY, geo_database_file_from_bytes, geo_database_file_from_digest, geo_inventory_from_files,
    missing_geo_database_file,
)
from keenvpn.domain.geodata import (
    GEOIP_FILE_NAME, GEOSITE_FILE_NAME, GeoDatabaseFile, GeoDatabaseInventory, GeoDataError, GeoDataErrorCode,
)
from tests.support.isolation import forbid_external_effects


class GeoDataFilesTests(unittest.TestCase):
    def test_files_become_records_with_size_hash_and_known_metadata(self):
        content = b"fixture-geoip-bytes"
        with forbid_external_effects():
            found = geo_database_file_from_bytes(GEOIP_FILE_NAME, content, source="fixture-source", version="fixture-v1")
            digest = geo_database_file_from_digest("custom.dat", 5, "AB" * 32)
            missing = missing_geo_database_file(GEOSITE_FILE_NAME)
            unknown = geo_database_file_from_bytes(GEOSITE_FILE_NAME, b"")
        self.assertEqual(found, GeoDatabaseFile(
            GEOIP_FILE_NAME, True, len(content), hashlib.sha256(content).hexdigest(), "fixture-source", "fixture-v1",
        ))
        self.assertEqual((digest.size, digest.sha256, digest.source, digest.version), (5, "ab" * 32, None, None))
        self.assertEqual((missing.present, missing.size, missing.sha256), (False, None, None))
        self.assertEqual((unknown.present, unknown.size, unknown.version), (True, 0, None))
        self.assertEqual(XRAY_ASSET_DIRECTORY, "/opt/etc/xray/dat")

    def test_inventory_adds_missing_standard_files_and_keeps_order(self):
        with forbid_external_effects():
            inventory = geo_inventory_from_files({"custom.dat": b"x", GEOSITE_FILE_NAME: None})
            empty = geo_inventory_from_files({})
        self.assertIs(type(inventory), GeoDatabaseInventory)
        self.assertEqual(
            [(item.name, item.present) for item in inventory.files],
            [("custom.dat", True), (GEOSITE_FILE_NAME, False), (GEOIP_FILE_NAME, False)],
        )
        self.assertEqual([(item.name, item.present) for item in empty.files], [(GEOIP_FILE_NAME, False), (GEOSITE_FILE_NAME, False)])

    def test_rejections_keep_model_codes_and_detach_context(self):
        for files in (None, [(GEOIP_FILE_NAME, b"")], {1: b""}):
            with self.subTest(files=type(files).__name__):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(GeoDataError) as caught:
                        geo_inventory_from_files(files)
                self.assertIs(caught.exception.code, GeoDataErrorCode.INVENTORY)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("fixture-private", str(caught.exception))
        for build in (
            lambda: geo_inventory_from_files({"bad/name.dat": b""}),
            lambda: geo_database_file_from_bytes(GEOIP_FILE_NAME, "fixture-private"),
            lambda: geo_database_file_from_digest(GEOIP_FILE_NAME, 5, "zz" * 32),
            lambda: geo_database_file_from_digest(GEOIP_FILE_NAME, True, "ab" * 32),
            lambda: missing_geo_database_file(GEOIP_FILE_NAME, version=" "),
        ):
            with self.subTest(case=build.__code__.co_firstlineno):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(GeoDataError) as caught:
                        build()
                self.assertIs(caught.exception.code, GeoDataErrorCode.FILE)
                self.assertIsNone(caught.exception.__context__)


if __name__ == "__main__":
    unittest.main()
