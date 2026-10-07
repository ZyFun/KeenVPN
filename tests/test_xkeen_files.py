"""Преобразование файлов Xray и XKeen снимка в модели без обращения к роутеру."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.xkeen_files import (
    XKEEN_INIT_PATH, XKEEN_LIST_DIRECTORY, XKEEN_SETTINGS_NAME, XKEEN_SETTINGS_PATH, xkeen_init_from_bytes,
    xkeen_init_from_flags, xkeen_list_from_bytes, xkeen_settings_from_bytes,
)
from keenvpn.adapters.xray_configs import XRAY_CONFIG_DIRECTORY, xray_config_from_files
from keenvpn.domain.config_document import ConfigDocumentError, ConfigDocumentErrorCode
from keenvpn.domain.xkeen_config import (
    XKeenConfigError, XKeenConfigErrorCode, XKeenFlag, XKeenFlagStatus, XKeenInitParameters, XKeenList,
    XKeenListName, XKeenSettings,
)
from keenvpn.domain.xray_config import XrayConfigError, XrayConfigErrorCode, XrayConfigSet
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import load_xkeen_snapshot, load_xray_snapshot_files


class XrayConfigFilesTests(unittest.TestCase):
    def test_parts_are_ordered_by_name_like_a_config_directory(self):
        files = load_xray_snapshot_files()
        shuffled = {name: files[name] for name in reversed(sorted(files))}
        with forbid_external_effects():
            config = xray_config_from_files(shuffled)
        self.assertIs(type(config), XrayConfigSet)
        self.assertEqual(config.part_names, tuple(sorted(files)))
        self.assertEqual([part.content for part in config.parts], [files[name] for name in sorted(files)])
        self.assertEqual(XRAY_CONFIG_DIRECTORY, "/opt/etc/xray/configs")
        self.assertEqual(xray_config_from_files({}).parts, ())

    def test_rejections_keep_model_codes_and_detach_context(self):
        for files in (None, [("01_log.json", b"{}")], {1: b"{}"}):
            with self.subTest(files=type(files).__name__):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(XrayConfigError) as caught:
                        xray_config_from_files(files)
                self.assertIs(caught.exception.code, XrayConfigErrorCode.PARTS)
                self.assertIsNone(caught.exception.__context__)
        with self.assertRaises(ConfigDocumentError) as caught:
            xray_config_from_files({"01_log.json": b"{}", "bad/name.json": b"{}"})
        self.assertIs(caught.exception.code, ConfigDocumentErrorCode.NAME)
        with self.assertRaises(ConfigDocumentError) as caught:
            xray_config_from_files({"01_log.json": b'{"log": NaN}'})
        self.assertIs(caught.exception.code, ConfigDocumentErrorCode.JSON)


class XKeenFilesTests(unittest.TestCase):
    def test_settings_init_and_lists_become_models(self):
        snapshot = load_xkeen_snapshot()
        with forbid_external_effects():
            settings = xkeen_settings_from_bytes(b'{"xkeen": {"killswitch": "off"}}')
            init = xkeen_init_from_bytes(b'start_auto="on"\n')
            flags = xkeen_init_from_flags(snapshot["init_flags"])
            exclude = xkeen_list_from_bytes(XKeenListName.PORT_EXCLUDE, snapshot["lists"]["port_exclude.lst"].encode())
        self.assertIs(type(settings), XKeenSettings)
        self.assertEqual(settings.document.name, XKEEN_SETTINGS_NAME)
        self.assertEqual(settings.killswitch, XKeenFlag(XKeenFlagStatus.PRESENT, "off"))
        self.assertIs(type(init), XKeenInitParameters)
        self.assertEqual(init.assignments[0].line_number, 1)
        self.assertIs(type(flags), XKeenInitParameters)
        self.assertEqual(
            [(item.name, item.raw, item.line_number, item.indented) for item in flags.assignments],
            [("start_auto", '"on"', None, False), ("proxy_dns", '"off"', None, False),
             ("proxy_router", '"off"', None, False), ("ipv6_support", '"on"', None, False)],
        )
        self.assertIs(type(exclude), XKeenList)
        self.assertTrue(exclude.lists_port(53))
        self.assertEqual((XKEEN_SETTINGS_PATH, XKEEN_INIT_PATH, XKEEN_LIST_DIRECTORY), (
            "/opt/etc/xkeen/xkeen.json", "/opt/etc/init.d/S05xkeen", "/opt/etc/xkeen",
        ))
        self.assertEqual(xkeen_init_from_flags({}).assignments, ())

    def test_flag_rejections_keep_model_code_and_detach_context(self):
        for flags in (
            None, [("start_auto", "on")], {"bad name": "on"}, {1: "on"}, {"start_auto": None},
            {"start_auto": 'o"n'}, {"start_auto": "$x"}, {"start_auto": "on\n"},
        ):
            with self.subTest(flags=repr(flags)):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(XKeenConfigError) as caught:
                        xkeen_init_from_flags(flags)
                self.assertIs(caught.exception.code, XKeenConfigErrorCode.INIT)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("fixture-private", str(caught.exception))
        with self.assertRaises(ConfigDocumentError):
            xkeen_settings_from_bytes(b"[]")
        with self.assertRaises(XKeenConfigError):
            xkeen_list_from_bytes("port_exclude.lst", b"53")


if __name__ == "__main__":
    unittest.main()
