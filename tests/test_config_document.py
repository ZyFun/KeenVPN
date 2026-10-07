"""Документ конфигурации: строгий JSON, ревизия и сохранность без обращения к файлам роутера."""

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.config_document import (
    MAX_JSON_DEPTH, ConfigDocument, ConfigDocumentError, ConfigDocumentErrorCode, parse_strict_json_object,
    strip_json_comments, valid_document_name, validate_config_document,
)
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import SNAPSHOT_ROOT, XRAY_SNAPSHOT_ROOT


SECRET = "fixture-private-secret"
CONTENT = ('{"outbounds": [{"tag": "out", "settings": {"password": "%s"}}], "log": {"loglevel": "warning"}}' % SECRET).encode()


class StrictJsonTests(unittest.TestCase):
    def test_accepts_comments_outside_strings_only(self):
        text = (
            '// заголовок\n{\n  "a": "http://x/y", /* блок\n на двух строках */ "b": "//не комментарий",\n'
            '  "c": "экранирование \\" // внутри", "d": 1 // хвост\n}\n'
        )
        self.assertEqual(parse_strict_json_object(text), {
            "a": "http://x/y", "b": "//не комментарий", "c": 'экранирование " // внутри', "d": 1,
        })
        self.assertEqual(strip_json_comments('"a/*b*/c"'), '"a/*b*/c"')
        self.assertEqual(strip_json_comments("/* незакрытый"), "")
        self.assertEqual(strip_json_comments("/* незакрытый\nхвост\n"), "\n\n")
        self.assertEqual(strip_json_comments('{"a": 1 /* x\ny\n */}'), '{"a": 1 \n\n}')

    def test_multiline_block_comment_does_not_join_tokens(self):
        # Построчный очиститель XKeen сохраняет переводы строк, и такие документы не проходят разбор.
        for text in ('{"a":1/*\n*/2}', '{"a":tr/*\n*/ue}', '{"a":nu/*\nx\n*/ll}', '{"a":"x"/*\n*/:1}'):
            with self.subTest(text=text), self.assertRaises(ConfigDocumentError) as caught:
                parse_strict_json_object(text)
            self.assertIs(caught.exception.code, ConfigDocumentErrorCode.JSON)
        self.assertEqual(parse_strict_json_object('{"a": 1, /*\n многострочный\n*/ "b": true}'), {"a": 1, "b": True})

    def test_rejects_ambiguous_or_unsupported_input(self):
        deep = "[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1)
        cases = {
            "duplicate_top": '{"a": 1, "a": 2}',
            "duplicate_nested": '{"a": {"b": 1, "b": 2}}',
            "nan": '{"a": NaN}',
            "infinity": '{"a": Infinity}',
            "negative_infinity": '{"a": -Infinity}',
            "overflow_float": '{"a": 1e999}',
            "array": "[]",
            "string": '"x"',
            "number": "1",
            "empty": "",
            "comment_only": "// ничего",
            "hash_comment": '# x\n{"a": 1}',
            "unterminated_block": '{"a": 1 /* ...',
            "trailing_text": '{"a": 1} {"b": 2}',
            "bom": '﻿{"a": 1}',
            "too_deep": '{"a": %s}' % deep,
            "recursion": "[" * 100_000 + "]" * 100_000,
            "huge_int": '{"a": %s}' % ("1" * 5000),
        }
        for label, text in cases.items():
            with self.subTest(case=label), self.assertRaises(ConfigDocumentError) as caught:
                parse_strict_json_object(text)
            self.assertIs(caught.exception.code, ConfigDocumentErrorCode.JSON)
        with self.assertRaises(ConfigDocumentError):
            parse_strict_json_object(b'{"a": 1}')
        self.assertEqual(set(parse_strict_json_object('{"a": %s}' % ("[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH))), {"a"})


class ConfigDocumentTests(unittest.TestCase):
    def test_snapshot_parts_match_manifest_revisions(self):
        manifest = json.loads((SNAPSHOT_ROOT / "manifest.json").read_text())
        for path in sorted(XRAY_SNAPSHOT_ROOT.iterdir()):
            content = path.read_bytes()
            with self.subTest(part=path.name), forbid_external_effects():
                document = ConfigDocument(path.name, content)
            self.assertEqual(document.size, len(content))
            self.assertEqual(document.sha256, manifest["files"][f"xray/{path.name}"])
            self.assertEqual(document.sha256, hashlib.sha256(content).hexdigest())
            self.assertEqual(document.export(), json.loads(content))
            self.assertEqual(len(document.sections), 1)

    def test_export_is_isolated_and_representations_hide_content(self):
        document = ConfigDocument("04_outbounds.json", CONTENT)
        exported = document.export()
        exported["outbounds"].clear()
        self.assertEqual(document.export()["outbounds"][0]["tag"], "out")
        self.assertEqual(document.sections, ("outbounds", "log"))
        self.assertEqual(document.to_diagnostic(), {
            "name": "04_outbounds.json", "size": len(CONTENT), "sha256": hashlib.sha256(CONTENT).hexdigest(),
            "sections": ["outbounds", "log"],
        })
        text = repr(document) + str(document) + json.dumps(document.to_diagnostic())
        self.assertNotIn(SECRET, text)
        self.assertEqual(repr(document), f"ConfigDocument(size={len(CONTENT)})")
        self.assertEqual(document.content, CONTENT)
        validate_config_document(document)
        with self.assertRaises(FrozenInstanceError):
            document.sha256 = "0" * 64
        with self.assertRaises(FrozenInstanceError):
            document.content = b"{}"

    def test_rejects_bad_names_content_and_json_with_codes(self):
        for name in ("", ".hidden", "a/b", "a\\b", " a", "a ", "a\nb", "a\tb", None, 5, "x" * 256):
            with self.subTest(name=repr(name)), self.assertRaises(ConfigDocumentError) as caught:
                ConfigDocument(name, b"{}")
            self.assertIs(caught.exception.code, ConfigDocumentErrorCode.NAME)
            self.assertFalse(valid_document_name(name))
        self.assertTrue(valid_document_name("копия 2.json"))
        self.assertTrue(valid_document_name("x" * 255))
        for content in ("{}", bytearray(b"{}"), None, b"\xff\xfe{}", b'{"a": "\xc3"}'):
            with self.subTest(content=type(content).__name__), self.assertRaises(ConfigDocumentError) as caught:
                ConfigDocument("a.json", content)
            self.assertIs(caught.exception.code, ConfigDocumentErrorCode.CONTENT)
        for content in (b"", b"[]", b'{"a": 1, "a": 2}', b'{"a": NaN}', b"\xef\xbb\xbf{}", b"{ // x"):
            with self.subTest(content=content), self.assertRaises(ConfigDocumentError) as caught:
                ConfigDocument("a.json", content)
            self.assertIs(caught.exception.code, ConfigDocumentErrorCode.JSON)

    def test_validation_detects_tampering_and_foreign_types(self):
        class Derived(ConfigDocument):
            pass

        for broken in (Derived("a.json", b"{}"), None, {"name": "a.json"}):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(ConfigDocumentError) as caught:
                validate_config_document(broken)
            self.assertIs(caught.exception.code, ConfigDocumentErrorCode.DOCUMENT)
        for field_name, value in (
            ("sha256", "0" * 64),
            ("_snapshot", '{"log": {}}'),
            ("content", b'{"log": {"loglevel": "error"}}'),
        ):
            document = ConfigDocument("01_log.json", b'{"log": {"loglevel": "warning"}}')
            object.__setattr__(document, field_name, value)
            with self.subTest(field=field_name), self.assertRaises(ConfigDocumentError) as caught:
                validate_config_document(document)
            self.assertIs(caught.exception.code, ConfigDocumentErrorCode.DOCUMENT)
        document = ConfigDocument("01_log.json", b'{"log": {}}')
        object.__setattr__(document, "name", "bad/name")
        with self.assertRaises(ConfigDocumentError) as caught:
            validate_config_document(document)
        self.assertIs(caught.exception.code, ConfigDocumentErrorCode.NAME)

    def test_errors_are_detached_from_foreign_context_and_hide_values(self):
        for name, content, code in (
            ("fixture-private/name", b"{}", ConfigDocumentErrorCode.NAME),
            ("a.json", "fixture-private-text", ConfigDocumentErrorCode.CONTENT),
            ("a.json", b'{"fixture-private-key": NaN}', ConfigDocumentErrorCode.JSON),
        ):
            with self.subTest(code=code):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(ConfigDocumentError) as caught:
                        ConfigDocument(name, content)
                error = caught.exception
                self.assertIs(error.code, code)
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertNotIn("fixture-private", str(error) + repr(error))


if __name__ == "__main__":
    unittest.main()
