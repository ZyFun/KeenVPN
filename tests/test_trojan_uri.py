"""Локальные проверки Trojan URI на полностью искусственных данных."""

import builtins
import contextlib
from dataclasses import FrozenInstanceError, asdict
import io
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import traceback
import unittest
from unittest.mock import patch
import urllib.request


# Изолированный запуск unittest не добавляет корень исходников в sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.trojan_uri import (
    MAX_URI_LENGTH,
    TrojanURIError,
    TrojanURIErrorCode,
    parse_trojan_uri,
)
from keenvpn.domain.connection import TrojanConnection


URI = (
    "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443"
    "?security=tls&type=ws&sni=tls.example.test&host=ws.example.test"
    "&path=%2Fsocket&fp=firefox#Example"
)


class TrojanURIParsingTests(unittest.TestCase):
    def test_complete_link_becomes_typed_connection(self):
        connection = parse_trojan_uri(URI)
        self.assertIsInstance(connection, TrojanConnection)
        self.assertEqual(
            (connection.protocol, connection.security, connection.transport),
            ("trojan", "tls", "ws"),
        )
        self.assertEqual((connection.server, connection.port), ("vpn.example.test", 443))
        self.assertEqual(connection.password.reveal(), "TEST_ONLY_PASSWORD")
        self.assertEqual(connection.sni, "tls.example.test")
        self.assertEqual(connection.host, "ws.example.test")
        self.assertEqual(connection.path, "/socket")
        self.assertEqual(connection.fingerprint, "firefox")
        self.assertEqual(connection.name, "Example")
        with self.assertRaises(FrozenInstanceError):
            connection.port = 8443

    def test_minimal_link_preserves_absent_optional_values(self):
        connection = parse_trojan_uri(
            "trojan://TEST_ONLY_PASSWORD@192.0.2.10:8443?type=ws&security=tls"
        )
        self.assertEqual((connection.server, connection.port, connection.path), ("192.0.2.10", 8443, "/"))
        self.assertEqual((connection.sni, connection.host, connection.fingerprint, connection.name), (None,) * 4)

    def test_ipv6_brackets_are_not_part_of_server(self):
        connection = parse_trojan_uri(
            "TROJAN://TEST_ONLY_PASSWORD@[2001:db8::1]:443/?security=tls&type=ws"
        )
        self.assertEqual(connection.server, "2001:db8::1")

    def test_input_is_only_data_without_io_or_evaluation(self):
        """Синтаксис shell/Python и пути не исполняются даже после декодирования."""
        payload = "$(id);`id`;__import__('os').system('id')"
        malicious = (
            f"trojan://{payload}@vpn.example.test:443"
            "?security=tls&type=ws&path=%2F..%2F..%2Fmarker"
            f"#{payload}"
        )
        output = io.StringIO()
        calls = (
            (builtins, "eval"), (builtins, "exec"), (builtins, "open"), (io, "open"),
            (os, "open"), (os, "system"), (os, "popen"),
            (subprocess, "Popen"), (socket, "socket"),
            (socket, "getaddrinfo"), (urllib.request, "urlopen"),
        )
        with contextlib.ExitStack() as stack:
            for owner, name in calls:
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError("Запрещён побочный эффект")))
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(output))
            connection = parse_trojan_uri(malicious)
            self.assertEqual(connection.password.reveal(), payload)
            self.assertEqual(connection.name, payload)
            self.assertEqual(connection.path, "/../../marker")
        self.assertEqual(output.getvalue(), "")

    def test_unsupported_input_is_not_silently_simplified(self):
        for uri in (
            URI.replace("trojan://", "vless://"),
            URI.replace("security=tls", "security=none"),
            URI.replace("type=ws", "type=grpc"),
            URI.replace("&fp=firefox", "&allowInsecure=1"),
        ):
            with self.subTest(uri_type=uri.split(":", 1)[0]):
                with self.assertRaises(TrojanURIError) as raised:
                    parse_trojan_uri(uri)
                self.assertEqual(raised.exception.code, TrojanURIErrorCode.UNSUPPORTED_URI)

    def test_malformed_input_is_rejected_without_fallback(self):
        for uri in (
            None, b"trojan://TEST_ONLY_PASSWORD", "", "x" * (MAX_URI_LENGTH + 1),
            URI.replace("@vpn.example.test:443", "@vpn.example.test"),
            URI.replace("vpn.example.test", "vpn.example.test]"),
            URI.replace("vpn.example.test", "%GG.example.test"),
            URI.replace(":443?", ":70000?"),
            URI.replace("TEST_ONLY_PASSWORD", ""),
            URI.replace("type=ws", "type=ws&type=ws"),
            URI.replace("type=ws", "type"),
            URI.replace("%2Fsocket", "%GG"),
            URI.replace("%2Fsocket", "%FF"),
            URI.replace("%2Fsocket", "%0D%0A"),
            URI + "\n", " " + URI,
        ):
            with self.assertRaises(TrojanURIError):
                parse_trojan_uri(uri)


class TrojanURIDecodingTests(unittest.TestCase):
    FIELD_TOKENS = {
        "password": "TEST_ONLY_PASSWORD",
        "path": "%2Fsocket",
        "sni": "tls.example.test",
        "host": "ws.example.test",
        "fingerprint": "firefox",
        "name": "Example",
    }

    def uri_with_field(self, field, value):
        """Заменить ровно одно поле искусственной ссылки до декодирования."""
        return URI.replace(self.FIELD_TOKENS[field], value, 1)

    def read_field(self, connection, field):
        value = getattr(connection, field)
        return value.reveal() if field == "password" else value

    def test_percent_encoded_fields_keep_delimiters_inside_values(self):
        """Декодирование значения не создаёт новый query, authority или fragment."""
        cases = (
            ("password", "TEST%40%3A%2F%3F%23%26%3D%25%2B", "TEST@:/?#&=%+"),
            ("path", "%2fsocket%3Ftype%3Dgrpc%26host%3Dother.test%23part", "/socket?type=grpc&host=other.test#part"),
            ("sni", "%54ls.%65xample.test", "Tls.example.test"),
            ("host", "%57s.example.test%3A8443", "Ws.example.test:8443"),
            ("fingerprint", "%66%69%72%65%66%6f%78", "firefox"),
            ("name", "Example%23part%3Ftype%3Dgrpc%26host%3Dother.test", "Example#part?type=grpc&host=other.test"),
        )
        for field, encoded, expected in cases:
            with self.subTest(field=field):
                connection = parse_trojan_uri(self.uri_with_field(field, encoded))
                self.assertEqual(self.read_field(connection, field), expected)
                self.assertEqual((connection.server, connection.port), ("vpn.example.test", 443))
                self.assertEqual((connection.security, connection.transport), ("tls", "ws"))

    def test_literal_and_encoded_unicode_preserve_codepoints(self):
        """Unicode не транслитерируется, не нормализуется и не переводится в IDNA."""
        word = "%D1%82%D0%B5%D1%81%D1%82"
        cases = (
            ("password", "тест🔒", word + "%F0%9F%94%92"),
            ("path", "/тест", "%2F" + word),
            ("sni", "тест.example", word + ".example"),
            ("host", "тест.example:8443", word + ".example%3A8443"),
            ("name", "Cafe\u0301🔒", "Cafe%CC%81%F0%9F%94%92"),
        )
        for field, literal, encoded in cases:
            for value in (literal, encoded):
                with self.subTest(field=field, encoded=value == encoded):
                    connection = parse_trojan_uri(self.uri_with_field(field, value))
                    self.assertEqual(self.read_field(connection, field), literal)

    def test_plus_spaces_and_percent_are_decoded_only_once(self):
        """Плюс не становится пробелом, а полученный '%' не запускает второй проход."""
        for field in ("password", "path", "name"):
            with self.subTest(field=field):
                connection = parse_trojan_uri(
                    self.uri_with_field(field, "%2FA+%2B%20%25%2520%2525%2541%250A")
                )
                self.assertEqual(self.read_field(connection, field), "/A++ %%20%25%41%0A")

    def test_empty_optional_values_and_encoded_spaces_are_not_defaulted(self):
        """Переданное пустое значение и кодированный пробел не удаляются скрытно."""
        for field in ("path", "sni", "host", "fingerprint", "name"):
            with self.subTest(field=field):
                connection = parse_trojan_uri(self.uri_with_field(field, ""))
                self.assertEqual(self.read_field(connection, field), "")
        for field in ("password", "path", "name"):
            with self.subTest(field=field):
                connection = parse_trojan_uri(self.uri_with_field(field, "%20value%20"))
                self.assertEqual(self.read_field(connection, field), " value ")

    def test_malformed_escapes_and_utf8_are_rejected_in_each_field(self):
        invalid = ("%", "%1", "%GG", "%80", "%C0%AF", "%E2%82", "%ED%A0%80", "%F4%90%80%80")
        for field in self.FIELD_TOKENS:
            for index, value in enumerate(invalid):
                with self.subTest(field=field, case=index):
                    with self.assertRaises(TrojanURIError) as raised:
                        parse_trojan_uri(self.uri_with_field(field, value))
                    self.assertEqual(raised.exception.code, TrojanURIErrorCode.INVALID_URI)

    def test_ascii_controls_are_rejected_after_decoding_in_each_field(self):
        for field in self.FIELD_TOKENS:
            for value in ("%00", "%09", "%0A", "%0D", "%1B", "%7F"):
                with self.subTest(field=field, control=value):
                    with self.assertRaises(TrojanURIError) as raised:
                        parse_trojan_uri(self.uri_with_field(field, value))
                    self.assertEqual(raised.exception.code, TrojanURIErrorCode.INVALID_URI)

    def test_encoded_keys_are_decoded_once_before_lookup_and_duplicate_check(self):
        encoded = URI.replace("security=tls", "%73ecurity=%74ls").replace("type=ws", "%74ype=%77s")
        encoded = encoded.replace("sni=", "%73ni=").replace("host=", "%68ost=")
        connection = parse_trojan_uri(encoded)
        self.assertEqual((connection.sni, connection.host), ("tls.example.test", "ws.example.test"))
        for uri, code in (
            (URI.replace("sni=", "%2573ni="), TrojanURIErrorCode.UNSUPPORTED_URI),
            (URI.replace("&host=", "&%73ni=other.example.test&host="), TrojanURIErrorCode.INVALID_URI),
        ):
            with self.subTest(code=code):
                with self.assertRaises(TrojanURIError) as raised:
                    parse_trojan_uri(uri)
                self.assertEqual(raised.exception.code, code)

    def test_raw_surrogates_are_rejected_without_exposing_input(self):
        """Некорректная Python-строка не должна становиться моделью с ложным успехом."""
        marker = "TEST_UNICODE_MARKER"
        for field in (*self.FIELD_TOKENS, "server"):
            for index, surrogate in enumerate(("\ud800", "\udfff", "\ud83d\udd12")):
                with self.subTest(field=field, case=index):
                    value = marker + surrogate
                    uri = (URI.replace("vpn.example.test", value) if field == "server"
                           else self.uri_with_field(field, value))
                    try:
                        parse_trojan_uri(uri)
                    except TrojanURIError as error:
                        self.assertEqual(error.code, TrojanURIErrorCode.INVALID_URI)
                        rendered = str(error) + repr(error) + "".join(traceback.format_exception(error))
                        self.assertNotIn(marker, rendered)
                        self.assertNotIn("UnicodeEncodeError", rendered)
                    else:
                        self.fail("Строка, не представимая в UTF-8, была принята")


class TrojanURIPrivacyTests(unittest.TestCase):
    def test_secret_is_masked_in_model_logs_and_generic_conversion(self):
        connection = parse_trojan_uri(URI)
        output = io.StringIO()
        logger = logging.Logger("trojan-uri-test")
        logger.addHandler(logging.StreamHandler(output))
        logger.warning("%s %r", connection, connection.password)
        rendered = " ".join((str(connection), repr(connection), repr(asdict(connection)), json.dumps(asdict(connection), default=str), output.getvalue()))
        self.assertNotIn("TEST_ONLY_PASSWORD", rendered)
        self.assertNotIn(URI, rendered)
        self.assertIn("скрыто", str(connection.password))

    def test_errors_do_not_echo_input_or_low_level_exception(self):
        for uri in (
            URI.replace("vpn.example.test", "[TEST_ONLY_PASSWORD]"),
            URI.replace("%2Fsocket", "%FFTEST_ONLY_PASSWORD"),
            URI.replace("type=ws", "TEST_ONLY_PASSWORD=ws"),
        ):
            try:
                parse_trojan_uri(uri)
            except TrojanURIError as error:
                rendered = str(error) + repr(error) + "".join(traceback.format_exception(error))
                self.assertNotIn("TEST_ONLY_PASSWORD", rendered)
                self.assertNotIn(uri, rendered)
                self.assertNotIn("IPv6Address", rendered)
            else:
                self.fail("Ожидалась безопасная ошибка")


if __name__ == "__main__":
    unittest.main()
