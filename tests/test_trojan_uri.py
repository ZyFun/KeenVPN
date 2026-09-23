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
