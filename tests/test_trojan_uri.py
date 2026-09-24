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
from urllib.parse import quote


# Изолированный запуск unittest не добавляет корень исходников в sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.trojan_uri import (
    MAX_URI_LENGTH,
    TrojanURIError,
    TrojanURIErrorCode,
    TrojanURIErrorReason,
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


class TrojanURIValidationTests(unittest.TestCase):
    def assert_rejected(self, uri, code):
        with self.assertRaises(TrojanURIError) as raised:
            parse_trojan_uri(uri)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_port_boundaries_and_leading_zeroes_are_accepted(self):
        for server in ("vpn.example.test", "192.0.2.10", "[2001:db8::1]"):
            for port, expected in (("1", 1), ("65535", 65535), ("00001", 1), ("00443", 443)):
                with self.subTest(server=server, port=port):
                    uri = f"trojan://TEST_ONLY_PASSWORD@{server}:{port}?security=tls&type=ws"
                    connection = parse_trojan_uri(uri)
                    self.assertEqual(connection.port, expected)
                    self.assertEqual(connection.path, "/")

    def test_invalid_port_syntax_and_range_are_rejected(self):
        for port in (
            "", "0", "00000", "65536", "99999", "000443", "9" * 100,
            "-1", "+443", "443.0", "1e3", "0x1bb", "4_43", "443:80",
            "%34%34%33", "٤٤٣", "４４３",
        ):
            with self.subTest(port=port):
                self.assert_rejected(URI.replace(":443?", f":{port}?"), TrojanURIErrorCode.INVALID_URI)

    def test_required_authority_parts_are_not_inferred(self):
        for endpoint in (
            "vpn.example.test:443", "@vpn.example.test:443", "TEST_ONLY_PASSWORD@:443",
            "TEST_ONLY_PASSWORD@vpn.example.test", "TEST_ONLY_PASSWORD@",
            "TEST_ONLY_PASSWORD@vpn.example.test@other.example.test:443",
            "TEST_ONLY_PASSWORD@2001:db8::1:443", "TEST_ONLY_PASSWORD@[invalid]:443",
        ):
            with self.subTest(endpoint=endpoint):
                self.assert_rejected(f"trojan://{endpoint}?security=tls&type=ws", TrojanURIErrorCode.INVALID_URI)

    def test_required_security_and_transport_must_be_present_and_nonempty(self):
        for query in (None, "", "security=tls", "type=ws", "security=&type=ws", "security=tls&type="):
            with self.subTest(query=query):
                uri = "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443"
                if query is not None:
                    uri += "?" + query
                self.assert_rejected(uri, TrojanURIErrorCode.INVALID_URI)

    def test_required_modes_are_compared_after_single_decoding(self):
        uri = "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443?%73ecurity=%74%6C%73&%74ype=%77%73"
        connection = parse_trojan_uri(uri)
        self.assertEqual((connection.security, connection.transport), ("tls", "ws"))
        for value in (uri.replace("%74%6C%73", "%2574ls"), uri.replace("%77%73", "%2577s")):
            self.assert_rejected(value, TrojanURIErrorCode.UNSUPPORTED_URI)

    def test_duplicate_parameters_are_rejected_even_if_values_agree(self):
        for key, value in (
            ("security", "tls"), ("type", "ws"), ("sni", "tls.example.test"),
            ("host", "ws.example.test"), ("path", "%2Fsocket"), ("fp", "firefox"),
        ):
            encoded_key = f"%{ord(key[0]):02X}" + key[1:]
            for duplicate_key in (key, encoded_key):
                for duplicate_value in (value, "", "other"):
                    for reverse in (False, True):
                        with self.subTest(key=key, duplicate_key=duplicate_key, value=duplicate_value, reverse=reverse):
                            pairs = [f"{key}={value}", f"{duplicate_key}={duplicate_value}"]
                            if reverse:
                                pairs.reverse()
                            uri = URI.replace(f"{key}={value}", "&".join(pairs))
                            self.assert_rejected(uri, TrojanURIErrorCode.INVALID_URI)

    def test_unknown_modes_and_parameters_are_not_ignored(self):
        cases = [URI.replace("trojan://", f"{scheme}://") for scheme in ("vless", "vmess", "http", "https")]
        cases += [URI.replace("security=tls", f"security={security}") for security in ("none", "reality", "TLS")]
        cases += [URI.replace("type=ws", f"type={transport}") for transport in ("tcp", "grpc", "xhttp", "h2", "WS")]
        cases += [URI.replace("#Example", f"&{parameter}#Example") for parameter in (
            "allowInsecure=1", "alpn=h2", "flow=other", "unknown=", "%75nknown=value",
        )]
        for uri in cases:
            with self.subTest(uri=uri):
                self.assert_rejected(uri, TrojanURIErrorCode.UNSUPPORTED_URI)

    def test_malformed_query_pairs_are_rejected(self):
        for query in (
            "security=tls&type=ws&", "&security=tls&type=ws", "security=tls&&type=ws",
            "security=tls&type=ws&path", "security=tls&type", "security=tls&type=ws&=value",
        ):
            with self.subTest(query=query):
                uri = "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443?" + query
                self.assert_rejected(uri, TrojanURIErrorCode.INVALID_URI)

    def test_validation_reasons_are_structured_and_do_not_echo_values(self):
        invalid = TrojanURIErrorCode.INVALID_URI
        unsupported = TrojanURIErrorCode.UNSUPPORTED_URI
        marker = "TEST_VALIDATION_MARKER"
        uri = URI.replace("TEST_ONLY_PASSWORD", marker)
        cases = (
            (uri.replace("vpn.example.test", f"[{marker}]"), invalid, TrojanURIErrorReason.INVALID_ENDPOINT),
            (uri.replace(":443?", f":{marker}?"), invalid, TrojanURIErrorReason.INVALID_PORT),
            (uri.replace(marker + "@", "@"), invalid, TrojanURIErrorReason.MISSING_PASSWORD),
            (uri.replace("security=tls&", ""), invalid, TrojanURIErrorReason.MISSING_SECURITY),
            (uri.replace("type=ws&", ""), invalid, TrojanURIErrorReason.MISSING_TRANSPORT),
            (uri.replace("#Example", f"&{marker}#Example"), invalid, TrojanURIErrorReason.INVALID_QUERY),
            (uri.replace("type=ws", f"type=ws&type={marker}"), invalid, TrojanURIErrorReason.DUPLICATE_PARAMETER),
            (uri.replace("trojan://", f"{marker}://"), unsupported, TrojanURIErrorReason.UNSUPPORTED_SCHEME),
            (uri.replace("security=tls", f"security={marker}"), unsupported, TrojanURIErrorReason.UNSUPPORTED_SECURITY),
            (uri.replace("type=ws", f"type={marker}"), unsupported, TrojanURIErrorReason.UNSUPPORTED_TRANSPORT),
            (uri.replace("#Example", f"&{marker}=1#Example"), unsupported, TrojanURIErrorReason.UNSUPPORTED_PARAMETER),
        )
        for value, code, reason in cases:
            with self.subTest(reason=reason):
                error = self.assert_rejected(value, code)
                self.assertEqual(error.reason, reason)
                rendered = str(error) + repr(error) + repr(vars(error)) + "".join(traceback.format_exception(error))
                self.assertNotIn(marker, rendered)
                self.assertNotIn(value, rendered)

        error = self.assert_rejected(None, invalid)
        self.assertIsNone(error.reason)


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
    def private_connection(self):
        """Поместить искусственный секрет во все произвольные поля ссылки."""
        marker = "TEST_PRIVATE_данные"
        encoded = quote(marker, safe="")
        uri = (
            f"trojan://{encoded}%2B%2F@{marker}.example.test:54321"
            f"?security=tls&type=ws&sni={encoded}&host={encoded}"
            f"&path=%2F{encoded}&fp={encoded}#trojan%3A%2F%2F{encoded}"
        )
        return parse_trojan_uri(uri), uri, marker

    def test_errors_do_not_retain_low_level_exception_context(self):
        marker = "TEST_PRIVATE_MARKER"
        for uri in (
            URI.replace("vpn.example.test", f"[{marker}]"),
            URI.replace("%2Fsocket", "%FF" + marker),
            URI.replace("Example", marker + "\ud800"),
        ):
            with self.subTest(uri=ascii(uri)):
                with self.assertRaises(TrojanURIError) as raised:
                    parse_trojan_uri(uri)
                self.assertIsNone(raised.exception.__context__)
                self.assertIsNone(raised.exception.__cause__)

    def test_parser_traceback_frames_do_not_retain_input(self):
        marker = "TEST_TRACEBACK_MARKER"
        for uri in (
            marker, URI.replace("%2Fsocket", "%FF" + marker),
            URI.replace("TEST_ONLY_PASSWORD", marker).replace("type=ws", "type=grpc"),
            URI.replace("TEST_ONLY_PASSWORD", marker) + "\n",
            URI.replace("TEST_ONLY_PASSWORD", marker).replace("%2Fsocket", "%GG"),
        ):
            with self.subTest(uri=uri):
                try:
                    parse_trojan_uri(uri)
                except TrojanURIError as error:
                    parser_frames = [
                        frame for frame, _ in traceback.walk_tb(error.__traceback__)
                        if frame.f_globals.get("__name__") == "keenvpn.adapters.trojan_uri"
                    ]
                    self.assertTrue(parser_frames)
                    for frame in parser_frames:
                        self.assertNotIn(marker, repr(frame.f_locals))
                else:
                    self.fail("Ожидалась ошибка разбора")

    def test_password_is_masked_in_model_logs_and_generic_conversion(self):
        connection = parse_trojan_uri(URI)
        output = io.StringIO()
        logger = logging.Logger("trojan-uri-test")
        logger.addHandler(logging.StreamHandler(output))
        logger.warning("%s %r", connection, connection.password)
        rendered = " ".join((str(connection), repr(connection), repr(asdict(connection)), json.dumps(asdict(connection), default=str), output.getvalue()))
        self.assertNotIn("TEST_ONLY_PASSWORD", rendered)
        self.assertNotIn(URI, rendered)
        self.assertIn("скрыто", str(connection.password))

    def test_connection_diagnostic_contains_only_safe_metadata(self):
        connection, uri, marker = self.private_connection()
        report = connection.to_diagnostic()
        self.assertEqual(report, {
            "protocol": "trojan", "security": "tls", "transport": "ws", "parameters": "<скрыто>",
            "has_sni": True, "has_host": True, "has_fingerprint": True, "has_name": True,
        })
        for rendered in (repr(report), json.dumps(report), json.dumps(report, ensure_ascii=False)):
            self.assertNotIn(marker, rendered)
            self.assertNotIn(quote(marker, safe=""), rendered)
            self.assertNotIn(uri, rendered)
            self.assertNotIn("54321", rendered)
        # Диагностика не редактирует приватную модель и не подменяет её экспорт.
        self.assertEqual(connection.password.reveal(), marker + "+/")
        self.assertEqual(connection.path, "/" + marker)
        self.assertEqual(connection.name, "trojan://" + marker)

    def test_diagnostic_presence_distinguishes_absent_from_empty_fields(self):
        minimal = "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443?security=tls&type=ws"
        for suffix, expected in (("", False), ("&sni=&host=&fp=#", True)):
            report = parse_trojan_uri(minimal + suffix).to_diagnostic()
            for name in ("has_sni", "has_host", "has_fingerprint", "has_name"):
                self.assertIs(report[name], expected)

    def test_error_diagnostic_ignores_notes_args_and_extra_attributes(self):
        marker = "TEST_ERROR_METADATA_MARKER"
        try:
            parse_trojan_uri(URI.replace("type=ws", "type=grpc"))
        except TrojanURIError as error:
            error.add_note(marker)
            error.args = (marker,)
            error.private_details = {"uri": URI}
            report = error.to_diagnostic()
            self.assertEqual(report, {"code": "unsupported_uri", "reason": "unsupported_transport"})
            rendered = json.dumps(report)
            self.assertNotIn(marker, rendered)
            self.assertNotIn("TEST_ONLY_PASSWORD", rendered)
        else:
            self.fail("Ожидалась ошибка неподдерживаемого транспорта")

        with self.assertRaises(TrojanURIError) as raised:
            parse_trojan_uri(None)
        self.assertEqual(raised.exception.to_diagnostic(), {"code": "invalid_uri", "reason": None})

    def test_repr_and_standard_logs_do_not_echo_arbitrary_connection_fields(self):
        connection, uri, marker = self.private_connection()
        output = io.StringIO()
        logger = logging.Logger("trojan-private-fields-test")
        logger.addHandler(logging.StreamHandler(output))
        logger.warning("%s %r %s %r", connection, [connection], connection.password, connection.to_diagnostic())
        rendered = " ".join((str(connection), repr(connection), ascii(connection), repr({"connection": connection}), output.getvalue()))
        self.assertNotIn(marker, rendered)
        self.assertNotIn(quote(marker, safe=""), rendered)
        self.assertNotIn(uri, rendered)
        self.assertNotIn("54321", rendered)

    def test_call_inside_except_does_not_attach_external_exception(self):
        try:
            raise ValueError("TEST_CALLER_SECRET")
        except ValueError as outer:
            try:
                parse_trojan_uri(URI.replace("type=ws", "type=grpc"))
            except TrojanURIError as error:
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertNotIn("TEST_CALLER_SECRET", "".join(traceback.format_exception(error)))
            else:
                self.fail("Ожидалась ошибка неподдерживаемого транспорта")
            self.assertEqual(outer.args, ("TEST_CALLER_SECRET",))

    def test_wrong_input_type_is_rejected_without_formatting_it(self):
        class PrivateInput:
            def __repr__(self):
                raise AssertionError("Не следует форматировать входной объект")

            __str__ = __repr__

        try:
            parse_trojan_uri(PrivateInput())
        except TrojanURIError as error:
            self.assertEqual(error.code, TrojanURIErrorCode.INVALID_URI)
            # Снимок только кадров парсера: кадры вызывающего кода остаются приватными.
            snapshot = traceback.TracebackException.from_exception(error, capture_locals=True)
            for frame in snapshot.stack:
                if frame.filename.endswith("/keenvpn/adapters/trojan_uri.py"):
                    self.assertNotIn("uri", frame.locals)
        else:
            self.fail("Ожидался отказ без форматирования входа")

    def test_errors_do_not_echo_input_or_low_level_exception(self):
        output = io.StringIO()
        logger = logging.Logger("trojan-errors-test")
        logger.addHandler(logging.StreamHandler(output))
        for uri in (
            URI.replace("vpn.example.test", "[TEST_ONLY_PASSWORD]"),
            URI.replace("%2Fsocket", "%FFTEST_ONLY_PASSWORD"),
            URI.replace("type=ws", "TEST_ONLY_PASSWORD=ws"),
        ):
            try:
                parse_trojan_uri(uri)
            except TrojanURIError as error:
                logger.exception("Ошибка импорта: %s; диагностика: %r", error, error.to_diagnostic())
                rendered = str(error) + repr(error) + "".join(traceback.format_exception(error))
                self.assertNotIn("TEST_ONLY_PASSWORD", rendered)
                self.assertNotIn(uri, rendered)
                self.assertNotIn("IPv6Address", rendered)
            else:
                self.fail("Ожидалась безопасная ошибка")
        self.assertNotIn("TEST_ONLY_PASSWORD", output.getvalue())
        self.assertNotIn("UnicodeDecodeError", output.getvalue())
        self.assertNotIn("AddressValueError", output.getvalue())

    def test_rejected_input_does_not_write_to_output_or_log(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with patch.object(logging.Logger, "_log", side_effect=AssertionError("Парсер не должен писать в лог")):
                for uri in (None, URI.replace("path=%2Fsocket", "path=%FF"), URI.replace("type=ws", "type=grpc")):
                    with self.assertRaises(TrojanURIError):
                        parse_trojan_uri(uri)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
