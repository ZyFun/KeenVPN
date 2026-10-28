"""Локальный транспорт RCI: только GET закрытого перечня, сроки, предел ответа, строгий JSON и вложенные ошибки."""

import ast
import errno
import http.client
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import keenetic_rci_http
from keenvpn.adapters.keenetic_rci_http import (
    CONNECT_TIMEOUT, RCI_HOST, RCI_PORT, REQUEST_TIMEOUT, RESPONSE_LIMIT, LoopbackConnection, RciResource, read_rci,
)
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from tests.support.isolation import forbid_external_effects
from tests.support.rci import RciReply, ScriptedRci
from tests.support.snapshot import load_keenetic_snapshot


Failure = RouterReadFailure
PRIVATE = "fixture-private"
HEADERS = {"Accept": "application/json", "Connection": "close"}
PATHS = {
    RciResource.POLICIES: "/rci/ip/policy", RciResource.HOTSPOT_SETTINGS: "/rci/ip/hotspot",
    RciResource.REGISTRATIONS: "/rci/known/host", RciResource.HOTSPOT_RUNTIME: "/rci/show/ip/hotspot",
}
# В тексте отказа нет адреса, пути, тела, сообщения RCI и текста чужого исключения.
ERROR_MARKERS = (PRIVATE, RCI_HOST, "/rci/", "ip/policy", "198.51.100", "02:00:00", "Command::")


def reply_script(reply: RciReply, resource: RciResource = RciResource.POLICIES) -> ScriptedRci:
    return ScriptedRci(replies={resource.path: reply})


def nested(depth: int) -> bytes:
    return b'{"a":' * depth + b"1" + b"}" * depth


class RciCase(unittest.TestCase):
    def assert_failure(self, call, failure):
        # Активное чужое исключение не должно попасть в цепочку отказа.
        try:
            raise ValueError(PRIVATE)
        except ValueError:
            with self.assertRaises(RouterReadError) as caught:
                call()
        error = caught.exception
        self.assertIs(error.failure, failure)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        text = str(error) + repr(error)
        for marker in ERROR_MARKERS:
            self.assertNotIn(marker, text)
        return error

    def assert_protocol(self, script, *, requested=True):
        """Одно соединение: не больше одного GET без тела по пути перечня, только разрешённые методы, закрытие в конце."""
        self.assertEqual(len(script.connections), 1)
        calls = script.connections[0].calls
        self.assertNotIn("forbidden", [call[0] for call in calls])
        self.assertEqual(calls[0], ("connect",))
        self.assertEqual(calls[-1], ("close",))
        requests = [call for call in calls if call[0] == "request"]
        self.assertEqual(len(requests), 1 if requested else 0)
        for _, args, kwargs in requests:
            self.assertEqual(len(args), 2)
            self.assertEqual(args[0], "GET")
            self.assertIn(args[1], PATHS.values())
            self.assertEqual(kwargs, {"headers": HEADERS})
        allowed = {"connect", "request", "getresponse", "read1", "response.close", "close"}
        self.assertLessEqual({call[0] for call in calls}, allowed)
        response = script.connections[0].response
        if response is not None:
            self.assertTrue(response.closed)
        return calls


class ResourceTests(RciCase):
    def test_closed_list_of_four_paths(self):
        self.assertEqual({resource: resource.path for resource in RciResource}, PATHS)
        # Обычный Enum: значение перечня не равно строке и не является ей.
        self.assertNotIsInstance(RciResource.POLICIES, str)
        self.assertNotEqual(RciResource.POLICIES, "ip/policy")

    def test_paths_are_not_built_from_strings(self):
        script = ScriptedRci()
        for value in ("ip/policy", "/rci/ip/policy", "ip/policy/../../x", None, RciResource.POLICIES.value):
            with self.subTest(value=value), self.assertRaises(TypeError):
                read_rci(value, connect=script)
        with self.assertRaises(TypeError):
            read_rci(RciResource.POLICIES, connect=object())
        self.assertEqual(script.connections, [])

    def test_limits_and_fixed_loopback_address(self):
        self.assertEqual((RCI_HOST, RCI_PORT), ("127.0.0.1", 79))
        self.assertEqual((CONNECT_TIMEOUT, REQUEST_TIMEOUT, RESPONSE_LIMIT), (2.0, 5.0, 4 * 1024 * 1024))
        self.assertIs(read_rci.__kwdefaults__["connect"], LoopbackConnection)


class ReadTests(RciCase):
    def test_each_resource_is_one_get_without_body_and_connection_is_closed(self):
        snapshot = load_keenetic_snapshot()
        for resource in RciResource:
            with self.subTest(resource=resource.name):
                script = ScriptedRci()
                started = time.monotonic()
                self.assertEqual(read_rci(resource, connect=script), snapshot[resource.value])
                calls = self.assert_protocol(script)
                self.assertEqual([call for call in calls if call[0] != "read1"], [
                    ("connect",), ("request", ("GET", resource.path), {"headers": HEADERS}), ("getresponse",),
                    ("response.close",), ("close",),
                ])
                # Тело читается порциями по 1 КиБ подставного ответа, не одним вызовом.
                self.assertGreater(len([call for call in calls if call[0] == "read1"]), 1)
                deadline = script.connections[0].deadline
                self.assertGreater(deadline, started)
                self.assertLessEqual(deadline - started, REQUEST_TIMEOUT + 0.5)

    def test_reading_has_no_terminal_file_network_or_process_effects(self):
        succeeding, failing = ScriptedRci(), reply_script(RciReply(status=500))
        with forbid_external_effects():
            self.assertIn("Policy10", read_rci(RciResource.POLICIES, connect=succeeding))
            self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=failing), Failure.HTTP_STATUS)

    def test_connection_failures(self):
        for error, failure in (
            (ConnectionRefusedError(errno.ECONNREFUSED, PRIVATE), Failure.CONNECTION_FAILED),
            (OSError(errno.ENETUNREACH, PRIVATE), Failure.CONNECTION_FAILED),
            (TimeoutError(PRIVATE), Failure.TIMEOUT),
            (socket.timeout(PRIVATE), Failure.TIMEOUT),
        ):
            with self.subTest(error=type(error).__name__, failure=failure.value):
                script = ScriptedRci(failures={"connect": error})
                self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), failure)
                self.assert_protocol(script, requested=False)

    def test_exchange_failures(self):
        for stage, error, failure in (
            ("request", TimeoutError(PRIVATE), Failure.TIMEOUT),
            ("request", BrokenPipeError(errno.EPIPE, PRIVATE), Failure.IO_ERROR),
            ("getresponse", TimeoutError(PRIVATE), Failure.TIMEOUT),
            ("getresponse", http.client.RemoteDisconnected(PRIVATE), Failure.INVALID_RESPONSE),
            ("getresponse", http.client.BadStatusLine(PRIVATE), Failure.INVALID_RESPONSE),
            ("getresponse", http.client.LineTooLong(PRIVATE), Failure.INVALID_RESPONSE),
            ("getresponse", ConnectionResetError(errno.ECONNRESET, PRIVATE), Failure.IO_ERROR),
        ):
            with self.subTest(stage=stage, error=type(error).__name__):
                script = ScriptedRci(failures={stage: error})
                self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), failure)
                self.assert_protocol(script)

    def test_body_failures_after_part_of_the_response(self):
        body = json.dumps({"Policy10": {"description": PRIVATE}}).encode("utf-8")
        for error, failure in (
            (http.client.IncompleteRead(PRIVATE.encode("utf-8")), Failure.INVALID_RESPONSE),
            (ConnectionResetError(errno.ECONNRESET, PRIVATE), Failure.IO_ERROR),
            (TimeoutError(PRIVATE), Failure.TIMEOUT),
        ):
            with self.subTest(error=type(error).__name__):
                script = reply_script(RciReply(body=body, chunk=4, fail_after=8, failure=error))
                self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), failure)
                self.assert_protocol(script)

    def test_status_other_than_200_is_rejected_without_reading_or_following(self):
        for status in (201, 204, 301, 302, 304, 307, 400, 401, 404, 500, 503):
            with self.subTest(status=status):
                script = reply_script(RciReply(status=status, body=b'{"location": "/rci/x"}'))
                self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), Failure.HTTP_STATUS)
                calls = self.assert_protocol(script)
                self.assertNotIn("read1", [call[0] for call in calls])

    def test_response_size_limit(self):
        # Объявленная длина больше предела: тело не читается.
        script = reply_script(RciReply(body=b"{}", length=RESPONSE_LIMIT + 1))
        self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), Failure.TOO_LARGE)
        self.assertNotIn("read1", [call[0] for call in self.assert_protocol(script)])
        # Без объявленной длины читается не больше предела плюс один байт.
        oversized = b'{"a":"' + b"x" * RESPONSE_LIMIT + b'"}'
        script = reply_script(RciReply(body=oversized, length=None, chunk=1024 * 1024))
        self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), Failure.TOO_LARGE)
        self.assert_protocol(script)
        self.assertEqual(script.connections[0].response._position, RESPONSE_LIMIT + 1)
        # Ровно предел — допустимый ответ.
        exact = b'{"a":"' + b"x" * (RESPONSE_LIMIT - 8) + b'"}'
        self.assertEqual(len(exact), RESPONSE_LIMIT)
        for length in (len(exact), None):
            with self.subTest(length=length):
                script = reply_script(RciReply(body=exact, length=length, chunk=1024 * 1024))
                self.assertEqual(len(read_rci(RciResource.POLICIES, connect=script)["a"]), RESPONSE_LIMIT - 8)

    def test_body_shorter_than_declared_length_is_invalid(self):
        script = reply_script(RciReply(body=b'{"a": 1}', length=20))
        self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), Failure.INVALID_RESPONSE)
        self.assert_protocol(script)

    def test_corrupt_or_non_object_bodies_are_invalid_responses(self):
        for body in (
            b"", b"{", b"[]", b'"text"', b"1", b"null", b'{"a": "\xff"}', b"\xef\xbb\xbf{}", b'{"a": 1, "a": 2}',
            b'{"a": NaN}', b'{"a": Infinity}', b'{"a": 1 /* comment */}', b'{"a": 1} // comment', nested(65),
            PRIVATE.encode("utf-8"),
        ):
            with self.subTest(body=body[:24]):
                script = reply_script(RciReply(body=body))
                self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), Failure.INVALID_RESPONSE)
        self.assertEqual(read_rci(RciResource.POLICIES, connect=reply_script(RciReply(body=nested(63)))), json.loads(nested(63)))

    def test_nested_error_status_at_any_depth_is_rejected_without_its_message(self):
        error = {"status": "error", "code": "7405600", "ident": "Command::Base", "message": PRIVATE + " 198.51.100.7"}
        for document in (
            {"status": [error]},
            error,
            {"host": [{"mac": "02:00:00:00:00:01", "items": [{"x": {"status": [error]}}]}]},
            {"Policy10": {"description": "TEST_POLICY", "status": [{"status": "message"}, error]}},
        ):
            with self.subTest(document=list(document)):
                script = reply_script(RciReply(body=json.dumps(document).encode("utf-8")))
                self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=script), Failure.RCI_ERROR)
        # Другие значения статуса — данные ресурса, а не ошибка.
        ok = {"status": "ok", "host": [{"status": [{"status": "message", "message": "TEST"}]}]}
        self.assertEqual(read_rci(RciResource.POLICIES, connect=reply_script(RciReply(body=json.dumps(ok).encode()))), ok)


class LoopbackConnectionTests(unittest.TestCase):
    def test_host_is_fixed_loopback_and_environment_proxy_is_ignored(self):
        proxy = "http://198.51.100.7:3128"
        environment = {"HTTP_PROXY": proxy, "http_proxy": proxy, "ALL_PROXY": proxy, "NO_PROXY": ""}
        with patch.dict(os.environ, environment), forbid_external_effects():
            connection = LoopbackConnection(time.monotonic() + REQUEST_TIMEOUT)
        self.assertEqual((connection.host, connection.port), (RCI_HOST, RCI_PORT))
        self.assertIsNone(connection._tunnel_host)
        # Создание соединения не подключается.
        self.assertIsNone(connection.sock)

    def test_invalid_deadline_or_port_is_a_programming_error(self):
        for deadline in (5, True, None, "5"):
            with self.subTest(deadline=deadline), self.assertRaises(TypeError):
                LoopbackConnection(deadline)
        for port in (0, 65536, -1, "79", True, 79.0):
            with self.subTest(port=port), self.assertRaises(ValueError):
                LoopbackConnection(time.monotonic(), port=port)

    def test_expired_deadline_fails_before_connecting(self):
        connection = LoopbackConnection(time.monotonic() - 1.0)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("Подключение после срока.")):
            with self.assertRaises(TimeoutError):
                connection.connect()
        self.assertIsNone(connection.sock)


class SourceTextTests(unittest.TestCase):
    """Модуль транспорта не содержит методов записи и других способов обратиться к роутеру."""

    def setUp(self):
        self.source = Path(keenetic_rci_http.__file__).read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def test_no_write_methods_or_other_transports(self):
        for token in (
            "POST", "PUT", "DELETE", "PATCH", "body=", "putrequest", "putheader", "endheaders", "set_tunnel", "urllib",
            "subprocess", "ssh", "ndmc",
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, self.source)

    def test_imports_only_standard_http_socket_and_project_modules(self):
        imported = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertEqual(
            {name for name in imported if not name.startswith("keenvpn.")},
            {"collections.abc", "enum", "http.client", "socket", "time"},
        )

    def test_single_request_call_is_a_constant_get_with_headers_only(self):
        calls = [
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("request", "putrequest", "send", "set_tunnel", "putheader", "endheaders", "urlopen")
        ]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(call.func.attr, "request")
        self.assertEqual(len(call.args), 2)
        self.assertIsInstance(call.args[0], ast.Constant)
        self.assertEqual(call.args[0].value, "GET")
        self.assertEqual([keyword.arg for keyword in call.keywords], ["headers"])


class LoopbackServer:
    """Сервер на 127.0.0.1 со случайным портом в потоке теста: один клиент, ответ по сценарию."""

    def __init__(self, respond):
        self._respond = respond
        self.request = b""
        self.client_closed = None
        self._listener = socket.create_server((RCI_HOST, 0))
        self._listener.settimeout(10.0)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            client, _ = self._listener.accept()
        except OSError:
            return
        with client:
            client.settimeout(10.0)
            while b"\r\n\r\n" not in self.request:
                data = client.recv(4096)
                if not data:
                    return
                self.request += data
            try:
                self._respond(client)
                # Клиент закрывает соединение сам: сервер дожидается конца потока.
                self.client_closed = client.recv(1) == b""
            except OSError:
                # Запись в закрытое клиентом соединение — тоже признак закрытия.
                self.client_closed = True

    def finish(self):
        self._thread.join(15.0)
        self._listener.close()

    def connect(self, deadline):
        return LoopbackConnection(deadline, port=self.port)


class RealSocketTests(RciCase):
    """Настоящий сокет на адресе обратной петли: сеть за пределами машины и роутер не используются."""

    def serve(self, respond):
        server = LoopbackServer(respond)
        self.addCleanup(server.finish)
        return server

    def test_chunked_response_is_read_with_proxy_environment_set(self):
        body = json.dumps(load_keenetic_snapshot()["ip/policy"]).encode("utf-8")

        def respond(client):
            client.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            for part in (body[:100], body[100:]):
                client.sendall(b"%x\r\n" % len(part) + part + b"\r\n")
            client.sendall(b"0\r\n\r\n")

        server = self.serve(respond)
        proxy = "http://198.51.100.7:9"
        with patch.dict(os.environ, {"HTTP_PROXY": proxy, "http_proxy": proxy, "ALL_PROXY": proxy, "NO_PROXY": ""}):
            result = read_rci(RciResource.POLICIES, connect=server.connect)
        self.assertEqual(result, json.loads(body))
        server.finish()
        self.assertTrue(server.request.startswith(b"GET /rci/ip/policy HTTP/1.1\r\n"))
        # Только строка запроса и заголовки: тела нет.
        self.assertTrue(server.request.endswith(b"\r\n\r\n"))
        self.assertEqual(server.request.count(b"\r\n\r\n"), 1)
        self.assertNotIn(b"content-length", server.request.lower())
        self.assertIn(b"Host: 127.0.0.1:", server.request)
        self.assertTrue(server.client_closed)

    def test_slow_delivery_cannot_extend_the_request_beyond_its_deadline(self):
        # Каждый байт приходит быстрее срока одного ожидания, поэтому отказ даёт только общий срок запроса.
        def drip_headers(client):
            for byte in b"HTTP/1.1 200 OK\r\nX-Padding: " + b"x" * 200:
                client.sendall(bytes([byte]))
                time.sleep(0.05)

        def drip_body(client):
            client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n{")
            for _ in range(200):
                time.sleep(0.05)
                client.sendall(b" ")

        for respond in (drip_headers, drip_body):
            with self.subTest(stage=respond.__name__):
                server = self.serve(respond)
                started = time.monotonic()
                self.assert_failure(
                    lambda: read_rci(
                        RciResource.POLICIES, connect=lambda _deadline: server.connect(time.monotonic() + 1.0),
                    ),
                    Failure.TIMEOUT,
                )
                elapsed = time.monotonic() - started
                self.assertGreaterEqual(elapsed, 0.9)
                self.assertLess(elapsed, 3.0)
                server.finish()
                self.assertTrue(server.client_closed)

    def test_refused_connection_redirect_and_declared_oversize(self):
        probe = socket.create_server((RCI_HOST, 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        self.assert_failure(
            lambda: read_rci(RciResource.POLICIES, connect=lambda deadline: LoopbackConnection(deadline, port=closed_port)),
            Failure.CONNECTION_FAILED,
        )
        for head, failure in (
            (b"HTTP/1.1 302 Found\r\nLocation: http://198.51.100.7/rci/ip/policy\r\nContent-Length: 0\r\n\r\n",
             Failure.HTTP_STATUS),
            (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n{}" % (RESPONSE_LIMIT + 1), Failure.TOO_LARGE),
        ):
            with self.subTest(failure=failure.value):
                server = self.serve(lambda client, head=head: client.sendall(head))
                self.assert_failure(lambda: read_rci(RciResource.POLICIES, connect=server.connect), failure)
                server.finish()
                self.assertEqual(server.request.count(b"GET "), 1)
                self.assertTrue(server.client_closed)


if __name__ == "__main__":
    unittest.main()
