"""Контракт прикладных сценариев на искусственных данных и управляемых портах."""

import builtins
import contextlib
from dataclasses import FrozenInstanceError
import gc
import io
import json
from pathlib import Path
import sys
import traceback
import types
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.connections import (
    ConnectionLinkView, InspectConnectionLink, InspectConnectionLinkHandler,
)
from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationStatus, Result,
)
from keenvpn.application.ports import ConnectionLinkRejected, LinkRejection
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler
from keenvpn.domain.connection import SecretValue, TrojanConnection
from keenvpn.domain.routing import (
    DomainCondition, GeoDatabase, GeoDatabaseKind, GeoIPCondition, IPCondition,
    RoutingAction, RoutingRule,
)
from keenvpn.domain.routing_explanation import DomainSource, GeoMatch, IPSource
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy


SECRET = "TEST_ONLY_PASSWORD"
LINK = (
    f"trojan://{SECRET}@vpn.example.test:443"
    "?security=tls&type=ws&sni=tls.example.test&path=%2Fsocket#Example"
)
PRIVATE_DOMAIN = "private-host.example.test"
PRIVATE_IP = "192.0.2.10"


def fixed_ids(*values):
    iterator = iter(values)
    return lambda: next(iterator)


def reachable(root):
    """Объекты, достижимые из результата, без обхода классов и модулей."""
    seen, stack, found = set(), [root], []
    while stack:
        item = stack.pop()
        if id(item) in seen or isinstance(item, (type, types.ModuleType, types.FunctionType)):
            continue
        seen.add(id(item))
        found.append(item)
        stack.extend(gc.get_referents(item))
    return found


class ForbiddenStdin(io.StringIO):
    def read(self, *args):
        raise AssertionError("Сценарий читал stdin.")

    readline = read


class RecordingParser:
    def __init__(self, outcome=None):
        self.calls = 0
        self.outcome = outcome

    def parse(self, link):
        self.calls += 1
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class ResultContractTests(unittest.TestCase):
    def test_success_and_failure_are_mutually_exclusive(self):
        view = ConnectionLinkView("trojan", "tls", "ws", False, False, False, False)
        error = ErrorDetail(ErrorCategory.INVALID_INPUT, "invalid_uri", "Сообщение.")
        ok = Result(operation_id="op", command="c", status=OperationStatus.SUCCEEDED, data=view)
        self.assertTrue(ok.succeeded)
        self.assertEqual(ok.contract_version, CONTRACT_VERSION)
        bad = Result(operation_id="op", command="c", status=OperationStatus.FAILED, error=error)
        self.assertFalse(bad.succeeded)
        for kwargs in (
            {"status": OperationStatus.SUCCEEDED},
            {"status": OperationStatus.SUCCEEDED, "data": view, "error": error},
            {"status": OperationStatus.FAILED},
            {"status": OperationStatus.FAILED, "data": view, "error": error},
            {"status": "succeeded", "data": view},
            {"status": OperationStatus.SUCCEEDED, "data": view, "operation_id": ""},
        ):
            arguments = {"operation_id": "op", "command": "c", **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                Result(**arguments)
        with self.assertRaises(FrozenInstanceError):
            ok.status = OperationStatus.FAILED

    def test_error_detail_requires_category_and_codes(self):
        for args in (
            ("invalid_input", "code", "Сообщение."),
            (ErrorCategory.INVALID_INPUT, "", "Сообщение."),
            (ErrorCategory.INVALID_INPUT, "code", ""),
        ):
            with self.subTest(args=args), self.assertRaises(TypeError):
                ErrorDetail(*args)
        with self.assertRaises(TypeError):
            ErrorDetail(ErrorCategory.INVALID_INPUT, "code", "Сообщение.", reason="")

    def test_default_operation_ids_are_unique(self):
        handler = InspectConnectionLinkHandler(TrojanLinkParser())
        ids = {handler.execute(InspectConnectionLink(SecretValue(LINK))).operation_id for _ in range(20)}
        self.assertEqual(len(ids), 20)


class InspectConnectionLinkTests(unittest.TestCase):
    def execute(self, command, parser=None):
        handler = InspectConnectionLinkHandler(parser or TrojanLinkParser(), operation_ids=fixed_ids("op-1"))
        return handler.execute(command)

    def assert_no_secret(self, result):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for fragment in (SECRET, "vpn.example.test", "tls.example.test", "socket", "Example"):
            self.assertNotIn(fragment, text)
        self.assertFalse(any(
            isinstance(item, (SecretValue, TrojanConnection, BaseException)) for item in reachable(result)
        ))

    def test_valid_link_returns_safe_view(self):
        result = self.execute(InspectConnectionLink(SecretValue(LINK)))
        self.assertEqual(result.to_dict(), {
            "contract_version": CONTRACT_VERSION,
            "operation_id": "op-1",
            "command": "inspect_connection_link",
            "status": "succeeded",
            "data": {
                "protocol": "trojan", "security": "tls", "transport": "ws",
                "has_sni": True, "has_host": False, "has_fingerprint": False, "has_name": True,
            },
            "error": None,
        })
        self.assert_no_secret(result)

    def test_parser_rejections_become_categories(self):
        cases = (
            (f"trojan://{SECRET}@vpn.example.test:0?security=tls&type=ws",
             ErrorCategory.INVALID_INPUT, "invalid_uri", "invalid_port"),
            (f"trojan://{SECRET}@vpn.example.test:443?security=tls&type=grpc",
             ErrorCategory.UNSUPPORTED, "unsupported_uri", "unsupported_transport"),
            (f"vless://{SECRET}@vpn.example.test:443",
             ErrorCategory.UNSUPPORTED, "unsupported_uri", "unsupported_scheme"),
            ("", ErrorCategory.INVALID_INPUT, "invalid_uri", None),
        )
        for link, category, code, reason in cases:
            with self.subTest(code=code, reason=reason):
                result = self.execute(InspectConnectionLink(SecretValue(link)))
                self.assertIs(result.status, OperationStatus.FAILED)
                self.assertIsNone(result.data)
                self.assertIs(result.error.category, category)
                self.assertEqual((result.error.code, result.error.reason), (code, reason))
                self.assertTrue(result.error.message)
                self.assert_no_secret(result)

    def test_malformed_command_is_rejected_before_parsing(self):
        cases = (
            (LINK, "invalid_command"),
            (InspectConnectionLink(LINK), "invalid_command"),
            (ExplainRoute(), "invalid_command"),
            (InspectConnectionLink(SecretValue(LINK), contract_version=CONTRACT_VERSION + 1),
             "unsupported_contract_version"),
            (InspectConnectionLink(SecretValue(LINK), contract_version=True), "unsupported_contract_version"),
        )
        for command, code in cases:
            with self.subTest(code=code, command=type(command).__name__):
                parser = RecordingParser()
                result = self.execute(command, parser)
                self.assertIs(result.error.category, ErrorCategory.INVALID_REQUEST)
                self.assertEqual(result.error.code, code)
                self.assertEqual(result.command, "inspect_connection_link")
                self.assertEqual(parser.calls, 0)
                self.assertNotIn(SECRET, repr(result) + json.dumps(result.to_dict()))

    def test_parser_failures_do_not_leak_or_pretend_success(self):
        cases = (
            (RuntimeError(f"сбой {LINK}"), ErrorCategory.SOURCE_FAILED, "connection_parser_failed"),
            (ConnectionLinkRejected("invalid", "x", f"текст {SECRET}"),
             ErrorCategory.INVALID_SOURCE_DATA, "invalid_parser_rejection"),
            (ConnectionLinkRejected(LinkRejection.INVALID, "", "Сообщение."),
             ErrorCategory.INVALID_SOURCE_DATA, "invalid_parser_rejection"),
            ({"password": SECRET}, ErrorCategory.INVALID_SOURCE_DATA, "invalid_connection_model"),
        )
        for outcome, category, code in cases:
            with self.subTest(code=code, outcome=type(outcome).__name__):
                result = self.execute(InspectConnectionLink(SecretValue(LINK)), RecordingParser(outcome))
                self.assertIs(result.status, OperationStatus.FAILED)
                self.assertIs(result.error.category, category)
                self.assertEqual(result.error.code, code)
                self.assert_no_secret(result)

    def test_interrupts_are_not_converted(self):
        parser = RecordingParser(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.execute(InspectConnectionLink(SecretValue(LINK)), parser)

    def test_command_repr_hides_link(self):
        command = InspectConnectionLink(SecretValue(LINK))
        self.assertNotIn(SECRET, repr(command) + str(command))
        with self.assertRaises(FrozenInstanceError):
            command.link = SecretValue("other")

    def test_scenario_does_not_use_terminal(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        forbidden = AssertionError("Сценарий обратился к терминалу.")
        with (
            patch.object(builtins, "input", side_effect=forbidden),
            patch.object(builtins, "print", side_effect=forbidden),
            patch.object(sys, "stdin", ForbiddenStdin()),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.execute(InspectConnectionLink(SecretValue(LINK)))
            self.execute(InspectConnectionLink(SecretValue("bad")))
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")


class TrojanLinkParserTests(unittest.TestCase):
    def test_returns_model_for_valid_link(self):
        connection = TrojanLinkParser().parse(LINK)
        self.assertIsInstance(connection, TrojanConnection)
        self.assertEqual(connection.password.reveal(), SECRET)

    def test_rejection_is_detached_from_input(self):
        link = f"trojan://{SECRET}@vpn.example.test:443?security=tls&type=grpc"
        # assertRaises удаляет traceback, поэтому кадры проверяются через except.
        try:
            TrojanLinkParser().parse(link)
        except ConnectionLinkRejected as rejected:
            error = rejected
        else:
            self.fail("Ожидался отказ парсера")
        self.assertIs(error.rejection, LinkRejection.UNSUPPORTED)
        self.assertEqual((error.code, error.reason), ("unsupported_uri", "unsupported_transport"))
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        # Кадры вызывающего теста содержат ссылку; проверяем только кадры адаптера.
        snapshot = traceback.TracebackException.from_exception(error, capture_locals=True)
        adapter_frames = [
            frame for frame in snapshot.stack if frame.filename.endswith("/keenvpn/adapters/trojan_uri.py")
        ]
        self.assertTrue(adapter_frames)
        for frame in adapter_frames:
            self.assertNotIn(SECRET, repr(frame.locals))


class StaticPolicySource:
    def __init__(self, policy):
        self.policy = policy
        self.calls = 0

    def current_routing_policy(self):
        self.calls += 1
        if isinstance(self.policy, BaseException):
            raise self.policy
        return self.policy


class StaticGeoData:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def match(self, condition, values):
        self.calls.append((condition, values))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class ExplainRouteTests(unittest.TestCase):
    def setUp(self):
        self.database = GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip", version="ip-v1")
        self.policy = RoutingPolicy((
            RoutingRule(GeoIPCondition(self.database, "test-set"), RoutingAction.DIRECT),
            RoutingRule(DomainCondition(PRIVATE_DOMAIN), RoutingAction.VPN),
            RoutingRule(IPCondition("198.51.100.0/24"), RoutingAction.BLOCK),
        ), FinalRoutingRule(RoutingAction.DIRECT))
        self.command = ExplainRoute(
            domain=PRIVATE_DOMAIN, domain_source=DomainSource.DESTINATION,
            ips=(PRIVATE_IP,), ip_source=IPSource.DNS,
        )

    def execute(self, command, source=None, geodata=None):
        handler = ExplainRouteHandler(
            source or StaticPolicySource(self.policy), geodata, operation_ids=fixed_ids("op-2"),
        )
        return handler.execute(command)

    def assert_private_hidden(self, result):
        text = repr(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for fragment in (PRIVATE_DOMAIN, PRIVATE_IP, "198.51.100", "fixture-ip", "ip-v1", "test-set"):
            self.assertNotIn(fragment, text)
        self.assertNotIn(PRIVATE_DOMAIN, repr(self.command))

    def test_selection_uses_policy_and_geodata_ports(self):
        geodata = StaticGeoData(GeoMatch(MatchResult.NO_MATCH, self.database))
        result = self.execute(self.command, geodata=geodata)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.command, "explain_route")
        self.assertEqual(geodata.calls[0][1], (PRIVATE_IP,))
        data = result.to_dict()["data"]
        self.assertTrue(data["preliminary"])
        self.assertEqual((data["domain_source"], data["ip_source"], data["ip_count"]), ("destination", "dns", 1))
        self.assertEqual(data["selection"], {"index": 1, "action": "VPN", "is_final": False})
        self.assertEqual([step["reason_code"] for step in data["steps"]], ["geodata", "domain"])
        self.assertEqual(data["steps"][0]["database_kind"], "geoip")
        self.assertTrue(data["steps"][0]["database_version_known"])
        self.assertIn("VPN", data["assumptions"][0])
        self.assert_private_hidden(result)

    def test_unknown_condition_is_success_without_selection(self):
        result = self.execute(self.command)
        self.assertIs(result.status, OperationStatus.SUCCEEDED)
        self.assertIsNone(result.data.selection)
        self.assertEqual(result.data.steps[-1].result, "unknown")
        self.assertEqual(result.data.steps[-1].reason_code, "geodata_missing")

    def test_invalid_input_does_not_read_source(self):
        cases = (
            (ExplainRoute(domain="http://bad/", domain_source=DomainSource.DESTINATION), "invalid_domain"),
            (ExplainRoute(ips=("192.0.2.0/24",), ip_source=IPSource.DNS), "invalid_routing_context"),
            (ExplainRoute(domain=PRIVATE_DOMAIN), "invalid_routing_context"),
            (ExplainRoute(domain_source="destination"), "invalid_routing_context"),
        )
        for command, code in cases:
            with self.subTest(code=code):
                source = StaticPolicySource(self.policy)
                result = self.execute(command, source)
                self.assertIs(result.error.category, ErrorCategory.INVALID_INPUT)
                self.assertEqual(result.error.code, code)
                self.assertEqual(source.calls, 0)

    def test_malformed_command_is_rejected(self):
        for command, code in (
            (InspectConnectionLink(SecretValue(LINK)), "invalid_command"),
            (ExplainRoute(contract_version=0), "unsupported_contract_version"),
        ):
            with self.subTest(code=code):
                source = StaticPolicySource(self.policy)
                result = self.execute(command, source)
                self.assertIs(result.error.category, ErrorCategory.INVALID_REQUEST)
                self.assertEqual(result.error.code, code)
                self.assertEqual(source.calls, 0)

    def test_source_failures_are_categorized_without_details(self):
        mismatch = GeoMatch(MatchResult.MATCH, GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip", version="ip-v2"))
        cases = (
            (StaticPolicySource(OSError(f"нет файла {PRIVATE_DOMAIN}")), None,
             ErrorCategory.SOURCE_FAILED, "routing_policy_unavailable"),
            (StaticPolicySource({"rules": PRIVATE_DOMAIN}), None,
             ErrorCategory.INVALID_SOURCE_DATA, "invalid_routing_policy"),
            (None, StaticGeoData(RuntimeError(f"сбой {PRIVATE_IP}")),
             ErrorCategory.SOURCE_FAILED, "rule_matcher_failed"),
            (None, StaticGeoData(mismatch),
             ErrorCategory.INVALID_SOURCE_DATA, "geodata_database_mismatch"),
            (None, StaticGeoData(PRIVATE_IP),
             ErrorCategory.INVALID_SOURCE_DATA, "invalid_geodata_result"),
        )
        for source, geodata, category, code in cases:
            with self.subTest(code=code):
                result = self.execute(self.command, source, geodata)
                self.assertIs(result.status, OperationStatus.FAILED)
                self.assertIsNone(result.data)
                self.assertIs(result.error.category, category)
                self.assertEqual(result.error.code, code)
                self.assert_private_hidden(result)
                self.assertFalse(any(isinstance(item, BaseException) for item in reachable(result)))

    def test_interrupts_are_not_converted(self):
        with self.assertRaises(KeyboardInterrupt):
            self.execute(self.command, StaticPolicySource(KeyboardInterrupt()))


if __name__ == "__main__":
    unittest.main()
