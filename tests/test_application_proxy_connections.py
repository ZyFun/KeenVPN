"""Список подключений: outbound и балансировщики из безопасной сводки на снимке и управляемых источниках."""

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.proxy_config import (
    InspectProxyConfig, InspectProxyConfigHandler, XrayConfigView, XrayPositionView,
)
from keenvpn.application.proxy_connections import (
    BalancerConnectionView, ConnectionKind, ConnectionsView, InspectConnections, InspectConnectionsHandler,
    OutboundConnectionView,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import XKeenListName
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_MARKERS, UNSAFE_PART_NAME, reachable, unsafe_xray_config
from tests.support.snapshot import snapshot_proxy_sources


PRIVATE_MARKERS = (
    "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "192.0.2.", "probe.example",
    "127.0.0.1", "/opt/var/log", "1181", "1191", "fixture-private", "Обезличенный", "geoip:", "domain:",
    "serverName", "streamSettings", "TEST_ONLY",
)
PRIVATE_TYPES = (ConfigDocument, XrayConfigSet, BaseException, bytes)
_DEFAULT = object()
SOURCES = ("xray", "settings", "init", "port_exclude", "port_proxying", "ip_exclude")
LIST_NAMES = (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING, XKeenListName.IP_EXCLUDE)
LIST_FIELDS = dict(zip(SOURCES[3:], LIST_NAMES))
UNAVAILABLE_CODES = {
    "xray": "xray_config_unavailable", "settings": "xkeen_settings_unavailable", "init": "xkeen_init_unavailable",
    "port_exclude": "xkeen_port_exclude_unavailable", "port_proxying": "xkeen_port_proxying_unavailable",
    "ip_exclude": "xkeen_ip_exclude_unavailable",
}
SNAPSHOT_CONNECTIONS = [
    {"kind": "outbound", "position": {"part": "04_outbounds.json", "index": 0}, "tag_known": True, "tag": "trojan-out",
     "protocol_known": True, "protocol": "trojan"},
    {"kind": "outbound", "position": {"part": "04_outbounds.json", "index": 1}, "tag_known": True, "tag": "direct",
     "protocol_known": True, "protocol": "freedom"},
    {"kind": "outbound", "position": {"part": "04_outbounds.json", "index": 2}, "tag_known": True, "tag": "blocked",
     "protocol_known": True, "protocol": "blackhole"},
    {"kind": "balancer", "position": {"part": "05_routing.json", "index": 0}, "tag_known": True, "tag": "vpn-group",
     "selector": ["trojan-out"], "selector_match_count": 1, "fallback_known": True, "fallback_tag": "blocked",
     "fallback_resolved": True, "fallback_position": {"part": "04_outbounds.json", "index": 2},
     "strategy_known": True, "strategy": "leastPing"},
]


def configure(sources, name, outcome):
    if name in LIST_FIELDS:
        sources.lists.set_response(LIST_FIELDS[name], outcome)
    else:
        getattr(sources, name).outcome = outcome


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


def outbound(index=0, part_name="04_outbounds.json", tag="proxy-out", protocol="trojan"):
    return OutboundConnectionView(XrayPositionView(part_name, index), True, tag, True, protocol)


def balancer(**changes):
    values = {
        "position": XrayPositionView("05_routing.json", 0), "tag_known": True, "tag": "pool",
        "selector": ("proxy-",), "selector_match_count": 1, "fallback_known": True, "fallback_tag": "direct",
        "fallback_resolved": True, "fallback_position": XrayPositionView("04_outbounds.json", 1),
        "strategy_known": True, "strategy": "leastPing",
    }
    values.update(changes)
    return BalancerConnectionView(**values)


class InspectConnectionsTests(unittest.TestCase):
    def setUp(self):
        self.sources = snapshot_proxy_sources()
        self.proxy = InspectProxyConfigHandler(
            self.sources.xray, self.sources.settings, self.sources.init, self.sources.lists, operation_ids=lambda: "op",
        )
        self.handler = InspectConnectionsHandler(self.proxy, operation_ids=lambda: "op-connections")

    def execute(self, command=_DEFAULT):
        return self.handler.execute(InspectConnections() if command is _DEFAULT else command)

    def assert_private(self, result):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertFalse([type(item).__name__ for item in reachable(result) if isinstance(item, PRIVATE_TYPES)])

    def assert_failed(self, result, category, code, reason=None):
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertEqual((result.error.category, result.error.code, result.error.reason), (category, code, reason))
        self.assert_private(result)

    def test_snapshot_lists_outbounds_then_balancers_in_summary_order(self):
        with forbid_external_effects():
            result = self.execute()
        self.assertTrue(result.succeeded)
        self.assertEqual(result.to_dict()["command"], "inspect_connections")
        self.assertIs(type(result.data), ConnectionsView)
        self.assertEqual(result.data.to_dict(), {
            "part_count": 7, "outbound_count": 3, "balancer_count": 1, "duplicate_outbound_tag_count": 0,
            "duplicate_balancer_tag_count": 0, "hidden_tag_count": 0, "connections": SNAPSHOT_CONNECTIONS,
        })
        self.assertEqual([type(item) for item in result.data.connections],
                         [OutboundConnectionView] * 3 + [BalancerConnectionView])
        self.assertEqual([item.kind for item in result.data.connections],
                         [ConnectionKind.OUTBOUND] * 3 + [ConnectionKind.BALANCER])
        # Источники читаются один раз в порядке сценария конфигурации прокси.
        self.assertEqual(self.sources.calls, (1, 1, 1, LIST_NAMES))
        self.assert_private(result)

    def test_view_matches_the_proxy_summary_of_the_same_sources(self):
        summary = self.proxy.execute(InspectProxyConfig()).data.xray
        self.assertEqual(ConnectionsView.from_config(summary), self.execute().data)
        with self.assertRaises(TypeError):
            ConnectionsView.from_config(summary.outbounds)

    def test_unsafe_tags_protocols_and_selectors_are_hidden_with_positions_kept(self):
        self.sources.xray.outcome = unsafe_xray_config()
        with forbid_external_effects():
            result = self.execute()
        self.assertTrue(result.succeeded)
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for marker in UNSAFE_MARKERS:
            self.assertNotIn(marker, text)
        self.assert_private(result)
        data = result.data
        # Четыре outbound и один балансировщик со скрытыми тегами.
        self.assertEqual((data.outbound_count, data.balancer_count, data.hidden_tag_count), (5, 2, 5))
        self.assertEqual((data.duplicate_outbound_tag_count, data.duplicate_balancer_tag_count), (1, 0))
        items = data.to_dict()["connections"]
        # Два outbound со скрытыми тегами (IPv6 на позициях 0 и 4) различаются только позицией.
        hidden = [item["position"] for item in items if item["kind"] == "outbound" and item["tag"] is None]
        self.assertEqual(hidden, [
            {"part": UNSAFE_PART_NAME, "index": 0}, {"part": UNSAFE_PART_NAME, "index": 2},
            {"part": UNSAFE_PART_NAME, "index": 3}, {"part": UNSAFE_PART_NAME, "index": 4},
        ])
        self.assertEqual(items[0], {
            "kind": "outbound", "position": {"part": UNSAFE_PART_NAME, "index": 0}, "tag_known": True, "tag": None,
            "protocol_known": True, "protocol": None,
        })
        self.assertEqual((items[1]["tag"], items[1]["protocol"]), ("proxy-safe", "trojan"))
        self.assertEqual((items[3]["tag"], items[3]["protocol"]), (None, "freedom"))
        first_balancer = items[5]
        self.assertEqual((first_balancer["tag_known"], first_balancer["tag"]), (True, None))
        self.assertEqual(first_balancer["selector"], [None, "proxy-", ""])
        self.assertEqual((first_balancer["fallback_known"], first_balancer["fallback_tag"]), (True, None))
        self.assertEqual((first_balancer["fallback_resolved"], first_balancer["fallback_position"]),
                         (True, {"part": UNSAFE_PART_NAME, "index": 3}))
        self.assertEqual((first_balancer["strategy_known"], first_balancer["strategy"]), (True, None))
        self.assertEqual((items[6]["tag"], items[6]["selector"], items[6]["strategy"]), ("pool", [""], "leastPing"))

    def test_absent_and_unresolved_fields_are_distinguished_from_hidden(self):
        self.sources.xray.outcome = XrayConfigSet((
            part("04_outbounds.json", {"outbounds": [{"protocol": "freedom"}, {"tag": "only-tag"}]}),
            part("05_routing.json", {"routing": {"balancers": [
                {"tag": "no-fallback", "selector": []},
                {"tag": "lost", "selector": ["only-"], "fallbackTag": "missing", "strategy": {"type": "random"}},
            ]}}),
        ))
        with forbid_external_effects():
            data = self.execute().data
        items = data.to_dict()["connections"]
        self.assertEqual((items[0]["tag_known"], items[0]["tag"], items[0]["protocol"]), (False, None, "freedom"))
        self.assertEqual((items[1]["tag"], items[1]["protocol_known"], items[1]["protocol"]), ("only-tag", False, None))
        self.assertEqual(
            (items[2]["selector"], items[2]["selector_match_count"], items[2]["fallback_known"],
             items[2]["fallback_resolved"], items[2]["fallback_position"], items[2]["strategy_known"]),
            ([], 0, False, None, None, False),
        )
        self.assertEqual(
            (items[3]["selector_match_count"], items[3]["fallback_tag"], items[3]["fallback_resolved"],
             items[3]["fallback_position"], items[3]["strategy"]),
            (1, "missing", False, None, "random"),
        )
        self.assertEqual(data.hidden_tag_count, 0)

    def test_each_source_failure_keeps_its_code_and_stops_reading(self):
        for name in SOURCES:
            with self.subTest(source=name):
                self.setUp()
                configure(self.sources, name, OSError("Отказ источника: fixture-private fixture-password /fixture/ws"))
                self.assert_failed(self.execute(), ErrorCategory.SOURCE_FAILED, UNAVAILABLE_CODES[name])
        self.setUp()
        self.sources.xray.outcome = None
        self.assert_failed(self.execute(), ErrorCategory.INVALID_SOURCE_DATA, "invalid_xray_config")

    def test_wrong_command_and_version_do_not_read_sources(self):
        for command in (None, InspectProxyConfig(), "inspect_connections"):
            with self.subTest(command=type(command).__name__):
                self.assert_failed(self.execute(command), ErrorCategory.INVALID_REQUEST, "invalid_command")
        self.assert_failed(
            self.execute(InspectConnections(contract_version=CONTRACT_VERSION + 1)),
            ErrorCategory.INVALID_REQUEST, "unsupported_contract_version",
        )
        self.assertEqual(self.sources.calls, (0, 0, 0, ()))

    def test_interruptions_are_not_converted_to_source_failure(self):
        for error in (KeyboardInterrupt(), SystemExit()):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                self.sources.xray.outcome = error
                with self.assertRaises(type(error)):
                    self.execute()

    def test_rendering_is_frozen_and_does_not_reread_sources(self):
        result = self.execute()
        calls = self.sources.calls
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        self.assertEqual(self.sources.calls, calls)
        for model, field in ((result.data, "connections"), (result.data.connections[0], "tag"),
                             (result.data.connections[3], "selector")):
            with self.assertRaises(FrozenInstanceError):
                setattr(model, field, None)


class ConnectionViewTests(unittest.TestCase):
    def test_outbound_requires_consistent_known_flags_and_position(self):
        self.assertEqual(outbound().to_dict()["kind"], "outbound")
        self.assertEqual(OutboundConnectionView(XrayPositionView("a.json", 0), False, None, True, None).to_dict()["tag"], None)
        for changes in (
            {"tag_known": False, "tag": "x"}, {"tag_known": "yes"}, {"tag": 1}, {"protocol_known": False, "protocol": "trojan"},
            {"protocol_known": 1}, {"position": ("a.json", 0)}, {"position": None},
        ):
            with self.subTest(changes=changes), self.assertRaises(TypeError):
                replace(outbound(), **changes)
        with self.assertRaises(TypeError):
            OutboundConnectionView.from_endpoint(outbound())

    def test_balancer_requires_consistent_fallback_and_selector_fields(self):
        self.assertEqual(balancer().to_dict()["kind"], "balancer")
        self.assertEqual(balancer(fallback_known=False, fallback_tag=None, fallback_resolved=None, fallback_position=None)
                         .to_dict()["fallback_position"], None)
        self.assertEqual(balancer(selector=("", None)).to_dict()["selector"], ["", None])
        for changes in (
            {"selector": ["proxy-"]}, {"selector": (1,)}, {"selector_match_count": -1}, {"selector_match_count": True},
            {"fallback_known": False, "fallback_tag": "direct"}, {"fallback_known": False, "fallback_resolved": True},
            {"fallback_resolved": "yes"}, {"fallback_resolved": None}, {"fallback_resolved": False},
            {"fallback_position": ("04_outbounds.json", 1)}, {"strategy_known": False, "strategy": "random"},
            {"tag_known": False, "tag": "pool"}, {"position": None},
        ):
            with self.subTest(changes=changes), self.assertRaises(TypeError):
                balancer(**changes)
        with self.assertRaises(TypeError):
            BalancerConnectionView.from_balancer(balancer())

    def test_list_requires_outbounds_before_balancers_and_matching_counts(self):
        view = ConnectionsView(2, 1, 1, 0, 0, 1, (outbound(), balancer(tag=None), ))
        self.assertEqual(view.hidden_tag_count, 1)
        for arguments in (
            (2, 1, 1, 0, 0, 0, (outbound(), balancer(tag=None))),
            (2, 1, 1, 0, 0, 1, (balancer(tag=None), outbound())),
            (2, 2, 1, 0, 0, 1, (outbound(), balancer(tag=None))),
            (2, 1, 1, 0, 0, 1, [outbound(), balancer(tag=None)]),
            (-1, 1, 1, 0, 0, 1, (outbound(), balancer(tag=None))),
            (True, 1, 1, 0, 0, 1, (outbound(), balancer(tag=None))),
            (2, 1, 1, 0, 0, 1, (outbound(), "balancer")),
        ):
            with self.subTest(arguments=arguments[:6]), self.assertRaises(TypeError):
                ConnectionsView(*arguments)
        self.assertEqual(ConnectionsView(0, 0, 0, 0, 0, 0, ()).to_dict()["connections"], [])


if __name__ == "__main__":
    unittest.main()
