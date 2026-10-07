"""Настройки XKeen: kill-switch, параметры init как данные, списки и факты по порту 53."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.config_document import ConfigDocument, ConfigDocumentError, ConfigDocumentErrorCode
from keenvpn.domain.xkeen_config import (
    DNS_PORT, KNOWN_INIT_FLAGS, Port53Facts, XKeenConfig, XKeenConfigError, XKeenConfigErrorCode, XKeenFlag,
    XKeenFlagStatus, XKeenInitAssignment, XKeenInitParameters, XKeenList, XKeenListItemKind, XKeenListLineKind,
    XKeenListName, XKeenSettings, assemble_xkeen_config, parse_xkeen_init, port_53_facts, validate_xkeen_config,
    validate_xkeen_init, validate_xkeen_list, validate_xkeen_settings,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.snapshot import snapshot_xkeen_init, snapshot_xkeen_list, snapshot_xkeen_settings


PRIVATE = "fixture-private"
# Синтетический init: реальный S05xkeen в репозиторий не копируется.
SYNTHETIC_INIT = f"""#!/bin/sh
# Синтетический init для тестов разбора.

PATH=/opt/sbin:/opt/bin:$PATH
name_policy="{PRIVATE}-policy"
url_server="127.0.0.1:79"

# Перехват DNS в прокси
proxy_dns="off"
proxy_router="off"
start_auto="on"
ipv6_support="on"
start_attempts=3
start_delay='5'
log_dir="$directory/logs"
comment="-m comment --comment $tag"
empty=""
pbr_strict="off" # strict
check_fd="off" && dscp_enable="on"
export extended_msg="off"
local backup="on"
check_mode="on"
check_mode="off"

helper() {{
    local file="$1"
    proxy_router="off"
    only_indented="yes"
    shadow="on"
    [ -n "$file" ] && aghfix="on"
}}
\tmixed_indent="on"
shadow="off"
"""


def settings(document):
    return XKeenSettings(ConfigDocument("xkeen.json", json.dumps(document).encode()))


def port_list(name, text):
    return XKeenList(name, text.encode("utf-8"))


class FlagTests(unittest.TestCase):
    def test_flag_requires_consistent_status_and_value(self):
        self.assertEqual(XKeenFlag(XKeenFlagStatus.PRESENT, "on").to_diagnostic(), {"status": "present", "value": "on"})
        self.assertEqual(XKeenFlag(XKeenFlagStatus.MISSING).to_diagnostic(), {"status": "missing", "value": None})
        for status, value in (
            (XKeenFlagStatus.PRESENT, None), (XKeenFlagStatus.PRESENT, "yes"), (XKeenFlagStatus.MISSING, "on"),
            (XKeenFlagStatus.UNEXPECTED, "off"), ("present", "on"), (XKeenFlagStatus.DUPLICATE, PRIVATE),
        ):
            with self.subTest(status=status, value=value), self.assertRaises(XKeenConfigError) as caught:
                XKeenFlag(status, value)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.CONFIG)
            self.assertNotIn(PRIVATE, str(caught.exception))


class SettingsTests(unittest.TestCase):
    def test_killswitch_states_and_diagnostic(self):
        cases = (
            ({"xkeen": {"verify_downloads": "strict", "killswitch": "on"}}, "present", "on"),
            ({"xkeen": {"killswitch": "off"}}, "present", "off"),
            ({"xkeen": {"killswitch": "yes"}}, "unexpected", None),
            ({"xkeen": {"killswitch": ""}}, "unexpected", None),
            ({"xkeen": {"killswitch": True}}, "unsupported", None),
            ({"xkeen": {"killswitch": None}}, "unsupported", None),
            ({"xkeen": {"policy": []}}, "missing", None),
            ({"xkeen": "on"}, "unsupported", None),
            ({"other": {"killswitch": "on"}}, "missing", None),
            ({}, "missing", None),
        )
        for document, status, value in cases:
            with self.subTest(document=document):
                model = settings(document)
                self.assertEqual(model.killswitch.to_diagnostic(), {"status": status, "value": value})
                self.assertEqual(model.export(), document)
        model = settings({"xkeen": {"verify_downloads": "strict", "killswitch": "on", "note": PRIVATE}})
        diagnostic = model.to_diagnostic()
        self.assertEqual(diagnostic["settings_keys"], ["verify_downloads", "killswitch", "note"])
        self.assertTrue(diagnostic["has_xkeen_section"])
        self.assertEqual(diagnostic["sections"], ["xkeen"])
        self.assertEqual(diagnostic["killswitch"], {"status": "present", "value": "on"})
        self.assertEqual(set(diagnostic), {"name", "size", "sha256", "sections", "has_xkeen_section", "settings_keys", "killswitch"})
        self.assertNotIn(PRIVATE, json.dumps(diagnostic) + repr(model))
        self.assertEqual(repr(model), f"XKeenSettings(size={model.document.size})")
        self.assertEqual(settings({"xkeen": []}).settings_keys, ())
        validate_xkeen_settings(model)

    def test_snapshot_settings_and_rejections(self):
        model = snapshot_xkeen_settings()
        self.assertEqual(model.killswitch, XKeenFlag(XKeenFlagStatus.PRESENT, "on"))
        self.assertEqual(model.settings_keys, ("verify_downloads", "killswitch"))

        class Derived(XKeenSettings):
            pass

        for document in (None, {"xkeen": {}}, b"{}"):
            with self.subTest(document=type(document).__name__), self.assertRaises(XKeenConfigError) as caught:
                XKeenSettings(document)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.SETTINGS)
        for broken in (Derived(model.document), None, model.document):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(XKeenConfigError) as caught:
                validate_xkeen_settings(broken)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.SETTINGS)
        object.__setattr__(model.document, "sha256", "0" * 64)
        with self.assertRaises(ConfigDocumentError) as caught:
            validate_xkeen_settings(model)
        self.assertIs(caught.exception.code, ConfigDocumentErrorCode.DOCUMENT)


class InitTests(unittest.TestCase):
    def test_synthetic_init_is_read_as_data_with_duplicates_and_unsupported_syntax(self):
        with forbid_external_effects():
            init = parse_xkeen_init(SYNTHETIC_INIT.encode("utf-8"))
            diagnostic = init.to_diagnostic()
        expected = {
            "PATH": ("unsupported", None, 1, 0),
            "name_policy": ("present", f"{PRIVATE}-policy", 1, 0),
            "url_server": ("present", "127.0.0.1:79", 1, 0),
            "proxy_dns": ("present", "off", 1, 0),
            "proxy_router": ("duplicate", None, 1, 1),
            "start_auto": ("present", "on", 1, 0),
            "ipv6_support": ("present", "on", 1, 0),
            "start_attempts": ("unsupported", None, 1, 0),
            "start_delay": ("unsupported", None, 1, 0),
            "log_dir": ("unsupported", None, 1, 0),
            "comment": ("unsupported", None, 1, 0),
            "empty": ("present", "", 1, 0),
            "pbr_strict": ("unsupported", None, 1, 0),
            "check_fd": ("unsupported", None, 1, 0),
            "dscp_enable": ("missing", None, 0, 0),
            "extended_msg": ("missing", None, 0, 0),
            "backup": ("missing", None, 0, 0),
            "check_mode": ("duplicate", None, 2, 0),
            "file": ("missing", None, 0, 0),
            "only_indented": ("unsupported", None, 0, 1),
            "shadow": ("duplicate", None, 1, 1),
            "aghfix": ("missing", None, 0, 0),
            "mixed_indent": ("unsupported", None, 0, 1),
        }
        for name, (status, value, top_level, indented) in expected.items():
            with self.subTest(name=name):
                parameter = init.parameter(name)
                self.assertEqual(
                    (parameter.status.value, parameter.value, parameter.top_level_count, parameter.indented_count),
                    (status, value, top_level, indented),
                )
                self.assertEqual(repr(parameter), f"XKeenInitParameter(status={status})")
        self.assertEqual(init.parameter_names, (
            "PATH", "name_policy", "url_server", "proxy_dns", "proxy_router", "start_auto", "ipv6_support",
            "start_attempts", "start_delay", "log_dir", "comment", "empty", "pbr_strict", "check_fd", "check_mode",
            "shadow",
        ))
        self.assertEqual(init.switch("empty"), XKeenFlag(XKeenFlagStatus.UNEXPECTED))
        self.assertEqual(init.switch("url_server"), XKeenFlag(XKeenFlagStatus.UNEXPECTED))
        self.assertEqual(init.switch("start_auto"), XKeenFlag(XKeenFlagStatus.PRESENT, "on"))
        self.assertEqual(init.switch("check_mode"), XKeenFlag(XKeenFlagStatus.DUPLICATE))
        self.assertEqual(diagnostic, {
            "assignment_count": 21, "top_level_count": 17, "indented_count": 4, "literal_count": 10,
            "expression_count": 7, "parameter_count": 16, "duplicate_names": ["check_mode", "proxy_router", "shadow"],
            "flags": {
                "start_auto": {"status": "present", "value": "on", "indented_count": 0},
                "proxy_dns": {"status": "present", "value": "off", "indented_count": 0},
                "proxy_router": {"status": "duplicate", "value": None, "indented_count": 1},
                "ipv6_support": {"status": "present", "value": "on", "indented_count": 0},
            },
        })
        self.assertEqual(tuple(diagnostic["flags"]), KNOWN_INIT_FLAGS)
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(init) + repr(init.assignments)
        for value in (PRIVATE, "127.0.0.1", "/opt/sbin", "$directory", "--comment"):
            self.assertNotIn(value, text)
        self.assertEqual(repr(init), "XKeenInitParameters(assignments=21)")
        assignment = init.assignments[1]
        self.assertEqual((assignment.name, assignment.line_number, assignment.indented, assignment.literal), ("name_policy", 5, False, True))
        self.assertEqual((assignment.value, assignment.raw), (f"{PRIVATE}-policy", f'"{PRIVATE}-policy"'))
        self.assertEqual(repr(assignment), "XKeenInitAssignment(<скрыто>)")
        self.assertEqual([item.line_number for item in init.assignments if item.name == "proxy_router"], [10, 27])
        validate_xkeen_init(init)

    def test_line_endings_heredoc_and_empty_text(self):
        init = parse_xkeen_init(b'start_auto="on"\r\nproxy_dns="off"\r\n\r\n')
        self.assertEqual(init.switch("start_auto"), XKeenFlag(XKeenFlagStatus.PRESENT, "on"))
        self.assertEqual(init.switch("proxy_dns"), XKeenFlag(XKeenFlagStatus.PRESENT, "off"))
        self.assertEqual(parse_xkeen_init(b"").assignments, ())
        self.assertEqual(parse_xkeen_init(b"# only comment\n").to_diagnostic()["flags"]["start_auto"], {
            "status": "missing", "value": None, "indented_count": 0,
        })
        # Разбор построчный, без семантики shell: строка внутри heredoc тоже считается присваиванием.
        heredoc = parse_xkeen_init(b'start_auto="on"\ncat <<EOF\nstart_auto="off"\nEOF\n')
        self.assertEqual(heredoc.switch("start_auto"), XKeenFlag(XKeenFlagStatus.DUPLICATE))
        self.assertEqual(heredoc.to_diagnostic()["duplicate_names"], ["start_auto"])
        # Значение не выбирается по первому присваиванию и при повторе с другим значением.
        self.assertIsNone(heredoc.parameter("start_auto").value)

    def test_rejections_and_assignment_invariants(self):
        for content in ("start_auto=on", None, b'start_auto="\xff"'):
            with self.subTest(content=type(content).__name__), self.assertRaises(XKeenConfigError) as caught:
                parse_xkeen_init(content)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.INIT)
        good = XKeenInitAssignment("start_auto", '"on"', 3, False)
        for arguments in (
            ("1bad", '"on"', 3, False), ("", '"on"', 3, False), (None, '"on"', 3, False),
            ("start_auto", 5, 3, False), ("start_auto", '"on"\n', 3, False),
            ("start_auto", '"on"', 0, False), ("start_auto", '"on"', True, False), ("start_auto", '"on"', "3", False),
            ("start_auto", '"on"', 3, 0), ("start_auto", '"on"', 3, None),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(XKeenConfigError) as caught:
                XKeenInitAssignment(*arguments)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.INIT)
        unnumbered = XKeenInitAssignment("proxy_dns", '"off"', None, False)
        for assignments in (
            [good], (good, None), (good, "x"), (good, unnumbered),
            (good, XKeenInitAssignment("proxy_dns", '"off"', 3, False)),
            (good, XKeenInitAssignment("proxy_dns", '"off"', 2, False)),
        ):
            with self.subTest(assignments=type(assignments).__name__), self.assertRaises(XKeenConfigError) as caught:
                XKeenInitParameters(assignments)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.INIT)
        init = XKeenInitParameters((good, XKeenInitAssignment("proxy_dns", '"off"', 4, False)))
        for name in ("bad name", "", None, 5):
            with self.subTest(name=name), self.assertRaises(XKeenConfigError):
                init.parameter(name)

        class Derived(XKeenInitParameters):
            pass

        for broken in (Derived(()), None, init.assignments):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(XKeenConfigError) as caught:
                validate_xkeen_init(broken)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.INIT)
        object.__setattr__(init, "assignments", (good, good))
        with self.assertRaises(XKeenConfigError):
            validate_xkeen_init(init)
        with self.assertRaises(FrozenInstanceError):
            good.raw = '"off"'

    def test_snapshot_flags_have_no_line_numbers(self):
        init = snapshot_xkeen_init()
        self.assertEqual([item.line_number for item in init.assignments], [None] * 4)
        self.assertEqual(init.parameter_names, KNOWN_INIT_FLAGS)
        self.assertEqual(
            {name: init.switch(name).value for name in KNOWN_INIT_FLAGS},
            {"start_auto": "on", "proxy_dns": "off", "proxy_router": "off", "ipv6_support": "on"},
        )


class ListTests(unittest.TestCase):
    def test_port_list_parsing_follows_installed_rules(self):
        text = (
            "# заголовок\n\n53\n 80 # web \n1000:2000\n3000-2500\n443,8443\nabc\n70000\n1:2:3\n0\n,\n"
            "22 ,  23\r\n   \nhttp\n"
        )
        with forbid_external_effects():
            model = port_list(XKeenListName.PORT_EXCLUDE, text)
            diagnostic = model.to_diagnostic()
        self.assertEqual([line.kind.value for line in model.lines], [
            "comment", "blank", "entry", "entry", "entry", "entry", "entry", "entry", "entry", "entry", "entry",
            "entry", "entry", "blank", "entry",
        ])
        self.assertEqual(model.lines[3].text, " 80 # web ")
        self.assertEqual(model.lines[3].entry, "80")
        self.assertEqual(model.lines[12].text, "22 ,  23\r")
        self.assertEqual(model.lines[12].entry, "22 ,  23")
        self.assertEqual(
            [(item.line_number, item.kind.value, item.port_range) for item in model.items],
            [(3, "port", (53, 53)), (4, "port", (80, 80)), (5, "range", (1000, 2000)), (6, "range", (2500, 3000)),
             (7, "port", (443, 443)), (7, "port", (8443, 8443)), (8, "invalid", None), (9, "invalid", None),
             (10, "invalid", None), (11, "invalid", None), (13, "port", (22, 22)), (13, "port", (23, 23)),
             (15, "invalid", None)],
        )
        self.assertTrue(model.lists_port(53))
        self.assertFalse(model.lists_port(1500))
        self.assertTrue(model.covers_port_by_range(1500))
        self.assertTrue(model.covers_port_by_range(2600))
        self.assertFalse(model.covers_port_by_range(53))
        self.assertEqual(diagnostic, {
            "name": "port_exclude.lst", "line_count": 15, "blank_count": 2, "comment_count": 1, "entry_count": 12,
            "port_count": 6, "range_count": 2, "address_count": None, "invalid_count": 5,
        })
        self.assertEqual(model.text, text)
        self.assertEqual(repr(model), "XKeenList(name=port_exclude.lst, lines=15)")
        self.assertNotIn("8443", repr(model) + json.dumps(diagnostic))
        self.assertEqual(port_list(XKeenListName.PORT_PROXYING, "53").to_diagnostic()["line_count"], 1)
        self.assertEqual(port_list(XKeenListName.PORT_PROXYING, "").lines, ())
        validate_xkeen_list(model)

    def test_long_numbers_are_invalid_items_without_exceptions(self):
        long_number = "1" * 5000
        model = port_list(XKeenListName.PORT_PROXYING, f"{long_number}\n1:{long_number}\n00053\n65535\n065536\n")
        with forbid_external_effects():
            items = model.items
            diagnostic = model.to_diagnostic()
        self.assertEqual(
            [(item.kind.value, item.port_range) for item in items],
            [("invalid", None), ("invalid", None), ("port", (53, 53)), ("port", (65535, 65535)), ("invalid", None)],
        )
        self.assertTrue(model.lists_port(53))
        self.assertFalse(model.covers_port_by_range(53))
        self.assertEqual((diagnostic["port_count"], diagnostic["invalid_count"]), (2, 3))

    def test_leading_zeros_follow_installed_numeric_comparison(self):
        zeros = "0" * 5000
        model = port_list(XKeenListName.PORT_EXCLUDE, f"000053\n000001:000100\n{zeros}80\n{zeros}\n0000\n{zeros}1:{zeros}65536\n")
        with forbid_external_effects():
            items = model.items
        self.assertEqual(
            [(item.text, item.kind.value, item.port_range) for item in items],
            [("000053", "port", (53, 53)), ("000001:000100", "range", (1, 100)), (f"{zeros}80", "port", (80, 80)),
             (zeros, "invalid", None), ("0000", "invalid", None), (f"{zeros}1:{zeros}65536", "invalid", None)],
        )
        self.assertTrue(model.lists_port(53))
        self.assertTrue(model.covers_port_by_range(53))
        for name in (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING):
            with self.subTest(list=name.value):
                lists = {item: port_list(item, "") for item in (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING)}
                lists[name] = port_list(name, "000053\n")
                facts = port_53_facts(snapshot_xkeen_init(), lists[XKeenListName.PORT_EXCLUDE], lists[XKeenListName.PORT_PROXYING])
                expected = name is XKeenListName.PORT_EXCLUDE
                self.assertEqual((facts.port_exclude_entry, facts.port_proxying_entry), (expected, not expected))

    def test_ip_list_recognizes_addresses_without_normalizing(self):
        text = f"192.0.2.0/24\n2001:db8::1 # {PRIVATE}\n192.0.2.1/24, 2001:db8::2;2001:db8::3\nfe80::1%eth0\nexample.test\n999.1.1.1\n"
        model = port_list(XKeenListName.IP_EXCLUDE, text)
        self.assertEqual(
            [(item.line_number, item.text, item.kind.value) for item in model.items],
            [(1, "192.0.2.0/24", "address"), (2, "2001:db8::1", "address"), (3, "192.0.2.1/24", "address"),
             (3, "2001:db8::2", "address"), (3, "2001:db8::3", "address"), (4, "fe80::1%eth0", "invalid"),
             (5, "example.test", "invalid"), (6, "999.1.1.1", "invalid")],
        )
        self.assertEqual(model.to_diagnostic(), {
            "name": "ip_exclude.lst", "line_count": 6, "blank_count": 0, "comment_count": 0, "entry_count": 6,
            "port_count": None, "range_count": None, "address_count": 5, "invalid_count": 3,
        })
        self.assertFalse(model.is_port_list)
        self.assertFalse(model.lists_port(53))
        self.assertNotIn(PRIVATE, json.dumps(model.to_diagnostic()) + repr(model))
        self.assertFalse(any(isinstance(item, XKeenList) for item in reachable(model.to_diagnostic())))

    def test_snapshot_lists_and_rejections(self):
        exclude = snapshot_xkeen_list(XKeenListName.PORT_EXCLUDE)
        self.assertEqual([line.kind for line in exclude.lines], [XKeenListLineKind.COMMENT, XKeenListLineKind.ENTRY])
        self.assertEqual([item.kind for item in exclude.items], [XKeenListItemKind.PORT])
        self.assertTrue(exclude.lists_port(DNS_PORT))
        self.assertEqual(snapshot_xkeen_list(XKeenListName.PORT_PROXYING).items, ())
        self.assertEqual(snapshot_xkeen_list(XKeenListName.IP_EXCLUDE).to_diagnostic()["address_count"], 0)
        for name, content in (
            ("port_exclude.lst", b"53"), (None, b"53"), (XKeenListName.PORT_EXCLUDE, "53"),
            (XKeenListName.PORT_EXCLUDE, None), (XKeenListName.PORT_EXCLUDE, b"\xff"),
        ):
            with self.subTest(name=name, content=type(content).__name__), self.assertRaises(XKeenConfigError) as caught:
                XKeenList(name, content)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.LIST)

        class Derived(XKeenList):
            pass

        for broken in (Derived(XKeenListName.IP_EXCLUDE, b""), None, "53"):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(XKeenConfigError) as caught:
                validate_xkeen_list(broken)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.LIST)
        object.__setattr__(exclude, "name", "port_exclude.lst")
        with self.assertRaises(XKeenConfigError):
            validate_xkeen_list(exclude)
        with self.assertRaises(FrozenInstanceError):
            exclude.text = ""


class FactsAndAssemblyTests(unittest.TestCase):
    def build(self, exclude="53\n", proxying="", init=None):
        return (
            snapshot_xkeen_settings(),
            snapshot_xkeen_init() if init is None else parse_xkeen_init(init),
            port_list(XKeenListName.PORT_EXCLUDE, exclude),
            port_list(XKeenListName.PORT_PROXYING, proxying),
            port_list(XKeenListName.IP_EXCLUDE, ""),
        )

    def test_port_53_facts_are_separate_and_make_no_interception_claim(self):
        cases = (
            ("53\n", "", (True, False, False, False)),
            ("1:1024\n", "", (False, True, False, False)),
            ("53\n1-100\n", "53", (True, True, True, False)),
            ("80\n", "40:60,53", (False, False, True, True)),
            ("", "", (False, False, False, False)),
        )
        for exclude, proxying, expected in cases:
            with self.subTest(exclude=exclude, proxying=proxying):
                models = self.build(exclude, proxying)
                with forbid_external_effects():
                    facts = port_53_facts(models[1], models[2], models[3])
                self.assertEqual((
                    facts.port_exclude_entry, facts.port_exclude_range, facts.port_proxying_entry,
                    facts.port_proxying_range,
                ), expected)
                self.assertEqual(facts.proxy_dns, XKeenFlag(XKeenFlagStatus.PRESENT, "off"))
                self.assertEqual(facts.proxy_router, XKeenFlag(XKeenFlagStatus.PRESENT, "off"))
                self.assertNotIn("intercept", json.dumps(facts.to_diagnostic()))
        models = self.build(init=b'proxy_dns="on"\nproxy_router="on"\nproxy_router="off"\n')
        facts = port_53_facts(models[1], models[2], models[3])
        self.assertEqual(facts.to_diagnostic(), {
            "port": 53, "port_exclude_entry": True, "port_exclude_range": False, "port_proxying_entry": False,
            "port_proxying_range": False, "proxy_dns": {"status": "present", "value": "on"},
            "proxy_router": {"status": "duplicate", "value": None},
        })
        missing = port_53_facts(parse_xkeen_init(b""), models[2], models[3])
        self.assertEqual(missing.proxy_dns, XKeenFlag(XKeenFlagStatus.MISSING))
        # Повтор с отступом и другим значением не даёт выбрать верхнее присваивание.
        for text in (b'proxy_dns="off"\n    proxy_dns="on"\n', b'    proxy_dns="on"\nproxy_dns="off"\n'):
            with self.subTest(text=text):
                shadowed = port_53_facts(parse_xkeen_init(text), models[2], models[3])
                self.assertEqual(shadowed.proxy_dns, XKeenFlag(XKeenFlagStatus.DUPLICATE))
                self.assertEqual(shadowed.to_diagnostic()["proxy_dns"], {"status": "duplicate", "value": None})
        for arguments in (
            (models[1], models[3], models[3]), (models[1], models[2], models[2]), (None, models[2], models[3]),
            (models[1], models[2], models[4]),
        ):
            with self.subTest(arguments=[type(item).__name__ for item in arguments]), self.assertRaises(XKeenConfigError) as caught:
                port_53_facts(*arguments)
            self.assertIs(caught.exception.code, XKeenConfigErrorCode.CONFIG)
        for arguments in (
            (1, False, False, False, facts.proxy_dns, facts.proxy_router),
            (True, False, False, False, "off", facts.proxy_router),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(XKeenConfigError):
                Port53Facts(*arguments)

    def test_assembly_diagnostic_and_validation(self):
        models = self.build()
        with forbid_external_effects():
            config = assemble_xkeen_config(*models)
            diagnostic = config.to_diagnostic()
        self.assertEqual(set(diagnostic), {"settings", "init", "lists", "port_53"})
        self.assertEqual(set(diagnostic["lists"]), {"port_exclude", "port_proxying", "ip_exclude"})
        self.assertEqual(diagnostic["port_53"], config.port_53.to_diagnostic())
        self.assertEqual(diagnostic["settings"]["killswitch"], {"status": "present", "value": "on"})
        self.assertEqual(json.loads(json.dumps(diagnostic)), diagnostic)
        self.assertEqual(repr(config), "XKeenConfig(assignments=4, lists=3)")
        self.assertFalse(any(
            isinstance(item, (XKeenSettings, XKeenInitParameters, XKeenList, XKeenFlag, Port53Facts, ConfigDocument))
            for item in reachable(diagnostic)
        ))
        validate_xkeen_config(config)

        class Derived(XKeenConfig):
            pass

        with self.assertRaises(XKeenConfigError) as caught:
            validate_xkeen_config(Derived(*models))
        self.assertIs(caught.exception.code, XKeenConfigErrorCode.CONFIG)
        swapped = list(models)
        swapped[2], swapped[3] = swapped[3], swapped[2]
        for arguments, code in (
            (swapped, XKeenConfigErrorCode.CONFIG),
            ((models[0], models[1], models[2], models[3], models[2]), XKeenConfigErrorCode.CONFIG),
            ((None, *models[1:]), XKeenConfigErrorCode.SETTINGS),
            ((models[0], None, *models[2:]), XKeenConfigErrorCode.INIT),
            ((*models[:2], None, *models[3:]), XKeenConfigErrorCode.LIST),
        ):
            with self.subTest(code=code), self.assertRaises(XKeenConfigError) as caught:
                assemble_xkeen_config(*arguments)
            self.assertIs(caught.exception.code, code)
        corrupted = assemble_xkeen_config(*models)
        object.__setattr__(corrupted, "ip_exclude", models[2])
        with self.assertRaises(XKeenConfigError) as caught:
            validate_xkeen_config(corrupted)
        self.assertIs(caught.exception.code, XKeenConfigErrorCode.CONFIG)
        with self.assertRaises(FrozenInstanceError):
            config.init = models[1]

    def test_errors_are_detached_from_foreign_context_and_hide_values(self):
        document = ConfigDocument("xkeen.json", b"{}")
        for function, arguments in (
            (XKeenSettings, (f"{PRIVATE}-settings",)),
            (parse_xkeen_init, (f"{PRIVATE}-init",)),
            (XKeenList, (f"{PRIVATE}.lst", b"53")),
            (XKeenFlag, (XKeenFlagStatus.MISSING, PRIVATE)),
            (assemble_xkeen_config, (XKeenSettings(document), PRIVATE, None, None, None)),
        ):
            with self.subTest(function=function.__name__):
                try:
                    raise ValueError(f"{PRIVATE}-context")
                except ValueError:
                    with self.assertRaises(XKeenConfigError) as caught:
                        function(*arguments)
                error = caught.exception
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertNotIn(PRIVATE, str(error) + repr(error))


if __name__ == "__main__":
    unittest.main()
