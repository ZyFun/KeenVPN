"""Метаданные геобаз и ссылки на наборы: разбор по правилам Xray, сопоставление с файлами и отказы."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.geodata import (
    GEOIP_FILE_NAME, GEOSITE_FILE_NAME, STANDARD_FILE_NAMES, GeoDatabaseFile, GeoDatabaseInventory, GeoDataError,
    GeoDataErrorCode, GeoDataState, GeoFileStatus, GeoReference, UnsupportedGeoReference, assemble_geodata_state,
    geo_references, parse_geo_reference, safe_geo_source, safe_geo_version, validate_geo_inventory,
    validate_geodata_state,
)
from keenvpn.domain.routing import ConditionFamily, GeoDatabase, GeoDatabaseKind
from keenvpn.domain.xray_config import RuleListValue, XrayConfigSet
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import SYNTHETIC_GEOIP_SHA256, SYNTHETIC_GEOIP_SOURCE, snapshot_xray_config, synthetic_geo_inventory


SHA = "a1" * 32
PART = "05_routing.json"
DOMAIN, IP = ConditionFamily.DOMAIN, ConditionFamily.IP


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


def listed(text, family=IP, *, qualified=True, path="routing.rules[0].ip[0]"):
    return RuleListValue(PART, path, family, qualified, text)


def reference(family, external, file_name, set_name, *, path="routing.rules[0].ip[0]", negated=False, attributes=()):
    return GeoReference(PART, path, family, external, file_name, set_name, negated=negated, attributes=attributes)


def routing_config(*values, key="ip"):
    rule = {"type": "field", key: list(values), "outboundTag": "direct"}
    return XrayConfigSet((part(PART, {"routing": {"rules": [rule]}}),))


class GeoDatabaseFileTests(unittest.TestCase):
    def test_present_missing_and_unknown_metadata_records(self):
        with forbid_external_effects():
            present = GeoDatabaseFile(GEOIP_FILE_NAME, True, 23330258, SHA.upper(), "fixture-source", "fixture-release")
            missing = GeoDatabaseFile(GEOSITE_FILE_NAME, False)
            unknown = GeoDatabaseFile(GEOIP_FILE_NAME, True, 0, SHA)
            custom = GeoDatabaseFile("custom.dat", True, 10 ** 40, SHA)
        self.assertEqual(present.sha256, SHA)
        self.assertIs(present.standard_kind, GeoDatabaseKind.GEOIP)
        self.assertEqual(
            present.database(GeoDatabaseKind.GEOIP),
            GeoDatabase(GeoDatabaseKind.GEOIP, GEOIP_FILE_NAME, "fixture-source", "fixture-release", SHA),
        )
        self.assertIs(missing.standard_kind, GeoDatabaseKind.GEOSITE)
        self.assertIsNone(missing.database(GeoDatabaseKind.GEOSITE))
        self.assertEqual(missing.to_diagnostic(), {
            "name": GEOSITE_FILE_NAME, "present": False, "size": None, "sha256": None,
            "source_known": False, "source": None, "version_known": False, "version": None,
        })
        self.assertEqual((unknown.source, unknown.version), (None, None))
        self.assertIsNone(unknown.database(GeoDatabaseKind.GEOIP).version)
        self.assertIsNone(custom.standard_kind)
        self.assertEqual(custom.database(GeoDatabaseKind.GEOSITE).kind, GeoDatabaseKind.GEOSITE)
        self.assertEqual(custom.to_diagnostic()["size"], 10 ** 40)
        self.assertEqual(repr(present), "GeoDatabaseFile(name='geoip.dat', present=True)")
        self.assertNotIn("fixture", repr(present) + repr(custom))
        with self.assertRaises(FrozenInstanceError):
            present.present = False

    def test_diagnostic_hides_credentials_and_unsafe_metadata(self):
        secret_url = "https://fixture-user:fixture-password@downloads.example.test:8443/fixture-token/geoip.dat?token=fixture-query#fixture-fragment"
        cases = (
            ("v2fly", "202609050329", "v2fly", "202609050329"),
            ("domain-list-community.v2", "1", "domain-list-community.v2", "1"),
            ("v2fly/geoip", "1", None, "1"),
            ("opt/../fixture-private/geoip.dat", "1", None, "1"),
            ("data/../../fixture-private/geosite.dat", "1", None, "1"),
            ("fixture-private/geoip.dat", "1", None, "1"),
            ("./fixture-private", "1", None, "1"),
            ("..", "1", None, "1"),
            (".fixture-private", "1", None, "1"),
            ("fixture-private..dat", "1", None, "1"),
            ("fixture-private.", "1", None, "1"),
            ("fixture-private\\geoip.dat", "1", None, "1"),
            ("x" * 129, "1", None, "1"),
            ("https://github.com/v2fly/geoip/releases/tag/202609050329", "fixture-release_1.2+b", "https://github.com", "fixture-release_1.2+b"),
            (secret_url, "release token=fixture-secret", "https://downloads.example.test:8443", None),
            ("HTTP://Example.TEST/path", "v/1", "http://example.test", None),
            ("ftp://fixture-user:fixture-password@example.test/x", "x" * 129, None, None),
            ("file:///fixture-private/geoip.dat", "1.0?", None, None),
            ("https://", "-1", None, None),
            ("https://example.test:99999/x", ".1", None, None),
            ("/opt/fixture-private/geoip.dat", "ок", None, None),
            ("fixture source with spaces", "1 0", None, None),
        )
        for source, version, safe_source, safe_version in cases:
            with self.subTest(source=source[:20], version=version[:20]):
                record = GeoDatabaseFile(GEOIP_FILE_NAME, True, 1, SHA, source, version)
                diagnostic = record.to_diagnostic()
                self.assertEqual(
                    (diagnostic["source_known"], diagnostic["source"], diagnostic["version_known"], diagnostic["version"]),
                    (True, safe_source, True, safe_version),
                )
                self.assertEqual((safe_geo_source(source), safe_geo_version(version)), (safe_source, safe_version))
                # Исходные значения остаются доверенному коду для условий маршрутизации.
                self.assertEqual((record.source, record.version), (source, version))
                self.assertEqual(record.database(GeoDatabaseKind.GEOIP).source, source)
                text = json.dumps(diagnostic, ensure_ascii=False) + repr(record)
                for private in ("fixture-user", "fixture-password", "fixture-token", "fixture-query", "fixture-fragment",
                                "fixture-secret", "fixture-private", "token="):
                    self.assertNotIn(private, text)
        self.assertEqual((safe_geo_source(None), safe_geo_version(None)), (None, None))

    def test_rejections_keep_code_and_detach_context(self):
        cases = (
            ("bad/name.dat", True, 1, SHA), (".hidden.dat", True, 1, SHA), (GEOIP_FILE_NAME, "yes", 1, SHA),
            (GEOIP_FILE_NAME, True, None, SHA), (GEOIP_FILE_NAME, True, True, SHA), (GEOIP_FILE_NAME, True, -1, SHA),
            (GEOIP_FILE_NAME, True, 1, None), (GEOIP_FILE_NAME, True, 1, "zz" * 32), (GEOIP_FILE_NAME, True, 1, SHA + "0"),
            (GEOIP_FILE_NAME, True, 1, 7), (GEOIP_FILE_NAME, False, 1, None), (GEOIP_FILE_NAME, False, None, SHA),
            (GEOIP_FILE_NAME, True, 1, SHA, " "), (GEOIP_FILE_NAME, True, 1, SHA, None, "v\n1"),
            (GEOIP_FILE_NAME, True, 1, SHA, 5), (GEOIP_FILE_NAME, False, None, None, "", None),
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(GeoDataError) as caught:
                        GeoDatabaseFile(*arguments)
                self.assertIs(caught.exception.code, GeoDataErrorCode.FILE)
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
                self.assertNotIn("fixture-private", str(caught.exception))
        for kind in (GeoDatabaseKind.GEOIP, "geosite", None):
            with self.subTest(kind=kind), self.assertRaises(GeoDataError) as caught:
                GeoDatabaseFile(GEOSITE_FILE_NAME, True, 1, SHA).database(kind)
            self.assertIs(caught.exception.code, GeoDataErrorCode.FILE)


class GeoDatabaseInventoryTests(unittest.TestCase):
    def test_inventory_requires_standard_names_once_and_describes_files(self):
        with forbid_external_effects():
            inventory = synthetic_geo_inventory()
            validate_geo_inventory(inventory)
        self.assertEqual(STANDARD_FILE_NAMES, {GeoDatabaseKind.GEOIP: "geoip.dat", GeoDatabaseKind.GEOSITE: "geosite.dat"})
        self.assertTrue(inventory.file(GEOIP_FILE_NAME).present)
        self.assertIsNone(inventory.file("other.dat"))
        self.assertIs(inventory.standard(GeoDatabaseKind.GEOSITE), inventory.files[1])
        self.assertEqual(inventory.to_diagnostic(), {
            "files": [
                {"name": GEOIP_FILE_NAME, "present": True, "size": 1024, "sha256": SYNTHETIC_GEOIP_SHA256,
                 "source_known": True, "source": SYNTHETIC_GEOIP_SOURCE, "version_known": False, "version": None},
                {"name": GEOSITE_FILE_NAME, "present": False, "size": None, "sha256": None,
                 "source_known": False, "source": None, "version_known": False, "version": None},
            ],
            "present_count": 1, "missing_count": 1, "extra_count": 0,
        })
        extra = GeoDatabaseInventory((*inventory.files, GeoDatabaseFile("custom.dat", True, 1, SHA)))
        self.assertEqual(extra.to_diagnostic()["extra_count"], 1)
        self.assertEqual(repr(extra), "GeoDatabaseInventory(files=3)")
        with self.assertRaises(FrozenInstanceError):
            inventory.files = ()

    def test_rejections_tampering_and_foreign_types(self):
        files = synthetic_geo_inventory().files
        for broken in (
            files[:1], files * 2, (files[0], GeoDatabaseFile("x.dat", False)), list(files), (files[0], None),
            (files[0], "fixture-private"), (),
        ):
            with self.subTest(files=type(broken).__name__, count=len(broken)):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(GeoDataError) as caught:
                        GeoDatabaseInventory(broken)
                self.assertIs(caught.exception.code, GeoDataErrorCode.INVENTORY)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("fixture-private", str(caught.exception))

        class Derived(GeoDatabaseInventory):
            pass

        for broken in (Derived(files), None, files):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(GeoDataError) as caught:
                validate_geo_inventory(broken)
            self.assertIs(caught.exception.code, GeoDataErrorCode.INVENTORY)
        # Повреждение поля записи отклоняет сама запись своим кодом; расхождение после
        # восстановления и нарушение состава — код инвентаря.
        for index, field_name, value, code in (
            (0, "sha256", SYNTHETIC_GEOIP_SHA256.upper(), GeoDataErrorCode.INVENTORY),
            (1, "name", GEOIP_FILE_NAME, GeoDataErrorCode.INVENTORY),
            (0, "present", 1, GeoDataErrorCode.FILE), (0, "size", "1024", GeoDataErrorCode.FILE),
            (1, "size", 5, GeoDataErrorCode.FILE), (1, "name", "bad/name.dat", GeoDataErrorCode.FILE),
            (0, "version", "", GeoDataErrorCode.FILE),
        ):
            with self.subTest(index=index, field=field_name):
                inventory = synthetic_geo_inventory()
                object.__setattr__(inventory.files[index], field_name, value)
                with self.assertRaises(GeoDataError) as caught:
                    validate_geo_inventory(inventory)
                self.assertIs(caught.exception.code, code)
        with self.assertRaises(GeoDataError):
            synthetic_geo_inventory().standard("geoip")


class GeoReferenceParsingTests(unittest.TestCase):
    def test_parse_follows_xray_loader_rules(self):
        cases = (
            (listed("geoip:ru"), reference(IP, False, GEOIP_FILE_NAME, "ru")),
            (listed("geoip:!cn"), reference(IP, False, GEOIP_FILE_NAME, "cn", negated=True)),
            (listed("ext:custom.dat:ru"), reference(IP, True, "custom.dat", "ru")),
            (listed("ext-ip:custom.dat:!ru"), reference(IP, True, "custom.dat", "ru", negated=True)),
            (listed("ext:geoip.dat:private"), reference(IP, True, GEOIP_FILE_NAME, "private")),
            (listed("ext:custom.dat:ru", qualified=False), reference(IP, True, "custom.dat", "ru")),
            (listed("geosite:category-ads-all", DOMAIN), reference(DOMAIN, False, GEOSITE_FILE_NAME, "category-ads-all")),
            (listed("geosite:google@cn@ads", DOMAIN), reference(DOMAIN, False, GEOSITE_FILE_NAME, "google", attributes=("cn", "ads"))),
            (listed("geosite:google@", DOMAIN), reference(DOMAIN, False, GEOSITE_FILE_NAME, "google", attributes=("",))),
            (listed("ext:sites.dat:tld-ru", DOMAIN), reference(DOMAIN, True, "sites.dat", "tld-ru")),
            (listed("ext-domain:sites.dat:tld-ru@attr", DOMAIN), reference(DOMAIN, True, "sites.dat", "tld-ru", attributes=("attr",))),
            (listed("geosite:x", DOMAIN, qualified=False), reference(DOMAIN, False, GEOSITE_FILE_NAME, "x")),
            (listed("ext:hosts.dat:x", DOMAIN, qualified=False), reference(DOMAIN, True, "hosts.dat", "x")),
        )
        for value, expected in cases:
            with self.subTest(value=value.value), forbid_external_effects():
                parsed = parse_geo_reference(value)
            self.assertEqual(parsed, expected)
            self.assertEqual(parsed.code, expected.set_name.upper())
        self.assertIs(reference(IP, True, GEOIP_FILE_NAME, "ru").standard_kind, GeoDatabaseKind.GEOIP)
        self.assertIs(reference(DOMAIN, False, GEOSITE_FILE_NAME, "ru").standard_kind, GeoDatabaseKind.GEOSITE)
        self.assertIsNone(reference(DOMAIN, True, "sites.dat", "ru").standard_kind)

    def test_values_xray_would_reject_become_unsupported_and_others_are_not_references(self):
        unsupported = (
            listed("geoip:"), listed("geoip:!"), listed("ext:"), listed("ext::ru"), listed("ext:custom.dat:"),
            listed("ext:a:b:c"), listed("ext:custom.dat:!"), listed("ext-ip:a:b:c"), listed("geoip:r\x00u"),
            listed("geosite:", DOMAIN), listed("geosite:@cn", DOMAIN), listed("ext::x", DOMAIN),
            listed("ext:a:b:c", DOMAIN), listed("ext:a:", DOMAIN), listed("ext-domain:a:", DOMAIN),
            listed("geosite:\tx", DOMAIN),
        )
        for value in unsupported:
            with self.subTest(value=value.value), forbid_external_effects():
                parsed = parse_geo_reference(value)
            self.assertEqual(parsed, UnsupportedGeoReference(PART, value.path, value.family))
            self.assertNotIn(value.value, repr(parsed) + repr(value))
        plain = (
            listed("192.0.2.0/24"), listed("*"), listed("GEOIP:ru"), listed("ext-domain:custom.dat:ru"),
            listed("ext-ip:x.dat:ru", qualified=False), listed("domain:ru", DOMAIN), listed("GEOSITE:ru", DOMAIN),
            listed("ext-ip:custom.dat:ru", DOMAIN), listed("ext-domain:sites.dat:ru", DOMAIN, qualified=False),
            listed("", DOMAIN), listed("", IP),
        )
        for value in plain:
            with self.subTest(value=value.value):
                self.assertIsNone(parse_geo_reference(value))
        for broken in ("geoip:ru", None, ("05_routing.json", "p", IP, True, "geoip:ru")):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(GeoDataError) as caught:
                parse_geo_reference(broken)
            self.assertIs(caught.exception.code, GeoDataErrorCode.REFERENCE)

    def test_reference_invariants_and_hidden_values(self):
        unsafe = reference(IP, True, "../fixture-private.dat", "fixture-private-set")
        self.assertFalse(unsafe.file_name_safe)
        self.assertIsNone(unsafe.standard_kind)
        self.assertNotIn("fixture-private", repr(unsafe) + repr(UnsupportedGeoReference(PART, "p", IP)))
        for build in (
            lambda: reference(DOMAIN, False, GEOSITE_FILE_NAME, "ru", negated=True),
            lambda: reference(IP, False, GEOIP_FILE_NAME, "ru", attributes=("a",)),
            lambda: GeoReference("bad/part", "p", IP, False, GEOIP_FILE_NAME, "ru"),
            lambda: GeoReference(PART, "", IP, False, GEOIP_FILE_NAME, "ru"),
            lambda: GeoReference(PART, "p\n", IP, False, GEOIP_FILE_NAME, "ru"),
            lambda: GeoReference(PART, "p", "ip", False, GEOIP_FILE_NAME, "ru"),
            lambda: GeoReference(PART, "p", IP, 1, GEOIP_FILE_NAME, "ru"),
            lambda: GeoReference(PART, "p", IP, False, "", "ru"),
            lambda: GeoReference(PART, "p", IP, False, None, "ru"),
            lambda: GeoReference(PART, "p", IP, False, GEOIP_FILE_NAME, " "),
            lambda: GeoReference(PART, "p", IP, False, GEOIP_FILE_NAME, "ru", negated=1),
            lambda: GeoReference(PART, "p", DOMAIN, False, GEOSITE_FILE_NAME, "ru", attributes=["a"]),
            lambda: GeoReference(PART, "p", DOMAIN, False, GEOSITE_FILE_NAME, "ru", attributes=(1,)),
            lambda: GeoReference(PART, "p", DOMAIN, False, GEOIP_FILE_NAME, "ru"),
            lambda: GeoReference(PART, "p", IP, False, GEOSITE_FILE_NAME, "ru"),
            lambda: GeoReference(PART, "p", IP, False, "custom.dat", "ru"),
            lambda: UnsupportedGeoReference("bad/part", "p", IP),
            lambda: UnsupportedGeoReference(PART, "", IP),
            lambda: UnsupportedGeoReference(PART, "p", "ip"),
        ):
            with self.subTest(case=build.__code__.co_firstlineno):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(GeoDataError) as caught:
                        build()
                self.assertIs(caught.exception.code, GeoDataErrorCode.REFERENCE)
                self.assertIsNone(caught.exception.__context__)
        with self.assertRaises(FrozenInstanceError):
            unsafe.negated = True

    def test_references_are_collected_from_rules_dns_servers_and_hosts(self):
        snapshot_config = snapshot_xray_config()
        with forbid_external_effects():
            snapshot = geo_references(snapshot_config)
        self.assertEqual(snapshot, (GeoReference(PART, "routing.rules[6].ip[0]", IP, False, GEOIP_FILE_NAME, "ru"),))
        config = XrayConfigSet((
            part("01_dns.json", {"dns": {"servers": [
                "198.51.100.53",
                {"address": "198.51.100.54", "domains": ["geosite:cn", "domain:fixture-private.example", "ext:custom.dat:list"],
                 "expectIPs": "geoip:cn,geoip:!private", "unexpectedIPs": ["*", "ext-ip:custom.dat:ru"]},
                7,
            ], "hosts": {
                "geosite:fixture": "127.0.0.1", "ext:hosts.dat:x": ["127.0.0.1"], "ext-domain:hosts.dat:x": "127.0.0.1",
                "fixture-private.example": "127.0.0.1",
            }}}),
            part("02_routing.json", {"routing": {"rules": [{
                "type": "field", "domain": "geosite:ru@attr,ext-domain:a.dat:b", "domains": ["geosite:extra"],
                "ip": ["geoip:ru", "ext:", "198.51.100.0/24"], "sourceIP": "ext-ip:s.dat:x",
                "localIP": ["geoip:private"], "outboundTag": "direct",
            }, {"type": "field", "domain": 7, "ip": [5, "geoip:us"], "outboundTag": "direct"},
               {"type": "field", "sourceIP": None, "source": ["geoip:!ru"], "outboundTag": "direct"}]}}),
        ))
        with forbid_external_effects():
            references = geo_references(config)
        dns, routing = "01_dns.json", "02_routing.json"
        self.assertEqual(references, (
            GeoReference(dns, "dns.servers[1].domains[0]", DOMAIN, False, GEOSITE_FILE_NAME, "cn"),
            GeoReference(dns, "dns.servers[1].domains[2]", DOMAIN, True, "custom.dat", "list"),
            GeoReference(dns, "dns.servers[1].expectIPs[0]", IP, False, GEOIP_FILE_NAME, "cn"),
            GeoReference(dns, "dns.servers[1].expectIPs[1]", IP, False, GEOIP_FILE_NAME, "private", negated=True),
            GeoReference(dns, "dns.servers[1].unexpectedIPs[1]", IP, True, "custom.dat", "ru"),
            GeoReference(dns, "dns.hosts[0]", DOMAIN, False, GEOSITE_FILE_NAME, "fixture"),
            GeoReference(dns, "dns.hosts[1]", DOMAIN, True, "hosts.dat", "x"),
            GeoReference(routing, "routing.rules[0].domain[0]", DOMAIN, False, GEOSITE_FILE_NAME, "ru", attributes=("attr",)),
            GeoReference(routing, "routing.rules[0].domain[1]", DOMAIN, True, "a.dat", "b"),
            GeoReference(routing, "routing.rules[0].domains[0]", DOMAIN, False, GEOSITE_FILE_NAME, "extra"),
            GeoReference(routing, "routing.rules[0].ip[0]", IP, False, GEOIP_FILE_NAME, "ru"),
            UnsupportedGeoReference(routing, "routing.rules[0].ip[1]", IP),
            GeoReference(routing, "routing.rules[0].sourceIP[0]", IP, True, "s.dat", "x"),
            GeoReference(routing, "routing.rules[0].localIP[0]", IP, False, GEOIP_FILE_NAME, "private"),
            GeoReference(routing, "routing.rules[1].ip[1]", IP, False, GEOIP_FILE_NAME, "us"),
            GeoReference(routing, "routing.rules[2].source[0]", IP, False, GEOIP_FILE_NAME, "ru", negated=True),
        ))
        self.assertNotIn("fixture-private", repr(references))
        for broken in (None, config.parts, "fixture-private"):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(GeoDataError) as caught:
                geo_references(broken)
            self.assertIs(caught.exception.code, GeoDataErrorCode.REFERENCE)


class GeoDataStateTests(unittest.TestCase):
    def setUp(self):
        self.inventory = synthetic_geo_inventory()
        self.config = XrayConfigSet((
            part(PART, {"routing": {"rules": [
                {"type": "field", "ip": ["geoip:ru", "geoip:RU", "ext:unknown.dat:x", "ext:../fixture-private.dat:x", "geoip:"],
                 "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:fixture-private-set"], "outboundTag": "direct"},
            ]}}),
        ))

    def test_resolution_statuses_and_diagnostic_without_set_names(self):
        with forbid_external_effects():
            state = assemble_geodata_state(self.inventory, self.config)
            resolutions = state.resolve()
            diagnostic = state.to_diagnostic()
        self.assertEqual(
            [item.status for item in resolutions],
            [GeoFileStatus.PRESENT, GeoFileStatus.PRESENT, GeoFileStatus.UNKNOWN, GeoFileStatus.UNKNOWN, GeoFileStatus.MISSING],
        )
        self.assertIs(resolutions[0].file, self.inventory.files[0])
        self.assertIsNone(resolutions[2].file)
        self.assertEqual([item["reference_count"] for item in diagnostic["files"]], [2, 1])
        self.assertEqual([item["set_count"] for item in diagnostic["files"]], [1, 1])
        self.assertEqual(diagnostic["files"][0]["source"], SYNTHETIC_GEOIP_SOURCE)
        self.assertEqual(
            (diagnostic["present_count"], diagnostic["missing_count"], diagnostic["extra_count"]), (1, 1, 0),
        )
        self.assertEqual(
            (diagnostic["reference_count"], diagnostic["resolved_count"], diagnostic["unresolved_count"]), (5, 2, 3),
        )
        self.assertEqual(diagnostic["references"][0], {
            "part": PART, "path": "routing.rules[0].ip[0]", "family": "ip", "external": False,
            "file_name": GEOIP_FILE_NAME, "file_status": "present", "negated": False, "attribute_count": 0,
        })
        self.assertEqual(diagnostic["references"][2]["file_name"], "unknown.dat")
        self.assertIsNone(diagnostic["references"][3]["file_name"])
        self.assertEqual(diagnostic["references"][3]["file_status"], "unknown")
        self.assertEqual(diagnostic["references"][4]["file_status"], "missing")
        self.assertEqual(diagnostic["unsupported_references"], [{"part": PART, "path": "routing.rules[0].ip[4]", "family": "ip"}])
        self.assertEqual(json.loads(json.dumps(diagnostic)), diagnostic)
        text = json.dumps(diagnostic, ensure_ascii=False) + repr(state) + repr(resolutions) + repr(state.references)
        for private in ("fixture-private", "../", '"ru"', '"RU"', "geoip:", "geosite:"):
            self.assertNotIn(private, text)
        self.assertEqual(repr(state), "GeoDataState(files=2, references=6)")
        with self.assertRaises(FrozenInstanceError):
            state.references = ()

    def test_state_validation_detects_tampering_and_foreign_types(self):
        state = assemble_geodata_state(self.inventory, self.config)
        validate_geodata_state(state)
        self.assertEqual(GeoDataState(self.inventory, ()).to_diagnostic()["reference_count"], 0)

        class Derived(GeoDataState):
            pass

        for broken in (Derived(self.inventory, ()), None, (self.inventory, ())):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(GeoDataError) as caught:
                validate_geodata_state(broken)
            self.assertIs(caught.exception.code, GeoDataErrorCode.STATE)
        for references, code in (
            (list(state.references), GeoDataErrorCode.STATE), (("fixture-private",), GeoDataErrorCode.STATE),
            ((None,), GeoDataErrorCode.STATE),
        ):
            with self.subTest(references=type(references[0]).__name__):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(GeoDataError) as caught:
                        GeoDataState(self.inventory, references)
                self.assertIs(caught.exception.code, code)
                self.assertIsNone(caught.exception.__context__)
        with self.assertRaises(GeoDataError) as caught:
            GeoDataState(None, ())
        self.assertIs(caught.exception.code, GeoDataErrorCode.INVENTORY)
        with self.assertRaises(GeoDataError) as caught:
            assemble_geodata_state(self.inventory, None)
        self.assertIs(caught.exception.code, GeoDataErrorCode.REFERENCE)
        # Повреждённое поле ссылки отклоняет сама ссылка; подмена семейства без смены
        # файла противоречит правилу «geoip: из geoip.dat, geosite: из geosite.dat».
        for index, field_name, value, code in (
            (0, "negated", 1, GeoDataErrorCode.REFERENCE), (0, "set_name", "", GeoDataErrorCode.REFERENCE),
            (0, "family", DOMAIN, GeoDataErrorCode.REFERENCE), (0, "external", 1, GeoDataErrorCode.REFERENCE),
            (4, "path", "", GeoDataErrorCode.REFERENCE),
        ):
            with self.subTest(index=index, field=field_name):
                tampered = assemble_geodata_state(self.inventory, self.config)
                object.__setattr__(tampered.references[index], field_name, value)
                with self.assertRaises(GeoDataError) as caught:
                    validate_geodata_state(tampered)
                self.assertIs(caught.exception.code, code)
        tampered = assemble_geodata_state(self.inventory, self.config)
        object.__setattr__(tampered.inventory.files[0], "sha256", SYNTHETIC_GEOIP_SHA256.upper())
        with self.assertRaises(GeoDataError) as caught:
            validate_geodata_state(tampered)
        self.assertIs(caught.exception.code, GeoDataErrorCode.INVENTORY)

    def test_resolution_cost_is_linear_in_references(self):
        timings = []
        for size in (2000, 8000):
            values = [f"geoip:set-{index}" if index % 2 else "ext:unknown.dat:x" for index in range(size)]
            state = assemble_geodata_state(self.inventory, routing_config(*values))
            # Сопоставление не ищет файл по списку для каждой ссылки: индекс строится один раз.
            with patch.object(GeoDatabaseInventory, "file", autospec=True, side_effect=GeoDatabaseInventory.file) as lookup:
                best = min(self._timed(state.to_diagnostic) for _ in range(3))
            self.assertEqual(lookup.call_count, 0)
            timings.append(best)
            diagnostic = state.to_diagnostic()
            self.assertEqual(diagnostic["reference_count"], size)
            self.assertEqual(diagnostic["files"][0]["set_count"], size // 2)
        # При квадратичной стоимости четырёхкратный рост дал бы примерно шестнадцатикратное время.
        self.assertLess(timings[1], timings[0] * 10 + 0.2)

    @staticmethod
    def _timed(action):
        started = time.perf_counter()
        action()
        return time.perf_counter() - started


if __name__ == "__main__":
    unittest.main()
