"""Локальная проверка кандидата на управляемых источниках в памяти."""

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import NEXT_STEP_MESSAGES, NextStepCode
from keenvpn.application.draft_candidate import (
    CheckDraftCandidate, CheckDraftCandidateHandler, DraftCandidate, GeoCategoryCatalog,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.geodata import GeoDatabaseInventory, GeoDataError, GeoDataErrorCode
from keenvpn.domain.routing import GeoDatabase, GeoDatabaseKind
from keenvpn.domain.routing_import import ImportReason, import_routing_scheme, inspect_routing_declarations
from keenvpn.domain.routing_order import OverlapKind, RuleOverlap, rule_overlaps
from keenvpn.domain.source_baseline import BaselineSource
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet, candidate_references
from tests.support.in_memory import InMemoryDraftSessionStore, InMemoryGeoDatabaseSource
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_MARKERS, reachable, unsafe_xray_config
from tests.test_application_draft_baseline_check import FIRST_ID, OPERATION, current_fingerprints, draft_bytes, token
from tests.test_application_quick_check import inventory
from tests.test_xray_api_target import config as api_config


OUT = {"tag": "TEST_direct", "protocol": "freedom"}
FINAL = {"network": "tcp,udp", "outboundTag": "TEST_direct"}


def config(*documents):
    return XrayConfigSet(tuple(ConfigDocument(f"{i}_TEST_part.json", json.dumps(doc).encode())
                               for i, doc in enumerate(documents)))


def rules(*items, **routing):
    return {"outbounds": [OUT], "routing": {"rules": [*items, FINAL], **routing}}


class DraftCandidateTests(unittest.TestCase):
    def setUp(self):
        self.raw = draft_bytes()
        self.store = InMemoryDraftSessionStore(self.raw)
        self.sources = current_fingerprints()
        self.files = InMemoryGeoDatabaseSource(inventory(True, True))
        self.catalogs = ()
        self.candidate = DraftCandidate(
            config(rules()), parse_xkeen_init(b'proxy_dns="off"\nproxy_router="on"\n'),
            XKeenList(XKeenListName.PORT_EXCLUDE, b""), XKeenList(XKeenListName.PORT_PROXYING, b""),
        )

    def run_check(self, **fields):
        handler = CheckDraftCandidateHandler(
            self.store, self.sources, self.files, self.catalogs, operation_ids=lambda: OPERATION,
        )
        command = CheckDraftCandidate(draft_id=FIRST_ID, expected_revision=token(self.raw),
                                      candidate=replace(self.candidate, **fields))
        with forbid_external_effects():
            result = handler.execute(command)
        self.assertEqual(self.store.create_calls, ())
        self.assertEqual(self.store.remove_calls, ())
        return result

    def test_geodata_error_with_unregistered_code_has_no_private_chain(self):
        xray = config(rules({"domain": "geosite:TEST_SITE", "outboundTag": OUT["tag"]}))
        error = GeoDataError(GeoDataErrorCode.INVENTORY)
        error.args = ("TEST_private_source",)
        error.__cause__ = OSError("TEST_private_cause")
        error.code = None
        self.files.outcome = error
        result = self.run_check(xray=xray)
        self.check_item(result, "candidate_geo_categories", "not_checked", "invalid_geo_databases")
        self.assertFalse(any(isinstance(item, BaseException) for item in reachable(result)))
        self.assertNotIn("TEST_", json.dumps(result.to_dict()))

    def test_unicode_geo_reference_cannot_match_another_ascii_category(self):
        db = self.files.outcome.standard(GeoDatabaseKind.GEOSITE).database(GeoDatabaseKind.GEOSITE)
        self.catalogs = (GeoCategoryCatalog(db, frozenset({"SS"})),)
        xray = config({**rules(), "dns": {"servers": [{"address": "198.51.100.1", "domains": ["geosite:ß"]}]}})
        result = self.run_check(xray=xray, geo_revisions=(db,))
        self.check_item(result, "candidate_geo_categories", "not_checked", "candidate_references_incomplete")
        self.assertEqual(result.data.outcome, "incomplete")
        self.assertIs(result.data.next_step.code, NextStepCode.CONSULT_DOCUMENTATION)

    def test_geo_incompleteness_priority_is_independent_of_reference_order(self):
        db = self.files.outcome.standard(GeoDatabaseKind.GEOSITE).database(GeoDatabaseKind.GEOSITE)
        self.catalogs = (GeoCategoryCatalog(db, frozenset({"TEST_SITE"})),)
        for first, second, reason, step in (
            ("ext:TEST_extra.dat:A", "geosite:ß", "file_not_inventoried", NextStepCode.CHECK_SOURCE),
            ("geosite:TEST_SITE", "geosite:ß", "geo_revision_unknown", NextStepCode.REVIEW_DRAFT),
        ):
            for domains in ((first, second), (second, first)):
                with self.subTest(domains=domains):
                    dns = {"servers": [{"address": "198.51.100.1", "domains": list(domains)}]}
                    result = self.run_check(xray=config({**rules(), "dns": dns}))
                    self.check_item(result, "candidate_geo_categories", "not_checked", reason)
                    self.assertIs(result.data.next_step.code, step)

    def test_derived_document_fields_cannot_override_candidate_bytes(self):
        class ForeignText(str):
            def __ne__(self, other):
                return False

        invalid = config(rules({"ip": "198.51.100.1", "outboundTag": "TEST_missing"}))
        good = config(rules()).parts[0]
        for field in ("_snapshot", "sha256"):
            with self.subTest(field=field):
                doc = ConfigDocument(invalid.parts[0].name, invalid.parts[0].content)
                candidate = XrayConfigSet((doc,))
                object.__setattr__(doc, field, ForeignText(getattr(good, field)))
                self.assertEqual(self.run_check(xray=candidate).error.code, "invalid_command")

    def test_unregistered_geo_kind_cannot_supply_evidence_or_a_revision(self):
        db = self.files.outcome.standard(GeoDatabaseKind.GEOSITE).database(GeoDatabaseKind.GEOSITE)
        forged = replace(db, kind=str.__new__(GeoDatabaseKind, db.kind.value))
        xray = config(rules({"domain": "geosite:TEST_SITE", "outboundTag": OUT["tag"]}))
        self.catalogs = (GeoCategoryCatalog(forged, frozenset({"TEST_SITE"})),)
        self.check_item(self.run_check(xray=xray, geo_revisions=(db,)), "candidate_geo_categories",
                        "not_checked", "geo_categories_unverified")
        self.catalogs = (GeoCategoryCatalog(db, frozenset({"TEST_SITE"})),)
        self.assertEqual(self.run_check(xray=xray, geo_revisions=(forged,)).error.code, "invalid_command")

    def test_incomplete_catalog_model_gives_an_unverified_category(self):
        db = self.files.outcome.standard(GeoDatabaseKind.GEOSITE).database(GeoDatabaseKind.GEOSITE)
        xray = config(rules({"domain": "geosite:TEST_SITE", "outboundTag": OUT["tag"]}))
        for field in ("database", "categories", "kind", "sha256", "reference"):
            with self.subTest(field=field):
                catalog = GeoCategoryCatalog(replace(db), frozenset({"TEST_SITE"}))
                owner = catalog if field in ("database", "categories") else catalog.database
                object.__delattr__(owner, field)
                self.catalogs = (catalog,)
                result = self.run_check(xray=xray, geo_revisions=(db,))
                self.assertEqual(result.data.outcome, "incomplete")
                self.check_item(result, "candidate_geo_categories", "not_checked", "geo_categories_unverified")

    def test_missing_command_fields_are_rejected_before_reads(self):
        handler = CheckDraftCandidateHandler(self.store, self.sources, self.files, operation_ids=lambda: OPERATION)
        for field in ("contract_version", "draft_id", "expected_revision", "candidate"):
            with self.subTest(field=field):
                command = CheckDraftCandidate(draft_id=FIRST_ID, expected_revision=token(self.raw),
                                              candidate=self.candidate)
                object.__delattr__(command, field)
                with forbid_external_effects():
                    result = handler.execute(command)
                self.assertEqual(result.error.code, "invalid_command")
                self.assertIsNone(result.data)
        self.assertFalse(self.sources.calls or self.files.calls or self.store.read_calls)

    def test_unicode_tail_marker_uses_the_same_outbound_replacement_as_ascii(self):
        first = config(rules()).parts[0]
        raw = json.dumps({"outbounds": [{"tag": "TEST_next", "protocol": "freedom"},
                                        {"tag": "TEST_next", "protocol": "blackhole"}]}).encode()
        for name in ("02_TAIL.json", "02_TAİL.json"):
            with self.subTest(name=name):
                candidate = XrayConfigSet((first, ConfigDocument(name, raw)))
                self.assertEqual(self.run_check(xray=candidate).data.outcome, "passed")

    def test_valid_candidate_and_effective_routing_only(self):
        replaced = rules({"domain": "geosite:TEST_missing", "outboundTag": "TEST_missing"})
        result = self.run_check(xray=config(replaced, rules(), {"routing": None}))
        self.assertEqual(result.data.outcome, "passed")
        self.assertEqual(self.files.calls, 0)

    def check_item(self, result, code, status, reason):
        self.assertTrue(result.succeeded, result.error)
        item = next(item for item in result.data.checks.items if item.code == code)
        self.assertEqual((item.status.value, item.reason), (status, reason))

    def test_rule_targets_and_unused_declarations(self):
        rule = {"domain": ["domain:example.test"], "outboundTag": "TEST_missing"}
        conflict = rules()
        conflict["api"] = {"tag": OUT["tag"]}
        for document, reason in (
            (rules(rule), "target_unresolved"),
            (rules({**rule, "balancerTag": "TEST_group"}), "target_ambiguous"),
            (rules({**rule, "outboundTag": ""}), "target_missing"),
            (rules(balancers=[{"tag": "TEST_group", "selector": "TEST_none"}]), "balancer_empty"),
            (rules(balancers=[{"tag": "TEST_group", "selector": "TEST_", "fallbackTag": "TEST_missing"}]),
             "fallback_unresolved"),
            ({**rules(), "outbounds": [OUT, OUT]}, "target_duplicate"),
            (conflict, "target_duplicate"),
        ):
            with self.subTest(reason=reason):
                result = self.run_check(xray=config(document))
                self.check_item(result, "candidate_targets", "failed", reason)
                self.assertEqual(result.data.outcome, "failed")

    def test_effective_outbounds_and_empty_alternative(self):
        first = rules({"domain": "full:example.test", "balancerTag": "TEST_group", "outboundTag": ""},
                      balancers=[{"tag": "TEST_group", "selector": "TEST_", "fallbackTag": OUT["tag"]}])
        first["outbounds"] = [{"tag": OUT["tag"], "protocol": "TEST_unknown"}]
        xray = config(first, {"outbounds": [OUT]})
        self.assertEqual(self.run_check(xray=xray).data.outcome, "passed")

    def test_empty_conditions_and_case_variant_are_distinct(self):
        for conditions, status, reason in (({"domain": []}, "failed", "values_empty"),
                                           ({}, "failed", "rule_without_conditions"),
                                           ({"DOMAIN": ["domain:example.test"]}, "unsupported", "field_case_variant")):
            with self.subTest(reason=reason):
                result = self.run_check(xray=config(rules({**conditions, "outboundTag": OUT["tag"]})))
                self.check_item(result, "candidate_schema", status, reason)

    def test_service_api_and_client_api_resolve_without_rewriting(self):
        # Обезличенная модель уже содержит исходный loopback служебного inbound.
        service = api_config()
        payload = tuple(p.content for p in service.parts)
        service_result = self.run_check(xray=service)
        self.assertEqual(service_result.data.outcome, "passed")
        self.assertEqual(payload, tuple(p.content for p in service.parts))
        client = rules({"inboundTag": ["TEST_client"], "outboundTag": "TEST_api"})
        client.update(api={"tag": "TEST_api"}, inbounds=[{"tag": "TEST_client", "listen": "198.51.100.1"}])
        result = self.run_check(xray=config(client))
        self.check_item(result, "candidate_targets", "passed", None)
        self.assertEqual(result.data.outcome, "incomplete")
        client["inbounds"] = []
        self.check_item(self.run_check(xray=config(client)), "candidate_targets", "failed", "missing_inbound")

    def test_idna_domain_and_network_overlaps_keep_first_rule(self):
        values = [
            {"domain": "domain:xn--p1ai"}, {"domain": "full:example.xn--p1ai"},
            {"ip": "198.51.100.0/24"}, {"ip": "198.51.100.1"}, {"ip": "2001:db8::1"},
        ]
        doc = rules(*({**v, "outboundTag": OUT["tag"]} for v in values))
        result = self.run_check(xray=config(doc))
        self.assertEqual([(w.earlier, w.later, w.kind.value) for w in result.data.warnings],
                         [(0, 1, "condition_covered"), (2, 3, "condition_covered")])
        self.assertEqual(result.data.outcome, "passed")

    def test_early_catch_all_and_noncanonical_unicode(self):
        self.check_item(self.run_check(xray=config(rules(FINAL))), "candidate_rule_order", "failed", "catch_all_not_last")
        result = self.run_check(xray=config(rules({"domain": "domain:рф", "outboundTag": OUT["tag"]})))
        self.check_item(result, "candidate_rule_order", "unsupported", "domain_not_canonical")

    def test_geo_revisions_categories_and_evidence(self):
        file = self.files.outcome.standard(GeoDatabaseKind.GEOSITE)
        db = file.database(GeoDatabaseKind.GEOSITE)
        xray = config(rules({"domain": "geosite:test_group", "outboundTag": OUT["tag"]}))
        good = GeoCategoryCatalog(db, frozenset({"TEST_GROUP"}))
        for catalogs, revisions, status, reason in (
            ((good,), (db,), "passed", None),
            ((), (db,), "not_checked", "geo_categories_unverified"),
            ((good,), (), "not_checked", "geo_revision_unknown"),
            ((replace(good, categories=None),), (db,), "failed", "corrupt_geo_file"),
            ((replace(good, categories=frozenset()),), (db,), "failed", "geo_category_missing"),
            ((good,), (replace(db, sha256="ab" * 32),), "failed", "geo_revision_changed"),
            ((replace(good, database=replace(db, sha256="ab" * 32)),), (db,), "not_checked", "geo_categories_unverified"),
        ):
            with self.subTest(reason=reason):
                self.catalogs = catalogs
                result = self.run_check(xray=xray, geo_revisions=revisions)
                self.check_item(result, "candidate_geo_categories", status, reason)
        self.files.outcome = inventory(True, False)
        self.check_item(self.run_check(xray=xray), "candidate_geo_categories", "failed", "missing_geo_file")

    def test_geoip_and_domain_zones_are_independent(self):
        db = self.files.outcome.standard(GeoDatabaseKind.GEOIP).database(GeoDatabaseKind.GEOIP)
        self.catalogs = (GeoCategoryCatalog(db, frozenset({"RU"})),)
        zones = {"domain": ["domain:ru", "domain:su", "domain:xn--p1ai"], "outboundTag": OUT["tag"]}
        geo = {"ip": "geoip:ru", "outboundTag": OUT["tag"]}
        for rule_list, warnings in (([geo, zones], ["earlier_geo_rule"]), ([zones], []), ([geo], [])):
            result = self.run_check(xray=config(rules(*rule_list)), geo_revisions=(db,))
            self.assertEqual(result.data.outcome, "passed")
            self.assertEqual([w.kind.value for w in result.data.warnings], warnings)

    def test_port_53_and_invalid_target_reported_together(self):
        for excluded, proxied, dns, status, reason in (
            (b"", b"", "on", "passed", None),
            (b"53", b"", "off", "passed", None),
            (b"50:55", b"53", "off", "failed", "port_53_in_both_lists"),
            (b"53", b"443", "off", "failed", "exclude_list_ignored"),
            (b"53", b"", "on", "failed", "proxy_dns_contradicts_exclusion"),
            (b"", b"", "TEST_unknown", "unsupported", "flags_unknown"),
        ):
            with self.subTest(reason=reason):
                result = self.run_check(
                    xray=config(rules({"ip": "198.51.100.1", "outboundTag": "TEST_missing"})),
                    init=parse_xkeen_init(f'proxy_dns="{dns}"\nproxy_router="on"\n'.encode()),
                    port_exclude=XKeenList(XKeenListName.PORT_EXCLUDE, excluded),
                    port_proxying=XKeenList(XKeenListName.PORT_PROXYING, proxied),
                )
                self.check_item(result, "dns_port_53_mode_consistent", status, reason)
                self.check_item(result, "candidate_targets", "failed", "target_unresolved")

    def test_revision_change_while_reading_and_invalid_input(self):
        invalid = self.run_check(port_exclude=self.candidate.port_proxying)
        self.assertEqual(invalid.error.code, "invalid_command")
        self.assertEqual(self.store.read_calls, 0)
        self.sources.hooks[BaselineSource.XRAY_CONFIGS] = lambda: setattr(self.store, "content", None)
        result = self.run_check()
        self.assertIsNone(result.data)
        self.assertEqual(result.error.code, "draft_revision_conflict")
        self.assertEqual(self.files.calls, 0)

    def test_privacy_and_failed_source(self):
        for xray in (unsafe_xray_config(), config(rules({"ip": "geoip:TEST_PRIVATE", "outboundTag": OUT["tag"]}))):
            self.files.outcome = OSError("/opt/etc/TEST_private")
            result = self.run_check(xray=xray)
            output = repr(result) + json.dumps(result.to_dict(), ensure_ascii=False)
            for marker in (*UNSAFE_MARKERS, "TEST_PRIVATE", "TEST_part.json"):
                self.assertNotIn(marker, output)
            self.assertFalse(any(isinstance(o, (DraftCandidate, XrayConfigSet, BaseException, GeoDatabase, bytes))
                                 for o in reachable(result)))
        self.check_item(result, "candidate_geo_categories", "not_checked", "geo_databases_unavailable")

    def test_schema_rejects_invalid_protocol_and_inbound_list_types(self):
        invalid = {**rules(), "outbounds": [OUT, {"tag": "TEST_unused", "protocol": 7}]}
        result = self.run_check(xray=config(invalid))
        self.check_item(result, "candidate_schema", "failed", "outbound_protocol_invalid")
        result = self.run_check(xray=config(rules({"inboundTag": 7, "outboundTag": OUT["tag"]})))
        self.check_item(result, "candidate_schema", "failed", "invalid_reference_structure")
        self.assertIsNotNone(result.data.to_dict()["next_step"])

    def test_dns_uses_only_effective_hosts_and_server_tags(self):
        db = self.files.outcome.standard(GeoDatabaseKind.GEOSITE).database(GeoDatabaseKind.GEOSITE)
        self.catalogs = (GeoCategoryCatalog(db, frozenset({"TEST_GROUP"})),)
        active = {"hosts": {"geosite:test_group": "198.51.100.1"}, "tag": "TEST_dns"}
        first = {**rules(), "dns": {"hosts": {"geosite:TEST_OLD": "198.51.100.2"}, "tag": "TEST_old"}}
        xray = config(first, {"dns": active}, {"dns": None})
        self.check_item(self.run_check(xray=xray, geo_revisions=(db,)), "candidate_geo_categories", "passed", None)
        bad = rules({"inboundTag": "TEST_old", "outboundTag": OUT["tag"]})
        self.check_item(self.run_check(xray=config(first, {**bad, "dns": active})),
                        "candidate_targets", "failed", "missing_inbound")

    def test_complete_diagnostics_require_coverage_of_the_declared_model(self):
        many = {"ip": ["198.51.100.1"] * 319, "outboundTag": OUT["tag"]}
        result = self.run_check(xray=config(rules(many)))
        self.check_item(result, "candidate_rule_order", "not_checked", "comparison_limit")
        self.assertEqual(result.data.outcome, "incomplete")

    def test_cannot_satisfy_a_geoip_reference_with_a_geosite_catalog(self):
        db = self.files.outcome.standard(GeoDatabaseKind.GEOIP).database(GeoDatabaseKind.GEOIP)
        self.catalogs = (GeoCategoryCatalog(replace(db, kind=GeoDatabaseKind.GEOSITE), frozenset({"RU"})),)
        result = self.run_check(xray=config(rules({"ip": "geoip:RU", "outboundTag": OUT["tag"]})), geo_revisions=(db,))
        self.check_item(result, "candidate_geo_categories", "not_checked", "geo_categories_unverified")
        object.__setattr__(db, "kind", GeoDatabaseKind.GEOIP.value)
        self.assertEqual(self.run_check(geo_revisions=(db,)).error.code, "invalid_command")

    def test_change_during_inventory_read_prevents_candidate_result(self):
        store = self.store

        class ChangingInventory(InMemoryGeoDatabaseSource):
            def current_geo_databases(self):
                store.content = None
                return super().current_geo_databases()

        self.files = ChangingInventory(self.files.outcome)
        result = self.run_check(xray=config(rules({"domain": "geosite:TEST_group", "outboundTag": OUT["tag"]})))
        self.assertIsNone(result.data)
        self.assertEqual(result.error.code, "draft_revision_conflict")

    def test_stale_source_and_token_use_existing_contract(self):
        from tests.test_application_draft_baseline_check import fingerprint
        self.sources.set_response(BaselineSource.XRAY_CONFIGS, fingerprint(BaselineSource.XRAY_CONFIGS, index=99))
        result = self.run_check()
        self.assertEqual(result.error.code, "draft_baseline_changed")
        self.assertEqual(result.error.next_step.code.value, "recreate_draft")
        self.assertIsNone(result.data)
        self.store.content = draft_bytes(TEST_extra="TEST_private")
        result = self.run_check()
        self.assertEqual(result.error.code, "draft_revision_conflict")
        self.assertNotIn("TEST_private", repr(result))

    def test_bad_reference_and_unknown_protocol_have_different_results(self):
        doc = rules({"domain": "geosite:", "outboundTag": OUT["tag"]})
        self.check_item(self.run_check(xray=config(doc)), "candidate_geo_categories", "failed", "invalid_geo_reference")
        doc = {**rules(), "outbounds": [{**OUT, "protocol": "TEST_transport"}]}
        result = self.run_check(xray=config(doc))
        self.check_item(result, "candidate_targets", "passed", None)
        self.check_item(result, "candidate_schema", "unsupported", "outbound_protocol_unsupported")
        self.assertEqual(result.data.outcome, "incomplete")

    def test_invalid_command_version_and_empty_input_do_not_read_sources(self):
        cmd = CheckDraftCandidate(draft_id=FIRST_ID, expected_revision=token(self.raw), candidate=self.candidate)
        handler = CheckDraftCandidateHandler(self.store, self.sources, self.files, operation_ids=lambda: OPERATION)
        for bad, code in ((object(), "invalid_command"), (replace(cmd, draft_id=""), "invalid_command"),
                          (replace(cmd, contract_version=2), "unsupported_contract_version")):
            with forbid_external_effects():
                result = handler.execute(bad)
            self.assertEqual(result.error.code, code)
        self.assertEqual(self.store.read_calls, 0)
        self.assertEqual(self.files.calls, 0)

    def test_nullable_fields_match_omitted_fields_without_changing_documents(self):
        server = {"address": "example.test"}
        rule = {"domain": "full:example.test", "outboundTag": OUT["tag"]}
        for field in ("tag", "hosts", "servers"):
            with self.subTest(dns=field):
                baseline = self.run_check(xray=config({**rules(), "dns": {}}))
                actual = self.run_check(xray=config({**rules(), "dns": {field: None}}))
                self.assertEqual(actual.to_dict(), baseline.to_dict())
        for field in ("tag", "domains", "expectedIPs", "expectIPs", "unexpectedIPs"):
            with self.subTest(server=field):
                baseline = self.run_check(xray=config({**rules(), "dns": {"servers": [server]}}))
                actual = self.run_check(xray=config({**rules(), "dns": {"servers": [{**server, field: None}]}}))
                self.assertEqual(actual.to_dict(), baseline.to_dict())
        for original in (rule, {"outboundTag": OUT["tag"]}):
            with self.subTest(rule=original):
                document = rules({**original, "inboundTag": None})
                candidate = config(document)
                baseline = self.run_check(xray=config(rules(original)))
                self.assertEqual(self.run_check(xray=candidate).to_dict(), baseline.to_dict())
                self.assertEqual(candidate.parts[0].export(), document)

    def test_null_outbound_tag_merges_as_empty_but_invalid_type_is_rejected(self):
        # Если tag:null не заменяет прежний безымянный outbound, остаётся
        # неиспользуемое объявление с неподдерживаемым протоколом.
        base = {**rules(), "outbounds": [OUT, {"protocol": "TEST_unknown"}]}
        for fields in ({}, {"tag": ""}, {"tag": None}):
            with self.subTest(fields=fields):
                xray = config(base, {"outbounds": [{"protocol": "freedom", **fields}]})
                self.assertEqual(self.run_check(xray=xray).data.outcome, "passed")
        invalid = {**rules(), "outbounds": [OUT, {"tag": 7, "protocol": "freedom"}]}
        self.check_item(self.run_check(xray=config(invalid)), "candidate_targets", "failed", "target_invalid")

    def test_overlap_across_rules_only_warns_and_keeps_checks_passed(self):
        small = {"domain": "full:sub.example.test", "outboundTag": OUT["tag"]}
        whole = {"domain": "domain:example.test", "outboundTag": OUT["tag"]}
        data = self.run_check(xray=config(rules(small, whole))).data
        self.assertEqual(data.warnings, (RuleOverlap(0, 1, OverlapKind.PARTIAL),))
        self.assertEqual(data.outcome, "passed")

    def test_duplicate_inbound_in_first_part_and_replacement_in_next(self):
        inbound = {"tag": "TEST_in", "protocol": "socks"}
        first = {**rules(), "inbounds": [inbound]}
        duplicate = {**first, "inbounds": [inbound, inbound]}
        result = self.run_check(xray=config(duplicate))
        self.check_item(result, "candidate_targets", "failed", "duplicate_inbound")
        self.assertEqual(result.data.outcome, "failed")
        replacement = self.run_check(xray=config(first, {"inbounds": [inbound, inbound]}))
        self.assertEqual(replacement.data.outcome, "passed")

    def test_geodata_source_coverage_and_zero_length_file(self):
        def georule(value):
            return config(rules({"ip": value, "outboundTag": OUT["tag"]}))

        unknown = self.run_check(xray=georule("ext:TEST_external.dat:TEST_set"))
        self.check_item(unknown, "candidate_geo_categories", "not_checked", "file_not_inventoried")
        self.assertEqual(unknown.data.outcome, "incomplete")
        files = self.files.outcome
        self.files.outcome = GeoDatabaseInventory(tuple(
            replace(item, size=0) if item.standard_kind is GeoDatabaseKind.GEOIP else item for item in files.files
        ))
        zero = self.run_check(xray=georule("geoip:ru"))
        self.check_item(zero, "candidate_geo_categories", "failed", "corrupt_geo_file")
        self.assertEqual(zero.data.outcome, "failed")
        self.files = None
        missing_source = self.run_check(xray=georule("geoip:ru"))
        self.check_item(missing_source, "candidate_geo_categories", "not_checked", "source_not_connected")
        self.assertEqual(missing_source.data.outcome, "incomplete")

    def test_schema_failure_limits_dependent_checks(self):
        result = self.run_check(xray=config({**rules(), "inbounds": 5}))
        self.check_item(result, "candidate_targets", "not_checked", "schema_incomplete")
        self.check_item(result, "candidate_geo_categories", "not_checked", "schema_incomplete")
        self.assertEqual(result.data.outcome, "failed")

    def test_unused_chained_outbound_keeps_resolved_rule_targets(self):
        chained = {"tag": "TEST_chain", "protocol": "freedom", "proxySettings": {"tag": OUT["tag"]}}
        result = self.run_check(xray=config({**rules(), "outbounds": [OUT, chained]}))
        self.check_item(result, "candidate_schema", "unsupported", "outbound_chained")
        self.check_item(result, "candidate_targets", "passed", None)
        self.assertEqual(result.data.outcome, "incomplete")

    def test_next_step_distinguishes_draft_source_and_static_limits(self):
        invalid = rules({"domain": "full:example.test", "outboundTag": "TEST_missing"})
        geo = rules({"ip": "geoip:RU", "outboundTag": OUT["tag"]})
        unsupported = rules({"network": "tcp", "outboundTag": OUT["tag"]})
        limited = rules({"ip": ["198.51.100.1"] * 317, "outboundTag": OUT["tag"]})
        for document, code in ((invalid, "review_draft"), (geo, "check_source"),
                               (unsupported, "consult_documentation"), (limited, "consult_documentation")):
            with self.subTest(code=code):
                data = self.run_check(xray=config(document)).data
                step = data.to_dict()["next_step"]
                self.assertEqual(step["code"], code)
                self.assertEqual(step["message"], NEXT_STEP_MESSAGES[NextStepCode(code)])
        self.assertEqual(self.run_check(xray=config(invalid)).data.next_step.message,
                         "Исправьте отмеченные ошибки в черновике и повторите проверку.")
        db = self.files.outcome.standard(GeoDatabaseKind.GEOIP).database(GeoDatabaseKind.GEOIP)
        stale = self.run_check(xray=config(geo), geo_revisions=(replace(db, sha256="ab" * 32),))
        self.assertEqual(stale.data.next_step.code, NextStepCode.OPEN_VIEW)
        self.catalogs = (GeoCategoryCatalog(db, frozenset({"RU"})),)
        no_revision = self.run_check(xray=config(geo))
        self.check_item(no_revision, "candidate_geo_categories", "not_checked", "geo_revision_unknown")
        self.assertEqual(no_revision.data.outcome, "incomplete")
        self.assertEqual(no_revision.data.next_step.code, NextStepCode.REVIEW_DRAFT)
        self.assertIsNone(self.run_check(xray=config(geo), geo_revisions=(db,)).data.next_step)
        self.assertIsNone(self.run_check().data.next_step)
        self.files.outcome = inventory(False, False)
        self.assertEqual(self.run_check(xray=config(geo)).data.next_step.code, NextStepCode.CHECK_SOURCE)


    def test_nullable_known_rule_fields_preserve_effective_conditions_and_final(self):
        ip = {"ip": ["198.51.100.0/24"], "outboundTag": OUT["tag"]}
        domain = {"domain": "full:example.test", "outboundTag": OUT["tag"]}
        for field, rule in (("domain", ip), ("domains", ip), ("ip", domain), ("network", ip),
                            ("port", FINAL), ("ruleTag", FINAL), ("balancerTag", FINAL)):
            with self.subTest(field=field):
                modified = {**rule, field: None}
                document = rules(modified) if rule is not FINAL else {**rules(), "routing": {"rules": [modified]}}
                baseline = rules(rule) if rule is not FINAL else rules()
                candidate = config(document)
                before = candidate.parts[0].content
                self.assertEqual(self.run_check(xray=candidate).to_dict(),
                                 self.run_check(xray=config(baseline)).to_dict())
                self.assertEqual(candidate.parts[0].content, before)
                self.assertEqual(candidate.parts[0].export(), document)
        only = self.run_check(xray=config(rules({"domain": None, "outboundTag": OUT["tag"]})))
        self.check_item(only, "candidate_schema", "failed", "rule_without_conditions")

    def test_unknown_and_case_variant_null_rules_are_still_incomplete(self):
        for field in ("TEST_unknown", "Domain", "Port"):
            with self.subTest(field=field):
                rule = {"ip": "198.51.100.1", field: None, "outboundTag": OUT["tag"]}
                data = self.run_check(xray=config(rules(rule))).data
                self.assertEqual(data.outcome, "incomplete")


    def test_effective_domain_strategy_rejects_non_string_values(self):
        for value in (7, False, {}, []):
            with self.subTest(value=value):
                result = self.run_check(xray=config(rules(domainStrategy=value)))
                self.check_item(result, "candidate_schema", "failed", "invalid_reference_structure")
                self.assertEqual(result.data.outcome, "failed")
        for value in ("IPIfNonMatch", "", None):
            with self.subTest(value=value):
                self.assertEqual(self.run_check(xray=config(rules(domainStrategy=value))).data.outcome, "passed")

    def test_numeric_rule_type_is_ignored_by_the_supported_decoder(self):
        document = {**rules(), "routing": {"rules": [{**FINAL, "type": 7}]}}
        self.assertEqual(self.run_check(xray=config(document)).to_dict(), self.run_check().to_dict())



class CandidateRoutingDomainTests(unittest.TestCase):
    def test_rule_overlaps_and_comparison_boundary(self):
        domain = {"domain": ["domain:example.test", "full:sub.example.test"], "outboundTag": OUT["tag"]}
        ip = {"ip": "198.51.100.1", "outboundTag": OUT["tag"]}
        subnet = {**ip, "ip": "198.51.100.0/24"}
        scheme = import_routing_scheme(config(rules(domain, ip, subnet, ip)))
        self.assertEqual(rule_overlaps(scheme), ((
            RuleOverlap(0, 0, OverlapKind.COVERED), RuleOverlap(1, 2, OverlapKind.PARTIAL),
            RuleOverlap(1, 3, OverlapKind.COVERED), RuleOverlap(2, 3, OverlapKind.COVERED),
        ), True))
        for count, complete in ((316, True), (317, False)):
            many = {**ip, "ip": [ip["ip"]] * count}
            scheme = import_routing_scheme(config(rules(many)))
            self.assertEqual(rule_overlaps(scheme), ((RuleOverlap(0, 0, OverlapKind.COVERED),), complete))

    def test_references_use_effective_dns_api_and_real_inbound_declarations(self):
        inbound = {"tag": "TEST_in", "protocol": "socks"}
        older = {"dns": {"tag": "TEST_old"}, "api": {}, "inbounds": [inbound]}
        names = ["TEST_global", "TEST_server", "TEST_in"]
        latest = {**rules({"inboundTag": names, "outboundTag": OUT["tag"]}),
                  "api": {"tag": "TEST_api"}, "inbounds": [inbound],
                  "dns": {"tag": "TEST_global", "servers": [{"tag": "TEST_server", "address": "example.test"}]}}
        refs = candidate_references(config(older, latest, {"api": None, "dns": None}))
        self.assertFalse(refs.schema_invalid or refs.missing_inbound or refs.duplicate_inbound)
        self.assertTrue(candidate_references(config(older, {**latest, "api": {}})).schema_invalid)
        self.assertTrue(candidate_references(config({**older, "inbounds": [inbound, inbound]}, latest)).duplicate_inbound)
        self.assertTrue(candidate_references(config(older, latest, {"dns": {"tag": "TEST_old"}})).missing_inbound)

    def test_declarations_share_the_imported_policy_and_include_unused_targets(self):
        chained = {"tag": "TEST_chain", "protocol": "freedom", "proxySettings": {"tag": OUT["tag"]}}
        balancer = {"tag": "TEST_pool", "selector": ["TEST_nowhere"], "fallbackTag": "TEST_missing"}
        xray = config({**rules(balancers=[balancer]), "outbounds": [OUT, chained]})
        scheme, reasons = inspect_routing_declarations(xray)
        self.assertEqual(scheme, import_routing_scheme(xray))
        self.assertEqual(scheme.final_group.target.tag, OUT["tag"])
        self.assertEqual(scheme.reasons, ())
        self.assertEqual(set(reasons), {ImportReason.OUTBOUND_CHAINED, ImportReason.BALANCER_EMPTY,
                                        ImportReason.FALLBACK_UNRESOLVED})

    def test_order_of_nested_values_matters_only_between_rules(self):
        for key, narrow, broad in (("domain", "full:a.example.test", "domain:example.test"),
                                   ("ip", "198.51.100.1", "198.51.100.0/24")):
            for first, second, between in ((narrow, broad, OverlapKind.PARTIAL), (broad, narrow, OverlapKind.COVERED)):
                with self.subTest(key=key, first=first):
                    same = config(rules({key: [first, second], "outboundTag": OUT["tag"]}))
                    separate = config(rules({key: first, "outboundTag": OUT["tag"]},
                                            {key: second, "outboundTag": OUT["tag"]}))
                    self.assertEqual(rule_overlaps(import_routing_scheme(same)),
                                     ((RuleOverlap(0, 0, OverlapKind.COVERED),), True))
                    self.assertEqual(rule_overlaps(import_routing_scheme(separate)), ((RuleOverlap(0, 1, between),), True))

    def test_geo_codes_ignore_case_only_for_the_same_kind_and_database(self):
        for first_key, first, second_key, second, kind in (
            ("domain", "geosite:TEST", "domain", "geosite:test", OverlapKind.COVERED),
            ("ip", "geoip:RU", "ip", "geoip:ru", OverlapKind.COVERED),
            ("ip", "geoip:RU", "ip", "geoip:TEST_other", OverlapKind.GEO),
            ("domain", "ext:TEST_a.dat:TEST", "domain", "ext:TEST_b.dat:test", OverlapKind.GEO),
            ("ip", "ext:TEST_a.dat:TEST", "domain", "ext:TEST_a.dat:test", OverlapKind.GEO),
        ):
            with self.subTest(first=first, second=second, second_key=second_key):
                xray = config(rules({first_key: first, "outboundTag": OUT["tag"]},
                                    {second_key: second, "outboundTag": OUT["tag"]}))
                self.assertEqual(rule_overlaps(import_routing_scheme(xray)), ((RuleOverlap(0, 1, kind),), True))
