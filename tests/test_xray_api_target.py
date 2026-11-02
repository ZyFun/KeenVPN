"""Тег раздела `api` Xray как назначение правила: сводка, импорт схемы, быстрая проверка и представления.

Части конфигурации обезличены и собираются прямо в тестах: снимок роутера
не меняется. Поведение декодера сверено с исходниками Xray-core v26.3.27:
`Config.Override` берёт раздел `api` последней части с не-`null` значением,
`APIConfig.Build` отклоняет пустой тег, `Commander.Start` регистрирует
обработчик API среди outbound по тегу, только если `listen` пуст. Роутер,
сеть и процессы не используются.
"""

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.checks import replaced_sections_repeated, xray_config_check
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler, XrayPositionView
from keenvpn.application.quick_check import QuickCheck, QuickCheckHandler
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler, RouteOutcome
from keenvpn.application.routing_import import ImportRoutingScheme, ImportRoutingSchemeHandler
from keenvpn.application.routing_rules import ListRoutingRules, ListRoutingRulesHandler, TargetPositionState
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.routing import RoutingAction
from keenvpn.domain.routing_explanation import destination_context, explain_route
from keenvpn.domain.routing_import import (
    ImportReason, RoutingImportError, RoutingImportErrorCode, RoutingScheme, RuleTarget, balancer_fallbacks,
    import_routing_scheme, validate_routing_scheme,
)
from keenvpn.domain.xray_config import (
    RuleTargetKind, XrayConfigSet, api_handler_conflict, api_handler_tag, config_case_variants,
    effective_api_section, summarize_xray_config, tag_repeats,
)
from keenvpn.interfaces.cli.presenters import (
    API_SERVICE_NOTE, TARGET_POSITION_LABELS, present_route_explanation, present_routing_scheme, present_rule_list,
)
from tests.support.in_memory import InMemoryManagerMetadataStore
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import UNSAFE_IDENTIFIERS, UNSAFE_MARKERS
from tests.support.snapshot import snapshot_proxy_sources


API_PART = "08_test_api.json"
LATER_API_PART = "09_test_api.json"
INBOUNDS = [{"tag": "test-api-in", "protocol": "dokodemo-door"}, {"tag": "test-lan", "protocol": "tunnel"}]
OUTBOUNDS = [
    {"tag": "test-proxy", "protocol": "trojan"},
    {"tag": "test-direct", "protocol": "freedom"},
    {"tag": "test-block", "protocol": "blackhole"},
]
API = {"tag": "test-api", "services": ["RoutingService"]}
LISTEN = "198.51.100.1:10085"
API_RULE = {"type": "field", "inboundTag": ["test-api-in"], "outboundTag": "test-api"}
"""Штатная схема Xray: трафик служебного inbound API направляется в обработчик API."""
FINAL = {"type": "field", "network": "tcp,udp", "outboundTag": "test-direct"}
RULES = [
    API_RULE,
    {"type": "field", "domain": ["domain:example.test"], "outboundTag": "test-proxy"},
    {"type": "field", "ip": ["198.51.100.0/24"], "outboundTag": "test-block"},
    FINAL,
]
POOL_RULES = [API_RULE, {"type": "field", "domain": ["domain:example.test"], "balancerTag": "test-pool"}, FINAL]
UNSAFE_TAG = UNSAFE_IDENTIFIERS["domain"]
UNSAFE_MARKER = "private.example"


def part(name, document):
    return ConfigDocument(name, json.dumps(document, ensure_ascii=False).encode("utf-8"))


def config(*, rules=RULES, outbounds=OUTBOUNDS, balancers=None, inbounds=INBOUNDS, api=API, api_parts=None):
    """Части по шаблону имени снимка: inbound, outbound, `routing` и части с разделом `api`.

    `api` — содержимое раздела единственной части `API_PART`; `api_parts` задаёт части целиком.
    """
    routing = {"rules": list(rules)}
    if balancers is not None:
        routing["balancers"] = list(balancers)
    if api_parts is None:
        api_parts = ((API_PART, {"api": api}),)
    parts = [
        part("03_inbounds.json", {"inbounds": inbounds}),
        part("04_outbounds.json", {"outbounds": outbounds}),
        part("05_routing.json", {"routing": routing}),
        *(part(name, document) for name, document in api_parts),
    ]
    return XrayConfigSet(tuple(sorted(parts, key=lambda item: item.name)))


def summary_rule(xray, index=0):
    return summarize_xray_config(xray.parts)["rules"][index]


def check_codes(xray):
    check = xray_config_check(xray)
    return check.status.value, check.reason


WITHOUT_HANDLER = {
    "нет раздела": {"api_parts": ()},
    "раздел null": {"api": None},
    "нет тега": {"api": {"services": ["RoutingService"]}},
    "пустой тег": {"api": {**API, "tag": ""}},
    "тег null": {"api": {**API, "tag": None}},
    "непустой listen": {"api": {**API, "listen": LISTEN}},
}
"""Конфигурации, где Xray не регистрирует обработчик API по тегу: правило в `test-api` цели не находит."""
INVALID_SECTIONS = {
    "раздел строка": ({"api": "test-api"}, "api"),
    "раздел список": ({"api": ["test-api"]}, "api"),
    "тег число": ({"api": {**API, "tag": 5}}, "api.tag"),
    "listen число": ({"api": {**API, "listen": 1}}, "api.listen"),
}
"""Разделы, которые декодер Xray не разберёт: место отмечается, обработчика нет."""
REPLACED_PARTS = ((API_PART, {"api": {"tag": "test-old"}}), (LATER_API_PART, {"api": API}))
"""Раздел `api` в двух частях: действует последний, тег первой части обработчика не даёт."""


class FalseUnresolvedRegressionTests(unittest.TestCase):
    """Ложная ошибка, найденная при приёмке на рабочем роутере: правило в тег API считалось неразрешённым."""

    def test_summary_resolves_rule_into_api_tag(self):
        with forbid_external_effects():
            rule = summary_rule(config())
        self.assertTrue(rule["target_resolved"])
        self.assertEqual("test-api", rule["target_tag"])
        self.assertIsNone(rule["target_position"])

    def test_quick_check_has_no_unresolved_references(self):
        with forbid_external_effects():
            self.assertEqual(("passed", None), check_codes(config()))

    def test_import_keeps_policy_and_has_no_unresolved_target(self):
        with forbid_external_effects():
            scheme = import_routing_scheme(config())
        self.assertNotIn(ImportReason.TARGET_UNRESOLVED, scheme.groups[0].target.reasons)
        self.assertNotIn(ImportReason.RULE_ACTION_UNRESOLVED, scheme.reasons)
        self.assertIsNotNone(scheme.policy)
        self.assertFalse(scheme.read_only)


class ApiSectionTests(unittest.TestCase):
    """Действующий раздел `api` и тег обработчика, как их видит декодер Xray."""

    def test_effective_section_is_the_last_non_null_one(self):
        first, second = {"tag": "test-a"}, {"tag": "test-b"}
        self.assertIs(second, effective_api_section([{"api": first}, {"api": second}, {"log": {}}]))
        self.assertIs(first, effective_api_section([{"api": first}, {"api": None}]))
        self.assertIsNone(effective_api_section([{"api": None}, {}]))
        self.assertIsNone(effective_api_section([]))

    def test_handler_tag_needs_non_empty_tag_and_empty_listen(self):
        cases = [
            (API, "test-api"), ({**API, "listen": None}, "test-api"), ({**API, "listen": ""}, "test-api"),
            ({**API, "listen": LISTEN}, None), ({}, None), ({"tag": ""}, None), ({"tag": None}, None),
            ({"tag": 5}, None), ({**API, "listen": 1}, None), ("test-api", None), (["test-api"], None), (None, None),
        ]
        for section, expected in cases:
            with self.subTest(section=section):
                self.assertEqual(expected, api_handler_tag(section))

    def test_constants_keep_stable_codes(self):
        self.assertEqual("api", RuleTargetKind.API.value)
        self.assertEqual("target_api", ImportReason.TARGET_API.value)
        self.assertEqual("api", TargetPositionState.API.value)
        self.assertIn(TargetPositionState.API, TARGET_POSITION_LABELS)


class ApiSummaryTests(unittest.TestCase):
    """Структурная сводка: правило в тег обработчика API разрешено без позиции."""

    def test_rule_into_handler_has_api_kind_and_others_keep_positions(self):
        rules = summarize_xray_config(config().parts)["rules"]
        self.assertEqual(
            ("api", True, "test-api", True, None),
            tuple(rules[0][key] for key in ("target_kind", "target_tag_known", "target_tag", "target_resolved", "target_position")),
        )
        self.assertTrue(rules[0]["inbound_tags_resolved"])
        self.assertEqual(("outbound", {"part": "04_outbounds.json", "index": 0}), (rules[1]["target_kind"], rules[1]["target_position"]))

    def test_without_registered_handler_the_rule_stays_unresolved(self):
        for name, options in WITHOUT_HANDLER.items():
            with self.subTest(name):
                summary = summarize_xray_config(config(**options).parts)
                self.assertEqual(("outbound", False), (summary["rules"][0]["target_kind"], summary["rules"][0]["target_resolved"]))
                self.assertEqual([], summary["unsupported_paths"])

    def test_invalid_sections_are_unsupported_places_without_handler(self):
        for name, (document, path) in INVALID_SECTIONS.items():
            with self.subTest(name):
                summary = summarize_xray_config(config(api_parts=((API_PART, document),)).parts)
                self.assertEqual([{"part": API_PART, "path": path}], summary["unsupported_paths"])
                self.assertFalse(summary["rules"][0]["target_resolved"])

    def test_last_section_replaces_earlier_and_null_does_not(self):
        old_rule = {**API_RULE, "outboundTag": "test-old"}
        summary = summarize_xray_config(config(rules=[API_RULE, old_rule, FINAL], api_parts=REPLACED_PARTS).parts)
        rules = summary["rules"]
        self.assertEqual(("api", True), (rules[0]["target_kind"], rules[0]["target_resolved"]))
        self.assertEqual(("outbound", False), (rules[1]["target_kind"], rules[1]["target_resolved"]))
        self.assertEqual([API_PART, LATER_API_PART], summary["sections"]["api"])
        kept = config(api_parts=((API_PART, {"api": API}), (LATER_API_PART, {"api": None})))
        self.assertEqual("api", summary_rule(kept)["target_kind"])

    def test_case_variants_of_section_and_read_fields_are_reported(self):
        variants = {
            "раздел": ({"API": API}, True), "тег": ({"api": {"Tag": "test-api"}}, True),
            "listen": ({"api": {**API, "LISTEN": ""}}, True), "services не читается": ({"api": {**API, "Services": []}}, False),
            "точные ключи": ({"api": API}, False),
        }
        for name, (document, expected) in variants.items():
            with self.subTest(name):
                self.assertIs(expected, config_case_variants(config(api_parts=((API_PART, document),)).parts))

    def test_handler_sharing_outbound_tag_is_ambiguous(self):
        shared = config(api={**API, "tag": "test-proxy"})
        rule = summary_rule(shared, 1)
        self.assertEqual(("outbound", True, None), (rule["target_kind"], rule["target_resolved"], rule["target_position"]))
        self.assertTrue(api_handler_conflict(shared.parts))
        listening = config(api={**API, "tag": "test-proxy", "listen": LISTEN})
        self.assertFalse(api_handler_conflict(listening.parts))
        self.assertEqual({"part": "04_outbounds.json", "index": 0}, summary_rule(listening, 1)["target_position"])

    def test_inbound_and_balancer_with_handler_tag_do_not_conflict(self):
        xray = config(
            inbounds=[*INBOUNDS, {"tag": "test-api", "protocol": "dokodemo-door"}],
            balancers=[{"tag": "test-api", "selector": ["test-proxy"]}],
        )
        self.assertEqual("api", summary_rule(xray)["target_kind"])
        self.assertFalse(api_handler_conflict(xray.parts))
        repeats = tag_repeats(xray.parts)
        self.assertEqual(((), ()), (repeats.within_parts, repeats.between_parts))

    def test_balancer_fields_of_the_summary_still_count_outbounds_only(self):
        """Граница задачи: сводка балансировщиков обработчик API не учитывает, это делает импорт."""
        balancer = summarize_xray_config(config(balancers=[
            {"tag": "test-pool", "selector": ["test-api", "test-proxy"], "fallbackTag": "test-api"},
        ]).parts)["balancers"][0]
        self.assertEqual((1, False, None), (
            balancer["selector_match_count"], balancer["fallback_resolved"], balancer["fallback_position"],
        ))


class ApiImportTests(unittest.TestCase):
    """Импорт схемы: обработчик API — служебное назначение без действия."""

    def test_service_rule_stays_outside_the_policy(self):
        with forbid_external_effects():
            scheme = import_routing_scheme(config())
        group = scheme.groups[0]
        self.assertEqual(
            (RuleTargetKind.API, "test-api", (), None, None, None, (ImportReason.TARGET_API,)),
            (group.target.kind, group.target.tag, group.target.outbound_tags, group.target.fallback_tag,
             group.target.strategy, group.target.action, group.target.reasons),
        )
        self.assertEqual((True, True, (), ("inboundTag",)), (group.api_service, group.read_only, group.rules, group.unsupported_fields))
        self.assertEqual((), scheme.reasons)
        self.assertFalse(scheme.read_only)
        self.assertEqual(
            [RoutingAction.VPN, RoutingAction.BLOCK], [rule.action for rule in scheme.policy.rules],
        )
        self.assertIs(RoutingAction.DIRECT, scheme.policy.final_rule.action)
        self.assertFalse(any(group.api_service for group in scheme.groups[1:]))
        validate_routing_scheme(scheme)

    def test_policy_positions_do_not_include_the_service_rule(self):
        policy = import_routing_scheme(config()).policy
        explanation = explain_route(policy, destination_context("www.example.test"))
        self.assertEqual((0, RoutingAction.VPN), (explanation.selection.index, explanation.selection.rule.action))
        address = explain_route(policy, destination_context("www.other.test 198.51.100.7"))
        self.assertEqual((1, RoutingAction.BLOCK), (address.selection.index, address.selection.rule.action))
        self.assertEqual(2, len(address.steps))

    def test_api_rule_with_client_conditions_blocks_the_policy(self):
        for name, fields in {
            "inbound и домен": {"inboundTag": ["test-api-in"], "domain": ["domain:example.test"]},
            "только домен": {"domain": ["domain:example.test"]},
            "inbound и порт": {"inboundTag": ["test-api-in"], "port": "443"},
        }.items():
            with self.subTest(name):
                scheme = import_routing_scheme(config(rules=[{"type": "field", **fields, "outboundTag": "test-api"}, *RULES[1:]]))
                self.assertIs(RuleTargetKind.API, scheme.groups[0].target.kind)
                self.assertFalse(scheme.groups[0].api_service)
                self.assertEqual((ImportReason.RULE_ACTION_UNRESOLVED,), scheme.reasons)
                self.assertIsNone(scheme.policy)
                self.assertTrue(scheme.read_only)

    def test_without_registered_handler_the_target_stays_unresolved(self):
        cases = {**WITHOUT_HANDLER, **{name: {"api_parts": ((API_PART, document),)} for name, (document, _path) in INVALID_SECTIONS.items()}}
        for name, options in cases.items():
            with self.subTest(name):
                scheme = import_routing_scheme(config(**options))
                target = scheme.groups[0].target
                self.assertEqual((RuleTargetKind.OUTBOUND, (ImportReason.TARGET_UNRESOLVED,)), (target.kind, target.reasons))
                self.assertFalse(scheme.groups[0].api_service)
                self.assertEqual((ImportReason.RULE_ACTION_UNRESOLVED,), scheme.reasons)

    def test_handler_sharing_outbound_tag_is_a_duplicate(self):
        scheme = import_routing_scheme(config(api={**API, "tag": "test-proxy"}))
        self.assertEqual(
            (RuleTargetKind.OUTBOUND, (ImportReason.TARGET_DUPLICATE,)),
            (scheme.groups[1].target.kind, scheme.groups[1].target.reasons),
        )
        self.assertIsNone(scheme.policy)
        listening = import_routing_scheme(config(api={**API, "tag": "test-proxy", "listen": LISTEN}))
        self.assertIs(RoutingAction.VPN, listening.groups[1].action)

    def test_last_api_section_is_effective(self):
        old_rule = {**API_RULE, "outboundTag": "test-old"}
        scheme = import_routing_scheme(config(rules=[API_RULE, old_rule, *RULES[1:]], api_parts=REPLACED_PARTS))
        self.assertIs(RuleTargetKind.API, scheme.groups[0].target.kind)
        self.assertEqual((ImportReason.TARGET_UNRESOLVED,), scheme.groups[1].target.reasons)
        kept = import_routing_scheme(config(api_parts=((API_PART, {"api": API}), (LATER_API_PART, {"api": None}))))
        self.assertTrue(kept.groups[0].api_service)
        self.assertIsNotNone(kept.policy)

    def test_case_variants_block_the_policy(self):
        for name, document in {
            "раздел": {"API": API}, "тег": {"api": {"tag": "test-api", "Tag": "test-other"}},
            "listen": {"api": {**API, "Listen": LISTEN}},
        }.items():
            with self.subTest(name):
                scheme = import_routing_scheme(config(api_parts=((API_PART, document),)))
                self.assertIn(ImportReason.FIELD_CASE_VARIANT, scheme.reasons)
                self.assertIsNone(scheme.policy)
                self.assertIsNone(balancer_fallbacks(config(api_parts=((API_PART, document),))))

    def test_balancer_choosing_the_handler_has_no_action(self):
        selecting = import_routing_scheme(config(
            rules=POOL_RULES, balancers=[{"tag": "test-pool", "selector": ["test-api", "test-proxy"]}],
        )).groups[1].target
        self.assertEqual(
            (RuleTargetKind.BALANCER, ("test-proxy", "test-api"), None, (ImportReason.TARGET_API,)),
            (selecting.kind, selecting.outbound_tags, selecting.action, selecting.reasons),
        )
        falling_back = import_routing_scheme(config(
            rules=POOL_RULES, balancers=[{"tag": "test-pool", "selector": ["test-proxy"], "fallbackTag": "test-api"}],
        )).groups[1].target
        self.assertEqual((None, (ImportReason.TARGET_API,)), (falling_back.action, falling_back.reasons))
        listening = import_routing_scheme(config(
            rules=POOL_RULES, balancers=[{"tag": "test-pool", "selector": ["test-api", "test-proxy"]}],
            api={**API, "listen": LISTEN},
        )).groups[1].target
        self.assertEqual((("test-proxy",), RoutingAction.VPN), (listening.outbound_tags, listening.action))

    def test_balancer_fallback_into_the_handler_is_an_api_target(self):
        (target,) = balancer_fallbacks(config(balancers=[{"tag": "test-pool", "selector": ["test-proxy"], "fallbackTag": "test-api"}]))
        self.assertEqual((RuleTargetKind.API, "test-api", None), (target.kind, target.tag, target.action))

    def test_api_target_revalidation_uses_exact_types(self):
        valid = RuleTarget(RuleTargetKind.API, "test-api", (), None, None, None, (ImportReason.TARGET_API,))
        self.assertEqual("api", valid.to_diagnostic()["kind"])
        broken = {
            "вид строкой": dict(kind="api"), "причина строкой": dict(reasons=("target_api",)),
            "без тега": dict(tag=None), "с действием": dict(action=RoutingAction.VPN),
            "с outbound": dict(outbound_tags=("test-api",)), "с fallback": dict(fallback_tag="test-proxy"),
            "со стратегией": dict(strategy="random"), "без причины": dict(reasons=()),
            "лишняя причина": dict(reasons=(ImportReason.TARGET_API, ImportReason.TARGET_DUPLICATE)),
            "чужая причина": dict(reasons=(ImportReason.TARGET_UNRESOLVED,)),
        }
        for name, change in broken.items():
            with self.subTest(name), self.assertRaises(RoutingImportError) as caught:
                replace(valid, **change)
            self.assertIs(RoutingImportErrorCode.TARGET, caught.exception.code)
            self.assertIsNone(caught.exception.__context__)

    def test_scheme_rejects_unresolved_non_service_group_next_to_a_policy(self):
        scheme = import_routing_scheme(config())
        group = scheme.groups[0]
        widened = replace(group, fields=("inboundTag", "port"), unsupported_fields=("inboundTag", "port"))
        self.assertFalse(widened.api_service)
        with self.assertRaises(RoutingImportError) as caught:
            RoutingScheme(scheme.routing_part, scheme.routing_parts, (widened, *scheme.groups[1:]), scheme.policy, scheme.reasons)
        self.assertIs(RoutingImportErrorCode.SCHEME, caught.exception.code)
        self.assertIsNone(caught.exception.__context__)

    def test_diagnostic_hides_unsafe_handler_tag(self):
        xray = config(api={"tag": UNSAFE_TAG}, rules=[{**API_RULE, "outboundTag": UNSAFE_TAG}, *RULES[1:]])
        scheme = import_routing_scheme(xray)
        diagnostic = scheme.to_diagnostic()["groups"][0]
        self.assertEqual(("api", True, None, True), (
            diagnostic["target"]["kind"], diagnostic["target"]["tag_known"], diagnostic["target"]["tag"], diagnostic["api_service"],
        ))
        rule = summary_rule(xray)
        self.assertEqual(("api", True, None), (rule["target_kind"], rule["target_tag_known"], rule["target_tag"]))
        text = json.dumps([scheme.to_diagnostic(), summarize_xray_config(xray.parts)], ensure_ascii=False)
        text += repr(scheme) + repr(scheme.groups) + repr(scheme.groups[0].target)
        self.assertNotIn(UNSAFE_MARKER, text)


class ApiQuickCheckTests(unittest.TestCase):
    """`xray_config_consistent`: тег обработчика API — разрешимая цель, отсутствие тега — по-прежнему ошибка."""

    def test_check_outcomes(self):
        cases = {
            "нет раздела": (config(api_parts=()), ("failed", "unresolved_references")),
            "непустой listen": (config(api={**API, "listen": LISTEN}), ("failed", "unresolved_references")),
            "тег число": (config(api={**API, "tag": 5}), ("failed", "unresolved_references")),
            "тег outbound": (config(api={**API, "tag": "test-proxy"}), ("failed", "duplicate_tags")),
            "раздел в двух частях": (config(api_parts=REPLACED_PARTS), ("unsupported", "sections_repeated_across_parts")),
            "вариант регистра": (config(api_parts=((API_PART, {"API": API}),)), ("unsupported", "case_variant_keys")),
            "inbound и балансировщик с тем же тегом": (config(
                inbounds=[*INBOUNDS, {"tag": "test-api", "protocol": "dokodemo-door"}],
                balancers=[{"tag": "test-api", "selector": ["test-proxy"]}],
            ), ("passed", None)),
            "правило API с доменом": (config(rules=[{**API_RULE, "domain": ["domain:example.test"]}, *RULES[1:]]), ("passed", None)),
        }
        for name, (xray, expected) in cases.items():
            with self.subTest(name), forbid_external_effects():
                self.assertEqual(expected, check_codes(xray))

    def test_repeated_api_section_does_not_affect_the_geodata_guard(self):
        self.assertFalse(replaced_sections_repeated(config(api_parts=REPLACED_PARTS)))


class ApiScenarioTests(unittest.TestCase):
    """Сценарии и меню поверх тех же моделей: импорт, список правил, объяснение и быстрая проверка."""

    def handlers(self, xray):
        sources = snapshot_proxy_sources()
        sources.xray.outcome = xray
        proxy = InspectProxyConfigHandler(
            sources.xray, sources.settings, sources.init, sources.lists, operation_ids=lambda: "op-proxy",
        )
        return proxy, ImportRoutingSchemeHandler(proxy, operation_ids=lambda: "op-import")

    def run_all(self, xray):
        proxy, routing = self.handlers(xray)
        store = InMemoryManagerMetadataStore()
        with forbid_external_effects():
            return {
                "proxy": proxy.execute(InspectProxyConfig()),
                "scheme": routing.execute(ImportRoutingScheme()),
                "rules": ListRoutingRulesHandler(routing, store, operation_ids=lambda: "op-rules").execute(ListRoutingRules()),
                "route": ExplainRouteHandler.from_import(routing, store, None, operation_ids=lambda: "op-route").execute(
                    ExplainRoute(destination="www.example.test"),
                ),
                "check": QuickCheckHandler(proxy, None, None, operation_ids=lambda: "op-check").execute(QuickCheck()),
            }

    def test_views_show_the_service_rule_and_build_the_policy(self):
        results = self.run_all(config())
        scheme = results["scheme"].data
        self.assertEqual(
            (True, "api", "test-api", None, ("target_api",)),
            (scheme.groups[0].api_service, scheme.groups[0].target.kind, scheme.groups[0].target.tag,
             scheme.groups[0].action, scheme.groups[0].target.reasons),
        )
        self.assertEqual((False, 2), (scheme.read_only, scheme.policy.rule_count))
        self.assertIs(True, scheme.to_dict()["groups"][0]["api_service"])
        self.assertIs(False, scheme.to_dict()["groups"][1]["api_service"])

        groups = results["rules"].data.groups
        self.assertEqual((TargetPositionState.API, None, 0, ()), (
            groups[0].target_position_state, groups[0].target_position, groups[0].rule_count, groups[0].rules,
        ))
        self.assertEqual(XrayPositionView("04_outbounds.json", 0), groups[1].target_position)
        self.assertEqual("api", results["rules"].data.to_dict()["groups"][0]["target_position_state"])

        route = results["route"].data
        self.assertIs(RouteOutcome.RULE, route.outcome)
        self.assertEqual((1, 0, "VPN"), (route.selection.group_index, route.selection.offset, route.selection.action))
        self.assertEqual((1, True), (route.scheme.api_service_group_count, route.scheme.policy_present))
        self.assertEqual(1, route.to_dict()["scheme"]["api_service_group_count"])

        rule = results["proxy"].data.xray.rules[0]
        self.assertEqual(("api", True, None), (rule.target_kind, rule.target_resolved, rule.target_position))
        check = {item.code: item for item in results["check"].data.checks.items}["xray_config_consistent"]
        self.assertEqual(("passed", None), (check.status.value, check.reason))

    def test_menu_labels_the_service_rule(self):
        results = self.run_all(config())
        scheme_list = present_routing_scheme(results["scheme"].data)
        self.assertIn("назначение api test-api", scheme_list.entries[0].label)
        self.assertIn(API_SERVICE_NOTE, scheme_list.entries[0].label)
        self.assertIn(f"Служебное правило API: {API_SERVICE_NOTE}", scheme_list.entries[0].card)
        self.assertIn("Служебное правило API: нет", scheme_list.entries[1].card)
        self.assertNotIn(API_SERVICE_NOTE, scheme_list.entries[1].label)
        rule_list = present_rule_list(results["rules"].data)
        self.assertIn(f"Назначение по позиции: {TARGET_POSITION_LABELS[TargetPositionState.API]}", rule_list.entries[0].card)
        route = present_route_explanation(results["route"].data)
        self.assertEqual(1, sum(line.startswith("Служебных правил API вне расчёта: 1") for line in route))

    def test_explanation_without_service_rules_has_no_extra_line(self):
        results = self.run_all(config(rules=RULES[1:], api_parts=()))
        self.assertEqual(0, results["route"].data.scheme.api_service_group_count)
        self.assertFalse(any("Служебных правил API" in line for line in present_route_explanation(results["route"].data)))

    def test_unsafe_handler_tag_is_hidden_everywhere(self):
        # Слово «тег» из маркера `unicode` есть в подписях меню; само значение проверяется целиком.
        markers = tuple(marker for marker in UNSAFE_MARKERS if marker != "тег")
        for name, tag in UNSAFE_IDENTIFIERS.items():
            with self.subTest(name):
                results = self.run_all(config(api={"tag": tag}, rules=[{**API_RULE, "outboundTag": tag}, *RULES[1:]]))
                target = results["scheme"].data.groups[0].target
                self.assertEqual(("api", True, None), (target.kind, target.tag_known, target.tag))
                self.assertEqual(TargetPositionState.API, results["rules"].data.groups[0].target_position_state)
                self.assertIs(RouteOutcome.RULE, results["route"].data.outcome)
                text = "".join(
                    repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False) for result in results.values()
                )
                text += "\n".join(present_route_explanation(results["route"].data))
                for menu in (present_routing_scheme(results["scheme"].data), present_rule_list(results["rules"].data)):
                    text += "\n".join((
                        *menu.header, *(entry.label for entry in menu.entries),
                        *(line for entry in menu.entries for line in entry.card),
                    ))
                for marker in (*markers, tag):
                    self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()
