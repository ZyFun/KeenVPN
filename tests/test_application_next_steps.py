"""Безопасный следующий шаг в контракте ошибок: каталог, назначение по коду и совместимость версии."""

import ast
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
from types import MappingProxyType
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.trojan_uri import TrojanLinkParser, TrojanURIErrorCode
from keenvpn.application.connections import InspectConnectionLink, InspectConnectionLinkHandler, link_rejection_detail
from keenvpn.application.contract import (
    CATEGORY_NEXT_STEPS, CODE_NEXT_STEPS, CONTRACT_VERSION, NEXT_STEP_MESSAGES, ErrorCategory, ErrorCode, ErrorDetail,
    NextStep, NextStepCode, OperationStatus, Result, check_contract_version, failed, invalid_command, next_step_for,
    succeeded,
)
from keenvpn.application.keenetic_policies import POLICIES_UNAVAILABLE
from keenvpn.application.manager_metadata import InspectManagerMetadata, InspectManagerMetadataHandler
from keenvpn.application.ports import (
    ConnectionLinkRejected, LinkRejection, ManagerMetadataStoreError, MetadataStoreFailure,
)
from keenvpn.application.protocol_registry import RegistryErrorCode
from keenvpn.application.protocol_support import registry_error_detail
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler
from keenvpn.domain.connection import SecretValue
from keenvpn.domain.keenetic_policy import KeeneticPolicyErrorCode
from keenvpn.domain.routing import RoutingErrorCode
from keenvpn.domain.routing_explanation import DomainSource
from tests.support.in_memory import InMemoryManagerMetadataStore, InMemoryRoutingPolicySource
from tests.support.isolation import forbid_external_effects


APPLICATION_ROOT = Path(__file__).resolve().parents[1] / "keenvpn" / "application"
SECRET = "TEST_ONLY_PASSWORD"
PRIVATE_HOST = "private-host.example.test"
PRIVATE_PATH = "/tmp/mnt/test-data/private-note"
LINK = f"trojan://{SECRET}@{PRIVATE_HOST}:443?security=tls&type=ws#Example"

FORBIDDEN_FRAGMENTS = ("direct", "напрям", "kill", "защит", "автозапуск", "отключ", "выключ", "fail-open", "блокир")
"""Фрагменты, которых не должно быть ни в кодах, ни в текстах шагов: шаг не предлагает ослабить защиту."""

EXPECTED_CATEGORY_STEPS = {
    ErrorCategory.INVALID_REQUEST: None,
    ErrorCategory.INVALID_INPUT: NextStepCode.RETRY_INPUT,
    ErrorCategory.UNSUPPORTED: NextStepCode.CONSULT_DOCUMENTATION,
    ErrorCategory.SOURCE_FAILED: NextStepCode.CHECK_SOURCE,
    ErrorCategory.INVALID_SOURCE_DATA: NextStepCode.INSPECT_SOURCE_DATA,
}
EXPECTED_CODE_STEPS = {
    (ErrorCategory.INVALID_REQUEST, "unsupported_contract_version"): NextStepCode.UPDATE_INTERFACE,
    (ErrorCategory.INVALID_REQUEST, "invalid_command"): None,
    (ErrorCategory.SOURCE_FAILED, "metadata_store_busy"): NextStepCode.RETRY_LATER,
    (ErrorCategory.SOURCE_FAILED, "metadata_revision_conflict"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "metadata_write_unconfirmed"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "metadata_store_failed"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.INVALID_SOURCE_DATA, "invalid_metadata_store_result"): NextStepCode.OPEN_VIEW,
    (ErrorCategory.SOURCE_FAILED, "metadata_store_unsafe"): NextStepCode.PRESERVE_FILE,
    (ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_metadata"): NextStepCode.PRESERVE_FILE,
    (ErrorCategory.UNSUPPORTED, "storage_placement_mismatch"): NextStepCode.OPEN_VIEW,
}
EXPECTED_STORE_STEPS = {
    MetadataStoreFailure.UNAVAILABLE: NextStepCode.CHECK_SOURCE,
    MetadataStoreFailure.UNSAFE: NextStepCode.PRESERVE_FILE,
    MetadataStoreFailure.BUSY: NextStepCode.RETRY_LATER,
    MetadataStoreFailure.CONFLICT: NextStepCode.OPEN_VIEW,
    MetadataStoreFailure.INVALID: NextStepCode.PRESERVE_FILE,
    MetadataStoreFailure.WRITE_FAILED: NextStepCode.CHECK_SOURCE,
    MetadataStoreFailure.WRITE_UNCONFIRMED: NextStepCode.OPEN_VIEW,
}

LITERAL_PAIRS = sorted({
    ("invalid_request", "invalid_command"),
    ("invalid_request", "unsupported_contract_version"),
    ("source_failed", "connection_parser_failed"),
    ("invalid_source_data", "invalid_connection_model"),
    ("invalid_source_data", "invalid_parser_rejection"),
    ("source_failed", "profile_preparation_failed"),
    ("invalid_input", "invalid_profile_id"),
    ("source_failed", "profile_source_failed"),
    ("invalid_input", "profile_not_found"),
    ("invalid_source_data", "invalid_profile_model"),
    ("unsupported", "unsupported_profile_format_version"),
    ("invalid_source_data", "profile_id_mismatch"),
    ("invalid_input", "invalid_profile_model"),
    ("invalid_input", "invalid_profile_link"),
    ("invalid_input", "invalid_profile_identity"),
    ("source_failed", "registry_failed"),
    ("invalid_source_data", "invalid_registry_data"),
    ("source_failed", "routing_policy_unavailable"),
    ("invalid_source_data", "invalid_routing_policy"),
    ("source_failed", "keenetic_policies_unavailable"),
    ("invalid_source_data", "invalid_keenetic_policies"),
    ("source_failed", "keenetic_hotspot_unavailable"),
    ("source_failed", "keenetic_registrations_unavailable"),
    ("source_failed", "keenetic_runtime_unavailable"),
    ("invalid_source_data", "invalid_keenetic_hotspot"),
    ("invalid_source_data", "invalid_keenetic_registrations"),
    ("invalid_source_data", "invalid_keenetic_runtime"),
    ("invalid_source_data", "keenetic_state_inconsistent"),
    ("source_failed", "xray_config_unavailable"),
    ("source_failed", "xkeen_settings_unavailable"),
    ("source_failed", "xkeen_init_unavailable"),
    ("source_failed", "xkeen_port_exclude_unavailable"),
    ("source_failed", "xkeen_port_proxying_unavailable"),
    ("source_failed", "xkeen_ip_exclude_unavailable"),
    ("invalid_source_data", "invalid_xray_config"),
    ("invalid_source_data", "invalid_xkeen_settings"),
    ("invalid_source_data", "invalid_xkeen_init"),
    ("invalid_source_data", "invalid_xkeen_port_exclude"),
    ("invalid_source_data", "invalid_xkeen_port_proxying"),
    ("invalid_source_data", "invalid_xkeen_ip_exclude"),
    ("invalid_source_data", "proxy_config_inconsistent"),
    ("source_failed", "geo_databases_unavailable"),
    ("source_failed", "xray_process_unavailable"),
    ("invalid_source_data", "invalid_geo_databases"),
    ("invalid_source_data", "invalid_xray_process"),
    ("invalid_source_data", "installation_inconsistent"),
    ("invalid_source_data", "routing_import_failed"),
    ("source_failed", "storage_placement_unavailable"),
    ("invalid_source_data", "invalid_storage_placement"),
    ("unsupported", "storage_placement_mismatch"),
    ("invalid_source_data", "manager_metadata_inconsistent"),
    ("invalid_source_data", "invalid_metadata_store_result"),
    ("source_failed", "metadata_store_failed"),
    ("source_failed", "metadata_store_unavailable"),
    ("source_failed", "metadata_store_unsafe"),
    ("source_failed", "metadata_store_busy"),
    ("source_failed", "metadata_revision_conflict"),
    ("invalid_source_data", "invalid_stored_metadata"),
    ("source_failed", "metadata_write_failed"),
    ("source_failed", "metadata_write_unconfirmed"),
    ("invalid_source_data", "rule_binding_failed"),
    ("invalid_source_data", "rule_id_generation_failed"),
})
"""Пары «категория, код», которые сценарии задают литералами; снимок неизменности кодов и категорий."""


def _category(node: ast.expr) -> ErrorCategory | None:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ErrorCategory":
        return ErrorCategory[node.attr]
    return None


def _code(node: ast.expr, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if (
        isinstance(node, ast.Attribute) and node.attr == "value" and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
    ):
        owner, member = node.value.value.id, node.value.attr
        if owner == "ErrorCode":
            return ErrorCode[member].value
        if owner == "MetadataStoreFailure":
            return MetadataStoreFailure[member].value
    return None


def literal_pairs_of(source: str) -> set[tuple[ErrorCategory, str]]:
    """Собрать пары «категория, код», заданные литералами в одном модуле application.

    Учитываются `ErrorDetail(ErrorCategory.X, "code", ...)`, `unavailable("code", ...)`,
    `SourceCheck("code", ...)`, таблицы `_UNAVAILABLE` и таблицы отказов хранилища
    с ключами `MetadataStoreFailure.X`; коды через константы модуля разрешаются.
    """
    tree = ast.parse(source)
    constants = {
        target.id: node.value.value
        for node in tree.body if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets if isinstance(target, ast.Name) and type(node.value.value) is str
    }
    pairs: set[tuple[ErrorCategory, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and len(node.args) >= 2:
            if node.func.id == "ErrorDetail":
                category, code = _category(node.args[0]), _code(node.args[1], constants)
                if category is not None and code is not None:
                    pairs.add((category, code))
            elif node.func.id == "unavailable" and (code := _code(node.args[0], constants)) is not None:
                pairs.add((ErrorCategory.SOURCE_FAILED, code))
            elif node.func.id == "SourceCheck" and (code := _code(node.args[0], constants)) is not None:
                pairs.add((ErrorCategory.INVALID_SOURCE_DATA, code))
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            named = any(isinstance(target, ast.Name) and target.id == "_UNAVAILABLE" for target in node.targets)
            for key, value in zip(node.value.keys, node.value.values):
                if not isinstance(value, ast.Tuple) or not value.elts:
                    continue
                if named and (code := _code(value.elts[0], constants)) is not None:
                    pairs.add((ErrorCategory.SOURCE_FAILED, code))
                failure = _code(ast.Attribute(key, "value"), constants) if isinstance(key, ast.Attribute) else None
                category = _category(value.elts[0])
                if failure is not None and category is not None:
                    pairs.add((category, failure))
    return pairs


def literal_pairs() -> set[tuple[ErrorCategory, str]]:
    pairs: set[tuple[ErrorCategory, str]] = set()
    for path in sorted(APPLICATION_ROOT.glob("*.py")):
        pairs |= literal_pairs_of(path.read_text(encoding="utf-8"))
    return pairs


def enum_pairs() -> set[tuple[ErrorCategory, str]]:
    """Пары, чьи коды сценарии берут из перечислений домена, реестра и парсера."""
    pairs: set[tuple[ErrorCategory, str]] = set()
    for code in RegistryErrorCode:
        detail = registry_error_detail(code)
        pairs.add((detail.category, detail.code))
    for rejection, code in (
        (LinkRejection.INVALID, TrojanURIErrorCode.INVALID_URI),
        (LinkRejection.UNSUPPORTED, TrojanURIErrorCode.UNSUPPORTED_URI),
    ):
        detail = link_rejection_detail(ConnectionLinkRejected(rejection, code.value, "Текст."))
        pairs.add((detail.category, detail.code))
    for code in (RoutingErrorCode.CONTEXT, RoutingErrorCode.DOMAIN, RoutingErrorCode.IP):
        pairs.add((ErrorCategory.INVALID_INPUT, code.value))
    pairs.add((ErrorCategory.SOURCE_FAILED, RoutingErrorCode.MATCHER.value))
    pairs |= {
        (ErrorCategory.INVALID_SOURCE_DATA, code.value) for code in RoutingErrorCode if code is not RoutingErrorCode.MATCHER
    }
    for code in (
        KeeneticPolicyErrorCode.DESCRIPTION, KeeneticPolicyErrorCode.POLICY_ID, KeeneticPolicyErrorCode.SELECTION_MISMATCH,
    ):
        pairs.add((ErrorCategory.INVALID_INPUT, code.value))
    return pairs


def step_code(step: NextStep | None) -> NextStepCode | None:
    return None if step is None else step.code


class NextStepCatalogTests(unittest.TestCase):
    def test_every_step_code_has_one_fixed_printable_message(self):
        self.assertEqual(set(NEXT_STEP_MESSAGES), set(NextStepCode))
        for code in NextStepCode:
            message = NEXT_STEP_MESSAGES[code]
            with self.subTest(code=code.value):
                self.assertTrue(message.isprintable())
                self.assertTrue(0 < len(message) <= 200)
                self.assertTrue(message.endswith("."))
                self.assertRegex(code.value, r"\A[a-z][a-z_]{2,40}\Z")
        self.assertEqual(len(set(NEXT_STEP_MESSAGES.values())), len(NextStepCode))

    def test_steps_never_suggest_direct_route_or_disabling_protection(self):
        for code in NextStepCode:
            text = (code.value + " " + NEXT_STEP_MESSAGES[code]).casefold()
            for fragment in FORBIDDEN_FRAGMENTS:
                with self.subTest(code=code.value, fragment=fragment):
                    self.assertNotIn(fragment, text)

    def test_next_step_model_accepts_only_catalog_text(self):
        step = NextStep(NextStepCode.RETRY_INPUT, NEXT_STEP_MESSAGES[NextStepCode.RETRY_INPUT])
        self.assertEqual(step.to_dict(), {"code": "retry_input", "message": NEXT_STEP_MESSAGES[NextStepCode.RETRY_INPUT]})
        for args in (
            ("retry_input", NEXT_STEP_MESSAGES[NextStepCode.RETRY_INPUT]),
            (NextStepCode.RETRY_INPUT, "Другой текст."),
            (NextStepCode.RETRY_INPUT, NEXT_STEP_MESSAGES[NextStepCode.OPEN_VIEW]),
            (NextStepCode.RETRY_INPUT, NEXT_STEP_MESSAGES[NextStepCode.RETRY_INPUT] + " " + SECRET),
            (None, NEXT_STEP_MESSAGES[NextStepCode.RETRY_INPUT]),
        ):
            with self.subTest(args=args), self.assertRaises(TypeError):
                NextStep(*args)
        with self.assertRaises(FrozenInstanceError):
            step.message = "Иначе."

    def test_catalog_tables_are_read_only(self):
        # Регрессия GitHub review 227-R02: правка таблиц из процесса меняла бы сериализацию уже созданных ошибок.
        for table, key in (
            (NEXT_STEP_MESSAGES, NextStepCode.RETRY_INPUT),
            (CATEGORY_NEXT_STEPS, ErrorCategory.INVALID_INPUT),
            (CODE_NEXT_STEPS, (ErrorCategory.SOURCE_FAILED, "metadata_store_busy")),
        ):
            with self.subTest(table=type(table).__name__, key=key):
                self.assertIs(type(table), MappingProxyType)
                with self.assertRaises(TypeError):
                    table[key] = None
                with self.assertRaises(TypeError):
                    del table[key]
                self.assertFalse(hasattr(table, "clear"))
        error = ErrorDetail(ErrorCategory.SOURCE_FAILED, "metadata_store_busy", "Текст.")
        self.assertEqual(step_code(error.next_step), NextStepCode.RETRY_LATER)

    def test_next_step_for_checks_argument_types(self):
        for args in (("invalid_input", "code"), (ErrorCategory.INVALID_INPUT, None), (ErrorCategory.INVALID_INPUT, b"code")):
            with self.subTest(args=args), self.assertRaises(TypeError):
                next_step_for(*args)

    def test_str_enum_code_is_accepted_like_error_detail_accepts_it(self):
        # Регрессия review 227-R01: ErrorDetail допускает подклассы str в коде, шаг не должен падать на них.
        for category, code, expected in (
            (ErrorCategory.INVALID_REQUEST, ErrorCode.INVALID_COMMAND, None),
            (ErrorCategory.INVALID_REQUEST, ErrorCode.UNSUPPORTED_CONTRACT_VERSION, NextStepCode.UPDATE_INTERFACE),
            (ErrorCategory.SOURCE_FAILED, MetadataStoreFailure.BUSY, NextStepCode.RETRY_LATER),
            (ErrorCategory.INVALID_SOURCE_DATA, MetadataStoreFailure.INVALID, NextStepCode.PRESERVE_FILE),
            (ErrorCategory.INVALID_INPUT, RoutingErrorCode.DOMAIN, NextStepCode.RETRY_INPUT),
        ):
            with self.subTest(code=code):
                self.assertEqual(step_code(next_step_for(category, code)), expected)
                error = ErrorDetail(category, code, "Текст.")
                self.assertEqual(step_code(error.next_step), expected)
                payload = failed("op", "cmd", error).to_dict()
                self.assertEqual(payload["error"]["code"], code.value)
                self.assertEqual(json.loads(json.dumps(payload, ensure_ascii=False)), payload)
                self.assertEqual(
                    payload["error"]["next_step"],
                    None if expected is None else {"code": expected.value, "message": NEXT_STEP_MESSAGES[expected]},
                )


class NextStepAssignmentTests(unittest.TestCase):
    def test_every_category_has_an_explicit_default(self):
        self.assertEqual(set(CATEGORY_NEXT_STEPS), set(ErrorCategory))
        self.assertEqual(CATEGORY_NEXT_STEPS, EXPECTED_CATEGORY_STEPS)
        for category in ErrorCategory:
            with self.subTest(category=category.value):
                step = next_step_for(category, "code_without_override_for_test")
                self.assertEqual(step_code(step), EXPECTED_CATEGORY_STEPS[category])
                if step is not None:
                    self.assertEqual(step.message, NEXT_STEP_MESSAGES[step.code])

    def test_code_overrides_match_the_documented_table(self):
        self.assertEqual(CODE_NEXT_STEPS, EXPECTED_CODE_STEPS)
        for (category, code), expected in EXPECTED_CODE_STEPS.items():
            with self.subTest(code=code):
                self.assertEqual(step_code(next_step_for(category, code)), expected)
                if expected is not None:
                    # Переопределение имеет смысл, только если отличается от шага категории.
                    self.assertNotEqual(expected, CATEGORY_NEXT_STEPS[category])
        # Остальные отказы хранилища остаются на шагах своих категорий.
        for code, expected in (
            ("metadata_store_unavailable", NextStepCode.CHECK_SOURCE), ("metadata_write_failed", NextStepCode.CHECK_SOURCE),
            ("storage_placement_unavailable", NextStepCode.CHECK_SOURCE),
        ):
            self.assertEqual(step_code(next_step_for(ErrorCategory.SOURCE_FAILED, code)), expected)
        for code in ("manager_metadata_inconsistent", "invalid_storage_placement"):
            self.assertEqual(step_code(next_step_for(ErrorCategory.INVALID_SOURCE_DATA, code)), NextStepCode.INSPECT_SOURCE_DATA)

    def test_literal_codes_of_scenarios_are_unchanged(self):
        # Снимок кодов и категорий, которые сценарии задают литералами: задача добавляет шаг, а не меняет коды.
        found = sorted((category.value, code) for category, code in literal_pairs())
        self.assertEqual(found, LITERAL_PAIRS)

    def test_overrides_refer_to_real_codes_and_every_real_code_resolves(self):
        actual = literal_pairs() | enum_pairs()
        self.assertGreaterEqual(len(actual), 70)
        for sample in (
            (ErrorCategory.INVALID_REQUEST, "invalid_command"), (ErrorCategory.UNSUPPORTED, "unknown_protocol"),
            (ErrorCategory.INVALID_INPUT, "invalid_uri"), (ErrorCategory.INVALID_INPUT, "policy_selection_mismatch"),
            (ErrorCategory.SOURCE_FAILED, "rule_matcher_failed"), (ErrorCategory.INVALID_SOURCE_DATA, "routing_import_failed"),
        ):
            self.assertIn(sample, actual)
        stale = set(CODE_NEXT_STEPS) - actual
        self.assertEqual(stale, set(), "переопределение ссылается на код, которого нет в сценариях")
        for category, code in sorted(actual, key=lambda pair: (pair[0].value, pair[1])):
            with self.subTest(category=category.value, code=code):
                step = next_step_for(category, code)
                if step is None:
                    self.assertEqual(category, ErrorCategory.INVALID_REQUEST)
                else:
                    self.assertIs(type(step), NextStep)
                    self.assertEqual(step.message, NEXT_STEP_MESSAGES[step.code])

    def test_error_detail_exposes_step_without_changing_equality_or_repr(self):
        error = ErrorDetail(
            ErrorCategory.SOURCE_FAILED, "keenetic_policies_unavailable", "Не удалось прочитать политики Keenetic.",
        )
        self.assertEqual(error, POLICIES_UNAVAILABLE)
        self.assertEqual(step_code(error.next_step), NextStepCode.CHECK_SOURCE)
        self.assertNotIn("next_step", repr(error))
        self.assertIsNone(invalid_command().next_step)
        self.assertEqual(step_code(check_contract_version(CONTRACT_VERSION + 1).next_step), NextStepCode.UPDATE_INTERFACE)
        self.assertEqual(invalid_command().to_dict()["next_step"], None)
        self.assertIn('"next_step": null', json.dumps(invalid_command().to_dict(), ensure_ascii=False))


class NextStepsInResultsTests(unittest.TestCase):
    """Шаг виден через результаты настоящих сценариев с управляемыми портами."""

    def assertSafe(self, result: Result, expected: NextStepCode | None):
        self.assertFalse(result.succeeded)
        self.assertEqual(step_code(result.error.next_step), expected)
        payload = result.to_dict()
        encoded = (
            json.dumps(payload, ensure_ascii=False) + repr(result) + repr(result.error) + repr(result.error.next_step)
        )
        for private in (SECRET, PRIVATE_HOST, PRIVATE_PATH):
            self.assertNotIn(private, encoded)
        step = payload["error"]["next_step"]
        if expected is None:
            self.assertIsNone(step)
        else:
            self.assertEqual(step, {"code": expected.value, "message": NEXT_STEP_MESSAGES[expected]})
        self.assertEqual(payload["contract_version"], CONTRACT_VERSION)

    def test_each_category_gives_the_documented_step(self):
        # Кодек IDNA импортируется при первом обращении: прогреваем его до запрета внешних эффектов.
        PRIVATE_HOST.encode("idna")
        links = InspectConnectionLinkHandler(TrojanLinkParser())
        policies = InMemoryRoutingPolicySource(OSError(f"{PRIVATE_PATH}: {SECRET}"))
        routes = ExplainRouteHandler(policies)
        with forbid_external_effects():
            self.assertSafe(links.execute("не команда"), None)
            self.assertSafe(
                links.execute(InspectConnectionLink(SecretValue(LINK), contract_version=CONTRACT_VERSION + 1)),
                NextStepCode.UPDATE_INTERFACE,
            )
            unsupported = InspectConnectionLink(SecretValue(LINK.replace("trojan://", "vless://")))
            self.assertSafe(links.execute(unsupported), NextStepCode.CONSULT_DOCUMENTATION)
            invalid = InspectConnectionLink(SecretValue(LINK.replace(":443", ":99999")))
            self.assertSafe(links.execute(invalid), NextStepCode.RETRY_INPUT)
            bad_input = ExplainRoute(domain="bad domain", domain_source=DomainSource.DESTINATION)
            self.assertSafe(routes.execute(bad_input), NextStepCode.RETRY_INPUT)
            self.assertEqual(policies.calls, 0)
            private = ExplainRoute(domain=PRIVATE_HOST, domain_source=DomainSource.DESTINATION)
            self.assertSafe(routes.execute(private), NextStepCode.CHECK_SOURCE)
            policies.outcome = None
            self.assertSafe(routes.execute(private), NextStepCode.INSPECT_SOURCE_DATA)

    def test_metadata_store_failures_never_suggest_overwriting(self):
        store = InMemoryManagerMetadataStore()
        handler = InspectManagerMetadataHandler(store)
        with forbid_external_effects():
            for failure, expected in EXPECTED_STORE_STEPS.items():
                with self.subTest(failure=failure.value):
                    store.read_failure = ManagerMetadataStoreError(failure, reason=None)
                    result = handler.execute(InspectManagerMetadata())
                    self.assertEqual(result.error.code, failure.value)
                    self.assertSafe(result, expected)
            store.read_failure = OSError(PRIVATE_PATH)
            result = handler.execute(InspectManagerMetadata())
            self.assertEqual(result.error.code, "metadata_store_failed")
            self.assertSafe(result, NextStepCode.OPEN_VIEW)
            store.read_failure = None
            store.content = b"{not json"
            result = handler.execute(InspectManagerMetadata())
            self.assertEqual(
                (result.error.code, result.error.reason), ("invalid_stored_metadata", "invalid_metadata_json"),
            )
            self.assertSafe(result, NextStepCode.PRESERVE_FILE)
        self.assertEqual(store.write_calls, ())


class ContractVersionSnapshotTests(unittest.TestCase):
    """Снимок контракта версии 1: изменение набора ключей, категорий или кодов требует решения о версии."""

    def test_contract_snapshot_is_version_1(self):
        self.assertEqual(CONTRACT_VERSION, 1)
        self.assertIsNone(check_contract_version(1))
        self.assertEqual(check_contract_version(2).code, ErrorCode.UNSUPPORTED_CONTRACT_VERSION.value)
        error = ErrorDetail(ErrorCategory.INVALID_INPUT, "invalid_uri", "Сообщение.", reason="invalid_port")
        self.assertEqual(
            list(failed("op", "cmd", error).to_dict()),
            ["contract_version", "operation_id", "command", "status", "data", "error"],
        )
        self.assertEqual(list(error.to_dict()), ["category", "code", "reason", "message", "next_step"])
        self.assertEqual(
            [category.value for category in ErrorCategory],
            ["invalid_request", "invalid_input", "unsupported", "source_failed", "invalid_source_data"],
        )
        self.assertEqual([code.value for code in ErrorCode], ["invalid_command", "unsupported_contract_version"])
        self.assertEqual(
            [code.value for code in NextStepCode],
            [
                "retry_input", "consult_documentation", "check_source", "inspect_source_data", "retry_later", "open_view",
                "preserve_file", "update_interface",
            ],
        )
        self.assertEqual([status.value for status in OperationStatus], ["succeeded", "failed"])

    def test_success_payload_is_unchanged_and_json_round_trips(self):
        class View:
            def to_dict(self):
                return {"ok": True}

        payload = succeeded("op", "cmd", View()).to_dict()
        self.assertEqual(payload, {
            "contract_version": 1, "operation_id": "op", "command": "cmd", "status": "succeeded", "data": {"ok": True},
            "error": None,
        })
        failure = failed("op", "cmd", ErrorDetail(ErrorCategory.SOURCE_FAILED, "metadata_store_busy", "Занято.")).to_dict()
        self.assertEqual(json.loads(json.dumps(failure, ensure_ascii=False)), failure)
        self.assertEqual(failure["error"]["next_step"]["code"], "retry_later")


if __name__ == "__main__":
    unittest.main()
