"""Прикладная проверка возможностей: отказы, изоляция и приватность."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keenvpn.adapters.protocols import bundled_protocols
from keenvpn.application.contract import ErrorCategory
from keenvpn.application.protocol_registry import (
    EngineBinding, EngineCapability, EngineRegistry, ProtocolCapability,
    ProtocolRegistry, RegistryError, RegistryErrorCode,
)
from keenvpn.application.protocol_support import InspectProtocolSupport, InspectProtocolSupportHandler
from keenvpn.domain.connection import SecretValue
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support.protocols import sample_module


class ProtocolSupportTests(unittest.TestCase):
    def setUp(self):
        self.registry = bundled_protocols()
        self.handler = InspectProtocolSupportHandler(self.registry, operation_ids=lambda: "test-operation")

    def execute(self, handler, command):
        """Выполнить любую ветку сценария под запретом внешних эффектов."""
        with forbid_external_effects():
            return handler.execute(command)

    def test_metadata_by_type_and_uri_are_identical_and_safe(self):
        commands = (
            InspectProtocolSupport(protocol="trojan", capability=ProtocolCapability.PARSE_URI),
            InspectProtocolSupport(uri=SecretValue("TROJAN://TEST_PRIVATE@vpn.example.test:443")),
        )
        results = []
        with forbid_external_effects():
            for command in commands:
                result = self.execute(self.handler, command)
                self.assertTrue(result.succeeded)
                results.append(result.to_dict())
                encoded = json.dumps(result.to_dict(), ensure_ascii=False) + repr(result) + repr(command)
                self.assertNotIn("TEST_PRIVATE", encoded)
                self.assertNotIn("vpn.example.test", encoded)
                self.assertEqual(result.data.capabilities, ("parse_uri",))
                for item in reachable(result):
                    self.assertNotIsInstance(item, (SecretValue, BaseException, ProtocolRegistry))
                    self.assertFalse(callable(item))
        self.assertEqual(results[0], results[1])

    def test_unknown_protocol_scheme_and_missing_capability(self):
        cases = (
            (InspectProtocolSupport(protocol="unknown"), "unknown_protocol"),
            (InspectProtocolSupport(uri=SecretValue("https://TEST_PRIVATE.py")), "unknown_uri_scheme"),
            (InspectProtocolSupport(protocol="trojan", capability=ProtocolCapability.VALIDATE_PARAMETERS), "unsupported_protocol_capability"),
            (InspectProtocolSupport(protocol="trojan", engine="xray", engine_capability=EngineCapability.PROBE), "unknown_engine"),
        )
        with forbid_external_effects():
            for command, code in cases:
                with self.subTest(code=code):
                    result = self.execute(self.handler, command)
                    self.assertFalse(result.succeeded)
                    self.assertIsNone(result.data)
                    self.assertIs(result.error.category, ErrorCategory.UNSUPPORTED)
                    self.assertEqual(result.error.code, code)
                    self.assertNotIn("TEST_PRIVATE", json.dumps(result.to_dict()) + repr(command))

    def test_invalid_commands_and_selector_values(self):
        for command in (
            None, {}, InspectProtocolSupport(), InspectProtocolSupport(protocol="trojan", uri=SecretValue("trojan://")),
            InspectProtocolSupport(protocol=[]), InspectProtocolSupport(uri="trojan://"),
            InspectProtocolSupport(uri=SecretValue(1)), InspectProtocolSupport(protocol="trojan", capability="parse_uri"),
            InspectProtocolSupport(protocol="trojan", engine="xray"),
            InspectProtocolSupport(protocol="trojan", engine_capability=EngineCapability.PROBE),
            InspectProtocolSupport(protocol="trojan", engine="xray", engine_capability="probe"),
        ):
            with self.subTest(command=command):
                result = self.execute(self.handler, command)
                self.assertIs(result.error.category, ErrorCategory.INVALID_REQUEST)
                self.assertEqual(result.error.code, "invalid_command")
        for command in (InspectProtocolSupport(protocol="!"), InspectProtocolSupport(uri=SecretValue("TEST_PRIVATE"))):
            result = self.execute(self.handler, command)
            self.assertIs(result.error.category, ErrorCategory.INVALID_INPUT)
            self.assertEqual(result.error.code, "invalid_protocol_selector")

    def test_version_is_checked_before_input_and_registry(self):
        registry = Mock()
        handler = InspectProtocolSupportHandler(registry)
        result = self.execute(handler, InspectProtocolSupport(protocol=[], contract_version=2))
        self.assertEqual(result.error.code, "unsupported_contract_version")
        self.assertEqual(registry.mock_calls, [])

    def test_invalid_engine_id_is_reported_as_engine_input(self):
        for engine in ("Xray", ""):
            with self.subTest(engine=engine), forbid_external_effects():
                result = self.execute(self.handler, InspectProtocolSupport(
                    protocol="trojan", engine=engine, engine_capability=EngineCapability.PROBE,
                ))
                self.assertFalse(result.succeeded)
                self.assertIsNone(result.data)
                self.assertIs(result.error.category, ErrorCategory.INVALID_INPUT)
                self.assertEqual(result.error.code, "invalid_engine_selector")
                self.assertEqual(result.error.message, "Некорректный идентификатор движка.")

    def test_second_protocol_uses_same_scenario_without_invoking_operations(self):
        parser, validator, probe = Mock(), Mock(), Mock()
        module = sample_module(parse_uri=parser, validate_parameters=validator)
        protocols = ProtocolRegistry((self.registry.by_protocol("trojan"), module))
        engines = EngineRegistry((EngineBinding("testengine", "sample", ((EngineCapability.PROBE, probe),)),))
        handler = InspectProtocolSupportHandler(protocols, engines)
        with forbid_external_effects():
            result = self.execute(handler, InspectProtocolSupport(
                uri=SecretValue("SAMPLE+ALIAS://TEST_PRIVATE"),
                capability=ProtocolCapability.VALIDATE_PARAMETERS,
                engine="testengine", engine_capability=EngineCapability.PROBE,
            ))
            self.assertTrue(result.succeeded)
            self.assertEqual(result.data.protocol, "sample")
            self.assertEqual(result.data.engine, "testengine")
            self.assertEqual(result.data.engine_capability, "probe")
            self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())
        for operation in (parser, validator, probe):
            operation.assert_not_called()

    def test_engine_protocol_and_operation_failures_stay_distinct(self):
        engine = EngineBinding("testengine", "sample", ((EngineCapability.PROBE, Mock()),))
        protocols = ProtocolRegistry((self.registry.by_protocol("trojan"), sample_module()))
        handler = InspectProtocolSupportHandler(protocols, EngineRegistry((engine,)))
        for protocol, code in (("trojan", "unsupported_engine_protocol"), ("sample", "unsupported_engine_capability")):
            result = self.execute(handler, InspectProtocolSupport(protocol=protocol, engine="testengine", engine_capability=EngineCapability.START))
            self.assertEqual(result.error.code, code)
            self.assertIsNone(result.data)

    def test_protocol_failure_precedes_engine_lookup(self):
        engines = Mock()
        handler = InspectProtocolSupportHandler(self.registry, engines)
        result = self.execute(handler, InspectProtocolSupport(protocol="trojan", capability=ProtocolCapability.VALIDATE_PARAMETERS,
                                                       engine="xray", engine_capability=EngineCapability.PROBE))
        self.assertEqual(result.error.code, "unsupported_protocol_capability")
        self.assertEqual(engines.mock_calls, [])

    def test_registry_failure_does_not_keep_exception_or_secret(self):
        registry = Mock()
        registry.by_protocol.side_effect = RuntimeError("TEST_PRIVATE")
        result = self.execute(InspectProtocolSupportHandler(registry), InspectProtocolSupport(protocol="trojan"))
        self.assertEqual(result.error.code, "registry_failed")
        self.assertNotIn("TEST_PRIVATE", json.dumps(result.to_dict()) + repr(result))
        self.assertFalse(any(isinstance(item, BaseException) for item in reachable(result)))

    def test_unexpected_registry_code_is_not_forwarded(self):
        registry = Mock()
        error = RegistryError(RegistryErrorCode.INVALID_REGISTRATION)
        error.code = "TEST_PRIVATE"
        registry.by_protocol.side_effect = error
        result = self.execute(InspectProtocolSupportHandler(registry), InspectProtocolSupport(protocol="trojan"))
        self.assertEqual(result.error.code, "invalid_registry_data")
        self.assertNotIn("TEST_PRIVATE", json.dumps(result.to_dict()))

    def test_interruptions_propagate(self):
        registry = Mock()
        for error in (KeyboardInterrupt(), SystemExit()):
            registry.by_protocol.side_effect = error
            with self.assertRaises(type(error)):
                self.execute(InspectProtocolSupportHandler(registry), InspectProtocolSupport(protocol="trojan"))


if __name__ == "__main__":
    unittest.main()
