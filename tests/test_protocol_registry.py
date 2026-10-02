"""Контракты явной регистрации, выбора и отсутствия скрытого fallback."""

from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keenvpn.adapters.protocols import bundled_protocols
from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.protocol_registry import (
    EngineBinding, EngineCapability, EngineRegistry, ProtocolCapability, ProtocolField,
    ProtocolRegistry, RegistryError, RegistryErrorCode,
)
from keenvpn.domain.connection import TrojanConnection
from keenvpn.domain.profile import ProfileErrorCode, ProfileIdentity, ProfileValidationError
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import frame_locals
from tests.support.protocols import SampleParameters, sample_module


class ProtocolRegistryTests(unittest.TestCase):
    def test_profile_protocol_id_is_accepted_by_protocol_and_engine_registries(self):
        for protocol in ("a", "trojan", "a0_-", "a" * 32):
            with self.subTest(protocol=protocol), forbid_external_effects():
                identity = ProfileIdentity(UUID("a0000000-0000-4000-8000-000000000001"), None, protocol)
                module = sample_module(protocol=identity.protocol)
                registry = ProtocolRegistry((module,))
                self.assertIs(registry.by_protocol(identity.protocol), module)
                binding = EngineBinding("testengine", identity.protocol, ((EngineCapability.PROBE, Mock()),))
                engines = EngineRegistry((binding,))
                self.assertIs(engines.resolve("testengine", identity.protocol, EngineCapability.PROBE), binding)

    def test_invalid_protocol_id_is_rejected_by_profile_and_both_registries(self):
        registry = bundled_protocols()
        engines = EngineRegistry()
        for protocol in ("", "A", "0a", "a.b", "a+b", "a b", "a" * 33, None, 1, []):
            with self.subTest(protocol=protocol):
                with self.assertRaises(ProfileValidationError) as caught:
                    ProfileIdentity(UUID("a0000000-0000-4000-8000-000000000001"), None, protocol)
                self.assertIs(caught.exception.code, ProfileErrorCode.PROTOCOL)
                self.assert_code(RegistryErrorCode.INVALID_REGISTRATION, lambda: sample_module(protocol=protocol))
                self.assert_code(RegistryErrorCode.INVALID_SELECTOR, lambda: registry.by_protocol(protocol))
                self.assert_code(RegistryErrorCode.INVALID_REGISTRATION, lambda: EngineBinding(
                    "testengine", protocol, ((EngineCapability.PROBE, Mock()),),
                ))
                self.assert_code(RegistryErrorCode.INVALID_SELECTOR, lambda: engines.resolve(
                    "testengine", protocol, EngineCapability.PROBE,
                ))

    def assert_code(self, code, action):
        with self.assertRaises(RegistryError) as caught:
            action()
        self.assertIs(caught.exception.code, code)
        self.assertNotIn("TEST_PRIVATE", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_bundled_module_delegates_to_unchanged_trojan_parser(self):
        uri = "trojan://TEST_PRIVATE@vpn.example.test:443?security=tls&type=ws"
        with forbid_external_effects():
            registry = bundled_protocols()
            module = registry.by_uri(uri)
            self.assertIs(module, registry.by_protocol("trojan"))
            self.assertIs(module.parameters_type, TrojanConnection)
            connection = module.parse_uri(uri)
            expected = TrojanLinkParser().parse(uri)
        self.assertEqual(connection.to_diagnostic(), expected.to_diagnostic())
        self.assertEqual(connection.server, expected.server)
        self.assertEqual(connection.password.reveal(), expected.password.reveal())
        self.assertEqual(module.capabilities, {ProtocolCapability.PARSE_URI})
        self.assertTrue(all(field.secret for field in module.fields))

    def test_second_module_and_alias_need_no_selection_changes(self):
        sample = sample_module()
        trojan = bundled_protocols().by_protocol("trojan")
        with forbid_external_effects():
            registry = ProtocolRegistry((trojan, sample))
            for uri in ("sample://TEST_PRIVATE", "SAMPLE+ALIAS://TEST_PRIVATE"):
                selected = registry.by_uri(uri)
                self.assertIs(selected, sample)
                registry.require(selected, ProtocolCapability.PARSE_URI)
                registry.require(selected, ProtocolCapability.VALIDATE_PARAMETERS)
                parameters = selected.parse_uri(uri)
                self.assertIs(type(parameters), SampleParameters)
                self.assertIsNone(selected.validate_parameters(parameters))
            self.assertIs(registry.by_protocol("sample"), sample)
            self.assertIs(registry.by_uri("TROJAN://TEST_PRIVATE"), trojan)

    def test_unknown_and_invalid_selectors_never_load_code(self):
        registry = bundled_protocols()
        with forbid_external_effects():
            for uri in ("https://TEST_PRIVATE/module.py", "file:///TEST_PRIVATE.py", "vless://TEST_PRIVATE"):
                self.assert_code(RegistryErrorCode.UNKNOWN_SCHEME, lambda: registry.by_uri(uri))
            for uri in (None, 1, "", " trojan://TEST_PRIVATE", "trojan%3a://TEST_PRIVATE", "x" * 33 + "://x"):
                self.assert_code(RegistryErrorCode.INVALID_SELECTOR, lambda: registry.by_uri(uri))
            self.assert_code(RegistryErrorCode.UNKNOWN_PROTOCOL, lambda: registry.by_protocol("unknown"))
            for protocol in ("TROJAN", "a.b", None, [], "", "a" * 33):
                self.assert_code(RegistryErrorCode.INVALID_SELECTOR, lambda: registry.by_protocol(protocol))

    def test_uri_rejection_traceback_does_not_retain_link(self):
        registry = bundled_protocols()
        cases = (
            ("unknown://TEST_PRIVATE@vpn.example.test:443", RegistryErrorCode.UNKNOWN_SCHEME),
            (" trojan://TEST_PRIVATE@vpn.example.test:443", RegistryErrorCode.INVALID_SELECTOR),
        )
        for uri, code in cases:
            with self.subTest(code=code):
                try:
                    registry.by_uri(uri)
                except RegistryError as error:
                    rejection = error
                else:
                    self.fail("Ожидался отказ реестра")
                self.assertIs(rejection.code, code)
                frames = frame_locals(rejection, "/keenvpn/application/protocol_registry.py")
                self.assertNotIn("TEST_PRIVATE", repr(frames))
                self.assertNotIn("vpn.example.test", repr(frames))

    def test_selection_does_not_parse_body_or_call_validation(self):
        parser, validator = Mock(), Mock()
        module = sample_module(parse_uri=parser, validate_parameters=validator)
        registry = ProtocolRegistry((module,))
        self.assertIs(registry.by_uri("sample://invalid-body"), module)
        registry.require(module, ProtocolCapability.VALIDATE_PARAMETERS)
        parser.assert_not_called()
        validator.assert_not_called()

    def test_missing_capability_and_foreign_module_are_rejected(self):
        registry = bundled_protocols()
        module = registry.by_protocol("trojan")
        self.assert_code(RegistryErrorCode.PROTOCOL_CAPABILITY, lambda: registry.require(module, ProtocolCapability.VALIDATE_PARAMETERS))
        self.assert_code(RegistryErrorCode.UNKNOWN_PROTOCOL, lambda: registry.require(replace(module), ProtocolCapability.PARSE_URI))
        self.assert_code(RegistryErrorCode.INVALID_SELECTOR, lambda: registry.require(module, "parse_uri"))

    def test_duplicate_identifiers_and_schemes_are_rejected(self):
        module = sample_module()
        self.assert_code(RegistryErrorCode.DUPLICATE_PROTOCOL, lambda: ProtocolRegistry((module, module)))
        self.assert_code(RegistryErrorCode.DUPLICATE_SCHEME, lambda: ProtocolRegistry((module, replace(module, protocol="other"))))

    def test_malformed_module_registration_is_rejected(self):
        for changes in (
            {"protocol": "../TEST_PRIVATE"}, {"uri_schemes": ["sample"]},
            {"uri_schemes": ("SAMPLE",)}, {"uri_schemes": ("sample", "sample")},
            {"uri_schemes": ()}, {"parameters_type": object()},
            {"parse_uri": "module:parser"}, {"validate_parameters": "eval"},
            {"fields": []}, {"fields": ("TEST_PRIVATE",)},
            {"fields": (ProtocolField("a", True, True), ProtocolField("a", False, True))},
        ):
            with self.subTest(changes=changes):
                self.assert_code(RegistryErrorCode.INVALID_REGISTRATION, lambda: sample_module(**changes))
        for modules in ([sample_module()], ("sample",), (object(),)):
            self.assert_code(RegistryErrorCode.INVALID_REGISTRATION, lambda: ProtocolRegistry(modules))
        for args in (("TEST_PRIVATE", True, True), ("value", 1, True), ("value", True, "yes")):
            self.assert_code(RegistryErrorCode.INVALID_REGISTRATION, lambda: ProtocolField(*args))

    def test_registration_errors_detach_external_context(self):
        try:
            raise ValueError("TEST_PRIVATE")
        except ValueError as outer:
            self.assert_code(RegistryErrorCode.INVALID_REGISTRATION, lambda: sample_module(protocol="!"))
            self.assertEqual(str(outer), "TEST_PRIVATE")


class EngineRegistryTests(unittest.TestCase):
    def test_invalid_engine_id_has_its_own_code(self):
        registry = EngineRegistry()
        for engine in ("Xray", ""):
            with self.subTest(engine=engine):
                with self.assertRaises(RegistryError) as caught:
                    registry.resolve(engine, "trojan", EngineCapability.PROBE)
                self.assertEqual(caught.exception.code.value, "invalid_engine_selector")

    def test_same_protocol_two_engines_and_one_engine_two_protocols(self):
        first, second, third = Mock(), Mock(), Mock()
        bindings = (
            EngineBinding("one", "sample", ((EngineCapability.PROBE, first),)),
            EngineBinding("two", "sample", ((EngineCapability.PROBE, second),)),
            EngineBinding("one", "trojan", ((EngineCapability.PROBE, third),)),
        )
        with forbid_external_effects():
            registry = EngineRegistry(bindings)
            for binding, callback in zip(bindings, (first, second, third)):
                selected = registry.resolve(binding.engine, binding.protocol, EngineCapability.PROBE)
                self.assertIs(selected, binding)
                self.assertIs(selected.operation(EngineCapability.PROBE), callback)
        for callback in (first, second, third):
            callback.assert_not_called()

    def test_unknown_engine_pair_and_capability_never_fallback(self):
        registry = EngineRegistry((EngineBinding("one", "sample", ((EngineCapability.PROBE, Mock()),)),))
        for engine, protocol, capability, code in (
            ("two", "sample", EngineCapability.PROBE, RegistryErrorCode.UNKNOWN_ENGINE),
            ("one", "trojan", EngineCapability.PROBE, RegistryErrorCode.ENGINE_PROTOCOL),
            ("one", "sample", EngineCapability.START, RegistryErrorCode.ENGINE_CAPABILITY),
            ("one", "sample", "probe", RegistryErrorCode.INVALID_SELECTOR),
        ):
            with self.subTest(code=code), self.assertRaises(RegistryError) as caught:
                registry.resolve(engine, protocol, capability)
            self.assertIs(caught.exception.code, code)

    def test_duplicates_and_malformed_bindings_are_rejected(self):
        binding = EngineBinding("one", "sample", ((EngineCapability.PROBE, Mock()),))
        with self.assertRaises(RegistryError) as caught:
            EngineRegistry((binding, binding))
        self.assertIs(caught.exception.code, RegistryErrorCode.DUPLICATE_ENGINE)
        for operations in ((), [], (("probe", Mock()),), ((EngineCapability.PROBE, "module.py"),), ((),), binding.operations * 2):
            with self.subTest(operations=operations), self.assertRaises(RegistryError) as caught:
                EngineBinding("one", "sample", operations)
            self.assertIs(caught.exception.code, RegistryErrorCode.INVALID_REGISTRATION)


if __name__ == "__main__":
    unittest.main()
