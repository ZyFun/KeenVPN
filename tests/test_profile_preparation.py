"""Сохранность Trojan при переходе к общему профилю и контракт расширения."""

from dataclasses import dataclass, fields, replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keenvpn.adapters.protocols import bundled_protocols
from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.connections import InspectConnectionLink, InspectConnectionLinkHandler
from keenvpn.application.contract import ErrorCategory
from keenvpn.application.ports import ConnectionLinkRejected, LinkRejection
from keenvpn.application.profile_preparation import ConnectionProfileFactory, ProfilePreparationError
from keenvpn.application.profiles import (
    InspectConnectionProfile, InspectConnectionProfileHandler, InspectProfileLink, InspectProfileLinkHandler,
)
from keenvpn.application.protocol_registry import ProtocolRegistry
from keenvpn.domain.connection import SecretValue, TrojanConnection
from keenvpn.domain.profile import ConnectionProfile, ProfileIdentity
from tests.support.in_memory import InMemoryConnectionProfileSource
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import frame_locals, reachable
from tests.support.protocols import SampleParameters, sample_module


PROFILE_ID = UUID("d0000000-0000-4000-8000-000000000001")
IDENTITY = ProfileIdentity(PROFILE_ID, "TEST_ONLY_PRIVATE_NAME", "trojan")
URI = "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443?type=ws&security=tls#URI-name"


class ProfilePreparationTests(unittest.TestCase):
    def setUp(self):
        self.factory = ConnectionProfileFactory(bundled_protocols())

    def rejection(self, action):
        try:
            with forbid_external_effects():
                action()
        except ProfilePreparationError as error:
            return error
        self.fail("Ожидался отказ подготовки профиля.")

    def test_regression_fixtures_keep_every_field_and_secret(self):
        fixtures = json.loads((Path(__file__).parent / "fixtures/trojan_profiles.json").read_text())
        for fixture in fixtures:
            with self.subTest(uri=fixture["expected"]["server"]), forbid_external_effects():
                legacy = TrojanLinkParser().parse(fixture["uri"])
                migrated = self.factory.from_parameters(IDENTITY, legacy)
                parsed = self.factory.from_link(IDENTITY, SecretValue(fixture["uri"]))
                self.assertIs(migrated.identity, IDENTITY)
                self.assertIs(migrated.parameters, legacy)
                self.assertIs(migrated.parameters.password, legacy.password)
                for profile in (migrated, parsed):
                    actual = {
                        field.name: getattr(profile.parameters, field.name)
                        for field in fields(TrojanConnection)
                    }
                    actual["password"] = actual["password"].reveal()
                    self.assertEqual(actual, fixture["expected"])
                    self.assertEqual(profile.identity.format_version, 1)
                self.assertEqual(parsed.identity.name, IDENTITY.name)

    def test_existing_parameters_are_not_reparsed_or_protocol_validated(self):
        module = bundled_protocols().by_protocol("trojan")
        parser, validator = Mock(side_effect=AssertionError), Mock(side_effect=AssertionError)
        factory = ConnectionProfileFactory(ProtocolRegistry((replace(
            module, parse_uri=parser, validate_parameters=validator,
        ),)))
        # Произвольная уже имеющаяся модель не объявляется валидной URI/работающим VPN.
        original = TrojanConnection("legacy.example.test", 0, SecretValue("TEST_ONLY"), "legacy")
        with forbid_external_effects():
            profile = factory.from_parameters(IDENTITY, original)
        self.assertIs(profile.parameters, original)
        parser.assert_not_called()
        validator.assert_not_called()

    def test_extension_fields_are_retained_on_original_typed_object(self):
        @dataclass(frozen=True, slots=True, repr=False)
        class ExtendedTrojan(TrojanConnection):
            extension: object = None

        extension = {"unknown": {"format_version": 7, "value": ["TEST_ONLY_EXTENSION"]}}
        original = ExtendedTrojan("legacy.example.test", 443, SecretValue("TEST_ONLY"), "/", extension=extension)
        with forbid_external_effects():
            profile = self.factory.from_parameters(IDENTITY, original)
        self.assertIs(profile.parameters, original)
        self.assertIs(profile.parameters.extension, extension)
        self.assertEqual(extension["unknown"]["format_version"], 7)

    def test_unknown_version_is_preserved_without_registry_or_parameter_access(self):
        registry = Mock(side_effect=AssertionError)
        factory = ConnectionProfileFactory(registry)
        identity = ProfileIdentity("future-id", "future\nname", "future.protocol", 2)
        parameters = {"unknown": ["TEST_ONLY"], "format_version": 9}
        with forbid_external_effects():
            profile = factory.from_parameters(identity, parameters)
            self.assertIs(profile.identity, identity)
            self.assertIs(profile.parameters, parameters)
            self.assertEqual(profile.to_diagnostic(), {"format_version": 2})
            error = self.rejection(lambda: factory.from_link(identity, object()))
        self.assertEqual(error.detail.code, "unsupported_profile_format_version")
        self.assertEqual(registry.mock_calls, [])

    def test_invalid_identity_is_rejected_before_parser(self):
        parser = Mock()
        module = replace(bundled_protocols().by_protocol("trojan"), parse_uri=parser)
        factory = ConnectionProfileFactory(ProtocolRegistry((module,)))
        damaged = replace(IDENTITY)
        object.__setattr__(damaged, "format_version", True)
        error = self.rejection(lambda: factory.from_link(damaged, SecretValue(URI)))
        self.assertEqual(error.detail.reason, "invalid_profile_format_version")
        parser.assert_not_called()
        self.assertEqual(self.rejection(lambda: factory.from_parameters(None, object())).detail.code,
                         "invalid_profile_identity")

    def test_wrong_model_and_protocol_mismatch_are_explicit(self):
        self.assertEqual(self.rejection(lambda: self.factory.from_parameters(
            IDENTITY, {"password": "TEST_ONLY"},
        )).detail.code, "invalid_connection_model")
        sample = sample_module(parse_uri=lambda uri: SampleParameters(SecretValue(uri), protocol="other"))
        factory = ConnectionProfileFactory(ProtocolRegistry((sample,)))
        error = self.rejection(lambda: factory.from_link(replace(IDENTITY, protocol="sample"), SecretValue("sample://x")))
        self.assertIs(error.detail.category, ErrorCategory.INVALID_SOURCE_DATA)
        self.assertEqual(error.detail.reason, "profile_protocol_mismatch")

    def test_second_protocol_uses_same_factory_and_scenario(self):
        factory = ConnectionProfileFactory(ProtocolRegistry((sample_module(),)))
        identity = replace(IDENTITY, protocol="sample", name=None)
        with forbid_external_effects():
            profile = factory.from_link(identity, SecretValue("sample+alias://TEST_ONLY"))
            wrapped = factory.from_parameters(identity, profile.parameters)
            result = InspectProfileLinkHandler(factory).execute(InspectProfileLink(identity, SecretValue("sample://x")))
        self.assertIs(wrapped.parameters, profile.parameters)
        self.assertEqual(profile.parameters.value.reveal(), "sample+alias://TEST_ONLY")
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data.protocol, "sample")

    def test_missing_module_or_parser_never_falls_back(self):
        unknown = replace(IDENTITY, protocol="unknown")
        self.assertEqual(self.rejection(lambda: self.factory.from_link(unknown, SecretValue(URI))).detail.code,
                         "unknown_protocol")
        factory = ConnectionProfileFactory(ProtocolRegistry((sample_module(parse_uri=None),)))
        self.assertEqual(self.rejection(lambda: factory.from_link(
            replace(IDENTITY, protocol="sample"), SecretValue("sample://x"),
        )).detail.code, "unsupported_protocol_capability")

    def test_existing_parameters_of_unregistered_protocol_are_rejected(self):
        identity = replace(IDENTITY, protocol="vless")
        parameters = SampleParameters(SecretValue("TEST_ONLY_UNREGISTERED"), protocol="vless")
        error = self.rejection(lambda: self.factory.from_parameters(identity, parameters))
        self.assertIs(error.detail.category, ErrorCategory.UNSUPPORTED)
        self.assertEqual(error.detail.code, "unknown_protocol")
        self.assertEqual(parameters.protocol, identity.protocol)
        self.assertEqual(parameters.value.reveal(), "TEST_ONLY_UNREGISTERED")

    def test_invalid_secret_input_never_calls_parser(self):
        parser = Mock()
        factory = ConnectionProfileFactory(ProtocolRegistry((replace(
            bundled_protocols().by_protocol("trojan"), parse_uri=parser,
        ),)))
        for link in (URI, None, SecretValue(b"bad")):
            with self.subTest(kind=type(link).__name__):
                error = self.rejection(lambda: factory.from_link(IDENTITY, link))
                self.assertEqual(error.detail.code, "invalid_profile_link")
        parser.assert_not_called()

    def test_parameter_rejection_does_not_retain_unknown_fields(self):
        parameters = {"unknown": URI}
        error = self.rejection(lambda: self.factory.from_parameters(IDENTITY, parameters))
        self.assertEqual(parameters, {"unknown": URI})
        self.assertIsNone(error.__context__)
        for frame in frame_locals(error, "/keenvpn/application/profile_preparation.py"):
            self.assertNotIn("TEST_ONLY", frame)
            self.assertNotIn("vpn.example.test", frame)

    def test_read_of_unknown_version_refuses_without_interpreting_parameters(self):
        identity = ProfileIdentity(PROFILE_ID, "future\nname", "future.protocol", 2)
        with forbid_external_effects():
            profile = self.factory.from_parameters(identity, {"TEST_ONLY": "opaque"})
            source = InMemoryConnectionProfileSource()
            source.set_response(PROFILE_ID, profile)
            result = InspectConnectionProfileHandler(source).execute(InspectConnectionProfile(PROFILE_ID))
        self.assertEqual(result.error.code, "unsupported_profile_format_version")
        self.assertEqual(profile.identity.format_version, 2)

    def test_trojan_refusals_keep_legacy_codes_reasons_and_messages(self):
        for uri in ("", "bad", URI.replace(":443", ":0"), URI.replace("type=ws", "type=grpc"),
                    URI.replace("type=ws", "type=ws&unknown=x"), URI.replace("trojan://", "vless://")):
            with self.subTest(uri=uri), forbid_external_effects():
                legacy = InspectConnectionLinkHandler(TrojanLinkParser()).execute(InspectConnectionLink(SecretValue(uri)))
                error = self.rejection(lambda: self.factory.from_link(IDENTITY, SecretValue(uri)))
                result = InspectProfileLinkHandler(self.factory).execute(InspectProfileLink(IDENTITY, SecretValue(uri)))
            self.assertEqual(error.detail, legacy.error)
            self.assertEqual(result.error, legacy.error)

    def test_parser_failure_and_bad_response_are_safe_and_detached(self):
        for outcome, code in ((RuntimeError(URI), "profile_preparation_failed"),
                              ({"secret": URI}, "invalid_connection_model")):
            parser = Mock(side_effect=outcome) if isinstance(outcome, Exception) else Mock(return_value=outcome)
            factory = ConnectionProfileFactory(ProtocolRegistry((replace(
                bundled_protocols().by_protocol("trojan"), parse_uri=parser,
            ),)))
            try:
                raise RuntimeError("TEST_ONLY_OUTER")
            except RuntimeError:
                error = self.rejection(lambda: factory.from_link(IDENTITY, SecretValue(URI)))
            self.assertEqual(error.detail.code, code)
            self.assertIsNone(error.__context__)
            self.assertIsNone(error.__cause__)
            self.assertNotIn("TEST_ONLY", repr(error) + repr(error.detail))
            for frame in frame_locals(error, "/keenvpn/application/profile_preparation.py"):
                self.assertNotIn("TEST_ONLY", frame)
                self.assertNotIn("vpn.example.test", frame)
            parser.assert_called_once_with(URI)

    def test_parser_rejection_subclass_is_not_interpreted(self):
        str_calls = []

        class SpecificRejection(ConnectionLinkRejected):
            def __str__(self):
                str_calls.append(self)
                return URI

        def reject(link):
            raise SpecificRejection(LinkRejection.INVALID, "invalid_uri", URI, reason="invalid_port")

        parser = Mock(side_effect=reject)
        factory = ConnectionProfileFactory(ProtocolRegistry((replace(
            bundled_protocols().by_protocol("trojan"), parse_uri=parser,
        ),)))
        error = self.rejection(lambda: factory.from_link(IDENTITY, SecretValue(URI)))
        with forbid_external_effects():
            result = InspectProfileLinkHandler(factory).execute(InspectProfileLink(IDENTITY, SecretValue(URI)))
        for detail in (error.detail, result.error):
            self.assertIs(detail.category, ErrorCategory.SOURCE_FAILED)
            self.assertEqual(detail.code, "profile_preparation_failed")
            self.assertIsNone(detail.reason)
            self.assertNotIn("TEST_ONLY", repr(detail) + json.dumps(detail.to_dict()))
        self.assertEqual(str_calls, [])
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertEqual(parser.call_count, 2)

    def test_interruptions_propagate(self):
        for interruption in (KeyboardInterrupt, SystemExit):
            parser = Mock(side_effect=interruption)
            factory = ConnectionProfileFactory(ProtocolRegistry((replace(
                bundled_protocols().by_protocol("trojan"), parse_uri=parser,
            ),)))
            with self.assertRaises(interruption), forbid_external_effects():
                factory.from_link(IDENTITY, SecretValue(URI))
            with self.assertRaises(interruption), forbid_external_effects():
                InspectProfileLinkHandler(factory).execute(InspectProfileLink(IDENTITY, SecretValue(URI)))

    def test_preview_matches_read_by_id_without_exposing_or_mutating_profile(self):
        with forbid_external_effects():
            profile = self.factory.from_link(IDENTITY, SecretValue(URI))
            source = InMemoryConnectionProfileSource()
            source.set_response(PROFILE_ID, profile)
            read = InspectConnectionProfileHandler(source).execute(InspectConnectionProfile(PROFILE_ID))
            command = InspectProfileLink(IDENTITY, SecretValue(URI))
            preview = InspectProfileLinkHandler(self.factory).execute(command)
            self.assertIs(source.get_profile(PROFILE_ID), profile)
        self.assertEqual(read.data, preview.data)
        self.assertEqual(profile.parameters.name, "URI-name")
        text = repr(command) + repr(preview) + json.dumps(preview.to_dict())
        for fragment in ("TEST_ONLY", "vpn.example.test", "URI-name"):
            self.assertNotIn(fragment, text)
        self.assertFalse(any(isinstance(item, (
            SecretValue, TrojanConnection, ConnectionProfile, ProfileIdentity, BaseException,
        )) for item in reachable(preview)))

    def test_preview_checks_command_and_version_before_factory(self):
        factory = Mock()
        handler = InspectProfileLinkHandler(factory)
        cases = (
            (URI, "invalid_command"),
            (InspectProfileLink(None, SecretValue(URI)), "invalid_command"),
            (InspectProfileLink(IDENTITY, URI), "invalid_command"),
            (InspectProfileLink(IDENTITY, SecretValue(b"bad")), "invalid_command"),
            (InspectProfileLink(None, None, contract_version=2), "unsupported_contract_version"),
            (InspectProfileLink(IDENTITY, SecretValue(URI), contract_version=True), "unsupported_contract_version"),
        )
        for command, code in cases:
            with self.subTest(code=code), forbid_external_effects():
                result = handler.execute(command)
            self.assertEqual(result.error.code, code)
            self.assertIs(result.error.category, ErrorCategory.INVALID_REQUEST)
        factory.assert_not_called()
        self.assertEqual(factory.mock_calls, [])

    def test_preview_rejects_unknown_profile_version_before_registry_and_parser(self):
        parser = Mock(side_effect=AssertionError("Парсер не должен вызываться."))
        module = replace(bundled_protocols().by_protocol("trojan"), parse_uri=parser)
        registry = Mock(wraps=ProtocolRegistry((module,)))
        factory = ConnectionProfileFactory(registry)
        identity = ProfileIdentity(PROFILE_ID, "future\nname", "future.protocol", 2)
        with forbid_external_effects():
            result = InspectProfileLinkHandler(factory).execute(InspectProfileLink(identity, SecretValue(URI)))
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.data)
        self.assertIs(result.error.category, ErrorCategory.UNSUPPORTED)
        self.assertEqual(result.error.code, "unsupported_profile_format_version")
        self.assertEqual(registry.mock_calls, [])
        parser.assert_not_called()

    def test_preview_rejects_bad_factory_data(self):
        cases = (
            ({"secret": URI}, "invalid_profile_model"),
            (ConnectionProfile(replace(IDENTITY, profile_id=UUID(int=1)), TrojanLinkParser().parse(URI)),
             "profile_id_mismatch"),
            (RuntimeError(URI), "profile_preparation_failed"),
        )
        for outcome, code in cases:
            factory = Mock()
            if isinstance(outcome, Exception):
                factory.from_link.side_effect = outcome
            else:
                factory.from_link.return_value = outcome
            with self.subTest(code=code), forbid_external_effects():
                result = InspectProfileLinkHandler(factory).execute(InspectProfileLink(IDENTITY, SecretValue(URI)))
            self.assertEqual(result.error.code, code)
            self.assertNotIn("TEST_ONLY", repr(result) + json.dumps(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
