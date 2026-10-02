"""Общий профиль на существующей модели Trojan и искусственном типе параметров."""

from dataclasses import FrozenInstanceError, dataclass, replace
import json
from pathlib import Path
import sys
import unittest
from uuid import UUID


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.trojan_uri import parse_trojan_uri
from keenvpn.domain.connection import SecretValue, TrojanConnection
from keenvpn.domain.profile import (
    PROFILE_FORMAT_VERSION, ConnectionProfile, ProfileErrorCode, ProfileIdentity,
    ProfileParameters, ProfileValidationError, validate_profile, validate_profile_identity,
)
from tests.support.isolation import forbid_external_effects


PROFILE_ID = UUID("a0000000-0000-4000-8000-000000000001")
SECRET = "TEST_ONLY_PROFILE_SECRET"
LINK = f"trojan://{SECRET}@vpn.example.test:443?security=tls&type=ws&path=%2Fsocket#URI-name"


@dataclass(frozen=True)
class SampleParameters:
    """Искусственная модель для проверки независимости от Trojan и движка."""

    token: SecretValue
    protocol: str = "sample"

    def to_diagnostic(self):
        raise AssertionError("Общий просмотр не должен вызывать методы параметров.")


class ProfileIdentityTests(unittest.TestCase):
    def test_identity_is_independent_of_parameters_and_name(self):
        identity = ProfileIdentity(PROFILE_ID, "Имя профиля", "trojan")
        connection = parse_trojan_uri(LINK)
        profile = ConnectionProfile(identity, connection)
        renamed = replace(profile, identity=replace(identity, name="Другое имя"))
        changed = replace(profile, parameters=replace(connection, server="other.example.test"))
        self.assertIs(profile.parameters, connection)
        self.assertIs(renamed.parameters, connection)
        self.assertIs(changed.identity, identity)
        self.assertEqual(renamed.identity.profile_id, PROFILE_ID)
        self.assertEqual(profile.identity.name, "Имя профиля")
        self.assertEqual(connection.name, "URI-name")
        self.assertEqual(connection.password.reveal(), SECRET)
        self.assertEqual(identity.format_version, PROFILE_FORMAT_VERSION)
        self.assertNotEqual(renamed.identity.name, connection.name)

    def test_names_are_optional_and_not_unique_keys(self):
        first = ProfileIdentity(PROFILE_ID, None, "trojan")
        second = replace(first, profile_id=UUID("a0000000-0000-4000-8000-000000000002"))
        self.assertEqual(first.name, second.name)
        self.assertNotEqual(first.profile_id, second.profile_id)
        self.assertEqual(replace(first, name="  Имя профиля  ").name, "  Имя профиля  ")

    def test_names_preserve_joiners_and_unassigned_characters(self):
        for name in ("👨\u200d💻 Работа", "کار\u200cها", "\U0002ebf0", "Имя \u0378"):
            with self.subTest(name=name):
                identity = ProfileIdentity(PROFILE_ID, name, "trojan")
                self.assertEqual(identity.name, name)

    def test_names_reject_controls_surrogates_private_use_and_bidi_controls(self):
        characters = (
            "\x00", "\n", "\t", "\x7f", "\x85", "\u2028", "\u2029", "\ud800", "\udfff",
            "\ue000", "\uf8ff", "\U000f0000", "\U0010fffd",
            *(chr(code) for code in range(0x202A, 0x202F)),
            *(chr(code) for code in range(0x2066, 0x206A)),
        )
        for character in characters:
            with self.subTest(codepoint=f"U+{ord(character):04X}"):
                with self.assertRaises(ProfileValidationError) as caught:
                    ProfileIdentity(PROFILE_ID, "Имя" + character, "trojan")
                self.assertIs(caught.exception.code, ProfileErrorCode.NAME)

    def test_invalid_metadata_has_safe_reason(self):
        cases = (
            ("profile_id", str(PROFILE_ID), ProfileErrorCode.ID),
            ("profile_id", UUID(int=0), ProfileErrorCode.ID),
            ("profile_id", None, ProfileErrorCode.ID),
            ("name", "", ProfileErrorCode.NAME),
            ("name", " \t", ProfileErrorCode.NAME),
            ("name", SECRET + "\n", ProfileErrorCode.NAME),
            ("name", SECRET + "\u202e", ProfileErrorCode.NAME),
            ("name", "x" * 257, ProfileErrorCode.NAME),
            ("name", 12, ProfileErrorCode.NAME),
            ("protocol", "", ProfileErrorCode.PROTOCOL),
            ("protocol", "Trojan", ProfileErrorCode.PROTOCOL),
            ("protocol", "trojan://" + SECRET, ProfileErrorCode.PROTOCOL),
            ("protocol", "x" * 33, ProfileErrorCode.PROTOCOL),
            ("protocol", 1, ProfileErrorCode.PROTOCOL),
            ("format_version", True, ProfileErrorCode.VERSION),
            ("format_version", 0, ProfileErrorCode.VERSION),
            ("format_version", -1, ProfileErrorCode.VERSION),
            ("format_version", 1.0, ProfileErrorCode.VERSION),
            ("format_version", "1", ProfileErrorCode.VERSION),
        )
        for key, value, code in cases:
            with self.subTest(field=key, kind=type(value).__name__):
                fields = dict(profile_id=PROFILE_ID, name=None, protocol="trojan")
                fields[key] = value
                with self.assertRaises(ProfileValidationError) as caught:
                    ProfileIdentity(**fields)
                self.assertIs(caught.exception.code, code)
                self.assertNotIn(SECRET, str(caught.exception) + repr(caught.exception))

    def test_positive_unknown_format_version_is_preserved(self):
        identity = ProfileIdentity(PROFILE_ID, None, "trojan", format_version=2)
        self.assertEqual(identity.format_version, 2)

    def test_unknown_version_preserves_fields_without_v1_validation(self):
        identity = ProfileIdentity("future-id", "Имя" * 100, "Protocol.v2", format_version=2)
        self.assertEqual(identity.profile_id, "future-id")
        self.assertEqual(identity.name, "Имя" * 100)
        self.assertEqual(identity.protocol, "Protocol.v2")
        self.assertEqual(identity.format_version, 2)

    def test_invalid_version_precedes_other_invalid_fields(self):
        for version in (None, True, 0, -1, 1.0, "2"):
            with self.subTest(version=version):
                with self.assertRaises(ProfileValidationError) as caught:
                    ProfileIdentity("future-id", "Имя" * 100, "Protocol.v2", format_version=version)
                self.assertIs(caught.exception.code, ProfileErrorCode.VERSION)


class ConnectionProfileTests(unittest.TestCase):
    def test_explicit_validation_preserves_supported_and_unknown_models(self):
        class OpaqueParameters:
            @property
            def protocol(self):
                raise AssertionError("Нельзя читать параметры неизвестной версии.")

        for identity, parameters in (
            (ProfileIdentity(PROFILE_ID, "  Cafe\u0301  ", "sample"), SampleParameters(SecretValue(SECRET))),
            (ProfileIdentity("future-id", SECRET * 30, "Protocol.v2", format_version=2), OpaqueParameters()),
        ):
            with self.subTest(version=identity.format_version):
                profile = ConnectionProfile(identity, parameters)
                before = (identity.profile_id, identity.name, identity.protocol, identity.format_version)
                for _ in range(2):
                    self.assertIsNone(validate_profile_identity(identity))
                    self.assertIsNone(validate_profile(profile))
                self.assertIs(profile.identity, identity)
                self.assertIs(profile.parameters, parameters)
                self.assertEqual(
                    (identity.profile_id, identity.name, identity.protocol, identity.format_version), before,
                )

    def test_explicit_validation_rejects_corrupted_identity_without_repair(self):
        identity = ProfileIdentity(PROFILE_ID, SECRET, "sample")
        parameters = SampleParameters(SecretValue(SECRET))
        profile = ConnectionProfile(identity, parameters)
        object.__setattr__(identity, "name", SECRET + "\n")
        for validate, model in ((validate_profile_identity, identity), (validate_profile, profile)):
            with self.subTest(validator=validate.__name__):
                with self.assertRaises(ProfileValidationError) as caught:
                    validate(model)
                self.assertIs(caught.exception.code, ProfileErrorCode.NAME)
                self.assertEqual(identity.name, SECRET + "\n")
                self.assertIs(profile.identity, identity)
                self.assertIs(profile.parameters, parameters)
                self.assertNotIn(SECRET, str(caught.exception) + repr(caught.exception))
        with self.assertRaises(ProfileValidationError) as caught:
            ConnectionProfile(identity, parameters)
        self.assertIs(caught.exception.code, ProfileErrorCode.NAME)
        self.assertEqual(identity.name, SECRET + "\n")

    def test_unknown_version_preserves_opaque_parameters_and_has_safe_diagnostic(self):
        class OpaqueParameters:
            @property
            def protocol(self):
                raise AssertionError("Нельзя интерпретировать параметры неизвестной версии.")

        parameters = OpaqueParameters()
        identity = ProfileIdentity(PROFILE_ID, SECRET, "trojan", format_version=2)
        profile = ConnectionProfile(identity, parameters)
        self.assertIs(profile.identity, identity)
        self.assertIs(profile.parameters, parameters)
        self.assertEqual(profile.to_diagnostic(), {"format_version": 2})
        self.assertNotIn(SECRET, repr(profile) + json.dumps(profile.to_diagnostic()))

    def test_typed_parameters_need_no_engine_or_trojan_fields(self):
        parameters = SampleParameters(SecretValue(SECRET))
        profile = ConnectionProfile(ProfileIdentity(PROFILE_ID, SECRET, "sample"), parameters)
        self.assertIsInstance(parameters, ProfileParameters)
        self.assertIs(profile.parameters, parameters)
        self.assertEqual(profile.to_diagnostic(), {
            "profile_id": str(PROFILE_ID), "protocol": "sample",
            "format_version": 1, "has_name": True,
        })
        self.assertNotIn(SECRET, json.dumps(profile.to_diagnostic()) + repr(profile) + repr(profile.identity))

    def test_invalid_parameter_structure_or_protocol_is_rejected(self):
        identity = ProfileIdentity(PROFILE_ID, None, "trojan")
        for parameters, code in (
            ({"protocol": "trojan", "password": SECRET}, ProfileErrorCode.PARAMETERS),
            (None, ProfileErrorCode.PARAMETERS),
            (SampleParameters(SecretValue(SECRET)), ProfileErrorCode.PROTOCOL_MISMATCH),
            (SampleParameters(SecretValue(SECRET), protocol=1), ProfileErrorCode.PARAMETERS),
        ):
            with self.subTest(kind=type(parameters).__name__), self.assertRaises(ProfileValidationError) as caught:
                ConnectionProfile(identity, parameters)
            self.assertIs(caught.exception.code, code)
        with self.assertRaises(ProfileValidationError) as caught:
            ConnectionProfile({"name": SECRET}, parse_trojan_uri(LINK))
        self.assertIs(caught.exception.code, ProfileErrorCode.IDENTITY)

    def test_parameter_exception_is_replaced_without_its_chain(self):
        class BrokenParameters:
            @property
            def protocol(self):
                raise RuntimeError(SECRET)

        try:
            ConnectionProfile(ProfileIdentity(PROFILE_ID, None, "trojan"), BrokenParameters())
        except ProfileValidationError as error:
            self.assertIs(error.code, ProfileErrorCode.PARAMETERS)
            self.assertIsNone(error.__context__)
            self.assertIsNone(error.__cause__)
            self.assertNotIn(SECRET, repr(error))
        else:
            self.fail("Ожидался безопасный отказ модели параметров.")

    def test_shell_is_immutable_and_does_not_change_trojan(self):
        connection = parse_trojan_uri(LINK)
        before = connection.to_diagnostic()
        profile = ConnectionProfile(ProfileIdentity(PROFILE_ID, None, "trojan"), connection)
        with self.assertRaises(FrozenInstanceError):
            profile.identity.name = "Другое имя"
        with self.assertRaises(FrozenInstanceError):
            profile.parameters = None
        self.assertEqual(connection.to_diagnostic(), before)
        self.assertEqual(connection.password.reveal(), SECRET)
        self.assertIsInstance(connection, TrojanConnection)

    def test_model_and_diagnostic_have_no_external_effects(self):
        with forbid_external_effects():
            connection = parse_trojan_uri(LINK)
            profile = ConnectionProfile(ProfileIdentity(PROFILE_ID, SECRET, "trojan"), connection)
            diagnostic = profile.to_diagnostic()
        self.assertFalse(any(isinstance(value, (SecretValue, TrojanConnection)) for value in diagnostic.values()))


if __name__ == "__main__":
    unittest.main()
