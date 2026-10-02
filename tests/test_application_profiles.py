"""Чтение общего профиля: точный ID, отказы, версии и приватность результата."""

from dataclasses import FrozenInstanceError, dataclass, replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from uuid import UUID


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory
from keenvpn.application.profiles import InspectConnectionProfile, InspectConnectionProfileHandler
from keenvpn.domain.connection import SecretValue, TrojanConnection
from keenvpn.domain.profile import ConnectionProfile, ProfileIdentity, ProfileValidationError
from tests.support.in_memory import (
    AdapterSetupError, InMemoryConnectionProfileSource, UnconfiguredResponseError,
)
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable


PROFILE_ID = UUID("b0000000-0000-4000-8000-000000000001")
OTHER_ID = UUID("b0000000-0000-4000-8000-000000000002")
SECRET = "TEST_ONLY_PROFILE_SECRET"
LINK = f"trojan://{SECRET}@vpn.example.test:443?security=tls&type=ws&path=%2Fsocket#URI-name"


def sample_profile():
    """Собрать профиль из результата действующего парсера без изменения модели."""
    return ConnectionProfile(
        ProfileIdentity(PROFILE_ID, SECRET, "trojan"), TrojanLinkParser().parse(LINK),
    )


class InspectConnectionProfileTests(unittest.TestCase):
    def setUp(self):
        self.source = InMemoryConnectionProfileSource()
        self.profile = sample_profile()
        self.source.set_response(PROFILE_ID, self.profile)
        self.handler = InspectConnectionProfileHandler(self.source, operation_ids=lambda: "op-1")

    def execute(self, command=None):
        return self.handler.execute(command if command is not None else InspectConnectionProfile(PROFILE_ID))

    def assert_private(self, result):
        text = repr(result) + str(result) + json.dumps(result.to_dict(), ensure_ascii=False)
        for value in (SECRET, LINK, "vpn.example.test", "/socket", "URI-name"):
            self.assertNotIn(value, text)
        self.assertFalse(any(isinstance(value, (
            SecretValue, TrojanConnection, ConnectionProfile, ProfileIdentity, BaseException,
        )) for value in reachable(result)))

    def test_reads_exact_id_and_returns_only_shared_metadata(self):
        result = self.execute()
        self.assertEqual(result.to_dict(), {
            "operation_id": "op-1", "command": "inspect_connection_profile",
            "contract_version": CONTRACT_VERSION, "status": "succeeded", "error": None,
            "data": {"profile_id": str(PROFILE_ID), "protocol": "trojan", "format_version": 1, "has_name": True},
        })
        self.assertEqual(self.source.calls, (PROFILE_ID,))
        self.assert_private(result)
        self.assertIs(self.source.get_profile(PROFILE_ID), self.profile)
        self.assertEqual(self.profile.parameters.password.reveal(), SECRET)

    def test_repeated_read_and_render_preserve_identity_without_extra_queries(self):
        first, second = self.execute(), self.execute()
        self.assertEqual(first.data, second.data)
        calls = self.source.calls
        self.assertEqual(json.loads(json.dumps(first.to_dict())), second.to_dict())
        self.assertIn("trojan", str(first.data))
        self.assertEqual(self.source.calls, calls)
        with self.assertRaises(FrozenInstanceError):
            first.data.profile_id = str(OTHER_ID)

    def test_read_does_not_repeat_construction_hooks_or_change_source(self):
        for model, field, replacement in (
            (ProfileIdentity, "name", "Café"),
            (ConnectionProfile, "parameters", object()),
        ):
            with self.subTest(model=model.__name__):
                profile = replace(self.profile, identity=replace(self.profile.identity, name="Cafe\u0301"))
                identity, parameters = profile.identity, profile.parameters
                self.source.set_response(PROFILE_ID, profile)

                def construction_hook(instance):
                    object.__setattr__(instance, field, replacement)

                with patch.object(model, "__post_init__", autospec=True, side_effect=construction_hook) as hook:
                    result = self.execute()

                self.assertTrue(result.succeeded)
                self.assertIs(profile.identity, identity)
                self.assertEqual(identity.name, "Cafe\u0301")
                self.assertIs(profile.parameters, parameters)
                self.assert_private(result)
                hook.assert_not_called()

    def test_profile_name_does_not_select_another_profile(self):
        other = replace(self.profile, identity=replace(self.profile.identity, profile_id=OTHER_ID))
        self.source.set_response(OTHER_ID, other)
        result = self.execute(InspectConnectionProfile(OTHER_ID))
        self.assertEqual(result.data.profile_id, str(OTHER_ID))
        self.assertEqual(self.source.calls, (OTHER_ID,))
        self.assertEqual(self.profile.identity.name, other.identity.name)

    def test_read_preserves_names_with_joiners_and_unassigned_characters(self):
        for name in ("👨\u200d💻 Работа", "کار\u200cها", "\U0002ebf0", "Имя \u0378"):
            with self.subTest(name=name):
                profile = replace(self.profile, identity=replace(self.profile.identity, name=name))
                self.source.set_response(PROFILE_ID, profile)
                result = self.execute()
                self.assertTrue(result.succeeded)
                self.assertIsNone(result.error)
                self.assertTrue(result.data.has_name)
                self.assertEqual(result.data.profile_id, str(PROFILE_ID))
                self.assertEqual(profile.identity.name, name)
                self.assertNotIn(name, repr(result) + json.dumps(result.to_dict(), ensure_ascii=False))
                self.assert_private(result)

    def test_wrong_command_and_version_do_not_read_source(self):
        for command, code, category in (
            (SECRET, "invalid_command", ErrorCategory.INVALID_REQUEST),
            (InspectConnectionProfile(SECRET), "invalid_command", ErrorCategory.INVALID_REQUEST),
            (InspectConnectionProfile(str(PROFILE_ID)), "invalid_command", ErrorCategory.INVALID_REQUEST),
            (InspectConnectionProfile(PROFILE_ID, contract_version=True),
             "unsupported_contract_version", ErrorCategory.INVALID_REQUEST),
            (InspectConnectionProfile(PROFILE_ID, contract_version=CONTRACT_VERSION + 1),
             "unsupported_contract_version", ErrorCategory.INVALID_REQUEST),
            (InspectConnectionProfile(UUID(int=0)), "invalid_profile_id", ErrorCategory.INVALID_INPUT),
        ):
            with self.subTest(code=code):
                result = self.execute(command)
                self.assertEqual(result.error.code, code)
                self.assertIs(result.error.category, category)
                self.assert_private(result)
                self.assertEqual(self.source.calls, ())

    def test_missing_profile_and_source_failure_have_distinct_results(self):
        for outcome, category, code in (
            (None, ErrorCategory.INVALID_INPUT, "profile_not_found"),
            (OSError(SECRET + LINK), ErrorCategory.SOURCE_FAILED, "profile_source_failed"),
            ({"name": SECRET}, ErrorCategory.INVALID_SOURCE_DATA, "invalid_profile_model"),
            (self.profile.parameters, ErrorCategory.INVALID_SOURCE_DATA, "invalid_profile_model"),
        ):
            with self.subTest(code=code):
                self.source.set_response(PROFILE_ID, outcome)
                result = self.execute()
                self.assertEqual(result.error.code, code)
                self.assertIs(result.error.category, category)
                self.assertIsNone(result.data)
                self.assert_private(result)

    def test_invalid_identity_preserves_the_domain_reason(self):
        class DerivedIdentity(ProfileIdentity):
            pass

        for identity in (None, object(), {"name": SECRET}, DerivedIdentity(PROFILE_ID, SECRET, "trojan")):
            with self.subTest(identity_type=type(identity).__name__):
                with self.assertRaises(ProfileValidationError) as caught:
                    ConnectionProfile(identity, self.profile.parameters)
                self.assertEqual(caught.exception.code.value, "invalid_profile_identity")
                profile = sample_profile()
                object.__setattr__(profile, "identity", identity)
                self.source.set_response(PROFILE_ID, profile)
                result = self.execute()
                self.assertIs(result.error.category, ErrorCategory.INVALID_SOURCE_DATA)
                self.assertEqual(result.error.code, "invalid_profile_model")
                self.assertEqual(result.error.reason, caught.exception.code.value)
                self.assertIsNone(result.data)
                self.assert_private(result)

    def test_wrong_profile_types_have_no_domain_reason_and_do_not_call_their_methods(self):
        calls = []

        class DerivedProfile(ConnectionProfile):
            def to_diagnostic(self):
                calls.append("diagnostic")
                raise AssertionError("Диагностика подкласса не должна вызываться.")

        class ProfileLike:
            @property
            def identity(self):
                calls.append("identity")
                raise AssertionError("Поля объекта другого типа не должны читаться.")

        derived = DerivedProfile(self.profile.identity, self.profile.parameters)
        for profile in (object(), {"name": SECRET}, self.profile.parameters, ProfileLike(), derived):
            with self.subTest(profile_type=type(profile).__name__):
                self.source.set_response(PROFILE_ID, profile)
                result = self.execute()
                self.assertIs(result.error.category, ErrorCategory.INVALID_SOURCE_DATA)
                self.assertEqual(result.error.code, "invalid_profile_model")
                self.assertIsNone(result.error.reason)
                self.assertIsNone(result.data)
                self.assertEqual(calls, [])
                self.assert_private(result)

    def test_source_cannot_substitute_another_profile(self):
        self.source.set_response(PROFILE_ID, replace(
            self.profile, identity=replace(self.profile.identity, profile_id=OTHER_ID),
        ))
        result = self.execute()
        self.assertEqual(result.error.code, "profile_id_mismatch")
        self.assertIs(result.error.category, ErrorCategory.INVALID_SOURCE_DATA)
        self.assert_private(result)

    def test_unknown_profile_version_is_separate_from_application_version(self):
        profile = replace(self.profile, identity=replace(self.profile.identity, format_version=2))
        self.source.set_response(PROFILE_ID, profile)
        result = self.execute()
        self.assertIs(result.error.category, ErrorCategory.UNSUPPORTED)
        self.assertEqual(result.error.code, "unsupported_profile_format_version")
        self.assertEqual(result.contract_version, CONTRACT_VERSION)
        self.assertEqual(profile.identity.format_version, 2)
        self.assertEqual(self.source.calls, (PROFILE_ID,))
        self.assert_private(result)

    def test_unknown_version_precedes_v1_validation_and_id_matching(self):
        cases = (
            ("identity", "name", SECRET * 30),
            ("identity", "protocol", "Protocol.v2"),
            ("identity", "profile_id", OTHER_ID),
            ("identity", "profile_id", "future-id"),
            ("profile", "parameters", object()),
        )
        for target, field, value in cases:
            with self.subTest(target=target, field=field):
                profile = replace(self.profile, identity=replace(self.profile.identity, format_version=2))
                object.__setattr__(profile.identity if target == "identity" else profile, field, value)
                self.source.set_response(PROFILE_ID, profile)
                result = self.execute()
                self.assertIs(result.error.category, ErrorCategory.UNSUPPORTED)
                self.assertEqual(result.error.code, "unsupported_profile_format_version")
                self.assertIsNone(result.data)
                self.assert_private(result)

    def test_invalid_version_precedes_v1_source_validation(self):
        for version in (None, True, 0, -1, 1.0, "2"):
            with self.subTest(version=version):
                profile = sample_profile()
                object.__setattr__(profile.identity, "format_version", version)
                object.__setattr__(profile.identity, "name", SECRET * 30)
                object.__setattr__(profile, "parameters", object())
                self.source.set_response(PROFILE_ID, profile)
                result = self.execute()
                self.assertIs(result.error.category, ErrorCategory.INVALID_SOURCE_DATA)
                self.assertEqual(result.error.code, "invalid_profile_model")
                self.assertEqual(result.error.reason, "invalid_profile_format_version")
                self.assert_private(result)

    def test_corrupted_source_metadata_is_rejected(self):
        for field, value, reason in (
            ("profile_id", SECRET, "invalid_profile_id"),
            ("name", "\n" + SECRET, "invalid_profile_name"),
            ("name", "Имя\u2028" + SECRET, "invalid_profile_name"),
            ("name", "Имя\u2029" + SECRET, "invalid_profile_name"),
            ("protocol", LINK, "invalid_profile_protocol"),
            ("protocol", "sample", "profile_protocol_mismatch"),
            ("format_version", True, "invalid_profile_format_version"),
        ):
            with self.subTest(field=field, reason=reason):
                profile = sample_profile()
                object.__setattr__(profile.identity, field, value)
                self.source.set_response(PROFILE_ID, profile)
                result = self.execute()
                self.assertEqual(result.error.code, "invalid_profile_model")
                self.assertEqual(result.error.reason, reason)
                self.assert_private(result)

    def test_changed_parameter_protocol_is_rejected(self):
        @dataclass
        class MutableParameters:
            protocol: str = "sample"

        parameters = MutableParameters()
        profile = ConnectionProfile(ProfileIdentity(PROFILE_ID, None, "sample"), parameters)
        parameters.protocol = "other"
        self.source.set_response(PROFILE_ID, profile)
        result = self.execute()
        self.assertEqual(result.error.reason, "profile_protocol_mismatch")
        self.assertIs(result.error.category, ErrorCategory.INVALID_SOURCE_DATA)

    def test_generic_read_does_not_use_protocol_specific_fields_or_diagnostic(self):
        @dataclass(frozen=True)
        class SampleParameters:
            secret: str = SECRET
            protocol: str = "sample"

            def to_diagnostic(self):
                raise AssertionError("Нельзя вызывать диагностику параметров.")

        profile = ConnectionProfile(ProfileIdentity(PROFILE_ID, None, "sample"), SampleParameters())
        self.source.set_response(PROFILE_ID, profile)
        result = self.execute()
        self.assertTrue(result.succeeded)
        self.assertFalse(result.data.has_name)
        self.assertEqual(result.data.protocol, "sample")
        self.assert_private(result)
        self.assertFalse(any(isinstance(value, SampleParameters) for value in reachable(result)))

    def test_interruptions_are_not_converted_to_source_failure(self):
        for error in (KeyboardInterrupt(), SystemExit()):
            self.source.set_response(PROFILE_ID, error)
            with self.assertRaises(type(error)):
                self.execute()

    def test_scenario_has_no_terminal_or_external_effects(self):
        with forbid_external_effects():
            self.assertTrue(self.execute().succeeded)
            self.source.set_response(PROFILE_ID, OSError(SECRET))
            self.assertEqual(self.execute().error.code, "profile_source_failed")
            self.source.set_response(PROFILE_ID, None)
            self.assertEqual(self.execute().error.code, "profile_not_found")

    def test_command_repr_is_safe_even_for_invalid_input(self):
        command = InspectConnectionProfile(LINK)
        self.assertNotIn(SECRET, str(command) + repr(command))
        with self.assertRaises(FrozenInstanceError):
            command.profile_id = PROFILE_ID


class InMemoryConnectionProfileSourceTests(unittest.TestCase):
    def test_responses_are_keyed_by_id_and_missing_setup_is_not_not_found(self):
        source = InMemoryConnectionProfileSource()
        source.set_response(PROFILE_ID, None)
        self.assertIsNone(source.get_profile(PROFILE_ID))
        with self.assertRaises(UnconfiguredResponseError):
            source.get_profile(OTHER_ID)
        self.assertEqual(source.calls, (PROFILE_ID, OTHER_ID))
        with self.assertRaises(UnconfiguredResponseError):
            InspectConnectionProfileHandler(source).execute(InspectConnectionProfile(OTHER_ID))

    def test_outcome_replacement_releases_exception_frames_and_repr_is_safe(self):
        source = InMemoryConnectionProfileSource()
        error = OSError(SECRET)
        source.set_response(PROFILE_ID, error)
        InspectConnectionProfileHandler(source).execute(InspectConnectionProfile(PROFILE_ID))
        self.assertIsNotNone(error.__traceback__)
        source.set_response(PROFILE_ID, sample_profile())
        self.assertIsNone(error.__traceback__)
        self.assertIsNone(error.__context__)
        self.assertNotIn(SECRET, repr(source))

    def test_invalid_setup_is_rejected(self):
        source = InMemoryConnectionProfileSource()
        for value in (None, SECRET, UUID(int=0)):
            with self.assertRaises(AdapterSetupError):
                source.set_response(value, None)
        source.set_response(PROFILE_ID, OSError)
        with self.assertRaises(AdapterSetupError):
            source.get_profile(PROFILE_ID)


if __name__ == "__main__":
    unittest.main()
