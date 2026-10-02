"""Отделение отказов профиля от внешних исключений с искусственными секретами."""

from dataclasses import dataclass
import io
import logging
from pathlib import Path
import sys
import traceback
import unittest
from uuid import UUID


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.profile import (
    ConnectionProfile, ProfileErrorCode, ProfileIdentity, ProfileValidationError,
    validate_profile, validate_profile_format_version, validate_profile_identity,
)


PROFILE_ID = UUID("a0000000-0000-4000-8000-000000000001")
OUTER_SECRET = "TEST_ONLY_OUTER_PROFILE_SECRET"
CAUSE_SECRET = "TEST_ONLY_CAUSE_PROFILE_SECRET"
PARAMETER_SECRET = "TEST_ONLY_PARAMETER_PROFILE_SECRET"


@dataclass
class Parameters:
    """Изменяемые доверенные параметры для повторной проверки профиля."""

    protocol: object = "sample"


class BrokenParameters:
    """Ошибка доверенной модели тоже может содержать приватные данные."""

    @property
    def protocol(self):
        raise RuntimeError(PARAMETER_SECRET)


def rejection_cases():
    """Все коды отказа при создании, повторной проверке и диагностике."""
    cases = [("version", ProfileErrorCode.VERSION, lambda: validate_profile_format_version(0))]
    for field, invalid, code in (
        ("format_version", 0, ProfileErrorCode.VERSION),
        ("profile_id", UUID(int=0), ProfileErrorCode.ID),
        ("name", "Имя\n", ProfileErrorCode.NAME),
        ("protocol", "Sample", ProfileErrorCode.PROTOCOL),
    ):
        fields = dict(profile_id=PROFILE_ID, name=None, protocol="sample")
        fields[field] = invalid
        cases.append((f"identity_constructor/{field}", code, lambda fields=fields: ProfileIdentity(**fields)))
        identity = ProfileIdentity(PROFILE_ID, None, "sample")
        profile = ConnectionProfile(identity, Parameters())
        object.__setattr__(identity, field, invalid)
        cases.extend((
            (f"identity_validation/{field}", code, lambda identity=identity: validate_profile_identity(identity)),
            (f"profile_constructor/{field}", code, lambda identity=identity: ConnectionProfile(identity, Parameters())),
            (f"profile_validation/{field}", code, lambda profile=profile: validate_profile(profile)),
        ))
        if field == "format_version":
            cases.append(("diagnostic/version", code, profile.to_diagnostic))
    for label, identity, parameters, code in (
        ("identity", None, Parameters(), ProfileErrorCode.IDENTITY),
        ("parameters_missing", ProfileIdentity(PROFILE_ID, None, "sample"), None, ProfileErrorCode.PARAMETERS),
        ("parameters_mapping", ProfileIdentity(PROFILE_ID, None, "sample"), {"protocol": "sample"}, ProfileErrorCode.PARAMETERS),
        ("protocol_type", ProfileIdentity(PROFILE_ID, None, "sample"), Parameters(1), ProfileErrorCode.PARAMETERS),
        ("protocol_mismatch", ProfileIdentity(PROFILE_ID, None, "sample"), Parameters("other"), ProfileErrorCode.PROTOCOL_MISMATCH),
        ("parameter_exception", ProfileIdentity(PROFILE_ID, None, "sample"), BrokenParameters(), ProfileErrorCode.PARAMETERS),
    ):
        cases.append((f"profile_constructor/{label}", code,
                      lambda identity=identity, parameters=parameters: ConnectionProfile(identity, parameters)))
        profile = ConnectionProfile(ProfileIdentity(PROFILE_ID, None, "sample"), Parameters())
        object.__setattr__(profile, "identity", identity)
        object.__setattr__(profile, "parameters", parameters)
        cases.append((f"profile_validation/{label}", code, lambda profile=profile: validate_profile(profile)))
    return cases


class ProfileErrorContextTests(unittest.TestCase):
    def check_rejection(self, operation, code, *, formatted=False, logged=False):
        """Проверять настоящее исключение внутри except, не очищая его unittest."""
        try:
            operation()
        except ProfileValidationError as error:
            self.assertIs(error.code, code)
            if formatted:
                rendered = "".join(traceback.format_exception(error))
                for secret in (OUTER_SECRET, CAUSE_SECRET, PARAMETER_SECRET):
                    self.assertNotIn(secret, rendered)
                self.assertIn("ProfileValidationError", rendered)
            if logged:
                stream = io.StringIO()
                logger = logging.Logger("profile-context-test")
                logger.addHandler(logging.StreamHandler(stream))
                logger.exception("Отказ профиля")
                for secret in (OUTER_SECRET, CAUSE_SECRET, PARAMETER_SECRET):
                    self.assertNotIn(secret, stream.getvalue())
                self.assertIn("ProfileValidationError", stream.getvalue())
            self.assertIsNone(error.__context__)
            self.assertIsNone(error.__cause__)
        else:
            self.fail("Ожидался отказ профиля.")

    def test_all_rejections_without_active_exception(self):
        for label, code, operation in rejection_cases():
            with self.subTest(path=label):
                self.check_rejection(operation, code, formatted=True)

    def run_inside_outer_exception(self, *, formatted=False, logged=False):
        cause = ValueError(CAUSE_SECRET)
        for label, code, operation in rejection_cases():
            with self.subTest(path=label):
                try:
                    raise RuntimeError(OUTER_SECRET) from cause
                except RuntimeError as outer:
                    original_traceback = outer.__traceback__
                    self.check_rejection(operation, code, formatted=formatted, logged=logged)
                    # Чужое исключение принадлежит вызывающему коду и не изменяется.
                    self.assertIs(outer.__cause__, cause)
                    self.assertIs(outer.__traceback__, original_traceback)
                    self.assertEqual(str(outer), OUTER_SECRET)

    def test_all_rejections_detach_active_context_and_cause(self):
        self.run_inside_outer_exception()

    def test_standard_traceback_does_not_print_external_secrets(self):
        self.run_inside_outer_exception(formatted=True)

    def test_logger_exception_does_not_print_external_secrets(self):
        self.run_inside_outer_exception(logged=True)

    def test_parameter_interruptions_are_not_wrapped(self):
        for interruption in (KeyboardInterrupt(), SystemExit()):
            class InterruptedParameters:
                @property
                def protocol(self):
                    raise interruption

            identity = ProfileIdentity(PROFILE_ID, None, "sample")
            for operation in (
                lambda: ConnectionProfile(identity, InterruptedParameters()),
                lambda: validate_profile(profile),
            ):
                profile = ConnectionProfile(identity, Parameters())
                object.__setattr__(profile, "parameters", InterruptedParameters())
                with self.subTest(interruption=type(interruption).__name__):
                    with self.assertRaises(type(interruption)) as caught:
                        operation()
                    self.assertIs(caught.exception, interruption)


if __name__ == "__main__":
    unittest.main()
