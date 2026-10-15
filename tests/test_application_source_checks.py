"""Проверка ответов источников: точный тип, повторная доменная проверка, безопасные коды."""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import ErrorCategory, ErrorDetail
from keenvpn.application.source_checks import SourceCheck, check_source_model, unavailable


class _Code(StrEnum):
    BROKEN = "model_broken"


class _DomainError(ValueError):
    def __init__(self, code: _Code) -> None:
        self.code = code
        super().__init__("Модель повреждена.")


@dataclass(frozen=True, slots=True)
class _Model:
    value: int


class _Subclass(_Model):
    pass


def _validate(model: object) -> None:
    if model.value < 0:
        raise _DomainError(_Code.BROKEN)


def _check(validate=_validate, domain_errors=(_DomainError,)) -> SourceCheck:
    return SourceCheck("invalid_test_model", _Model, validate, "Неподдерживаемый формат.", "Некорректные данные.", domain_errors)


class UnavailableTests(unittest.TestCase):
    def test_describes_source_failure_with_fixed_text(self):
        detail = unavailable("test_unavailable", "Не удалось прочитать тестовый источник.")
        self.assertEqual(
            detail, ErrorDetail(ErrorCategory.SOURCE_FAILED, "test_unavailable", "Не удалось прочитать тестовый источник."),
        )
        self.assertIsNone(detail.reason)


class SourceCheckTests(unittest.TestCase):
    def test_rejects_inconsistent_description(self):
        valid = dict(code="c", model_type=_Model, validate=_validate, type_message="t", data_message="d",
                     domain_errors=(_DomainError,))
        for field, value in (
            ("code", ""), ("code", 1), ("model_type", "Model"), ("validate", None), ("type_message", ""),
            ("data_message", 2), ("domain_errors", [_DomainError]), ("domain_errors", ()),
            ("domain_errors", (_DomainError, "x")), ("domain_errors", (int,)),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(TypeError):
                    SourceCheck(**{**valid, field: value})


class CheckSourceModelTests(unittest.TestCase):
    def test_valid_model_passes_after_one_validation(self):
        calls = []
        check = _check(validate=lambda model: calls.append(model))
        self.assertIsNone(check_source_model(check, _Model(1)))
        self.assertEqual(calls, [_Model(1)])

    def test_other_type_and_subclass_give_type_message_without_reason(self):
        check = _check()
        for value in ("модель", None, _Subclass(1), 1):
            with self.subTest(value=type(value).__name__):
                self.assertEqual(
                    check_source_model(check, value),
                    ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, "invalid_test_model", "Неподдерживаемый формат."),
                )

    def test_domain_error_gives_data_message_with_its_code(self):
        self.assertEqual(
            check_source_model(_check(), _Model(-1)),
            ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, "invalid_test_model", "Некорректные данные.", reason="model_broken"),
        )

    def test_unexpected_validation_error_gives_type_message_without_its_text(self):
        def explode(model: object) -> None:
            raise RuntimeError("TEST_SECRET_PATH")

        detail = check_source_model(_check(validate=explode), _Model(1))
        self.assertEqual(detail, ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, "invalid_test_model", "Неподдерживаемый формат."))
        self.assertNotIn("TEST_SECRET_PATH", repr(detail) + str(detail.to_dict()))

    def test_only_listed_domain_errors_carry_a_reason(self):
        class _Other(ValueError):
            code = _Code.BROKEN

        def reject(model: object) -> None:
            raise _Other()

        detail = check_source_model(_check(validate=reject), _Model(1))
        self.assertEqual(detail.message, "Неподдерживаемый формат.")
        self.assertIsNone(detail.reason)


if __name__ == "__main__":
    unittest.main()
