"""Проверки приватности результатов сценариев не зависят от случайного идентификатора операции."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import new_operation_id
from tests.support.privacy import operation_ids_with_marker


PRIVATE_RESULT_MODULES = (
    "tests.test_application_installation", "tests.test_application_proxy_config", "tests.test_application_routing_import",
)
"""Модули, где результат обработчика из помощника `handler_for` проходит проверку приватных маркеров."""
ID_MARKERS = ("1181", "1191")
"""Приватные маркеры этих модулей только из шестнадцатеричных цифр: лишь они могут оказаться в UUID."""


class OperationIdIndependenceTests(unittest.TestCase):
    def test_marker_in_random_operation_id_does_not_fail_privacy_checks(self):
        for marker in ID_MARKERS:
            with self.subTest(marker=marker), operation_ids_with_marker(marker):
                # Без этой проверки смена генератора сделала бы подмену пустой, а тест — бесполезным.
                self.assertIn(marker, new_operation_id())
                suite = unittest.defaultTestLoader.loadTestsFromNames(PRIVATE_RESULT_MODULES)
                expected = suite.countTestCases()
                result = unittest.TestResult()
                suite.run(result)
                self.assertGreater(expected, 0)
                self.assertEqual(result.testsRun, expected)
                self.assertEqual([test.id() for test, _ in result.failures + result.errors], [])


if __name__ == "__main__":
    unittest.main()
