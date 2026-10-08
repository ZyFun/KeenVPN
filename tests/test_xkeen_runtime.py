"""Преобразование вывода `pidof` и наличия маркера в наблюдение без обращения к роутеру."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.xkeen_runtime import (
    XKEEN_READY_MARKER_PATH, XKEEN_RUNTIME_DIRECTORY, XRAY_PROCESS_NAME, xray_process_from_pidof,
)
from keenvpn.domain.xray_process import XrayProcessError, XrayProcessErrorCode, XrayProcessObservation, XrayProcessState
from tests.support.isolation import forbid_external_effects


class PidofObservationTests(unittest.TestCase):
    def test_pidof_output_becomes_observation_in_output_order(self):
        for output, marker, pids, state in (
            (b"", False, (), XrayProcessState.STOPPED),
            (b"", True, (), XrayProcessState.MARKER_WITHOUT_PROCESS),
            (b"4242\n", True, (4242,), XrayProcessState.RUNNING),
            (b"4242", False, (4242,), XrayProcessState.PROCESS_WITHOUT_MARKER),
            (b"28147 1294\n", True, (28147, 1294), XrayProcessState.MULTIPLE_PROCESSES),
            (b"  7 \t 8\r\n", False, (7, 8), XrayProcessState.MULTIPLE_PROCESSES),
        ):
            with self.subTest(output=output, marker=marker), forbid_external_effects():
                observation = xray_process_from_pidof(output, marker)
            self.assertIs(type(observation), XrayProcessObservation)
            self.assertEqual((observation.pids, observation.ready_marker, observation.state), (pids, marker, state))
        self.assertEqual(XRAY_PROCESS_NAME, "xray")
        self.assertEqual((XKEEN_RUNTIME_DIRECTORY, XKEEN_READY_MARKER_PATH), ("/tmp/.xkeen", "/tmp/.xkeen/ready"))

    def test_rejections_keep_model_code_and_detach_context(self):
        for output, marker in (
            (b"abc", True), (b"4242 abc", True), (b"0", True), (b"042", True), (("1" * 5000).encode(), True),
            (b"4194305", True), (b"-5", True), (b"+5", True), (b"4242 4242", True), (b"\xff", True),
            ("4242", True), (b"4242", 1), (b"4242", None), ("١٢".encode("utf-8"), True),
            (b"4242,4243", False), (b"42.42", False),
        ):
            with self.subTest(output=output, marker=marker):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(XrayProcessError) as caught:
                        xray_process_from_pidof(output, marker)
                self.assertIs(caught.exception.code, XrayProcessErrorCode.OBSERVATION)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("fixture-private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
