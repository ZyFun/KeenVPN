"""Наблюдение процесса Xray и маркера готовности: состояния, отказы и отсутствие вывода о VPN."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.xray_process import (
    PID_MAX, XrayProcessError, XrayProcessErrorCode, XrayProcessObservation, XrayProcessState,
    validate_xray_process_observation,
)
from tests.support.isolation import forbid_external_effects


class XrayProcessObservationTests(unittest.TestCase):
    def test_states_follow_process_and_marker_without_choosing_first(self):
        cases = (
            ((), False, XrayProcessState.STOPPED, True),
            ((4242,), True, XrayProcessState.RUNNING, True),
            ((4242,), False, XrayProcessState.PROCESS_WITHOUT_MARKER, False),
            ((), True, XrayProcessState.MARKER_WITHOUT_PROCESS, False),
            ((4242, 4243), True, XrayProcessState.MULTIPLE_PROCESSES, False),
            ((4243, 4242), False, XrayProcessState.MULTIPLE_PROCESSES, False),
            ((1, PID_MAX), True, XrayProcessState.MULTIPLE_PROCESSES, False),
        )
        for pids, marker, state, consistent in cases:
            with self.subTest(pids=pids, marker=marker), forbid_external_effects():
                observation = XrayProcessObservation(pids, marker)
                self.assertIs(observation.state, state)
                self.assertEqual(observation.consistent, consistent)
                self.assertEqual(observation.process_count, len(pids))
                diagnostic = observation.to_diagnostic()
                self.assertEqual(diagnostic, {
                    "process_count": len(pids), "pids": list(pids), "ready_marker": marker,
                    "state": state.value, "consistent": consistent,
                })
                self.assertEqual(json.loads(json.dumps(diagnostic)), diagnostic)
                # Наблюдение не делает выводов о готовности канала или работе VPN.
                self.assertNotIn("vpn", json.dumps(diagnostic).lower())
                validate_xray_process_observation(observation)
        with self.assertRaises(FrozenInstanceError):
            XrayProcessObservation((4242,), True).ready_marker = False

    def test_rejections_keep_code_and_detach_context(self):
        for pids, marker in (
            ([4242], True), (None, True), ((True,), True), ((0,), True), ((-1,), False), ((PID_MAX + 1,), True),
            ((10 ** 5000,), True), (("4242",), True), ((4242, 4242), True), ((4242,), 1), ((4242,), None),
            ((4242, 4243, 4242), False),
        ):
            with self.subTest(pids=type(pids).__name__, marker=marker):
                try:
                    raise ValueError("fixture-private-context")
                except ValueError:
                    with self.assertRaises(XrayProcessError) as caught:
                        XrayProcessObservation(pids, marker)
                self.assertIs(caught.exception.code, XrayProcessErrorCode.OBSERVATION)
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
                self.assertNotIn("fixture-private", str(caught.exception) + repr(caught.exception))

    def test_validation_detects_tampering_and_foreign_types(self):
        class Derived(XrayProcessObservation):
            pass

        for broken in (Derived((4242,), True), None, (4242,), {"pids": (4242,), "ready_marker": True}):
            with self.subTest(broken=type(broken).__name__), self.assertRaises(XrayProcessError) as caught:
                validate_xray_process_observation(broken)
            self.assertIs(caught.exception.code, XrayProcessErrorCode.OBSERVATION)
        for field_name, value in (("pids", (4242, 4242)), ("pids", [4242]), ("pids", (0,)), ("ready_marker", 1)):
            with self.subTest(field=field_name):
                tampered = XrayProcessObservation((4242,), True)
                object.__setattr__(tampered, field_name, value)
                with self.assertRaises(XrayProcessError) as caught:
                    validate_xray_process_observation(tampered)
                self.assertIs(caught.exception.code, XrayProcessErrorCode.OBSERVATION)


if __name__ == "__main__":
    unittest.main()
