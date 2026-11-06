"""Отмена выделенного координатора: настоящий staging, двойники процессов и сигналов."""

from contextlib import ExitStack
from pathlib import Path
import os
import hashlib
import signal
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters import xray_isolated_port as port
from keenvpn.adapters import xray_linux_runner as runner_module
from keenvpn.adapters.xray_candidate_test import StagedXrayTest, XrayTestExit
from keenvpn.adapters.xray_owned_wait import ProcessCleanupFailed
from keenvpn.application.xray_candidate import CandidateAsset, XrayTestInput, XrayTestOutcome as Outcome
from keenvpn.domain.routing import GeoDatabaseKind


class _WorkerExit(BaseException):
    pass


class _Signals:
    """Моделирует kernel-pending и уже доставленный Python сигнал без сигналов ОС."""

    def __init__(self, python_pending=False):
        self.mask = set()
        self.pending = set()
        self.handlers = {}
        self.python_pending = python_pending

    def install(self, number, handler):
        self.handlers[number] = handler

    def emit(self):
        if signal.SIGINT in self.mask:
            self.pending.add(signal.SIGINT)
        else:
            self.handlers[signal.SIGINT](signal.SIGINT, None)

    def masking(self, how, values):
        previous = self.mask.copy()
        self.mask = previous | set(values) if how == signal.SIG_BLOCK else set(values)
        if self.python_pending and how == signal.SIG_BLOCK:
            # PyErr_CheckSignals может вызвать уже pending обработчик и после блокирования ОС.
            self.python_pending = False
            self.handlers[signal.SIGINT](signal.SIGINT, None)
        if signal.SIGINT in self.pending and signal.SIGINT not in self.mask:
            self.pending.remove(signal.SIGINT)
            self.handlers[signal.SIGINT](signal.SIGINT, None)
        return previous


class WorkerCleanupTests(unittest.TestCase):
    def execute_worker(self, cause, phase, *, failure=None):
        signals = _Signals(python_pending=phase == 'python_pending')
        events, reports = [], []
        native, mounts = Mock(), Mock()
        mounts.owns_staging.return_value = True
        def release_cage():
            if failure == 'cage':
                raise OSError('TEST_unmount_failed')
            events.append('cage_released')
        mounts.release_cage.side_effect = release_cage
        real_write, real_close, real_unlink = os.write, os.close, os.unlink
        injected = False

        class Group:
            leader = 123  # Только значение двойника; процессы и сигналы ОС не используются.
            streams = {}
            all_reaped = False

            def collect(self):
                if cause is None:
                    return XrayTestExit(0, b'Xray 26.3.27 (TEST_build)\nConfiguration OK.\n', b'', False)
                if cause is KeyboardInterrupt:
                    signals.emit()
                    raise AssertionError('Первая отмена должна прервать исполнение.')
                raise cause

            def terminate_and_wait(self):
                if phase == 'group':
                    signals.emit()
                if failure == 'group':
                    raise ProcessCleanupFailed
                self.all_reaped = True
                events.append('group_reaped')

            def close_streams(self):
                if failure == 'streams':
                    raise OSError('TEST_close_failed')
                events.append('streams_closed')

        def start(runner, request):
            runner._group = Group()

        def unlink(name, *, dir_fd=None):
            nonlocal injected
            if dir_fd is not None and str(name).endswith('.json') and not injected:
                injected = True
                if phase == 'unlink':
                    signals.emit()
                if failure == 'unlink':
                    raise OSError('TEST_unlink_failed')
                events.append('staging_unlinked')
            return real_unlink(name, dir_fd=dir_fd)

        def write(fd, data):
            if fd == -1:
                reports.append(data)
                return len(data)
            return real_write(fd, data)

        def close(fd):
            if fd != -1:
                real_close(fd)

        def finish_mounts():
            if failure == 'mounts':
                raise OSError('TEST_final_unmount_failed')
            if phase == 'preparation':
                # Уже доставленный Python callback, даже при заблокированных сигналах ОС.
                signals.handlers[signal.SIGINT](signal.SIGINT, None)
            events.append('mounts_released')

        mounts.close.side_effect = finish_mounts
        if phase == 'preparation':
            mounts.prepare.side_effect = signals.emit
        config = (b'{"routing":{"rules":[{"outboundTag":"TEST_out","ip":["geoip:TEST"],'
                  b'"domain":["geosite:TEST"]}]},"outbounds":[{"protocol":"blackhole","tag":"TEST_out"}]}')
        assets = tuple(CandidateAsset(kind, name, hashlib.sha256(data).hexdigest(), data)
                       for kind, name, data in ((GeoDatabaseKind.GEOIP, 'geoip.dat', b'TEST_IP'),
                                                (GeoDatabaseKind.GEOSITE, 'geosite.dat', b'TEST_SITE')))
        candidate = XrayTestInput(parts=(('part.json', config),), assets=assets,
                                  categories=((GeoDatabaseKind.GEOIP, 'geoip.dat', 'TEST'),
                                              (GeoDatabaseKind.GEOSITE, 'geosite.dat', 'TEST')))
        self.assertIsNotNone(port.checked_port_input(candidate))
        with tempfile.TemporaryDirectory() as directory:
            directory = str(Path(directory).resolve())
            with ExitStack() as stack:
                stack.enter_context(patch.object(port, 'PrivateMounts', return_value=mounts))
                stack.enter_context(patch.object(port, 'close_other_fds'))
                stack.enter_context(patch.object(port, 'monotonic', return_value=0))
                stack.enter_context(patch.object(port.signal, 'signal', side_effect=signals.install))
                stack.enter_context(patch.object(port.signal, 'pthread_sigmask', side_effect=signals.masking))
                stack.enter_context(patch.object(port.signal, 'sigpending', side_effect=lambda: signals.pending.copy()))
                stack.enter_context(patch.object(port.os, 'getppid', return_value=91))
                stack.enter_context(patch.object(port.os, '_exit', side_effect=_WorkerExit))
                stack.enter_context(patch.object(port.os, 'write', side_effect=write))
                stack.enter_context(patch.object(port.os, 'close', side_effect=close))
                stack.enter_context(patch.object(port.os, 'unlink', side_effect=unlink))
                stack.enter_context(patch.object(runner_module, 'require_empty_child_scope'))
                stack.enter_context(patch.object(runner_module.LinuxXrayRunner, 'start', start))
                stack.enter_context(patch.object(port, 'StagedXrayTest', side_effect=lambda _, runner, **kwargs:
                                                StagedXrayTest(directory, runner, **kwargs)))
                try:
                    with self.assertRaises(_WorkerExit):
                        port._worker(native, candidate, 30, -1, 91, (4096, 4096))
                except KeyboardInterrupt:
                    self.fail('Отложенная отмена прервала завершение координатора.')
            if failure is None:
                self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(len(reports), 1)
        return Outcome(reports[0].decode().strip()), events

    def test_second_signal_during_group_cleanup_preserves_timeout_and_interruption(self):
        for cause, expected in ((TimeoutError, Outcome.TIMEOUT), (KeyboardInterrupt, Outcome.INTERRUPTED)):
            with self.subTest(cause=cause):
                result, events = self.execute_worker(cause, 'group')
                self.assertEqual(events, ['group_reaped', 'streams_closed', 'cage_released',
                                          'staging_unlinked', 'mounts_released'])
                self.assertIs(result, expected)

    def test_second_signal_during_staging_unlink_preserves_timeout_and_interruption(self):
        for cause, expected in ((TimeoutError, Outcome.TIMEOUT), (KeyboardInterrupt, Outcome.INTERRUPTED)):
            with self.subTest(cause=cause):
                result, events = self.execute_worker(cause, 'unlink')
                self.assertIn('staging_unlinked', events)
                self.assertIs(result, expected)

    def test_python_pending_signal_at_cleanup_entry_does_not_skip_cleanup(self):
        result, events = self.execute_worker(TimeoutError, 'python_pending')
        self.assertIn('group_reaped', events)
        self.assertIn('staging_unlinked', events)
        self.assertIs(result, Outcome.TIMEOUT)

    def test_repeated_cancel_during_preparation_cleanup_preserves_interruption(self):
        result, events = self.execute_worker(KeyboardInterrupt, 'preparation')
        self.assertEqual(events, ['mounts_released'])
        self.assertIs(result, Outcome.INTERRUPTED)

    def test_real_group_or_staging_cleanup_failure_is_not_hidden_by_cancel(self):
        for failure in ('group', 'unlink', 'streams', 'cage', 'mounts'):
            with self.subTest(failure=failure):
                result, _ = self.execute_worker(KeyboardInterrupt, 'group', failure=failure)
                self.assertIs(result, Outcome.CLEANUP)

    def test_first_late_cancel_changes_success_to_interruption_after_confirmed_cleanup(self):
        for phase in ('group', 'unlink', 'python_pending'):
            with self.subTest(phase=phase):
                result, events = self.execute_worker(None, phase)
                self.assertIn('group_reaped', events)
                self.assertIn('staging_unlinked', events)
                self.assertIn('mounts_released', events)
                self.assertIs(result, Outcome.INTERRUPTED)

    def test_success_without_cancel_is_not_changed(self):
        result, _ = self.execute_worker(None, 'none')
        self.assertIs(result, Outcome.PASSED)


if __name__ == '__main__':
    unittest.main()
