"""Порт проверки Xray: отдельный координатор до первой записи staging.

Вызывающий получает только фиксированный Outcome после reap координатора.
Его mount namespace, обработчики сигналов, UID, ограничения и cwd не меняются.
На неподтверждённой платформе отказ происходит до fork или файловых эффектов.
"""

import os
import select
import signal
from time import monotonic

from keenvpn.adapters.xray_candidate_test import (
    MEMORY_LIMIT, IsolationUnavailable, StagedXrayTest, TIMEOUT, valid_memory_limit,
)
from keenvpn.adapters.xray_image_files import BINARY_SIZE
from keenvpn.adapters.xray_linux_native import LinuxAarch64
from keenvpn.adapters.xray_linux_runner import LinuxXrayRunner
from keenvpn.adapters.xray_owned_wait import ProcessCleanupFailed, WorkerOwnership, wait_owned
from keenvpn.adapters.xray_private_mount import (
    MountCleanupFailed, PrivateMounts, namespace_identity, preparation_sizes,
)
from keenvpn.adapters.xray_tracee_setup import close_other_fds, private_pipe
from keenvpn.application.xray_candidate import (
    MAX_ASSET_BYTES, MAX_ASSETS, MAX_CONFIG_BYTES, MAX_CONFIG_SEPARATORS,
    MAX_PART_BYTES, MAX_TOTAL_ASSET_BYTES, CandidateAsset, XrayTestInput,
    XrayTestOutcome as Outcome, checked_port_input,
)
from keenvpn.domain.source_baseline import MAX_BASELINE_PARTS


_CANCEL_SIGNALS = frozenset((signal.SIGINT, signal.SIGTERM, signal.SIGHUP))


class _WorkerCancellation:
    """Однократная отмена только выделенного worker; маска сохраняется до его exit."""

    def __init__(self) -> None:
        self.stopping = False
        self.requested = False

    def cancel(self, _number, _frame) -> None:
        self.requested = True
        if self.stopping:
            return
        self.begin_cleanup()
        raise KeyboardInterrupt

    def begin_cleanup(self) -> None:
        # Состояние предшествует ОС-вызову: pthread_sigmask может доставить Python-pending сигнал.
        self.stopping = True
        signal.pthread_sigmask(signal.SIG_BLOCK, _CANCEL_SIGNALS)

    def result(self, outcome: Outcome) -> Outcome:
        if outcome is Outcome.PASSED and (self.requested or _CANCEL_SIGNALS.intersection(signal.sigpending())):
            return Outcome.INTERRUPTED
        return outcome


class _ChangedInput(Exception):
    pass


def _input_sizes(candidate: XrayTestInput) -> tuple[int, int]:
    """До fork только точные типы и len(); JSON и хеши проверяет наблюдаемый worker."""
    if type(candidate) is not XrayTestInput:
        raise _ChangedInput
    try:
        parts, assets, categories = candidate.parts, candidate.assets, candidate.categories
        if (type(parts) is not tuple or not 0 < len(parts) <= MAX_BASELINE_PARTS
                or type(assets) is not tuple or len(assets) > MAX_ASSETS
                or type(categories) is not tuple or len(categories) > MAX_CONFIG_SEPARATORS):
            raise _ChangedInput
        part_sizes = []
        for item in parts:
            if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                    or type(item[1]) is not bytes or len(item[1]) > MAX_PART_BYTES):
                raise _ChangedInput
            part_sizes.append(len(item[1]))
        asset_sizes = []
        for asset in assets:
            if (type(asset) is not CandidateAsset or type(asset.content) is not bytes
                    or not 0 < len(asset.content) <= MAX_ASSET_BYTES):
                raise _ChangedInput
            asset_sizes.append(len(asset.content))
        if sum(part_sizes) > MAX_CONFIG_BYTES or sum(asset_sizes) > MAX_TOTAL_ASSET_BYTES:
            raise _ChangedInput
    except AttributeError:
        raise _ChangedInput from None
    return preparation_sizes(tuple(part_sizes + asset_sizes), BINARY_SIZE)


def _worker(native: LinuxAarch64, candidate: XrayTestInput, deadline: float,
            response: int, parent_pid: int, sizes: tuple[int, int], memory_limit: int = MEMORY_LIMIT) -> None:
    """Только child-ветка fork; не возвращается к коду CLI и не печатает ошибок."""
    outcome = Outcome.EXECUTION
    mounts = None
    cancellation = _WorkerCancellation()
    try:
        native.prctl(1, int(signal.SIGKILL))
        if os.getppid() != parent_pid:
            raise IsolationUnavailable
        for number in _CANCEL_SIGNALS:
            signal.signal(number, cancellation.cancel)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        close_other_fds(frozenset((response,)))
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        native.require_coordinator()
        if monotonic() >= deadline:
            raise TimeoutError
        verified = checked_port_input(candidate)
        if verified is None:
            raise _ChangedInput
        if monotonic() >= deadline:
            raise TimeoutError
        mounts = PrivateMounts(native, *sizes)
        mounts.prepare()
        if monotonic() >= deadline:
            raise TimeoutError
        runner = LinuxXrayRunner(native, mounts, deadline, begin_cleanup=cancellation.begin_cleanup)
        outcome = StagedXrayTest('/tmp', runner, memory_limit=memory_limit).test(verified)
    except _ChangedInput:
        outcome = Outcome.CHANGED
    except KeyboardInterrupt:
        outcome = Outcome.INTERRUPTED
    except TimeoutError:
        outcome = Outcome.TIMEOUT
    except IsolationUnavailable:
        outcome = Outcome.ISOLATION
    except BaseException:
        outcome = Outcome.EXECUTION
    finally:
        try:
            cancellation.begin_cleanup()
        except KeyboardInterrupt:
            # Первая отмена на входе в callback уже включила stopping; повторить только переход.
            cancellation.begin_cleanup()
        try:
            if mounts is not None:
                try:
                    mounts.close()
                except BaseException:
                    outcome = Outcome.CLEANUP
            try:
                outcome = cancellation.result(outcome)
                message = outcome.value.encode('ascii') + b'\n'
                if os.write(response, message) != len(message):
                    os._exit(125)
                os.close(response)
            except BaseException:
                os._exit(125)
        finally:
            # Не возвращать доставку отложенных сигналов в окно между отчётом и exit.
            # Эта ветка всегда завершает собственный процесс; маска родителя отдельная.
            os._exit(0)


def _drain_response(fd: int, data: bytearray) -> bool:
    """Фиксированный протокол, не stdout/stderr Xray. EOF обязателен для завершения."""
    while True:
        try:
            chunk = os.read(fd, 129 - len(data))
        except BlockingIOError:
            return False
        if not chunk:
            return True
        data.extend(chunk)
        if len(data) >= 128:
            raise ProcessCleanupFailed


def _decode_response(data: bytearray, eof: bool) -> Outcome:
    if not eof or not data.endswith(b'\n') or data.count(b'\n') != 1:
        raise ProcessCleanupFailed
    try:
        return Outcome(bytes(data[:-1]).decode('ascii'))
    except (ValueError, UnicodeError):
        raise ProcessCleanupFailed from None


def _wait_worker(owner: WorkerOwnership, response: int, deadline: float, data: bytearray) -> Outcome:
    eof = False
    while not owner.leader_reaped:
        if monotonic() >= deadline:
            raise TimeoutError
        eof = _drain_response(response, data) or eof
        pid, status = wait_owned(owner, os.WNOHANG)
        if pid:
            if pid != owner.leader or not owner.leader_reaped or os.waitstatus_to_exitcode(status) != 0:
                raise ProcessCleanupFailed
        else:
            select.select((response,) if not eof else (), (), (), 0.005)
    eof = _drain_response(response, data) or eof
    return _decode_response(data, eof)


def _cleanup_worker(owner: WorkerOwnership) -> bool:
    """Попросить собственный worker убрать job; затем ограниченно завершить зависший worker."""
    if owner.ownership_lost or owner.wait_uncertain:
        return False
    if owner.leader is None:
        return True
    if type(owner.leader) is not int or not 0 < owner.leader < 1 << 31:
        return False
    if owner.leader_reaped:
        return owner.terminal_status == 0
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
    try:
        for sig, seconds in ((signal.SIGINT, 2.5), (signal.SIGKILL, 0.5)):
            if owner.leader_reaped:
                return sig == signal.SIGINT
            try:
                os.kill(owner.leader, sig)
            except ProcessLookupError:
                pass
            deadline = monotonic() + seconds
            while monotonic() < deadline:
                _, status = wait_owned(owner, os.WNOHANG)
                if owner.leader_reaped:
                    return sig == signal.SIGINT and os.waitstatus_to_exitcode(status) == 0
                select.select((), (), (), 0.005)
        return False
    except (Exception, KeyboardInterrupt):
        return False
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


class IsolatedInstalledXray:
    """Явно выбираемый Linux-порт; импорт и конструктор не обращаются к ОС или роутеру."""

    def __init__(self, *, memory_limit: int = MEMORY_LIMIT) -> None:
        self._memory_limit = memory_limit

    def test(self, candidate: XrayTestInput) -> Outcome:
        owner = WorkerOwnership()
        descriptors: set[int] = set()
        original_namespace = None
        outcome = Outcome.ISOLATION
        response = None
        response_data = bytearray()
        deadline = monotonic() + TIMEOUT
        try:
            if not valid_memory_limit(self._memory_limit):
                raise IsolationUnavailable
            native = LinuxAarch64()
            native.require_coordinator()
            sizes = _input_sizes(candidate)
            original_namespace = namespace_identity()
            if monotonic() >= deadline:
                raise TimeoutError
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
            try:
                response, sender = private_pipe()
                descriptors.update((response, sender))
                os.set_blocking(response, False)
                parent_pid = os.getpid()
                try:
                    pid = os.fork()
                except OSError:
                    raise
                except BaseException:
                    owner.ownership_lost = True
                    raise ProcessCleanupFailed from None
                if pid == 0:
                    try:
                        _worker(native, candidate, deadline, sender, parent_pid, sizes, self._memory_limit)
                    finally:
                        os._exit(125)
                owner.leader = pid
                descriptors.remove(sender)
                try:
                    os.close(sender)
                except OSError:
                    raise ProcessCleanupFailed from None
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            outcome = _wait_worker(owner, response, deadline, response_data)
        except _ChangedInput:
            outcome = Outcome.CHANGED
        except TimeoutError:
            outcome = Outcome.TIMEOUT
        except KeyboardInterrupt:
            outcome = Outcome.INTERRUPTED
        except IsolationUnavailable:
            outcome = Outcome.ISOLATION
        except (ProcessCleanupFailed, MountCleanupFailed, ChildProcessError):
            outcome = Outcome.CLEANUP
        except Exception:
            outcome = Outcome.EXECUTION
        finally:
            # Вложенные consuming wait восстанавливают именно эту защищённую маску.
            # Повторная отмена доставляется лишь после отчёта, всех fd и проверки ns.
            cleanup_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
            try:
                try:
                    cleaned = _cleanup_worker(owner)
                except (Exception, KeyboardInterrupt):
                    cleaned = False
                if not cleaned:
                    outcome = Outcome.CLEANUP
                if owner.leader_reaped and response is not None:
                    try:
                        reported = _decode_response(response_data, _drain_response(response, response_data))
                        if reported is Outcome.CLEANUP:
                            outcome = Outcome.CLEANUP
                    except (Exception, KeyboardInterrupt):
                        outcome = Outcome.CLEANUP
                for fd in tuple(descriptors):
                    descriptors.remove(fd)
                    try:
                        os.close(fd)
                    except OSError:
                        outcome = Outcome.CLEANUP
                if original_namespace is not None:
                    try:
                        if namespace_identity() != original_namespace:
                            outcome = Outcome.CLEANUP
                    except OSError:
                        outcome = Outcome.CLEANUP
            finally:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
                except KeyboardInterrupt:
                    # Завершённую ошибку (особенно CLEANUP) поздняя отмена не скрывает.
                    if outcome is Outcome.PASSED:
                        outcome = Outcome.INTERRUPTED
                except Exception:
                    outcome = Outcome.CLEANUP
        return outcome
