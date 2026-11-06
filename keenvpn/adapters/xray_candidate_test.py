"""Приватная подготовка config test. Исполнитель изоляции явно передаёт доверенный вызывающий."""

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import os
from secrets import token_hex
import stat
from time import monotonic
from typing import Protocol

from keenvpn.adapters.entware_files import DIRECTORY_FLAGS, PathFailure, walk_directory
from keenvpn.adapters.private_files import PROTECTED_DIRECTORIES
from keenvpn.application.xray_candidate import XrayTestInput, XrayTestOutcome as Outcome, checked_port_input
from keenvpn.domain.config_document import valid_document_name
from keenvpn.domain.manager_metadata import valid_storage_path
from keenvpn.domain.routing import GeoDatabaseKind
from keenvpn.domain.xray_config import is_xray_tail_part


XRAY_BINARY = "/opt/sbin/xray"
XRAY_VERSION = "26.3.27"
OUTPUT_LIMIT = 64 * 1024
MEMORY_LIMIT = 256 * 1024 * 1024
TIMEOUT = 30.0


def valid_memory_limit(value: object) -> bool:
    """Вызывающий может только уменьшить общий потолок памяти проверочного Xray."""
    return type(value) is int and 0 < value <= MEMORY_LIMIT


@dataclass(frozen=True, slots=True, repr=False)
class XrayTestFile:
    """Файл для неизменяемого пространства процесса. Дескриптор заимствован до завершения группы."""

    name: str
    descriptor: int
    size: int
    sha256: bytes


@dataclass(frozen=True, slots=True, repr=False)
class XrayTestInvocation:
    """Один новый процесс в файловом пространстве переданного манифеста.

    memory_limit ограничивает сумму резидентных пользовательских страниц Xray и потомков;
    общее адресное пространство потоков учитывается один раз. Координатор, подготовка
    временных файлов и неотображённый в эти процессы файловый кэш ОС находятся вне метрики.
    """

    job: str
    files: tuple[XrayTestFile, ...]
    argv: tuple[str, ...]
    categories: tuple[tuple[GeoDatabaseKind, str, str], ...]
    deadline: float
    memory_limit: int = MEMORY_LIMIT
    output_limit: int = OUTPUT_LIMIT
    required_version: str = XRAY_VERSION
    environment: tuple[tuple[str, str], ...] = (("XRAY_LOCATION_ASSET", "assets"),)


@dataclass(frozen=True, slots=True, repr=False)
class XrayTestExit:
    """Закрытые потоки завершившегося процесса. Не сериализуются и не выводятся."""

    returncode: int
    stdout: bytes
    stderr: bytes
    file_access_denied: bool


class IsolatedXrayRunner(Protocol):
    """Изоляция проверочного процесса в доверенном окружении хоста.

    Координатор, ядро ОС и администратор хоста с полными полномочиями доверены.
    Проверочный Xray, его потомки и процессы без административных полномочий
    ограничены контрактом, в том числе если используют тот же UID.
    """

    def reserve_staging(self, job: str, parent_fd: int) -> bool:
        """До mkdir исключить запись посторонних процессов без административных полномочий.

        Это относится и к процессам с тем же UID. Только True означает эксклюзивное владение
        на весь срок до release_staging. Права 0700 или рекомендательная блокировка сами по себе
        этого не обеспечивают. Без гарантии вернуть False.
        """
        ...

    def start(self, invocation: XrayTestInvocation) -> None:
        """Проверить доверенный установленный бинарник и создать группу с указанным job без shell.

        Из закреплённых дескрипторов манифеста создать неизменяемое файловое пространство cwd;
        сверить размер и SHA-256 именно доступных ядру байтов до запуска. Пути хоста не открывать.
        Среда задаётся целиком. Запретить сеть, слушатели, запись, внешние конфиги, кэши и файлы.
        Бинарник и необходимые библиотеки предоставляет исполнитель. Чужие дескрипторы закрыты;
        stdin — собственный канал с немедленным EOF без внешнего ввода. При входе в Xray
        проверить принадлежность и назначение всех трёх стандартных каналов.
        До запуска обеспечить общий memory_limit для резидентных пользовательских страниц
        Xray и потомков; общее адресное пространство потоков учитывать один раз.
        Другая версия — UnsupportedXrayVersion, невозможность обеспечить изоляцию — IsolationUnavailable.
        """
        ...

    def collect(self, job: str) -> XrayTestExit:
        """Собрать оба потока в пределах общего лимита и срока, иначе поднять исключение.

        file_access_denied устанавливается по факту запрета файловой операции средой проверки.
        Вывод Xray и его код выхода не позволяют установить причину запрета. Если исполнитель
        не может наблюдать запреты отдельно, он обязан отказаться с IsolationUnavailable.
        """
        ...

    def terminate_and_wait(self, job: str) -> None:
        """Завершить и дождаться всей группы job, в том числе при частичном старте. Отсутствие группы допустимо."""
        ...

    def release_staging(self, job: str) -> None:
        """Освободить собственную резервацию, включая частично полученную. Отсутствие резервации допустимо."""
        ...


class UnsupportedXrayVersion(Exception):
    """Исполнитель не подтвердил закреплённую версию."""


class IsolationUnavailable(Exception):
    """Исполнитель не может установить требуемые границы."""


class OutputLimitExceeded(Exception):
    """Суммарный лимит потоков превышен во время чтения."""


class _Changed(Exception):
    pass


class _Cleanup(Exception):
    pass


def _unsafe_parent(_reason: PathFailure) -> None:
    raise OSError


def _same_entry(parent: int, name: str, expected: os.stat_result) -> bool:
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    return os.path.samestat(current, expected)


@contextmanager
def _new_directory(parent: int, name: str) -> Iterator[int]:
    os.mkdir(name, 0o700, dir_fd=parent)
    initial = descriptor = None
    try:
        try:
            initial = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError:
            # При однократном отказе stat закрепить запись под эксклюзивной резервацией только для уборки.
            descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
            initial = os.fstat(descriptor)
            raise
        descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
        info = os.fstat(descriptor)
        if (not os.path.samestat(info, initial) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.geteuid()):
            raise _Changed
        yield descriptor
    finally:
        try:
            if initial is None or not _same_entry(parent, name, initial):
                # При неизвестном inode либо при замене не удалять неподтверждённую запись.
                raise _Cleanup
            os.rmdir(name, dir_fd=parent)
        except (OSError, KeyboardInterrupt):
            raise _Cleanup from None
        finally:
            if descriptor is not None:
                os.close(descriptor)


@dataclass(frozen=True, slots=True, repr=False)
class _StagedFile:
    descriptor: int
    initial: os.stat_result
    digest: bytes


@contextmanager
def _new_file(parent: int, name: str, data: bytes) -> Iterator[_StagedFile]:
    if not valid_document_name(name) or type(data) is not bytes:
        raise ValueError
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise _Changed
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
        info = os.fstat(fd)
        if info.st_size != len(data):
            raise _Changed
        yield _StagedFile(fd, info, hashlib.sha256(data).digest())
    finally:
        try:
            if not _same_entry(parent, name, os.fstat(fd)):
                raise _Cleanup
            os.unlink(name, dir_fd=parent)
        except (OSError, KeyboardInterrupt):
            raise _Cleanup from None
        finally:
            os.close(fd)


def _unchanged(directory: int, entries: dict[str, _StagedFile]) -> bool:
    if set(os.listdir(directory)) != entries.keys():
        return False
    for name, entry in entries.items():
        digest = hashlib.sha256()
        offset = 0
        while offset < entry.initial.st_size:
            chunk = os.pread(entry.descriptor, min(1024 * 1024, entry.initial.st_size - offset), offset)
            if not chunk:
                return False
            digest.update(chunk)
            offset += len(chunk)
        current = os.fstat(entry.descriptor)
        if (digest.digest() != entry.digest or not _same_entry(directory, name, current)
                or current.st_nlink != 1 or stat.S_IMODE(current.st_mode) != 0o600
                or current.st_ctime_ns != entry.initial.st_ctime_ns or current.st_size != entry.initial.st_size):
            return False
    return True


def _exit_outcome(reply: object) -> Outcome:
    if type(reply) is not XrayTestExit or type(reply.returncode) is not int:
        return Outcome.BAD_OUTPUT
    if type(reply.file_access_denied) is not bool or type(reply.stdout) is not bytes or type(reply.stderr) is not bytes:
        return Outcome.BAD_OUTPUT
    if len(reply.stdout) + len(reply.stderr) > OUTPUT_LIMIT:
        return Outcome.OUTPUT_LIMIT
    if reply.file_access_denied:
        return Outcome.FILE_ACCESS_DENIED
    try:
        output = reply.stdout.decode("utf-8").split("\n")
        reply.stderr.decode("utf-8")
    except UnicodeError:
        return Outcome.BAD_OUTPUT
    if reply.returncode != 0:
        return Outcome.REJECTED if reply.returncode == 23 else Outcome.EXECUTION
    if (not output or not output[0].startswith("Xray " + XRAY_VERSION + " ")
            or "Configuration OK." not in output[1:]):
        return Outcome.BAD_OUTPUT
    return Outcome.PASSED


def _run(runner: IsolatedXrayRunner, request: XrayTestInvocation) -> Outcome:
    try:
        try:
            if runner.start(request) is not None:
                return Outcome.EXECUTION
            result = _exit_outcome(runner.collect(request.job))
        finally:
            try:
                if runner.terminate_and_wait(request.job) is not None:
                    raise _Cleanup
            except (Exception, KeyboardInterrupt):
                raise _Cleanup from None
        return Outcome.TIMEOUT if monotonic() >= request.deadline else result
    except UnsupportedXrayVersion:
        return Outcome.UNSUPPORTED
    except IsolationUnavailable:
        return Outcome.ISOLATION
    except FileNotFoundError:
        return Outcome.MISSING
    except TimeoutError:
        return Outcome.TIMEOUT
    except OutputLimitExceeded:
        return Outcome.OUTPUT_LIMIT
    except _Cleanup:
        raise
    except KeyboardInterrupt:
        return Outcome.INTERRUPTED
    except Exception:
        return Outcome.EXECUTION


@contextmanager
def _exclusive_staging(runner: IsolatedXrayRunner, job: str, parent: int) -> Iterator[None]:
    try:
        try:
            reserved = runner.reserve_staging(job, parent)
        except Exception:
            raise IsolationUnavailable from None
        if reserved is not True:
            raise IsolationUnavailable
        yield
    finally:
        try:
            if runner.release_staging(job) is not None:
                raise _Cleanup
        except (Exception, KeyboardInterrupt):
            raise _Cleanup from None


def _directory_stamp(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    return info.st_ctime_ns, info.st_mtime_ns


class StagedXrayTest:
    """Готовит один временный каталог внутри явно заданного приватного родителя."""

    def __init__(self, directory: str, runner: IsolatedXrayRunner | None = None, *,
                 memory_limit: int = MEMORY_LIMIT) -> None:
        self._directory = directory
        self._runner = runner
        self._memory_limit = memory_limit

    def test(self, candidate: XrayTestInput) -> Outcome:
        if self._runner is None or not valid_memory_limit(self._memory_limit):
            return Outcome.ISOLATION
        path = self._directory
        if not valid_storage_path(path) or any(path == p or path.startswith(p + "/") for p in PROTECTED_DIRECTORIES):
            return Outcome.FILES
        try:
            candidate = checked_port_input(candidate)
            if candidate is None:
                return Outcome.CHANGED
            with walk_directory(path, _unsafe_parent) as parent:
                info = os.fstat(parent)
                if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
                    return Outcome.FILES
                job = token_hex(16)
                with _exclusive_staging(self._runner, job, parent):
                    with _new_directory(parent, ".xray-test-" + job) as root:
                        outcome = self._test_directory(job, root, candidate)
                with walk_directory(path, _unsafe_parent) as current:
                    if not os.path.samestat(info, os.fstat(current)):
                        return Outcome.CHANGED
                return outcome
        except _Cleanup:
            return Outcome.CLEANUP
        except _Changed:
            return Outcome.CHANGED
        except IsolationUnavailable:
            return Outcome.ISOLATION
        except KeyboardInterrupt:
            return Outcome.INTERRUPTED
        except (ValueError, TypeError, AttributeError, OSError):
            return Outcome.FILES

    def _test_directory(self, job: str, root: int, candidate: XrayTestInput) -> Outcome:
        with ExitStack() as stack:
            parts = stack.enter_context(_new_directory(root, "parts"))
            assets = stack.enter_context(_new_directory(root, "assets"))
            part_entries = {}
            asset_entries = {}
            argv = [XRAY_BINARY, "run", "-test", "-format", "json"]
            for index, (original, content) in enumerate(candidate.parts):
                # Config.Override учитывает «tail» в имени. Другие исходные значения в argv не нужны.
                marker = "-tail" if is_xray_tail_part(original) else ""
                name = f"{index:03d}{marker}.json"
                part_entries[name] = stack.enter_context(_new_file(parts, name, content))
                argv.extend(("-c", "parts/" + name))
            for asset in candidate.assets:
                asset_entries[asset.name] = stack.enter_context(_new_file(assets, asset.name, asset.content))

            directories = (root, parts, assets)
            stamps = tuple(map(_directory_stamp, directories))

            def intact() -> bool:
                return (_same_entry(root, "parts", os.fstat(parts)) and _same_entry(root, "assets", os.fstat(assets))
                        and set(os.listdir(root)) == {"parts", "assets"}
                        and _unchanged(parts, part_entries) and _unchanged(assets, asset_entries)
                        and stamps == tuple(map(_directory_stamp, directories)))

            if not intact():
                return Outcome.CHANGED
            files = tuple(
                XrayTestFile(f"{area}/{name}", entry.descriptor, entry.initial.st_size, entry.digest)
                for area, entries in (("parts", part_entries), ("assets", asset_entries))
                for name, entry in entries.items()
            )
            request = XrayTestInvocation(job, files, tuple(argv), candidate.categories, monotonic() + TIMEOUT,
                                         memory_limit=self._memory_limit)
            result = _run(self._runner, request)
            return result if intact() else Outcome.CHANGED
