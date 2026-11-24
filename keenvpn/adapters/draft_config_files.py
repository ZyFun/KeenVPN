"""Файловая запись Xray и XKeen по тем же путям, что чтение отпечатков."""

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import errno
import hashlib
import os
import posixpath
import stat
from typing import NoReturn

from keenvpn.adapters.entware_files import (
    DIRECTORY_FLAGS, PathFailure, confirm_directory_path, digest_file, walk_directory,
)
from keenvpn.adapters.file_writes import exclusive_rename_available, read_linux_inode_flags, rename_new_file, write_all
from keenvpn.adapters.router_sources import XRAY_PART_LIMIT, SourceFingerprints
from keenvpn.application.draft_backup import FileMetadata
from keenvpn.application.draft_file_apply import (
    DraftFileChange, DraftFileTarget, FilePublication, FileStepFailure, FileStepResult,
)
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.domain.source_baseline import BaselineSource, valid_part_name


_TEMP_FILE = "candidate"
_RENAME_PROBE_FILE = "rename-probe"
_NAME_MAX_BYTES = 255
"""Предел компонента имени на ext4 для файлов Entware."""

_SYSTEM = os.uname()
_LINUX_ARCH = _SYSTEM.machine if _SYSTEM.sysname == "Linux" else None
_EXT4_LAYOUT_FLAGS = 0x00080000 | 0x10000000  # EXTENTS и INLINE_DATA

_PUBLICATION_REFUSALS = {
    errno.EACCES, errno.EDQUOT, errno.EEXIST, errno.EISDIR, errno.ENAMETOOLONG, errno.ENOENT,
    errno.EINVAL, errno.ENOSPC, errno.ENOSYS, errno.ENOTDIR, errno.ENOTSUP,
    errno.EPERM, errno.EROFS, errno.EXDEV,
}


def _unavailable(_failure: PathFailure) -> NoReturn:
    raise OSError(errno.EIO, "Не удалось открыть каталог записи.")


def _entry(parent: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _metadata(info: os.stat_result) -> FileMetadata:
    return FileMetadata(stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)


def _version(info: os.stat_result | None) -> tuple[int, ...] | None:
    if info is None:
        return None
    return info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mtime_ns, info.st_size


def _extended_attributes(descriptor: int) -> list[str]:
    if not hasattr(os, "listxattr"):
        return []
    try:
        return os.listxattr(descriptor)
    except OSError as error:
        if error.errno == errno.ENOTSUP:
            return []
        raise


def _has_unsupported_linux_flags(descriptor: int) -> bool:
    return bool(read_linux_inode_flags(descriptor, _LINUX_ARCH) & ~_EXT4_LAYOUT_FLAGS)


def _matches_original(parent: int, name: str, info: os.stat_result | None, metadata: FileMetadata | None) -> bool:
    if info is None or metadata is None:
        return info is None and metadata is None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or _metadata(info) != metadata
            or getattr(info, "st_flags", 0)):
        return False
    if _LINUX_ARCH is not None or hasattr(os, "listxattr"):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            return (_version(os.fstat(descriptor)) == _version(info)
                    and not _has_unsupported_linux_flags(descriptor) and not _extended_attributes(descriptor))
        finally:
            os.close(descriptor)
    return True


def _remove_staged(
    parent: int, name: str, created: os.stat_result, staging: int | None, descriptor: int | None,
) -> bool:
    """Убирать только собственные объекты. Потерявшие идентичность оставлять на месте."""
    cleaned = True
    if descriptor is not None:
        try:
            entry = _entry(staging, _TEMP_FILE)
            if entry is not None:
                if os.path.samestat(entry, os.fstat(descriptor)):
                    os.unlink(_TEMP_FILE, dir_fd=staging)
                else:
                    cleaned = False
        except OSError:
            cleaned = False
    try:
        entry = _entry(parent, name)
        if entry is None or not os.path.samestat(entry, created):
            return False
        os.rmdir(name, dir_fd=parent)
    except OSError:
        cleaned = False
    return cleaned


@dataclass(slots=True)
class _StageCleanup:
    failed: bool = False

    def close(self, descriptor: int) -> None:
        try:
            os.close(descriptor)
        except OSError:
            self.failed = True


def _verify_staged(descriptor: int, content: bytes, metadata: FileMetadata) -> os.stat_result:
    """Сверить подготовленные байты и метаданные, закрепив версию файла для публикации."""
    before = os.fstat(descriptor)
    if (before.st_size != len(content) or _metadata(before) != metadata or before.st_nlink != 1
            or getattr(before, "st_flags", 0) or _has_unsupported_linux_flags(descriptor)
            or _extended_attributes(descriptor)):
        raise OSError(errno.EIO, "Не удалось подтвердить временный файл.")
    offset = 0
    while chunk := os.pread(descriptor, min(128 * 1024, len(content) + 1 - offset), offset):
        if chunk != content[offset:offset + len(chunk)]:
            raise OSError(errno.EIO, "Содержимое временного файла изменилось.")
        offset += len(chunk)
    if offset != len(content) or _version(os.fstat(descriptor)) != _version(before):
        raise OSError(errno.EIO, "Версия временного файла изменилась.")
    return before


@contextmanager
def _stage(
    parent: int, content: bytes | None, original_metadata: FileMetadata | None, cleanup: _StageCleanup,
) -> Iterator[tuple[int | None, os.stat_result | None]]:
    """Подготовить файл в приватном подкаталоге на устройстве каталога назначения."""
    if content is None:
        yield None, None
        return
    name = ".keenvpn-write-" + os.urandom(16).hex()
    os.mkdir(name, 0o700, dir_fd=parent)
    try:
        created = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        cleanup.failed = True
        raise
    if not stat.S_ISDIR(created.st_mode) or created.st_uid != os.geteuid() or created.st_mode & 0o077:
        cleanup.failed = True
        raise OSError(errno.EPERM, "Временный каталог не является приватным.")
    staging = None
    writer = None
    reader = None
    try:
        staging = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
        info = os.fstat(staging)
        if (_version(info) != _version(created) or info.st_dev != os.fstat(parent).st_dev
                or info.st_mode != created.st_mode):
            raise OSError(errno.EPERM, "Временный каталог изменился.")
        writer = os.open(
            _TEMP_FILE, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=staging,
        )
        write_all(writer, content)
        current = _metadata(os.fstat(writer))
        metadata = original_metadata or FileMetadata(0o600, current.uid, current.gid)
        if (current.uid, current.gid) != (metadata.uid, metadata.gid):
            os.fchown(writer, metadata.uid, metadata.gid)
        os.fchmod(writer, metadata.mode)
        os.fsync(writer)
        staged = _verify_staged(writer, content, metadata)
        reader = os.open(_TEMP_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=staging)
        if _version(os.fstat(reader)) != _version(staged):
            raise OSError(errno.EIO, "Временный файл подменён при открытии для чтения.")
        # Запись закрывается до публикации, чтобы Linux мог сразу запустить init.
        descriptor, writer = writer, None
        os.close(descriptor)
        yield staging, staged
    finally:
        with ExitStack() as descriptors:
            for opened in (staging, reader, writer):
                if opened is not None:
                    descriptors.callback(cleanup.close, opened)
            if not _remove_staged(parent, name, created, staging, writer if writer is not None else reader):
                cleanup.failed = True


def _probe_exclusive_rename(parent: int) -> bool:
    """Проверить вызов на файловой системе назначения только на временных именах."""
    cleanup = _StageCleanup()
    with _stage(parent, b"", None, cleanup) as (staging, staged):
        try:
            rename_new_file(_TEMP_FILE, _RENAME_PROBE_FILE, src_dir_fd=staging, dst_dir_fd=staging)
            moved = _entry(staging, _RENAME_PROBE_FILE)
            confirmed = (moved is not None and os.path.samestat(moved, staged)
                         and _entry(staging, _TEMP_FILE) is None)
        finally:
            moved = _entry(staging, _RENAME_PROBE_FILE)
            if moved is not None:
                if os.path.samestat(moved, staged):
                    os.unlink(_RENAME_PROBE_FILE, dir_fd=staging)
                else:
                    cleanup.failed = True
    return confirmed and not cleanup.failed


class DraftConfigFiles(SourceFingerprints):
    """Штатные отпечатки, копирование и атомарная запись отдельных файлов."""

    def _location(self, target: DraftFileTarget) -> tuple[str, str, int]:
        if target.source is BaselineSource.XRAY_CONFIGS and valid_part_name(target.part):
            return self._xray, target.part, XRAY_PART_LIMIT
        if target.part is None and type(target.source) is BaselineSource and target.source in self._files:
            path, limit = self._files[target.source]
            return posixpath.dirname(path), posixpath.basename(path), limit
        raise ValueError("Недопустимая цель записи.")

    def supports_file_name(self, target: DraftFileTarget) -> bool:
        _, name, _ = self._location(target)
        try:
            return len(os.fsencode(name)) <= _NAME_MAX_BYTES
        except UnicodeError:
            return False

    def file_size_limit(self, target: DraftFileTarget) -> int:
        return self._location(target)[2]

    def supports_exclusive_rename(self) -> bool:
        return exclusive_rename_available(rename_new_file)

    def supports_exclusive_rename_in(self, targets: tuple[DraftFileTarget, ...]) -> bool:
        directories = dict.fromkeys(self._location(target)[0] for target in targets)
        try:
            for path in directories:
                with walk_directory(path, _unavailable) as parent:
                    if not _probe_exclusive_rename(parent):
                        return False
                    confirm_directory_path(path, parent)
        except (OSError, RouterReadError):
            return False
        return True

    def supports_file_restore_metadata(self, target: DraftFileTarget, metadata: FileMetadata) -> bool:
        """Проверить возврат исходного владельца и прав на временном файле."""
        path, _, _ = self._location(target)
        cleanup = _StageCleanup()
        try:
            with walk_directory(path, _unavailable) as parent:
                with _stage(parent, b"", metadata, cleanup):
                    confirm_directory_path(path, parent)
        except (OSError, RouterReadError):
            return False
        return not cleanup.failed

    def write_draft_file(
        self, change: DraftFileChange, check_current: Callable[[], FileStepFailure | None],
    ) -> FileStepResult:
        cleanup = _StageCleanup()
        result = self._publish_file(change, check_current, cleanup)
        if isinstance(result, FilePublication):
            return FileStepResult(None, cleanup.failed, result)
        return FileStepResult(result, cleanup.failed)

    def check_draft_file_publication(
        self, target: DraftFileTarget, expected: FilePublication,
    ) -> FileStepFailure | None:
        """Сверить версию опубликованного файла или подтверждённое удаление."""
        path, name, _ = self._location(target)
        try:
            with walk_directory(path, _unavailable) as parent:
                info = os.fstat(parent)
                if (info.st_dev, info.st_ino) != expected.parent_identity:
                    return FileStepFailure.CONFLICT
                current = _entry(parent, name)
                if (_version(current) != expected.version
                        or not _matches_original(parent, name, current, expected.metadata)):
                    return FileStepFailure.CONFLICT
                confirm_directory_path(path, parent)
                if _version(_entry(parent, name)) != expected.version:
                    return FileStepFailure.CONFLICT
        except RouterReadError as error:
            if error.failure is RouterReadFailure.CHANGED:
                return FileStepFailure.CONFLICT
            return FileStepFailure.READ_FAILED
        except OSError:
            return FileStepFailure.READ_FAILED
        return None

    def _publish_file(
        self, change: DraftFileChange, check_current: Callable[[], FileStepFailure | None], cleanup: _StageCleanup,
    ) -> FileStepFailure | FilePublication:
        path, name, limit = self._location(change.target)
        publication_attempted = False
        try:
            with walk_directory(path, _unavailable) as parent:
                try:
                    info = os.fstat(parent)
                    parent_identity = info.st_dev, info.st_ino
                    original = _entry(parent, name)
                    matches = _matches_original(parent, name, original, change.original_metadata)
                except OSError:
                    return FileStepFailure.READ_FAILED
                if (not matches or (change.expected_parent is not None and parent_identity != change.expected_parent)
                        or (change.expected_version is not None and _version(original) != change.expected_version)):
                    return FileStepFailure.CONFLICT
                metadata = change.restore_metadata or change.original_metadata
                with _stage(parent, change.content, metadata, cleanup) as (staging, staged):
                    failure = check_current()
                    if failure is not None:
                        return failure
                    confirm_directory_path(path, parent)
                    if _version(_entry(parent, name)) != _version(original):
                        return FileStepFailure.CONFLICT
                    if staging is not None and _version(_entry(staging, _TEMP_FILE)) != _version(staged):
                        return FileStepFailure.WRITE_FAILED
                    creating = staging is not None and original is None
                    publication_attempted = True
                    try:
                        if staging is None:
                            os.unlink(name, dir_fd=parent)
                        elif creating:
                            rename_new_file(_TEMP_FILE, name, src_dir_fd=staging, dst_dir_fd=parent)
                        else:
                            os.replace(_TEMP_FILE, name, src_dir_fd=staging, dst_dir_fd=parent)
                    except OSError as error:
                        if error.errno in _PUBLICATION_REFUSALS:
                            publication_attempted = False
                            if creating and error.errno == errno.EEXIST:
                                return FileStepFailure.CONFLICT
                            return FileStepFailure.WRITE_FAILED
                        return FileStepFailure.UNCONFIRMED
                    if staging is not None:
                        os.fsync(staging)
                    os.fsync(parent)
                    observed = self._confirmed(path, parent, name, limit, change, staged)
        except RouterReadError as error:
            if publication_attempted:
                return FileStepFailure.UNCONFIRMED
            if error.failure is RouterReadFailure.CHANGED:
                return FileStepFailure.CONFLICT
            return FileStepFailure.READ_FAILED
        except OSError:
            return FileStepFailure.UNCONFIRMED if publication_attempted else FileStepFailure.WRITE_FAILED
        metadata = None if observed is None else _metadata(observed)
        return FilePublication(parent_identity, metadata, _version(observed))

    @staticmethod
    def _confirmed(
        path: str, parent: int, name: str, limit: int, change: DraftFileChange,
        descriptor_info: os.stat_result | None,
    ) -> os.stat_result | None:
        before = _entry(parent, name)
        if change.content is not None:
            _, digest = digest_file(posixpath.join(path, name), limit)
            if digest != hashlib.sha256(change.content).hexdigest():
                raise OSError(errno.EIO, "Не удалось подтвердить байты файла после публикации.")
        confirm_directory_path(path, parent)
        final = _entry(parent, name)
        if descriptor_info is None and final is None:
            return None
        if (descriptor_info is not None and final is not None and _version(final) == _version(before)
                and os.path.samestat(final, descriptor_info) and _metadata(final) == _metadata(descriptor_info)):
            return final
        raise OSError(errno.EIO, "Не удалось подтвердить итоговый файл после публикации.")
