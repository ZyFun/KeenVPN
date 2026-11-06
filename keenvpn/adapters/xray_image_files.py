"""Закреплённый образ официального Xray и копирование манифеста в private tmpfs."""

from contextlib import contextmanager
import hashlib
import math
import os
import re
import stat
from time import monotonic

from keenvpn.adapters.entware_files import walk_directory
from keenvpn.adapters.xray_candidate_test import (
    IsolationUnavailable, UnsupportedXrayVersion, XRAY_BINARY, XRAY_VERSION, XrayTestFile, XrayTestInvocation,
)
from keenvpn.adapters.xray_initial_memory import load_ranges
from keenvpn.domain.config_document import valid_document_name


# Официальный Xray-linux-arm64-v8a.zip, релиз 26.3.27; SHA именно ELF, не архива.
# Новый бинарник требует отдельной проверки совместимости профиля.
BINARY_SIZE = 34_209_918
BINARY_SHA256 = bytes.fromhex('c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04')


def _unsafe_parent(_reason) -> None:
    raise IsolationUnavailable


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _deadline(deadline: float) -> None:
    if monotonic() >= deadline:
        raise TimeoutError


@contextmanager
def installed_binary():
    """Открыть ровно установленный файл без symlink; ничего не выполнять."""
    with walk_directory('/opt/sbin', _unsafe_parent) as parent:
        fd = os.open('xray', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or info.st_nlink != 1 or info.st_size != BINARY_SIZE):
                raise UnsupportedXrayVersion
            yield fd
        finally:
            os.close(fd)


def _digest(fd: int, size: int, deadline: float) -> bytes:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        _deadline(deadline)
        data = os.pread(fd, min(65536, size - offset), offset)
        if not data:
            raise IsolationUnavailable
        digest.update(data)
        offset += len(data)
    if os.pread(fd, 1, size):
        raise IsolationUnavailable
    return digest.digest()


def copy_verified(source: int, destination: str, size: int, digest: bytes, mode: int, deadline: float) -> None:
    """Проверить доступные ядру байты копии; смещение заимствованного fd не менять."""
    original = os.fstat(source)
    if not stat.S_ISREG(original.st_mode) or original.st_size != size:
        raise IsolationUnavailable
    fd = os.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        copied = hashlib.sha256()
        while offset < size:
            _deadline(deadline)
            chunk = os.pread(source, min(65536, size - offset), offset)
            if not chunk:
                raise IsolationUnavailable
            copied.update(chunk)
            view = memoryview(chunk)
            while view:
                _deadline(deadline)
                count = os.write(fd, view)
                if count <= 0:
                    raise IsolationUnavailable
                view = view[count:]
            offset += len(chunk)
        if (_stamp(os.fstat(source)) != _stamp(original) or os.pread(source, 1, size)
                or copied.digest() != digest or os.fstat(fd).st_size != size
                or _digest(fd, size, deadline) != digest):
            raise IsolationUnavailable
        os.fchmod(fd, mode)
        if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
            raise IsolationUnavailable
    finally:
        os.close(fd)


def verify_invocation(request: XrayTestInvocation) -> None:
    """Повторно проверить критичные границы, даже при прямом вызове адаптера."""
    if (type(request) is not XrayTestInvocation or type(request.job) is not str
            or re.fullmatch('[0-9a-f]{32}', request.job) is None
            or request.required_version != XRAY_VERSION
            or type(request.files) is not tuple or not 0 < len(request.files) <= 128
            or request.environment != (('XRAY_LOCATION_ASSET', 'assets'),)
            or type(request.argv) is not tuple or request.argv[:5] != (XRAY_BINARY, 'run', '-test', '-format', 'json')
            or type(request.memory_limit) is not int or not 0 < request.memory_limit <= 256 * 1024 * 1024
            or type(request.output_limit) is not int or not 0 < request.output_limit <= 65536):
        raise IsolationUnavailable
    if type(request.deadline) not in (int, float) or not math.isfinite(request.deadline) or request.deadline <= 0:
        raise IsolationUnavailable
    names = set()
    parts = []
    try:
        for item in request.files:
            if type(item) is not XrayTestFile or type(item.name) is not str:
                raise IsolationUnavailable
            area, name = item.name.split('/')
            if (area not in ('parts', 'assets') or not valid_document_name(name) or item.name in names
                    or type(item.descriptor) is not int or item.descriptor < 0
                    or type(item.size) is not int or item.size < 0
                    or type(item.sha256) is not bytes or len(item.sha256) != 32):
                raise IsolationUnavailable
            names.add(item.name)
            if area == 'parts':
                parts.extend(('-c', item.name))
    except (ValueError, AttributeError, TypeError):
        raise IsolationUnavailable from None
    if not parts or request.argv[5:] != tuple(parts):
        raise IsolationUnavailable


def _readable_directory(path: str) -> None:
    os.mkdir(path, 0o755)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(fd, 0o755)  # mkdir(mode) применяет унаследованную umask.
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o755:
            raise IsolationUnavailable
    finally:
        os.close(fd)


def populate_cage(cage: str, request: XrayTestInvocation, binary_fd: int,
                  deadline: float) -> tuple[tuple[int, int], ...]:
    """Создать только файлы манифеста и execute-only ELF; исходные fd не менять."""
    verify_invocation(request)
    if _digest(binary_fd, BINARY_SIZE, deadline) != BINARY_SHA256:
        raise UnsupportedXrayVersion
    for name in ('parts', 'assets'):
        _readable_directory(cage + '/' + name)
    for item in request.files:
        copy_verified(item.descriptor, cage + '/' + item.name, item.size, item.sha256, 0o444, deadline)
    copy_verified(binary_fd, cage + '/xray', BINARY_SIZE, BINARY_SHA256, 0o111, deadline)
    # Структуру считать именно из проверенной копии. Исходный установленный inode
    # мог изменяться между отдельным hash и чтением заголовка, даже при том же fd.
    fd = os.open(cage + '/xray', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return load_ranges(os.pread(fd, 4096, 0), BINARY_SIZE)
    finally:
        os.close(fd)
