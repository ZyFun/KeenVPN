"""Запись и публикация файлов через уже открытые дескрипторы."""

from collections.abc import Callable
import errno
import fcntl
import os
import struct


_LINUX_RENAMEAT2 = {"aarch64": 276, "x86_64": 316}
_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004
# Linux задаёт FS_IOC_GETFLAGS как _IOR('f', 1, long), ext4 возвращает unsigned int.
_IOCTL_LONG_SIZE = struct.calcsize("@l")
_FS_IOC_GETFLAGS = (2 << 30) | (_IOCTL_LONG_SIZE << 16) | (ord("f") << 8) | 1


def write_all(descriptor: int, content: bytes) -> None:
    """Дописывать после коротких записей. Нулевой прогресс означает отказ."""
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]


def read_linux_inode_flags(descriptor: int, architecture: str | None) -> int:
    """Прочитать флаги inode на поддерживаемой Linux ABI."""
    if architecture is None:
        return 0
    if architecture not in _LINUX_RENAMEAT2:
        raise OSError(errno.ENOTSUP, "Неизвестный ABI чтения флагов inode Linux.")
    raw = bytearray(_IOCTL_LONG_SIZE)
    fcntl.ioctl(descriptor, _FS_IOC_GETFLAGS, raw)
    flags, = struct.unpack_from("=I", raw)
    return flags


def exclusive_rename_available(rename: Callable[..., None]) -> bool:
    """Проверить наличие вызова без записи на диск."""
    try:
        rename("source", "target", src_dir_fd=-1, dst_dir_fd=-1)
    except OSError as error:
        return error.errno == errno.EBADF
    return False


def rename_new_file(source: str, target: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
    """Атомарно перенести файл в свободное имя. Занятое имя даёт EEXIST."""
    unavailable = "Атомарное переименование без перезаписи недоступно."
    try:
        # Модуль нужен только для добавления файлов действующей конфигурации.
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
    except (ImportError, OSError):
        raise OSError(errno.ENOTSUP, unavailable) from None

    source_bytes, target_bytes = os.fsencode(source), os.fsencode(target)
    if b"\0" in source_bytes or b"\0" in target_bytes:
        raise OSError(errno.EINVAL, "Имя файла содержит нулевой байт.")
    arguments = (
        ctypes.c_int(src_dir_fd), ctypes.c_char_p(source_bytes),
        ctypes.c_int(dst_dir_fd), ctypes.c_char_p(target_bytes),
    )
    system = os.uname()
    try:
        if system.sysname == "Linux" and system.machine in _LINUX_RENAMEAT2 and ctypes.sizeof(ctypes.c_long) == 8:
            # Системный вызов доступен и на libc без собственного символа renameat2.
            syscall = libc.syscall
            syscall.argtypes = [ctypes.c_long]
            syscall.restype = ctypes.c_long
            result = syscall(_LINUX_RENAMEAT2[system.machine], *arguments, ctypes.c_uint(_RENAME_NOREPLACE))
        elif system.sysname == "Darwin":
            rename = libc.renameatx_np
            rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            rename.restype = ctypes.c_int
            result = rename(*arguments, ctypes.c_uint(_DARWIN_RENAME_EXCL))
        else:
            raise OSError(errno.ENOTSUP, unavailable)
    except AttributeError:
        raise OSError(errno.ENOTSUP, unavailable) from None
    if result != 0:
        raise OSError(ctypes.get_errno() or errno.EIO, "Не удалось атомарно опубликовать новый файл.")
