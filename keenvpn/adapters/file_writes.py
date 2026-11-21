"""Запись и публикация файлов через уже открытые дескрипторы."""

import errno
import os


_LINUX_RENAMEAT2 = {"aarch64": 276, "x86_64": 316}
_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004


def write_all(descriptor: int, content: bytes) -> None:
    """Дописывать после коротких записей. Нулевой прогресс означает отказ."""
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]


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
