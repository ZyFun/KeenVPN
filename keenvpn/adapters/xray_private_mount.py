"""Приватные tmpfs для подготовки и неизменяемой клетки одного задания.

Этот код вызывается только в отдельном доверенном координаторе. Сначала проверяет
отдельный private mount namespace; до этого не создаёт файлов. Носители хоста
не изменяются. Размонтирование обычное, без скрывающего занятость lazy detach.
"""

import os
import stat

from keenvpn.adapters.xray_candidate_test import IsolationUnavailable
from keenvpn.adapters.xray_linux_native import LinuxAarch64


MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_REMOUNT = 32
MAX_PREPARATION_BYTES = 128 * 1024 * 1024
DIRECTORY_RESERVE = 128 * 4096


class MountCleanupFailed(Exception):
    """Освобождение приватного файлового пространства не подтверждено."""


def bounded_read(path: str, limit: int) -> bytes:
    """Только доверенные пути proc, без вывода данных или цепочки исключения."""
    with open(path, 'rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise IsolationUnavailable
    return data


def namespace_identity() -> tuple[int, int]:
    info = os.stat('/proc/self/ns/mnt')
    return info.st_dev, info.st_ino


def _mount_rows() -> list[tuple[str, str, tuple[str, ...], str]]:
    rows = []
    try:
        for line in bounded_read('/proc/self/mountinfo', 256 * 1024).decode('ascii').splitlines():
            fields = line.split()
            separator = fields.index('-')
            if separator < 6 or len(fields) < separator + 4:
                raise IsolationUnavailable
            rows.append((fields[2], fields[4], tuple(fields[6:separator]), fields[separator + 1]))
    except (ValueError, UnicodeError, IndexError):
        raise IsolationUnavailable from None
    if not rows:
        raise IsolationUnavailable
    return rows


def _verify_tmpfs(path: str, previous: os.stat_result) -> os.stat_result:
    current = os.lstat(path)
    device = f'{os.major(current.st_dev)}:{os.minor(current.st_dev)}'
    # mountinfo сохраняет и скрытые нижние mount в той же точке. Нужен тот,
    # чьё устройство фактически видно через stat после нашего нового tmpfs.
    rows = [row for row in _mount_rows() if row[1] == path and row[0] == device]
    if (current.st_dev == previous.st_dev or not stat.S_ISDIR(current.st_mode)
            or len(rows) != 1 or rows[0][3] != 'tmpfs'):
        raise IsolationUnavailable
    return current


def preparation_sizes(sizes: tuple[int, ...], binary_size: int) -> tuple[int, int]:
    """Лимит tmpfs — отдельный ресурс подготовки, не подмена RSS-бюджета Xray."""
    if (type(sizes) is not tuple or not sizes or len(sizes) > 128
            or any(type(v) is not int or v < 0 for v in sizes)
            or type(binary_size) is not int or binary_size <= 0):
        raise IsolationUnavailable
    inputs = sum((size + 4095) & -4096 for size in sizes)
    staging = inputs + DIRECTORY_RESERVE
    cage = staging + ((binary_size + 4095) & -4096)
    if staging + cage > MAX_PREPARATION_BYTES:
        raise IsolationUnavailable
    return staging, cage


class PrivateMounts:
    """Один namespace координатора, один job; владение хранится до обычного umount."""

    def __init__(self, native: LinuxAarch64, stage_size: int, cage_size: int) -> None:
        if (type(stage_size) is not int or type(cage_size) is not int
                or min(stage_size, cage_size) <= 0 or stage_size + cage_size > MAX_PREPARATION_BYTES):
            raise IsolationUnavailable
        self.native = native
        self.stage_size, self.cage_size = stage_size, cage_size
        self.original: os.stat_result | None = None
        self.stage: os.stat_result | None = None
        self.namespace: tuple[int, int] | None = None
        self._stage_mounted = False
        self._cage_mounted = False

    def prepare(self) -> None:
        if self.original is not None:
            raise IsolationUnavailable
        self.original = os.lstat('/tmp')
        if not stat.S_ISDIR(self.original.st_mode):
            raise IsolationUnavailable
        previous_namespace = namespace_identity()
        os.chdir('/')
        self.native.prctl(4, 0)  # PR_SET_DUMPABLE, до создания приватных файлов.
        if self.native.prctl(3) != 0:
            raise IsolationUnavailable
        self.native.unshare_mounts()
        self.namespace = namespace_identity()
        if self.namespace == previous_namespace:
            raise IsolationUnavailable
        self.native.mount(None, b'/', None, 0x4000 | 0x40000)  # MS_REC | MS_PRIVATE.
        if any(any(item.startswith(('shared:', 'master:', 'propagate_from:')) for item in row[2])
               for row in _mount_rows()):
            raise IsolationUnavailable
        options = f'size={self.stage_size},nr_inodes=512,mode=0700'.encode('ascii')
        self.native.mount(b'tmpfs', b'/tmp', b'tmpfs', MS_NOSUID | MS_NODEV, options)
        self._stage_mounted = True
        self.stage = _verify_tmpfs('/tmp', self.original)
        if self.stage.st_uid != 0 or stat.S_IMODE(self.stage.st_mode) != 0o700:
            raise IsolationUnavailable

    def owns_staging(self, descriptor: int) -> bool:
        return (self.stage is not None and self._stage_mounted
                and namespace_identity() == self.namespace and self.native.prctl(3) == 0
                and os.path.samestat(os.fstat(descriptor), self.stage))

    def create_cage(self) -> str:
        if not self._stage_mounted or self._cage_mounted:
            raise IsolationUnavailable
        os.mkdir('/tmp/cage', 0o700)
        previous = os.lstat('/tmp/cage')
        options = f'size={self.cage_size},nr_inodes=512,mode=0755'.encode('ascii')
        self.native.mount(b'tmpfs', b'/tmp/cage', b'tmpfs', MS_NOSUID | MS_NODEV, options)
        self._cage_mounted = True
        _verify_tmpfs('/tmp/cage', previous)
        return '/tmp/cage'

    def seal_cage(self) -> None:
        if not self._cage_mounted:
            raise IsolationUnavailable
        self.native.mount(None, b'/tmp/cage', None, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
        if not os.statvfs('/tmp/cage').f_flag & os.ST_RDONLY:
            raise IsolationUnavailable

    def release_cage(self) -> None:
        if self._cage_mounted:
            try:
                self.native.unmount(b'/tmp/cage')
            except Exception:
                raise MountCleanupFailed from None
            self._cage_mounted = False

    def close(self) -> None:
        """Вызывать после завершения tracee и закрытия закреплённых fd подготовки."""
        self.release_cage()
        if self._stage_mounted:
            try:
                self.native.unmount(b'/tmp')
                self._stage_mounted = False
                if not os.path.samestat(os.lstat('/tmp'), self.original):
                    raise MountCleanupFailed
            except Exception:
                raise MountCleanupFailed from None
