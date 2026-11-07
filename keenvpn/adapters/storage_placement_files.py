"""Источник обнаруженного размещения действующей установки; только чтение.

Читает поддерживаемые тексты архива/истории, mountinfo, UUID BusyBox blkid
и маркер истории. Каталоги не создаёт, SQLite не открывает, shell/SQL не
исполняет. Не подключает хранилища к CLI и не повторяет сценарий импорта.
"""

from dataclasses import dataclass
import os
import posixpath
import re
import stat

from keenvpn.adapters.entware_files import fail_read, read_file, walk_directory, PathFailure
from keenvpn.adapters.router_sources import CommandRunner, run_read_command
from keenvpn.adapters import storage_placement_formats as formats
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.domain.manager_metadata import (
    HistoryLimits, RoleLocation, StoragePlacement, StorageRoles, StorageVariant, TrackedValue, ValueState,
    valid_storage_path,
)


BLKID_PATH = "/opt/sbin/blkid"
BLKID_TIMEOUT = 5.0
BLKID_OUTPUT_LIMIT = 32768
MOUNTINFO_LIMIT = 131072
MOUNT_COUNT_LIMIT = 1024
DEVICE_COUNT_LIMIT = 8
BACKUP_CONFIG = "/opt/etc/vpn-backup.json"
BACKUP_WRAPPER = "/opt/sbin/vpn-backup"
BACKUP_ENTRY = "/opt/share/keenvpn-backup/scripts/router_backup.py"
BACKUP_ADAPTER = "/opt/share/keenvpn-backup/keenvpn/adapters/router_backup.py"
HISTORY_SCRIPT = "/opt/sbin/vpn-history"
HISTORY_INIT = "/opt/etc/init.d/S07vpn-history"
HISTORY_INGEST = "/opt/etc/vpn-history/ingest.sql"
_DEVICE = re.compile(r"/dev/sd[a-z]+[1-9][0-9]*")


@dataclass(frozen=True, repr=False)
class _Mount:
    """Поля одной строки mountinfo без приватных значений в repr."""

    number: int
    device: tuple[int, int]
    root: str
    point: str
    options: frozenset[str]
    filesystem: str
    source: str
    super_options: frozenset[str]


@dataclass(frozen=True, repr=False)
class _DeviceIdentity:
    """Прочитанные номер и UUID устройства, включая несовпадение с mountinfo."""

    number: tuple[int, int]
    storage_id: str


def _unescape(value: str) -> str:
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    if re.search(r"\\(?!040|011|012|134)", value):
        formats.reject_format()
    return re.sub(r"\\(040|011|012|134)", lambda match: escapes[match.group(1)], value)


def _options(value: str) -> frozenset[str]:
    parts = value.split(",")
    if not all(parts) or len(set(parts)) != len(parts) or len(set(parts) & {"ro", "rw"}) != 1:
        formats.reject_format()
    return frozenset(parts)


def mounts_from_bytes(content: bytes) -> tuple[_Mount, ...]:
    """Ограниченный mountinfo; неоднозначные точки остаются несколькими записями."""
    if type(content) is not bytes or len(content) > MOUNTINFO_LIMIT:
        fail_read(RouterReadFailure.TOO_LARGE)
    text = None
    try:
        text = content.decode("utf-8", "strict")
    except UnicodeDecodeError:
        pass
    if not text or not text.endswith("\n"):
        formats.reject_format()
    lines = text.splitlines()
    if len(lines) > MOUNT_COUNT_LIMIT:
        fail_read(RouterReadFailure.TOO_LARGE)
    result, numbers = [], set()
    for line in lines:
        fields = line.split(" ")
        if not all(fields) or fields.count("-") != 1:
            formats.reject_format()
        split = fields.index("-")
        if split < 6 or len(fields) != split + 4:
            formats.reject_format()
        if (not re.fullmatch(r"[1-9][0-9]{0,9}", fields[0])
                or not re.fullmatch(r"0|[1-9][0-9]{0,9}", fields[1])
                or not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", fields[2])
                or any(re.fullmatch(r"(?:shared|master|propagate_from):[1-9][0-9]*|unbindable", item) is None
                       for item in fields[6:split])):
            formats.reject_format()
        number = int(fields[0])
        if number in numbers:
            formats.reject_format()
        numbers.add(number)
        root, point, source = map(_unescape, (fields[3], fields[4], fields[split + 2]))
        filesystem = fields[split + 1]
        namespace_root = filesystem == "nsfs" and re.fullmatch(r"[a-z]+:\[[0-9]+\]", root) is not None
        if ((root != "/" and not valid_storage_path(root) and not namespace_root)
                or (point != "/" and not valid_storage_path(point))):
            formats.reject_format()
        result.append(_Mount(number, tuple(map(int, fields[2].split(":"))), root, point,
                             _options(fields[5]), filesystem, source, _options(fields[split + 3])))
    return tuple(result)


def uuid_from_blkid(output: bytes, device: str) -> str:
    """Полная строка BusyBox; дубли, чужое устройство и неизвестные поля — отказ."""
    if type(output) is not bytes or len(output) > BLKID_OUTPUT_LIMIT:
        fail_read(RouterReadFailure.TOO_LARGE)
    text = None
    try:
        text = output.decode("utf-8", "strict")
    except UnicodeDecodeError:
        pass
    prefix = device + ": "
    if text is None or not text.startswith(prefix):
        formats.reject_format()
    tail = text[len(prefix):].removesuffix("\n")
    pattern = r'([A-Z][A-Z0-9_]*)="([^"\\\n\r]*)"'
    pairs = tuple(re.finditer(pattern, tail))
    if " ".join(match.group(0) for match in pairs) != tail:
        formats.reject_format()
    keys = tuple(match.group(1) for match in pairs)
    if len(set(keys)) != len(keys) or not set(keys) <= {"LABEL", "UUID", "TYPE", "PARTUUID"} or "UUID" not in keys:
        formats.reject_format()
    values = {match.group(1): match.group(2) for match in pairs}
    if (not formats.valid_storage_id(values["UUID"]) or any(not value.isprintable() for value in values.values())
            or ("TYPE" in values and values["TYPE"] != "ext4")):
        formats.reject_format()
    return values["UUID"]


def _known(value):
    return TrackedValue(ValueState.KNOWN, value)


def _path_failure(failure: PathFailure) -> None:
    mapping = {PathFailure.MISSING: RouterReadFailure.MISSING,
               PathFailure.PERMISSION_DENIED: RouterReadFailure.PERMISSION_DENIED,
               PathFailure.IO_ERROR: RouterReadFailure.IO_ERROR}
    fail_read(mapping.get(failure, RouterReadFailure.UNSAFE))


class StoragePlacementFiles:
    """`StoragePlacementSource` для подтверждённых операционных форматов.

    `root` подменяется только тестами, `run` имеет существующий контракт
    CommandRunner. Отсутствующий/ro/подменённый mount оставляет прочитанное
    размещение с verified=False, без обращения к нижележащему каталогу.
    Повреждённый/неизвестный формат и изменение во время сбора — отказ.
    """

    def __init__(self, *, root: str = "/", run: CommandRunner = run_read_command) -> None:
        if (root != "/" and not valid_storage_path(root)) or not callable(run):
            raise ValueError("Неверные параметры источника размещения.")
        self._root, self._run = root, run

    def _under(self, path: str) -> str:
        return path if self._root == "/" else self._root + path

    def _optional(self, path: str, limit: int) -> bytes | None:
        try:
            return read_file(self._under(path), limit)
        except RouterReadError as error:
            if error.failure is not RouterReadFailure.MISSING:
                raise
        return None

    def _mountinfo(self) -> bytes:
        # /proc/self — ссылка; PID собственного процесса позволяет обойти её.
        path = self._under("/proc/" + str(os.getpid()))
        with walk_directory(path, _path_failure) as directory:
            descriptor = os.open("mountinfo", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    fail_read(RouterReadFailure.UNSAFE)
                chunks, size = [], 0
                while chunk := os.read(descriptor, min(65536, MOUNTINFO_LIMIT + 1 - size)):
                    size += len(chunk)
                    if size > MOUNTINFO_LIMIT:
                        fail_read(RouterReadFailure.TOO_LARGE)
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                os.close(descriptor)

    def _block_device(self, device: str) -> tuple[int, int]:
        with walk_directory(self._under("/dev"), _path_failure) as directory:
            info = os.stat(posixpath.basename(device), dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISBLK(info.st_mode):
            fail_read(RouterReadFailure.UNSAFE)
        return os.major(info.st_rdev), os.minor(info.st_rdev)

    def _directory_identity(self, path: str) -> tuple[tuple[int, int], int]:
        with walk_directory(self._under(path), _path_failure) as directory:
            info = os.fstat(directory)
        return (os.major(info.st_dev), os.minor(info.st_dev)), info.st_ino

    def _identities(self, mounts: tuple[_Mount, ...]) -> dict[str, _DeviceIdentity]:
        devices = {mount.source for mount in mounts
                   if mount.filesystem == "ext4" and _DEVICE.fullmatch(mount.source)}
        if len(devices) > DEVICE_COUNT_LIMIT:
            fail_read(RouterReadFailure.TOO_LARGE)
        identities = {}
        for device in sorted(devices):
            number = self._block_device(device)
            status, output = self._run((BLKID_PATH, device), BLKID_TIMEOUT, BLKID_OUTPUT_LIMIT)
            if type(status) is not int or type(output) is not bytes:
                formats.reject_format()
            if status != 0:
                fail_read(RouterReadFailure.EXIT_STATUS)
            identities[device] = _DeviceIdentity(number, uuid_from_blkid(output, device))
        return identities

    def _verified(self, storage_id: str, path: str, mount_point: str,
                  mounts: tuple[_Mount, ...], identities: dict[str, _DeviceIdentity], held: dict) -> bool:
        candidates = [mount for mount in mounts
                      if mount.point == "/" or path == mount.point or path.startswith(mount.point + "/")]
        if not candidates:
            return False
        length = max(len(mount.point) for mount in candidates)
        selected = [mount for mount in candidates if len(mount.point) == length]
        if len(selected) != 1:
            return False
        mount = selected[0]
        device_identity = identities.get(mount.source)
        if (mount.point != mount_point or mount.root != "/" or mount.filesystem != "ext4"
                or "rw" not in mount.options or "rw" not in mount.super_options
                or device_identity is None or device_identity.number != mount.device
                or device_identity.storage_id != storage_id
                or sum(value.storage_id == storage_id for value in identities.values()) != 1
                or any(item.point.startswith(path + "/") for item in mounts)):
            return False
        try:
            identity = self._directory_identity(path)
        except RouterReadError as error:
            if error.failure is not RouterReadFailure.MISSING:
                raise
            return False
        if identity[0] != mount.device:
            return False
        held[path] = identity
        return True

    def _collect(self) -> StoragePlacement:
        before = self._mountinfo()
        mounts = mounts_from_bytes(before)
        inputs = {}

        def read(path, limit=131072):
            value = self._optional(path, limit)
            inputs[path] = limit, value
            return value

        backup_config, backup_wrapper = read(BACKUP_CONFIG, 4096), read(BACKUP_WRAPPER, 4096)
        backup = None
        if backup_config is not None or backup_wrapper is not None:
            if backup_config is None or backup_wrapper is None:
                formats.reject_format()
            formats.confirm_code(backup_wrapper, formats.BACKUP_WRAPPER_SHA256)
            formats.confirm_code(read(BACKUP_ENTRY), formats.BACKUP_ENTRY_SHA256)
            formats.confirm_code(read(BACKUP_ADAPTER), formats.BACKUP_ADAPTER_SHA256)
            backup = formats.backup_placement(backup_config)
        script, init = read(HISTORY_SCRIPT), read(HISTORY_INIT, 16384)
        history = None
        if script is not None or init is not None:
            if script is None or init is None:
                formats.reject_format()
            formats.confirm_code(init, formats.HISTORY_INIT_SHA256)
            history = formats.history_placement(script, read(HISTORY_INGEST))
        identities = self._identities(mounts) if backup is not None or history is not None else {}
        held = {}
        absent, unknown = ValueState.ABSENT, ValueState.UNKNOWN
        data_role, backup_role, history_role = RoleLocation(unknown), RoleLocation(absent), RoleLocation(absent)
        variant = TrackedValue(unknown)
        limits = HistoryLimits(TrackedValue(absent), TrackedValue(absent))
        entware_ok = backup is None or self._verified(backup.entware_uuid, "/opt", "/opt", mounts, identities, held)
        if backup is not None:
            data = "/tmp/mnt/" + backup.data_uuid
            target_mount = "/tmp/mnt/" + backup.backup_uuid
            target = target_mount + "/keenvpn/daily"
            data_ok = self._verified(backup.data_uuid, data, data, mounts, identities, held)
            backup_ok = self._verified(backup.backup_uuid, target, target_mount, mounts, identities, held)
            data_role = RoleLocation(ValueState.KNOWN, _known(backup.data_uuid), _known(data), entware_ok and data_ok)
            backup_role = RoleLocation(ValueState.KNOWN, _known(backup.backup_uuid), _known(target), entware_ok and backup_ok)
            # Поддерживаемый архив явно задаёт три разных раздела: это расширенный вариант.
            variant = _known(StorageVariant.EXTENDED)
        if history is not None:
            history_ok = self._verified(history.storage_id, history.path, history.mount, mounts, identities, held)
            if history_ok:
                marker = read(history.path + "/.store-id", 128)
                history_ok = marker is not None and marker.rstrip(b"\n") == history.storage_id.encode("ascii")
            history_role = RoleLocation(ValueState.KNOWN, _known(history.storage_id), _known(history.path),
                                        history_ok)
            limits = HistoryLimits(_known(history.size_bytes), _known(history.retention_seconds))
        for path, (limit, content) in inputs.items():
            if self._optional(path, limit) != content:
                fail_read(RouterReadFailure.CHANGED)
        for path, identity in held.items():
            if self._directory_identity(path) != identity:
                fail_read(RouterReadFailure.CHANGED)
        if identities and self._identities(mounts) != identities:
            fail_read(RouterReadFailure.CHANGED)
        if self._mountinfo() != before:
            fail_read(RouterReadFailure.CHANGED)
        return StoragePlacement(variant, StorageRoles(data_role, history_role, backup_role), limits)

    def current_storage_placement(self) -> StoragePlacement:
        """Собрать одну проверяемую модель; чужие ошибки наружу не передаются."""
        failure = RouterReadFailure.IO_ERROR
        try:
            return self._collect()
        except RouterReadError as error:
            if type(error) is RouterReadError and type(error.failure) is RouterReadFailure:
                failure = error.failure
        except Exception:
            pass
        fail_read(failure)
