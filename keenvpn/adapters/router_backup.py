"""Приватные архивы Entware на проверенных по UUID разделах Keenetic.

Не восстанавливает архив и не управляет VPN. Все операции с источниками — чтение;
SQLite сохраняется через online backup API. Абсолютные ссылки сохраняются как
ссылки и никогда не разыменовываются при проверке архива.
"""

from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time

from keenvpn.application.backup import BackupError, BackupResult


ARCHIVE_NAME = re.compile(r"keenvpn-[0-9]{8}T[0-9]{6}\.[0-9]{6}Z\.tar\.gz\Z")
EXCLUDED_OPT = (
    "tmp", "backups", "var/backups", "var/log", "var/run", "var/lock",
    "var/cache", "var/opkg-lists", "lost+found",
)
HISTORY = "keenvpn/vpn-history/history.sqlite"
EXCLUDED_DATA = (HISTORY, HISTORY + "-wal", HISTORY + "-shm", HISTORY + "-journal")
RESTORE_GUIDE = """Приватная резервная копия, содержит пароли и закрытые ключи.
Не публиковать. SHA-256 всего архива хранится в соседнем файле .sha256.
manifest.json содержит состав, права, владельцев, ссылки и SHA-256 файлов.
opt/ — Entware и доработки; data/ — постоянные данные со снимком SQLite;
keenetic/running-config.txt — текущая, не обязательно сохранённая конфигурация.
Это не образ флешки и не прошивка. Службы при создании не останавливались.
Для восстановления сначала проверить архив и UUID новых разделов, архитектуру,
KeeneticOS, свободное место и сделать копию текущего состояния. Распаковывать
только в отдельный приватный каталог с защитой от traversal и ссылок; никогда
не распаковывать вслепую поверх /opt. Абсолютные символьные ссылки требуют
отдельной проверки. На другой архитектуре бинарные пакеты переустановить.
Keenetic импортировать отдельно после сверки интерфейсов и политик. Исправить
UUID в настройках истории/бекапа при замене носителя. Затем отдельно проверить
SSH, init, SQLite, защиту, каждый VPN-канал, DNS и NoVPN. Автовосстановления нет.
Копия на той же флешке не защищает от её поломки: скачать на другой носитель.
"""


@dataclass(frozen=True)
class BackupConfig:
    """Явные хранилища; пути не принимаются из конфигурации."""

    entware_uuid: str
    data_uuid: str
    backup_uuid: str
    keep: int = 5

    def __post_init__(self):
        values = (self.entware_uuid, self.data_uuid, self.backup_uuid)
        if any(type(v) is not str or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", v,
        ) for v in values) or len(set(values)) != 3:
            raise BackupError("Некорректные или совпадающие UUID разделов.")
        if type(self.keep) is not int or not 1 <= self.keep <= 30:
            raise BackupError("Число копий должно быть от 1 до 30.")


def load_config(path: Path) -> BackupConfig:
    """Не исполнять конфигурацию; принимать только известные JSON-поля."""
    with path.open("rb") as source:
        raw = source.read(4097)
    if len(raw) > 4096:
        raise BackupError("Конфигурация резервных копий слишком велика.")
    try:
        data = json.loads(raw)
        if type(data) is not dict or set(data) != {
            "entware_uuid", "data_uuid", "backup_uuid", "keep",
        }:
            raise ValueError
        return BackupConfig(**data)
    except (ValueError, TypeError):
        raise BackupError("Некорректная конфигурация резервных копий.") from None


def digest_file(path: Path) -> str:
    """Потоковый SHA-256, без загрузки большого архива в память."""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def fingerprint(info: os.stat_result) -> tuple:
    """Поймать изменение или подмену файла во время сбора копии."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def inventory(root: Path, exclusions: tuple[str, ...]) -> dict[str, tuple]:
    """Обойти ровно один раздел, не переходя по символическим ссылкам."""
    device = root.stat().st_dev
    result = {}

    def visit(directory: Path):
        for path in sorted(directory.iterdir()):
            name = path.relative_to(root).as_posix()
            if any(name == x or name.startswith(x + "/") for x in exclusions):
                continue
            info = path.lstat()
            if info.st_dev != device:
                raise BackupError("Источник содержит другое смонтированное хранилище.")
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)):
                raise BackupError("Источник содержит неподдерживаемый тип файла.")
            # mtime каталога меняется и при записи исключённых временных файлов.
            result[name] = fingerprint(info) if not stat.S_ISDIR(info.st_mode) else (
                info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            )
            if stat.S_ISDIR(info.st_mode):
                visit(path)
    visit(root)
    return result


@contextmanager
def sqlite_parent(path: Path, identities: list | None = None):
    """Закрепить каталог БД, не переходя по ссылкам ни в одном компоненте."""
    absolute = path.absolute()
    descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if identities is not None:
            info = os.fstat(descriptor)
            identities.append((info.st_dev, info.st_ino))
        for name in absolute.parts[1:-1]:
            if name == "..":
                raise BackupError("Небезопасный путь снимка SQLite.")
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
            except OSError:
                raise BackupError("Каталог SQLite отсутствует или заменён ссылкой.") from None
            os.close(descriptor)
            descriptor = child
            if identities is not None:
                info = os.fstat(descriptor)
                identities.append((info.st_dev, info.st_ino))
        yield absolute, descriptor
    finally:
        os.close(descriptor)


def sqlite_source_info(path: Path) -> os.stat_result:
    """База и все родительские каталоги должны быть обычными объектами."""
    with sqlite_parent(path) as (absolute, descriptor):
        try:
            info = os.stat(absolute.name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            raise BackupError("База истории отсутствует или недоступна.") from None
        if not stat.S_ISREG(info.st_mode):
            raise BackupError("База истории отсутствует или заменена ссылкой.")
        return info


@contextmanager
def sqlite_source(path: Path):
    """Удерживать файл открытым, чтобы его inode не переиспользовался при проверках."""
    identities = []
    with sqlite_parent(path, identities) as (absolute, parent):
        try:
            descriptor = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=parent)
        except OSError:
            raise BackupError("База истории отсутствует или заменена ссылкой.") from None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise BackupError("База истории имеет неподдерживаемый тип.")
            identities.append((info.st_dev, info.st_ino))
            yield tuple(identities)
        finally:
            os.close(descriptor)


def check_sqlite_identity(path: Path, expected: tuple) -> None:
    """Разрешать запись WAL, но отклонять смену файла и родительских каталогов."""
    with sqlite_source(path) as actual:
        if actual != expected:
            raise BackupError("Источник SQLite заменён: архив не опубликован.")


def snapshot_sqlite(source: Path, destination: Path, timeout: float = 60) -> None:
    """Согласованный снимок работающей БД с ограниченным временем ожидания."""
    source = source.absolute()
    sqlite_source_info(source)
    with sqlite_parent(destination) as (destination, parent):
        # Существующие файлы, включая ссылки и посторонние БД, не перезаписываются.
        descriptor = os.open(destination.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                             | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        os.close(descriptor)
    deadline = time.monotonic() + timeout

    def progress(_status, _remaining, _total):
        if time.monotonic() > deadline:
            raise BackupError("Истекло время создания снимка SQLite.")

    with sqlite_source(source) as identity:
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", timeout=5, uri=True)) as original:
            check_sqlite_identity(source, identity)
            with closing(sqlite3.connect(destination)) as copy:
                original.backup(copy, pages=128, progress=progress, sleep=0.1)
                check_sqlite_identity(source, identity)
                if copy.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise BackupError("Проверка снимка SQLite не пройдена.")
        check_sqlite_identity(source, identity)
    os.chmod(destination, 0o600)


def verify_archive(path: Path, expected: dict) -> None:
    """Проверить все записи и хеши без распаковки и исполнения ссылок."""
    seen = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name
            pure = PurePosixPath(name)
            if (pure.is_absolute() or ".." in pure.parts or str(pure) != name
                    or name in seen or name not in expected):
                raise BackupError("Некорректный состав архива.")
            seen.add(name)
            record = expected[name]
            kind = "file" if member.isfile() else "dir" if member.isdir() else "link" if member.issym() else "invalid"
            if (kind != record["type"] or member.mode != record["mode"]
                    or member.uid != record["uid"] or member.gid != record["gid"]):
                raise BackupError("Метаданные архива не совпали.")
            if kind == "file":
                content = archive.extractfile(member)
                if (member.size != record["size"] or content is None
                        or hashlib.file_digest(content, "sha256").hexdigest() != record["sha256"]):
                    raise BackupError("Контрольная сумма файла архива не совпала.")
            elif kind == "link" and member.linkname != record["target"]:
                raise BackupError("Символическая ссылка архива не совпала.")
    if seen != set(expected):
        raise BackupError("Архив неполон.")
    # tar заканчивается раньше gzip; дочитать поток для проверки CRC и хвоста.
    with gzip.open(path, "rb") as source:
        while source.read(1024 * 1024):
            pass


class RouterBackupStorage:
    """Реальный файловый адаптер. Подмена layout разрешена только из Python-тестов."""

    def __init__(self, config: BackupConfig, *, system_root: Path = Path("/"),
                 mounts_file: Path = Path("/proc/mounts")):
        self.config = config
        self.system_root = system_root
        self.mounts_file = mounts_file
        self.opt = system_root / "opt"
        self.mount_base = system_root / "tmp/mnt"
        self.data = self.mount_base / config.data_uuid
        self.backup = self.mount_base / config.backup_uuid
        self.target = self.backup / "keenvpn/daily"
        self.work = None
        self.published = False

    def command(self, args: list[str]) -> bytes:
        """Ограниченный вызов без shell, stderr никогда не попадает в сообщение."""
        try:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=30, check=True)
        except (OSError, subprocess.SubprocessError):
            raise BackupError("Не удалось прочитать сведения о системе.") from None
        if len(result.stdout) > 8 * 1024 * 1024:
            raise BackupError("Системный ответ превышает лимит.")
        return result.stdout

    def check_mounts(self) -> None:
        """UUID, ext4, rw, отдельные устройства и действующий bind /opt."""
        rows = [line.split() for line in self.mounts_file.read_text().splitlines()]
        devices = []
        for uuid in (self.config.entware_uuid, self.config.data_uuid, self.config.backup_uuid):
            point = self.mount_base / uuid
            matches = [r for r in rows if len(r) >= 4 and r[1] == str(point)]
            if (len(matches) != 1 or matches[0][2] != "ext4"
                    or "rw" not in matches[0][3].split(",") or point.is_symlink()):
                raise BackupError("Выбранный USB-раздел отсутствует или недоступен для записи.")
            device = matches[0][0]
            if not re.fullmatch(r"/dev/sd[a-z]+[1-9][0-9]*", device):
                raise BackupError("Неожиданное устройство USB-раздела.")
            # BusyBox игнорирует util-linux-флаги -s/-o и возвращает полную строку.
            actual = self.command([str(self.opt / "sbin/blkid"), device]).strip()
            values = re.findall(rb'(?:^| )UUID="([^"\n]+)"(?= |$)', actual)
            if not actual.startswith(device.encode() + b": ") or values != [uuid.encode()]:
                raise BackupError("UUID USB-раздела не совпал.")
            devices.append(device)
        if len(set(devices)) != 3 or not any(
            len(r) >= 4 and r[1] == str(self.opt) and r[0] == devices[0]
            and "rw" in r[3].split(",") for r in rows
        ) or self.opt.is_symlink():
            raise BackupError("Корень Entware не соответствует выбранному разделу.")

    @contextmanager
    def session(self):
        """Ядро освобождает flock даже после аварии; cwd удерживает нужный mount."""
        lock = self.system_root / "tmp/keenvpn-backup.lock"
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        old_cwd = None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise BackupError("Небезопасный файл блокировки.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BackupError("Резервное копирование уже выполняется.") from None
            self.check_mounts()
            for folder in (self.backup / "keenvpn", self.target):
                if folder.is_symlink():
                    raise BackupError("Каталог копий заменён ссылкой.")
                folder.mkdir(mode=0o700, exist_ok=True)
                if folder.stat().st_uid != os.geteuid():
                    raise BackupError("Неверный владелец каталога копий.")
                folder.chmod(0o700)
            old_cwd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
            directory = os.open(self.target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchdir(directory)
            finally:
                os.close(directory)
            # После SIGKILL могут остаться только наши временные каталоги.
            for entry in Path(".").iterdir():
                if re.fullmatch(r"\.partial-[a-z0-9_]{8}", entry.name) and not entry.is_symlink() and entry.is_dir():
                    shutil.rmtree(entry)
            self.work = Path(tempfile.mkdtemp(prefix=".partial-", dir=".")).absolute()
            # Все дальнейшие записи — относительно закреплённого каталога.
            self.work = Path(self.work.name)
            # Удерживать исходный файл до публикации; WAL и содержимое могут меняться.
            with sqlite_source(self.data / HISTORY) as self.database_identity:
                yield self
        finally:
            if self.work is not None:
                shutil.rmtree(self.work, ignore_errors=True)
            if old_cwd is not None:
                os.fchdir(old_cwd)
                os.close(old_cwd)
            os.close(fd)

    def prepare(self) -> None:
        self.check_mounts()
        source_database = (self.data / HISTORY).absolute()
        check_sqlite_identity(source_database, self.database_identity)
        database_info = sqlite_source_info(source_database)
        self.sources = ((self.opt, "opt", EXCLUDED_OPT), (self.data, "data", EXCLUDED_DATA))
        self.before = {label: inventory(root, exclude) for root, label, exclude in self.sources}
        total = sum(info[5] for entries in self.before.values() for info in entries.values()
                    if len(info) > 5 and stat.S_ISREG(info[2]))
        # Дерево, архив и возможный снимок/журнал SQLite; резерв 256 МиБ.
        required = total * 3 + database_info.st_size * 3 + 256 * 1024 * 1024
        if shutil.disk_usage(".").free < required:
            raise BackupError("Недостаточно места: старые копии сохранены.")
        self.stage = self.work / "payload"
        self.stage.mkdir(mode=0o700)
        for root, label, _exclude in self.sources:
            base = self.stage / label
            base.mkdir()
            for name, revision in self.before[label].items():
                source, target = root / name, base / name
                mode = revision[2]
                if stat.S_ISDIR(mode):
                    target.mkdir()
                elif stat.S_ISLNK(mode):
                    target.symlink_to(os.readlink(source))
                else:
                    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(descriptor, "rb") as reader, target.open("xb") as writer:
                        if fingerprint(os.fstat(reader.fileno())) != revision:
                            raise BackupError("Исходные файлы изменились во время копирования.")
                        shutil.copyfileobj(reader, writer, 1024 * 1024)
                        if fingerprint(os.fstat(reader.fileno())) != revision:
                            raise BackupError("Исходные файлы изменились во время копирования.")
                if not target.is_symlink():
                    shutil.copystat(source, target, follow_symlinks=False)
                os.chown(target, revision[3], revision[4], follow_symlinks=False)
        # SQLite пишет вне скопированного дерева, которое содержит ссылки источников.
        snapshot = self.work / "history.sqlite"
        check_sqlite_identity(source_database, self.database_identity)
        snapshot_sqlite(source_database, snapshot)
        check_sqlite_identity(source_database, self.database_identity)
        # Смена владельца может сбросить специальные биты, поэтому права — после неё.
        os.chown(snapshot, database_info.st_uid, database_info.st_gid, follow_symlinks=False)
        os.chmod(snapshot, stat.S_IMODE(database_info.st_mode))
        database = self.stage / "data" / HISTORY
        with sqlite_parent(database) as (absolute, parent):
            os.replace(snapshot, absolute.name, dst_dir_fd=parent)
        (self.stage / "keenetic").mkdir()
        native = self.command([str(self.system_root / "bin/ndmc"), "-c", "show running-config"])
        native = re.sub(bytes([27]) + rb"\[[0-9;]*[A-Za-z]", b"", native)
        if not native.startswith(b"! $$$ Agent:") or native.count(b"\n") < 30:
            raise BackupError("Не удалось экспортировать конфигурацию Keenetic.")
        (self.stage / "keenetic/running-config.txt").write_bytes(native)
        self.native_revision = hashlib.sha256(native).hexdigest()
        (self.stage / "metadata").mkdir()
        for name, command in (
            ("packages.txt", [str(self.opt / "bin/opkg"), "list-installed"]),
            ("keenetic-version.txt", [str(self.system_root / "bin/ndmc"), "-c", "show version"]),
            ("xray-version.txt", [str(self.opt / "sbin/xray"), "version"]),
        ):
            value = self.command(command)
            if not value.strip():
                raise BackupError("Отсутствуют обязательные сведения о версиях.")
            (self.stage / "metadata" / name).write_bytes(value)
        (self.stage / "RESTORE.txt").write_text(RESTORE_GUIDE, encoding="utf-8")

    def create_and_verify(self) -> None:
        database_name = "data/" + HISTORY
        # Снимок обязателен как отдельный файл внутри payload, а не цель ссылки.
        sqlite_source_info(self.stage / database_name)
        now = datetime.now(timezone.utc)
        self.name = "keenvpn-" + now.strftime("%Y%m%dT%H%M%S.%fZ") + ".tar.gz"
        records = {}
        for path in sorted(self.stage.rglob("*")):
            name = path.relative_to(self.stage).as_posix()
            info = path.lstat()
            record = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
            if path.is_symlink():
                record.update(type="link", target=os.readlink(path))
            elif path.is_dir():
                record.update(type="dir")
            else:
                record.update(type="file", size=info.st_size, sha256=digest_file(path))
            records[name] = record
        if database_name not in records or records[database_name]["type"] != "file":
            raise BackupError("Архив не содержит обязательного снимка SQLite.")
        manifest = {
            "format": "keenvpn-installation-backup", "version": 1,
            "created_utc": now.isoformat(), "python": platform.python_version(),
            "architecture": platform.machine(), "storage": self.config.__dict__,
            "sqlite": {"path": "data/" + HISTORY, "method": "online-backup", "integrity": "ok"},
            "native_config": "running-config, не startup-config",
            "excluded_opt": EXCLUDED_OPT, "files": records,
        }
        manifest_path = self.stage / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        records = dict(records)
        meta = manifest_path.stat()
        records["manifest.json"] = {"type": "file", "mode": stat.S_IMODE(meta.st_mode),
                                    "uid": meta.st_uid, "gid": meta.st_gid, "size": meta.st_size,
                                    "sha256": digest_file(manifest_path)}
        self.candidate = self.work / self.name
        with tarfile.open(self.candidate, "x:gz", compresslevel=3, dereference=False) as archive:
            for name in sorted(records):
                archive.add(self.stage / name, arcname=name, recursive=False)
        self.candidate.chmod(0o600)
        verify_archive(self.candidate, records)
        for root, label, exclude in self.sources:
            if inventory(root, exclude) != self.before[label]:
                raise BackupError("Исходные файлы изменились: архив не опубликован.")
        native = self.command([str(self.system_root / "bin/ndmc"), "-c", "show running-config"])
        native = re.sub(bytes([27]) + rb"\[[0-9;]*[A-Za-z]", b"", native)
        if hashlib.sha256(native).hexdigest() != self.native_revision:
            raise BackupError("Конфигурация Keenetic изменилась: архив не опубликован.")
        self.check_mounts()
        check_sqlite_identity(self.data / HISTORY, self.database_identity)
        self.sha256 = digest_file(self.candidate)
        self.size = self.candidate.stat().st_size
        self.checksum = self.work / (self.name + ".sha256")
        self.checksum.write_text(self.sha256 + "  " + self.name + "\n", encoding="ascii")
        for path in (self.candidate, self.checksum):
            with path.open("rb") as source:
                os.fsync(source.fileno())

    def publish(self) -> None:
        self.check_mounts()
        check_sqlite_identity(self.data / HISTORY, self.database_identity)
        # Сначала checksum, последним — атомарная публикация готового архива.
        os.replace(self.checksum, Path(self.name + ".sha256"))
        os.replace(self.candidate, Path(self.name))
        descriptor = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.published = True

    def retain(self) -> BackupResult:
        if not self.published:
            raise BackupError("Ротация без опубликованного архива запрещена.")
        self.check_mounts()
        archives = sorted(p for p in Path(".").iterdir()
                          if ARCHIVE_NAME.fullmatch(p.name) and p.is_file() and not p.is_symlink())
        if not archives or archives[-1].name != self.name:
            raise BackupError("Время системы изменилось: ротация приостановлена.")
        for old in archives[:-self.config.keep]:
            old.unlink()
            sidecar = Path(old.name + ".sha256")
            if sidecar.is_file() and not sidecar.is_symlink():
                sidecar.unlink()
        return BackupResult(self.name, self.sha256, self.size, min(len(archives), self.config.keep))
