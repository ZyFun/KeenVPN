"""Подключение приватных файлов чтения к подтверждённой роли DATA.

Каталоги — непосредственные отдельные потомки роли: отсутствующий собственный
каталог означает отсутствие файла, отсутствующий DATA — отказ. Размещение
проверяется при подключении и до/после каждого чтения; смена UUID или пути
не переключает уже подключённое хранилище. Файлы и каталоги не создаются.
"""

from contextlib import AbstractContextManager
from dataclasses import dataclass
import os

from keenvpn.adapters.draft_backup_files import DraftBackupFiles
from keenvpn.adapters.draft_config_files import DraftConfigFiles
from keenvpn.adapters.draft_journal_files import DraftJournalFiles
from keenvpn.adapters.draft_session_files import DraftSessionFiles
from keenvpn.adapters.entware_files import walk_directory
from keenvpn.adapters.manager_metadata_files import ManagerMetadataFiles
from keenvpn.adapters.private_files import PROTECTED_DIRECTORIES, StoreFailure
from keenvpn.adapters.xray_configs import XRAY_CONFIG_DIRECTORY
from keenvpn.application.contract import ErrorCategory, ErrorDetail
from keenvpn.application.manager_metadata import read_storage_placement
from keenvpn.application.ports import LockedDraftSession, StoragePlacementSource, StoreReason
from keenvpn.domain.manager_metadata import RoleLocation, ValueState, valid_storage_path


DRAFT_DIRECTORY = "keenvpn-drafts"
METADATA_DIRECTORY = "keenvpn-metadata"
APPLY_BACKUP_DIRECTORY = "keenvpn-apply-backups"
APPLY_JOURNAL_DIRECTORY = "keenvpn-apply-journal"
"""Имена собственных каталогов внутри подтверждённого пути роли DATA."""


def _unavailable(code: str, message: str) -> ErrorDetail:
    return ErrorDetail(ErrorCategory.SOURCE_FAILED, code, message)


def _data_role(source: StoragePlacementSource) -> RoleLocation | ErrorDetail:
    placement = read_storage_placement(source)
    if isinstance(placement, ErrorDetail):
        return placement
    role = placement.roles.data
    if role.state is not ValueState.KNOWN:
        return _unavailable("data_placement_unknown", "Размещение роли data не определено.")
    if not role.verified:
        return _unavailable(
            "data_placement_unverified", "Размещение роли data не подтверждено или неоднозначно.",
        )
    return role


class _PlacementGuard:
    """Проверка неизменного выбора DATA без приватных значений в repr."""

    def __init__(self, source: StoragePlacementSource, role: RoleLocation) -> None:
        self._source, self._role = source, role

    def check(self) -> StoreReason | None:
        role = _data_role(self._source)
        if isinstance(role, ErrorDetail):
            return StoreReason.IO_ERROR
        if role.storage_id.value != self._role.storage_id.value or role.path.value != self._role.path.value:
            return StoreReason.REPLACED
        return None


class _PlacedReadOnly:
    """Дополнение файлового адаптера: повторная проверка размещения и запрет записи."""

    def __init__(self, directory: str, guard: _PlacementGuard, protected: tuple[str, ...]) -> None:
        super().__init__(directory, protected_directories=protected)
        self._guard = guard

    def _read_file(self):
        reason = self._guard.check()
        if reason is not None:
            self._raise(StoreFailure.UNAVAILABLE, reason)
        stored = super()._read_file()
        reason = self._guard.check()
        if reason is not None:
            self._raise(StoreFailure.UNAVAILABLE, reason)
        return stored

    def _write_file(self, content, expected_revision):
        self._raise(StoreFailure.UNAVAILABLE, StoreReason.READ_ONLY)

    def _remove_file(self, expected_revision):
        self._raise(StoreFailure.UNAVAILABLE, StoreReason.READ_ONLY)

    def _confirm_absent(self):
        self._raise(StoreFailure.UNAVAILABLE, StoreReason.READ_ONLY)


class RouterDraftSessionFiles(_PlacedReadOnly, DraftSessionFiles):
    """Чтение сессии с проверкой DATA; изменяющие методы порта дают read_only."""

    def lock_for_apply(self) -> AbstractContextManager[LockedDraftSession | None]:
        """Отклонить попытку начать применение через хранилище только для чтения."""
        self._raise(StoreFailure.UNAVAILABLE, StoreReason.READ_ONLY)


class RouterDraftApplyFiles(RouterDraftSessionFiles):
    """Разрешить блокировку и завершение применённой ревизии внутри неё."""

    def lock_for_apply(self) -> AbstractContextManager[LockedDraftSession | None]:
        reason = self._guard.check()
        if reason is not None:
            self._raise(StoreFailure.UNAVAILABLE, reason)
        return DraftSessionFiles.lock_for_apply(self)

    def _close_applied_draft(self, directory: int, expected_revision: str, operation_id: str) -> None:
        reason = self._guard.check()
        if reason is not None:
            self._raise(StoreFailure.UNAVAILABLE, reason)
        super()._close_applied_draft(directory, expected_revision, operation_id)


class RouterManagerMetadataFiles(_PlacedReadOnly, ManagerMetadataFiles):
    """Чтение метаданных с проверкой DATA; запись даёт read_only."""


@dataclass(frozen=True, slots=True)
class RouterManagerFiles:
    """Подключённые хранилища либо безопасное объяснение отказа подключения."""

    drafts: RouterDraftSessionFiles | None = None
    metadata: RouterManagerMetadataFiles | None = None
    error: ErrorDetail | None = None


def connect_router_manager_files(source: StoragePlacementSource, *, root: str = "/") -> RouterManagerFiles:
    """Выбрать собственные каталоги по DATA, не читая и не создавая их.

    `root` — только подмена корня файлов в локальных тестах. Проверки прав,
    владельца, ссылок и формата выполняют прежние файловые хранилища при чтении.
    Неподтверждённое размещение оставляет оба хранилища неподключёнными.
    """
    if root != "/" and not valid_storage_path(root):
        raise ValueError("Неверный корень источников хранилищ.")
    role = _data_role(source)
    if isinstance(role, ErrorDetail):
        return RouterManagerFiles(error=role)
    paths = tuple(role.path.value + "/" + name for name in (DRAFT_DIRECTORY, METADATA_DIRECTORY))
    if any(not valid_storage_path(path) or any(
        path == item or path.startswith(item + "/") for item in PROTECTED_DIRECTORIES
    ) for path in paths):
        return RouterManagerFiles(error=_unavailable(
            "data_directory_unsafe", "Каталоги хранилищ недопустимы: защищённое размещение или неверный путь.",
        ))
    prefix = "" if root == "/" else root
    guard = _PlacementGuard(source, role)
    protected = tuple(prefix + item for item in PROTECTED_DIRECTORIES)
    return RouterManagerFiles(
        RouterDraftSessionFiles(prefix + paths[0], guard, protected),
        RouterManagerMetadataFiles(prefix + paths[1], guard, protected),
    )


@dataclass(frozen=True, slots=True, repr=False)
class RouterDraftApplyPorts:
    drafts: RouterDraftApplyFiles
    files: DraftConfigFiles
    backup: DraftBackupFiles
    journal: DraftJournalFiles
    guard: _PlacementGuard
    data: str
    identity: tuple[int, int]

    def readiness(self) -> ErrorDetail | None:
        """Проверить прежнее размещение и права без создания файлов."""
        if self.guard.check() is not None:
            return _unavailable("data_placement_unverified", "Размещение DATA изменилось или недоступно.")
        try:
            if _writable_directory(self.data) != self.identity:
                return _unavailable("data_placement_unverified", "Каталог DATA заменён.")
            _writable_directory(XRAY_CONFIG_DIRECTORY)
        except OSError:
            return _unavailable("draft_apply_permissions", "Не подтверждены права записи в DATA или каталог Xray.")
        if not self.backup.directory_writable():
            return _unavailable("draft_apply_permissions", "Не подтверждён доступ к приватному каталогу копий применения.")
        if not self.journal.directory_writable():
            return _unavailable("draft_apply_permissions", "Не подтверждён доступ к приватному каталогу журнала применения.")
        return None


def _writable_directory(path: str) -> tuple[int, int]:
    def unavailable(_failure):
        raise OSError("Каталог не подтверждён.")

    with walk_directory(path, unavailable) as directory:
        if not os.access(".", os.W_OK | os.X_OK, dir_fd=directory):
            raise OSError("Нет прав записи в каталог.")
        info = os.fstat(directory)
        return info.st_dev, info.st_ino


def connect_router_draft_apply(source: StoragePlacementSource) -> RouterDraftApplyPorts | ErrorDetail:
    """Собрать явно разрешённую запись на подтверждённой DATA."""
    role = _data_role(source)
    if isinstance(role, ErrorDetail):
        return role
    data = role.path.value
    paths = tuple(f"{data}/{name}" for name in (DRAFT_DIRECTORY, APPLY_BACKUP_DIRECTORY, APPLY_JOURNAL_DIRECTORY))
    if any(not valid_storage_path(path) or any(
        path == protected or path.startswith(protected + "/") for protected in PROTECTED_DIRECTORIES
    ) for path in paths):
        return _unavailable("data_directory_unsafe", "Каталоги применения не прошли проверку размещения.")
    try:
        identity = _writable_directory(data)
    except OSError:
        return _unavailable("draft_apply_permissions", "Не подтверждены права записи в DATA.")
    guard = _PlacementGuard(source, role)
    ports = RouterDraftApplyPorts(
        RouterDraftApplyFiles(paths[0], guard, PROTECTED_DIRECTORIES), DraftConfigFiles(),
        DraftBackupFiles(paths[1], parent_identity=identity), DraftJournalFiles(paths[2], parent_identity=identity),
        guard, data, identity,
    )
    return ports.readiness() or ports
