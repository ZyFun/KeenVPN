"""Подключение приватных файлов чтения к подтверждённой роли DATA.

Каталоги — непосредственные отдельные потомки роли: отсутствующий собственный
каталог означает отсутствие файла, отсутствующий DATA — отказ. Размещение
проверяется при подключении и до/после каждого чтения; смена UUID или пути
не переключает уже подключённое хранилище. Файлы и каталоги не создаются.
"""

from dataclasses import dataclass

from keenvpn.adapters.draft_session_files import DraftSessionFiles
from keenvpn.adapters.manager_metadata_files import ManagerMetadataFiles
from keenvpn.adapters.private_files import PROTECTED_DIRECTORIES, StoreFailure
from keenvpn.application.contract import ErrorCategory, ErrorDetail
from keenvpn.application.manager_metadata import read_storage_placement
from keenvpn.application.ports import StoragePlacementSource, StoreReason
from keenvpn.domain.manager_metadata import RoleLocation, ValueState, valid_storage_path


DRAFT_DIRECTORY = "keenvpn-drafts"
METADATA_DIRECTORY = "keenvpn-metadata"
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
