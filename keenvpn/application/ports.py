"""Порты: что прикладным сценариям нужно от внешних источников.

Реализации находятся в адаптерах или тестах и передаются сценарию при сборке.
Сценарии не импортируют конкретные адаптеры.
"""

from enum import StrEnum
from typing import Protocol
from uuid import UUID

from keenvpn.domain.connection import TrojanConnection
from keenvpn.domain.geodata import GeoDatabaseInventory
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicySet
from keenvpn.domain.manager_metadata import ManagerMetadata, StoredManagerMetadata
from keenvpn.domain.profile import ConnectionProfile
from keenvpn.domain.routing import GeoIPCondition, GeoSiteCondition
from keenvpn.domain.routing_explanation import GeoMatch
from keenvpn.domain.routing_policy import RoutingPolicy
from keenvpn.domain.xkeen_config import XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation


class LinkRejection(StrEnum):
    """Почему парсер отклонил ссылку подключения."""

    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


class ConnectionLinkRejected(ValueError):
    """Отказ парсера ссылки с безопасными кодами и заранее заданным текстом.

    Ни ссылка, ни её части не должны попадать в поля и сообщение.
    """

    def __init__(self, rejection: LinkRejection, code: str, message: str, *, reason: str | None = None) -> None:
        self.rejection = rejection
        self.code = code
        self.reason = reason
        super().__init__(message)


class ConnectionLinkParser(Protocol):
    """Разбор ссылки подключения в модель без сети, файлов и процессов."""

    def parse(self, link: str) -> TrojanConnection:
        """Вернуть модель или вызвать ConnectionLinkRejected."""
        ...


class ConnectionProfileSource(Protocol):
    """Чтение профиля по стабильному ID без изменения профиля и конфигурации."""

    def get_profile(self, profile_id: UUID) -> ConnectionProfile | None:
        """Вернуть профиль или None при отсутствии; при сбое — вызвать исключение."""
        ...


class RoutingPolicySource(Protocol):
    """Чтение действующих правил маршрутизации без их изменения."""

    def current_routing_policy(self) -> RoutingPolicy:
        """Вернуть правила; при невозможности чтения — вызвать исключение."""
        ...


class KeeneticPolicySource(Protocol):
    """Чтение действующего списка политик Keenetic без его изменения."""

    def current_policies(self) -> KeeneticPolicySet:
        """Вернуть политики; при невозможности чтения — вызвать исключение."""
        ...


class KeeneticHotspotSettingsSource(Protocol):
    """Чтение сохранённых настроек `ip/hotspot` отдельно от регистрации и runtime."""

    def current_hotspot_settings(self) -> KeeneticHotspotSettings:
        """Вернуть записи устройств и назначения сегментов; при сбое — вызвать исключение."""
        ...


class KeeneticRegistrationSource(Protocol):
    """Чтение реестра регистраций `known/host` без его изменения."""

    def current_registrations(self) -> KeeneticRegistrations:
        """Вернуть регистрации; при сбое — вызвать исключение."""
        ...


class KeeneticHotspotRuntimeSource(Protocol):
    """Чтение наблюдаемого состояния клиентов `show/ip/hotspot` на момент вызова."""

    def current_hotspot_runtime(self) -> KeeneticHotspotRuntime:
        """Вернуть наблюдения; при сбое — вызвать исключение."""
        ...


class XrayConfigSource(Protocol):
    """Чтение частей конфигурации Xray без их изменения и без запуска Xray."""

    def current_xray_config(self) -> XrayConfigSet:
        """Вернуть части в порядке загрузки; при сбое — вызвать исключение."""
        ...


class XKeenSettingsSource(Protocol):
    """Чтение `xkeen.json` целиком без вызова команд XKeen."""

    def current_xkeen_settings(self) -> XKeenSettings:
        """Вернуть настройки; при сбое — вызвать исключение."""
        ...


class XKeenInitSource(Protocol):
    """Чтение параметров init XKeen как данных, без исполнения и `source`."""

    def current_xkeen_init(self) -> XKeenInitParameters:
        """Вернуть присваивания; при сбое — вызвать исключение."""
        ...


class XKeenListSource(Protocol):
    """Чтение одного из трёх списков XKeen по имени с сохранением текста."""

    def current_xkeen_list(self, name: XKeenListName) -> XKeenList:
        """Вернуть список с этим именем; при сбое — вызвать исключение."""
        ...


class GeoDatabaseSource(Protocol):
    """Чтение инвентаря файлов геобаз: имена, наличие, размер, SHA-256 и известные метаданные."""

    def current_geo_databases(self) -> GeoDatabaseInventory:
        """Вернуть инвентарь со стандартными именами; при сбое — вызвать исключение."""
        ...


class XrayProcessSource(Protocol):
    """Наблюдение процесса Xray и ready-маркера чтением, без команд XKeen и init."""

    def current_xray_process(self) -> XrayProcessObservation:
        """Вернуть наблюдение на момент вызова; при сбое — вызвать исключение."""
        ...


class GeoDataSource(Protocol):
    """Доверенный источник членства значений в наборах GeoIP и GeoSite."""

    def match(self, condition: GeoIPCondition | GeoSiteCondition, values: tuple[str, ...]) -> GeoMatch:
        """Вернуть результат и метаданные фактически использованной базы."""
        ...


class MetadataStoreFailure(StrEnum):
    """Почему хранилище метаданных менеджера отказало."""

    UNAVAILABLE = "metadata_store_unavailable"
    """Каталог или его родитель отсутствует либо не читается."""
    UNSAFE = "metadata_store_unsafe"
    """Ссылка, неверные права, владелец или тип, защищённый или подменённый каталог."""
    BUSY = "metadata_store_busy"
    """Запись уже выполняет другая операция."""
    CONFLICT = "metadata_revision_conflict"
    """Текущая ревизия не совпала с ожидаемой."""
    INVALID = "invalid_stored_metadata"
    """Файл нарушает формат или имеет другую версию схемы; код домена — в `reason`."""
    WRITE_FAILED = "metadata_write_failed"
    """Запись не выполнена, прежний файл не заменён."""
    WRITE_UNCONFIRMED = "metadata_write_unconfirmed"
    """Новый файл виден, но сохранность переименования на диске не подтверждена."""


class MetadataStoreReason(StrEnum):
    """Уточнение отказа хранилища, кроме `invalid_stored_metadata`."""

    INVALID_DIRECTORY = "invalid_directory"
    PROTECTED_DIRECTORY = "protected_directory"
    MISSING = "missing"
    SYMLINK = "symlink"
    NOT_DIRECTORY = "not_directory"
    NOT_REGULAR_FILE = "not_regular_file"
    OWNER = "owner"
    PERMISSIONS = "permissions"
    REPLACED = "replaced"
    NO_SPACE = "no_space"
    READ_ONLY = "read_only"
    PERMISSION_DENIED = "permission_denied"
    IO_ERROR = "io_error"


_METADATA_STORE_MESSAGES = {
    MetadataStoreFailure.UNAVAILABLE: "Каталог метаданных менеджера недоступен.",
    MetadataStoreFailure.UNSAFE: (
        "Каталог или файл метаданных менеджера небезопасен: ссылка, неверные права, владелец или тип."
    ),
    MetadataStoreFailure.BUSY: "Метаданные менеджера уже записывает другая операция.",
    MetadataStoreFailure.CONFLICT: "Метаданные менеджера изменились после чтения: запись отклонена.",
    MetadataStoreFailure.INVALID: "Файл метаданных менеджера повреждён или имеет неподдерживаемую версию схемы.",
    MetadataStoreFailure.WRITE_FAILED: "Не удалось записать метаданные менеджера: прежний файл сохранён.",
    MetadataStoreFailure.WRITE_UNCONFIRMED: (
        "Метаданные менеджера записаны, но сохранность на диске не подтверждена: перечитайте их."
    ),
}


class ManagerMetadataStoreError(Exception):
    """Отказ хранилища метаданных с безопасными кодами и заранее заданным текстом.

    Пути, имена файлов, содержимое и текст системной ошибки в поля
    и сообщение не попадают.
    """

    def __init__(self, failure: MetadataStoreFailure, *, reason: str | None = None) -> None:
        self.failure = failure
        self.reason = reason
        super().__init__(_METADATA_STORE_MESSAGES[failure])


class ManagerMetadataStore(Protocol):
    """Собственные метаданные менеджера отдельно от active configs.

    Ревизия — SHA-256 байтов файла. Запись сравнивает её с ожидаемой
    и при расхождении отказывает, не перезаписывая файл.
    """

    def read_metadata(self) -> StoredManagerMetadata | None:
        """Вернуть метаданные с ревизией или None, если их ещё нет; при отказе — ManagerMetadataStoreError."""
        ...

    def write_metadata(self, metadata: ManagerMetadata, expected_revision: str | None) -> str:
        """Записать при совпадении ревизии и вернуть новую.

        `expected_revision=None` означает, что метаданных быть не должно.
        Совпадающее содержимое не перезаписывается. При отказе — ManagerMetadataStoreError.
        """
        ...
