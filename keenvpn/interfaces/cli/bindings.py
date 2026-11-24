"""Источники и действия для сборки разделов терминального меню."""

from dataclasses import dataclass

from keenvpn.application.contract import ErrorDetail
from keenvpn.application.ports import (
    DraftSessionStore, GeoDatabaseSource, GeoDataSource, KeeneticHotspotRuntimeSource, KeeneticHotspotSettingsSource,
    KeeneticPolicySource, KeeneticRegistrationSource, ManagerMetadataStore, XKeenInitSource, XKeenListSource,
    XKeenSettingsSource, XrayConfigSource, XrayProcessSource, SourceFingerprintSource,
)
from keenvpn.application.saved_draft import CandidateAssetSource, GeoCategorySource
from keenvpn.application.saved_draft_apply import ApplySavedDraftHandler
from keenvpn.application.xray_candidate import InstalledXrayPort
from keenvpn.interfaces.cli.menu import UnavailableReason
from keenvpn.interfaces.cli.terminal import Action


SectionActions = dict[str, Action | UnavailableReason]
"""Привязки пунктов к операциям или объяснениям недоступности в текущем запуске."""


@dataclass(frozen=True, slots=True, kw_only=True)
class MenuSources:
    """Источники и явно разрешённые операции меню; `None` — порт не подключён.

    Источники конфигурации только читают. Порт отмены может удалить файл
    выбранной сессии после подтверждения. Отдельный порт проверки Xray
    создаёт временную область и запускает изолированный config test
    при выборе проверки черновика. Запись возможна только при явно подключённом
    сценарии применения.
    """

    policies: KeeneticPolicySource | None = None
    hotspot: KeeneticHotspotSettingsSource | None = None
    registrations: KeeneticRegistrationSource | None = None
    runtime: KeeneticHotspotRuntimeSource | None = None
    xray: XrayConfigSource | None = None
    xkeen_settings: XKeenSettingsSource | None = None
    xkeen_init: XKeenInitSource | None = None
    xkeen_lists: XKeenListSource | None = None
    geodata: GeoDatabaseSource | None = None
    process: XrayProcessSource | None = None
    metadata: ManagerMetadataStore | None = None
    geo_match: GeoDataSource | None = None
    """Источник членства в наборах GeoIP и GeoSite для объяснения маршрута; без него условия геобаз «неизвестны»."""
    drafts: DraftSessionStore | None = None
    """Хранилище сессии для чтения, если не подключён `draft_discard`."""
    draft_discard: DraftSessionStore | None = None
    """Хранилище, разрешённое для отмены; при подключении используется и для всех чтений черновика."""
    storage_error: ErrorDetail | None = None
    """Безопасная причина неподключённых хранилищ при неподтверждённом размещении DATA."""
    fingerprints: SourceFingerprintSource | None = None
    """Текущие отпечатки всех управляемых источников для проверки сохранённой сессии."""
    candidate_assets: CandidateAssetSource | None = None
    """Полные байты геобаз; ожидаемые ревизии всегда берутся из кандидата."""
    geo_catalogs: GeoCategorySource | None = None
    """Доверенные свидетельства категорий; отсутствие не подменяется именем или SHA."""
    installed_xray: InstalledXrayPort | None = None
    """Изолированный исполнитель; его отсутствие не блокирует статический отчёт."""
    draft_apply: ApplySavedDraftHandler | None = None
    """Готовый прикладной сценарий применения с явно разрешённой записью."""
    draft_apply_unavailable: UnavailableReason = UnavailableReason.DRAFT_APPLY_NOT_CONNECTED

    @property
    def keenetic_connected(self) -> bool:
        """Подключены ли все четыре источника состояния Keenetic."""
        return None not in (self.policies, self.hotspot, self.registrations, self.runtime)

    @property
    def proxy_connected(self) -> bool:
        """Подключены ли все четыре источника конфигурации Xray и XKeen."""
        return None not in (self.xray, self.xkeen_settings, self.xkeen_init, self.xkeen_lists)

    @property
    def draft_store(self) -> DraftSessionStore | None:
        """Общее хранилище сессии для просмотра, проверки и решения о выходе."""
        return self.draft_discard if self.draft_discard is not None else self.drafts
