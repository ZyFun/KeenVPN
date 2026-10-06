"""Порты: что прикладным сценариям нужно от внешних источников.

Реализации находятся в адаптерах или тестах и передаются сценарию при сборке.
Сценарии не импортируют конкретные адаптеры.
"""

from enum import StrEnum
from typing import Protocol
from uuid import UUID

from keenvpn.domain.connection import TrojanConnection
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicySet
from keenvpn.domain.profile import ConnectionProfile
from keenvpn.domain.routing import GeoIPCondition, GeoSiteCondition
from keenvpn.domain.routing_explanation import GeoMatch
from keenvpn.domain.routing_policy import RoutingPolicy


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


class GeoDataSource(Protocol):
    """Доверенный источник членства значений в наборах GeoIP и GeoSite."""

    def match(self, condition: GeoIPCondition | GeoSiteCondition, values: tuple[str, ...]) -> GeoMatch:
        """Вернуть результат и метаданные фактически использованной базы."""
        ...
