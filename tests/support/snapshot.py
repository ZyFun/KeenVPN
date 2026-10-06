"""Модели и источники из обезличенного снимка только для локальных тестов.

Фикстуры `tests/fixtures/router_snapshot` преобразуются в модели функциями
адаптера RCI, а затем передаются управляемым источникам в памяти. Это не
чтение роутера: транспорт, таймауты и ошибки RCI здесь не воспроизводятся.
Снимок обезличен; реальные данные здесь не появляются.
"""

from dataclasses import dataclass
import json
from pathlib import Path

from keenvpn.adapters.keenetic_rci import (
    HOTSPOT_RUNTIME_RESOURCE, HOTSPOT_SETTINGS_RESOURCE, POLICIES_RESOURCE, REGISTRATIONS_RESOURCE,
    hotspot_runtime_from_rci, hotspot_settings_from_rci, policies_from_rci, registrations_from_rci,
)
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicySet
from tests.support.in_memory import (
    InMemoryKeeneticHotspotRuntimeSource, InMemoryKeeneticHotspotSettingsSource, InMemoryKeeneticPolicySource,
    InMemoryKeeneticRegistrationSource,
)


SNAPSHOT_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "router_snapshot"

__all__ = [
    "SNAPSHOT_ROOT", "SnapshotKeeneticSources", "load_keenetic_snapshot", "policies_from_rci",
    "snapshot_hotspot_runtime", "snapshot_hotspot_settings", "snapshot_keenetic_sources",
    "snapshot_policies", "snapshot_registrations",
]


def load_keenetic_snapshot() -> dict[str, object]:
    """Прочитать обезличенные ответы RCI из фикстуры."""
    return json.loads((SNAPSHOT_ROOT / "keenetic.json").read_text(encoding="utf-8"))


def snapshot_policies() -> KeeneticPolicySet:
    """Политики обезличенного снимка в порядке фикстуры."""
    return policies_from_rci(load_keenetic_snapshot()[POLICIES_RESOURCE])


def snapshot_hotspot_settings() -> KeeneticHotspotSettings:
    """Настройки hotspot снимка: записи устройств и назначения сегментов."""
    return hotspot_settings_from_rci(load_keenetic_snapshot()[HOTSPOT_SETTINGS_RESOURCE])


def snapshot_registrations() -> KeeneticRegistrations:
    """Реестр регистраций снимка с искусственными именами."""
    return registrations_from_rci(load_keenetic_snapshot()[REGISTRATIONS_RESOURCE])


def snapshot_hotspot_runtime() -> KeeneticHotspotRuntime:
    """Сокращённое наблюдаемое состояние клиентов снимка."""
    return hotspot_runtime_from_rci(load_keenetic_snapshot()[HOTSPOT_RUNTIME_RESOURCE])


@dataclass(frozen=True, slots=True)
class SnapshotKeeneticSources:
    """Четыре управляемых источника, заранее заполненные моделями снимка.

    Ответы и отказы каждого источника тест меняет независимо через `outcome`.
    """

    policies: InMemoryKeeneticPolicySource
    hotspot: InMemoryKeeneticHotspotSettingsSource
    registrations: InMemoryKeeneticRegistrationSource
    runtime: InMemoryKeeneticHotspotRuntimeSource

    @property
    def calls(self) -> tuple[int, int, int, int]:
        """Число обращений к каждому источнику в порядке чтения сценария."""
        return (self.policies.calls, self.hotspot.calls, self.registrations.calls, self.runtime.calls)


def snapshot_keenetic_sources() -> SnapshotKeeneticSources:
    """Собрать источники из одного чтения фикстуры."""
    snapshot = load_keenetic_snapshot()
    return SnapshotKeeneticSources(
        InMemoryKeeneticPolicySource(policies_from_rci(snapshot[POLICIES_RESOURCE])),
        InMemoryKeeneticHotspotSettingsSource(hotspot_settings_from_rci(snapshot[HOTSPOT_SETTINGS_RESOURCE])),
        InMemoryKeeneticRegistrationSource(registrations_from_rci(snapshot[REGISTRATIONS_RESOURCE])),
        InMemoryKeeneticHotspotRuntimeSource(hotspot_runtime_from_rci(snapshot[HOTSPOT_RUNTIME_RESOURCE])),
    )
