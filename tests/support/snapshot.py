"""Модели и источники из обезличенного снимка только для локальных тестов.

Фикстуры `tests/fixtures/router_snapshot` преобразуются в модели функциями
адаптеров, а затем передаются управляемым источникам в памяти. Это не
чтение роутера: транспорт, таймауты и ошибки чтения здесь не воспроизводятся.
Снимок обезличен; реальные данные здесь не появляются.
"""

from dataclasses import dataclass
import json
from pathlib import Path

from keenvpn.adapters.keenetic_rci import (
    HOTSPOT_RUNTIME_RESOURCE, HOTSPOT_SETTINGS_RESOURCE, POLICIES_RESOURCE, REGISTRATIONS_RESOURCE,
    hotspot_runtime_from_rci, hotspot_settings_from_rci, policies_from_rci, registrations_from_rci,
)
from keenvpn.adapters.xkeen_files import xkeen_init_from_flags, xkeen_list_from_bytes, xkeen_settings_from_bytes
from keenvpn.adapters.xray_configs import xray_config_from_files
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicySet
from keenvpn.domain.xkeen_config import XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings
from keenvpn.domain.xray_config import XrayConfigSet
from tests.support.in_memory import (
    InMemoryKeeneticHotspotRuntimeSource, InMemoryKeeneticHotspotSettingsSource, InMemoryKeeneticPolicySource,
    InMemoryKeeneticRegistrationSource, InMemoryXKeenInitSource, InMemoryXKeenListSource,
    InMemoryXKeenSettingsSource, InMemoryXrayConfigSource,
)


SNAPSHOT_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "router_snapshot"
XRAY_SNAPSHOT_ROOT = SNAPSHOT_ROOT / "xray"

__all__ = [
    "SNAPSHOT_ROOT", "XRAY_SNAPSHOT_ROOT", "SnapshotKeeneticSources", "SnapshotProxySources",
    "load_keenetic_snapshot", "load_xkeen_snapshot", "load_xray_snapshot_files", "policies_from_rci",
    "snapshot_hotspot_runtime", "snapshot_hotspot_settings", "snapshot_keenetic_sources", "snapshot_policies",
    "snapshot_proxy_sources", "snapshot_registrations", "snapshot_xkeen_init", "snapshot_xkeen_list",
    "snapshot_xkeen_settings", "snapshot_xray_config",
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


def load_xray_snapshot_files() -> dict[str, bytes]:
    """Байты семи частей Xray по именам файлов фикстуры."""
    return {path.name: path.read_bytes() for path in XRAY_SNAPSHOT_ROOT.iterdir() if path.suffix == ".json"}


def load_xkeen_snapshot() -> dict[str, object]:
    """Прочитать обёртку снимка XKeen: настройки, извлечённые флаги и тексты списков."""
    return json.loads((SNAPSHOT_ROOT / "xkeen.json").read_text(encoding="utf-8"))


def snapshot_xray_config() -> XrayConfigSet:
    """Части Xray снимка в порядке имён файлов; размер и SHA-256 совпадают с manifest."""
    return xray_config_from_files(load_xray_snapshot_files())


def snapshot_xkeen_settings() -> XKeenSettings:
    """Настройки XKeen из проекции снимка.

    Фикстура хранит разобранный объект, поэтому размер и SHA-256 относятся
    к его сериализации, а не к файлу роутера.
    """
    settings = load_xkeen_snapshot()["settings"]
    return xkeen_settings_from_bytes((json.dumps(settings, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def snapshot_xkeen_init() -> XKeenInitParameters:
    """Параметры init из четырёх извлечённых флагов снимка; текста init в снимке нет."""
    return xkeen_init_from_flags(load_xkeen_snapshot()["init_flags"])


def snapshot_xkeen_list(name: XKeenListName) -> XKeenList:
    """Один список XKeen из текста снимка."""
    return xkeen_list_from_bytes(name, load_xkeen_snapshot()["lists"][name.value].encode("utf-8"))


@dataclass(frozen=True, slots=True)
class SnapshotProxySources:
    """Четыре управляемых источника конфигурации прокси, заполненные моделями снимка.

    Списки настраиваются по имени через `lists.set_response(name, outcome)`.
    """

    xray: InMemoryXrayConfigSource
    settings: InMemoryXKeenSettingsSource
    init: InMemoryXKeenInitSource
    lists: InMemoryXKeenListSource

    @property
    def calls(self) -> tuple[int, int, int, tuple[XKeenListName, ...]]:
        """Число обращений к источникам и имена запрошенных списков в порядке чтения."""
        return (self.xray.calls, self.settings.calls, self.init.calls, self.lists.calls)


def snapshot_proxy_sources() -> SnapshotProxySources:
    """Собрать источники из одного чтения фикстур."""
    xkeen = load_xkeen_snapshot()
    lists = InMemoryXKeenListSource()
    for name in XKeenListName:
        lists.set_response(name, xkeen_list_from_bytes(name, xkeen["lists"][name.value].encode("utf-8")))
    return SnapshotProxySources(
        InMemoryXrayConfigSource(xray_config_from_files(load_xray_snapshot_files())),
        InMemoryXKeenSettingsSource(xkeen_settings_from_bytes(
            (json.dumps(xkeen["settings"], indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        )),
        InMemoryXKeenInitSource(xkeen_init_from_flags(xkeen["init_flags"])),
        lists,
    )
