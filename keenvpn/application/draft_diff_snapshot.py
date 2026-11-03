"""Приватные полные снимки восьми источников для сравнения в памяти."""

from dataclasses import dataclass
import hashlib

from keenvpn.domain.config_document import ConfigDocument, validate_config_document
from keenvpn.domain.keenetic_native import KeeneticHotspotSettings, validate_hotspot_settings
from keenvpn.domain.source_baseline import (
    MAX_BASELINE_PARTS, BaselineSource, FingerprintState, SourceFingerprint, canonical_native_bytes, valid_part_name,
)
from keenvpn.domain.xray_config import XrayConfigSet


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class DraftDiffSnapshot:
    """Все поля обязательны. None означает засвидетельствованное отсутствие источника.

    Файлы XKeen передаются исходными байтами, включая оболочку init и комментарии.
    Для политик нужен весь объект ip/policy. Список ID и описаний теряет permit.
    """

    xray_configs: XrayConfigSet | None
    xkeen_settings: bytes | None
    xkeen_init: bytes | None
    xkeen_port_exclude: bytes | None
    xkeen_port_proxying: bytes | None
    xkeen_ip_exclude: bytes | None
    keenetic_policies: dict[str, object] | None
    keenetic_hotspot_settings: KeeneticHotspotSettings | None


def _copy_parts(value: XrayConfigSet) -> dict[str, bytes]:
    """Восстановить каждую часть из байтов и проверить приватные производные поля."""
    if type(value) is not XrayConfigSet or type(value.parts) is not tuple or len(value.parts) > MAX_BASELINE_PARTS:
        raise ValueError("Некорректный каталог частей.")
    parts = {}
    for part in value.parts:
        if type(part) is not ConfigDocument or not valid_part_name(part.name) or part.name in parts:
            raise ValueError("Некорректный набор частей.")
        if type(part.sha256) is not str or type(part._snapshot) is not str:
            raise ValueError("Некорректный документ части.")
        validate_config_document(part)
        parts[part.name] = part.content
    return dict(sorted(parts.items()))


@dataclass(frozen=True, slots=True, repr=False)
class PreparedSnapshot:
    """Собственные данные одного вызова. Отпечатки вычисляются по тем же байтам, что и diff."""

    sources: dict[BaselineSource, bytes | dict[str, bytes] | None]

    def current_fingerprint(self, source: BaselineSource) -> SourceFingerprint:
        payload = self.sources[source]
        if payload is None:
            return SourceFingerprint(source, FingerprintState.ABSENT)
        if source is BaselineSource.XRAY_CONFIGS:
            parts = tuple((name, hashlib.sha256(content).hexdigest()) for name, content in payload.items())
            return SourceFingerprint(source, FingerprintState.PRESENT, parts=parts)
        return SourceFingerprint(source, FingerprintState.PRESENT, sha256=hashlib.sha256(payload).hexdigest())


def prepare_snapshot(snapshot: DraftDiffSnapshot) -> PreparedSnapshot | None:
    """Повторно проверить вход и отделить содержимое от переданных изменяемых моделей."""
    if type(snapshot) is not DraftDiffSnapshot:
        return None
    sources = {}
    try:
        for source in BaselineSource:
            value = getattr(snapshot, source.value)
            if value is None:
                payload = None
            elif source is BaselineSource.XRAY_CONFIGS:
                payload = _copy_parts(value)
            elif source is BaselineSource.KEENETIC_POLICIES:
                payload = canonical_native_bytes(value)
            elif source is BaselineSource.KEENETIC_HOTSPOT_SETTINGS:
                validate_hotspot_settings(value)
                payload = canonical_native_bytes(value.export())
            elif type(value) is bytes:
                payload = value
                if source is BaselineSource.XKEEN_SETTINGS:
                    ConfigDocument("xkeen.json", payload)
                elif source is not BaselineSource.XKEEN_INIT:
                    # Три текстовых списка должны читаться и при добавлении, и при нулевом diff.
                    payload.decode("utf-8")
            else:
                return None
            sources[source] = payload
    except Exception:
        # Включая удалённое поле или повреждённый снимок. Чужие ошибки с данными не передаются.
        return None
    return PreparedSnapshot(sources)
