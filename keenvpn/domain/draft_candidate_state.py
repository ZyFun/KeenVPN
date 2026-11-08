"""Приватный раздел кандидата: два полных снимка и ожидаемые ревизии геобаз.

Файлы сохраняются в base64 без изменения байтов; это кодирование, не шифрование.
Порядок частей Xray задаётся массивом пар [имя, содержимое]. Native-объекты
сохраняются целиком. Неизвестные поля раздела и записи снимков/геобаз остаются
в закрытом JSON-снимке и переживают замену известных данных кандидата.
"""

import base64
from dataclasses import dataclass
import json

from keenvpn.domain.config_document import ConfigDocument, valid_document_name, valid_json_tree
from keenvpn.domain.draft_snapshot import DraftDiffSnapshot, prepare_snapshot
from keenvpn.domain.keenetic_native import KeeneticHotspotSettings
from keenvpn.domain.manager_metadata import UnknownFields, rebuild_unknown_fields, valid_metadata_revision
from keenvpn.domain.routing import GeoDatabase, GeoDatabaseKind
from keenvpn.domain.source_baseline import BaselineSource, MAX_BASELINE_PARTS, valid_part_name
from keenvpn.domain.xray_config import XrayConfigSet


class DraftCandidateStateError(ValueError):
    """Фиксированный отказ без приватных полей и цепочки чужого исключения."""

    def __init__(self) -> None:
        super().__init__("Раздел кандидата черновика повреждён или неполон.")


def _fail():
    try:
        raise DraftCandidateStateError() from None
    except DraftCandidateStateError as error:
        error.__context__ = None
        raise


def _decode_bytes(value: object) -> bytes:
    if type(value) is not str:
        _fail()
    content = base64.b64decode(value, validate=True)
    if base64.b64encode(content).decode("ascii") != value:
        _fail()
    return content


def _read_snapshot(document: object, *, original: bool) -> DraftDiffSnapshot:
    if type(document) is not dict:
        _fail()
    values = {}
    for source in BaselineSource:
        value = document[source.value]
        if value is None:
            payload = None
        elif source is BaselineSource.XRAY_CONFIGS:
            if type(value) is not list or len(value) > MAX_BASELINE_PARTS:
                _fail()
            parts = []
            for pair in value:
                if type(pair) is not list or len(pair) != 2 or not valid_part_name(pair[0]):
                    _fail()
                parts.append(ConfigDocument(pair[0], _decode_bytes(pair[1])))
            payload = XrayConfigSet(tuple(parts))
        elif source is BaselineSource.KEENETIC_POLICIES:
            payload = value
        elif source is BaselineSource.KEENETIC_HOTSPOT_SETTINGS:
            payload = KeeneticHotspotSettings(value)
        else:
            payload = _decode_bytes(value)
        values[source.value] = payload
    snapshot = DraftDiffSnapshot(**values)
    if prepare_snapshot(snapshot, require_sorted_parts=original) is None:
        _fail()
    return snapshot


def snapshot_document(snapshot: DraftDiffSnapshot, *, original: bool = False) -> dict[str, object]:
    """Отделить входные модели и получить полный приватный документ известных источников."""
    prepared = prepare_snapshot(snapshot, require_sorted_parts=original)
    if prepared is None:
        _fail()
    document = {}
    for source, payload in prepared.sources.items():
        if payload is None:
            value = None
        elif source is BaselineSource.XRAY_CONFIGS:
            value = [[name, base64.b64encode(content).decode("ascii")] for name, content in payload.items()]
        elif source in (BaselineSource.KEENETIC_POLICIES, BaselineSource.KEENETIC_HOTSPOT_SETTINGS):
            value = json.loads(payload)
        else:
            value = base64.b64encode(payload).decode("ascii")
        document[source.value] = value
    return document


def _geo_document(revisions: tuple[GeoDatabase, ...]) -> dict[str, object]:
    if type(revisions) is not tuple:
        _fail()
    document = {kind.value: {} for kind in GeoDatabaseKind}
    for item in revisions:
        if (type(item) is not GeoDatabase or not any(item.kind is kind for kind in GeoDatabaseKind)
                or not valid_document_name(item.reference) or not valid_metadata_revision(item.sha256)):
            _fail()
        entries = document[item.kind.value]
        if item.reference in entries:
            _fail()
        entries[item.reference] = item.sha256
    return document


def _read_geo(document: object) -> tuple[GeoDatabase, ...]:
    if type(document) is not dict:
        _fail()
    revisions = []
    for kind in GeoDatabaseKind:
        entries = document[kind.value]
        if type(entries) is not dict:
            _fail()
        for name, sha in entries.items():
            if not valid_document_name(name) or not valid_metadata_revision(sha):
                _fail()
            revisions.append(GeoDatabase(kind, name, sha256=sha))
    return tuple(revisions)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class DraftCandidateState:
    """Неизменяемый приватный JSON-снимок; свойства возвращают собственные копии.

    `original` всегда в порядке файлового каталога; порядок `snapshot` значим.
    None у источника означает подтверждённое отсутствие, а не неизвестность.
    Неизвестные записи доступны только через приватный export; их наличие
    нельзя считать подтверждением проверки этих данных известными сценариями.
    """

    _fields: UnknownFields

    def __init__(self, document: dict[str, object]) -> None:
        fields = None
        try:
            if type(document) is not dict or not valid_json_tree(document):
                _fail()
            fields = UnknownFields(document)
            values = fields.export()
            _read_snapshot(values["original"], original=True)
            _read_snapshot(values["snapshot"], original=False)
            _read_geo(values["geo_revisions"])
        except Exception:
            fields = None
        if fields is None:
            _fail()
        object.__setattr__(self, "_fields", fields)

    def export(self) -> dict[str, object]:
        """Копия полного раздела для доверенного кода; не для интерфейса и журналов."""
        return self._fields.export()

    @property
    def original(self) -> DraftDiffSnapshot:
        """Полный исходный снимок известных источников."""
        return _read_snapshot(self.export()["original"], original=True)

    @property
    def snapshot(self) -> DraftDiffSnapshot:
        """Полный кандидат известных источников, включая байты и порядок частей."""
        return _read_snapshot(self.export()["snapshot"], original=False)

    @property
    def geo_revisions(self) -> tuple[GeoDatabase, ...]:
        """Ожидаемые ревизии известных видов геобаз; это не свидетельства категорий."""
        return _read_geo(self.export()["geo_revisions"])


def rebuild_draft_candidate(value: object) -> DraftCandidateState:
    """Повторно проверить готовую модель, включая тип и содержимое закрытого снимка."""
    rebuilt = None
    try:
        if (type(value) is DraftCandidateState and type(value._fields) is UnknownFields
                and type(value._fields._snapshot) is str and type(value._fields._names) is tuple
                and all(type(name) is str for name in value._fields._names)):
            rebuilt = DraftCandidateState(rebuild_unknown_fields(value._fields).export())
    except Exception:
        pass
    if rebuilt is None:
        _fail()
    return rebuilt


def build_draft_candidate(
    original: DraftDiffSnapshot, snapshot: DraftDiffSnapshot, geo_revisions: tuple[GeoDatabase, ...],
    previous: DraftCandidateState | None = None,
) -> DraftCandidateState:
    """Заменить известный кандидат, сохранив исходный снимок и неизвестные записи.

    При повторном редактировании исходные данные не меняются. Вызывающий
    проверяет их соответствие baseline.
    """
    result = None
    try:
        original_document = snapshot_document(original, original=True)
        candidate_document = snapshot_document(snapshot)
        geo_document = _geo_document(geo_revisions)
        if previous is None:
            document = {"original": original_document, "snapshot": candidate_document, "geo_revisions": geo_document}
        else:
            checked = rebuild_draft_candidate(previous)
            # Сравнение JSON-снимков различает true, 1 и 1.0, в отличие от dict ==.
            if UnknownFields(snapshot_document(checked.original, original=True)) != UnknownFields(original_document):
                _fail()
            document = checked.export()
            document["snapshot"].update(candidate_document)
            document["geo_revisions"].update(geo_document)
        result = DraftCandidateState(document)
    except Exception:
        pass
    if result is None:
        _fail()
    return result
