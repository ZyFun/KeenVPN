"""Структурные операции просмотра. В записи попадают только коды схемы и позиции."""

from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from itertools import zip_longest
import json

from keenvpn.application.draft_diff_snapshot import PreparedSnapshot
from keenvpn.domain.config_document import parse_strict_json_object
from keenvpn.domain.source_baseline import BaselineSource as Source
from keenvpn.domain.xkeen_config import KNOWN_INIT_FLAGS, XKeenConfigError, XKeenList, XKeenListName, parse_xkeen_init


class DiffOperation(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    REORDERED = "reordered"


@dataclass(frozen=True, slots=True)
class DiffEntry:
    """Позиции с нуля. При удалении позиция исходная, при добавлении или изменении — кандидатная."""

    source: Source
    area: str
    operation: DiffOperation
    part: int | None = None
    position: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {"source": self.source.value, "area": self.area, "operation": self.operation.value,
                "part": self.part, "position": self.position}


# Только правая сторона схемы может попасть в отчёт. Неизвестные поля одного объекта
# сравниваются вместе. Их имена и внутреннее устройство никогда не образуют путь вывода.
_FIELDS = {
    "xray": {"routing": "routing", "inbounds": "inbounds", "outbounds": "outbounds", "api": "api",
             "dns": "dns", "log": "log", "observatory": "observatory", "burstObservatory": "observatory"},
    "routing": {"rules": "routing_rules", "balancers": "balancers", "domainStrategy": "domain_strategy"},
    "outbounds": {"settings": "connection_settings", "streamSettings": "transport", "tag": "connection",
                  "protocol": "connection"},
    "inbounds": {"settings": "connection_settings", "tag": "connection", "protocol": "connection"},
    "connection_settings": {"servers": "servers", "vnext": "servers", "clients": "accounts", "password": "credentials"},
    "servers": {"password": "credentials", "users": "accounts", "address": "endpoint", "port": "endpoint"},
    "accounts": {"password": "credentials", "id": "credentials", "pass": "credentials"},
    "transport": {"realitySettings": "reality", "tlsSettings": "tls"},
    "reality": {"privateKey": "credentials", "publicKey": "credentials", "shortId": "credentials",
               "shortIds": "credentials", "password": "credentials"},
    "xkeen": {"xkeen": "xkeen_flags"},
    "xkeen_flags": {"killswitch": "killswitch"},
    "policy": {"permit": "permit", "description": "description"},
    "hotspot": {"host": "hosts", "policy": "segment_assignments", "auto-register": "auto_register"},
}
_ARRAYS = {"routing_rules", "balancers", "outbounds", "inbounds", "servers", "accounts", "permit", "hosts",
           "segment_assignments", "list_entries"}
_MISSING = object()


def _key(value: object) -> str:
    """Ключ сравнения: сохраняет типы, порядок массивов и порядок полей Xray.

    В native-снимках ключи уже упорядочены при подготовке.
    """
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def _array_delta(area: str, before: list, after: list, position: int | None) -> Iterator[tuple]:
    """Сопоставить неизменённые элементы с учётом повторов до сравнения оставшихся.

    При смешанном редактировании сохраняется отдельная операция перестановки
    общих элементов. Позиция относится к внешнему списку, если он уже выбран.
    """
    left = [_key(item) for item in before]
    right = [_key(item) for item in after]
    common = Counter(left) & Counter(right)

    def split(keys):
        remaining = common.copy()
        matched, gaps = [], defaultdict(list)
        for index, key in enumerate(keys):
            if remaining[key]:
                matched.append(key)
                remaining[key] -= 1
            else:
                gaps[len(matched)].append(index)
        return matched, gaps

    old_order, removed = split(left)
    new_order, added = split(right)
    reordered = old_order != new_order
    if reordered:
        yield area, DiffOperation.REORDERED, position
    for gap in sorted(removed.keys() | added.keys()):
        old_indexes, new_indexes = removed[gap], added[gap]
        # Заменой считаем только правки между теми же неизменёнными элементами.
        pairs = zip_longest(old_indexes, new_indexes)
        if reordered:
            pairs = [(i, None) for i in old_indexes] + [(None, i) for i in new_indexes]
        for old, new in pairs:
            index = old if new is None else new
            at = index if position is None else position
            if old is None:
                yield area, DiffOperation.ADDED, at
            elif new is None:
                yield area, DiffOperation.REMOVED, at
            else:
                for child_area, operation, child_position in _delta(area, before[old], after[new], at, element=True):
                    if position is None and operation is DiffOperation.REMOVED:
                        child_position = old
                    yield child_area, operation, child_position


def _delta(area: str, before: object, after: object, position: int | None = None, *, element: bool = False
           ) -> Iterator[tuple]:
    if area == "xkeen_flags" and (type(before) is dict) != (type(after) is dict):
        # Даже при добавлении или удалении всего раздела выделить защитный флаг.
        old = before.get("killswitch", _MISSING) if type(before) is dict else _MISSING
        new = after.get("killswitch", _MISSING) if type(after) is dict else _MISSING
        if old is not _MISSING or new is not _MISSING:
            yield from _delta("killswitch", old, new, position)
    if before is _MISSING:
        yield area, DiffOperation.ADDED, position
    elif after is _MISSING:
        yield area, DiffOperation.REMOVED, position
    elif _key(before) == _key(after):
        return
    elif type(before) is dict and type(after) is dict and area in _FIELDS:
        fields = _FIELDS[area]
        if [key for key in before if key in after] != [key for key in after if key in before]:
            # В Xray варианты регистра могут назначать одно поле в порядке чтения.
            yield "field_order", DiffOperation.REORDERED, position
        for name, child in fields.items():
            if name in before or name in after:
                yield from _delta(child, before.get(name, _MISSING), after.get(name, _MISSING), position)
        old_extra = {k: v for k, v in before.items() if k not in fields}
        new_extra = {k: v for k, v in after.items() if k not in fields}
        if _key(old_extra) != _key(new_extra):
            yield "other_fields", DiffOperation.CHANGED, position
    elif type(before) is list and type(after) is list and area in _ARRAYS and not element:
        yield from _array_delta(area, before, after, position)
    else:
        yield area, DiffOperation.CHANGED, position


_LISTS = {
    Source.XKEEN_PORT_EXCLUDE: XKeenListName.PORT_EXCLUDE,
    Source.XKEEN_PORT_PROXYING: XKeenListName.PORT_PROXYING,
    Source.XKEEN_IP_EXCLUDE: XKeenListName.IP_EXCLUDE,
}


def _init_projection(content: bytes) -> tuple[dict, list[bytes]]:
    """Приватные состояния флагов и исходные строки без распознанных значений on/off."""
    model = parse_xkeen_init(content)
    flags = {}
    lines = content.split(b"\n")
    for name in KNOWN_INIT_FLAGS:
        switch = model.switch(name)
        assignments = tuple(item for item in model.assignments if item.name == name)
        if switch.value is None:
            # У двух неподдержанных выражений может быть разный смысл для shell.
            flags[name] = tuple((item.indented, item.raw) for item in assignments)
        else:
            flags[name] = switch.value
            index = assignments[0].line_number - 1
            literal = b'"' + switch.value.encode("ascii") + b'"'
            lines[index] = lines[index].replace(literal, b'""', 1)
    return flags, lines


def _init_delta(before: bytes, after: bytes) -> Iterator[tuple]:
    try:
        old, old_lines = _init_projection(before)
        new, new_lines = _init_projection(after)
    except XKeenConfigError:
        yield "file", DiffOperation.CHANGED, None
        return
    for name in KNOWN_INIT_FLAGS:
        if old[name] != new[name]:
            yield name, DiffOperation.CHANGED, None
    if old_lines != new_lines:
        yield "file", DiffOperation.CHANGED, None


def _file_delta(source: Source, before: bytes, after: bytes) -> Iterator[tuple]:
    if source in (Source.XRAY_CONFIGS, Source.XKEEN_SETTINGS):
        area = "xray" if source is Source.XRAY_CONFIGS else "xkeen"
        old = parse_strict_json_object(before.decode("utf-8"))
        new = parse_strict_json_object(after.decode("utf-8"))
    elif source in _LISTS:
        area = "list_entries"
        old, new = ([line.entry for line in XKeenList(_LISTS[source], raw).lines if line.entry is not None]
                    for raw in (before, after))
    elif source is Source.XKEEN_INIT:
        yield from _init_delta(before, after)
        return
    else:
        area = "hotspot"
        old, new = json.loads(before), json.loads(after)
    if _key(old) == _key(new):
        yield "representation", DiffOperation.CHANGED, None
    else:
        yield from _delta(area, old, new)


def snapshot_changes(original: PreparedSnapshot, candidate: PreparedSnapshot) -> Iterator[DiffEntry]:
    """Перечислить только безопасные записи в порядке источников и имён частей."""
    for source in Source:
        old, new = original.sources[source], candidate.sources[source]
        # Исходный каталог упорядочен по имени. Равенство dict не учитывает порядок загрузки.
        if source is Source.XRAY_CONFIGS and new is not None and list(new) != sorted(new):
            yield DiffEntry(source, "part", DiffOperation.REORDERED)
        if old == new:
            continue
        if old is None or new is None:
            yield DiffEntry(source, "source", DiffOperation.ADDED if old is None else DiffOperation.REMOVED)
            if source is Source.XKEEN_INIT or source is Source.XKEEN_SETTINGS:
                empty = b"" if source is Source.XKEEN_INIT else b"{}"
                for area, operation, _ in _file_delta(source, empty if old is None else old, empty if new is None else new):
                    if area in KNOWN_INIT_FLAGS or area == "killswitch":
                        yield DiffEntry(source, area, operation)
        elif source is Source.KEENETIC_POLICIES:
            # Канонический JSON уже отсортирован по приватным ID политик.
            before, after = json.loads(old), json.loads(new)
            before_index = {key: index for index, key in enumerate(before)}
            after_index = {key: index for index, key in enumerate(after)}
            for key in sorted(before.keys() | after.keys()):
                changes = _delta("policy", before.get(key, _MISSING), after.get(key, _MISSING))
                for area, operation, position in changes:
                    ordinal = before_index[key] if operation is DiffOperation.REMOVED else after_index[key]
                    yield DiffEntry(source, area, operation, ordinal, position)
        elif source is Source.XRAY_CONFIGS:
            old_indexes = {name: index for index, name in enumerate(old)}
            new_indexes = {name: index for index, name in enumerate(sorted(new))}
            for name in sorted(old.keys() | new.keys()):
                if name not in old:
                    yield DiffEntry(source, "part", DiffOperation.ADDED, new_indexes[name])
                elif name not in new:
                    yield DiffEntry(source, "part", DiffOperation.REMOVED, old_indexes[name])
                elif old[name] != new[name]:
                    for area, operation, position in _file_delta(source, old[name], new[name]):
                        ordinal = old_indexes[name] if operation is DiffOperation.REMOVED else new_indexes[name]
                        yield DiffEntry(source, area, operation, ordinal, position)
        else:
            for area, operation, position in _file_delta(source, old, new):
                yield DiffEntry(source, area, operation, position=position)
