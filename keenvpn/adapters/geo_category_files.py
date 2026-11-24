"""Каталоги имён из GeoIPList/GeoSiteList Xray без сторонних зависимостей."""

from collections.abc import Iterator
import hashlib

from keenvpn.application.draft_candidate import GeoCategoryCatalog
from keenvpn.application.saved_draft import CandidateAssetSource
from keenvpn.application.xray_candidate import MAX_ASSET_BYTES, MAX_ASSETS, MAX_TOTAL_ASSET_BYTES
from keenvpn.domain.routing import GeoDatabase


_MAX_CODE_BYTES = 127
_MAX_CATEGORIES = 65_536


def _varint(content: bytes, start: int, stop: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if start == stop:
            break
        byte = content[start]
        start += 1
        if shift == 63 and byte > 1:
            break
        value |= (byte & 127) << shift
        if byte < 128:
            return value, start
    raise ValueError("Недопустимое целое protobuf.")


def _fields(content: bytes, start: int, stop: int) -> Iterator[tuple[int, int, int, int]]:
    while start < stop:
        tag, start = _varint(content, start, stop)
        field, wire = tag >> 3, tag & 7
        if not 0 < field < 1 << 29:
            raise ValueError("Недопустимый номер поля protobuf.")
        if wire == 2:
            size, start = _varint(content, start, stop)
            end = start + size
        elif wire == 0:
            _, end = _varint(content, start, stop)
        elif wire in (1, 5):
            end = start + (8 if wire == 1 else 4)
        else:
            raise ValueError("Неподдерживаемое поле protobuf.")
        if end > stop:
            raise ValueError("Оборванное поле protobuf.")
        yield field, wire, start, end
        start = end


def _categories(content: bytes) -> frozenset[str]:
    # Xray v26.3.27, app/router/config.proto: у обоих списков entry = 1,
    # у обеих записей country_code = 1. Загрузчик infra/conf/router.go ищет
    # код в начале записи и читает его длину одним байтом.
    categories = set()
    offset = 0
    while offset < len(content):
        if content[offset] != 0x0a:
            raise ValueError("Недопустимое поле списка геобазы.")
        size, start = _varint(content, offset + 1, len(content))
        end = start + size
        if size < 3 or end > len(content) or content[start] != 0x0a:
            raise ValueError("Недопустимая запись геобазы.")
        length = content[start + 1]
        code_end = start + 2 + length
        if not 0 < length <= _MAX_CODE_BYTES or code_end > end:
            raise ValueError("Недопустимое имя категории.")
        code = content[start + 2:code_end].decode("ascii")
        if not code.isprintable() or code.strip() != code or code.upper() != code:
            raise ValueError("Недопустимое имя категории.")
        if any(field == 1 for field, _, _, _ in _fields(content, code_end, end)):
            raise ValueError("Повтор имени внутри записи.")
        if code in categories or len(categories) == _MAX_CATEGORIES:
            raise ValueError("Не удалось подтвердить единственность или состав категорий.")
        categories.add(code)
        offset = end
    if not categories:
        raise ValueError("Геобаза пуста.")
    return frozenset(categories)


class GeoCategoryFiles:
    """Извлечь полные имена из доверенных байтов той же ожидаемой ревизии."""

    def __init__(self, assets: CandidateAssetSource) -> None:
        self._assets = assets

    def read_catalogs(self, revisions: tuple[GeoDatabase, ...]) -> tuple[GeoCategoryCatalog, ...]:
        if len(revisions) > MAX_ASSETS:
            return ()
        catalogs = []
        total = 0
        for revision in revisions:
            limit = min(MAX_ASSET_BYTES, MAX_TOTAL_ASSET_BYTES - total)
            if limit <= 0:
                break
            try:
                content = self._assets.read_asset(revision.reference, limit)
            except Exception:
                continue
            if type(content) is not bytes or len(content) > limit:
                continue
            total += len(content)
            if hashlib.sha256(content).hexdigest() == revision.sha256:
                try:
                    categories = _categories(content)
                except ValueError:
                    categories = None
                catalogs.append(GeoCategoryCatalog(revision, categories))
            del content
        return tuple(catalogs)
