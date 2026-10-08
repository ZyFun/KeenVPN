"""Метаданные файлов GeoIP и GeoSite и ссылки на их наборы из конфигурации Xray.

Модели работают в памяти: размер и SHA-256 файла передаёт источник, содержимое
баз и наличие наборов внутри них не проверяются. Отсутствующая база отражается
записью `present=False`: она не создаётся и не обновляется. Версия не выводится
из имени файла, источник и способ обновления не угадываются: известны только
переданные источником сведения либо их отсутствие. Ссылки `geoip:`, `geosite:`,
`ext:`, `ext-domain:` и `ext-ip:` разбираются по правилам загрузчика Xray и
сопоставляются с файлами только по имени; произвольный файл не считается
обслуживаемым штатной командой XKeen.
"""

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import NoReturn
from urllib.parse import urlsplit

from keenvpn.domain.config_document import valid_document_name
from keenvpn.domain.routing import ConditionFamily, GeoDatabase, GeoDatabaseKind, _is_text
from keenvpn.domain.xray_config import RuleListValue, XrayConfigSet, rule_list_values


GEOIP_FILE_NAME = "geoip.dat"
"""Файл, из которого Xray читает `geoip:` и `ext:geoip.dat:`."""
GEOSITE_FILE_NAME = "geosite.dat"
"""Файл, из которого Xray читает `geosite:` и `ext:geosite.dat:`."""
STANDARD_FILE_NAMES = {GeoDatabaseKind.GEOIP: GEOIP_FILE_NAME, GeoDatabaseKind.GEOSITE: GEOSITE_FILE_NAME}
"""Имена баз, которые инвентарь описывает всегда — найденными или отсутствующими."""

_STANDARD_KINDS = {name: kind for kind, name in STANDARD_FILE_NAMES.items()}
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
"""Версия в безопасном выводе: короткий идентификатор релиза без пробелов и разделителей URL."""
_SAFE_SOURCE = re.compile(r"(?=.{1,128}\Z)[A-Za-z0-9][A-Za-z0-9_+-]*(?:\.[A-Za-z0-9_+-]+)*")
"""Источник в безопасном выводе: один сегмент вида `v2fly` без `/`, `:`, `@`, `?`, `#` и пустых частей между точками.

`/` не допускается совсем: двухсегментный относительный путь неотличим
от формы «владелец/репозиторий» и может содержать приватные каталоги."""
_SAFE_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
_GEOSITE_PREFIX = "geosite:"
_GEOIP_PREFIX = "geoip:"
_EXT_PREFIX = "ext:"
_EXT_DOMAIN_PREFIX = "ext-domain:"
_EXT_IP_PREFIX = "ext-ip:"


class GeoDataErrorCode(StrEnum):
    """Причины отказа без имён файлов, значений правил и метаданных."""

    FILE = "invalid_geo_database_file"
    INVENTORY = "invalid_geo_inventory"
    REFERENCE = "invalid_geo_reference"
    STATE = "invalid_geodata_state"


_MESSAGES = {
    GeoDataErrorCode.FILE: (
        "Запись файла геобазы должна содержать имя файла, признак наличия, а для найденного файла — размер и SHA-256."
    ),
    GeoDataErrorCode.INVENTORY: (
        "Инвентарь геобаз должен быть кортежем записей с уникальными именами, включая geoip.dat и geosite.dat."
    ),
    GeoDataErrorCode.REFERENCE: "Ссылка на набор геобазы имеет неподдерживаемую структуру.",
    GeoDataErrorCode.STATE: "Состояние геобаз должно содержать инвентарь и кортеж ссылок конфигурации.",
}


class GeoDataError(ValueError):
    """Отказ с машинным кодом и фиксированным безопасным текстом."""

    def __init__(self, code: GeoDataErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: GeoDataErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise GeoDataError(code) from None
    except GeoDataError as error:
        error.__context__ = None
        raise


def safe_geo_version(value: str | None) -> str | None:
    """Версия для вывода, если она короткий идентификатор; иное значение скрывается."""
    return value if type(value) is str and _SAFE_VERSION.fullmatch(value) else None


def safe_geo_source(value: str | None) -> str | None:
    """Источник для вывода без учётных данных и параметров.

    Идентификатор из одного сегмента показывается как есть. URL `http`/`https`
    сводится к схеме и хосту с портом: `userinfo`, путь, query и fragment могут
    содержать пароли и токены и не выводятся. Файловые пути, абсолютные и
    относительные, и иные значения скрываются.
    """
    if type(value) is not str:
        return None
    if _SAFE_SOURCE.fullmatch(value):
        return value
    host = port = scheme = None
    try:
        parts = urlsplit(value)
        scheme, host, port = parts.scheme.lower(), parts.hostname, parts.port
    except ValueError:
        return None
    if scheme not in ("http", "https") or host is None or _SAFE_HOST.fullmatch(host) is None:
        return None
    return f"{scheme}://{host}" if port is None else f"{scheme}://{host}:{port}"


class GeoFileStatus(StrEnum):
    """Итог сопоставления ссылки с инвентарём файлов."""

    PRESENT = "present"
    """Файл есть в инвентаре и найден."""
    MISSING = "missing"
    """Файл описан инвентарём как отсутствующий."""
    UNKNOWN = "unknown"
    """Файла нет в инвентаре: источник его не наблюдал."""


@dataclass(frozen=True, slots=True, repr=False)
class GeoDatabaseFile:
    """Файл геобазы: имя, наличие, размер, SHA-256 и известные источник и версия.

    `None` в `source` и `version` означает отсутствие сведений, а не значение
    по умолчанию: версия не выводится из имени, источник не угадывается.
    Для отсутствующего файла размер и хеш всегда `None`.
    """

    name: str
    present: bool
    size: int | None = None
    sha256: str | None = None
    source: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        if not valid_document_name(self.name) or type(self.present) is not bool:
            _raise_detached(GeoDataErrorCode.FILE)
        if self.present:
            if (
                type(self.size) is not int or self.size < 0
                or type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None
            ):
                _raise_detached(GeoDataErrorCode.FILE)
            object.__setattr__(self, "sha256", self.sha256.lower())
        elif self.size is not None or self.sha256 is not None:
            _raise_detached(GeoDataErrorCode.FILE)
        if any(value is not None and not _is_text(value) for value in (self.source, self.version)):
            _raise_detached(GeoDataErrorCode.FILE)

    def __repr__(self) -> str:
        return f"GeoDatabaseFile(name={self.name!r}, present={self.present})"

    @property
    def standard_kind(self) -> GeoDatabaseKind | None:
        """Тип стандартной базы по имени файла; для прочих файлов — None."""
        return _STANDARD_KINDS.get(self.name)

    def database(self, kind: GeoDatabaseKind) -> GeoDatabase | None:
        """Метаданные базы для условий маршрутизации; для отсутствующего файла — None."""
        if not isinstance(kind, GeoDatabaseKind) or (self.standard_kind is not None and self.standard_kind is not kind):
            _raise_detached(GeoDataErrorCode.FILE)
        if not self.present:
            return None
        return GeoDatabase(kind, self.name, self.source, self.version, self.sha256)

    def to_diagnostic(self) -> dict[str, object]:
        """Имя, наличие, ревизия и безопасные источник и версия.

        Исходные значения доступны доверенному коду через поля и `database()`.
        В вывод они попадают только в безопасной форме (`safe_geo_source`,
        `safe_geo_version`); признаки `*_known` сохраняют факт наличия сведений.
        """
        return {
            "name": self.name,
            "present": self.present,
            "size": self.size,
            "sha256": self.sha256,
            "source_known": self.source is not None,
            "source": safe_geo_source(self.source),
            "version_known": self.version is not None,
            "version": safe_geo_version(self.version),
        }


def _check_files(files: object) -> None:
    if type(files) is not tuple or any(type(item) is not GeoDatabaseFile for item in files):
        _raise_detached(GeoDataErrorCode.INVENTORY)
    for item in files:
        rebuilt = GeoDatabaseFile(item.name, item.present, item.size, item.sha256, item.source, item.version)
        if rebuilt != item:
            _raise_detached(GeoDataErrorCode.INVENTORY)
    names = [item.name for item in files]
    unique = set(names)
    if len(unique) != len(names) or any(name not in unique for name in STANDARD_FILE_NAMES.values()):
        _raise_detached(GeoDataErrorCode.INVENTORY)


@dataclass(frozen=True, slots=True, repr=False)
class GeoDatabaseInventory:
    """Файлы каталога геобаз в порядке источника; стандартные имена описаны всегда.

    Инвентарь — снимок каталога на момент чтения: он не подтверждает, что
    Xray загрузил эти файлы, и не содержит наборов внутри баз.
    """

    files: tuple[GeoDatabaseFile, ...]

    def __post_init__(self) -> None:
        _check_files(self.files)

    def __repr__(self) -> str:
        return f"GeoDatabaseInventory(files={len(self.files)})"

    def file(self, name: str) -> GeoDatabaseFile | None:
        """Запись файла по точному имени либо None, если источник его не наблюдал."""
        for item in self.files:
            if item.name == name:
                return item
        return None

    def standard(self, kind: GeoDatabaseKind) -> GeoDatabaseFile:
        """Запись стандартной базы; инвентарь гарантирует её наличие."""
        if not isinstance(kind, GeoDatabaseKind):
            _raise_detached(GeoDataErrorCode.INVENTORY)
        item = self.file(STANDARD_FILE_NAMES[kind])
        if item is None:
            _raise_detached(GeoDataErrorCode.INVENTORY)
        return item

    def to_diagnostic(self) -> dict[str, object]:
        """Записи файлов и счётчики найденных, отсутствующих и нестандартных файлов."""
        return {
            "files": [item.to_diagnostic() for item in self.files],
            "present_count": sum(item.present for item in self.files),
            "missing_count": sum(not item.present for item in self.files),
            "extra_count": sum(item.standard_kind is None for item in self.files),
        }


def validate_geo_inventory(inventory: GeoDatabaseInventory) -> None:
    """Проверить готовую модель заново, включая каждую запись файла."""
    if type(inventory) is not GeoDatabaseInventory:
        _raise_detached(GeoDataErrorCode.INVENTORY)
    _check_files(inventory.files)


@dataclass(frozen=True, slots=True, repr=False)
class GeoReference:
    """Ссылка правила или DNS на набор геобазы по правилам загрузчика Xray.

    `set_name` хранится как написан; Xray сравнивает коды без учёта регистра.
    Отрицание `!` возможно только для адресов, атрибуты `@attr` — только для
    доменов. Имя внешнего файла задаёт пользователь, поэтому в безопасный вывод
    оно попадает только в форме имени файла без каталога.
    """

    part: str
    path: str
    family: ConditionFamily
    external: bool
    file_name: str
    set_name: str
    negated: bool = False
    attributes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not valid_document_name(self.part)
            or type(self.path) is not str or not self.path or not self.path.isprintable()
            or not isinstance(self.family, ConditionFamily)
            or type(self.external) is not bool
            or type(self.file_name) is not str or not self.file_name
            or not _is_text(self.set_name)
            or type(self.negated) is not bool
            or (self.negated and self.family is not ConditionFamily.IP)
            or type(self.attributes) is not tuple or any(type(item) is not str for item in self.attributes)
            or (self.attributes and self.family is not ConditionFamily.DOMAIN)
            or (not self.external and self.file_name != STANDARD_FILE_NAMES[self._standard_kind_for_family()])
        ):
            _raise_detached(GeoDataErrorCode.REFERENCE)

    def _standard_kind_for_family(self) -> GeoDatabaseKind:
        """`geosite:` читается из geosite.dat, `geoip:` — из geoip.dat."""
        return GeoDatabaseKind.GEOSITE if self.family is ConditionFamily.DOMAIN else GeoDatabaseKind.GEOIP

    def __repr__(self) -> str:
        return (
            f"GeoReference(part={self.part!r}, path={self.path!r}, family={self.family.value}, "
            f"external={self.external})"
        )

    @property
    def code(self) -> str:
        """Код набора в верхнем регистре, как его ищет Xray."""
        return self.set_name.upper()

    @property
    def file_name_safe(self) -> bool:
        """Можно ли показывать имя файла: имя без каталога, как у частей конфигурации."""
        return valid_document_name(self.file_name)

    @property
    def standard_kind(self) -> GeoDatabaseKind | None:
        """Тип базы для стандартных ссылок и файлов; для прочего внешнего файла — None."""
        if not self.external:
            return self._standard_kind_for_family()
        return _STANDARD_KINDS.get(self.file_name)


@dataclass(frozen=True, slots=True)
class UnsupportedGeoReference:
    """Ссылка с префиксом геобазы, которую загрузчик Xray отклонил бы; текст не сохраняется."""

    part: str
    path: str
    family: ConditionFamily

    def __post_init__(self) -> None:
        if (
            not valid_document_name(self.part)
            or type(self.path) is not str or not self.path or not self.path.isprintable()
            or not isinstance(self.family, ConditionFamily)
        ):
            _raise_detached(GeoDataErrorCode.REFERENCE)


def _external_rest(text: str, qualified: bool, qualified_prefix: str) -> str | None:
    if text.startswith(_EXT_PREFIX):
        return text[len(_EXT_PREFIX):]
    if qualified and text.startswith(qualified_prefix):
        return text[len(qualified_prefix):]
    return None


def _site_reference(value: RuleListValue, external: bool, file_name: str, site_with_attr: str) -> GeoReference | UnsupportedGeoReference:
    """Как `loadGeositeWithAttr`: код до первого `@`, атрибуты после; пустой код Xray не загрузит."""
    code, *attributes = site_with_attr.split("@")
    unsupported = UnsupportedGeoReference(value.part, value.path, value.family)
    if not code:
        return unsupported
    try:
        return GeoReference(
            value.part, value.path, ConditionFamily.DOMAIN, external, file_name, code, attributes=tuple(attributes),
        )
    except GeoDataError:
        return unsupported


def _ip_reference(value: RuleListValue, external: bool, file_name: str, country: str) -> GeoReference | UnsupportedGeoReference:
    """Как `ToCidrList`: ведущий `!` — отрицание; пустой код после него Xray отклоняет."""
    negated = country.startswith("!")
    if negated:
        country = country[1:]
    unsupported = UnsupportedGeoReference(value.part, value.path, value.family)
    if not country:
        return unsupported
    try:
        return GeoReference(value.part, value.path, ConditionFamily.IP, external, file_name, country, negated=negated)
    except GeoDataError:
        return unsupported


def parse_geo_reference(value: RuleListValue) -> GeoReference | UnsupportedGeoReference | None:
    """Разобрать значение списка по правилам Xray; значение без префикса геобазы даёт None.

    Домены: `geosite:` и `ext:`/`ext-domain:` файл и список через `:`.
    Адреса: `geoip:` и `ext:`/`ext-ip:`; префиксы проверяются в порядке Xray.
    Внешняя ссылка должна делиться ровно на имя файла и список; пустые части
    и прочие структуры, которые Xray не загрузит, становятся неподдержанной ссылкой.
    """
    if type(value) is not RuleListValue:
        _raise_detached(GeoDataErrorCode.REFERENCE)
    text = value.value
    if value.family is ConditionFamily.DOMAIN:
        if text.startswith(_GEOSITE_PREFIX):
            return _site_reference(value, False, GEOSITE_FILE_NAME, text[len(_GEOSITE_PREFIX):])
        rest = _external_rest(text, value.qualified, _EXT_DOMAIN_PREFIX)
        build = _site_reference
    else:
        if text.startswith(_GEOIP_PREFIX):
            return _ip_reference(value, False, GEOIP_FILE_NAME, text[len(_GEOIP_PREFIX):])
        rest = _external_rest(text, value.qualified, _EXT_IP_PREFIX)
        build = _ip_reference
    if rest is None:
        return None
    file_name, separator, set_name = rest.partition(":")
    if not separator or ":" in set_name or not file_name or not set_name:
        return UnsupportedGeoReference(value.part, value.path, value.family)
    return build(value, True, file_name, set_name)


def geo_references(config: XrayConfigSet) -> tuple[GeoReference | UnsupportedGeoReference, ...]:
    """Ссылки на наборы геобаз из правил маршрутизации, серверов и `hosts` DNS в порядке частей."""
    if type(config) is not XrayConfigSet:
        _raise_detached(GeoDataErrorCode.REFERENCE)
    found = []
    for value in rule_list_values(config.parts):
        reference = parse_geo_reference(value)
        if reference is not None:
            found.append(reference)
    return tuple(found)


@dataclass(frozen=True, slots=True, repr=False)
class GeoReferenceResolution:
    """Ссылка и запись файла, с которой она сопоставлена по имени."""

    reference: GeoReference
    status: GeoFileStatus
    file: GeoDatabaseFile | None

    def __repr__(self) -> str:
        return f"GeoReferenceResolution(status={self.status.value})"


def _check_references(references: object) -> None:
    if type(references) is not tuple:
        _raise_detached(GeoDataErrorCode.STATE)
    for item in references:
        if type(item) is GeoReference:
            rebuilt = GeoReference(
                item.part, item.path, item.family, item.external, item.file_name, item.set_name,
                negated=item.negated, attributes=item.attributes,
            )
        elif type(item) is UnsupportedGeoReference:
            rebuilt = UnsupportedGeoReference(item.part, item.path, item.family)
        else:
            _raise_detached(GeoDataErrorCode.STATE)
        if rebuilt != item:
            _raise_detached(GeoDataErrorCode.STATE)


@dataclass(frozen=True, slots=True, repr=False)
class GeoDataState:
    """Инвентарь файлов и ссылки конфигурации; сопоставление считается по имени файла.

    Это снимок на момент чтения: он не доказывает, что Xray загрузил найденные
    файлы и что наборы существуют внутри них. Отсутствующая и неизвестная
    инвентарю база отражаются в сопоставлении, но не создаются.
    """

    inventory: GeoDatabaseInventory
    references: tuple[GeoReference | UnsupportedGeoReference, ...]

    def __post_init__(self) -> None:
        validate_geo_inventory(self.inventory)
        _check_references(self.references)

    def __repr__(self) -> str:
        return f"GeoDataState(files={len(self.inventory.files)}, references={len(self.references)})"

    def resolve(self) -> tuple[GeoReferenceResolution, ...]:
        """Сопоставить каждую разобранную ссылку с файлом инвентаря; стоимость линейна."""
        by_name = {item.name: item for item in self.inventory.files}
        resolutions = []
        for reference in self.references:
            if type(reference) is not GeoReference:
                continue
            found = by_name.get(reference.file_name)
            if found is None:
                status = GeoFileStatus.UNKNOWN
            elif found.present:
                status = GeoFileStatus.PRESENT
            else:
                status = GeoFileStatus.MISSING
            resolutions.append(GeoReferenceResolution(reference, status, found))
        return tuple(resolutions)

    def to_diagnostic(self) -> dict[str, object]:
        """Файлы со счётчиками ссылок, ссылки без кодов наборов и неподдержанные места."""
        resolutions = self.resolve()
        reference_counts: dict[str, int] = {}
        codes: dict[str, set[str]] = {}
        for resolution in resolutions:
            name = resolution.reference.file_name
            reference_counts[name] = reference_counts.get(name, 0) + 1
            codes.setdefault(name, set()).add(resolution.reference.code)
        files = [
            {
                **item.to_diagnostic(),
                "reference_count": reference_counts.get(item.name, 0),
                "set_count": len(codes.get(item.name, ())),
            }
            for item in self.inventory.files
        ]
        references = [
            {
                "part": resolution.reference.part,
                "path": resolution.reference.path,
                "family": resolution.reference.family.value,
                "external": resolution.reference.external,
                "file_name": resolution.reference.file_name if resolution.reference.file_name_safe else None,
                "file_status": resolution.status.value,
                "negated": resolution.reference.negated,
                "attribute_count": len(resolution.reference.attributes),
            }
            for resolution in resolutions
        ]
        unsupported = [
            {"part": item.part, "path": item.path, "family": item.family.value}
            for item in self.references if type(item) is UnsupportedGeoReference
        ]
        return {
            "files": files,
            "present_count": sum(item.present for item in self.inventory.files),
            "missing_count": sum(not item.present for item in self.inventory.files),
            "extra_count": sum(item.standard_kind is None for item in self.inventory.files),
            "references": references,
            "reference_count": len(references),
            "resolved_count": sum(item.status is GeoFileStatus.PRESENT for item in resolutions),
            "unresolved_count": sum(item.status is not GeoFileStatus.PRESENT for item in resolutions),
            "unsupported_references": unsupported,
        }


def assemble_geodata_state(inventory: GeoDatabaseInventory, config: XrayConfigSet) -> GeoDataState:
    """Собрать состояние геобаз из инвентаря и ссылок конфигурации без ввода-вывода."""
    return GeoDataState(inventory, geo_references(config))


def validate_geodata_state(state: GeoDataState) -> None:
    """Проверить готовую модель заново, включая инвентарь и каждую ссылку."""
    if type(state) is not GeoDataState:
        _raise_detached(GeoDataErrorCode.STATE)
    validate_geo_inventory(state.inventory)
    _check_references(state.references)
