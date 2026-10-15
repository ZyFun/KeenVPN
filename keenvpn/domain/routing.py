"""Условия и действия маршрутизации в памяти, без чтения баз и конфигураций."""

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
from typing import NoReturn
import unicodedata


MAX_RULE_NAME_LENGTH = 64
"""Предел длины названия правила в символах Unicode; в UTF-8 это не больше 256 байт."""

_RULE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class RoutingAction(str, Enum):
    """Направление трафика; VPN не подразумевает прямого резерва."""

    DIRECT = "DIRECT"
    VPN = "VPN"
    BLOCK = "BLOCK"


class DomainMatch(str, Enum):
    """Точное имя либо имя вместе с поддоменами."""

    EXACT = "exact"
    SUBDOMAINS = "subdomains"


class GeoDatabaseKind(str, Enum):
    """Независимые базы IP-сетей и доменных наборов."""

    GEOIP = "geoip"
    GEOSITE = "geosite"


class ConditionFamily(str, Enum):
    """Область неизвестной ссылки, сохранённая при импорте."""

    DOMAIN = "domain"
    IP = "ip"


class RoutingErrorCode(str, Enum):
    """Причина отказа без включения исходного значения в сообщение."""

    DOMAIN = "invalid_domain"
    DOMAIN_MATCH = "invalid_domain_match"
    IP = "invalid_ip_or_cidr"
    DATABASE = "invalid_database"
    DATABASE_KIND = "invalid_database_kind"
    SET_NAME = "invalid_set_name"
    REFERENCE = "invalid_imported_reference"
    RULE_FIELDS = "invalid_rule_fields"
    CONDITION = "invalid_condition"
    ACTION = "invalid_action"
    RULES = "invalid_rules"
    FINAL_RULE = "invalid_final_rule"
    POSITION = "invalid_rule_position"
    READ_ONLY = "read_only_routing_policy"
    MATCH_RESULT = "invalid_match_result"
    MATCH_UNKNOWN = "unknown_rule_match"
    MATCHER = "rule_matcher_failed"
    RULE_STATE = "invalid_rule_state"
    RULE_ID = "invalid_rule_id"
    RULE_NAME = "invalid_rule_name"
    DUPLICATE_RULE_ID = "duplicate_rule_id"
    PROTECTED_RULE = "protected_rule"
    PROTECTED_ORDER = "invalid_protected_rule_order"
    CONTEXT = "invalid_routing_context"
    GEODATA_RESULT = "invalid_geodata_result"
    GEODATA_MISMATCH = "geodata_database_mismatch"
    EXPLANATION = "invalid_route_explanation"


class RoutingValidationError(ValueError):
    """Ошибка доменной модели с безопасным машинным кодом."""

    def __init__(self, code: RoutingErrorCode) -> None:
        self.code = code
        messages = {
            RoutingErrorCode.RULE_STATE: "Состояние и защита правила должны быть bool.",
            RoutingErrorCode.RULE_ID: "Идентификатор правила должен быть UUID в нижнем регистре либо None.",
            RoutingErrorCode.RULE_NAME: (
                f"Название правила должно быть строкой от 1 до {MAX_RULE_NAME_LENGTH} печатных символов "
                "без пробелов по краям либо None."
            ),
            RoutingErrorCode.DUPLICATE_RULE_ID: "Идентификаторы правил в пределах политики должны быть уникальными.",
            RoutingErrorCode.PROTECTED_RULE: (
                "Служебное правило должно быть включено; обычный редактор "
                "не может добавлять, удалять, перемещать или переключать его."
            ),
            RoutingErrorCode.PROTECTED_ORDER: (
                "Служебные правила должны оставаться непрерывным блоком "
                "в начале списка; пользовательское правило нельзя поставить перед ними."
            ),
        }
        super().__init__(messages.get(code, f"Некорректные данные маршрутизации: {code.value}."))


class _PrivateRepresentation:
    """Произвольные строки модели не предназначены для журналирования."""

    __slots__ = ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<скрытые параметры>)"


def _raise_detached(code: RoutingErrorCode) -> NoReturn:
    """Сообщить об отказе внешнего источника без его исключения и кадров.

    from None скрывает вывод, но сохраняет исходную цепочку. Её нужно очистить
    после raise и передать ошибку дальше без нового связывания.
    """
    try:
        raise RoutingValidationError(code) from None
    except RoutingValidationError as error:
        error.__context__ = None
        raise


def _normalize_domain(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 1024:
        return None
    candidate = unicodedata.normalize("NFC", value.lower()).translate(
        str.maketrans({"。": ".", "．": ".", "｡": "."})
    )
    if candidate.endswith("."):
        candidate = candidate[:-1]
    try:
        labels = []
        for label in candidate.split("."):
            encoded = label.encode("idna").decode("ascii")
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", encoded):
                return None
            decoded = encoded.encode("ascii").decode("idna")
            # IDNA стандартной библиотеки не должен незаметно менять имя,
            # например превращать ß в ss или удалять невидимый символ.
            if not label.isascii() and decoded != label:
                return None
            if decoded.encode("idna").decode("ascii") != encoded:
                return None
            labels.append(encoded)
        result = ".".join(labels)
        if len(result) > 253:
            return None
        try:
            ipaddress.ip_address(result)
        except ValueError:
            return result
        return None
    except (UnicodeError, ValueError):
        return None


def _normalize_ip(value: object) -> str | None:
    if not isinstance(value, str) or not value or "%" in value:
        return None
    try:
        if "/" not in value:
            return str(ipaddress.ip_address(value))
        address, prefix = value.split("/")
        if not re.fullmatch(r"0|[1-9][0-9]*", prefix):
            return None
        # Не расширять адрес с установленными битами хоста до целой сети.
        return str(ipaddress.ip_network(f"{address}/{prefix}", strict=True))
    except ValueError:
        return None


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.isprintable()


def valid_rule_id(value: object) -> bool:
    """Проверить формат идентификатора правила: UUID 8-4-4-4-12 в нижнем регистре.

    Регистр не нормализуется, версия UUID не проверяется. Формат не доказывает,
    что правило с таким идентификатором существует в политике или метаданных.
    """
    return type(value) is str and _RULE_ID.fullmatch(value) is not None


def valid_rule_name(value: object) -> bool:
    """Проверить название правила: от 1 до `MAX_RULE_NAME_LENGTH` символов Unicode.

    Только печатные символы по `str.isprintable()`: управляющие, форматирующие,
    невидимые и неразрывные пробелы отклоняются. Пробелы по краям не обрезаются,
    а отклоняются; содержимое не нормализуется. Дубли названий здесь не проверяются.
    """
    return (
        type(value) is str and 1 <= len(value) <= MAX_RULE_NAME_LENGTH
        and value.isprintable() and value == value.strip()
    )


@dataclass(frozen=True, slots=True, repr=False)
class DomainCondition(_PrivateRepresentation):
    """Нормализованное IDNA-имя; режим задаётся отдельно от имени."""

    value: str
    mode: DomainMatch = DomainMatch.SUBDOMAINS

    def __post_init__(self) -> None:
        if not isinstance(self.mode, DomainMatch):
            raise RoutingValidationError(RoutingErrorCode.DOMAIN_MATCH) from None
        normalized = _normalize_domain(self.value)
        if normalized is None:
            raise RoutingValidationError(RoutingErrorCode.DOMAIN) from None
        object.__setattr__(self, "value", normalized)

    @property
    def display_name(self) -> str:
        """Получить Unicode-имя для явного отображения пользователю."""
        return self.value.encode("ascii").decode("idna")


@dataclass(frozen=True, slots=True, repr=False)
class IPCondition(_PrivateRepresentation):
    """Отдельный IPv4/IPv6-адрес либо CIDR с корректным адресом сети."""

    value: str

    def __post_init__(self) -> None:
        normalized = _normalize_ip(self.value)
        if normalized is None:
            raise RoutingValidationError(RoutingErrorCode.IP) from None
        object.__setattr__(self, "value", normalized)


@dataclass(frozen=True, slots=True, repr=False)
class GeoDatabase(_PrivateRepresentation):
    """Явные метаданные базы; None означает неизвестное значение.

    reference — непрозрачная ссылка, а не разрешение читать файл.
    Версия не выводится из имени; SHA-256 не подтверждается без чтения базы.
    """

    kind: GeoDatabaseKind
    reference: str
    source: str | None = None
    version: str | None = None
    sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, GeoDatabaseKind):
            raise RoutingValidationError(RoutingErrorCode.DATABASE_KIND) from None
        if not _is_text(self.reference) or any(
            value is not None and not _is_text(value)
            for value in (self.source, self.version)
        ):
            raise RoutingValidationError(RoutingErrorCode.DATABASE) from None
        if self.sha256 is not None:
            if not isinstance(self.sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256):
                raise RoutingValidationError(RoutingErrorCode.DATABASE) from None
            object.__setattr__(self, "sha256", self.sha256.lower())


def _validate_geo_set(database: GeoDatabase, kind: GeoDatabaseKind, set_name: str) -> None:
    if not isinstance(database, GeoDatabase):
        raise RoutingValidationError(RoutingErrorCode.DATABASE) from None
    if database.kind is not kind:
        raise RoutingValidationError(RoutingErrorCode.DATABASE_KIND) from None
    # Имя не сверяется с каталогом и не преобразуется в другую категорию.
    if not isinstance(set_name, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_!@.\-]*", set_name
    ):
        raise RoutingValidationError(RoutingErrorCode.SET_NAME) from None


@dataclass(frozen=True, slots=True, repr=False)
class GeoIPCondition(_PrivateRepresentation):
    """Ссылка на именованный набор IP; наличие набора пока не подтверждено."""

    database: GeoDatabase
    set_name: str

    def __post_init__(self) -> None:
        _validate_geo_set(self.database, GeoDatabaseKind.GEOIP, self.set_name)


@dataclass(frozen=True, slots=True, repr=False)
class GeoSiteCondition(_PrivateRepresentation):
    """Ссылка на доменный набор, независимая от IP-страны и доменной зоны."""

    database: GeoDatabase
    set_name: str

    def __post_init__(self) -> None:
        _validate_geo_set(self.database, GeoDatabaseKind.GEOSITE, self.set_name)


@dataclass(frozen=True, slots=True, repr=False)
class UnknownCondition(_PrivateRepresentation):
    """Непонятная импортированная ссылка без нормализации и интерпретации.

    Исходная строка сохраняется даже с неподдержанным синтаксисом. Такое
    условие доступно только для просмотра и не становится обычным правилом.
    """

    family: ConditionFamily
    reference: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.family, ConditionFamily)
            or not isinstance(self.reference, str)
            or not self.reference
        ):
            raise RoutingValidationError(RoutingErrorCode.REFERENCE) from None


@dataclass(frozen=True, slots=True, repr=False)
class UnsupportedRuleCondition(_PrivateRepresentation):
    """Условия правила Xray целиком, которые модель не сводит к одному условию.

    Хранит имена полей условий правила в порядке файла и канонический
    JSON-снимок их значений, чтобы правило сохранило позицию в порядке без
    подмены смысла: логическое И нескольких полей, порты, сети, inbound и
    прочие поля Xray модель не сопоставляет. Имя поля — исходный ключ JSON,
    поэтому допустима любая строка, включая пустую; повторов нет. Пустой
    кортеж полей описывает правило без условий, которое не может быть
    финальным. Такое условие доступно только для просмотра, как и
    неизвестная ссылка.
    """

    fields: tuple[str, ...]
    snapshot: str

    def __post_init__(self) -> None:
        if (
            type(self.fields) is not tuple
            or any(type(name) is not str for name in self.fields)
            or len(set(self.fields)) != len(self.fields)
            or type(self.snapshot) is not str
            or not self.snapshot
        ):
            raise RoutingValidationError(RoutingErrorCode.RULE_FIELDS) from None


RoutingCondition = (
    DomainCondition | IPCondition | GeoIPCondition | GeoSiteCondition | UnknownCondition | UnsupportedRuleCondition
)


@dataclass(frozen=True, slots=True, repr=False)
class RoutingRule(_PrivateRepresentation):
    """Условие, действие и метаданные состояния, без применения к трафику.

    `rule_id` и `name` — метаданные менеджера, не поля Xray JSON и не `ruleTag`.
    Оба необязательны: импортированное правило их не имеет. Идентификатор
    присваивает доверенный код; название — произвольная строка пользователя,
    которая не попадает в `repr`, диагностику и ошибки.
    """

    condition: RoutingCondition
    action: RoutingAction
    enabled: bool = field(default=True, kw_only=True)
    protected: bool = field(default=False, kw_only=True)
    rule_id: str | None = field(default=None, kw_only=True)
    name: str | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if not isinstance(self.condition, RoutingCondition):
            raise RoutingValidationError(RoutingErrorCode.CONDITION) from None
        if not isinstance(self.action, RoutingAction):
            raise RoutingValidationError(RoutingErrorCode.ACTION) from None
        if type(self.enabled) is not bool or type(self.protected) is not bool:
            raise RoutingValidationError(RoutingErrorCode.RULE_STATE) from None
        if self.protected and not self.enabled:
            raise RoutingValidationError(RoutingErrorCode.PROTECTED_RULE) from None
        if self.rule_id is not None and not valid_rule_id(self.rule_id):
            raise RoutingValidationError(RoutingErrorCode.RULE_ID) from None
        if self.name is not None and not valid_rule_name(self.name):
            raise RoutingValidationError(RoutingErrorCode.RULE_NAME) from None

    @property
    def read_only(self) -> bool:
        """Неизвестную ссылку и неподдержанное правило нельзя безопасно редактировать как известные."""
        return isinstance(self.condition, (UnknownCondition, UnsupportedRuleCondition))

    def to_diagnostic(self) -> dict[str, str | bool | int | None]:
        """Описание структуры без доменов, адресов, ссылок и названия.

        Идентификатор выводится: он прошёл проверку формата и нужен для ссылок
        меню и Web. От названия остаются только признак наличия и длина в символах.
        """
        return {
            "condition_type": type(self.condition).__name__,
            "action": self.action.value,
            "read_only": self.read_only,
            "enabled": self.enabled,
            "protected": self.protected,
            "has_id": self.rule_id is not None,
            "rule_id": self.rule_id,
            "has_name": self.name is not None,
            "name_length": None if self.name is None else len(self.name),
            "parameters": "<скрыто>",
        }
