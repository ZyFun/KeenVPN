"""Предварительное объяснение правил по явно заданным сведениям в памяти."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
import ipaddress
from typing import TypeAlias

from keenvpn.domain.routing import (
    MAX_DESTINATION_ADDRESSES, MAX_DESTINATION_LENGTH, DomainCondition, DomainMatch, GeoDatabase, GeoIPCondition,
    GeoSiteCondition, IPCondition, RoutingCondition, RoutingErrorCode, RoutingRule, RoutingValidationError,
    UnknownCondition, UnsupportedRuleCondition, _normalize_domain, _normalize_ip, _PrivateRepresentation,
    _raise_detached,
)
from keenvpn.domain.routing_policy import (
    FinalRoutingRule, MatchResult, RoutingPolicy, RoutingSelection,
)


class DomainSource(str, Enum):
    """Предположение о видимости имени, а не результат сетевой проверки."""

    DESTINATION = "destination"
    SNIFFING = "sniffing"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class IPSource(str, Enum):
    """Откуда взят полный набор адресов, доступных этому расчёту."""

    DESTINATION = "destination"
    DNS = "dns"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ExplanationReason(str, Enum):
    """Безопасное объяснение шага без исходных строк."""

    DISABLED = "Правило выключено и пропущено."
    DOMAIN = "Проверено имя с учётом режима точного совпадения или поддоменов."
    DOMAIN_UNAVAILABLE = "По предположению имя недоступно для доменных правил."
    DOMAIN_UNKNOWN = "Видимость доменного имени неизвестна."
    IP = "Проверено вхождение переданных адресов в IP/CIDR."
    IP_UNAVAILABLE = "По предположению адреса недоступны для IP-правил."
    IP_UNKNOWN = "Доступные IP-адреса неизвестны; DNS здесь не выполняется."
    GEODATA = "Использован результат источника для указанного набора и версии базы."
    GEODATA_MISSING = "Источник содержимого геобазы не передан."
    GEODATA_UNKNOWN = "Источник не смог определить членство в наборе геобазы."
    UNSUPPORTED = "Смысл импортированного условия неизвестен."
    FINAL = "Все включённые условия проверены и не совпали; выбрано финальное правило."


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class RoutingContext(_PrivateRepresentation):
    """Один фиксированный снимок доступных имени и адресов.

    UNKNOWN означает недостаток сведений, UNAVAILABLE — явное предположение
    об отсутствии. Для DNS передаётся полный непустой набор результатов.
    Назначение соединения — либо имя, либо IP, поэтому оба источника
    DESTINATION одновременно недопустимы.
    Здесь не моделируются этапы domainStrategy, DNS или работа sniffing.
    """

    domain: str | None = None
    domain_source: DomainSource = DomainSource.UNKNOWN
    ips: tuple[str, ...] | None = None
    ip_source: IPSource = IPSource.UNKNOWN

    def __post_init__(self) -> None:
        if not isinstance(self.domain_source, DomainSource) or not isinstance(self.ip_source, IPSource):
            raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
        if self.domain_source is DomainSource.DESTINATION and self.ip_source is IPSource.DESTINATION:
            raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
        visible = self.domain_source in (DomainSource.DESTINATION, DomainSource.SNIFFING)
        if visible:
            object.__setattr__(self, "domain", DomainCondition(self.domain).value)
        elif self.domain is not None:
            raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
        if self.ip_source is IPSource.UNKNOWN:
            if self.ips is not None:
                raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
            return
        if not isinstance(self.ips, (list, tuple)):
            raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
        if self.ip_source is IPSource.UNAVAILABLE:
            if self.ips:
                raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
        elif not self.ips or (self.ip_source is IPSource.DESTINATION and len(self.ips) != 1):
            raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
        addresses = []
        for value in self.ips:
            if not isinstance(value, str) or "/" in value:
                raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
            addresses.append(IPCondition(value).value)
        object.__setattr__(self, "ips", tuple(addresses))

    def to_diagnostic(self) -> dict[str, str | int | None]:
        """Показать предположения и число адресов, скрыв сами имя и адреса."""
        return {
            "domain_source": self.domain_source.value,
            "ip_source": self.ip_source.value,
            "ip_count": None if self.ips is None else len(self.ips),
        }


_DOMAIN_ASSUMPTIONS = {
    DomainSource.DESTINATION: "Имя назначения считается видимым; подмена через sniffing не моделируется.",
    DomainSource.SNIFFING: "Предполагается, что sniffing предоставил указанное имя для маршрутизации.",
    DomainSource.UNAVAILABLE: "Предполагается отсутствие видимого имени, в том числе из sniffing.",
    DomainSource.UNKNOWN: "Видимость имени назначения и результата sniffing неизвестна.",
}
_IP_ASSUMPTIONS = {
    IPSource.DESTINATION: "Используется переданный IP назначения; DNS не выполняется.",
    IPSource.DNS: "Переданный набор считается полным результатом DNS, доступным всем IP-правилам этого расчёта.",
    IPSource.UNAVAILABLE: "Предполагается отсутствие доступных IP; DNS не выполняется.",
    IPSource.UNKNOWN: "Доступные IP и результат DNS неизвестны; DNS не выполняется.",
}


def context_assumptions(context: RoutingContext) -> tuple[str, ...]:
    """Явно назвать исходные предположения расчёта для контекста, включая DNS и sniffing.

    Текст зависит только от источников контекста: имя и адреса в него не входят.
    Те же строки возвращает `RouteExplanation.assumptions`; функция нужна, когда
    расчёт не выполнялся, например без собранной политики.
    """
    if not isinstance(context, RoutingContext):
        raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
    return (
        "Предварительный статический расчёт не доказывает реальный сетевой путь или доступность VPN.",
        "Правила проверяются за один проход по фиксированным данным; этапы Xray domainStrategy не моделируются.",
        _DOMAIN_ASSUMPTIONS[context.domain_source],
        _IP_ASSUMPTIONS[context.ip_source],
        "Членство в GeoIP/GeoSite и метаданные использованной базы декларирует переданный источник.",
    )


def destination_context(text: str) -> RoutingContext:
    """Собрать контекст из строки назначения: домен, отдельный адрес или домен с адресами через пробел.

    Слова делятся пробельными символами. Каждое слово — отдельный IPv4/IPv6-адрес
    без CIDR, зоны и порта либо домен по правилам `DomainCondition`; домен —
    не больше одного, адресов — не больше `MAX_DESTINATION_ADDRESSES`, вся строка —
    не длиннее `MAX_DESTINATION_LENGTH`. Только домен — имя назначения считается
    видимым, адреса неизвестны; один адрес — адрес назначения, видимость имени
    неизвестна; несколько адресов — полный набор, который считается результатом
    DNS; домен с адресами — видимое имя и адреса как результат DNS. Пустая строка,
    второй домен, CIDR, слово не домен и не адрес и лишние слова дают
    `RoutingValidationError` с кодом `DESTINATION`; сама строка в ошибку не входит.
    DNS и другие сетевые запросы здесь не выполняются.
    """
    if type(text) is not str or len(text) > MAX_DESTINATION_LENGTH:
        raise RoutingValidationError(RoutingErrorCode.DESTINATION) from None
    words = text.split()
    if not words or len(words) > MAX_DESTINATION_ADDRESSES + 1:
        raise RoutingValidationError(RoutingErrorCode.DESTINATION) from None
    domain = None
    addresses: list[str] = []
    for word in words:
        if "/" not in word and _normalize_ip(word) is not None:
            addresses.append(word)
            continue
        if domain is not None or _normalize_domain(word) is None:
            raise RoutingValidationError(RoutingErrorCode.DESTINATION) from None
        domain = word
    if len(addresses) > MAX_DESTINATION_ADDRESSES:
        raise RoutingValidationError(RoutingErrorCode.DESTINATION) from None
    domain_source = DomainSource.UNKNOWN if domain is None else DomainSource.DESTINATION
    if not addresses:
        return RoutingContext(domain=domain, domain_source=domain_source)
    if domain is None and len(addresses) == 1:
        return RoutingContext(ips=tuple(addresses), ip_source=IPSource.DESTINATION)
    return RoutingContext(domain=domain, domain_source=domain_source, ips=tuple(addresses), ip_source=IPSource.DNS)


@dataclass(frozen=True, slots=True, repr=False)
class GeoMatch(_PrivateRepresentation):
    """Ответ доверенного источника с метаданными фактически использованной базы.

    MATCH — хотя бы одно значение входит в набор; NO_MATCH — все проверены
    и не входят. Неполные данные, неизвестный набор или база дают UNKNOWN.
    Версию/хеш декларирует источник; модель не проверяет файл по сети или с диска.
    """

    result: MatchResult
    database: GeoDatabase

    def __post_init__(self) -> None:
        if not isinstance(self.result, MatchResult) or not isinstance(self.database, GeoDatabase):
            raise RoutingValidationError(RoutingErrorCode.GEODATA_RESULT) from None


IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
GeoMatcher = Callable[[GeoIPCondition | GeoSiteCondition, tuple[str, ...]], GeoMatch]


@dataclass(frozen=True, slots=True, repr=False)
class ExplanationStep(_PrivateRepresentation):
    """Проверенное или пропущенное правило; индекс в сохранённом порядке."""

    index: int
    rule: RoutingRule | FinalRoutingRule
    result: MatchResult | None
    reason: ExplanationReason
    database: GeoDatabase | None = None

    def __post_init__(self) -> None:
        if (
            type(self.index) is not int or self.index < 0
            or not isinstance(self.rule, (RoutingRule, FinalRoutingRule))
            or (self.result is not None and not isinstance(self.result, MatchResult))
            or not isinstance(self.reason, ExplanationReason)
            or (self.database is not None and not isinstance(self.database, GeoDatabase))
        ):
            raise RoutingValidationError(RoutingErrorCode.EXPLANATION) from None

    def to_diagnostic(self) -> dict[str, object]:
        """Не включать значения условий, ссылки, источники и версии геобаз."""
        final = isinstance(self.rule, FinalRoutingRule)
        return {
            "index": self.index,
            "condition_type": None if final else type(self.rule.condition).__name__,
            "enabled": None if final else self.rule.enabled,
            "protected": None if final else self.rule.protected,
            "action": self.rule.action.value,
            "result": None if self.result is None else self.result.value,
            "reason": self.reason.value,
            "database_kind": None if self.database is None else self.database.kind.value,
            "database_version_known": self.database is not None and self.database.version is not None,
        }


@dataclass(frozen=True, slots=True, repr=False)
class RouteExplanation(_PrivateRepresentation):
    """Результат расчёта; selection=None при первом неизвестном условии."""

    context: RoutingContext
    steps: tuple[ExplanationStep, ...]
    selection: RoutingSelection | None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.context, RoutingContext)
            or not isinstance(self.steps, (tuple, list))
            or not self.steps
            or any(not isinstance(step, ExplanationStep) for step in self.steps)
            or (self.selection is not None and not isinstance(self.selection, RoutingSelection))
        ):
            raise RoutingValidationError(RoutingErrorCode.EXPLANATION) from None
        object.__setattr__(self, "steps", tuple(self.steps))

    @property
    def assumptions(self) -> tuple[str, ...]:
        """Явно назвать исходные предположения, включая DNS и sniffing."""
        return context_assumptions(self.context)

    def to_diagnostic(self) -> dict[str, object]:
        """Вернуть безопасную трассу и ограничения без произвольных полей."""
        return {
            "preliminary": True,
            "context": self.context.to_diagnostic(),
            "assumptions": list(self.assumptions),
            "steps": [step.to_diagnostic() for step in self.steps],
            "selection": None if self.selection is None else self.selection.to_diagnostic(),
        }


def _match_geodata(
    condition: GeoIPCondition | GeoSiteCondition,
    values: tuple[str, ...],
    matcher: GeoMatcher | None,
) -> tuple[MatchResult, ExplanationReason, GeoDatabase | None]:
    if matcher is None:
        return MatchResult.UNKNOWN, ExplanationReason.GEODATA_MISSING, None
    try:
        evidence = matcher(condition, values)
    except RoutingValidationError:
        # Источник не смог построить корректный ответ модели, например GeoMatch.
        _raise_detached(RoutingErrorCode.GEODATA_RESULT)
    except Exception:
        _raise_detached(RoutingErrorCode.MATCHER)
    if not isinstance(evidence, GeoMatch):
        raise RoutingValidationError(RoutingErrorCode.GEODATA_RESULT) from None
    expected = condition.database
    actual = evidence.database
    # Неизвестные метаданные можно уточнить. Известную ревизию подменять нельзя.
    if expected.kind is not actual.kind or expected.reference != actual.reference or any(
        getattr(expected, field) is not None and getattr(expected, field) != getattr(actual, field)
        for field in ("source", "version", "sha256")
    ):
        raise RoutingValidationError(RoutingErrorCode.GEODATA_MISMATCH) from None
    reason = ExplanationReason.GEODATA_UNKNOWN if evidence.result is MatchResult.UNKNOWN else ExplanationReason.GEODATA
    return evidence.result, reason, actual


def _routable_address(value: str) -> IPAddress:
    """Сопоставлять IPv4-mapped IPv6 с IPv4-сетями, как это делает Xray."""
    address = ipaddress.ip_address(value)
    mapped = getattr(address, "ipv4_mapped", None)
    return address if mapped is None else mapped


def _match_condition(
    condition: RoutingCondition,
    context: RoutingContext,
    addresses: tuple[IPAddress, ...] | None,
    matcher: GeoMatcher | None,
) -> tuple[MatchResult, ExplanationReason, GeoDatabase | None]:
    if isinstance(condition, (UnknownCondition, UnsupportedRuleCondition)):
        return MatchResult.UNKNOWN, ExplanationReason.UNSUPPORTED, None
    if isinstance(condition, (DomainCondition, GeoSiteCondition)):
        if context.domain_source is DomainSource.UNKNOWN:
            return MatchResult.UNKNOWN, ExplanationReason.DOMAIN_UNKNOWN, None
        if context.domain_source is DomainSource.UNAVAILABLE:
            return MatchResult.NO_MATCH, ExplanationReason.DOMAIN_UNAVAILABLE, None
        if isinstance(condition, GeoSiteCondition):
            return _match_geodata(condition, (context.domain,), matcher)
        matches = context.domain == condition.value or (
            condition.mode is DomainMatch.SUBDOMAINS and context.domain.endswith("." + condition.value)
        )
        return (MatchResult.MATCH if matches else MatchResult.NO_MATCH), ExplanationReason.DOMAIN, None
    if context.ip_source is IPSource.UNKNOWN:
        return MatchResult.UNKNOWN, ExplanationReason.IP_UNKNOWN, None
    if context.ip_source is IPSource.UNAVAILABLE:
        return MatchResult.NO_MATCH, ExplanationReason.IP_UNAVAILABLE, None
    if isinstance(condition, GeoIPCondition):
        return _match_geodata(condition, context.ips, matcher)
    network = ipaddress.ip_network(condition.value)
    matches = any(address in network for address in addresses)
    return (MatchResult.MATCH if matches else MatchResult.NO_MATCH), ExplanationReason.IP, None


def explain_route(
    policy: RoutingPolicy, context: RoutingContext, *, geo_matcher: GeoMatcher | None = None,
) -> RouteExplanation:
    """Объяснить первое совпадение либо первую неизвестность без успешного fallback.

    Источник геоданных — доверенный адаптер: обязан использовать переданную
    категорию и вернуть метаданные прочитанной базы. Чистота его I/O не изолируется.
    После остановки более поздние правила и базы не проверяются.
    """
    if not isinstance(policy, RoutingPolicy):
        raise RoutingValidationError(RoutingErrorCode.RULES) from None
    if not isinstance(context, RoutingContext):
        raise RoutingValidationError(RoutingErrorCode.CONTEXT) from None
    if geo_matcher is not None and not callable(geo_matcher):
        raise RoutingValidationError(RoutingErrorCode.MATCHER) from None
    addresses = None if context.ips is None else tuple(_routable_address(value) for value in context.ips)
    steps = []

    def skip(index: int, rule: RoutingRule) -> None:
        steps.append(ExplanationStep(index, rule, None, ExplanationReason.DISABLED))

    def evaluate(index: int, rule: RoutingRule) -> MatchResult:
        result, reason, database = _match_condition(rule.condition, context, addresses, geo_matcher)
        steps.append(ExplanationStep(index, rule, result, reason, database))
        return result

    selection = policy.walk_first_match(evaluate, skip)
    if selection is not None and selection.is_final:
        steps.append(ExplanationStep(selection.index, selection.rule, MatchResult.MATCH, ExplanationReason.FINAL))
    return RouteExplanation(context, tuple(steps), selection)
