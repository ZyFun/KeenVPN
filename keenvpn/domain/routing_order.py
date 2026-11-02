"""Статические пересечения условий в сохранённом порядке правил Xray."""

from dataclasses import dataclass
from enum import StrEnum
import ipaddress

from keenvpn.domain.routing import DomainCondition, DomainMatch, GeoIPCondition, GeoSiteCondition, IPCondition
from keenvpn.domain.routing_import import RoutingScheme


class OverlapKind(StrEnum):
    """Доказанное покрытие условия, частичное пересечение или возможное влияние геобазы."""

    COVERED = "condition_covered"
    PARTIAL = "conditions_intersect"
    GEO = "earlier_geo_rule"


@dataclass(frozen=True, slots=True)
class RuleOverlap:
    """Позиции в действующем routing.rules с нуля, без значений условий."""

    earlier: int
    later: int
    kind: OverlapKind

    def to_dict(self) -> dict[str, object]:
        return {"earlier": self.earlier, "later": self.later, "reason": self.kind.value}


def _domain_covers(first: DomainCondition, second: DomainCondition) -> bool:
    if first.mode is DomainMatch.EXACT:
        return second.mode is DomainMatch.EXACT and first.value == second.value
    return first.value == second.value or second.value.endswith("." + first.value)


def _overlap(first, second) -> OverlapKind | None:
    if isinstance(first, DomainCondition) and isinstance(second, DomainCondition):
        if _domain_covers(first, second):
            return OverlapKind.COVERED
        if _domain_covers(second, first):
            return OverlapKind.PARTIAL
    elif isinstance(first, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and type(first) is type(second):
        if second.subnet_of(first):
            return OverlapKind.COVERED
        if first.subnet_of(second):
            return OverlapKind.PARTIAL
    elif isinstance(first, (GeoSiteCondition, GeoIPCondition)):
        if (
            type(first) is type(second) and first.database == second.database
            and first.set_name.upper() == second.set_name.upper()
        ):
            return OverlapKind.COVERED
        return OverlapKind.GEO
    return None


def rule_overlaps(scheme: RoutingScheme) -> tuple[tuple[RuleOverlap, ...], bool]:
    """Проверить пары условий. При исчерпании бюджета вернуть найденное и признак неполноты.

    Условия одного правила объединены через ИЛИ: повтор внутри группы тоже
    избыточен. Предупреждение относится к условию, а не ко всему правилу.
    """
    previous = []
    warnings: dict[RuleOverlap, None] = {}
    remaining = 50_000
    for group in scheme.groups:
        if group.api_service:
            continue
        for condition in group.conditions:
            if not isinstance(condition, (DomainCondition, IPCondition, GeoSiteCondition, GeoIPCondition)):
                continue
            value = ipaddress.ip_network(condition.value) if isinstance(condition, IPCondition) else condition
            for index, earlier in previous:
                if not remaining:
                    return tuple(warnings), False
                remaining -= 1
                kind = _overlap(earlier, value)
                if index == group.index and kind is OverlapKind.PARTIAL:
                    kind = OverlapKind.COVERED
                if kind is not None and (index != group.index or kind is not OverlapKind.GEO):
                    warnings[RuleOverlap(index, group.index, kind)] = None
            previous.append((group.index, value))
    return tuple(warnings), True
