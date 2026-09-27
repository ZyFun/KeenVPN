"""Порядок правил и выбор первого совпадения по переданным результатам."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from keenvpn.domain.routing import (
    RoutingAction,
    RoutingCondition,
    RoutingErrorCode,
    RoutingRule,
    RoutingValidationError,
    UnknownCondition,
)


class MatchResult(Enum):
    """Неизвестное совпадение нельзя считать отсутствующим."""

    MATCH = "match"
    NO_MATCH = "no_match"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FinalRoutingRule:
    """Явное действие для остатка трафика, без условия и значения по умолчанию."""

    action: RoutingAction

    def __post_init__(self) -> None:
        if not isinstance(self.action, RoutingAction):
            raise RoutingValidationError(RoutingErrorCode.ACTION) from None


@dataclass(frozen=True, slots=True, repr=False)
class RoutingSelection:
    """Выбранное правило и его индекс в конкретном неизменяемом списке."""

    index: int
    rule: RoutingRule | FinalRoutingRule

    def __post_init__(self) -> None:
        if type(self.index) is not int or self.index < 0:
            raise RoutingValidationError(RoutingErrorCode.POSITION) from None
        if not isinstance(self.rule, (RoutingRule, FinalRoutingRule)):
            raise RoutingValidationError(RoutingErrorCode.RULES) from None

    @property
    def action(self) -> RoutingAction:
        """Получить явное действие выбранного правила."""
        return self.rule.action

    @property
    def is_final(self) -> bool:
        """Показать, выбран ли остаток трафика после всех обычных правил."""
        return isinstance(self.rule, FinalRoutingRule)

    def __repr__(self) -> str:
        return "RoutingSelection(<скрытые параметры>)"

    def to_diagnostic(self) -> dict[str, int | str | bool]:
        """Вернуть позицию и действие без значений условия."""
        return {"index": self.index, "action": self.action.value, "is_final": self.is_final}


@dataclass(frozen=True, slots=True, repr=False)
class RoutingPolicy:
    """Обычные правила в явном порядке и ровно одно финальное в конце.

    Список копируется в tuple. Все операции возвращают новую модель;
    индексы начинаются с нуля. Здесь нет DNS, чтения геобаз или Xray JSON.
    """

    rules: tuple[RoutingRule, ...]
    final_rule: FinalRoutingRule

    def __post_init__(self) -> None:
        if not isinstance(self.rules, (tuple, list)):
            raise RoutingValidationError(RoutingErrorCode.RULES) from None
        rules = tuple(self.rules)
        if any(not isinstance(rule, RoutingRule) for rule in rules):
            raise RoutingValidationError(RoutingErrorCode.RULES) from None
        if not isinstance(self.final_rule, FinalRoutingRule):
            raise RoutingValidationError(RoutingErrorCode.FINAL_RULE) from None
        object.__setattr__(self, "rules", rules)

    def __repr__(self) -> str:
        return "RoutingPolicy(<скрытые параметры>)"

    @property
    def ordered_rules(self) -> tuple[RoutingRule | FinalRoutingRule, ...]:
        """Вернуть полный порядок; финальное правило всегда последнее."""
        return (*self.rules, self.final_rule)

    @property
    def read_only(self) -> bool:
        """Не менять приоритеты, пока смысл импортированного условия неизвестен."""
        return any(rule.read_only for rule in self.rules)

    def to_diagnostic(self) -> dict[str, int | str | bool]:
        """Вернуть только число правил, финальное действие и ограничение редактирования."""
        return {
            "rule_count": len(self.rules),
            "final_action": self.final_rule.action.value,
            "read_only": self.read_only,
        }

    def _require_editable(self) -> None:
        if self.read_only:
            raise RoutingValidationError(RoutingErrorCode.READ_ONLY) from None

    def _validate_index(self, index: int, *, insertion: bool = False) -> None:
        limit = len(self.rules) + int(insertion)
        if type(index) is not int or not 0 <= index < limit:
            raise RoutingValidationError(RoutingErrorCode.POSITION) from None

    def insert(self, index: int, rule: RoutingRule) -> "RoutingPolicy":
        """Вставить правило перед индексом; len(rules) означает перед финальным."""
        self._require_editable()
        self._validate_index(index, insertion=True)
        return RoutingPolicy(self.rules[:index] + (rule,) + self.rules[index:], self.final_rule)

    def move(self, source_index: int, target_index: int) -> "RoutingPolicy":
        """Переместить обычное правило на итоговый индекс, сохранив порядок остальных."""
        self._require_editable()
        self._validate_index(source_index)
        self._validate_index(target_index)
        rules = list(self.rules)
        rule = rules.pop(source_index)
        rules.insert(target_index, rule)
        return RoutingPolicy(tuple(rules), self.final_rule)

    def remove(self, index: int) -> "RoutingPolicy":
        """Удалить обычное правило; индекс финального недопустим."""
        self._require_editable()
        self._validate_index(index)
        return RoutingPolicy(self.rules[:index] + self.rules[index + 1:], self.final_rule)

    def with_final_action(self, action: RoutingAction) -> "RoutingPolicy":
        """Явно сменить финальное действие без изменения порядка условий."""
        self._require_editable()
        return RoutingPolicy(self.rules, FinalRoutingRule(action))

    def select_first(
        self, matcher: Callable[[RoutingCondition], MatchResult]
    ) -> RoutingSelection:
        """Выбрать первое совпадение; неизвестность и ошибка останавливают выбор.

        matcher — доверенный источник результатов для одного набора входных
        данных. Модель не проверяет его достоверность или отсутствие I/O.
        Неизвестные импортированные условия ему не передаются.
        """
        if not callable(matcher):
            raise RoutingValidationError(RoutingErrorCode.MATCHER) from None
        for index, rule in enumerate(self.rules):
            if isinstance(rule.condition, UnknownCondition):
                raise RoutingValidationError(RoutingErrorCode.MATCH_UNKNOWN) from None
            try:
                result = matcher(rule.condition)
            except Exception:
                # Текст ошибки источника может содержать приватное условие.
                raise RoutingValidationError(RoutingErrorCode.MATCHER) from None
            if not isinstance(result, MatchResult):
                raise RoutingValidationError(RoutingErrorCode.MATCH_RESULT) from None
            if result is MatchResult.UNKNOWN:
                raise RoutingValidationError(RoutingErrorCode.MATCH_UNKNOWN) from None
            if result is MatchResult.MATCH:
                return RoutingSelection(index, rule)
        return RoutingSelection(len(self.rules), self.final_rule)
