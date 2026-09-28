"""Порядок правил и выбор первого совпадения по переданным результатам."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum

from keenvpn.domain.routing import (
    RoutingAction,
    RoutingCondition,
    RoutingErrorCode,
    RoutingRule,
    RoutingValidationError,
    UnknownCondition,
    _raise_detached,
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
        user_rule_seen = False
        for rule in rules:
            if rule.protected and user_rule_seen:
                raise RoutingValidationError(RoutingErrorCode.PROTECTED_ORDER) from None
            if not rule.protected:
                user_rule_seen = True
        object.__setattr__(self, "rules", rules)

    def __repr__(self) -> str:
        return "RoutingPolicy(<скрытые параметры>)"

    @property
    def ordered_rules(self) -> tuple[RoutingRule | FinalRoutingRule, ...]:
        """Вернуть сохранённый порядок, включая отключённые; финальное последнее."""
        return (*self.rules, self.final_rule)

    @property
    def active_rules(self) -> tuple[RoutingRule | FinalRoutingRule, ...]:
        """Исключить отключённые из активного списка, сохранив порядок и финальное.

        Это доменные объекты в памяти, не Xray JSON и не разрешение на применение.
        Неизвестные включённые условия сохраняются без подмены.
        """
        return (*tuple(rule for rule in self.rules if rule.enabled), self.final_rule)

    @property
    def protected_rule_count(self) -> int:
        """Получить длину закреплённого служебного блока в начале списка."""
        return sum(rule.protected for rule in self.rules)

    @property
    def read_only(self) -> bool:
        """Не менять приоритеты, пока смысл импортированного условия неизвестен."""
        return any(rule.read_only for rule in self.rules)

    def to_diagnostic(self) -> dict[str, int | str | bool]:
        """Вернуть только число правил, финальное действие и ограничение редактирования."""
        return {
            "rule_count": len(self.rules),
            "active_rule_count": sum(rule.enabled for rule in self.rules),
            "protected_rule_count": self.protected_rule_count,
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
        """Вставить пользовательское правило после служебного блока и до финального."""
        self._require_editable()
        self._validate_index(index, insertion=True)
        if not isinstance(rule, RoutingRule):
            raise RoutingValidationError(RoutingErrorCode.RULES) from None
        if rule.protected:
            raise RoutingValidationError(RoutingErrorCode.PROTECTED_RULE) from None
        if index < self.protected_rule_count:
            raise RoutingValidationError(RoutingErrorCode.PROTECTED_ORDER) from None
        return RoutingPolicy(self.rules[:index] + (rule,) + self.rules[index:], self.final_rule)

    def move(self, source_index: int, target_index: int) -> "RoutingPolicy":
        """Переместить обычное правило на итоговый индекс, сохранив порядок остальных."""
        self._require_editable()
        self._validate_index(source_index)
        self._validate_index(target_index)
        if self.rules[source_index].protected:
            raise RoutingValidationError(RoutingErrorCode.PROTECTED_RULE) from None
        if target_index < self.protected_rule_count:
            raise RoutingValidationError(RoutingErrorCode.PROTECTED_ORDER) from None
        rules = list(self.rules)
        rule = rules.pop(source_index)
        rules.insert(target_index, rule)
        return RoutingPolicy(tuple(rules), self.final_rule)

    def remove(self, index: int) -> "RoutingPolicy":
        """Удалить обычное правило; индекс финального недопустим."""
        self._require_editable()
        self._validate_index(index)
        if self.rules[index].protected:
            raise RoutingValidationError(RoutingErrorCode.PROTECTED_RULE) from None
        return RoutingPolicy(self.rules[:index] + self.rules[index + 1:], self.final_rule)

    def with_enabled(self, index: int, enabled: bool) -> "RoutingPolicy":
        """Явно переключить пользовательское правило в его сохранённой позиции."""
        self._require_editable()
        self._validate_index(index)
        if type(enabled) is not bool:
            raise RoutingValidationError(RoutingErrorCode.RULE_STATE) from None
        if self.rules[index].protected:
            raise RoutingValidationError(RoutingErrorCode.PROTECTED_RULE) from None
        changed = replace(self.rules[index], enabled=enabled)
        return RoutingPolicy(self.rules[:index] + (changed,) + self.rules[index + 1:], self.final_rule)

    def with_final_action(self, action: RoutingAction) -> "RoutingPolicy":
        """Явно сменить финальное действие без изменения порядка условий."""
        self._require_editable()
        return RoutingPolicy(self.rules, FinalRoutingRule(action))

    def walk_first_match(
        self,
        evaluate: Callable[[int, RoutingRule], MatchResult],
        skip: Callable[[int, RoutingRule], None] | None = None,
    ) -> RoutingSelection | None:
        """Обойти сохранённый порядок до первого совпадения или неизвестности.

        evaluate получает только включённые правила, skip — отключённые.
        None означает остановку на первом UNKNOWN; финальное правило
        выбирается, только если все включённые условия заведомо не совпали.
        """
        for index, rule in enumerate(self.rules):
            if not rule.enabled:
                if skip is not None:
                    skip(index, rule)
                continue
            result = evaluate(index, rule)
            if not isinstance(result, MatchResult):
                raise RoutingValidationError(RoutingErrorCode.MATCH_RESULT) from None
            if result is MatchResult.UNKNOWN:
                return None
            if result is MatchResult.MATCH:
                return RoutingSelection(index, rule)
        return RoutingSelection(len(self.rules), self.final_rule)

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

        def evaluate(index: int, rule: RoutingRule) -> MatchResult:
            if isinstance(rule.condition, UnknownCondition):
                raise RoutingValidationError(RoutingErrorCode.MATCH_UNKNOWN) from None
            try:
                return matcher(rule.condition)
            except Exception:
                _raise_detached(RoutingErrorCode.MATCHER)

        selection = self.walk_first_match(evaluate)
        if selection is None:
            raise RoutingValidationError(RoutingErrorCode.MATCH_UNKNOWN) from None
        return selection
