"""Политики Keenetic и определение ID по действующему списку, без RCI и записи.

ID политики (`Policy2`, в RCI — поле `name`) задаёт роутер и на другой
установке он иной, поэтому в код не зашивается. Описание — метка, которую
видит пользователь (`xkeen`); по ней ID находят в текущем списке. Модели
работают в памяти: не читают роутер, не создают и не удаляют политики.
"""

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import NoReturn
import unicodedata


POLICY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
"""Технический идентификатор без пробелов и управляющих символов."""

MAX_DESCRIPTION_LENGTH = 256
_FORBIDDEN_DESCRIPTION_CATEGORIES = frozenset({"Cc", "Cs", "Co", "Zl", "Zp"})


class KeeneticPolicyErrorCode(StrEnum):
    """Причины отказа без исходных значений политик."""

    POLICY_ID = "invalid_policy_id"
    DESCRIPTION = "invalid_policy_description"
    POLICY = "invalid_policy"
    POLICIES = "invalid_policies"
    DUPLICATE_POLICY_ID = "duplicate_policy_id"
    RESOLUTION = "invalid_policy_resolution"
    SELECTION_MISMATCH = "policy_selection_mismatch"


_MESSAGES = {
    KeeneticPolicyErrorCode.POLICY_ID: "Идентификатор политики имеет недопустимый формат.",
    KeeneticPolicyErrorCode.DESCRIPTION: "Описание политики для поиска имеет недопустимый формат.",
    KeeneticPolicyErrorCode.POLICY: "Политика должна быть моделью KeeneticPolicy.",
    KeeneticPolicyErrorCode.POLICIES: "Список политик должен быть кортежем моделей KeeneticPolicy.",
    KeeneticPolicyErrorCode.DUPLICATE_POLICY_ID: "Идентификаторы политик должны быть уникальными.",
    KeeneticPolicyErrorCode.RESOLUTION: "Результат определения политики противоречив.",
    KeeneticPolicyErrorCode.SELECTION_MISMATCH: (
        "Выбранная политика не входит в текущие политики с указанным описанием."
    ),
}


class KeeneticPolicyError(ValueError):
    """Ошибка модели политик с безопасным машинным кодом и заданным текстом."""

    def __init__(self, code: KeeneticPolicyErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _raise_detached(code: KeeneticPolicyErrorCode) -> NoReturn:
    """Отделить отказ от активного исключения без изменения чужих кадров.

    from None скрывает печать цепочки, но сохраняет __context__. Очистка
    после первого raise и bare raise не связывают ошибку с ним повторно.
    """
    try:
        raise KeeneticPolicyError(code) from None
    except KeeneticPolicyError as error:
        error.__context__ = None
        raise


def valid_policy_id(value: object) -> bool:
    """Проверить формат ID политики без преобразований."""
    return type(value) is str and POLICY_ID_PATTERN.fullmatch(value) is not None


def validate_policy_id(value: object) -> None:
    """Отклонить ID недопустимого формата."""
    if not valid_policy_id(value):
        _raise_detached(KeeneticPolicyErrorCode.POLICY_ID)


def validate_policy_description(value: object) -> None:
    """Проверить описание, по которому ищут политику.

    Непустая строка до 256 символов без управляющих символов, суррогатов,
    символов частного использования и разделителей строк. Регистр и пробелы
    не нормализуются: сравнение с описаниями роутера точное.
    """
    if (
        type(value) is not str or not value.strip() or len(value) > MAX_DESCRIPTION_LENGTH
        or any(unicodedata.category(char) in _FORBIDDEN_DESCRIPTION_CATEGORIES for char in value)
    ):
        _raise_detached(KeeneticPolicyErrorCode.DESCRIPTION)


@dataclass(frozen=True, slots=True, repr=False)
class KeeneticPolicy:
    """Политика из действующего списка: технический ID и описание-метка.

    Описание задаёт пользователь роутера и оно может содержать личные
    данные, поэтому скрывается в repr и не входит в безопасные результаты.
    Разрешённые подключения и прочие поля RCI сюда не переносятся: модель
    служит для чтения и сопоставления, а не для записи политики.
    """

    policy_id: str
    description: str | None = None

    def __post_init__(self) -> None:
        validate_policy(self)

    def __repr__(self) -> str:
        return "KeeneticPolicy(<скрыто>)"


def validate_policy(policy: KeeneticPolicy) -> None:
    """Проверить поля политики без нормализации и изменения объекта."""
    validate_policy_id(policy.policy_id)
    if policy.description is not None and type(policy.description) is not str:
        _raise_detached(KeeneticPolicyErrorCode.DESCRIPTION)


@dataclass(frozen=True, slots=True, repr=False)
class KeeneticPolicySet:
    """Действующий список политик в порядке источника с уникальными ID.

    Список копируется в tuple. Пустой список допустим: отсутствие политик —
    состояние роутера, которое определение ID сообщит как отсутствие.
    """

    policies: tuple[KeeneticPolicy, ...]

    def __post_init__(self) -> None:
        if isinstance(self.policies, list):
            object.__setattr__(self, "policies", tuple(self.policies))
        validate_policy_set(self)

    def __len__(self) -> int:
        return len(self.policies)

    @property
    def policy_ids(self) -> tuple[str, ...]:
        """Вернуть ID в порядке источника."""
        return tuple(policy.policy_id for policy in self.policies)

    def __repr__(self) -> str:
        return f"KeeneticPolicySet(policies={len(self.policies)})"


def validate_policy_set(policies: KeeneticPolicySet) -> None:
    """Проверить готовый список без вызова хуков создания и изменения полей.

    Принимаются только точные экземпляры KeeneticPolicy: методы подклассов
    не участвуют в сопоставлении, а их поля могли измениться после создания.
    """
    if type(policies.policies) is not tuple:
        _raise_detached(KeeneticPolicyErrorCode.POLICIES)
    seen: set[str] = set()
    for policy in policies.policies:
        if type(policy) is not KeeneticPolicy:
            _raise_detached(KeeneticPolicyErrorCode.POLICY)
        validate_policy(policy)
        if policy.policy_id in seen:
            _raise_detached(KeeneticPolicyErrorCode.DUPLICATE_POLICY_ID)
        seen.add(policy.policy_id)


class PolicyResolutionOutcome(StrEnum):
    """Итог поиска; ID есть только у RESOLVED."""

    RESOLVED = "resolved"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True, repr=False)
class PolicyResolution:
    """Результат определения ID по описанию в конкретном списке политик.

    `candidates` — ID всех политик с точно совпавшим описанием в порядке
    источника. При AMBIGUOUS их две и больше, `policy_id` пуст: выбор
    остаётся за пользователем. `selected_by_user` отмечает, что ID подтверждён
    явным выбором, а не единственным совпадением.
    """

    outcome: PolicyResolutionOutcome
    policy_id: str | None
    candidates: tuple[str, ...]
    policy_count: int
    selected_by_user: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.outcome, PolicyResolutionOutcome)
            or type(self.candidates) is not tuple or not all(valid_policy_id(value) for value in self.candidates)
            or len(set(self.candidates)) != len(self.candidates)
            or type(self.policy_count) is not int or self.policy_count < len(self.candidates)
            or type(self.selected_by_user) is not bool
        ):
            _raise_detached(KeeneticPolicyErrorCode.RESOLUTION)
        if self.outcome is PolicyResolutionOutcome.RESOLVED:
            consistent = valid_policy_id(self.policy_id) and self.policy_id in self.candidates and (
                self.selected_by_user or len(self.candidates) == 1
            )
        elif self.outcome is PolicyResolutionOutcome.MISSING:
            consistent = self.policy_id is None and not self.candidates and not self.selected_by_user
        else:
            consistent = self.policy_id is None and len(self.candidates) >= 2 and not self.selected_by_user
        if not consistent:
            _raise_detached(KeeneticPolicyErrorCode.RESOLUTION)

    @property
    def resolved(self) -> bool:
        """Показать, определён ли ровно один ID."""
        return self.outcome is PolicyResolutionOutcome.RESOLVED

    def __repr__(self) -> str:
        return f"PolicyResolution(outcome={self.outcome.value}, candidates={len(self.candidates)})"

    def to_diagnostic(self) -> dict[str, object]:
        """Вернуть итог без описаний: только исход, ID и счётчики."""
        return {
            "outcome": self.outcome.value,
            "policy_id": self.policy_id,
            "candidates": list(self.candidates),
            "policy_count": self.policy_count,
            "selected_by_user": self.selected_by_user,
        }


def resolve_policy(
    policies: KeeneticPolicySet, description: str, *, selected_policy_id: str | None = None,
) -> PolicyResolution:
    """Найти ID политики по точному совпадению описания в текущем списке.

    Одно совпадение даёт RESOLVED, ни одного — MISSING, несколько — AMBIGUOUS
    без выбора первой. Явный `selected_policy_id` принимается только из числа
    совпавших: иначе SELECTION_MISMATCH, чтобы устаревший или чужой выбор
    не привязал другую политику. При отсутствии совпадений выбор не рассматривается.
    """
    if type(policies) is not KeeneticPolicySet:
        _raise_detached(KeeneticPolicyErrorCode.POLICIES)
    validate_policy_description(description)
    if selected_policy_id is not None:
        validate_policy_id(selected_policy_id)
    candidates = tuple(policy.policy_id for policy in policies.policies if policy.description == description)
    count = len(policies.policies)
    if not candidates:
        return PolicyResolution(PolicyResolutionOutcome.MISSING, None, (), count)
    if selected_policy_id is not None:
        if selected_policy_id not in candidates:
            _raise_detached(KeeneticPolicyErrorCode.SELECTION_MISMATCH)
        return PolicyResolution(PolicyResolutionOutcome.RESOLVED, selected_policy_id, candidates, count, True)
    if len(candidates) == 1:
        return PolicyResolution(PolicyResolutionOutcome.RESOLVED, candidates[0], candidates, count)
    return PolicyResolution(PolicyResolutionOutcome.AMBIGUOUS, None, candidates, count)
