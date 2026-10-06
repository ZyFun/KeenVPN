"""Определение ID политики Keenetic по действующему списку без записи и выбора по умолчанию."""

from dataclasses import KW_ONLY, dataclass
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import KeeneticPolicySource
from keenvpn.domain.keenetic_policy import (
    KeeneticPolicyError, KeeneticPolicyErrorCode, KeeneticPolicySet, PolicyResolution,
    resolve_policy, validate_policy_description, validate_policy_id, validate_policy_set,
)


@dataclass(frozen=True, slots=True, repr=False)
class ResolveKeeneticPolicy:
    """Найти ID политики по описанию; выбор среди совпавших — только явный.

    `selected_policy_id` передаётся после исхода `ambiguous` и принимается
    только из текущих кандидатов. Описание считается приватным значением.
    """

    name: ClassVar[str] = "resolve_keenetic_policy"

    description: str
    _: KW_ONLY
    selected_policy_id: str | None = None
    contract_version: int = CONTRACT_VERSION

    def __repr__(self) -> str:
        return "ResolveKeeneticPolicy(<скрыто>)"


@dataclass(frozen=True, slots=True)
class KeeneticPolicyResolutionView:
    """Исход поиска, ID и счётчики без описаний политик.

    `policy_id` заполнен только при `outcome == "resolved"`. `missing`
    означает отсутствие политики с таким описанием, `ambiguous` — несколько
    совпадений, из которых сценарий не выбирает первую.
    """

    outcome: str
    policy_id: str | None
    candidates: tuple[str, ...]
    policy_count: int
    selected_by_user: bool

    @classmethod
    def from_resolution(cls, resolution: PolicyResolution) -> "KeeneticPolicyResolutionView":
        """Построить представление из безопасной диагностики домена."""
        diagnostic = resolution.to_diagnostic()
        return cls(
            outcome=diagnostic["outcome"],
            policy_id=diagnostic["policy_id"],
            candidates=tuple(diagnostic["candidates"]),
            policy_count=diagnostic["policy_count"],
            selected_by_user=diagnostic["selected_by_user"],
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "outcome": self.outcome,
            "policy_id": self.policy_id,
            "candidates": list(self.candidates),
            "policy_count": self.policy_count,
            "selected_by_user": self.selected_by_user,
        }


def _well_typed(command: object) -> bool:
    """Проверить типы полей: аннотации dataclass при создании не проверяются."""
    return (
        type(command) is ResolveKeeneticPolicy
        and type(command.description) is str
        and (command.selected_policy_id is None or type(command.selected_policy_id) is str)
    )


def check_policies(policies: object) -> ErrorDetail | None:
    """Проверить ответ источника политик до его использования любым сценарием."""
    if type(policies) is not KeeneticPolicySet:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_keenetic_policies",
            "Источник вернул политики Keenetic в неподдерживаемом формате.",
        )
    try:
        # Повторная проверка ловит данные, изменённые после создания модели.
        validate_policy_set(policies)
    except KeeneticPolicyError as error:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_keenetic_policies",
            "Источник вернул некорректный список политик Keenetic.", reason=error.code.value,
        )
    except Exception:
        return ErrorDetail(
            ErrorCategory.INVALID_SOURCE_DATA, "invalid_keenetic_policies",
            "Источник вернул политики Keenetic в неподдерживаемом формате.",
        )
    return None


class ResolveKeeneticPolicyHandler:
    """Определить ID по текущему списку источника без изменения политик.

    Отсутствие и неоднозначность возвращаются как исход в данных: это
    состояние роутера, а не отказ сценария. ID по умолчанию не подставляется.
    """

    def __init__(
        self, policies: KeeneticPolicySource, *, operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._policies = policies
        self._operation_ids = operation_ids

    def execute(self, command: ResolveKeeneticPolicy) -> Result[KeeneticPolicyResolutionView]:
        """Один запрос к источнику только для корректной команды."""
        operation_id = self._operation_ids()
        name = ResolveKeeneticPolicy.name
        if not _well_typed(command):
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        try:
            validate_policy_description(command.description)
            if command.selected_policy_id is not None:
                validate_policy_id(command.selected_policy_id)
        except KeeneticPolicyError as invalid:
            return failed(operation_id, name, ErrorDetail(ErrorCategory.INVALID_INPUT, invalid.code.value, str(invalid)))

        try:
            policies = self._policies.current_policies()
        except Exception:
            # Текст и цепочка исключения адаптера могут содержать описания политик.
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.SOURCE_FAILED, "keenetic_policies_unavailable",
                "Не удалось прочитать политики Keenetic.",
            ))
        error = check_policies(policies)
        if error is not None:
            return failed(operation_id, name, error)

        try:
            resolution = resolve_policy(
                policies, command.description, selected_policy_id=command.selected_policy_id,
            )
        except KeeneticPolicyError as rejected:
            if rejected.code is KeeneticPolicyErrorCode.SELECTION_MISMATCH:
                return failed(operation_id, name, ErrorDetail(
                    ErrorCategory.INVALID_INPUT, rejected.code.value, str(rejected),
                ))
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, "invalid_keenetic_policies",
                "Источник вернул некорректный список политик Keenetic.", reason=rejected.code.value,
            ))
        return succeeded(operation_id, name, KeeneticPolicyResolutionView.from_resolution(resolution))
