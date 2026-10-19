"""Правила маршрутизации вместе с названиями и идентификаторами из метаданных менеджера.

Просмотр читает действующие правила через обработчик импорта схемы и записи
раздела `rules` через порт хранилища метаданных, привязывает записи к правилам
по семантическому ключу и возвращает безопасное представление: позиции,
признаки и длину названия, идентификаторы и причины отсутствия привязки.
Просмотр ничего не записывает. Присвоение идентификаторов — отдельная
команда: она генерирует новые идентификаторы подставляемой фабрикой только
для правил без записи, дописывает записи без названия и пишет раздел один
раз только при изменениях; без новых записей ничего не кодируется и не
пишется, а совпадение канонических байтов записи не вызывает. Xray JSON, `ruleTag`, active configs и роутер не затрагиваются.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar
import uuid

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.manager_metadata import (
    INCONSISTENT, INVALID_STORE_RESULT, read_stored_metadata, store_error_detail,
)
from keenvpn.application.ports import ManagerMetadataStore
from keenvpn.application.routing_import import ImportRoutingSchemeHandler
from keenvpn.application.views import view_dict, view_fields
from keenvpn.domain.manager_metadata import (
    ManagerMetadata, ManagerMetadataError, RuleRecord, StoredManagerMetadata, UnknownFields,
    encode_manager_metadata, metadata_revision,
)
from keenvpn.domain.routing import RoutingValidationError, valid_rule_id
from keenvpn.domain.routing_import import RoutingScheme
from keenvpn.domain.rule_binding import (
    BindingReason, RuleBinding, RuleBindingError, bind_routing_scheme, rule_key,
)


RuleIdFactory = Callable[[], str]


def new_rule_id() -> str:
    """Создать случайный идентификатор правила: UUID в канонической строчной форме."""
    return str(uuid.uuid4())


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectRoutingRules:
    """Прочитать правила вместе с названиями и идентификаторами из метаданных без записи."""

    name: ClassVar[str] = "inspect_routing_rules"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True, kw_only=True)
class AssignRuleIdentifiers:
    """Присвоить идентификаторы правилам без записи и записать раздел `rules` при изменениях."""

    name: ClassVar[str] = "assign_rule_identifiers"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class RuleIdentityView:
    """Правило в порядке схемы: позиция, структура, идентичность и итог привязки.

    `index` — позиция среди правил схемы, `group_index` — индекс правила Xray
    в действующей части, `offset` — позиция внутри его группы. `binding` —
    `bound` либо причина отсутствия привязки. Название скрыто: только
    признак и длина в символах; идентификатор показан после проверки формата.
    """

    index: int
    part: str
    group_index: int
    offset: int
    condition_type: str
    action: str
    read_only: bool
    has_id: bool
    rule_id: str | None
    has_name: bool
    name_length: int | None
    binding: str


@dataclass(frozen=True, slots=True)
class UnboundRecordView:
    """Запись метаданных без правила: идентификатор, признак и длина названия, причина."""

    rule_id: str
    has_name: bool
    name_length: int | None
    reason: str


@dataclass(frozen=True, slots=True)
class RoutingRulesView:
    """Безопасное представление правил с идентичностью из метаданных.

    `record_count` — `None`, если раздел `rules` не записан; `metadata_present`
    — есть ли файл метаданных вообще. Домены, адреса, коды наборов,
    названия и ключи сюда не входят.
    """

    routing_part: str | None
    metadata_present: bool
    scheme_read_only: bool
    policy_present: bool
    rule_count: int
    bound_rule_count: int
    named_rule_count: int
    unbound_rule_count: int
    record_count: int | None
    unbound_record_count: int
    rules: tuple[RuleIdentityView, ...]
    unbound_records: tuple[UnboundRecordView, ...]

    @classmethod
    def from_binding(
        cls, scheme: RoutingScheme, binding: RuleBinding, stored: StoredManagerMetadata | None,
    ) -> "RoutingRulesView":
        """Построить представление из диагностики схемы и привязки."""
        diagnostic = binding.to_diagnostic()
        positions = [
            (group.part, group.index, offset) for group in scheme.groups for offset in range(len(group.rules))
        ]
        rules = tuple(
            RuleIdentityView(**view_fields(
                RuleIdentityView, {**item, "part": part, "group_index": group_index, "offset": offset},
            ))
            for item, (part, group_index, offset) in zip(diagnostic["rules"], positions, strict=True)
        )
        records = None if stored is None else stored.metadata.rules
        return cls(
            routing_part=scheme.routing_part,
            metadata_present=stored is not None,
            scheme_read_only=scheme.read_only,
            policy_present=binding.policy is not None,
            rule_count=diagnostic["rule_count"],
            bound_rule_count=diagnostic["bound_rule_count"],
            named_rule_count=diagnostic["named_rule_count"],
            unbound_rule_count=diagnostic["unbound_rule_count"],
            record_count=None if records is None else len(records),
            unbound_record_count=diagnostic["unbound_record_count"],
            rules=rules,
            unbound_records=tuple(
                UnboundRecordView(**view_fields(UnboundRecordView, item)) for item in diagnostic["unbound_records"]
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            **view_dict(self),
            "rules": [view_dict(item) for item in self.rules],
            "unbound_records": [view_dict(item) for item in self.unbound_records],
        }


class RuleIdentityAssignmentOutcome(StrEnum):
    """Итог успешного присвоения идентификаторов."""

    CREATED = "created"
    """Новые записи добавлены и раздел `rules` записан."""
    UNCHANGED = "unchanged"
    """Все правила уже привязаны или присваивать нечего: ничего не записывалось."""


@dataclass(frozen=True, slots=True)
class RuleIdentityAssignmentView:
    """Итог присвоения, число новых записей и правила после операции."""

    outcome: str
    assigned_count: int
    rules: RoutingRulesView

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {"outcome": self.outcome, "assigned_count": self.assigned_count, "rules": self.rules.to_dict()}


_BINDING_FAILED = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "rule_binding_failed",
    "Не удалось привязать записи метаданных к правилам маршрутизации.",
)
_ID_GENERATION_FAILED = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "rule_id_generation_failed",
    "Фабрика идентификаторов правил вернула некорректный или повторяющийся идентификатор.",
)
_INCONSISTENT_MESSAGE = "Записи правил не удалось объединить с сохранёнными метаданными менеджера."


@dataclass(frozen=True, slots=True)
class _Reading:
    """Схема, прочитанные метаданные и привязка; доверенные модели не покидают модуль."""

    scheme: RoutingScheme
    stored: StoredManagerMetadata | None
    binding: RuleBinding

    @property
    def records(self) -> tuple[RuleRecord, ...]:
        return () if self.stored is None or self.stored.metadata.rules is None else self.stored.metadata.rules


def _read(routing: ImportRoutingSchemeHandler, store: ManagerMetadataStore) -> _Reading | ErrorDetail:
    """Прочитать схему и метаданные по одному разу и привязать записи к правилам."""
    scheme = routing.read()
    if isinstance(scheme, ErrorDetail):
        return scheme
    stored = read_stored_metadata(store)
    if isinstance(stored, ErrorDetail):
        return stored
    records = () if stored is None or stored.metadata.rules is None else stored.metadata.rules
    try:
        binding = bind_routing_scheme(scheme, records)
    except (RuleBindingError, RoutingValidationError, ManagerMetadataError) as error:
        return ErrorDetail(
            _BINDING_FAILED.category, _BINDING_FAILED.code, _BINDING_FAILED.message, reason=error.code.value,
        )
    return _Reading(scheme, stored, binding)


class InspectRoutingRulesHandler:
    """Показать правила с названиями и идентификаторами из метаданных; ничего не записывать.

    Источники Xray и XKeen читаются обработчиком импорта схемы в его порядке
    и с его кодами отказов, метаданные — одним чтением хранилища; отсутствие
    метаданных или раздела `rules` — не отказ. Хранилище не получает запись.
    """

    def __init__(
        self, routing: ImportRoutingSchemeHandler, store: ManagerMetadataStore, *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._routing = routing
        self._store = store
        self._operation_ids = operation_ids

    def execute(self, command: InspectRoutingRules) -> Result[RoutingRulesView]:
        """Выполнить просмотр; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = InspectRoutingRules.name
        if type(command) is not InspectRoutingRules:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        reading = _read(self._routing, self._store)
        if isinstance(reading, ErrorDetail):
            return failed(operation_id, name, reading)
        return succeeded(operation_id, name, RoutingRulesView.from_binding(reading.scheme, reading.binding, reading.stored))


class AssignRuleIdentifiersHandler:
    """Присвоить идентификаторы правилам без записи и записать раздел `rules` при изменениях.

    После того же чтения и привязки, что и у просмотра, каждое правило
    с причиной `record_missing` получает новую запись без названия с ключом
    и идентификатором из фабрики; правила с неоднозначным ключом записей
    не получают, записи без правила сохраняются. Без новых записей операция
    завершается `unchanged` до кодирования: кандидат совпал бы с прочитанной
    моделью по построению, а компактный файл в пределах лимита не должен
    блокировать повтор из-за форматированной копии. Иначе кандидат —
    прочитанные метаданные с дополненным разделом; при совпадении его
    канонических байтов с прочитанным файлом запись не вызывается, иначе
    выполняется одна запись с прочитанной ревизией; ревизию в последний
    момент сверяет хранилище. Без правил, которым нужен идентификатор,
    файл не создаётся.
    """

    def __init__(
        self, routing: ImportRoutingSchemeHandler, store: ManagerMetadataStore, *,
        rule_ids: RuleIdFactory = new_rule_id, operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._routing = routing
        self._store = store
        self._rule_ids = rule_ids
        self._operation_ids = operation_ids

    def execute(self, command: AssignRuleIdentifiers) -> Result[RuleIdentityAssignmentView]:
        """Выполнить присвоение; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = AssignRuleIdentifiers.name
        if type(command) is not AssignRuleIdentifiers:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        reading = _read(self._routing, self._store)
        if isinstance(reading, ErrorDetail):
            return failed(operation_id, name, reading)

        missing = [item for item in reading.binding.rules if item.reason is BindingReason.RECORD_MISSING]
        existing = {record.rule_id for record in reading.records}
        added: list[RuleRecord] = []
        for item in missing:
            try:
                rule_id = self._rule_ids()
            except Exception:
                # Текст исключения фабрики не является безопасным кодом.
                return failed(operation_id, name, _ID_GENERATION_FAILED)
            if not valid_rule_id(rule_id) or rule_id in existing:
                return failed(operation_id, name, _ID_GENERATION_FAILED)
            existing.add(rule_id)
            added.append(RuleRecord(rule_id, None, rule_key(item.rule)))

        stored = reading.stored
        unchanged = RuleIdentityAssignmentView(
            RuleIdentityAssignmentOutcome.UNCHANGED.value, 0,
            RoutingRulesView.from_binding(reading.scheme, reading.binding, stored),
        )
        if not added:
            # Без новых записей кандидат совпадает с прочитанной моделью по построению: ни запись,
            # ни кодирование не нужны, а компактный файл в пределах лимита не блокирует повтор.
            # Без метаданных файл не создаётся.
            return succeeded(operation_id, name, unchanged)
        reason = None
        try:
            candidate = ManagerMetadata(
                storage=None if stored is None else stored.metadata.storage,
                extra=UnknownFields() if stored is None else stored.metadata.extra,
                rules=reading.records + tuple(added),
            )
            content = encode_manager_metadata(candidate)
            current = None if stored is None else encode_manager_metadata(stored.metadata)
        except ManagerMetadataError as error:
            # Например, вместе с прежними неизвестными полями файл превысил бы предел размера.
            reason = error.code.value
        if reason is not None:
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, INCONSISTENT, _INCONSISTENT_MESSAGE, reason=reason,
            ))
        if content == current:
            return succeeded(operation_id, name, unchanged)

        try:
            revision = self._store.write_metadata(candidate, None if stored is None else stored.revision)
        except Exception as error:
            return failed(operation_id, name, store_error_detail(error))
        if type(revision) is not str or revision != metadata_revision(content):
            return failed(operation_id, name, INVALID_STORE_RESULT)
        try:
            binding = bind_routing_scheme(reading.scheme, candidate.rules)
        except (RuleBindingError, RoutingValidationError, ManagerMetadataError) as error:
            return failed(operation_id, name, ErrorDetail(
                _BINDING_FAILED.category, _BINDING_FAILED.code, _BINDING_FAILED.message, reason=error.code.value,
            ))
        written = StoredManagerMetadata(candidate, revision)
        view = RoutingRulesView.from_binding(reading.scheme, binding, written)
        return succeeded(operation_id, name, RuleIdentityAssignmentView(
            RuleIdentityAssignmentOutcome.CREATED.value, len(added), view,
        ))
