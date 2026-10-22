"""Правила маршрутизации вместе с названиями и идентификаторами из метаданных менеджера.

Просмотр читает действующие правила через обработчик импорта схемы и записи
раздела `rules` через порт хранилища метаданных, привязывает записи к правилам
по семантическому ключу и возвращает безопасное представление: позиции,
признаки и длину названия, идентификаторы и причины отсутствия привязки.
Просмотр ничего не записывает. Присвоение идентификаторов — отдельная
команда: она генерирует новые идентификаторы подставляемой фабрикой только
для правил без записи, дописывает записи без названия и пишет раздел один
раз только при изменениях; без новых записей ничего не кодируется и не
пишется, а совпадение канонических байтов записи не вызывает. Список
правил для меню — третья, тоже читающая команда: она показывает группы
правил в фактическом порядке действующего раздела `routing` вместе
с идентичностью из метаданных, когда они доступны, а отказ или отсутствие
хранилища не отказывает всему списку. Xray JSON, `ruleTag`, active configs и роутер не затрагиваются.
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
from keenvpn.application.proxy_config import XrayConfigView, XrayPositionView, XrayRuleView
from keenvpn.application.routing_import import ImportRoutingSchemeHandler, RoutingSchemeView
from keenvpn.application.views import view_dict, view_fields
from keenvpn.domain.manager_metadata import (
    ManagerMetadata, ManagerMetadataError, RuleRecord, StoredManagerMetadata, UnknownFields,
    encode_manager_metadata, metadata_revision,
)
from keenvpn.domain.routing import RoutingValidationError, valid_rule_id, valid_rule_name
from keenvpn.domain.routing_import import RoutingScheme
from keenvpn.domain.rule_binding import (
    BindingReason, RuleBinding, RuleBindingError, RuleBindingErrorCode, bind_routing_scheme, rule_key,
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


@dataclass(frozen=True, slots=True, kw_only=True)
class ListRoutingRules:
    """Показать группы правил в фактическом порядке с названиями и идентификаторами, когда они доступны."""

    name: ClassVar[str] = "list_routing_rules"

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


class MetadataState(StrEnum):
    """Доступность метаданных менеджера для списка правил."""

    NOT_CONNECTED = "not_connected"
    """Хранилище при сборке не подключено: названия и идентификаторы не читались."""
    ABSENT = "absent"
    """Хранилище подключено, файла метаданных нет: идентификаторы ещё не присвоены."""
    PRESENT = "present"
    """Метаданные прочитаны; раздел `rules` может отсутствовать."""
    FAILED = "failed"
    """Хранилище отказало или ответило не по контракту: список показан без идентичности."""


class TargetPositionState(StrEnum):
    """Как структурная сводка определила позицию назначения правила."""

    RESOLVED = "resolved"
    """Тег носит ровно один outbound или балансировщик среди всех частей."""
    AMBIGUOUS = "ambiguous"
    """Тег найден, но повторяется: позиция не выбирается по первому."""
    UNRESOLVED = "unresolved"
    """Тег не найден ни в одной части."""
    ABSENT = "absent"
    """У правила нет ни `outboundTag`, ни `balancerTag`."""
    UNSUPPORTED = "unsupported"
    """Заданы оба тега: сводка не разрешает выбор одного из них."""
    UNAVAILABLE = "unavailable"
    """Сводка не описывает это правило, например правило не объект."""


_BOUND = "bound"


@dataclass(frozen=True, slots=True)
class RuleListEntryView:
    """Правило модели внутри группы: позиция, структура, идентификатор, название и итог привязки.

    `index` — позиция среди правил схемы, `offset` — внутри группы. Название
    показывается как есть после проверки `valid_rule_name`: это пользовательский
    текст, интерфейс выводит его только через свой фильтр. Идентификатор показан
    после проверки формата.
    """

    index: int
    offset: int
    condition_type: str
    action: str
    read_only: bool
    has_id: bool
    rule_id: str | None
    has_name: bool
    name: str | None
    binding: str

    def __post_init__(self) -> None:
        if (
            type(self.index) is not int or self.index < 0 or type(self.offset) is not int or self.offset < 0
            or type(self.condition_type) is not str or type(self.action) is not str or type(self.read_only) is not bool
            or type(self.has_id) is not bool or self.has_id != (self.rule_id is not None)
            or (self.rule_id is not None and not valid_rule_id(self.rule_id))
            or type(self.has_name) is not bool or self.has_name != (self.name is not None)
            or (self.name is not None and not valid_rule_name(self.name))
            or type(self.binding) is not str
            or (self.binding == _BOUND) != self.has_id
        ):
            raise TypeError("Некорректное описание правила в списке правил.")


@dataclass(frozen=True, slots=True)
class RuleGroupIdentityView:
    """Группа правила Xray: число правил модели, позиция назначения и правила с идентичностью.

    `index` — индекс правила Xray в действующей части, как у группы схемы.
    `rules` — `None`, когда метаданные недоступны: тогда ни одно правило
    не помечается ни привязанным, ни непривязанным.
    """

    index: int
    rule_count: int
    target_position_state: TargetPositionState
    target_position: XrayPositionView | None
    rules: tuple[RuleListEntryView, ...] | None

    def __post_init__(self) -> None:
        if (
            type(self.index) is not int or self.index < 0 or type(self.rule_count) is not int or self.rule_count < 0
            or type(self.target_position_state) is not TargetPositionState
            or not (self.target_position is None or type(self.target_position) is XrayPositionView)
            or (self.target_position is not None) != (self.target_position_state is TargetPositionState.RESOLVED)
            or not (self.rules is None or (
                type(self.rules) is tuple and len(self.rules) == self.rule_count
                and all(type(item) is RuleListEntryView and item.offset == offset for offset, item in enumerate(self.rules))
            ))
        ):
            raise TypeError("Некорректное описание группы в списке правил.")


@dataclass(frozen=True, slots=True)
class RuleIdentitySummaryView:
    """Счётчики привязки: правила с записью, с названием, без привязки, записи раздела и записи без правила."""

    bound_rule_count: int
    named_rule_count: int
    unbound_rule_count: int
    record_count: int | None
    unbound_record_count: int

    def __post_init__(self) -> None:
        counts = (self.bound_rule_count, self.named_rule_count, self.unbound_rule_count, self.unbound_record_count)
        if (
            any(type(value) is not int or value < 0 for value in counts)
            or not (self.record_count is None or (type(self.record_count) is int and self.record_count >= 0))
            or self.named_rule_count > self.bound_rule_count
        ):
            raise TypeError("Некорректные счётчики идентичности правил.")


_IDENTITY_STATES = frozenset({MetadataState.ABSENT, MetadataState.PRESENT})


@dataclass(frozen=True, slots=True)
class RuleListView:
    """Группы правил в фактическом порядке с идентичностью из метаданных, когда она доступна.

    `scheme` — безопасное представление схемы импорта; `groups` идут в том же
    порядке. `identity` и `rules` групп есть только при прочитанных метаданных
    (`absent` или `present`); при `failed` `metadata_error` описывает отказ
    хранилища с безопасным следующим шагом, при `not_connected` отказа нет.
    Домены, адреса, коды наборов и ключи записей сюда не входят.
    """

    scheme: RoutingSchemeView
    metadata_state: MetadataState
    metadata_error: ErrorDetail | None
    identity: RuleIdentitySummaryView | None
    groups: tuple[RuleGroupIdentityView, ...]

    def __post_init__(self) -> None:
        bound = self.metadata_state in _IDENTITY_STATES
        if (
            type(self.scheme) is not RoutingSchemeView or type(self.metadata_state) is not MetadataState
            or (self.metadata_error is not None) != (self.metadata_state is MetadataState.FAILED)
            or not (self.metadata_error is None or type(self.metadata_error) is ErrorDetail)
            or (self.identity is not None) != bound
            or not (self.identity is None or type(self.identity) is RuleIdentitySummaryView)
            or type(self.groups) is not tuple or len(self.groups) != len(self.scheme.groups)
            or any(
                type(item) is not RuleGroupIdentityView or item.index != group.index or (item.rules is not None) != bound
                for item, group in zip(self.groups, self.scheme.groups)
            )
        ):
            raise TypeError("Список правил не согласован со схемой и состоянием метаданных.")

    @classmethod
    def build(
        cls, scheme: RoutingScheme, summary: XrayConfigView, state: MetadataState, error: ErrorDetail | None,
        binding: RuleBinding | None, stored: StoredManagerMetadata | None,
    ) -> "RuleListView":
        """Собрать список из схемы, структурной сводки и привязки; привязка есть только при прочитанных метаданных."""
        rules_by_group = _rules_by_group(scheme, binding)
        positions = {(rule.part, rule.index): rule for rule in summary.rules}
        groups = tuple(
            RuleGroupIdentityView(
                group.index, len(group.rules), *_target_position(positions.get((group.part, group.index))),
                rules_by_group[number],
            )
            for number, group in enumerate(scheme.groups)
        )
        identity = None
        if binding is not None:
            diagnostic = binding.to_diagnostic()
            records = None if stored is None else stored.metadata.rules
            identity = RuleIdentitySummaryView(
                diagnostic["bound_rule_count"], diagnostic["named_rule_count"], diagnostic["unbound_rule_count"],
                None if records is None else len(records), diagnostic["unbound_record_count"],
            )
        return cls(RoutingSchemeView.from_scheme(scheme), state, error, identity, groups)

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "scheme": self.scheme.to_dict(),
            "metadata_state": self.metadata_state.value,
            "metadata_error": None if self.metadata_error is None else self.metadata_error.to_dict(),
            "identity": None if self.identity is None else view_dict(self.identity),
            "groups": [
                {
                    **view_dict(group),
                    "target_position_state": group.target_position_state.value,
                    "target_position": None if group.target_position is None else view_dict(group.target_position),
                    "rules": None if group.rules is None else [view_dict(item) for item in group.rules],
                }
                for group in self.groups
            ],
        }


def _target_position(rule: XrayRuleView | None) -> tuple[TargetPositionState, XrayPositionView | None]:
    """Состояние и позиция назначения по правилу структурной сводки; ничего не выбирается по первому."""
    if rule is None:
        return TargetPositionState.UNAVAILABLE, None
    if rule.target_kind == "both":
        return TargetPositionState.UNSUPPORTED, None
    if rule.target_kind == "none" or not rule.target_tag_known:
        return TargetPositionState.ABSENT, None
    if not rule.target_resolved:
        return TargetPositionState.UNRESOLVED, None
    if rule.target_position is None:
        return TargetPositionState.AMBIGUOUS, None
    return TargetPositionState.RESOLVED, rule.target_position


def _rules_by_group(
    scheme: RoutingScheme, binding: RuleBinding | None,
) -> list[tuple[RuleListEntryView, ...] | None]:
    """Разложить правила привязки по группам схемы в их порядке; без привязки — `None` для каждой группы."""
    if binding is None:
        return [None] * len(scheme.groups)
    bound = iter(binding.rules)
    result = []
    for group in scheme.groups:
        entries = []
        for offset in range(len(group.rules)):
            item = next(bound)
            diagnostic = item.to_diagnostic()
            entries.append(RuleListEntryView(**{
                **view_fields(RuleListEntryView, {**diagnostic, "offset": offset, "name": item.rule.name}),
            }))
        result.append(tuple(entries))
    if next(bound, None) is not None:
        raise RuleBindingError(RuleBindingErrorCode.BINDING)
    return result


class ListRoutingRulesHandler:
    """Показать группы правил в фактическом порядке с идентичностью из метаданных; ничего не записывать.

    Источники Xray и XKeen читаются обработчиком конфигурации прокси один раз
    в его порядке и с его кодами отказов, схема строится тем же переводом, что
    у импорта, а позиции назначений берутся из структурной сводки тех же
    моделей. Метаданные читаются одним чтением хранилища, если оно
    подключено: их отсутствие — состояние, отказ хранилища — состояние
    с описанием отказа, а не отказ списка. Хранилище не получает запись.
    """

    def __init__(
        self, routing: ImportRoutingSchemeHandler, store: ManagerMetadataStore | None, *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._routing = routing
        self._store = store
        self._operation_ids = operation_ids

    def execute(self, command: ListRoutingRules) -> Result[RuleListView]:
        """Выполнить просмотр; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = ListRoutingRules.name
        if type(command) is not ListRoutingRules:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        models = self._routing.proxy.read()
        if isinstance(models, ErrorDetail):
            return failed(operation_id, name, models)
        scheme = self._routing.import_models(models)
        if isinstance(scheme, ErrorDetail):
            return failed(operation_id, name, scheme)
        summary = XrayConfigView.from_config(models.xray)

        state, store_error, stored, binding = MetadataState.NOT_CONNECTED, None, None, None
        if self._store is not None:
            stored = read_stored_metadata(self._store)
            if isinstance(stored, ErrorDetail):
                state, store_error, stored = MetadataState.FAILED, stored, None
            else:
                state = MetadataState.ABSENT if stored is None else MetadataState.PRESENT
                records = () if stored is None or stored.metadata.rules is None else stored.metadata.rules
                try:
                    binding = bind_routing_scheme(scheme, records)
                except (RuleBindingError, RoutingValidationError, ManagerMetadataError) as error:
                    return failed(operation_id, name, ErrorDetail(
                        _BINDING_FAILED.category, _BINDING_FAILED.code, _BINDING_FAILED.message,
                        reason=error.code.value,
                    ))
        try:
            view = RuleListView.build(scheme, summary, state, store_error, binding, stored)
        except (RuleBindingError, RoutingValidationError, TypeError):
            return failed(operation_id, name, _BINDING_FAILED)
        return succeeded(operation_id, name, view)
