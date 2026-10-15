"""Импорт действующих правил Xray в модель маршрутизации поверх чтения конфигурации прокси.

Сценарий читает части Xray через обработчик `InspectProxyConfig` и переводит
действующий раздел `routing` в группы правил и политику в памяти. Ничего не
записывается, не применяется и не сохраняется: метаданные менеджера,
нулевой diff и генерация конфигурации сюда не входят. Успех описывает
перевод снимка файлов, а не работу VPN или маршрут клиента.
"""

from dataclasses import dataclass
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.views import view_dict, view_fields
from keenvpn.domain.config_document import ConfigDocumentError
from keenvpn.domain.geodata import GeoDataError
from keenvpn.domain.routing import RoutingValidationError
from keenvpn.domain.routing_import import RoutingImportError, RoutingScheme, import_routing_scheme
from keenvpn.domain.xray_config import XrayConfigError


@dataclass(frozen=True, slots=True, kw_only=True)
class ImportRoutingScheme:
    """Перевести действующие правила Xray в модель маршрутизации без записи."""

    name: ClassVar[str] = "import_routing_scheme"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class RuleTargetView:
    """Назначение правила: вид, теги и стратегия в безопасной форме, действие и причины.

    Тег вне формата технического идентификатора и неизвестная стратегия
    заменены на `None`; `*_known` показывают, было ли значение задано.
    """

    kind: str
    tag_known: bool
    tag: str | None
    outbound_tags: tuple[str | None, ...]
    fallback_known: bool
    fallback_tag: str | None
    strategy_known: bool
    strategy: str | None
    action: str | None
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConditionTypeView:
    """Тип условия модели и число условий этого типа в группе."""

    name: str
    count: int


@dataclass(frozen=True, slots=True)
class ValueReasonView:
    """Путь значения списка правила и причина, по которой оно сохранено как неизвестное."""

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class RuleGroupView:
    """Группа правила: состав условий, поля, назначение и причины режима только для просмотра."""

    part: str
    index: int
    kind: str
    condition_count: int
    condition_types: tuple[ConditionTypeView, ...]
    value_count: int
    fields: tuple[str, ...]
    unsupported_fields: tuple[str, ...]
    unknown_field_count: int
    has_rule_tag: bool
    action: str | None
    read_only: bool
    reasons: tuple[str, ...]
    value_reasons: tuple[ValueReasonView, ...]
    target: RuleTargetView


@dataclass(frozen=True, slots=True)
class RoutingPolicyView:
    """Счётчики собранной политики и её финальное действие."""

    rule_count: int
    active_rule_count: int
    protected_rule_count: int
    final_action: str
    read_only: bool


@dataclass(frozen=True, slots=True)
class RoutingSchemeView:
    """Безопасное представление импортированной схемы.

    Имена частей, известные имена полей Xray, теги outbound и балансировщиков
    в формате технического идентификатора и известные стратегии — данные
    установки. Домены, адреса, коды наборов, теги правил, имена неизвестных
    полей, значения неподдержанных полей и теги вне безопасного формата сюда
    не входят.
    """

    routing_part: str | None
    routing_parts: tuple[str, ...]
    group_count: int
    rule_count: int
    final_action: str | None
    read_only: bool
    reasons: tuple[str, ...]
    policy: RoutingPolicyView | None
    groups: tuple[RuleGroupView, ...]

    @classmethod
    def from_scheme(cls, scheme: RoutingScheme) -> "RoutingSchemeView":
        """Построить представление из безопасной диагностики домена."""
        diagnostic = scheme.to_diagnostic()
        policy = diagnostic["policy"]
        return cls(
            routing_part=diagnostic["routing_part"],
            routing_parts=tuple(diagnostic["routing_parts"]),
            group_count=diagnostic["group_count"],
            rule_count=diagnostic["rule_count"],
            final_action=diagnostic["final_action"],
            read_only=diagnostic["read_only"],
            reasons=tuple(diagnostic["reasons"]),
            policy=None if policy is None else RoutingPolicyView(**view_fields(RoutingPolicyView, policy)),
            groups=tuple(
                RuleGroupView(**{
                    **view_fields(RuleGroupView, item),
                    "condition_types": tuple(
                        ConditionTypeView(name, count) for name, count in item["condition_types"].items()
                    ),
                    "fields": tuple(item["fields"]),
                    "unsupported_fields": tuple(item["unsupported_fields"]),
                    "reasons": tuple(item["reasons"]),
                    "value_reasons": tuple(
                        ValueReasonView(**view_fields(ValueReasonView, value)) for value in item["value_reasons"]
                    ),
                    "target": RuleTargetView(**{
                        **view_fields(RuleTargetView, item["target"]),
                        "outbound_tags": tuple(item["target"]["outbound_tags"]),
                        "reasons": tuple(item["target"]["reasons"]),
                    }),
                })
                for item in diagnostic["groups"]
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            **view_dict(self),
            "routing_parts": list(self.routing_parts),
            "reasons": list(self.reasons),
            "policy": None if self.policy is None else view_dict(self.policy),
            "groups": [
                {
                    **view_dict(group),
                    "condition_types": {item.name: item.count for item in group.condition_types},
                    "fields": list(group.fields),
                    "unsupported_fields": list(group.unsupported_fields),
                    "reasons": list(group.reasons),
                    "value_reasons": [view_dict(item) for item in group.value_reasons],
                    "target": {
                        **view_dict(group.target),
                        "outbound_tags": list(group.target.outbound_tags),
                        "reasons": list(group.target.reasons),
                    },
                }
                for group in self.groups
            ],
        }


IMPORT_FAILED = "routing_import_failed"
"""Код отказа, когда прочитанные части Xray не удалось перевести в модель."""
_DOMAIN_ERRORS = (RoutingImportError, RoutingValidationError, XrayConfigError, ConfigDocumentError, GeoDataError)


class ImportRoutingSchemeHandler:
    """Прочитать конфигурацию прокси её обработчиком и перевести правила Xray в модель.

    Источники читаются обработчиком `InspectProxyConfig` в его порядке и с его
    кодами отказов; отказ любого источника завершает сценарий без частичного
    результата. Перевод выполняется в памяти; части, их байты и неизвестные
    поля не меняются. Успех не подтверждает принятие конфигурации Xray,
    работу XKeen или VPN.
    """

    def __init__(
        self, proxy: InspectProxyConfigHandler, *, operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._proxy = proxy
        self._operation_ids = operation_ids

    def execute(self, command: ImportRoutingScheme) -> Result[RoutingSchemeView]:
        """Выполнить импорт; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = ImportRoutingScheme.name
        if type(command) is not ImportRoutingScheme:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        scheme = self.read()
        if isinstance(scheme, ErrorDetail):
            return failed(operation_id, name, scheme)
        return succeeded(operation_id, name, RoutingSchemeView.from_scheme(scheme))

    def read(self) -> RoutingScheme | ErrorDetail:
        """Прочитать источники и вернуть схему для доверенного кода; отказ — ErrorDetail.

        Схема содержит условия с доменами, адресами и кодами наборов:
        наружу передаётся только представление.
        """
        models = self._proxy.read()
        if isinstance(models, ErrorDetail):
            return models
        try:
            return import_routing_scheme(models.xray)
        except _DOMAIN_ERRORS as error:
            return ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, IMPORT_FAILED,
                "Не удалось перевести правила Xray в модель маршрутизации.", reason=error.code.value,
            )
