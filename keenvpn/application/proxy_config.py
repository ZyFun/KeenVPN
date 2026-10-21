"""Чтение конфигурации прозрачного прокси: части Xray, настройки XKeen, init и списки."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import XKeenInitSource, XKeenListSource, XKeenSettingsSource, XrayConfigSource
from keenvpn.application.source_checks import SourceCheck, check_source_model, unavailable
from keenvpn.application.views import view_dict, view_fields
from keenvpn.domain.config_document import ConfigDocumentError
from keenvpn.domain.xkeen_config import (
    Port53Facts, XKeenConfig, XKeenConfigError, XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings,
    assemble_xkeen_config, validate_xkeen_init, validate_xkeen_list, validate_xkeen_settings,
)
from keenvpn.domain.xray_config import XrayConfigError, XrayConfigSet, validate_xray_config_set


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectProxyConfig:
    """Прочитать части Xray, `xkeen.json`, параметры init и три списка XKeen."""

    name: ClassVar[str] = "inspect_proxy_config"

    contract_version: int = CONTRACT_VERSION


@dataclass(frozen=True, slots=True)
class XrayPartView:
    """Ревизия одной части, известные разделы верхнего уровня и число остальных."""

    name: str
    size: int
    sha256: str
    sections: tuple[str, ...]
    unknown_section_count: int


@dataclass(frozen=True, slots=True)
class XraySectionView:
    """Раздел верхнего уровня и части, в которых он встречается."""

    name: str
    parts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class XrayPositionView:
    """Позиция элемента: часть и индекс в своём списке, как в путях `unsupported_paths`."""

    part: str
    index: int


def _position(value: dict[str, object] | None) -> XrayPositionView | None:
    return None if value is None else XrayPositionView(**view_fields(XrayPositionView, value))


def _position_dict(value: XrayPositionView | None) -> dict[str, object] | None:
    return None if value is None else view_dict(value)


@dataclass(frozen=True, slots=True)
class XrayEndpointView:
    """Inbound или outbound: позиция, тег после проверки формата и известный протокол.

    `tag` и `protocol` — `None`, если поля нет или значение скрыто как
    небезопасное либо неизвестное; `tag_known` и `protocol_known` различают эти случаи.
    """

    part: str
    index: int
    tag_known: bool
    tag: str | None
    protocol_known: bool
    protocol: str | None


@dataclass(frozen=True, slots=True)
class XrayConditionView:
    """Имя известного поля условия Xray и число его значений; сами значения скрыты."""

    key: str
    value_count: int


@dataclass(frozen=True, slots=True)
class XrayRuleView:
    """Правило маршрутизации: ссылки на теги, назначение, его позиция и состав условий.

    Скрытый тег в `inbound_tags` заменяется на `None` на своей позиции.
    `target_position` указывает outbound или балансировщик, если цель однозначна;
    `unknown_condition_count` — число полей, которые декодер Xray не читает.
    """

    part: str
    index: int
    type_known: bool
    type: str | None
    inbound_tags: tuple[str | None, ...]
    inbound_tags_resolved: bool
    target_kind: str
    target_tag_known: bool
    target_tag: str | None
    target_resolved: bool
    target_position: XrayPositionView | None
    has_rule_tag: bool
    conditions: tuple[XrayConditionView, ...]
    unknown_condition_count: int


@dataclass(frozen=True, slots=True)
class XrayBalancerView:
    """Балансировщик: позиция, селекторы, `fallbackTag` с позицией цели и известная стратегия.

    Пустой селектор остаётся пустым, скрытый — `None` на своей позиции.
    """

    part: str
    index: int
    tag_known: bool
    tag: str | None
    selector: tuple[str | None, ...]
    selector_match_count: int
    fallback_known: bool
    fallback_tag: str | None
    fallback_resolved: bool | None
    fallback_position: XrayPositionView | None
    strategy_known: bool
    strategy: str | None


@dataclass(frozen=True, slots=True)
class XrayObservatorySubjectView:
    """Селектор наблюдателя после проверки формата и число совпавших outbound."""

    part: str
    section: str
    selector: str | None
    match_count: int


@dataclass(frozen=True, slots=True)
class XrayUnsupportedPathView:
    """Место части, структура которого не поддержана сводкой."""

    part: str
    path: str


@dataclass(frozen=True, slots=True)
class XrayConfigView:
    """Ревизии частей и структурная сводка без доменов, адресов, путей и паролей.

    Строки из конфигурации показываются по правилу `keenvpn.domain.xray_identifiers`:
    теги и селекторы — после проверки формата, протоколы, стратегии, `type`
    правила, имена полей условий и разделов — только из списков известных
    значений Xray; скрытое значение — `None`, признаки `*_known` сохраняют факт
    его наличия. В списках скрытый элемент стоит на своей позиции.
    """

    part_count: int
    parts: tuple[XrayPartView, ...]
    sections: tuple[XraySectionView, ...]
    duplicate_sections: tuple[str, ...]
    dns_tags: tuple[str | None, ...]
    domain_strategies: tuple[str | None, ...]
    inbounds: tuple[XrayEndpointView, ...]
    outbounds: tuple[XrayEndpointView, ...]
    duplicate_inbound_tags: tuple[str | None, ...]
    duplicate_outbound_tags: tuple[str | None, ...]
    duplicate_balancer_tags: tuple[str | None, ...]
    rule_count: int
    rules: tuple[XrayRuleView, ...]
    balancers: tuple[XrayBalancerView, ...]
    observatory_subjects: tuple[XrayObservatorySubjectView, ...]
    unsupported_paths: tuple[XrayUnsupportedPathView, ...]

    @classmethod
    def from_config(cls, config: XrayConfigSet) -> "XrayConfigView":
        """Построить представление из безопасной диагностики домена."""
        diagnostic = config.to_diagnostic()
        return cls(
            part_count=diagnostic["part_count"],
            parts=tuple(
                XrayPartView(**{**view_fields(XrayPartView, item), "sections": tuple(item["sections"])})
                for item in diagnostic["parts"]
            ),
            sections=tuple(XraySectionView(name, tuple(parts)) for name, parts in diagnostic["sections"].items()),
            duplicate_sections=tuple(diagnostic["duplicate_sections"]),
            dns_tags=tuple(diagnostic["dns_tags"]),
            domain_strategies=tuple(diagnostic["domain_strategies"]),
            inbounds=tuple(XrayEndpointView(**view_fields(XrayEndpointView, item)) for item in diagnostic["inbounds"]),
            outbounds=tuple(XrayEndpointView(**view_fields(XrayEndpointView, item)) for item in diagnostic["outbounds"]),
            duplicate_inbound_tags=tuple(diagnostic["duplicate_inbound_tags"]),
            duplicate_outbound_tags=tuple(diagnostic["duplicate_outbound_tags"]),
            duplicate_balancer_tags=tuple(diagnostic["duplicate_balancer_tags"]),
            rule_count=diagnostic["rule_count"],
            rules=tuple(
                XrayRuleView(**{
                    **view_fields(XrayRuleView, item),
                    "inbound_tags": tuple(item["inbound_tags"]),
                    "target_position": _position(item["target_position"]),
                    "conditions": tuple(XrayConditionView(key, count) for key, count in item["conditions"].items()),
                })
                for item in diagnostic["rules"]
            ),
            balancers=tuple(
                XrayBalancerView(**{
                    **view_fields(XrayBalancerView, item),
                    "selector": tuple(item["selector"]),
                    "fallback_position": _position(item["fallback_position"]),
                })
                for item in diagnostic["balancers"]
            ),
            observatory_subjects=tuple(
                XrayObservatorySubjectView(**view_fields(XrayObservatorySubjectView, item))
                for item in diagnostic["observatory_subjects"]
            ),
            unsupported_paths=tuple(
                XrayUnsupportedPathView(**view_fields(XrayUnsupportedPathView, item))
                for item in diagnostic["unsupported_paths"]
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "part_count": self.part_count,
            "parts": [{**view_dict(part), "sections": list(part.sections)} for part in self.parts],
            "sections": {section.name: list(section.parts) for section in self.sections},
            "duplicate_sections": list(self.duplicate_sections),
            "dns_tags": list(self.dns_tags),
            "domain_strategies": list(self.domain_strategies),
            "inbounds": [view_dict(item) for item in self.inbounds],
            "outbounds": [view_dict(item) for item in self.outbounds],
            "duplicate_inbound_tags": list(self.duplicate_inbound_tags),
            "duplicate_outbound_tags": list(self.duplicate_outbound_tags),
            "duplicate_balancer_tags": list(self.duplicate_balancer_tags),
            "rule_count": self.rule_count,
            "rules": [
                {
                    **view_dict(rule),
                    "inbound_tags": list(rule.inbound_tags),
                    "target_position": _position_dict(rule.target_position),
                    "conditions": {condition.key: condition.value_count for condition in rule.conditions},
                }
                for rule in self.rules
            ],
            "balancers": [
                {
                    **view_dict(item),
                    "selector": list(item.selector),
                    "fallback_position": _position_dict(item.fallback_position),
                }
                for item in self.balancers
            ],
            "observatory_subjects": [view_dict(item) for item in self.observatory_subjects],
            "unsupported_paths": [view_dict(item) for item in self.unsupported_paths],
        }


@dataclass(frozen=True, slots=True)
class XKeenFlagView:
    """Статус флага и его значение `on`/`off`, если оно известно."""

    status: str
    value: str | None


@dataclass(frozen=True, slots=True)
class XKeenSettingsView:
    """Ревизия `xkeen.json`, имена разделов и полей объекта `xkeen` после проверки формата и kill-switch.

    Имена, не похожие на технический идентификатор, не показываются и учитываются
    счётчиками `hidden_section_count` и `hidden_settings_key_count`.
    """

    name: str
    size: int
    sha256: str
    sections: tuple[str, ...]
    hidden_section_count: int
    has_xkeen_section: bool
    settings_keys: tuple[str, ...]
    hidden_settings_key_count: int
    killswitch: XKeenFlagView


@dataclass(frozen=True, slots=True)
class XKeenInitFlagView:
    """Известный флаг init и число его присваиваний с отступом."""

    name: str
    status: str
    value: str | None
    indented_count: int


@dataclass(frozen=True, slots=True)
class XKeenInitView:
    """Счётчики присваиваний init, имена повторов и известные флаги."""

    assignment_count: int
    top_level_count: int
    indented_count: int
    literal_count: int
    expression_count: int
    parameter_count: int
    duplicate_names: tuple[str, ...]
    flags: tuple[XKeenInitFlagView, ...]


@dataclass(frozen=True, slots=True)
class XKeenListView:
    """Счётчики строк и элементов одного списка без значений портов и адресов."""

    name: str
    line_count: int
    blank_count: int
    comment_count: int
    entry_count: int
    port_count: int | None
    range_count: int | None
    address_count: int | None
    invalid_count: int


@dataclass(frozen=True, slots=True)
class Port53View:
    """Раздельные факты о порту 53; это не вывод о фактическом перехвате."""

    port: int
    port_exclude_entry: bool
    port_exclude_range: bool
    port_proxying_entry: bool
    port_proxying_range: bool
    proxy_dns: XKeenFlagView
    proxy_router: XKeenFlagView

    @classmethod
    def from_facts(cls, facts: Port53Facts) -> "Port53View":
        """Построить представление из фактов домена."""
        diagnostic = facts.to_diagnostic()
        return cls(**{
            **view_fields(cls, {**diagnostic, "proxy_dns": None, "proxy_router": None}),
            "proxy_dns": XKeenFlagView(**diagnostic["proxy_dns"]),
            "proxy_router": XKeenFlagView(**diagnostic["proxy_router"]),
        })

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {**view_dict(self), "proxy_dns": view_dict(self.proxy_dns), "proxy_router": view_dict(self.proxy_router)}


@dataclass(frozen=True, slots=True)
class XKeenConfigView:
    """Настройки, init, три списка и факты по порту 53."""

    settings: XKeenSettingsView
    init: XKeenInitView
    port_exclude: XKeenListView
    port_proxying: XKeenListView
    ip_exclude: XKeenListView
    port_53: Port53View

    @classmethod
    def from_config(cls, config: XKeenConfig) -> "XKeenConfigView":
        """Построить представление из безопасной диагностики домена."""
        diagnostic = config.to_diagnostic()
        settings = diagnostic["settings"]
        init = diagnostic["init"]
        lists = diagnostic["lists"]
        return cls(
            settings=XKeenSettingsView(**{
                **view_fields(XKeenSettingsView, {**settings, "killswitch": XKeenFlagView(**settings["killswitch"])}),
                "sections": tuple(settings["sections"]),
                "settings_keys": tuple(settings["settings_keys"]),
            }),
            init=XKeenInitView(**{
                **view_fields(XKeenInitView, {**init, "flags": ()}),
                "duplicate_names": tuple(init["duplicate_names"]),
                "flags": tuple(XKeenInitFlagView(name=name, **flag) for name, flag in init["flags"].items()),
            }),
            port_exclude=XKeenListView(**view_fields(XKeenListView, lists["port_exclude"])),
            port_proxying=XKeenListView(**view_fields(XKeenListView, lists["port_proxying"])),
            ip_exclude=XKeenListView(**view_fields(XKeenListView, lists["ip_exclude"])),
            port_53=Port53View.from_facts(config.port_53),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "settings": {
                **view_dict(self.settings),
                "sections": list(self.settings.sections),
                "settings_keys": list(self.settings.settings_keys),
                "killswitch": view_dict(self.settings.killswitch),
            },
            "init": {
                **view_dict(self.init),
                "duplicate_names": list(self.init.duplicate_names),
                "flags": {flag.name: {name: getattr(flag, name) for name in ("status", "value", "indented_count")}
                          for flag in self.init.flags},
            },
            "lists": {
                "port_exclude": view_dict(self.port_exclude),
                "port_proxying": view_dict(self.port_proxying),
                "ip_exclude": view_dict(self.ip_exclude),
            },
            "port_53": self.port_53.to_dict(),
        }


@dataclass(frozen=True, slots=True, repr=False)
class ProxyConfigModels:
    """Прочитанные модели Xray и XKeen для доверенного кода; содержат секреты конфигурации."""

    xray: XrayConfigSet
    xkeen: XKeenConfig

    def __repr__(self) -> str:
        return f"ProxyConfigModels(parts={len(self.xray.parts)})"


@dataclass(frozen=True, slots=True)
class ProxyConfigView:
    """Безопасное представление прочитанной конфигурации Xray и XKeen.

    Имена файлов проверяет `valid_document_name`; теги, протоколы, стратегии,
    имена разделов и ключи `xkeen.json` — значения из файлов, а не доверенные
    идентификаторы: они показываются только после проверки формата или по
    списку известных значений Xray. Домены, адреса, пути, пароли, теги правил,
    значения параметров init и записи списков сюда не входят.
    """

    xray: XrayConfigView
    xkeen: XKeenConfigView

    @classmethod
    def from_models(cls, models: ProxyConfigModels) -> "ProxyConfigView":
        """Построить представление из прочитанных моделей."""
        return cls(XrayConfigView.from_config(models.xray), XKeenConfigView.from_config(models.xkeen))

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {"xray": self.xray.to_dict(), "xkeen": self.xkeen.to_dict()}


class ProxyConfigSource(StrEnum):
    """Источник конфигурации прокси; порядок членов — порядок чтения сценария."""

    XRAY = "xray"
    SETTINGS = "settings"
    INIT = "init"
    PORT_EXCLUDE = "port_exclude"
    PORT_PROXYING = "port_proxying"
    IP_EXCLUDE = "ip_exclude"


_LIST_FIELDS = {
    XKeenListName.PORT_EXCLUDE: "port_exclude",
    XKeenListName.PORT_PROXYING: "port_proxying",
    XKeenListName.IP_EXCLUDE: "ip_exclude",
}
_LIST_NAME = {field_name: name for name, field_name in _LIST_FIELDS.items()}
_DOMAIN_ERRORS = (XrayConfigError, XKeenConfigError, ConfigDocumentError)
_UNAVAILABLE = {
    "xray": ("xray_config_unavailable", "Не удалось прочитать части конфигурации Xray."),
    "settings": ("xkeen_settings_unavailable", "Не удалось прочитать настройки XKeen."),
    "init": ("xkeen_init_unavailable", "Не удалось прочитать параметры init XKeen."),
    "port_exclude": ("xkeen_port_exclude_unavailable", "Не удалось прочитать список исключённых портов XKeen."),
    "port_proxying": ("xkeen_port_proxying_unavailable", "Не удалось прочитать список перехватываемых портов XKeen."),
    "ip_exclude": ("xkeen_ip_exclude_unavailable", "Не удалось прочитать список исключённых адресов XKeen."),
}
_CHECKS = {
    "xray": SourceCheck(
        "invalid_xray_config", XrayConfigSet, validate_xray_config_set,
        "Источник вернул части конфигурации Xray в неподдерживаемом формате.",
        "Источник вернул некорректные части конфигурации Xray.", _DOMAIN_ERRORS,
    ),
    "settings": SourceCheck(
        "invalid_xkeen_settings", XKeenSettings, validate_xkeen_settings,
        "Источник вернул настройки XKeen в неподдерживаемом формате.",
        "Источник вернул некорректные настройки XKeen.", _DOMAIN_ERRORS,
    ),
    "init": SourceCheck(
        "invalid_xkeen_init", XKeenInitParameters, validate_xkeen_init,
        "Источник вернул параметры init XKeen в неподдерживаемом формате.",
        "Источник вернул некорректные параметры init XKeen.", _DOMAIN_ERRORS,
    ),
    "port_exclude": SourceCheck(
        "invalid_xkeen_port_exclude", XKeenList, validate_xkeen_list,
        "Источник вернул список исключённых портов XKeen в неподдерживаемом формате.",
        "Источник вернул некорректный список исключённых портов XKeen.", _DOMAIN_ERRORS,
    ),
    "port_proxying": SourceCheck(
        "invalid_xkeen_port_proxying", XKeenList, validate_xkeen_list,
        "Источник вернул список перехватываемых портов XKeen в неподдерживаемом формате.",
        "Источник вернул некорректный список перехватываемых портов XKeen.", _DOMAIN_ERRORS,
    ),
    "ip_exclude": SourceCheck(
        "invalid_xkeen_ip_exclude", XKeenList, validate_xkeen_list,
        "Источник вернул список исключённых адресов XKeen в неподдерживаемом формате.",
        "Источник вернул некорректный список исключённых адресов XKeen.", _DOMAIN_ERRORS,
    ),
}
LIST_NAME_MISMATCH = "xkeen_list_name_mismatch"
"""Причина отказа, когда источник вернул список с другим именем."""


def _check_model(source: str, value: object) -> ErrorDetail | None:
    """Проверить ответ источника; у списка дополнительно сверить имя с запрошенным."""
    check = _CHECKS[source]
    error = check_source_model(check, value)
    if error is not None:
        return error
    if check.model_type is XKeenList and value.name is not _LIST_NAME[source]:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, check.code, check.data_message, reason=LIST_NAME_MISMATCH)
    return None


class InspectProxyConfigHandler:
    """Прочитать шесть источников раздельно и собрать безопасное представление.

    Источники вызываются по одному разу в фиксированном порядке: части Xray,
    настройки XKeen, параметры init, списки исключённых портов, перехватываемых
    портов и исключённых адресов. Отказ или некорректный ответ любого из них
    завершает сценарий отдельным кодом; частичного результата нет. Успех
    описывает снимок файлов на момент чтения, а не работу Xray, XKeen или VPN.
    """

    def __init__(
        self,
        xray: XrayConfigSource,
        settings: XKeenSettingsSource,
        init: XKeenInitSource,
        lists: XKeenListSource,
        *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._xray = xray
        self._settings = settings
        self._init = init
        self._lists = lists
        self._operation_ids = operation_ids

    def execute(self, command: InspectProxyConfig) -> Result[ProxyConfigView]:
        """Выполнить чтение; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = InspectProxyConfig.name
        if type(command) is not InspectProxyConfig:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)
        models = self.read()
        if isinstance(models, ErrorDetail):
            return failed(operation_id, name, models)
        return succeeded(operation_id, name, ProxyConfigView.from_models(models))

    def read(self) -> ProxyConfigModels | ErrorDetail:
        """Прочитать источники и собрать модели для доверенного кода; отказ — ErrorDetail.

        Общий сценарий чтения установки использует этот метод, чтобы не повторять
        порядок чтения и коды отказов и разобрать ссылки правил на геобазы.
        Модели содержат домены, адреса и пароли: наружу передаётся только представление.
        """
        models: dict[str, object] = {}
        for source in ProxyConfigSource:
            value = self.read_source(source)
            if isinstance(value, ErrorDetail):
                return value
            models[source.value] = value

        try:
            xkeen = assemble_xkeen_config(
                models["settings"], models["init"], models["port_exclude"], models["port_proxying"],
                models["ip_exclude"],
            )
        except _DOMAIN_ERRORS as error:
            return ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, "proxy_config_inconsistent",
                "Прочитанные файлы Xray и XKeen не удалось согласовать.", reason=error.code.value,
            )
        return ProxyConfigModels(models["xray"], xkeen)

    def read_source(self, source: ProxyConfigSource) -> object | ErrorDetail:
        """Прочитать один источник и проверить ответ; отказ — ErrorDetail с кодом этого источника.

        Источник вызывается один раз. `read()` читает так все шесть по порядку
        и останавливается на первом отказе; сводка состояния читает нужные ей
        источники по одному, чтобы отказ одного не скрывал остальные. Модель
        содержит секреты конфигурации: наружу передаётся только представление.
        """
        if type(source) is not ProxyConfigSource:
            raise TypeError("Источник задаётся ProxyConfigSource.")
        read = self._reader(source)
        try:
            value = read()
        except Exception:
            # Текст и цепочка исключения источника могут содержать пароли, адреса и пути.
            return unavailable(*_UNAVAILABLE[source.value])
        error = _check_model(source.value, value)
        return value if error is None else error

    def _reader(self, source: ProxyConfigSource) -> Callable[[], object]:
        if source is ProxyConfigSource.XRAY:
            return self._xray.current_xray_config
        if source is ProxyConfigSource.SETTINGS:
            return self._settings.current_xkeen_settings
        if source is ProxyConfigSource.INIT:
            return self._init.current_xkeen_init
        list_name = _LIST_NAME[source.value]
        return lambda: self._lists.current_xkeen_list(list_name)
