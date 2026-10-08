"""Чтение конфигурации прозрачного прокси: части Xray, настройки XKeen, init и списки."""

from dataclasses import dataclass
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.ports import XKeenInitSource, XKeenListSource, XKeenSettingsSource, XrayConfigSource
from keenvpn.domain.config_document import ConfigDocumentError
from keenvpn.domain.xkeen_config import (
    XKeenConfig, XKeenConfigError, XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings,
    assemble_xkeen_config, validate_xkeen_init, validate_xkeen_list, validate_xkeen_settings,
)
from keenvpn.domain.xray_config import XrayConfigError, XrayConfigSet, validate_xray_config_set


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectProxyConfig:
    """Прочитать части Xray, `xkeen.json`, параметры init и три списка XKeen."""

    name: ClassVar[str] = "inspect_proxy_config"

    contract_version: int = CONTRACT_VERSION


def _fields(view_type: type, values: dict[str, object]) -> dict[str, object]:
    return {name: values[name] for name in view_type.__dataclass_fields__}


def _view_dict(view: object) -> dict[str, object]:
    """Снять поля frozen dataclass со слотами, у которого нет `__dict__`."""
    return {name: getattr(view, name) for name in view.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class XrayPartView:
    """Ревизия одной части и имена её разделов верхнего уровня."""

    name: str
    size: int
    sha256: str
    sections: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class XraySectionView:
    """Раздел верхнего уровня и части, в которых он встречается."""

    name: str
    parts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class XrayEndpointView:
    """Inbound или outbound: часть, тег и протокол без настроек."""

    part: str
    tag: str | None
    protocol: str | None


@dataclass(frozen=True, slots=True)
class XrayConditionView:
    """Имя поля условия правила и число его значений; сами значения скрыты."""

    key: str
    value_count: int


@dataclass(frozen=True, slots=True)
class XrayRuleView:
    """Правило маршрутизации: ссылки на теги, назначение и состав условий."""

    part: str
    index: int
    type: str | None
    inbound_tags: tuple[str, ...]
    inbound_tags_resolved: bool
    target_kind: str
    target_tag: str | None
    target_resolved: bool
    has_rule_tag: bool
    conditions: tuple[XrayConditionView, ...]


@dataclass(frozen=True, slots=True)
class XrayBalancerView:
    """Балансировщик: селекторы, `fallbackTag` и стратегия."""

    part: str
    tag: str | None
    selector: tuple[str, ...]
    selector_match_count: int
    fallback_tag: str | None
    fallback_resolved: bool | None
    strategy: str | None


@dataclass(frozen=True, slots=True)
class XrayObservatorySubjectView:
    """Селектор наблюдателя и число совпавших outbound."""

    part: str
    section: str
    selector: str
    match_count: int


@dataclass(frozen=True, slots=True)
class XrayUnsupportedPathView:
    """Место части, структура которого не поддержана сводкой."""

    part: str
    path: str


@dataclass(frozen=True, slots=True)
class XrayConfigView:
    """Ревизии частей и структурная сводка без доменов, адресов, путей и паролей."""

    part_count: int
    parts: tuple[XrayPartView, ...]
    sections: tuple[XraySectionView, ...]
    duplicate_sections: tuple[str, ...]
    dns_tags: tuple[str, ...]
    domain_strategies: tuple[str, ...]
    inbounds: tuple[XrayEndpointView, ...]
    outbounds: tuple[XrayEndpointView, ...]
    duplicate_inbound_tags: tuple[str, ...]
    duplicate_outbound_tags: tuple[str, ...]
    duplicate_balancer_tags: tuple[str, ...]
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
                XrayPartView(**{**_fields(XrayPartView, item), "sections": tuple(item["sections"])})
                for item in diagnostic["parts"]
            ),
            sections=tuple(XraySectionView(name, tuple(parts)) for name, parts in diagnostic["sections"].items()),
            duplicate_sections=tuple(diagnostic["duplicate_sections"]),
            dns_tags=tuple(diagnostic["dns_tags"]),
            domain_strategies=tuple(diagnostic["domain_strategies"]),
            inbounds=tuple(XrayEndpointView(**_fields(XrayEndpointView, item)) for item in diagnostic["inbounds"]),
            outbounds=tuple(XrayEndpointView(**_fields(XrayEndpointView, item)) for item in diagnostic["outbounds"]),
            duplicate_inbound_tags=tuple(diagnostic["duplicate_inbound_tags"]),
            duplicate_outbound_tags=tuple(diagnostic["duplicate_outbound_tags"]),
            duplicate_balancer_tags=tuple(diagnostic["duplicate_balancer_tags"]),
            rule_count=diagnostic["rule_count"],
            rules=tuple(
                XrayRuleView(**{
                    **_fields(XrayRuleView, item),
                    "inbound_tags": tuple(item["inbound_tags"]),
                    "conditions": tuple(XrayConditionView(key, count) for key, count in item["conditions"].items()),
                })
                for item in diagnostic["rules"]
            ),
            balancers=tuple(
                XrayBalancerView(**{**_fields(XrayBalancerView, item), "selector": tuple(item["selector"])})
                for item in diagnostic["balancers"]
            ),
            observatory_subjects=tuple(
                XrayObservatorySubjectView(**_fields(XrayObservatorySubjectView, item))
                for item in diagnostic["observatory_subjects"]
            ),
            unsupported_paths=tuple(
                XrayUnsupportedPathView(**_fields(XrayUnsupportedPathView, item))
                for item in diagnostic["unsupported_paths"]
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "part_count": self.part_count,
            "parts": [{**_view_dict(part), "sections": list(part.sections)} for part in self.parts],
            "sections": {section.name: list(section.parts) for section in self.sections},
            "duplicate_sections": list(self.duplicate_sections),
            "dns_tags": list(self.dns_tags),
            "domain_strategies": list(self.domain_strategies),
            "inbounds": [_view_dict(item) for item in self.inbounds],
            "outbounds": [_view_dict(item) for item in self.outbounds],
            "duplicate_inbound_tags": list(self.duplicate_inbound_tags),
            "duplicate_outbound_tags": list(self.duplicate_outbound_tags),
            "duplicate_balancer_tags": list(self.duplicate_balancer_tags),
            "rule_count": self.rule_count,
            "rules": [
                {
                    **_view_dict(rule),
                    "inbound_tags": list(rule.inbound_tags),
                    "conditions": {condition.key: condition.value_count for condition in rule.conditions},
                }
                for rule in self.rules
            ],
            "balancers": [{**_view_dict(item), "selector": list(item.selector)} for item in self.balancers],
            "observatory_subjects": [_view_dict(item) for item in self.observatory_subjects],
            "unsupported_paths": [_view_dict(item) for item in self.unsupported_paths],
        }


@dataclass(frozen=True, slots=True)
class XKeenFlagView:
    """Статус флага и его значение `on`/`off`, если оно известно."""

    status: str
    value: str | None


@dataclass(frozen=True, slots=True)
class XKeenSettingsView:
    """Ревизия `xkeen.json`, имена полей объекта `xkeen` и kill-switch."""

    name: str
    size: int
    sha256: str
    sections: tuple[str, ...]
    has_xkeen_section: bool
    settings_keys: tuple[str, ...]
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
        port_53 = diagnostic["port_53"]
        return cls(
            settings=XKeenSettingsView(**{
                **_fields(XKeenSettingsView, {**settings, "killswitch": XKeenFlagView(**settings["killswitch"])}),
                "sections": tuple(settings["sections"]),
                "settings_keys": tuple(settings["settings_keys"]),
            }),
            init=XKeenInitView(**{
                **_fields(XKeenInitView, {**init, "flags": ()}),
                "duplicate_names": tuple(init["duplicate_names"]),
                "flags": tuple(XKeenInitFlagView(name=name, **flag) for name, flag in init["flags"].items()),
            }),
            port_exclude=XKeenListView(**_fields(XKeenListView, lists["port_exclude"])),
            port_proxying=XKeenListView(**_fields(XKeenListView, lists["port_proxying"])),
            ip_exclude=XKeenListView(**_fields(XKeenListView, lists["ip_exclude"])),
            port_53=Port53View(**{
                **_fields(Port53View, {**port_53, "proxy_dns": None, "proxy_router": None}),
                "proxy_dns": XKeenFlagView(**port_53["proxy_dns"]),
                "proxy_router": XKeenFlagView(**port_53["proxy_router"]),
            }),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "settings": {
                **_view_dict(self.settings),
                "sections": list(self.settings.sections),
                "settings_keys": list(self.settings.settings_keys),
                "killswitch": _view_dict(self.settings.killswitch),
            },
            "init": {
                **_view_dict(self.init),
                "duplicate_names": list(self.init.duplicate_names),
                "flags": {flag.name: {name: getattr(flag, name) for name in ("status", "value", "indented_count")}
                          for flag in self.init.flags},
            },
            "lists": {
                "port_exclude": _view_dict(self.port_exclude),
                "port_proxying": _view_dict(self.port_proxying),
                "ip_exclude": _view_dict(self.ip_exclude),
            },
            "port_53": {
                **_view_dict(self.port_53),
                "proxy_dns": _view_dict(self.port_53.proxy_dns),
                "proxy_router": _view_dict(self.port_53.proxy_router),
            },
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

    Теги, протоколы, имена разделов и файлов — технические идентификаторы
    установки. Домены, адреса, пути, пароли, теги правил, значения параметров
    init и записи списков сюда не входят.
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


_LIST_FIELDS = {
    XKeenListName.PORT_EXCLUDE: "port_exclude",
    XKeenListName.PORT_PROXYING: "port_proxying",
    XKeenListName.IP_EXCLUDE: "ip_exclude",
}
_UNAVAILABLE = {
    "xray": ("xray_config_unavailable", "Не удалось прочитать части конфигурации Xray."),
    "settings": ("xkeen_settings_unavailable", "Не удалось прочитать настройки XKeen."),
    "init": ("xkeen_init_unavailable", "Не удалось прочитать параметры init XKeen."),
    "port_exclude": ("xkeen_port_exclude_unavailable", "Не удалось прочитать список исключённых портов XKeen."),
    "port_proxying": ("xkeen_port_proxying_unavailable", "Не удалось прочитать список перехватываемых портов XKeen."),
    "ip_exclude": ("xkeen_ip_exclude_unavailable", "Не удалось прочитать список исключённых адресов XKeen."),
}
_INVALID = {
    "xray": (
        "invalid_xray_config", XrayConfigSet, validate_xray_config_set,
        "Источник вернул части конфигурации Xray в неподдерживаемом формате.",
        "Источник вернул некорректные части конфигурации Xray.",
    ),
    "settings": (
        "invalid_xkeen_settings", XKeenSettings, validate_xkeen_settings,
        "Источник вернул настройки XKeen в неподдерживаемом формате.",
        "Источник вернул некорректные настройки XKeen.",
    ),
    "init": (
        "invalid_xkeen_init", XKeenInitParameters, validate_xkeen_init,
        "Источник вернул параметры init XKeen в неподдерживаемом формате.",
        "Источник вернул некорректные параметры init XKeen.",
    ),
    "port_exclude": (
        "invalid_xkeen_port_exclude", XKeenList, validate_xkeen_list,
        "Источник вернул список исключённых портов XKeen в неподдерживаемом формате.",
        "Источник вернул некорректный список исключённых портов XKeen.",
    ),
    "port_proxying": (
        "invalid_xkeen_port_proxying", XKeenList, validate_xkeen_list,
        "Источник вернул список перехватываемых портов XKeen в неподдерживаемом формате.",
        "Источник вернул некорректный список перехватываемых портов XKeen.",
    ),
    "ip_exclude": (
        "invalid_xkeen_ip_exclude", XKeenList, validate_xkeen_list,
        "Источник вернул список исключённых адресов XKeen в неподдерживаемом формате.",
        "Источник вернул некорректный список исключённых адресов XKeen.",
    ),
}
_DOMAIN_ERRORS = (XrayConfigError, XKeenConfigError, ConfigDocumentError)
LIST_NAME_MISMATCH = "xkeen_list_name_mismatch"
"""Причина отказа, когда источник вернул список с другим именем."""


def _unavailable(source: str) -> ErrorDetail:
    code, message = _UNAVAILABLE[source]
    return ErrorDetail(ErrorCategory.SOURCE_FAILED, code, message)


def _check_model(source: str, value: object) -> ErrorDetail | None:
    """Проверить тип ответа и повторно проверить модель по её данным."""
    code, model_type, validate, type_message, data_message = _INVALID[source]
    if type(value) is not model_type:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, type_message)
    try:
        validate(value)
    except _DOMAIN_ERRORS as error:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, data_message, reason=error.code.value)
    except Exception:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, type_message)
    if model_type is XKeenList and value.name is not _LIST_NAME[source]:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, data_message, reason=LIST_NAME_MISMATCH)
    return None


_LIST_NAME = {field_name: name for name, field_name in _LIST_FIELDS.items()}


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
        reads = [
            ("xray", self._xray.current_xray_config),
            ("settings", self._settings.current_xkeen_settings),
            ("init", self._init.current_xkeen_init),
        ]
        reads += [
            (field_name, lambda list_name=list_name: self._lists.current_xkeen_list(list_name))
            for list_name, field_name in _LIST_FIELDS.items()
        ]
        for source, read in reads:
            try:
                value = read()
            except Exception:
                # Текст и цепочка исключения источника могут содержать пароли, адреса и пути.
                return _unavailable(source)
            error = _check_model(source, value)
            if error is not None:
                return error
            models[source] = value

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
