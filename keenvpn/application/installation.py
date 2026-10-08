"""Общий сценарий чтения существующей установки для первого шага мастера.

Объединяет чтение Keenetic, конфигурации Xray и XKeen, инвентаря геобаз
и наблюдения процесса Xray. Сценарий собран поверх обработчиков
`InspectKeeneticState` и `InspectProxyConfig`: он использует их чтение и коды
отказов, а не повторяет их. Ничего не записывается, не устанавливается
и не применяется; команды XKeen и init не вызываются. Успех описывает снимок
на момент чтения и не подтверждает работу VPN, перехват трафика или маршрут клиента.
"""

from dataclasses import dataclass
from typing import ClassVar

from keenvpn.application.contract import (
    CONTRACT_VERSION, ErrorCategory, ErrorDetail, OperationIdFactory, Result,
    check_contract_version, failed, invalid_command, new_operation_id, succeeded,
)
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler, KeeneticStateView
from keenvpn.application.ports import GeoDatabaseSource, XrayProcessSource
from keenvpn.application.proxy_config import InspectProxyConfigHandler, ProxyConfigView
from keenvpn.domain.geodata import (
    GeoDatabaseInventory, GeoDataError, GeoDataState, assemble_geodata_state, validate_geo_inventory,
)
from keenvpn.domain.xray_process import XrayProcessError, XrayProcessObservation, validate_xray_process_observation


@dataclass(frozen=True, slots=True, kw_only=True)
class InspectInstallation:
    """Прочитать Keenetic, Xray/XKeen, геобазы и процесс Xray одним сценарием."""

    name: ClassVar[str] = "inspect_installation"

    contract_version: int = CONTRACT_VERSION


def _fields(view_type: type, values: dict[str, object]) -> dict[str, object]:
    return {name: values[name] for name in view_type.__dataclass_fields__}


def _view_dict(view: object) -> dict[str, object]:
    """Снять поля frozen dataclass со слотами, у которого нет `__dict__`."""
    return {name: getattr(view, name) for name in view.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class GeoDatabaseFileView:
    """Файл геобазы: наличие, ревизия, безопасные источник и версия и число ссылок на него.

    `source` и `version` — `None`, если сведений нет или значение скрыто как
    небезопасное; `source_known` и `version_known` различают эти случаи.
    """

    name: str
    present: bool
    size: int | None
    sha256: str | None
    source_known: bool
    source: str | None
    version_known: bool
    version: str | None
    reference_count: int
    set_count: int


@dataclass(frozen=True, slots=True)
class GeoReferenceView:
    """Ссылка правила или DNS на набор геобазы без кода набора.

    `file_name` — `None`, если имя внешнего файла содержит каталог или иначе
    непригодно для показа. `file_status` — `present`, `missing` или `unknown`.
    """

    part: str
    path: str
    family: str
    external: bool
    file_name: str | None
    file_status: str
    negated: bool
    attribute_count: int


@dataclass(frozen=True, slots=True)
class UnsupportedGeoReferenceView:
    """Место конфигурации со ссылкой, которую загрузчик Xray отклонил бы."""

    part: str
    path: str
    family: str


@dataclass(frozen=True, slots=True)
class GeoDataView:
    """Инвентарь файлов, сопоставленные ссылки и счётчики без доменов, адресов и кодов наборов."""

    files: tuple[GeoDatabaseFileView, ...]
    present_count: int
    missing_count: int
    extra_count: int
    references: tuple[GeoReferenceView, ...]
    reference_count: int
    resolved_count: int
    unresolved_count: int
    unsupported_references: tuple[UnsupportedGeoReferenceView, ...]

    @classmethod
    def from_state(cls, state: GeoDataState) -> "GeoDataView":
        """Построить представление из безопасной диагностики домена."""
        diagnostic = state.to_diagnostic()
        return cls(
            files=tuple(GeoDatabaseFileView(**_fields(GeoDatabaseFileView, item)) for item in diagnostic["files"]),
            present_count=diagnostic["present_count"],
            missing_count=diagnostic["missing_count"],
            extra_count=diagnostic["extra_count"],
            references=tuple(GeoReferenceView(**_fields(GeoReferenceView, item)) for item in diagnostic["references"]),
            reference_count=diagnostic["reference_count"],
            resolved_count=diagnostic["resolved_count"],
            unresolved_count=diagnostic["unresolved_count"],
            unsupported_references=tuple(
                UnsupportedGeoReferenceView(**_fields(UnsupportedGeoReferenceView, item))
                for item in diagnostic["unsupported_references"]
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            **_view_dict(self),
            "files": [_view_dict(item) for item in self.files],
            "references": [_view_dict(item) for item in self.references],
            "unsupported_references": [_view_dict(item) for item in self.unsupported_references],
        }


@dataclass(frozen=True, slots=True)
class XrayProcessView:
    """PID, маркер и согласованность; ни одно состояние не подтверждает готовность канала."""

    process_count: int
    pids: tuple[int, ...]
    ready_marker: bool
    state: str
    consistent: bool

    @classmethod
    def from_observation(cls, observation: XrayProcessObservation) -> "XrayProcessView":
        """Построить представление из диагностики наблюдения."""
        diagnostic = observation.to_diagnostic()
        return cls(**{**_fields(XrayProcessView, diagnostic), "pids": tuple(diagnostic["pids"])})

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {**_view_dict(self), "pids": list(self.pids)}


@dataclass(frozen=True, slots=True)
class InstallationView:
    """Безопасное представление прочитанной установки из четырёх областей.

    Состав полей каждой области задают её сценарий и модели. Секреты,
    домены, адреса правил, MAC и имена устройств сюда не входят.
    """

    keenetic: KeeneticStateView
    proxy: ProxyConfigView
    geodata: GeoDataView
    xray_process: XrayProcessView

    def to_dict(self) -> dict[str, object]:
        """Вернуть JSON-совместимое представление."""
        return {
            "keenetic": self.keenetic.to_dict(),
            "proxy": self.proxy.to_dict(),
            "geodata": self.geodata.to_dict(),
            "xray_process": self.xray_process.to_dict(),
        }


_UNAVAILABLE = {
    "geodata": ("geo_databases_unavailable", "Не удалось прочитать инвентарь файлов геобаз."),
    "process": ("xray_process_unavailable", "Не удалось наблюдать процесс Xray и маркер готовности."),
}
_INVALID = {
    "geodata": (
        "invalid_geo_databases", GeoDatabaseInventory, validate_geo_inventory,
        "Источник вернул инвентарь геобаз в неподдерживаемом формате.",
        "Источник вернул некорректный инвентарь геобаз.",
    ),
    "process": (
        "invalid_xray_process", XrayProcessObservation, validate_xray_process_observation,
        "Источник вернул наблюдение процесса Xray в неподдерживаемом формате.",
        "Источник вернул некорректное наблюдение процесса Xray.",
    ),
}
_DOMAIN_ERRORS = (GeoDataError, XrayProcessError)


def _unavailable(source: str) -> ErrorDetail:
    code, message = _UNAVAILABLE[source]
    return ErrorDetail(ErrorCategory.SOURCE_FAILED, code, message)


def _check_model(source: str, value: object) -> ErrorDetail | None:
    """Проверить тип ответа и повторно проверить модель вместе с вложенными записями."""
    code, model_type, validate, type_message, data_message = _INVALID[source]
    if type(value) is not model_type:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, type_message)
    try:
        validate(value)
    except _DOMAIN_ERRORS as error:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, data_message, reason=error.code.value)
    except Exception:
        return ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, code, type_message)
    return None


class InspectInstallationHandler:
    """Прочитать четыре области в фиксированном порядке и собрать одно представление.

    Порядок: состояние Keenetic через его обработчик, конфигурация Xray и XKeen
    через её обработчик, инвентарь геобаз, наблюдение процесса. Каждый источник
    вызывается один раз; отказ или некорректный ответ любого из них завершает
    сценарий тем же отдельным кодом, что и у области, без частичного результата.
    """

    def __init__(
        self,
        keenetic: InspectKeeneticStateHandler,
        proxy: InspectProxyConfigHandler,
        geodata: GeoDatabaseSource,
        processes: XrayProcessSource,
        *,
        operation_ids: OperationIdFactory = new_operation_id,
    ) -> None:
        self._keenetic = keenetic
        self._proxy = proxy
        self._geodata = geodata
        self._processes = processes
        self._operation_ids = operation_ids

    def execute(self, command: InspectInstallation) -> Result[InstallationView]:
        """Выполнить чтение; ожидаемые отказы возвращаются через Result."""
        operation_id = self._operation_ids()
        name = InspectInstallation.name
        if type(command) is not InspectInstallation:
            return failed(operation_id, name, invalid_command())
        error = check_contract_version(command.contract_version)
        if error is not None:
            return failed(operation_id, name, error)

        keenetic = self._keenetic.read()
        if isinstance(keenetic, ErrorDetail):
            return failed(operation_id, name, keenetic)
        proxy = self._proxy.read()
        if isinstance(proxy, ErrorDetail):
            return failed(operation_id, name, proxy)

        models: dict[str, object] = {}
        for source, read in (
            ("geodata", self._geodata.current_geo_databases),
            ("process", self._processes.current_xray_process),
        ):
            try:
                value = read()
            except Exception:
                # Текст и цепочка исключения источника могут содержать пути и вывод команд.
                return failed(operation_id, name, _unavailable(source))
            error = _check_model(source, value)
            if error is not None:
                return failed(operation_id, name, error)
            models[source] = value

        try:
            geodata = assemble_geodata_state(models["geodata"], proxy.xray)
        except GeoDataError as error:
            return failed(operation_id, name, ErrorDetail(
                ErrorCategory.INVALID_SOURCE_DATA, "installation_inconsistent",
                "Прочитанные источники установки не удалось согласовать.", reason=error.code.value,
            ))
        view = InstallationView(
            KeeneticStateView.from_state(keenetic),
            ProxyConfigView.from_models(proxy),
            GeoDataView.from_state(geodata),
            XrayProcessView.from_observation(models["process"]),
        )
        return succeeded(operation_id, name, view)
