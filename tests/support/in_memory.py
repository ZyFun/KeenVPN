"""Управляемые реализации используемых портов только для локальных тестов.

Ответы задаёт тест: модели возвращаются как есть, экземпляр BaseException
вызывается как отказ. Any намеренно допускает некорректные ответы для проверки
границы application. Здесь нет чтения баз, сети, файлов или процессов.
Используйте только искусственные данные, в том числе в исключениях.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn
from uuid import UUID

from keenvpn.application.ports import (
    ConnectionLinkParser, ConnectionProfileSource, GeoDatabaseSource, GeoDataSource, KeeneticHotspotRuntimeSource,
    KeeneticHotspotSettingsSource, KeeneticPolicySource, KeeneticRegistrationSource, ManagerMetadataStore,
    ManagerMetadataStoreError, MetadataStoreFailure, RoutingPolicySource, StoragePlacementSource, XKeenInitSource,
    XKeenListSource, XKeenSettingsSource, XrayConfigSource, XrayProcessSource,
)
from keenvpn.domain.connection import TrojanConnection
from keenvpn.domain.geodata import GeoDatabaseInventory
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicySet
from keenvpn.domain.manager_metadata import (
    ManagerMetadata, ManagerMetadataError, StoragePlacement, StoredManagerMetadata, decode_manager_metadata,
    encode_manager_metadata, metadata_revision,
)
from keenvpn.domain.profile import ConnectionProfile
from keenvpn.domain.routing import DomainCondition, GeoIPCondition, GeoSiteCondition
from keenvpn.domain.routing_explanation import GeoMatch, IPSource, RoutingContext
from keenvpn.domain.routing_policy import RoutingPolicy
from keenvpn.domain.xkeen_config import XKeenInitParameters, XKeenList, XKeenListName, XKeenSettings
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation


_UNSET = object()


class AdapterSetupError(BaseException):
    """Ошибка подготовки теста, а не отказ источника.

    Наследует BaseException, чтобы `except Exception` сценария не превратил её
    в source_failed: иначе тест отказа проходил бы без настроенного отказа.
    """


class UnconfiguredResponseError(AdapterSetupError):
    """Тест не задал ответ для вызванного порта или точного запроса."""

    def __init__(self) -> None:
        super().__init__("Ответ тестового адаптера не задан.")


def _release(outcome: Any) -> None:
    """Отпустить кадры прошлого вызова и чужой __context__ настроенного отказа."""
    if isinstance(outcome, BaseException):
        outcome.__context__ = None
        outcome.__traceback__ = None


def _resolve(outcome: Any) -> Any:
    """Вернуть заданные данные либо передать отказ без успешной подмены."""
    if outcome is _UNSET:
        raise UnconfiguredResponseError()
    if isinstance(outcome, type) and issubclass(outcome, BaseException):
        raise AdapterSetupError("Отказ задаётся экземпляром исключения, а не классом.")
    if isinstance(outcome, BaseException):
        # Повторяемый ответ — один объект. Без сброса он накапливал бы кадры
        # всех прошлых вызовов и сохранял бы __context__ чужого исключения.
        _release(outcome)
        raise outcome
    return outcome


class _ScriptedPort:
    """Повторяемый ответ одного метода порта; outcome можно заменить между вызовами."""

    def __init__(self, outcome: Any = _UNSET) -> None:
        self._outcome = outcome
        self.calls = 0

    @property
    def outcome(self) -> Any:
        """Настроенный ответ метода порта."""
        return self._outcome

    @outcome.setter
    def outcome(self, outcome: Any) -> None:
        # Тест часто держит заменяемый отказ в переменной: без сброса он
        # удерживал бы кадры обработчика вместе с командой и её секретами.
        _release(self._outcome)
        self._outcome = outcome

    def _respond(self) -> Any:
        """Учесть обращение, включая отказ, и вернуть настроенный ответ."""
        self.calls += 1
        return _resolve(self.outcome)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(calls={self.calls})"


class InMemoryRoutingPolicySource(_ScriptedPort, RoutingPolicySource):
    """Заданный ответ источника правил маршрутизации."""

    def current_routing_policy(self) -> RoutingPolicy:
        return self._respond()


class InMemoryKeeneticPolicySource(_ScriptedPort, KeeneticPolicySource):
    """Заданный список политик Keenetic; роутер и RCI не читаются."""

    def current_policies(self) -> KeeneticPolicySet:
        return self._respond()


class InMemoryKeeneticHotspotSettingsSource(_ScriptedPort, KeeneticHotspotSettingsSource):
    """Заданные настройки hotspot Keenetic; читаются отдельно от регистрации и runtime."""

    def current_hotspot_settings(self) -> KeeneticHotspotSettings:
        return self._respond()


class InMemoryKeeneticRegistrationSource(_ScriptedPort, KeeneticRegistrationSource):
    """Заданный реестр регистраций Keenetic."""

    def current_registrations(self) -> KeeneticRegistrations:
        return self._respond()


class InMemoryKeeneticHotspotRuntimeSource(_ScriptedPort, KeeneticHotspotRuntimeSource):
    """Заданное наблюдаемое состояние клиентов Keenetic."""

    def current_hotspot_runtime(self) -> KeeneticHotspotRuntime:
        return self._respond()


class InMemoryXrayConfigSource(_ScriptedPort, XrayConfigSource):
    """Заданный набор частей конфигурации Xray; файлы и Xray не читаются."""

    def current_xray_config(self) -> XrayConfigSet:
        return self._respond()


class InMemoryXKeenSettingsSource(_ScriptedPort, XKeenSettingsSource):
    """Заданные настройки `xkeen.json`."""

    def current_xkeen_settings(self) -> XKeenSettings:
        return self._respond()


class InMemoryXKeenInitSource(_ScriptedPort, XKeenInitSource):
    """Заданные параметры init XKeen; текст init не исполняется и не читается."""

    def current_xkeen_init(self) -> XKeenInitParameters:
        return self._respond()


class InMemoryGeoDatabaseSource(_ScriptedPort, GeoDatabaseSource):
    """Заданный инвентарь файлов геобаз; каталог и файлы не читаются."""

    def current_geo_databases(self) -> GeoDatabaseInventory:
        return self._respond()


class InMemoryXrayProcessSource(_ScriptedPort, XrayProcessSource):
    """Заданное наблюдение процесса Xray; `pidof`, файлы и команды XKeen не вызываются."""

    def current_xray_process(self) -> XrayProcessObservation:
        return self._respond()


class InMemoryStoragePlacementSource(_ScriptedPort, StoragePlacementSource):
    """Заданное обнаруженное размещение; монтирования, UUID, каталоги и файлы не читаются."""

    def current_storage_placement(self) -> StoragePlacement:
        return self._respond()


@dataclass(frozen=True, slots=True, repr=False)
class MetadataWriteCall:
    """Запрос записи метаданных: модель и ожидаемая ревизия.

    Поля доступны тесту явно; `repr` показывает только, ожидалось ли отсутствие файла.
    """

    metadata: Any
    expected_revision: Any

    def __repr__(self) -> str:
        expected = "None" if self.expected_revision is None else "ревизия"
        return f"MetadataWriteCall(expected={expected})"


def _store_failure(failure: MetadataStoreFailure, reason: str | None = None) -> NoReturn:
    """Отказ хранилища без активного чужого исключения в цепочке, как у файлового адаптера."""
    try:
        raise ManagerMetadataStoreError(failure, reason=reason) from None
    except ManagerMetadataStoreError as error:
        error.__context__ = None
        raise


def _checked_content(content: Any) -> bytes | None:
    if content is not None and type(content) is not bytes:
        raise AdapterSetupError("Содержимое файла метаданных задаётся bytes или None.")
    return content


def _checked_failure(outcome: Any) -> BaseException | None:
    if outcome is None or isinstance(outcome, BaseException):
        return outcome
    raise AdapterSetupError("Отказ хранилища задаётся экземпляром исключения или None.")


class InMemoryManagerMetadataStore(ManagerMetadataStore):
    """Файл метаданных в памяти с семантикой ревизии `ManagerMetadataFiles`.

    `content` — байты файла или `None`, если его нет. Чтение разбирает их
    штатным `decode_manager_metadata`: повреждённые байты и другая версия
    схемы дают `invalid_stored_metadata` с кодом домена в `reason`. Запись
    сначала кодирует модель штатным `encode_manager_metadata` (некорректная —
    `ManagerMetadataError` без изменений), затем сверяет текущую ревизию
    с ожидаемой: `None` — файла быть не должно, расхождение —
    `metadata_revision_conflict`, повреждённый файл не перезаписывается.
    Совпадающие байты не публикуются повторно. Возвращается SHA-256 байтов.

    Отказы задаются экземплярами исключений и повторяются до замены:
    `read_failure` — при чтении; `write_failure` — при записи до сверки
    ревизии без изменения байтов, а при `publish_before_failure=True` — после
    сверки и публикации, как `metadata_write_unconfirmed` файлового хранилища.
    `before_revision_check` вызывается при записи непосредственно перед
    сверкой ревизии: так тест имитирует внешнюю правку в последний момент.
    Каталоги, файлы и блокировки не используются.
    """

    def __init__(self, content: bytes | None = None) -> None:
        self._content = _checked_content(content)
        self._read_failure: BaseException | None = None
        self._write_failure: BaseException | None = None
        self.publish_before_failure = False
        self.before_revision_check: Callable[[], None] | None = None
        self.read_calls = 0
        self.publications = 0
        self._write_calls: list[MetadataWriteCall] = []

    @property
    def content(self) -> bytes | None:
        """Текущие байты файла или None."""
        return self._content

    @content.setter
    def content(self, content: bytes | None) -> None:
        # Замена байтов тестом — внешняя правка файла в обход хранилища.
        self._content = _checked_content(content)

    @property
    def read_failure(self) -> BaseException | None:
        """Настроенный отказ чтения."""
        return self._read_failure

    @read_failure.setter
    def read_failure(self, outcome: BaseException | None) -> None:
        checked = _checked_failure(outcome)
        _release(self._read_failure)
        self._read_failure = checked

    @property
    def write_failure(self) -> BaseException | None:
        """Настроенный отказ записи."""
        return self._write_failure

    @write_failure.setter
    def write_failure(self, outcome: BaseException | None) -> None:
        checked = _checked_failure(outcome)
        _release(self._write_failure)
        self._write_failure = checked

    @property
    def write_calls(self) -> tuple[MetadataWriteCall, ...]:
        """Неизменяемая история запросов записи, включая отклонённые."""
        return tuple(self._write_calls)

    def read_metadata(self) -> StoredManagerMetadata | None:
        self.read_calls += 1
        if self._read_failure is not None:
            _resolve(self._read_failure)
        return self._current()

    def write_metadata(self, metadata: ManagerMetadata, expected_revision: str | None) -> str:
        self._write_calls.append(MetadataWriteCall(metadata, expected_revision))
        content = encode_manager_metadata(metadata)
        revision = metadata_revision(content)
        failure = self._write_failure
        if failure is not None and not self.publish_before_failure:
            _resolve(failure)
        if self.before_revision_check is not None:
            self.before_revision_check()
        current = self._current()
        if (None if current is None else current.revision) != expected_revision:
            _store_failure(MetadataStoreFailure.CONFLICT)
        if current is None or current.revision != revision:
            self._content = content
            self.publications += 1
        if failure is not None:
            _resolve(failure)
        return revision

    def _current(self) -> StoredManagerMetadata | None:
        if self._content is None:
            return None
        code = None
        try:
            return decode_manager_metadata(self._content)
        except ManagerMetadataError as error:
            code = error.code
        _store_failure(MetadataStoreFailure.INVALID, code.value)

    def __repr__(self) -> str:
        return (
            f"InMemoryManagerMetadataStore(present={self._content is not None}, read_calls={self.read_calls}, "
            f"write_calls={len(self._write_calls)}, publications={self.publications})"
        )


class InMemoryXKeenListSource(XKeenListSource):
    """Ответы по точному имени списка; незаданное имя — ошибка подготовки теста."""

    def __init__(self) -> None:
        self._responses: dict[XKeenListName, Any] = {}
        self._calls: list[XKeenListName] = []

    @property
    def calls(self) -> tuple[XKeenListName, ...]:
        """Неизменяемая история запрошенных имён списков."""
        return tuple(self._calls)

    def set_response(self, name: XKeenListName, outcome: Any) -> None:
        """Настроить ответ одного списка, освобождая кадры прежнего отказа."""
        if type(name) is not XKeenListName:
            raise AdapterSetupError("Ответ списка требует имя XKeenListName.")
        _release(self._responses.get(name))
        self._responses[name] = outcome

    def current_xkeen_list(self, name: XKeenListName) -> XKeenList:
        self._calls.append(name)
        return _resolve(self._responses.get(name, _UNSET))

    def __repr__(self) -> str:
        return f"InMemoryXKeenListSource(calls={len(self._calls)}, responses={len(self._responses)})"


class InMemoryConnectionLinkParser(_ScriptedPort, ConnectionLinkParser):
    """Заданный ответ парсера без разбора и сохранения переданной ссылки.

    Для проверки самого формата URI используйте настоящий TrojanLinkParser.
    """

    def parse(self, link: str) -> TrojanConnection:
        """Учесть вызов; ссылка не остаётся в полях адаптера и в его кадре."""
        del link
        return self._respond()


class InMemoryConnectionProfileSource(ConnectionProfileSource):
    """Ответы по точному ID; отсутствие профиля задаётся явно через None."""

    def __init__(self) -> None:
        self._responses: dict[UUID, Any] = {}
        self._calls: list[UUID] = []

    @property
    def calls(self) -> tuple[UUID, ...]:
        """Неизменяемая история запрошенных идентификаторов."""
        return tuple(self._calls)

    def set_response(self, profile_id: UUID, outcome: Any) -> None:
        """Настроить ответ точного запроса, освобождая кадры прежнего отказа."""
        if type(profile_id) is not UUID or profile_id.int == 0:
            raise AdapterSetupError("Ответ профиля требует непустой UUID.")
        _release(self._responses.get(profile_id))
        self._responses[profile_id] = outcome

    def get_profile(self, profile_id: UUID) -> ConnectionProfile | None:
        self._calls.append(profile_id)
        return _resolve(self._responses.get(profile_id, _UNSET))

    def __repr__(self) -> str:
        return f"InMemoryConnectionProfileSource(calls={len(self._calls)}, responses={len(self._responses)})"


@dataclass(frozen=True, slots=True, repr=False)
class GeoDataCall:
    """Точный запрос к источнику; значения доступны явно, но скрыты в repr."""

    condition: GeoIPCondition | GeoSiteCondition
    values: tuple[str, ...]

    def __repr__(self) -> str:
        return f"GeoDataCall({type(self.condition).__name__}, значений={len(self.values)})"


def _canonical_values(
    condition: GeoIPCondition | GeoSiteCondition, values: tuple[str, ...],
) -> tuple[str, ...]:
    """Привести значения ключа к форме, в которой их передаёт сценарий.

    Нормализацию выполняет доменная модель, как в RoutingContext.
    """
    if type(values) is not tuple or not all(isinstance(value, str) for value in values):
        raise TypeError("Значения запроса задаются tuple строк.")
    if isinstance(condition, GeoIPCondition):
        return RoutingContext(ips=values, ip_source=IPSource.DNS).ips
    if isinstance(condition, GeoSiteCondition):
        return tuple(DomainCondition(value).value for value in values)
    raise TypeError("Условие запроса должно быть GeoIPCondition или GeoSiteCondition.")


class InMemoryGeoDataSource(GeoDataSource):
    """Ответы по точным запросам, включая базу, набор и весь tuple значений.

    Ответ сохраняется для повторных вызовов. Незаданный запрос вызывает ошибку
    подготовки теста; UNKNOWN, NO_MATCH и MATCH задаются явно через GeoMatch.
    Членство в геонаборах здесь не вычисляется.
    """

    def __init__(self) -> None:
        self._responses: dict[GeoDataCall, Any] = {}
        self._calls: list[GeoDataCall] = []

    @property
    def calls(self) -> tuple[GeoDataCall, ...]:
        """Неизменяемый снимок истории обращений в порядке вызова."""
        return tuple(self._calls)

    def set_response(
        self, condition: GeoIPCondition | GeoSiteCondition, values: tuple[str, ...], outcome: Any,
    ) -> None:
        """Задать или заменить ответ одного точного запроса в памяти.

        Заменяемый отказ отпускает кадры последнего вызова, как и замена outcome.
        """
        call = GeoDataCall(condition, _canonical_values(condition, values))
        _release(self._responses.get(call))
        self._responses[call] = outcome

    def match(self, condition: GeoIPCondition | GeoSiteCondition, values: tuple[str, ...]) -> GeoMatch:
        """Записать запрос и вернуть только явно настроенный для него ответ."""
        call = GeoDataCall(condition, values)
        self._calls.append(call)
        return _resolve(self._responses.get(call, _UNSET))

    def __repr__(self) -> str:
        return f"InMemoryGeoDataSource(calls={len(self._calls)}, responses={len(self._responses)})"
