"""Управляемые реализации используемых портов только для локальных тестов.

Ответы задаёт тест: модели возвращаются как есть, экземпляр BaseException
вызывается как отказ. Any намеренно допускает некорректные ответы для проверки
границы application. Здесь нет чтения баз, сети, файлов или процессов.
Используйте только искусственные данные, в том числе в исключениях.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from keenvpn.application.ports import (
    ConnectionLinkParser, ConnectionProfileSource, GeoDataSource, KeeneticHotspotRuntimeSource,
    KeeneticHotspotSettingsSource, KeeneticPolicySource, KeeneticRegistrationSource, RoutingPolicySource,
)
from keenvpn.domain.connection import TrojanConnection
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicySet
from keenvpn.domain.profile import ConnectionProfile
from keenvpn.domain.routing import DomainCondition, GeoIPCondition, GeoSiteCondition
from keenvpn.domain.routing_explanation import GeoMatch, IPSource, RoutingContext
from keenvpn.domain.routing_policy import RoutingPolicy


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
