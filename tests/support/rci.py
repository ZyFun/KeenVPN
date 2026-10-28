"""Подставное соединение RCI для тестов транспорта и источников без сокетов.

Соединение отвечает по пути запроса заданным ответом и записывает каждый
вызов. Методов, кроме `connect`, `request`, `getresponse` и `close`, у него
нет: обращение к любому другому атрибуту записывается и поднимает
AssertionError, поэтому тест видит и попытку записи, и попытку обойти
`request`. Ответы снимка — сериализованные в тесте ответы фикстуры
`keenetic.json`; фикстура не меняется.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
import json

from keenvpn.adapters.keenetic_rci_http import RciResource, read_rci
from keenvpn.adapters.router_sources import (
    KeeneticHotspotRuntimeRci, KeeneticHotspotSettingsRci, KeeneticPoliciesRci, KeeneticRegistrationsRci,
)
from tests.support.snapshot import load_keenetic_snapshot


_DECLARED = object()
"""Объявленная длина по умолчанию — размер тела, как у ответа с `Content-Length`."""


@dataclass
class RciReply:
    """Ответ подставного соединения; `length=None` — тело без объявленной длины (chunked или до закрытия)."""

    status: int = 200
    body: bytes = b"{}"
    length: object = _DECLARED
    chunk: int = 1024
    """Сколько байт `read1` отдаёт за вызов, чтобы чтение шло порциями."""
    fail_after: int | None = None
    """После стольких отданных байт `read1` поднимает `failure`."""
    failure: BaseException | None = None


class FakeResponse:
    """Ответ с семантикой `http.client`: `read1` не выходит за объявленную длину и уменьшает её."""

    def __init__(self, reply: RciReply, log: list[tuple]) -> None:
        self._reply = reply
        self._log = log
        self._position = 0
        self.status = reply.status
        self.length = len(reply.body) if reply.length is _DECLARED else reply.length
        self.closed = False

    def read1(self, size: int) -> bytes:
        self._log.append(("read1", size))
        reply = self._reply
        if reply.fail_after is not None and self._position >= reply.fail_after:
            raise reply.failure
        if self.length is not None:
            size = min(size, self.length)
        stop = min(len(reply.body), self._position + min(size, reply.chunk))
        if reply.fail_after is not None:
            stop = min(stop, reply.fail_after)
        chunk = reply.body[self._position:stop]
        self._position = stop
        if self.length is not None:
            self.length -= len(chunk)
        return chunk

    def close(self) -> None:
        self._log.append(("response.close",))
        self.closed = True


class FakeConnection:
    """Соединение без сокета: журнал вызовов и ответ по пути; запрещённые атрибуты поднимают AssertionError."""

    def __init__(self, script: "ScriptedRci", deadline: float) -> None:
        object.__setattr__(self, "deadline", deadline)
        object.__setattr__(self, "calls", [])
        object.__setattr__(self, "_script", script)
        object.__setattr__(self, "_path", None)
        object.__setattr__(self, "response", None)

    def __getattr__(self, name: str) -> object:
        self.calls.append(("forbidden", name))
        raise AssertionError(f"Транспорт обратился к атрибуту соединения {name!r}.")

    def __setattr__(self, name: str, value: object) -> None:
        self.calls.append(("forbidden", name))
        raise AssertionError(f"Транспорт изменил атрибут соединения {name!r}.")

    def _fail(self, stage: str) -> None:
        failure = self._script.failures.get(stage)
        if failure is not None:
            raise failure

    def connect(self) -> None:
        self.calls.append(("connect",))
        self._fail("connect")

    def request(self, *args: object, **kwargs: object) -> None:
        self.calls.append(("request", args, kwargs))
        if len(args) == 2 and type(args[1]) is str:
            object.__setattr__(self, "_path", args[1])
        self._fail("request")

    def getresponse(self) -> FakeResponse:
        self.calls.append(("getresponse",))
        self._fail("getresponse")
        response = FakeResponse(self._script.replies[self._path], self.calls)
        object.__setattr__(self, "response", response)
        return response

    def close(self) -> None:
        self.calls.append(("close",))


def snapshot_rci_replies() -> dict[str, RciReply]:
    """Ответы четырёх ресурсов: JSON фикстуры, сериализованный в тесте, по путям запроса."""
    snapshot = load_keenetic_snapshot()
    return {
        resource.path: RciReply(body=json.dumps(snapshot[resource.value], ensure_ascii=False).encode("utf-8"))
        for resource in RciResource
    }


@dataclass
class ScriptedRci:
    """Фабрика подставных соединений: ответ по пути, отказы по этапу, журнал всех соединений."""

    replies: dict[str, RciReply] = field(default_factory=snapshot_rci_replies)
    failures: dict[str, BaseException] = field(default_factory=dict)
    """Отказ этапа `connect`, `request` или `getresponse`."""
    connections: list[FakeConnection] = field(default_factory=list)

    def __call__(self, deadline: float) -> FakeConnection:
        connection = FakeConnection(self, deadline)
        self.connections.append(connection)
        return connection

    def read(self, resource: RciResource) -> dict[str, object]:
        """`read_rci` с этой фабрикой: так источники читают без сокетов."""
        return read_rci(resource, connect=self)

    @property
    def paths(self) -> tuple[str, ...]:
        """Пути запросов по порядку соединений."""
        return tuple(call[1][1] for connection in self.connections for call in connection.calls if call[0] == "request")


def rci_sources(script: ScriptedRci) -> Mapping[str, object]:
    """Четыре источника Keenetic поверх подставного соединения, по именам полей `MenuSources`."""
    return {
        "policies": KeeneticPoliciesRci(read=script.read),
        "hotspot": KeeneticHotspotSettingsRci(read=script.read),
        "registrations": KeeneticRegistrationsRci(read=script.read),
        "runtime": KeeneticHotspotRuntimeRci(read=script.read),
    }
