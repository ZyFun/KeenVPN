"""Локальный транспорт RCI Keenetic: только чтение четырёх ресурсов на адресе обратной петли.

Запрос — `GET` без тела к `127.0.0.1:79` по пути из закрытого перечня
`RciResource`; путь из ввода не собирается. `http.client` не читает
переменные прокси окружения и не следует перенаправлениям: любой код ответа,
кроме 200, — отказ. Подключение ограничено 2 с, весь запрос — 5 с общим
сроком: перед каждым ожиданием сокета таймаут равен оставшемуся времени,
поэтому медленная выдача заголовков или тела не растягивает запрос. Тело
читается порциями, всего не больше предела плюс один байт. Ответ должен быть
строгим JSON-объектом в UTF-8 без вложенного статуса ошибки RCI.

Методов записи в модуле нет. Отказы — `RouterReadError` с безопасным кодом:
адрес, путь, тело ответа, сообщения RCI и текст чужого исключения в ошибку
не попадают. Успешное чтение не подтверждает работу VPN.
"""

from collections.abc import Callable
from enum import Enum
import http.client
import socket
import time

from keenvpn.adapters.entware_files import fail_read
from keenvpn.adapters.keenetic_rci import (
    HOTSPOT_RUNTIME_RESOURCE, HOTSPOT_SETTINGS_RESOURCE, POLICIES_RESOURCE, REGISTRATIONS_RESOURCE,
)
from keenvpn.application.ports import RouterReadFailure
from keenvpn.domain.config_document import ConfigDocumentError, parse_strict_json_object


RCI_HOST = "127.0.0.1"
"""Адрес обратной петли: служебный порт RCI доступен только на самом роутере."""
RCI_PORT = 79
RCI_PATH_PREFIX = "/rci/"
CONNECT_TIMEOUT = 2.0
"""Секунды на установку соединения."""
REQUEST_TIMEOUT = 5.0
"""Секунды на весь запрос: подключение, отправка и ответ до последнего байта."""
RESPONSE_LIMIT = 4 * 1024 * 1024
"""Предел тела ответа; самый большой из четырёх ресурсов на проверенной платформе — десятки килобайт."""
_CHUNK = 64 * 1024
_REQUEST_HEADERS = {"Accept": "application/json", "Connection": "close"}
_HTTP_OK = 200


class RciResource(Enum):
    """Закрытый перечень читаемых ресурсов RCI; другие пути не запрашиваются."""

    POLICIES = POLICIES_RESOURCE
    HOTSPOT_SETTINGS = HOTSPOT_SETTINGS_RESOURCE
    REGISTRATIONS = REGISTRATIONS_RESOURCE
    HOTSPOT_RUNTIME = HOTSPOT_RUNTIME_RESOURCE

    @property
    def path(self) -> str:
        """Путь запроса: префикс RCI и имя ресурса."""
        return RCI_PATH_PREFIX + self.value


def _remaining(deadline: float) -> float:
    """Время до крайнего срока; истёкший срок — TimeoutError."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


class _DeadlineSocket(socket.socket):
    """TCP-сокет с общим сроком: каждое ожидание отправки и приёма ограничено оставшимся временем.

    `http.client` читает заголовки и тело через `makefile`, который вызывает
    `recv_into` этого сокета. Таймаут сокета сам по себе ограничивает только
    одно ожидание, и сервер, выдающий ответ по байту, растянул бы запрос.
    """

    __slots__ = ("_deadline",)

    def __init__(self, deadline: float) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self._deadline = deadline

    def sendall(self, data: bytes, flags: int = 0) -> None:
        self.settimeout(_remaining(self._deadline))
        super().sendall(data, flags)

    def recv_into(self, buffer: bytearray | memoryview, nbytes: int = 0, flags: int = 0) -> int:
        self.settimeout(_remaining(self._deadline))
        return super().recv_into(buffer, nbytes, flags)


class LoopbackConnection(http.client.HTTPConnection):
    """HTTP-соединение только с адресом обратной петли и общим сроком запроса.

    Хост — константа; порт отличается от служебного только в тестах с
    локальным сервером. Туннель прокси не настраивается.
    """

    def __init__(self, deadline: float, *, port: int = RCI_PORT) -> None:
        if type(deadline) is not float:
            raise TypeError("Крайний срок запроса задаётся значением time.monotonic().")
        if type(port) is not int or not 0 < port < 65536:
            raise ValueError("Порт локального интерфейса управления задаётся числом от 1 до 65535.")
        super().__init__(RCI_HOST, port, timeout=CONNECT_TIMEOUT)
        self._deadline = deadline

    def connect(self) -> None:
        """Подключиться не дольше `CONNECT_TIMEOUT` и оставшегося срока запроса."""
        sock = _DeadlineSocket(self._deadline)
        try:
            sock.settimeout(min(CONNECT_TIMEOUT, _remaining(self._deadline)))
            sock.connect((RCI_HOST, self.port))
        except BaseException:
            sock.close()
            raise
        self.sock = sock


ConnectionFactory = Callable[[float], http.client.HTTPConnection]
"""Создание соединения по крайнему сроку запроса (`time.monotonic()`).

`read_rci` вызывает у соединения только `connect`, `request`, `getresponse`
и `close`, а у ответа — `status`, `length`, `read1` и `close`; тесты
подставляют объект с этими методами.
"""


def _body(response: http.client.HTTPResponse) -> bytes:
    """Проверить код ответа и прочитать тело не больше предела плюс один байт."""
    if response.status != _HTTP_OK:
        fail_read(RouterReadFailure.HTTP_STATUS)
    if response.length is not None and response.length > RESPONSE_LIMIT:
        # Объявленная длина больше предела: тело не читается.
        fail_read(RouterReadFailure.TOO_LARGE)
    chunks = []
    size = 0
    while chunk := response.read1(min(_CHUNK, RESPONSE_LIMIT + 1 - size)):
        size += len(chunk)
        if size > RESPONSE_LIMIT:
            fail_read(RouterReadFailure.TOO_LARGE)
        chunks.append(chunk)
    if response.length:
        # Соединение закрылось раньше объявленной длины: `read1` об этом не сообщает.
        fail_read(RouterReadFailure.INVALID_RESPONSE)
    return b"".join(chunks)


def _exchange(connection: http.client.HTTPConnection, path: str) -> bytes:
    """Подключиться, отправить запрос и прочитать тело; отказ — RouterReadError."""
    try:
        connection.connect()
    except TimeoutError:
        fail_read(RouterReadFailure.TIMEOUT)
    except OSError:
        fail_read(RouterReadFailure.CONNECTION_FAILED)
    try:
        connection.request("GET", path, headers=_REQUEST_HEADERS)
        response = connection.getresponse()
        try:
            return _body(response)
        finally:
            response.close()
    except TimeoutError:
        fail_read(RouterReadFailure.TIMEOUT)
    except http.client.HTTPException:
        # Сюда входят обрыв до строки статуса, неполное тело и нарушения протокола.
        fail_read(RouterReadFailure.INVALID_RESPONSE)
    except OSError:
        fail_read(RouterReadFailure.IO_ERROR)


def _reports_error(value: object) -> bool:
    """Найти объект с `status`, равным `error`, на любой глубине: так RCI сообщает об ошибке при коде 200."""
    if type(value) is dict:
        return value.get("status") == "error" or any(_reports_error(item) for item in value.values())
    if type(value) is list:
        return any(_reports_error(item) for item in value)
    return False


def _document(body: bytes) -> dict[str, object]:
    """Разобрать тело как строгий JSON-объект в UTF-8 и отклонить вложенный статус ошибки RCI."""
    try:
        document = parse_strict_json_object(body.decode("utf-8"), comments=False)
    except (UnicodeDecodeError, ConfigDocumentError):
        fail_read(RouterReadFailure.INVALID_RESPONSE)
    if _reports_error(document):
        fail_read(RouterReadFailure.RCI_ERROR)
    return document


def read_rci(resource: RciResource, *, connect: ConnectionFactory = LoopbackConnection) -> dict[str, object]:
    """Прочитать один ресурс RCI и вернуть разобранный JSON-объект; отказ — RouterReadError.

    Соединение создаётся на один запрос и закрывается при любом исходе.
    Ответ передаётся преобразователям `keenetic_rci` без изменений.
    """
    if type(resource) is not RciResource:
        raise TypeError("Ресурс RCI задаётся RciResource.")
    if not callable(connect):
        raise TypeError("Соединение задаётся вызываемым объектом.")
    connection = connect(time.monotonic() + REQUEST_TIMEOUT)
    try:
        body = _exchange(connection, resource.path)
    finally:
        connection.close()
    return _document(body)
