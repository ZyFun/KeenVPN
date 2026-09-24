"""Чистый разбор Trojan URI без запуска команд, соединений и записи файлов."""

from enum import StrEnum
from ipaddress import IPv6Address
import re
from urllib.parse import unquote

from keenvpn.domain.connection import SecretValue, TrojanConnection


MAX_URI_LENGTH = 16_384
_PARAMETERS = frozenset({"security", "type", "sni", "host", "path", "fp"})
_ENDPOINT = re.compile(r"(?P<server>\[[^\]]+\]|[^:/?#@\s\\\[\]]+):(?P<port>[^:/?#@\s\\\[\]]*)")
_PORT = re.compile(r"[0-9]{1,5}")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


class TrojanURIErrorCode(StrEnum):
    """Причина отказа без включения входных значений."""

    INVALID_URI = "invalid_uri"
    UNSUPPORTED_URI = "unsupported_uri"


class TrojanURIErrorReason(StrEnum):
    """Уточнение причины отказа без пользовательских ключей и значений."""

    INVALID_ENDPOINT = "invalid_endpoint"
    INVALID_PORT = "invalid_port"
    MISSING_PASSWORD = "missing_password"
    MISSING_SECURITY = "missing_security"
    MISSING_TRANSPORT = "missing_transport"
    INVALID_QUERY = "invalid_query"
    DUPLICATE_PARAMETER = "duplicate_parameter"
    UNSUPPORTED_SCHEME = "unsupported_scheme"
    UNSUPPORTED_SECURITY = "unsupported_security"
    UNSUPPORTED_TRANSPORT = "unsupported_transport"
    UNSUPPORTED_PARAMETER = "unsupported_parameter"


class TrojanURIError(ValueError):
    """Безопасная ошибка формата, пригодная для обработки без разбора текста."""

    def __init__(self, code: TrojanURIErrorCode, *, reason: TrojanURIErrorReason | None = None) -> None:
        self.code = code
        self.reason = reason
        messages = {
            TrojanURIErrorCode.INVALID_URI: "Некорректная ссылка подключения Trojan.",
            TrojanURIErrorCode.UNSUPPORTED_URI: "Поддерживается только Trojan с TLS и WebSocket и известными параметрами.",
        }
        reasons = {
            TrojanURIErrorReason.INVALID_ENDPOINT: "Укажите адрес и явный порт сервера; IPv6 должен быть в квадратных скобках.",
            TrojanURIErrorReason.INVALID_PORT: "Порт должен состоять из 1–5 ASCII-цифр и находиться в диапазоне 1–65535.",
            TrojanURIErrorReason.MISSING_PASSWORD: "Укажите непустой пароль перед разделителем @.",
            TrojanURIErrorReason.MISSING_SECURITY: "Укажите обязательный непустой параметр security=tls.",
            TrojanURIErrorReason.MISSING_TRANSPORT: "Укажите обязательный непустой параметр type=ws.",
            TrojanURIErrorReason.INVALID_QUERY: "Параметры query должны иметь вид ключ=значение и разделяться одиночным &.",
            TrojanURIErrorReason.DUPLICATE_PARAMETER: "Каждый query-параметр разрешён только один раз, даже при одинаковых значениях.",
            TrojanURIErrorReason.UNSUPPORTED_SCHEME: "Поддерживается только схема trojan://.",
            TrojanURIErrorReason.UNSUPPORTED_SECURITY: "Поддерживается только режим безопасности TLS (security=tls).",
            TrojanURIErrorReason.UNSUPPORTED_TRANSPORT: "Поддерживается только транспорт WebSocket (type=ws).",
            TrojanURIErrorReason.UNSUPPORTED_PARAMETER: "Поддерживаются только параметры security, type, sni, host, path и fp.",
        }
        super().__init__(messages[code] if reason is None else reasons[reason])

    def to_diagnostic(self) -> dict[str, str | None]:
        """Вернуть только коды отказа, без traceback, контекста и заметок."""
        return {
            "code": self.code.value,
            "reason": self.reason.value if self.reason is not None else None,
        }


def _decode(value: str) -> str:
    """Снять один уровень URI-кодирования, не интерпретируя текст как код."""
    if _BAD_ESCAPE.search(value):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    decoded = unquote(value, encoding="utf-8", errors="strict")
    if any(ord(char) < 32 or ord(char) == 127 for char in decoded):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    return decoded


def parse_trojan_uri(uri: str) -> TrojanConnection:
    """Разобрать одну ссылку в модель, не применяя и не проверяя соединение.

    Ожидаемые ошибки выходят без внутреннего контекста и кадров разбора.
    Вход, reveal() и кадры вызывающего кода не предназначены для диагностики.
    """
    try:
        return _parse(uri)
    except TrojanURIError as error:
        code, reason = error.code, error.reason
    except ValueError:
        code, reason = TrojanURIErrorCode.INVALID_URI, None

    # Новый экземпляр вне обработчика не сохраняет decoder/IPv6-исключение
    # и его кадры. Удаляем вход и из собственного кадра публичной функции.
    del uri
    try:
        raise TrojanURIError(code, reason=reason) from None
    except TrojanURIError as error:
        # Вызов мог произойти внутри чужого except: from None скрывает контекст
        # только при печати, поэтому разрываем и саму ссылку на него.
        error.__context__ = None
        raise


def _parse(uri: str) -> TrojanConnection:
    if type(uri) is not str or not uri or len(uri) > MAX_URI_LENGTH:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in uri):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    if _BAD_ESCAPE.search(uri):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    # unquote() не проверяет Unicode в частях строки без escape-последовательностей.
    # До разбора отклоняем суррогатные кодовые точки, не представимые в UTF-8.
    uri.encode("utf-8", errors="strict")
    scheme, separator, remainder = uri.partition("://")
    if not separator or scheme.lower() != "trojan":
        raise TrojanURIError(TrojanURIErrorCode.UNSUPPORTED_URI, reason=TrojanURIErrorReason.UNSUPPORTED_SCHEME)

    before_fragment, has_fragment, fragment = remainder.partition("#")
    authority, _, query = before_fragment.partition("?")
    if authority.count("@") != 1:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.INVALID_ENDPOINT)
    password_text, endpoint = authority.split("@", 1)
    if not password_text:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.MISSING_PASSWORD)
    # Допустим завершающий '/', но путь WebSocket читается только из query.
    if endpoint.endswith("/"):
        endpoint = endpoint[:-1]
    match = _ENDPOINT.fullmatch(endpoint)
    if match is None:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.INVALID_ENDPOINT)
    server = match["server"]
    if server.startswith("["):
        server = server[1:-1]
        if "%" in server:
            raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.INVALID_ENDPOINT)
        try:
            IPv6Address(server)
        except ValueError:
            raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.INVALID_ENDPOINT) from None
    if not _PORT.fullmatch(match["port"]):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.INVALID_PORT)
    port = int(match["port"])
    if not 1 <= port <= 65_535:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.INVALID_PORT)

    parameters: dict[str, str] = {}
    for item in query.split("&") if query else ():
        key_text, has_value, value_text = item.partition("=")
        if not has_value or not key_text:
            raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.INVALID_QUERY)
        key = _decode(key_text)
        if key not in _PARAMETERS:
            raise TrojanURIError(TrojanURIErrorCode.UNSUPPORTED_URI, reason=TrojanURIErrorReason.UNSUPPORTED_PARAMETER)
        if key in parameters:
            raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.DUPLICATE_PARAMETER)
        parameters[key] = _decode(value_text)
    if not parameters.get("security"):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.MISSING_SECURITY)
    if not parameters.get("type"):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI, reason=TrojanURIErrorReason.MISSING_TRANSPORT)
    if parameters["security"] != "tls":
        raise TrojanURIError(TrojanURIErrorCode.UNSUPPORTED_URI, reason=TrojanURIErrorReason.UNSUPPORTED_SECURITY)
    if parameters["type"] != "ws":
        raise TrojanURIError(TrojanURIErrorCode.UNSUPPORTED_URI, reason=TrojanURIErrorReason.UNSUPPORTED_TRANSPORT)

    return TrojanConnection(
        server=server,
        port=port,
        password=SecretValue(_decode(password_text)),
        path=parameters.get("path", "/"),
        sni=parameters.get("sni"),
        host=parameters.get("host"),
        fingerprint=parameters.get("fp"),
        name=_decode(fragment) if has_fragment else None,
    )
