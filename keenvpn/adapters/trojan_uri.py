"""Чистый разбор Trojan URI без запуска команд, соединений и записи файлов."""

from enum import StrEnum
from ipaddress import IPv6Address
import re
from urllib.parse import unquote

from keenvpn.domain.connection import SecretValue, TrojanConnection


MAX_URI_LENGTH = 16_384
_PARAMETERS = frozenset({"security", "type", "sni", "host", "path", "fp"})
_ENDPOINT = re.compile(r"(?P<server>\[[^\]]+\]|[^:/?#@\s\\\[\]]+):(?P<port>[0-9]{1,5})")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


class TrojanURIErrorCode(StrEnum):
    """Причина отказа без включения входных значений."""

    INVALID_URI = "invalid_uri"
    UNSUPPORTED_URI = "unsupported_uri"


class TrojanURIError(ValueError):
    """Безопасная ошибка формата, пригодная для обработки без разбора текста."""

    def __init__(self, code: TrojanURIErrorCode) -> None:
        self.code = code
        messages = {
            TrojanURIErrorCode.INVALID_URI: "Некорректная ссылка подключения Trojan.",
            TrojanURIErrorCode.UNSUPPORTED_URI: "Поддерживается только Trojan с TLS и WebSocket и известными параметрами.",
        }
        super().__init__(messages[code])


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

    Ошибки не содержат исходную ссылку или значения её полей. Нельзя печатать
    входную строку, reveal() или локальные переменные traceback при диагностике.
    """
    if type(uri) is not str or not uri or len(uri) > MAX_URI_LENGTH:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in uri):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    if _BAD_ESCAPE.search(uri):
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    try:
        return _parse(uri)
    except TrojanURIError:
        raise
    except ValueError:
        # Исключения декодера/IPv6 могут включать фрагмент входа: наружу только код.
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI) from None


def _parse(uri: str) -> TrojanConnection:
    scheme, separator, remainder = uri.partition("://")
    if not separator or scheme.lower() != "trojan":
        raise TrojanURIError(TrojanURIErrorCode.UNSUPPORTED_URI)

    before_fragment, has_fragment, fragment = remainder.partition("#")
    authority, has_query, query = before_fragment.partition("?")
    if not has_query or authority.count("@") != 1:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    password_text, endpoint = authority.split("@", 1)
    # Допустим завершающий '/', но путь WebSocket читается только из query.
    if endpoint.endswith("/"):
        endpoint = endpoint[:-1]
    match = _ENDPOINT.fullmatch(endpoint)
    if match is None or not password_text:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
    server = match["server"]
    if server.startswith("["):
        server = server[1:-1]
        if "%" in server:
            raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
        IPv6Address(server)
    port = int(match["port"])
    if not 1 <= port <= 65_535:
        raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)

    parameters: dict[str, str] = {}
    for item in query.split("&"):
        key_text, has_value, value_text = item.partition("=")
        if not has_value:
            raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
        key = _decode(key_text)
        if key not in _PARAMETERS:
            raise TrojanURIError(TrojanURIErrorCode.UNSUPPORTED_URI)
        if key in parameters:
            raise TrojanURIError(TrojanURIErrorCode.INVALID_URI)
        parameters[key] = _decode(value_text)
    if parameters.get("security") != "tls" or parameters.get("type") != "ws":
        raise TrojanURIError(TrojanURIErrorCode.UNSUPPORTED_URI)

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
