"""Представление подключения Trojan с TLS и WebSocket в памяти."""

from dataclasses import dataclass, field
from typing import Literal


class SecretValue:
    """Значение с явным доступом к секрету и маскированным выводом.

    Это не шифрование: доверенный код получает строку через reveal().
    Объект не является dataclass, чтобы asdict() не извлекал пароль.
    """

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        self.__value = value

    def reveal(self) -> str:
        """Получить секрет для операции, которой он действительно нужен."""
        return self.__value

    def __repr__(self) -> str:
        return "SecretValue(<скрыто>)"

    def __str__(self) -> str:
        return "<скрыто>"


@dataclass(frozen=True, slots=True, repr=False)
class TrojanConnection:
    """Приватные данные; для отчёта используется только to_diagnostic().

    Наличие модели не подтверждает работу сервера. asdict() не является
    безопасным отчётом: произвольные поля тоже могут содержать секрет.
    """

    server: str
    port: int
    password: SecretValue
    path: str
    sni: str | None = None
    host: str | None = None
    fingerprint: str | None = None
    name: str | None = None
    protocol: Literal["trojan"] = field(default="trojan", init=False)
    security: Literal["tls"] = field(default="tls", init=False)
    transport: Literal["ws"] = field(default="ws", init=False)

    def __repr__(self) -> str:
        # Произвольные поля ссылки тоже могут содержать секрет или управляющий текст.
        return "TrojanConnection(<скрытые параметры>)"

    def to_diagnostic(self) -> dict[str, str | bool]:
        """Вернуть описание формата и наличие полей без их значений."""
        return {
            "protocol": self.protocol,
            "security": self.security,
            "transport": self.transport,
            "parameters": "<скрыто>",
            "has_sni": self.sni is not None,
            "has_host": self.host is not None,
            "has_fingerprint": self.fingerprint is not None,
            "has_name": self.name is not None,
        }
