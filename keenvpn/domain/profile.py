"""Идентичность профиля отдельно от приватных параметров его протокола."""

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import NoReturn, Protocol, runtime_checkable
import unicodedata
from uuid import UUID


PROFILE_FORMAT_VERSION = 1
"""Версия общей оболочки профиля, независимая от контракта application."""


_FORBIDDEN_NAME_CATEGORIES = frozenset({"Cc", "Cs", "Co", "Zl", "Zp"})
_BIDI_NAME_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
# Cf содержит обычные ZWJ/ZWNJ, а Cn зависит от версии базы Unicode.


class ProfileErrorCode(StrEnum):
    """Причины отказа без исходных значений профиля."""

    ID = "invalid_profile_id"
    NAME = "invalid_profile_name"
    PROTOCOL = "invalid_profile_protocol"
    VERSION = "invalid_profile_format_version"
    IDENTITY = "invalid_profile_identity"
    PARAMETERS = "invalid_profile_parameters"
    PROTOCOL_MISMATCH = "profile_protocol_mismatch"


class ProfileValidationError(ValueError):
    """Безопасная ошибка общей структуры, без проверки параметров протокола."""

    def __init__(self, code: ProfileErrorCode) -> None:
        self.code = code
        super().__init__("Некорректная структура профиля подключения.")


def _raise_detached(code: ProfileErrorCode) -> NoReturn:
    """Отделить отказ от активного исключения без изменения чужих кадров.

    from None скрывает печать цепочки, но сохраняет __context__. Очистка
    после первого raise и bare raise не связывают ошибку с ним повторно.
    Собственный traceback и локальные переменные вызывающего кода остаются.
    """
    try:
        raise ProfileValidationError(code) from None
    except ProfileValidationError as error:
        error.__context__ = None
        raise


def validate_profile_format_version(version: object) -> None:
    """Проверить общий заголовок до интерпретации полей конкретной версии."""
    if type(version) is not int or version < 1:
        _raise_detached(ProfileErrorCode.VERSION)


def valid_protocol_id(value: object) -> bool:
    """Проверить ID протокола формата v1 для профиля и реестра без преобразований."""
    return type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value) is not None


@dataclass(frozen=True, slots=True, repr=False)
class ProfileIdentity:
    """Стабильный ID, имя, протокол и версия общей оболочки.

    ID назначает вызывающий код; чтение не создаёт новую идентичность.
    Имя может отсутствовать и не является ключом профиля. Произвольное имя
    скрывается в диагностике, поскольку тоже может содержать секрет.
    Поля неизвестной положительной версии сохраняются без правил v1.
    """

    profile_id: UUID
    name: str | None
    protocol: str
    format_version: int = PROFILE_FORMAT_VERSION

    def __post_init__(self) -> None:
        validate_profile_identity(self)

    def __repr__(self) -> str:
        return "ProfileIdentity(<скрытые метаданные>)"


def validate_profile_identity(identity: ProfileIdentity) -> None:
    """Проверить поля идентичности без нормализации и изменения объекта."""
    validate_profile_format_version(identity.format_version)
    if identity.format_version != PROFILE_FORMAT_VERSION:
        return
    if type(identity.profile_id) is not UUID or identity.profile_id.int == 0:
        _raise_detached(ProfileErrorCode.ID)
    if identity.name is not None and (
        type(identity.name) is not str or not identity.name.strip() or len(identity.name) > 256
        or any(
            unicodedata.category(char) in _FORBIDDEN_NAME_CATEGORIES or char in _BIDI_NAME_CONTROLS
            for char in identity.name
        )
    ):
        _raise_detached(ProfileErrorCode.NAME)
    if not valid_protocol_id(identity.protocol):
        _raise_detached(ProfileErrorCode.PROTOCOL)


@runtime_checkable
class ProfileParameters(Protocol):
    """Типизированная модель доверенного модуля, без привязки к движку.

    Собственный парсер/валидатор отвечает за значения параметров. Этот
    контракт проверяет лишь соответствие типа протокола идентичности
    поддержанной версии профиля.
    """

    @property
    def protocol(self) -> str: ...


@dataclass(frozen=True, slots=True, repr=False)
class ConnectionProfile[ParametersT: ProfileParameters]:
    """Общая оболочка и типизированные параметры без копирования и сериализации.

    Неизменяемость оболочки не замораживает вложенную модель. Параметры
    предоставляются доверенным кодом; их проверка и хранение ей не принадлежат.
    asdict(), прямой доступ к полям и дамп объектов не являются диагностикой.
    Параметры неизвестной версии сохраняются непрозрачно без правил v1.
    """

    identity: ProfileIdentity
    parameters: ParametersT

    def __post_init__(self) -> None:
        validate_profile(self)

    def __repr__(self) -> str:
        return "ConnectionProfile(<скрытый профиль>)"

    def to_diagnostic(self) -> dict[str, str | int | bool]:
        """Показать общую структуру, не вызывая методы приватных параметров."""
        validate_profile_format_version(self.identity.format_version)
        if self.identity.format_version != PROFILE_FORMAT_VERSION:
            return {"format_version": self.identity.format_version}
        return {
            "profile_id": str(self.identity.profile_id),
            "protocol": self.identity.protocol,
            "format_version": self.identity.format_version,
            "has_name": self.identity.name is not None,
        }


def validate_profile(profile: ConnectionProfile) -> None:
    """Проверить готовую модель без вызова хуков создания и изменения полей."""
    if type(profile.identity) is not ProfileIdentity:
        _raise_detached(ProfileErrorCode.IDENTITY)
    validate_profile_identity(profile.identity)
    if profile.identity.format_version != PROFILE_FORMAT_VERSION:
        # Формат параметров неизвестен: сохраняем объект без интерпретации.
        return
    code = None
    try:
        if not isinstance(profile.parameters, ProfileParameters):
            code = ProfileErrorCode.PARAMETERS
        else:
            protocol = profile.parameters.protocol
            if type(protocol) is not str:
                code = ProfileErrorCode.PARAMETERS
            elif protocol != profile.identity.protocol:
                code = ProfileErrorCode.PROTOCOL_MISMATCH
    except Exception:
        # Ошибка чужой модели может содержать секрет; её цепочка не нужна.
        code = ProfileErrorCode.PARAMETERS
    if code is not None:
        _raise_detached(code)
