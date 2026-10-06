"""Преобразование ответов GET RCI Keenetic в модели чтения без обращения к роутеру.

Функции принимают уже разобранный JSON отдельного ресурса. Транспорт (SSH,
локальный HTTP), таймауты, ограничение размера ответа и разбор вложенных
статусов ошибок RCI принадлежат адаптеру транспорта, которого здесь нет.
Ресурсы читаются раздельно: настройки, регистрация и runtime не смешиваются.
Ничего не записывается.
"""

from typing import NoReturn

from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import (
    KeeneticPolicy, KeeneticPolicyError, KeeneticPolicyErrorCode, KeeneticPolicySet,
)


POLICIES_RESOURCE = "ip/policy"
"""Настроенные политики: объект по ID политики с `description` и `permit`."""
HOTSPOT_SETTINGS_RESOURCE = "ip/hotspot"
"""Сохранённые настройки hotspot: записи `host`, назначения сегментов `policy`."""
REGISTRATIONS_RESOURCE = "known/host"
"""Реестр регистраций: имя регистрации — ключ, значение содержит `mac`."""
HOTSPOT_RUNTIME_RESOURCE = "show/ip/hotspot"
"""Наблюдаемое состояние клиентов: массив `host`."""


def _reject_policies() -> NoReturn:
    """Отсоединить отказ от активного чужого исключения, как в моделях домена.

    `from None` скрывает печать цепочки, но сохраняет `__context__`, который
    может содержать приватные данные вызывающего кода.
    """
    try:
        raise KeeneticPolicyError(KeeneticPolicyErrorCode.POLICIES) from None
    except KeeneticPolicyError as error:
        error.__context__ = None
        raise


def policies_from_rci(payload: dict[str, dict[str, object]]) -> KeeneticPolicySet:
    """Собрать модели из объекта `ip/policy`: ключ — ID, `description` — метка.

    Порядок ключей сохраняется. Отсутствующее описание остаётся None,
    пустая строка не подставляется. Разрешённые подключения и прочие поля
    политики в модель не переносятся.
    """
    if type(payload) is not dict or any(type(entry) is not dict for entry in payload.values()):
        _reject_policies()
    return KeeneticPolicySet(tuple(
        KeeneticPolicy(policy_id, entry.get("description")) for policy_id, entry in payload.items()
    ))


def hotspot_settings_from_rci(payload: dict[str, object]) -> KeeneticHotspotSettings:
    """Сохранить объект `ip/hotspot` целиком и проверить его записи и назначения."""
    return KeeneticHotspotSettings(payload)


def registrations_from_rci(payload: dict[str, object]) -> KeeneticRegistrations:
    """Сохранить объект `known/host` целиком; имена регистраций остаются приватными."""
    return KeeneticRegistrations(payload)


def hotspot_runtime_from_rci(payload: dict[str, object]) -> KeeneticHotspotRuntime:
    """Сохранить объект `show/ip/hotspot` целиком как наблюдение на момент чтения."""
    return KeeneticHotspotRuntime(payload)
