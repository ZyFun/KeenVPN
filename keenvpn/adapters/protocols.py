"""Явный состав доверенных протокольных модулей из поставки."""

from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.protocol_registry import ProtocolField, ProtocolModule, ProtocolRegistry
from keenvpn.domain.connection import TrojanConnection


def bundled_protocols() -> ProtocolRegistry:
    """Зарегистрировать существующий парсер, не искать плагины и движки.

    Поля подключения считаются приватными для формы. Их значения и defaults
    не входят в метаданные. Парсер сам проверяет URI; отдельный валидатор
    произвольно созданной модели здесь не заявляется.
    """
    return ProtocolRegistry((ProtocolModule(
        protocol="trojan", uri_schemes=("trojan",), parameters_type=TrojanConnection,
        parse_uri=TrojanLinkParser().parse,
        fields=tuple(
            ProtocolField(name=name, secret=True, required=required)
            for name, required in (
                ("server", True), ("port", True), ("password", True), ("path", False),
                ("sni", False), ("host", False), ("fingerprint", False), ("name", False),
            )
        ),
    ),))
