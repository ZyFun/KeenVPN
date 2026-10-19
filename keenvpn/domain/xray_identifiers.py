"""Проверка формата и известные значения идентификаторов Xray для безопасного вывода.

Теги, селекторы, имена полей и разделов конфигурации Xray и ключи `xkeen.json`
задаёт пользователь, поэтому представления показывают их только после одной
общей проверки: либо значение похоже на технический идентификатор, либо входит
в список известных значений Xray установленной версии. Модуль общий для импорта
правил и сводки конфигурации прокси: одно правило — один вывод. Списки известных
значений сверены с исходниками тега `XRAY_VERSION` (`infra/conf/xray.go`,
`router.go`, `loader.go`); здесь нет чтения файлов и обращения к Xray.
"""

import ipaddress
import re


XRAY_VERSION = "v26.3.27"
"""Тег Xray-core, по исходникам которого составлены списки известных значений."""
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,127}")
"""Технический идентификатор в безопасном выводе: без `.`, `/`, `:`, `@`, пробелов и управляющих символов.

Без точки и двоеточия в вывод не попадают IPv4- и IPv6-адреса и имена,
похожие на домен.
"""
BALANCER_STRATEGIES = frozenset({"random", "leastping", "roundrobin", "leastload"})
"""Стратегии балансировщика (`BalancingRule.Build`); тип сравнивается без учёта регистра, как в загрузчике."""
DOMAIN_STRATEGIES = frozenset({"asis", "ipifnonmatch", "ipondemand"})
"""Значения `routing.domainStrategy` (`getDomainStrategy`, без учёта регистра).

Любое другое значение Xray трактует как `AsIs`; сводка его скрывает, а не
подменяет известным.
"""
INBOUND_PROTOCOLS = frozenset({
    "tunnel", "dokodemo-door", "http", "shadowsocks", "mixed", "socks", "vless", "vmess", "trojan", "wireguard",
    "hysteria", "tun",
})
"""Ключи `inboundConfigLoader`; идентификатор сравнивается без учёта регистра (`LoadWithID`)."""
OUTBOUND_PROTOCOLS = frozenset({
    "block", "blackhole", "loopback", "direct", "freedom", "http", "shadowsocks", "socks", "vless", "vmess", "trojan",
    "hysteria", "dns", "wireguard",
})
"""Ключи `outboundConfigLoader`; идентификатор сравнивается без учёта регистра (`LoadWithID`)."""
RULE_TYPES = frozenset({"field"})
"""Документированное значение `type` правила; декодер поле не читает, поэтому сравнение точное."""
XRAY_RULE_CONDITION_FIELDS = frozenset({
    "domain", "domains", "ip", "port", "network", "sourceIP", "source", "sourcePort", "user", "vlessRoute",
    "inboundTag", "protocol", "attrs", "localIP", "localPort", "process", "webhook",
})
"""Поля условий правила, которые читает `parseFieldRule` (`RawFieldRule`); регистр имён учитывается."""
XRAY_SECTIONS = frozenset({
    "log", "api", "dns", "routing", "policy", "inbounds", "outbounds", "transport", "stats", "reverse", "fakeDns",
    "metrics", "observatory", "burstObservatory", "version",
})
"""Разделы верхнего уровня структуры `Config`; сравнение точное.

Декодер Go принял бы имя и в другом регистре; такой раздел сводка считает
неизвестным и только учитывает — отступление в безопасную сторону.
"""


def safe_identifier(value: object) -> str | None:
    """Тег, селектор или ключ для вывода, если он похож на технический идентификатор.

    Значение с разделителями URL, пути, адреса, домена или учётных данных
    скрывается и заменяется на `None`; отдельно скрывается всё, что разбирается
    как IP-адрес. Проверка формата не отличает секрет из букв, цифр, `_`, `+`
    и `-` от обычного тега.
    """
    if type(value) is not str or not _SAFE_IDENTIFIER.fullmatch(value):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return None


def safe_selector(value: object) -> str | None:
    """Элемент селектора для вывода: пустой селектор показывается пустым, остальные — после проверки формата."""
    if value == "" and type(value) is str:
        return ""
    return safe_identifier(value)


def _known_folded(value: object, known: frozenset[str]) -> str | None:
    """Значение как написано, если оно из ASCII и без учёта регистра есть среди известных.

    Строка с не-ASCII символами скрывается до сравнения: `str.lower` сводит,
    например, знак Кельвина U+212A к `k`, и `soc\u212As` совпал бы с `socks`.
    """
    return value if type(value) is str and value.isascii() and value.lower() in known else None


def safe_strategy(value: object) -> str | None:
    """Тип стратегии для вывода, только если это известная стратегия Xray."""
    return _known_folded(value, BALANCER_STRATEGIES)


def safe_domain_strategy(value: object) -> str | None:
    """`routing.domainStrategy` для вывода, только если это известное значение Xray."""
    return _known_folded(value, DOMAIN_STRATEGIES)


def safe_inbound_protocol(value: object) -> str | None:
    """Протокол inbound для вывода, только если его знает загрузчик Xray."""
    return _known_folded(value, INBOUND_PROTOCOLS)


def safe_outbound_protocol(value: object) -> str | None:
    """Протокол outbound для вывода, только если его знает загрузчик Xray."""
    return _known_folded(value, OUTBOUND_PROTOCOLS)


def safe_rule_type(value: object) -> str | None:
    """`type` правила для вывода, только если это документированное значение."""
    return value if type(value) is str and value in RULE_TYPES else None


def known_section(name: object) -> bool:
    """Является ли имя разделом верхнего уровня конфигурации Xray."""
    return type(name) is str and name in XRAY_SECTIONS


def known_condition_field(name: object) -> bool:
    """Является ли имя полем условия правила, которое читает декодер Xray."""
    return type(name) is str and name in XRAY_RULE_CONDITION_FIELDS
