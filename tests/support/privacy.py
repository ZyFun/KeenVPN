"""Проверки, что результаты и кадры не удерживают приватные данные, и искусственные небезопасные значения."""

from collections.abc import Iterator
from contextlib import contextmanager
import gc
import json
import traceback
import types
from unittest.mock import patch
import uuid

from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import XKeenSettings
from keenvpn.domain.xray_config import XrayConfigSet


def reachable(root: object) -> list[object]:
    """Объекты, достижимые из результата, без обхода классов и модулей."""
    seen, stack, found = set(), [root], []
    while stack:
        item = stack.pop()
        if id(item) in seen or isinstance(item, (type, types.ModuleType, types.FunctionType)):
            continue
        seen.add(id(item))
        found.append(item)
        stack.extend(gc.get_referents(item))
    return found


def frame_locals(error: BaseException, module_suffix: str) -> list[str]:
    """Вернуть repr локальных переменных кадров модуля из traceback ошибки.

    Пустой результат считается ошибкой теста: иначе после переименования
    модуля проверка проходила бы, не просмотрев ни одного кадра.
    """
    snapshot = traceback.TracebackException.from_exception(error, capture_locals=True)
    frames = [repr(frame.locals) for frame in snapshot.stack if frame.filename.endswith(module_suffix)]
    if not frames:
        raise AssertionError("В traceback нет кадров проверяемого модуля.")
    return frames


UNSAFE_IDENTIFIERS = {
    "uri": "trojan://TEST_pass@198.51.100.7:443/TEST_path?q=1#TEST_frag",
    "ipv4": "198.51.100.7",
    "ipv6": "2001:db8::1",
    "domain": "private.example.test",
    "path": "/opt/etc/TEST_secret",
    "userinfo": "TEST_user@example.test",
    "control": "tag\x1b[31m\x07",
    "newline": "tag\nTEST_line",
    "unicode": "тег-TEST",
    "kelvin": "soc\u212as",
    "long": "T" * 129,
}
"""Искусственные значения, которые безопасный вывод обязан скрыть: по одному на класс из критериев приёмки.

`kelvin` — не-ASCII строка, которую `str.lower` сводит к известному протоколу `socks`.
"""
UNSAFE_MARKERS = (
    "TEST_pass", "TEST_path", "TEST_frag", "198.51.100.7", "2001:db8", "private.example", "/opt/etc/TEST",
    "TEST_user@", "\x1b", "\x07", "TEST_line", "тег", "\u212a", "T" * 129,
)
"""Подстроки значений выше; ни одна не должна встречаться в repr, str и JSON результата."""
UNSAFE_PART_NAME = "01_unsafe.json"


def unsafe_xray_config() -> XrayConfigSet:
    """Набор частей Xray, где каждое выводимое поле границы получило небезопасное значение.

    Теги, протоколы, селекторы, `fallbackTag`, `strategy.type`, `domainStrategy`,
    `dns.tag`, `type` правила, имена неизвестных полей условий и разделов — все
    заполнены значениями `UNSAFE_IDENTIFIERS`. Рядом стоят безопасные значения,
    чтобы проверить, что они по-прежнему показываются. Outbound с тегом IPv6
    повторяется: ссылка правила на него разрешима, но позиция неоднозначна.
    """
    u = UNSAFE_IDENTIFIERS
    document = {
        "log": {},
        u["domain"]: {"note": 1},
        "inbounds": [
            {"tag": u["uri"], "protocol": u["path"]},
            {"tag": "lan", "protocol": "tunnel"},
            {"tag": u["ipv4"], "protocol": u["kelvin"]},
        ],
        "outbounds": [
            {"tag": u["ipv6"], "protocol": u["long"]},
            {"tag": "proxy-safe", "protocol": "trojan"},
            {"tag": u["userinfo"], "protocol": u["control"]},
            {"tag": u["domain"], "protocol": "freedom"},
            {"tag": u["ipv6"], "protocol": "freedom"},
        ],
        "dns": {"tag": u["newline"]},
        "routing": {
            "domainStrategy": u["uri"],
            "rules": [
                {"type": u["control"], "inboundTag": [u["uri"], "lan"], "outboundTag": u["ipv6"],
                 u["path"]: ["x"], "domain": ["geosite:test"]},
                {"type": "field", "balancerTag": u["userinfo"], u["userinfo"]: 1, u["unicode"]: 2},
                {"type": "field", "outboundTag": "proxy-safe", "network": "tcp"},
            ],
            "balancers": [
                {"tag": u["userinfo"], "selector": [u["ipv4"], "proxy-", ""], "fallbackTag": u["domain"],
                 "strategy": {"type": u["uri"]}},
                {"tag": "pool", "selector": "", "fallbackTag": "proxy-safe", "strategy": {"type": "leastPing"}},
            ],
        },
        "observatory": {"subjectSelector": [u["long"], "proxy-"]},
    }
    return XrayConfigSet((ConfigDocument(UNSAFE_PART_NAME, json.dumps(document, ensure_ascii=False).encode("utf-8")),))


def unsafe_xkeen_settings() -> XKeenSettings:
    """`xkeen.json`, где имена полей объекта `xkeen` и разделов верхнего уровня небезопасны."""
    u = UNSAFE_IDENTIFIERS
    document = {"xkeen": {"killswitch": "on", u["uri"]: 1, u["domain"]: 2, "verify_downloads": "strict"}, u["path"]: {}}
    return XKeenSettings(ConfigDocument("xkeen.json", json.dumps(document, ensure_ascii=False).encode("utf-8")))


@contextmanager
def operation_ids_with_marker(marker: str) -> Iterator[str]:
    """Подменить случайный UUID так, чтобы идентификатор операции по умолчанию содержал маркер.

    Случайный `operation_id` изредка совпадал с приватным маркером из одних
    шестнадцатеричных цифр, и проверка приватности падала без утечки. Подмена
    делает это совпадение постоянным. Маркер не из шестнадцатеричных цифр
    отклоняется: с UUID он совпасть не может.
    """
    value = uuid.UUID(hex=(marker + "e" * 32)[:32])
    with patch("uuid.uuid4", return_value=value):
        yield value.hex
