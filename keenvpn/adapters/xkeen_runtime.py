"""Преобразование наблюдений процесса Xray и маркера XKeen в модель без обращения к роутеру.

Функции принимают уже полученный вывод `pidof` и уже проверенное наличие
файла-маркера. Запуск `pidof`, проверка файла, таймауты и коды возврата
принадлежат адаптеру транспорта, которого здесь нет. Команды XKeen и init
не вызываются: даже `xkeen -status` меняет служебные файлы.
"""

from typing import NoReturn

from keenvpn.domain.xray_process import PID_MAX, XrayProcessError, XrayProcessErrorCode, XrayProcessObservation


XRAY_PROCESS_NAME = "xray"
"""Имя процесса для `pidof`; вспомогательные вызовы `xray api` видны под тем же именем."""
XKEEN_RUNTIME_DIRECTORY = "/tmp/.xkeen"
"""Каталог временного состояния XKeen с правами 700; на диск не сохраняется."""
XKEEN_READY_MARKER_PATH = "/tmp/.xkeen/ready"
"""Маркер завершённого запуска; снимается штатной остановкой, при аварии может остаться."""

_PID_DIGITS = len(str(PID_MAX))


def _reject() -> NoReturn:
    """Отсоединить отказ от активного чужого исключения, как в моделях домена."""
    try:
        raise XrayProcessError(XrayProcessErrorCode.OBSERVATION) from None
    except XrayProcessError as error:
        error.__context__ = None
        raise


def xray_process_from_pidof(output: bytes, ready_marker: bool) -> XrayProcessObservation:
    """Разобрать вывод `pidof`: PID через пробелы; пустой вывод означает отсутствие процесса.

    Код возврата `pidof` транспорт не передаёт: при отсутствии процесса он
    даёт пустой вывод. Токен не из цифр, ведущий ноль, ноль, длинное число
    и повтор PID отклоняются; длина проверяется до преобразования в число.
    """
    if type(output) is not bytes or type(ready_marker) is not bool:
        _reject()
    text = None
    try:
        text = output.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        pass
    if text is None:
        _reject()
    pids = []
    for token in text.split():
        if not token.isdigit() or not token.isascii() or token[0] == "0" or len(token) > _PID_DIGITS:
            _reject()
        pids.append(int(token))
    return XrayProcessObservation(tuple(pids), ready_marker)
