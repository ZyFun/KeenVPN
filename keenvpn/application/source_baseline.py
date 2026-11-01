"""Фиксация исходных отпечатков управляемых источников для сессии черновика.

Источник отпечатков читается один раз на каждый источник перечня, в порядке
`BaselineSource`, и его ответ проверяется до использования. Отсутствующий
источник — состояние `absent`, а не отказ. Недоступный источник останавливает
чтение: отказ возвращается с кодом причины, остальные источники не читаются,
отпечаток «недоступен» не записывается и не выдаётся за совпадение. Хеши
в результаты сценариев не попадают. Сравнение с текущим состоянием и
блокировка устаревшего черновика — не этого модуля.
"""

from keenvpn.application.contract import ErrorCategory, ErrorDetail
from keenvpn.application.ports import SourceFingerprintSource
from keenvpn.application.source_checks import SourceCheck, read_source_checked, unavailable
from keenvpn.domain.source_baseline import (
    BaselineSource, SourceBaseline, SourceBaselineError, SourceFingerprint, validate_source_fingerprint,
)


BASELINE_UNAVAILABLE = unavailable(
    "draft_baseline_unavailable", "Не удалось прочитать исходное состояние управляемого источника.",
)
"""Отказ чтения отпечатка: код отказа чтения роутера — в `reason`."""
BASELINE_CHECK = SourceCheck(
    "invalid_draft_baseline_source", SourceFingerprint, validate_source_fingerprint,
    "Источник исходных отпечатков вернул ответ в неподдерживаемом формате.",
    "Источник исходных отпечатков вернул некорректный отпечаток.", (SourceBaselineError,),
)
"""Проверка ответа источника отпечатков; повторная проверка ловит данные, изменённые после создания модели."""
_OTHER_SOURCE = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_baseline_source",
    "Источник исходных отпечатков вернул отпечаток другого источника.",
)


def read_fingerprint(source: SourceFingerprintSource, which: BaselineSource) -> SourceFingerprint | ErrorDetail:
    """Прочитать отпечаток одного источника один раз и проверить ответ.

    Отказ чтения роутера — `draft_baseline_unavailable` с причиной; ошибка
    модели внутри источника — `invalid_draft_baseline_source` с кодом домена;
    отпечаток чужого источника — тот же код без причины.
    """
    if type(which) is not BaselineSource:
        raise TypeError("Источник задаётся BaselineSource.")
    fingerprint = read_source_checked(
        BASELINE_CHECK, lambda: source.current_fingerprint(which), BASELINE_UNAVAILABLE.code,
        BASELINE_UNAVAILABLE.message,
    )
    if isinstance(fingerprint, ErrorDetail):
        return fingerprint
    return fingerprint if fingerprint.source is which else _OTHER_SOURCE


def capture_baseline(source: SourceFingerprintSource) -> SourceBaseline | ErrorDetail:
    """Прочитать отпечатки всех управляемых источников по порядку; первый отказ останавливает чтение."""
    fingerprints = []
    for which in BaselineSource:
        fingerprint = read_fingerprint(source, which)
        if isinstance(fingerprint, ErrorDetail):
            return fingerprint
        fingerprints.append(fingerprint)
    return SourceBaseline(tuple(fingerprints))
