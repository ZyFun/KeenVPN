"""Фиксация исходных отпечатков управляемых источников и их сравнение с текущим состоянием.

Источник отпечатков читается один раз на каждый источник перечня, в порядке
`BaselineSource`, и его ответ проверяется до использования. Отсутствующий
источник — состояние `absent`, а не отказ. При фиксации недоступный источник
останавливает чтение: отказ возвращается с кодом причины, остальные источники
не читаются, отпечаток «недоступен» не записывается и не выдаётся за
совпадение. При сравнении читаются все источники, а каждое расхождение
и каждый отказ чтения становятся записью конфликта. Хеши в результаты
сценариев не попадают.
"""

from dataclasses import replace
from types import MappingProxyType

from keenvpn.application.contract import Conflict, ConflictState, ConflictSubject, ErrorCategory, ErrorDetail
from keenvpn.application.ports import SourceFingerprintSource
from keenvpn.application.source_checks import SourceCheck, read_source_checked, unavailable
from keenvpn.domain.source_baseline import (
    BaselineSource, FingerprintState, SourceBaseline, SourceBaselineError, SourceBaselineErrorCode, SourceFingerprint, same_fingerprint,
    validate_source_fingerprint,
)


BASELINE_UNAVAILABLE = unavailable(
    "draft_baseline_unavailable", "Не удалось прочитать состояние управляемого источника.",
)
"""Отказ чтения отпечатка: код отказа чтения роутера — в `reason`."""
BASELINE_CHECK = SourceCheck(
    "invalid_draft_baseline_source", SourceFingerprint, validate_source_fingerprint,
    "Источник исходных отпечатков вернул ответ в неподдерживаемом формате.",
    "Источник исходных отпечатков вернул некорректный отпечаток.", (SourceBaselineError,), SourceBaselineErrorCode,
)
"""Проверка ответа источника отпечатков; повторная проверка ловит данные, изменённые после создания модели."""
BASELINE_CHANGED = ErrorDetail(
    ErrorCategory.SOURCE_FAILED, "draft_baseline_changed",
    "Черновик устарел: управляемые источники изменились после его создания или их исходное состояние "
    "не сверяется этой версией.",
)
"""Отказ сравнения: источник разошёлся с исходным отпечатком или сравнить его нельзя; записи — в `conflicts`."""
_OTHER_SOURCE = ErrorDetail(
    ErrorCategory.INVALID_SOURCE_DATA, "invalid_draft_baseline_source",
    "Источник исходных отпечатков вернул отпечаток другого источника.",
)
_CONFLICT_STATES = MappingProxyType({
    FingerprintState.PRESENT: ConflictState.PRESENT, FingerprintState.ABSENT: ConflictState.ABSENT,
})


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


def _source_conflict(
    which: BaselineSource, expected: SourceFingerprint | None, found: SourceFingerprint | None,
) -> Conflict | None:
    """Запись конфликта одного источника; `None` у отпечатка — не зафиксирован или не прочитан."""
    expected_state = ConflictState.UNKNOWN if expected is None else _CONFLICT_STATES[expected.state]
    if found is None:
        found_state = ConflictState.UNKNOWN
    elif expected is not None and same_fingerprint(expected, found):
        return None
    elif expected is not None and expected.state is found.state:
        # Оба `present`, хеши или набор частей Xray разные.
        found_state = ConflictState.CHANGED
    else:
        found_state = _CONFLICT_STATES[found.state]
    return Conflict(ConflictSubject.SOURCE, expected_state, found_state, which)


def compare_baseline(source: SourceFingerprintSource, baseline: SourceBaseline | None) -> ErrorDetail | None:
    """Повторно прочитать все управляемые источники и сравнить с исходными отпечатками черновика.

    Каждый источник перечня читается один раз по порядку, в том числе не
    зафиксированный в черновике; отказ одного источника не останавливает
    чтение остальных. `None` — все источники совпали с отпечатками, раздел
    полон и неизвестных записей нет. Иначе — отказ с записями конфликта
    по одной на источник в порядке перечня и одной записью `source=None`
    для неизвестных этой версии записей раздела. Черновик без раздела
    сравнивается как черновик без записей.

    Если все записи — только отказы чтения зафиксированных источников,
    возвращается первый отказ чтения с его кодом и причиной: после
    восстановления источника проверку можно повторить. Любое расхождение
    или незафиксированный источник дают `draft_baseline_changed`: повтор
    не поможет. Отказ чтения совпадением не считается.
    """
    if baseline is not None and type(baseline) is not SourceBaseline:
        raise TypeError("Исходные отпечатки задаются SourceBaseline.")
    conflicts = []
    failure = None
    for which in BaselineSource:
        expected = None if baseline is None else baseline.fingerprint(which)
        found = read_fingerprint(source, which)
        if isinstance(found, ErrorDetail):
            if failure is None:
                failure = found
            found = None
        conflict = _source_conflict(which, expected, found)
        if conflict is not None:
            conflicts.append(conflict)
    if baseline is not None and len(baseline.extra):
        conflicts.append(Conflict(ConflictSubject.SOURCE, ConflictState.UNKNOWN, ConflictState.UNKNOWN))
    if not conflicts:
        return None
    if failure is not None and all(
        item.expected is not ConflictState.UNKNOWN and item.found is ConflictState.UNKNOWN for item in conflicts
    ):
        return replace(failure, conflicts=tuple(conflicts))
    return replace(BASELINE_CHANGED, conflicts=tuple(conflicts))
