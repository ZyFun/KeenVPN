"""Исходные отпечатки управляемых источников: перечень, модель и раздел формата черновика.

При создании черновика фиксируется, в каком состоянии были файлы Xray и
XKeen и native-настройки Keenetic, которыми управляет менеджер. Отпечаток
файла — SHA-256 его байтов, каталога частей Xray — набор имён `*.json` с
SHA-256 каждой части, native-настройки — SHA-256 канонического JSON всего
объекта ресурса: ключи объектов отсортированы, массивы остаются в исходном
порядке. Отсутствующий источник (`absent`) отличается от пустого файла и
пустого каталога (`present`). Недоступный источник здесь не моделируется:
его отказ передаёт порт чтения, а сценарий не создаёт черновик.

Модуль ничего не читает и не записывает: он проверяет модели и переводит
раздел `baseline` в JSON и обратно. Хеши — данные доверенного кода: `repr`
и диагностика показывают только источник и состояние. Сравнение с текущим
состоянием и блокировка устаревшего черновика — не этого модуля.
"""

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
from typing import NoReturn

from keenvpn.domain.config_document import valid_document_name, valid_json_tree
from keenvpn.domain.manager_metadata import (
    ManagerMetadataError, UnknownFields, rebuild_unknown_fields, valid_metadata_revision,
)


MAX_BASELINE_PARTS = 64
"""Предел числа частей Xray в отпечатке; совпадает с пределом чтения каталога конфигураций."""
XRAY_PART_SUFFIX = ".json"


class BaselineSource(StrEnum):
    """Управляемые менеджером источники; порядок перечисления — порядок чтения и записи.

    Геобазы, runtime Keenetic, реестр регистраций и процесс Xray не входят:
    черновик их не меняет.
    """

    XRAY_CONFIGS = "xray_configs"
    XKEEN_SETTINGS = "xkeen_settings"
    XKEEN_INIT = "xkeen_init"
    XKEEN_PORT_EXCLUDE = "xkeen_port_exclude"
    XKEEN_PORT_PROXYING = "xkeen_port_proxying"
    XKEEN_IP_EXCLUDE = "xkeen_ip_exclude"
    KEENETIC_POLICIES = "keenetic_policies"
    KEENETIC_HOTSPOT_SETTINGS = "keenetic_hotspot_settings"


class FingerprintState(StrEnum):
    """Состояние источника в момент чтения."""

    PRESENT = "present"
    """Источник прочитан; пустой файл и пустой каталог — тоже `present`."""
    ABSENT = "absent"
    """Файла, каталога или его родителя нет."""


class SourceBaselineErrorCode(StrEnum):
    """Стабильные коды нарушений модели и раздела исходных отпечатков."""

    SOURCE = "invalid_baseline_source"
    STATE = "invalid_baseline_state"
    DIGEST = "invalid_baseline_digest"
    PARTS = "invalid_baseline_parts"
    ENTRY = "invalid_baseline_entry"
    BASELINE = "invalid_source_baseline"
    NATIVE = "invalid_native_document"


_MESSAGES = {
    SourceBaselineErrorCode.SOURCE: "Источник исходного отпечатка не входит в перечень управляемых.",
    SourceBaselineErrorCode.STATE: "Состояние источника должно быть present или absent и согласовано с отпечатком.",
    SourceBaselineErrorCode.DIGEST: "Отпечаток должен быть SHA-256 в нижнем регистре.",
    SourceBaselineErrorCode.PARTS: (
        "Части Xray должны иметь допустимые имена *.json без повторов, идти по порядку имён и не превышать предел."
    ),
    SourceBaselineErrorCode.ENTRY: "Запись источника в разделе исходных отпечатков нарушает структуру.",
    SourceBaselineErrorCode.BASELINE: "Раздел исходных отпечатков нарушает структуру.",
    SourceBaselineErrorCode.NATIVE: "Native-настройки должны быть объектом JSON поддерживаемой структуры.",
}
_SOURCES = {source.value: source for source in BaselineSource}
_STATES = {state.value: state for state in FingerprintState}
_ORDER = {source: index for index, source in enumerate(BaselineSource)}


class SourceBaselineError(ValueError):
    """Отказ с машинным кодом и фиксированным текстом без хешей, имён частей и значений."""

    def __init__(self, code: SourceBaselineErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


def _fail(code: SourceBaselineErrorCode) -> NoReturn:
    """Не сохранять активное чужое исключение в цепочке ошибки."""
    try:
        raise SourceBaselineError(code) from None
    except SourceBaselineError as error:
        error.__context__ = None
        raise


def valid_part_name(value: object) -> bool:
    """Имя части Xray: допустимое имя файла без каталога с окончанием `.json`."""
    return valid_document_name(value) and value.endswith(XRAY_PART_SUFFIX)


def native_fingerprint(document: object) -> str:
    """SHA-256 канонического JSON объекта native-настроек.

    Ключи объектов сортируются, массивы сохраняют исходный порядок: порядок
    разрешённых подключений значим. `true` и `1`, строка и число различаются.
    """
    if type(document) is not dict or not valid_json_tree(document):
        _fail(SourceBaselineErrorCode.NATIVE)
    text = None
    try:
        text = json.dumps(document, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (ValueError, TypeError, RecursionError):
        # Например, целое длиннее предела преобразования в текст.
        pass
    if text is None:
        _fail(SourceBaselineErrorCode.NATIVE)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _check_parts(parts: object) -> None:
    if type(parts) is not tuple or len(parts) > MAX_BASELINE_PARTS:
        _fail(SourceBaselineErrorCode.PARTS)
    previous = None
    for item in parts:
        if type(item) is not tuple or len(item) != 2 or not valid_part_name(item[0]):
            _fail(SourceBaselineErrorCode.PARTS)
        if not valid_metadata_revision(item[1]):
            _fail(SourceBaselineErrorCode.DIGEST)
        if previous is not None and not previous < item[0]:
            _fail(SourceBaselineErrorCode.PARTS)
        previous = item[0]


@dataclass(frozen=True, slots=True, repr=False)
class SourceFingerprint:
    """Отпечаток одного источника.

    `present` у каталога частей Xray задаёт `parts` — пары «имя, SHA-256» по
    порядку имён, у остальных источников — `sha256`. `absent` не содержит
    отпечатков. Формат SHA-256 тот же, что у ревизии черновика.
    """

    source: BaselineSource
    state: FingerprintState
    sha256: str | None = None
    parts: tuple[tuple[str, str], ...] | None = None

    def __post_init__(self) -> None:
        if type(self.source) is not BaselineSource:
            _fail(SourceBaselineErrorCode.SOURCE)
        if type(self.state) is not FingerprintState:
            _fail(SourceBaselineErrorCode.STATE)
        if self.state is FingerprintState.ABSENT:
            if self.sha256 is not None or self.parts is not None:
                _fail(SourceBaselineErrorCode.STATE)
        elif self.source is BaselineSource.XRAY_CONFIGS:
            if self.sha256 is not None:
                _fail(SourceBaselineErrorCode.STATE)
            _check_parts(self.parts)
        elif self.parts is not None:
            _fail(SourceBaselineErrorCode.STATE)
        elif not valid_metadata_revision(self.sha256):
            _fail(SourceBaselineErrorCode.DIGEST)

    def __repr__(self) -> str:
        # Устойчив к повреждённой после создания модели: значения полей не выводятся.
        source = self.source.value if type(self.source) is BaselineSource else "?"
        state = self.state.value if type(self.state) is FingerprintState else "?"
        parts = f", parts={len(self.parts)}" if type(self.parts) is tuple else ""
        return f"SourceFingerprint(source={source}, state={state}{parts})"

    def to_diagnostic(self) -> dict[str, str]:
        """Источник и состояние без хешей и имён частей."""
        return {"source": self.source.value, "state": self.state.value}


def _no_fields() -> UnknownFields:
    return UnknownFields()


@dataclass(frozen=True, slots=True, repr=False)
class SourceBaseline:
    """Исходные отпечатки черновика: каждый источник не больше одного раза, в порядке перечня.

    `extra` — записи источников, неизвестных этой версии менеджера: они
    сохраняются без изменений, но сравнить их эта версия не может.
    """

    fingerprints: tuple[SourceFingerprint, ...]
    extra: UnknownFields = field(default_factory=_no_fields)

    def __post_init__(self) -> None:
        if type(self.fingerprints) is not tuple or any(
            type(item) is not SourceFingerprint for item in self.fingerprints
        ):
            _fail(SourceBaselineErrorCode.BASELINE)
        positions = [
            _ORDER[item.source] if type(item.source) is BaselineSource else None for item in self.fingerprints
        ]
        if any(position is None for position in positions) or positions != sorted(set(positions)):
            _fail(SourceBaselineErrorCode.BASELINE)
        if type(self.extra) is not UnknownFields or any(name in _SOURCES for name in self.extra.names):
            _fail(SourceBaselineErrorCode.BASELINE)

    def __repr__(self) -> str:
        return f"SourceBaseline(sources={len(self.fingerprints)}, unknown_sources={len(self.extra)})"

    def fingerprint(self, source: BaselineSource) -> SourceFingerprint | None:
        """Отпечаток источника или None, если он не зафиксирован."""
        if type(source) is not BaselineSource:
            raise TypeError("Источник задаётся BaselineSource.")
        return next((item for item in self.fingerprints if item.source is source), None)

    def to_diagnostic(self) -> dict[str, object]:
        """Источники с состояниями и число неизвестных записей без хешей, имён частей и значений."""
        return {
            "sources": [item.to_diagnostic() for item in self.fingerprints],
            "unknown_source_count": len(self.extra),
        }


def validate_source_fingerprint(fingerprint: SourceFingerprint) -> None:
    """Проверить готовый отпечаток заново, пересобрав его из собственных полей.

    Конструктор требует точных типов, поэтому подкласс `str`, строка вместо
    перечисления и список вместо кортежа не проходят; код ошибки поля сохраняется.
    """
    code = None
    try:
        if type(fingerprint) is not SourceFingerprint:
            _fail(SourceBaselineErrorCode.ENTRY)
        SourceFingerprint(fingerprint.source, fingerprint.state, fingerprint.sha256, fingerprint.parts)
    except SourceBaselineError as error:
        code = error.code
    except Exception:
        # Повреждённая модель: удалённый атрибут и подобное.
        code = SourceBaselineErrorCode.ENTRY
    if code is not None:
        _fail(code)


def rebuild_source_baseline(baseline: SourceBaseline) -> SourceBaseline:
    """Пересобрать раздел из собственных полей и снимка неизвестных записей.

    Подмена типов, отпечатков или снимка — ошибка раздела; код ошибки
    отпечатка сохраняется.
    """
    code = rebuilt = None
    try:
        if type(baseline) is not SourceBaseline or type(baseline.fingerprints) is not tuple:
            _fail(SourceBaselineErrorCode.BASELINE)
        for item in baseline.fingerprints:
            validate_source_fingerprint(item)
        rebuilt = SourceBaseline(baseline.fingerprints, rebuild_unknown_fields(baseline.extra))
    except SourceBaselineError as error:
        code = error.code
    except Exception:
        # Испорченный снимок неизвестных записей, удалённый атрибут и подобное.
        code = SourceBaselineErrorCode.BASELINE
    if code is not None:
        _fail(code)
    return rebuilt


def export_source_baseline(baseline: SourceBaseline) -> dict[str, object]:
    """Раздел JSON: известные источники в порядке перечня, затем неизвестные записи в исходном порядке."""
    rebuilt = rebuild_source_baseline(baseline)
    document: dict[str, object] = {}
    for item in rebuilt.fingerprints:
        entry: dict[str, object] = {"state": item.state.value}
        if item.sha256 is not None:
            entry["sha256"] = item.sha256
        if item.parts is not None:
            entry["parts"] = dict(item.parts)
        document[item.source.value] = entry
    document.update(rebuilt.extra.export())
    return document


def _entry_keys(source: BaselineSource, state: FingerprintState) -> set[str]:
    if state is FingerprintState.ABSENT:
        return {"state"}
    return {"state", "parts" if source is BaselineSource.XRAY_CONFIGS else "sha256"}


def _parse_entry(source: BaselineSource, entry: object) -> SourceFingerprint:
    if type(entry) is not dict:
        _fail(SourceBaselineErrorCode.ENTRY)
    value = entry.get("state")
    state = _STATES.get(value) if type(value) is str else None
    if state is None:
        _fail(SourceBaselineErrorCode.STATE)
    if set(entry) != _entry_keys(source, state):
        _fail(SourceBaselineErrorCode.ENTRY)
    if state is FingerprintState.ABSENT:
        return SourceFingerprint(source, state)
    if source is BaselineSource.XRAY_CONFIGS:
        parts = entry["parts"]
        if type(parts) is not dict:
            _fail(SourceBaselineErrorCode.PARTS)
        # Порядок ключей объекта не значим: части упорядочиваются по имени, как при загрузке Xray.
        return SourceFingerprint(source, state, parts=tuple(sorted(parts.items())))
    return SourceFingerprint(source, state, sha256=entry["sha256"])


def parse_source_baseline(value: object) -> SourceBaseline:
    """Разобрать раздел JSON строго: известные записи проверяются, неизвестные источники сохраняются.

    Значения разобраны строгим парсером документа, поэтому дублей ключей
    в них нет; лишнее или отсутствующее поле записи известного источника —
    ошибка.
    """
    if type(value) is not dict:
        _fail(SourceBaselineErrorCode.BASELINE)
    known: dict[BaselineSource, SourceFingerprint] = {}
    unknown: dict[str, object] = {}
    for key, entry in value.items():
        source = _SOURCES.get(key)
        if source is None:
            unknown[key] = entry
        else:
            known[source] = _parse_entry(source, entry)
    extra = None
    try:
        extra = UnknownFields(unknown)
    except ManagerMetadataError:
        pass
    if extra is None:
        _fail(SourceBaselineErrorCode.BASELINE)
    return SourceBaseline(tuple(known[source] for source in BaselineSource if source in known), extra)
