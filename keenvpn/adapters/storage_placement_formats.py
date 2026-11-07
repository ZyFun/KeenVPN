"""Строгие форматы действующих операционных команд архива и истории.

Shell и SQL здесь только данные. Поддерживается проверенная структура файлов:
после замены разрешённых литералов её SHA-256 должен совпасть с эталоном.
Так присваивание внутри произвольного скрипта не становится настройкой.
Эталоны обезличены; значения размещения и лимитов в них не закреплены.
"""

from dataclasses import dataclass
import hashlib
import re

from keenvpn.adapters.entware_files import fail_read
from keenvpn.application.ports import RouterReadFailure
from keenvpn.domain.config_document import ConfigDocumentError, parse_strict_json_object
from keenvpn.domain.manager_metadata import MAX_LIMIT_VALUE, valid_storage_id, valid_storage_path


HISTORY_SCRIPT_SHA256 = "efb5d528f0ff86299cc39f71d9698e2016bcac9b5b5c98053b9a9a0302141806"
HISTORY_INGEST_SHA256 = "0d97b48e0adc2b5d2f99436c0c73cfd7f03f0196e07da201c839635d3b30fccf"
BACKUP_WRAPPER_SHA256 = "d5ec227a074743a90a55a231a6f29454f07af0c5d5d2851300f803212d866dc2"
BACKUP_ENTRY_SHA256 = "eb164850f8845084251fc240cdc072c3e8be49134b1144bb75966ca20c766ed0"
BACKUP_ADAPTER_SHA256 = "abef37fbd5f7423a04eed30a15634641ab6c8901eefeac1452539a2f75141a72"
HISTORY_INIT_SHA256 = "c0af56b09677ba5d1ec9658f23a12888e5fe56a311936a5f2d218326c37824d8"


@dataclass(frozen=True, repr=False)
class BackupPlacement:
    """Литералы известного формата; только для доверенного адаптера."""

    entware_uuid: str
    data_uuid: str
    backup_uuid: str


@dataclass(frozen=True, repr=False)
class HistoryPlacement:
    """Прочитанные настройки без значений в repr."""

    storage_id: str
    mount: str
    path: str
    size_bytes: int
    retention_seconds: int


def reject_format() -> None:
    """Не возвращать фрагменты непонятого документа или цепочку исключений."""
    fail_read(RouterReadFailure.INVALID_RESPONSE)


def confirm_code(content: bytes, expected: str) -> None:
    """Подтвердить известный неизменяемый текст без его исполнения."""
    if type(content) is not bytes or hashlib.sha256(content).hexdigest() != expected:
        reject_format()


def _text(content: bytes) -> str:
    if type(content) is not bytes or len(content) > 131072:
        reject_format()
    result = None
    try:
        result = content.decode("utf-8", "strict")
    except UnicodeDecodeError:
        pass
    if result is None:
        reject_format()
    return result


def backup_placement(content: bytes) -> BackupPlacement:
    """Ровно четыре поля JSON операционной команды; никаких defaults."""
    document = None
    try:
        document = parse_strict_json_object(_text(content), comments=False)
    except ConfigDocumentError:
        pass
    if type(document) is not dict or set(document) != {"entware_uuid", "data_uuid", "backup_uuid", "keep"}:
        reject_format()
    values = tuple(document[key] for key in ("entware_uuid", "data_uuid", "backup_uuid"))
    if (not all(valid_storage_id(value) for value in values) or len(set(values)) != 3
            or type(document["keep"]) is not int or not 1 <= document["keep"] <= 30):
        reject_format()
    return BackupPlacement(*values)


def _replace(text: str, pattern: str, replacement: str, count: int = 1) -> tuple[str, tuple[str, ...]]:
    matches = tuple(match.group(1) for match in re.finditer(pattern, text, re.MULTILINE))
    if len(matches) != count:
        reject_format()
    normalized, replaced = re.subn(pattern, lambda match: match.group(0).replace(match.group(1), replacement, 1),
                                  text, flags=re.MULTILINE)
    if replaced != count:
        reject_format()
    return normalized, matches


def _positive(value: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]{0,18}", value):
        reject_format()
    result = int(value)
    if result > MAX_LIMIT_VALUE:
        reject_format()
    return result


def normalized_history(content: bytes) -> tuple[bytes, tuple[str, str, str, int]]:
    """Выделить только литералы известной формы shell, остальное оставить точным."""
    text = _text(content)
    values = []
    for name, marker in (("history_uuid", "__UUID__"), ("history_mount", "__MOUNT__"),
                         ("history_store", "__STORE__")):
        text, found = _replace(text, "^" + name + "=(.*)$", marker)
        values.append(found[0])
    storage_id, mount, path = values
    # Некавыченные shell-литералы не допускают подстановок, пробелов и операторов.
    if (not valid_storage_id(storage_id) or any(
        not valid_storage_path(value) or re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is None
        for value in (mount, path)
    )):
        reject_format()
    text, sizes = _replace(text, r'^  \[ "\$history_size" -le ([0-9]+) \] \|\|', "__BUDGET_KIB__")
    budget = _positive(sizes[0])
    if budget > MAX_LIMIT_VALUE // 1024:
        reject_format()
    text, free = _replace(text, r'^  \[ "\$\{history_free:-0\}" -ge ([0-9]+) \] \|\|', "__FREE_KIB__")
    _positive(free[0])
    return text.encode("utf-8"), (storage_id, mount, path, budget * 1024)


def normalized_ingest(content: bytes) -> tuple[bytes, int]:
    """Три согласованных срока очистки; другие SQL-операторы должны совпасть с эталоном."""
    text = _text(content)
    limits = []
    for table in ("cycles", "events", "internet_cycles"):
        pattern = r"^DELETE FROM " + table + r" WHERE utc < CAST\(strftime\('%s','now'\) AS INTEGER\)-([0-9]+);$"
        text, found = _replace(text, pattern, "__RETENTION_SECONDS__")
        limits.append(_positive(found[0]))
    if len(set(limits)) != 1:
        reject_format()
    text, pages = _replace(text, r"^PRAGMA max_page_count=([0-9]+);$", "__MAX_PAGES__")
    text, trim = _replace(text, r"^ \(SELECT page_count FROM pragma_page_count\)-\(SELECT freelist_count FROM pragma_freelist_count\)>([0-9]+) AS trim;$", "__TRIM_PAGES__")
    if _positive(trim[0]) >= _positive(pages[0]):
        reject_format()
    return text.encode("utf-8"), limits[0]


def history_placement(script: bytes, ingest: bytes) -> HistoryPlacement:
    """Получить размещение и независимые бюджет/срок только после проверки обоих текстов."""
    normalized_script, values = normalized_history(script)
    normalized_sql, retention = normalized_ingest(ingest)
    confirm_code(normalized_script, HISTORY_SCRIPT_SHA256)
    confirm_code(normalized_sql, HISTORY_INGEST_SHA256)
    return HistoryPlacement(*values, retention)
