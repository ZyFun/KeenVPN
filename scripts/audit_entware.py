#!/usr/bin/env python3
"""Исследовать локальную копию каталога и IPK Entware, не исполняя их.

Утилита для разработчика на Mac/Linux, не установщик и не проверка роутера.
Поддерживает простой формат Depends исследованного каталога без ограничений
версий и альтернатив. Неизвестный формат останавливает аудит.
"""

import sys

sys.dont_write_bytecode = True

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import ssl
import tarfile


ROOT_PACKAGES = (
    "python3-light", "python3-codecs", "python3-logging", "python3-openssl",
    "python3-urllib", "python3-uuid", "ca-bundle",
)
PROVIDERS = {"ca-certs": "ca-bundle"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+.-]*\Z")
MAX_INDEX = 16 * 1024 * 1024
MAX_IPK = 64 * 1024 * 1024
MAX_TAR = 128 * 1024 * 1024


class AuditError(Exception):
    """Ошибка аудита с фиксированным текстом без содержимого входных файлов."""


def read_limited(path, limit):
    """Ограничить чтение файла; исходный путь не входит в сообщения утилиты."""
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise AuditError("Превышен допустимый размер входного файла.")
    return data


def parse_index(data):
    """Прочитать записи Packages; описания и строки продолжения не используются."""
    records = {}
    for paragraph in data.decode("utf-8").strip().split("\n\n"):
        record = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                if key in record:
                    raise AuditError("Повтор поля в записи каталога.")
                record[key] = value
        name = record.get("Package", "")
        if not NAME.fullmatch(name) or name in records:
            raise AuditError("Некорректная или повторная запись пакета.")
        records[name] = record
    return records


def dependency_closure(records, roots=ROOT_PACKAGES, providers=None):
    """Собрать зависимости без повторов; виртуальный пакет требует явного выбора."""
    providers = PROVIDERS if providers is None else providers
    selected = {}

    def visit(requested):
        if not NAME.fullmatch(requested):
            raise AuditError("Неподдерживаемое выражение зависимости.")
        name = providers.get(requested, requested)
        if name not in records:
            raise AuditError("Зависимость или выбранный поставщик отсутствует.")
        record = records[name]
        if name != requested and requested not in record.get("Provides", "").split(", "):
            raise AuditError("Пакет не предоставляет выбранную зависимость.")
        if name in selected:
            return
        selected[name] = record
        for dependency in record.get("Depends", "").split(","):
            if dependency.strip():
                visit(dependency.strip())

    for root in roots:
        visit(root)
    return selected


def inspect_ipk(data, record):
    """Проверить SHA-256/размер, затем прочитать tar в памяти без извлечения."""
    if len(data) != int(record["Size"]) or hashlib.sha256(data).hexdigest() != record["SHA256sum"]:
        raise AuditError("Размер или SHA-256 архива не совпадает с каталогом.")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        outer = compressed.read(MAX_TAR + 1)
    if len(outer) > MAX_TAR:
        raise AuditError("Превышен допустимый размер оболочки IPK.")
    with tarfile.open(fileobj=io.BytesIO(outer), mode="r:") as archive:
        candidates = [m for m in archive if m.name in ("data.tar.gz", "./data.tar.gz")]
        if len(candidates) != 1 or not candidates[0].isfile() or candidates[0].size > MAX_IPK:
            raise AuditError("Неизвестный формат IPK.")
        with gzip.GzipFile(fileobj=archive.extractfile(candidates[0])) as payload:
            unpacked = payload.read(MAX_TAR + 1)
    if len(unpacked) > MAX_TAR:
        raise AuditError("Превышен допустимый размер содержимого IPK.")

    files, regular_bytes, blocks_4k, members = {}, 0, 0, 0
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as payload:
        for member in payload:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise AuditError("Недопустимый путь в архиве.")
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise AuditError("Неподдерживаемый тип записи в архиве.")
            members += 1
            blocks_4k += ((member.size + 4095) // 4096) * 4096 if member.isfile() else 4096
            if member.isfile():
                name = str(path)
                if name in files:
                    raise AuditError("Повтор файла в архиве.")
                files[name] = payload.extractfile(member).read()
                regular_bytes += member.size
    return files, {
        "payload_tar_bytes": len(unpacked), "regular_file_bytes": regular_bytes,
        "estimated_4k_bytes": blocks_4k, "archive_members": members,
    }


def module_owners(module, inventories):
    """Найти файл модуля; для двух встроенных модулей проверить символ libpython."""
    suffix = "/" + module.replace(".", "/")
    owners = []
    for package, files in inventories.items():
        found = any(
            name.endswith((suffix + ".pyc", suffix + "/__init__.pyc", suffix + ".py", suffix + "/__init__.py"))
            or (suffix + ".cpython-" in name and name.endswith(".so"))
            for name in files
        )
        if module in ("errno", "time"):
            found = found or any(
                "/libpython" in name and ("PyInit_" + module).encode() in data
                for name, data in files.items()
            )
        if found:
            owners.append(package)
    return owners


def ca_count(data):
    """Загрузить только выбранный PEM в память без системного CA/fallback и сети."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=data.decode("ascii"))
    count = context.cert_store_stats()["x509_ca"]
    if not count or not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise AuditError("Не удалось загрузить CA с обязательной проверкой сертификатов.")
    return count


def load_python_requirements():
    """Загрузить общее правило версии и список модулей диагностической утилиты."""
    spec = importlib.util.spec_from_file_location("check_python", Path(__file__).with_name("check_python.py"))
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    return checker


def audit(index_data, archive_directory, required_modules=None):
    """Вернуть публичный статический отчёт; пути и исходные исключения не выводятся."""
    checker = load_python_requirements()
    if required_modules is None:
        required_modules = checker.REQUIRED_MODULES
    selected = dependency_closure(parse_index(index_data))
    python_versions = {
        record["Version"] for name, record in selected.items()
        if name.startswith("python3-") or name == "libpython3"
    }
    if len(python_versions) != 1:
        raise AuditError("Выбранные пакеты Python относятся к разным сборкам.")
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:-[0-9]+)?", next(iter(python_versions)))
    if match is None:
        raise AuditError("Неподдерживаемый формат версии пакетов Python.")
    version_info = tuple(int(part) for part in match.groups()) + ("final", 0)
    if not checker.version_is_eligible(version_info, "cpython"):
        raise AuditError("Выбранная ветка Python не соответствует требованиям проекта.")
    inventories, packages = {}, {}
    for name, record in selected.items():
        filename = record["Filename"]
        if not re.fullmatch(r"[A-Za-z0-9_+.~:-]+\.ipk", filename):
            raise AuditError("Недопустимое имя файла пакета.")
        if record["Architecture"] not in ("aarch64-3.10", "all"):
            raise AuditError("Архитектура пакета не соответствует исследуемому каталогу.")
        if not re.fullmatch(r"[A-Za-z0-9_+.~:-]+", record["Version"]):
            raise AuditError("Неподдерживаемый формат версии пакета.")
        if not re.fullmatch(r"[0-9]+", record["Installed-Size"]):
            raise AuditError("Неизвестный размер установленного пакета.")
        files, sizes = inspect_ipk(read_limited(Path(archive_directory) / filename, MAX_IPK), record)
        inventories[name] = files
        packages[name] = {
            "version": record["Version"], "sha256": record["SHA256sum"],
            "download_bytes": int(record["Size"]),
            "installed_size_field": int(record["Installed-Size"]), **sizes,
        }
    ownership = {module: module_owners(module, inventories) for module in required_modules}
    if not all(ownership.values()):
        raise AuditError("Для обязательного модуля не найден файл или встроенный символ.")
    # Наличие ssl.pyc недостаточно: расширения криптобиблиотеки проверяются отдельно.
    for module in ("_ssl", "_hashlib", "_uuid"):
        if not module_owners(module, inventories):
            raise AuditError("Не найдено необходимое бинарное расширение Python.")
    certificates = ca_count(inventories["ca-bundle"]["opt/etc/ssl/certs/ca-certificates.crt"])
    totals = {key: sum(p[key] for p in packages.values()) for key in (
        "download_bytes", "installed_size_field", "payload_tar_bytes",
        "regular_file_bytes", "estimated_4k_bytes", "archive_members",
    )}
    return {
        "index_sha256": hashlib.sha256(index_data).hexdigest(),
        "roots": list(ROOT_PACKAGES), "packages": packages, "totals": totals,
        "module_owners": ownership, "ca_count_local": certificates,
        "limitations": "Статический аудит. Не проверены ABI/импорты Entware, HTTPS, свободное место и работа роутера/VPN.",
    }


def main(argv=None):
    """Два пути на входе; 0 — аудит пройден, 1 — ошибка, 2 — неверный вызов."""
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("Использование: python3 -I -S -B scripts/audit_entware.py PACKAGES IPK_DIR", file=sys.stderr)
        return 2
    try:
        report = audit(read_limited(argv[0], MAX_INDEX), argv[1])
    except Exception:
        print("Ошибка аудита: проверьте каталог, полный набор архивов, их целостность, зависимости и CA.", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
