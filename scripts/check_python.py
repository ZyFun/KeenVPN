#!/usr/bin/env python3
"""Проверить требования к Python без изменения конфигурации и сетевых запросов.

Это отдельная диагностическая утилита, не установщик и не vpn-menu.
Синтаксис запуска совместим с Python 3.9, чтобы показать отказ старой среды.
"""

import sys


MINIMUM_VERSION = (3, 12)

# Прямые требования первой версии; транзитивные импорты проверяются вместе с ними.
REQUIRED_MODULES = (
    "argparse", "getpass", "termios", "logging",
    "dataclasses", "enum", "typing", "contextlib",
    "json", "re", "ipaddress", "urllib.parse", "base64", "binascii",
    "unicodedata", "encodings.idna",
    "pathlib", "os", "stat", "shutil", "tempfile", "io",
    "hashlib", "hmac", "secrets", "uuid",
    "fcntl", "subprocess", "signal", "errno", "time", "datetime",
    "socket", "ssl", "urllib.request", "urllib.error", "http.client",
    "tarfile", "gzip", "zlib",
)


def version_is_eligible(version_info, implementation):
    """Проверить нижнюю границу, реализацию и отсутствие prerelease."""
    return (
        implementation == "cpython"
        and version_info[0] == 3
        and version_info[:2] >= MINIMUM_VERSION
        and version_info[3] == "final"
    )


def import_module(name):
    """Загрузить модуль, включая подмодуль, без зависимости от importlib."""
    return __import__(name, fromlist=["__name__"])


def check_python(version_info=None, implementation=None, importer=None):
    """Вернуть пары (идентификатор, успех) без терминального вывода.

    Версия и загрузчик подменяются в тестах. Сырые исключения не входят в отчёт.
    Проверка API не выполняет запись файлов, flock, subprocess или socket connect.
    """
    if version_info is None:
        version_info = sys.version_info
    if implementation is None:
        implementation = sys.implementation.name
    if importer is None:
        importer = import_module

    eligible = version_is_eligible(version_info, implementation)
    results = [("CPython 3.12+ (стабильная версия Python 3)", eligible)]
    if not eligible:
        return results

    modules = {}
    for name in REQUIRED_MODULES:
        try:
            modules[name] = importer(name)
        except Exception:
            # Даже сообщение ImportError может содержать приватный путь или секрет.
            results.append(("Импорт " + name, False))
        else:
            results.append(("Импорт " + name, True))

    def check_api(label, dependencies, check):
        """Не проверять возможности модулей, импорт которых уже завершился ошибкой."""
        if not all(name in modules for name in dependencies):
            return
        try:
            passed = bool(check())
        except Exception:
            passed = False
        results.append((label, passed))

    def filesystem_api():
        """Проверить наличие API, не выполнять файловые операции."""
        module = modules["os"]
        return (
            all(callable(getattr(module, name, None)) for name in (
                "replace", "fsync", "chmod", "fchmod", "open",
            ))
            and hasattr(module, "O_NOFOLLOW")
            and hasattr(module, "O_DIRECTORY")
        )

    def tls_client_context():
        """Создать контекст без сети, чтения CA и обработки SSLKEYLOGFILE."""
        ssl = modules["ssl"]
        # create_default_context может открыть SSLKEYLOGFILE из окружения.
        # Само хранилище сертификатов и TLS handshake проверяются отдельно.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        return context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED

    check_api("API файловых операций POSIX", ("os",), filesystem_api)
    check_api(
        "API блокировки flock", ("fcntl",),
        lambda: callable(getattr(modules["fcntl"], "flock", None))
        and all(hasattr(modules["fcntl"], name) for name in ("LOCK_EX", "LOCK_NB", "LOCK_UN")),
    )
    check_api(
        "API ограниченного запуска процессов", ("subprocess",),
        lambda: callable(getattr(modules["subprocess"], "run", None))
        and hasattr(modules["subprocess"], "TimeoutExpired"),
    )
    check_api("Контекст TLS с проверкой имени и сертификата", ("ssl",), tls_client_context)
    check_api(
        "SHA-256", ("hashlib",),
        lambda: modules["hashlib"].sha256(b"abc").hexdigest()
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    check_api(
        "JSON с Unicode", ("json",),
        lambda: modules["json"].loads(modules["json"].dumps({"name": "Проверка"}))
        == {"name": "Проверка"},
    )
    check_api(
        "IDNA-кодек", ("encodings.idna",),
        lambda: "пример.invalid".encode("idna") == b"xn--e1afmkfd.invalid",
    )
    check_api(
        "Сжатие gzip в памяти", ("gzip", "zlib"),
        lambda: modules["gzip"].decompress(modules["gzip"].compress(b"keenvpn-check"))
        == b"keenvpn-check",
    )
    check_api(
        "Фильтр tarfile.data_filter", ("tarfile",),
        lambda: callable(getattr(modules["tarfile"], "data_filter", None)),
    )
    return results


def main(argv=None):
    """Вывести безопасный отчёт; 0 — требования выполнены, 1 — нет, 2 — неверный вызов."""
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("Использование: python3 -I -S -B scripts/check_python.py", file=sys.stderr)
        return 2

    sys.dont_write_bytecode = True
    results = check_python()
    for label, passed in results:
        print(("OK: " if passed else "ОШИБКА: ") + label)
    print(
        "Не проверены: актуальность исправлений Python, пакеты Entware, CA/HTTPS, "
        "операции на USB, совместимость KeeneticOS, Xray/XKeen и работа VPN."
    )
    return 0 if all(passed for _, passed in results) else 1


if __name__ == "__main__":
    sys.exit(main())
