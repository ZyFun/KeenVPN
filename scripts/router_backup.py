#!/usr/bin/env python3
"""Тонкая CLI-команда создания приватного архива на Keenetic с Entware."""

import os
from pathlib import Path
import signal
import sys
import syslog

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keenvpn.application.backup import BackupError, create_backup
from keenvpn.adapters.router_backup import RouterBackupStorage, load_config


def main() -> int:
    """Ограничить время, не выводить исключения с приватными путями/содержимым."""
    if sys.argv[1:] or os.geteuid() != 0:
        print("Запустите vpn-backup без аргументов от root.", file=sys.stderr)
        return 2
    os.umask(0o077)
    os.nice(10)
    syslog.openlog("keenvpn-backup")

    def interrupt(_number, _frame):
        raise BackupError("Резервное копирование прервано или превышено время 30 минут.")

    for event in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(event, interrupt)
    signal.alarm(1800)
    try:
        config = load_config(Path("/opt/etc/vpn-backup.json"))
        result = create_backup(RouterBackupStorage(config))
    except BackupError as error:
        message = str(error)
        syslog.syslog(syslog.LOG_ERR, message)
        print(message, file=sys.stderr)
        return 1
    except Exception:
        message = "Ошибка файловой системы или проверки архива; ротация не завершена."
        syslog.syslog(syslog.LOG_ERR, message)
        print(message, file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
    message = f"Готово: {result.name}; {result.size} байт; сохранено копий: {result.retained}."
    syslog.syslog(syslog.LOG_INFO, message)
    print(message)
    print("SHA-256: " + result.sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
