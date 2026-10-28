"""Обезличенный снимок файлов роутера во временном корне для тестов источников чтения.

Раскладка повторяет пути проверенной платформы внутри корня: части Xray и
списки XKeen берутся из фикстур снимка, текст init и геобаза — искусственные.
Запуск `pidof` подменяет `ScriptedCommand`: тесты не запускают процессы роутера.
"""

from pathlib import Path

from keenvpn.adapters.router_sources import (
    GeoDatabaseFiles, XKeenInitFile, XKeenListFiles, XKeenSettingsFile, XrayConfigFiles, XrayProcessObserver,
)
from keenvpn.application.ports import RouterReadError
from keenvpn.interfaces.cli.composition import MenuSources
from tests.support.snapshot import load_xkeen_snapshot, load_xray_snapshot_files, snapshot_xkeen_settings_bytes


SYNTHETIC_INIT = (
    "#!/bin/sh\n"
    "# Искусственный init для тестов: только присваивания флагов снимка.\n"
    'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\nipv6_support="on"\n'
).encode("utf-8")
SYNTHETIC_GEOIP = b"synthetic-geoip-bytes-not-a-database"
SYNTHETIC_PIDOF = b"4242\n"
XRAY_CONFIGS = "opt/etc/xray/configs"
XKEEN = "opt/etc/xkeen"
INIT = "opt/etc/init.d/S05xkeen"
GEODATA = "opt/etc/xray/dat"
READY = "tmp/.xkeen/ready"


def write_router_snapshot(root: Path) -> None:
    """Разложить обезличенный снимок по путям платформы внутри `root`; `geosite.dat` отсутствует."""
    configs = root / XRAY_CONFIGS
    configs.mkdir(parents=True)
    for name, content in load_xray_snapshot_files().items():
        (configs / name).write_bytes(content)
    xkeen = root / XKEEN
    xkeen.mkdir(parents=True)
    (xkeen / "xkeen.json").write_bytes(snapshot_xkeen_settings_bytes())
    for name, text in load_xkeen_snapshot()["lists"].items():
        (xkeen / name).write_bytes(text.encode("utf-8"))
    (root / INIT).parent.mkdir(parents=True)
    (root / INIT).write_bytes(SYNTHETIC_INIT)
    (root / GEODATA).mkdir(parents=True)
    (root / GEODATA / "geoip.dat").write_bytes(SYNTHETIC_GEOIP)
    (root / READY).parent.mkdir(parents=True)
    (root / READY).write_bytes(b"")


class ScriptedCommand:
    """Подставной запуск команды: записывает вызовы и возвращает заданный результат или поднимает отказ."""

    def __init__(self, outcome: tuple[int, bytes] | BaseException = (0, SYNTHETIC_PIDOF)) -> None:
        self.outcome = outcome
        self.calls: list[tuple[tuple[str, ...], float, int]] = []

    def __call__(self, arguments: tuple[str, ...], timeout: float, limit: int) -> tuple[int, bytes]:
        self.calls.append((arguments, timeout, limit))
        if isinstance(self.outcome, BaseException):
            if isinstance(self.outcome, RouterReadError):
                self.outcome.__traceback__ = None
            raise self.outcome
        return self.outcome


def router_file_sources(root: Path, run: ScriptedCommand) -> MenuSources:
    """Источники меню, как у `--read-router`, но внутри временного корня и с подставным `pidof`."""
    base = str(root)
    return MenuSources(
        xray=XrayConfigFiles(root=base), xkeen_settings=XKeenSettingsFile(root=base), xkeen_init=XKeenInitFile(root=base),
        xkeen_lists=XKeenListFiles(root=base), geodata=GeoDatabaseFiles(root=base),
        process=XrayProcessObserver(root=base, run=run),
    )
