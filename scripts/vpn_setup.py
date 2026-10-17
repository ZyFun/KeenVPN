#!/usr/bin/env python3
"""Тонкая команда vpn-setup: открыть меню мастера KeenVPN в текущем терминале."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keenvpn.interfaces.cli.entrypoints import vpn_setup


if __name__ == "__main__":
    raise SystemExit(vpn_setup(sys.argv[1:], sys.stdin, sys.stdout, sys.stderr))
