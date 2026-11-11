"""Командная строка fw-integrity.

    fw-integrity run                 запустить процесс подсистемы (для systemd)
    fw-integrity init [--force]      сформировать эталоны (при установке ПО МЭ)
    fw-integrity gate                можно ли запускать фильтрацию (код 0 -- да)

Служебные команды для отладки (через сокет процесса, нужен доступ к нему).
Администратор пользуется этими функциями через fw-cli и web-интерфейс:
    fw-integrity status | check | violations
    fw-integrity restore PATH | --all
    fw-integrity set-period MINUTES
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .config import DEFAULT_CONFIG_PATH, ConfigError, load_settings
from .manifest import ManifestError
from .protocol import ApiError, call_sync
from .store import StoreError

DEBUG_CTX = {"user": "root", "role": "rw", "iface": "console"}


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fw-integrity", description="Подсистема контроля целостности ПО МЭ")
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="файл настроек")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="запустить процесс подсистемы")
    init = sub.add_parser("init", help="сформировать эталоны")
    init.add_argument("--force", action="store_true", help="пересоздать существующие эталоны")
    sub.add_parser("gate", help="проверить, можно ли запускать фильтрацию")
    sub.add_parser("status")
    sub.add_parser("check")
    sub.add_parser("violations")
    r = sub.add_parser("restore")
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("path", nargs="?")
    g.add_argument("--all", action="store_true")
    sp = sub.add_parser("set-period")
    sp.add_argument("minutes", type=int)
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"ошибка настроек: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "run":
        from .daemon import run
        return asyncio.run(run(settings))

    if args.cmd == "init":
        from .service import initialize_reference
        try:
            stats = initialize_reference(settings, force=args.force)
        except (StoreError, ManifestError, OSError) as exc:
            print(f"ошибка: {exc}", file=sys.stderr)
            return 1
        print(f"эталоны сформированы: {stats['files']} файлов "
              f"(неизменяемых {stats['static']}, конфигурационных {stats['config']})")
        return 0

    if args.cmd == "gate":
        from .service import gate
        allowed, reason = gate(settings)
        print(reason, file=sys.stdout if allowed else sys.stderr)
        return 0 if allowed else 1

    command, params = {
        "status": ("get_status", {}),
        "check": ("integrity_check", {}),
        "violations": ("list_violations", {}),
        "restore": ("restore", {"all": True} if getattr(args, "all", False) else {"path": getattr(args, "path", None)}),
        "set-period": ("set_params", {"period_min": getattr(args, "minutes", None)}),
    }[args.cmd]
    try:
        _print(call_sync(settings.socket_path, command, params, DEBUG_CTX, timeout=600))
    except ApiError as exc:
        print(f"ошибка {exc.code}: {exc.message}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"процесс fw-integrity недоступен: {exc}", file=sys.stderr)
        return 1
    return 0
