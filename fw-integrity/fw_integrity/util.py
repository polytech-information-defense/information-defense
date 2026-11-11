"""Вспомогательные функции: атомарная запись, время, идентификатор загрузки."""

import contextlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def now_iso() -> str:
    """Текущее время с часовым поясом, с точностью до миллисекунд."""
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def fsync_dir(directory: Path) -> None:
    """Сбросить на диск запись каталога (нужно после os.replace)."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Записать файл атомарно: временный файл, fsync, rename.

    Читатель всегда видит либо старое, либо новое содержимое целиком.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def atomic_write_json(path: Path, obj: Any, mode: int = 0o600) -> None:
    data = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    atomic_write_bytes(path, data + b"\n", mode)


def read_boot_id(path: Path = BOOT_ID_PATH) -> str | None:
    """Идентификатор текущей загрузки ядра (меняется при каждой перезагрузке)."""
    try:
        return path.read_text().strip()
    except OSError:
        return None
