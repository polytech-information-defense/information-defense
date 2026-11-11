"""Помощники для других подсистем.

Легитимное изменение конфигурационного файла (ЦЛС-02) обязательно
оборачивается в begin_update / commit_update, иначе следующая проверка
сочтёт изменение нарушением и включит аварийный режим:

    from fw_integrity.client import legit_update, atomic_write

    with legit_update("/var/lib/fw/policy.json", subsystem="filter"):
        atomic_write("/var/lib/fw/policy.json", data)

Писать файл нужно атомарно (временный файл + rename): если запись
прервётся, на диске останется старое содержимое, совпадающее с эталоном.
"""

import contextlib
from collections.abc import Iterator
from pathlib import Path

from .protocol import call_sync
from .util import atomic_write_bytes

DEFAULT_SOCKET = Path("/run/fw/integrity.sock")


@contextlib.contextmanager
def legit_update(path: str | Path, *, subsystem: str,
                 socket_path: Path = DEFAULT_SOCKET, timeout: float = 10.0) -> Iterator[None]:
    ctx = {"subsystem": subsystem}
    params = {"path": str(path)}
    call_sync(socket_path, "begin_update", params, ctx, timeout=timeout)
    try:
        yield
    except BaseException:
        with contextlib.suppress(Exception):
            call_sync(socket_path, "abort_update", params, ctx, timeout=timeout)
        raise
    call_sync(socket_path, "commit_update", params, ctx, timeout=timeout)


def atomic_write(path: str | Path, data: bytes | str, mode: int = 0o640) -> None:
    if isinstance(data, str):
        data = data.encode("utf-8")
    atomic_write_bytes(Path(path), data, mode)
