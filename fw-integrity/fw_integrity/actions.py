"""Глобальная блокировка трафика (ЦЛС-04) и её снятие (ЦЛС-06).

Блокировка в два эшелона:
1. команда ``set_emergency`` подсистеме фильтрации: она сразу начинает
   удалять все кадры (стрелка «глобальная блокировка» на схеме);
2. остановка служб из ``emergency_stop_units`` (по умолчанию fw-filter,
   fw-web, ssh). После остановки fw-filter кадры портов по-прежнему
   отбрасываются правилом drop на netdev ingress (ОБР-02), поэтому трафик
   не пройдёт, даже если исполняемый файл фильтрации повреждён.
   В аварийном режиме остаётся только локальный CLI (ЦЛС-05).
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Protocol

from .constants import SUBSYSTEM
from .protocol import ApiError, call

log = logging.getLogger(__name__)

CommandRunner = Callable[[Sequence[str]], Awaitable[tuple[int, str]]]


class TrafficControl(Protocol):
    async def block(self) -> list[str]: ...
    async def unblock(self) -> list[str]: ...


async def run_command(cmd: Sequence[str], timeout: float = 60.0) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError:
        return 127, f"{cmd[0]}: команда не найдена"
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, "превышено время выполнения"
    return proc.returncode or 0, out.decode(errors="replace").strip()


class SystemTrafficControl:
    def __init__(self, filter_socket: Path, units: Sequence[str], *,
                 timeout: float = 3.0, runner: CommandRunner = run_command,
                 retries: int = 10, retry_delay: float = 0.5):
        self.filter_socket = Path(filter_socket)
        self.units = tuple(units)
        self.timeout = timeout
        self.runner = runner
        self.retries = retries
        self.retry_delay = retry_delay

    async def _set_filter(self, enabled: bool) -> str | None:
        try:
            await call(self.filter_socket, "set_emergency", {"enabled": enabled},
                       ctx={"subsystem": SUBSYSTEM}, timeout=self.timeout)
            return None
        except (ApiError, OSError, TimeoutError, ValueError) as exc:
            return str(exc) or type(exc).__name__

    async def block(self) -> list[str]:
        warnings: list[str] = []
        if (err := await self._set_filter(True)) is not None:
            warnings.append(f"подсистема фильтрации не подтвердила блокировку: {err}")
        if self.units:
            rc, out = await self.runner(["systemctl", "stop", *self.units])
            if rc != 0:
                warnings.append(f"systemctl stop завершился с кодом {rc}: {out}")
        for w in warnings:
            log.warning(w)
        return warnings

    async def unblock(self) -> list[str]:
        warnings: list[str] = []
        if self.units:
            rc, out = await self.runner(["systemctl", "start", *self.units])
            if rc != 0:
                warnings.append(f"systemctl start завершился с кодом {rc}: {out}")
        # Фильтрация могла не останавливаться (если её нет в списке служб)
        # или ещё не успела открыть сокет после запуска -- пробуем несколько раз.
        err = None
        for _ in range(self.retries):
            if (err := await self._set_filter(False)) is None:
                break
            await asyncio.sleep(self.retry_delay)
        if err is not None:
            warnings.append(f"подсистема фильтрации не подтвердила снятие блокировки: {err}")
        for w in warnings:
            log.warning(w)
        return warnings
