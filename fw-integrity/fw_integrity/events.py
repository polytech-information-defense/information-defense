"""Отправка событий в подсистему регистрации (РЕГ-01, РЕГ-02).

Событие отправляется командой ``log_event`` в сокет подсистемы регистрации.
Если она недоступна, события копятся в очереди и досылаются позже, а пока
дублируются в журнал процесса (stderr, его собирает journald), чтобы
событие не потерялось бесследно.
"""

import logging
from collections import deque
from pathlib import Path
from typing import Any, Protocol

from .constants import SUBSYSTEM
from .protocol import ApiError, call
from .util import now_iso

log = logging.getLogger(__name__)

# Поля контекста администратора, которые попадают в запись журнала (РЕГ-02)
CTX_FIELDS = ("user", "ip", "iface", "subsystem")


class EventSink(Protocol):
    async def emit(self, code: int, description: str, *, success: bool,
                   ctx: dict[str, Any] | None = None,
                   details: dict[str, Any] | None = None) -> None: ...


def make_event(code: int, description: str, *, success: bool,
               ctx: dict[str, Any] | None, details: dict[str, Any] | None) -> dict[str, Any]:
    event: dict[str, Any] = {
        "time": now_iso(),
        "code": int(code),
        "description": description,
        "success": success,
        "subsystem": SUBSYSTEM,
        "details": details or {},
    }
    for key in CTX_FIELDS:
        if ctx and ctx.get(key) is not None:
            event["initiator_subsystem" if key == "subsystem" else key] = ctx[key]
    return event


class LogClient:
    """Клиент подсистемы регистрации с очередью недоставленных событий."""

    def __init__(self, socket_path: Path, *, timeout: float = 3.0, maxlen: int = 1000):
        self.socket_path = Path(socket_path)
        self.timeout = timeout
        self.queue: deque[dict[str, Any]] = deque(maxlen=maxlen)

    async def emit(self, code: int, description: str, *, success: bool,
                   ctx: dict[str, Any] | None = None,
                   details: dict[str, Any] | None = None) -> None:
        event = make_event(code, description, success=success, ctx=ctx, details=details)
        log.info("событие %s: %s %s", code, description, event["details"] or "")
        if len(self.queue) == self.queue.maxlen:
            log.error("очередь событий переполнена, самое старое событие потеряно")
        self.queue.append(event)
        await self.flush()

    async def flush(self) -> None:
        while self.queue:
            event = self.queue[0]
            try:
                await call(self.socket_path, "log_event", event,
                           ctx={"subsystem": SUBSYSTEM}, timeout=self.timeout)
            except ApiError as exc:
                # Подсистема регистрации отвергла событие -- повтор не поможет
                log.error("событие %s отклонено подсистемой регистрации: %s", event["code"], exc.message)
            except (OSError, TimeoutError, ValueError) as exc:
                log.debug("подсистема регистрации недоступна (%s), в очереди %d", exc, len(self.queue))
                return
            self.queue.popleft()
