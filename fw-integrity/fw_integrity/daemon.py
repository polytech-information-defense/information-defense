"""Процесс fw-integrity: сокет API, проверка при запуске, периодическая проверка."""

import asyncio
import contextlib
import logging
import os
import signal
import socket

from .actions import SystemTrafficControl
from .config import Settings
from .events import LogClient
from .os_state import OsStateChecker
from .protocol import serve_unix
from .service import IntegrityService

log = logging.getLogger(__name__)

FLUSH_INTERVAL_S = 5.0


def sd_notify(message: str) -> None:
    """Сообщить systemd о готовности (Type=notify), без внешних библиотек."""
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(address)
            s.sendall(message.encode())
    except OSError as exc:
        log.warning("не удалось уведомить systemd: %s", exc)


async def _wait_any(*aws) -> None:
    tasks = [asyncio.ensure_future(a) for a in aws]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()


async def periodic_checks(service: IntegrityService, stop: asyncio.Event) -> None:
    """ЦЛС-03: проверка каждые period_min минут после предыдущей.

    При изменении периода и после проверки по запросу срок следующей
    проверки пересчитывается сразу.
    """
    while not stop.is_set():
        service.reschedule.clear()
        last = service.last_check_mono or service.clock()
        delay = max(0.0, last + service.state.period_min * 60 - service.clock())
        try:
            async with asyncio.timeout(delay):
                await _wait_any(stop.wait(), service.reschedule.wait())
        except TimeoutError:
            try:
                await service.run_check("periodic")
            except Exception:
                log.exception("ошибка периодической проверки")


async def flush_events(events: LogClient, stop: asyncio.Event) -> None:
    while not stop.is_set():
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(FLUSH_INTERVAL_S):
                await stop.wait()
        await events.flush()


async def run(settings: Settings) -> int:
    events = LogClient(settings.log_socket, timeout=settings.request_timeout_s)
    traffic = SystemTrafficControl(settings.filter_socket, settings.emergency_stop_units,
                                   timeout=settings.request_timeout_s)
    service = IntegrityService(settings, events, traffic, OsStateChecker(settings.os_check))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    # Сокет открывается раньше проверки: пока она идёт, управление уже может
    # узнать режим (get_status). Команды подождут блокировку.
    server = await serve_unix(settings.socket_path, service.handle, group=settings.socket_group)
    log.info("сокет %s открыт", settings.socket_path)

    result = await service.startup()
    log.info("проверка при запуске: %s, режим %s",
             "успешно" if result.ok else f"нарушений {len(result.violations)}", service.state.mode)
    # Только теперь systemd запустит службы с After=fw-integrity.service
    sd_notify("READY=1")

    tasks = [asyncio.create_task(periodic_checks(service, stop)),
             asyncio.create_task(flush_events(events, stop))]
    await stop.wait()
    log.info("остановка")
    sd_notify("STOPPING=1")
    server.close()
    await server.wait_closed()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await events.flush()
    with contextlib.suppress(FileNotFoundError):
        settings.socket_path.unlink()
    return 0
