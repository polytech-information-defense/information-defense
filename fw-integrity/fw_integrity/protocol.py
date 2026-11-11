"""Протокол обмена между подсистемами (АПИ-03, АПИ-04, АПИ-09).

Потоковый UNIX-сокет, UTF-8, один JSON-объект на строку.
Запрос:  {"id": 1, "command": "...", "params": {...}, "ctx": {...}}
Ответ:   {"id": 1, "status": "ok", "result": ...}
         {"id": 1, "status": "error", "error": {"code": "...", "message": "..."}}

Поле ctx -- контекст вызова (кто и откуда): для администратора
{"user", "role", "iface", "ip"}, для подсистемы {"subsystem"}.
"""

import asyncio
import contextlib
import grp
import itertools
import json
import logging
import os
import socket
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from .constants import ErrorCode

log = logging.getLogger(__name__)

MAX_LINE = 1 << 20
_ids = itertools.count(1)

type Handler = Callable[[str, dict[str, Any], dict[str, Any]], Awaitable[Any]]


class ApiError(Exception):
    def __init__(self, code: ErrorCode | str, message: str, request_id: Any = None):
        super().__init__(message)
        self.code = str(code)
        self.message = message
        self.request_id = request_id


def ok_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"id": request_id, "status": "ok", "result": result}


def error_response(request_id: Any, code: ErrorCode | str, message: str) -> dict[str, Any]:
    return {"id": request_id, "status": "error", "error": {"code": str(code), "message": message}}


def encode(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n"


def parse_request(line: bytes) -> tuple[Any, str, dict[str, Any], dict[str, Any]]:
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError(ErrorCode.BAD_REQUEST, f"некорректный JSON: {exc}") from None
    if not isinstance(obj, dict):
        raise ApiError(ErrorCode.BAD_REQUEST, "запрос должен быть JSON-объектом")
    req_id = obj.get("id")
    if isinstance(req_id, bool) or not isinstance(req_id, (int, str)):
        raise ApiError(ErrorCode.BAD_REQUEST, "поле id должно быть числом или строкой")
    command = obj.get("command")
    if not isinstance(command, str) or not command:
        raise ApiError(ErrorCode.BAD_REQUEST, "поле command должно быть непустой строкой", req_id)
    params = obj.get("params", {})
    if not isinstance(params, dict):
        raise ApiError(ErrorCode.BAD_REQUEST, "поле params должно быть объектом", req_id)
    ctx = obj.get("ctx", {})
    if not isinstance(ctx, dict):
        raise ApiError(ErrorCode.BAD_REQUEST, "поле ctx должно быть объектом", req_id)
    return req_id, command, params, ctx


async def dispatch(handler: Handler, line: bytes) -> dict[str, Any]:
    req_id = None
    try:
        req_id, command, params, ctx = parse_request(line)
        return ok_response(req_id, await handler(command, params, ctx))
    except ApiError as exc:
        return error_response(exc.request_id if req_id is None else req_id, exc.code, exc.message)
    except Exception:
        log.exception("внутренняя ошибка при обработке запроса")
        return error_response(req_id, ErrorCode.INTERNAL, "внутренняя ошибка подсистемы")


async def _client(handler: Handler, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            try:
                line = await reader.readline()
            except ValueError:
                writer.write(encode(error_response(None, ErrorCode.BAD_REQUEST, "слишком длинная строка")))
                await writer.drain()
                break
            if not line:
                break
            if not line.strip():
                continue
            writer.write(encode(await dispatch(handler, line)))
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def serve_unix(path: Path, handler: Handler, *, group: str | None = None) -> asyncio.Server:
    """Запустить сервер. Доступ к сокету: владелец и группа (АПИ-11)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    old = os.umask(0o117)
    try:
        server = await asyncio.start_unix_server(
            lambda r, w: _client(handler, r, w), path=str(path), limit=MAX_LINE)
    finally:
        os.umask(old)
    os.chmod(path, 0o660)
    if group:
        try:
            os.chown(path, -1, grp.getgrnam(group).gr_gid)
        except KeyError:
            log.warning("группа %s не найдена, сокет доступен только владельцу", group)
        except PermissionError:
            log.warning("нет прав сменить группу сокета на %s", group)
    return server


def _unwrap(resp: Any) -> Any:
    if not isinstance(resp, dict):
        raise ApiError(ErrorCode.INTERNAL, "некорректный ответ")
    if resp.get("status") == "ok":
        return resp.get("result")
    err = resp.get("error") or {}
    raise ApiError(err.get("code", ErrorCode.INTERNAL), err.get("message", "ошибка без описания"))


async def call(path: Path, command: str, params: dict[str, Any] | None = None,
               ctx: dict[str, Any] | None = None, *, timeout: float = 3.0) -> Any:
    """Отправить одну команду другой подсистеме и дождаться ответа."""
    request = {"id": next(_ids), "command": command, "params": params or {}}
    if ctx:
        request["ctx"] = ctx
    async with asyncio.timeout(timeout):
        reader, writer = await asyncio.open_unix_connection(str(path), limit=MAX_LINE)
        try:
            writer.write(encode(request))
            await writer.drain()
            line = await reader.readline()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    if not line:
        raise ConnectionError("подсистема закрыла соединение без ответа")
    return _unwrap(json.loads(line))


def call_sync(path: Path, command: str, params: dict[str, Any] | None = None,
              ctx: dict[str, Any] | None = None, *, timeout: float = 5.0) -> Any:
    """То же, что call(), но без asyncio -- для утилит и синхронного кода."""
    request = {"id": next(_ids), "command": command, "params": params or {}}
    if ctx:
        request["ctx"] = ctx
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(path))
        s.sendall(encode(request))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_LINE:
                raise ApiError(ErrorCode.INTERNAL, "слишком длинный ответ")
    if not buf:
        raise ConnectionError("подсистема закрыла соединение без ответа")
    return _unwrap(json.loads(buf))
