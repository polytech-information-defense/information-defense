import asyncio
import json
import unittest

from fw_integrity.actions import SystemTrafficControl
from fw_integrity.events import LogClient
from fw_integrity.protocol import ApiError, call, call_sync, serve_unix
from fw_integrity.service import IntegrityService, initialize_reference

from helpers import RW, Env, FakeTraffic


async def raw_exchange(path, payload: bytes) -> dict:
    reader, writer = await asyncio.open_unix_connection(str(path))
    writer.write(payload)
    await writer.drain()
    line = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return json.loads(line)


class Recorder:
    """Заглушка чужой подсистемы: записывает команды и отвечает ok."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict, dict]] = []

    async def __call__(self, command, params, ctx):
        self.calls.append((command, params, ctx))
        return {}


class TestProtocol(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.env = Env()
        initialize_reference(self.env.settings)
        self.log = Recorder()
        self.log_server = await serve_unix(self.env.settings.log_socket, self.log)
        events = LogClient(self.env.settings.log_socket, timeout=1)
        self.svc = IntegrityService(self.env.settings, events, FakeTraffic(), boot_id=lambda: "b")
        self.server = await serve_unix(self.env.settings.socket_path, self.svc.handle)
        self.sock = self.env.settings.socket_path

    async def asyncTearDown(self):
        for s in (self.server, self.log_server):
            s.close()
            await s.wait_closed()
        self.env.cleanup()

    async def test_bad_json_returns_null_id(self):
        resp = await raw_exchange(self.sock, b"{oops\n")
        self.assertEqual(resp["id"], None)
        self.assertEqual(resp["status"], "error")
        self.assertEqual(resp["error"]["code"], "bad_request")

    async def test_not_an_object(self):
        resp = await raw_exchange(self.sock, b"[1,2]\n")
        self.assertEqual(resp["error"]["code"], "bad_request")

    async def test_missing_command_keeps_id(self):
        resp = await raw_exchange(self.sock, b'{"id": 7, "params": {}}\n')
        self.assertEqual(resp["id"], 7)
        self.assertEqual(resp["error"]["code"], "bad_request")

    async def test_unknown_command(self):
        request = {"id": "a", "command": "nope", "params": {}, "ctx": {"role": "rw", "user": "u"}}
        resp = await raw_exchange(self.sock, json.dumps(request).encode() + b"\n")
        self.assertEqual(resp, {"id": "a", "status": "error",
                                "error": {"code": "unknown_command", "message": "неизвестная команда 'nope'"}})

    async def test_full_check_over_socket_and_event_delivery(self):
        result = await call(self.sock, "integrity_check", {}, RW)
        self.assertTrue(result["ok"])
        sent = [c for c in self.log.calls if c[0] == "log_event"]
        self.assertEqual(sent[-1][1]["code"], 500)
        self.assertEqual(sent[-1][1]["user"], "admin")
        self.assertEqual(sent[-1][1]["subsystem"], "integrity")

    async def test_error_raised_on_client(self):
        with self.assertRaises(ApiError) as cm:
            await call(self.sock, "set_params", {"period_min": 0}, RW)
        self.assertEqual(cm.exception.code, "invalid_params")

    async def test_sync_client(self):
        status = await asyncio.to_thread(call_sync, self.sock, "get_status", {}, RW)
        self.assertEqual(status["mode"], "normal")

    async def test_several_requests_on_one_connection(self):
        reader, writer = await asyncio.open_unix_connection(str(self.sock))
        for i in range(3):
            writer.write(json.dumps({"id": i, "command": "get_params", "params": {}, "ctx": RW}).encode() + b"\n")
        await writer.drain()
        ids = [json.loads(await reader.readline())["id"] for _ in range(3)]
        writer.close()
        await writer.wait_closed()
        self.assertEqual(ids, [0, 1, 2])


class TestEventQueue(unittest.IsolatedAsyncioTestCase):
    async def test_events_queued_until_log_available(self):
        env = Env()
        try:
            client = LogClient(env.settings.log_socket, timeout=0.5)
            await client.emit(500, "test", success=True)
            await client.emit(501, "test2", success=False, ctx={"user": "u", "role": "rw"})
            self.assertEqual(len(client.queue), 2)
            rec = Recorder()
            server = await serve_unix(env.settings.log_socket, rec)
            await client.flush()
            self.assertEqual(len(client.queue), 0)
            self.assertEqual([c[1]["code"] for c in rec.calls], [500, 501])
            self.assertNotIn("role", rec.calls[1][1])   # роль в журнал не пишется, только пользователь
            server.close()
            await server.wait_closed()
        finally:
            env.cleanup()


class TestTrafficControl(unittest.IsolatedAsyncioTestCase):
    async def test_block_and_unblock(self):
        env = Env()
        try:
            filt = Recorder()
            server = await serve_unix(env.settings.filter_socket, filt)
            commands = []

            async def runner(cmd):
                commands.append(list(cmd))
                return 0, ""

            tc = SystemTrafficControl(env.settings.filter_socket, ["fw-filter.service", "fw-web.service"],
                                      timeout=1, runner=runner, retries=2, retry_delay=0)
            self.assertEqual(await tc.block(), [])
            self.assertEqual(await tc.unblock(), [])
            self.assertEqual([(c[0], c[1]) for c in filt.calls],
                             [("set_emergency", {"enabled": True}), ("set_emergency", {"enabled": False})])
            self.assertEqual(commands, [["systemctl", "stop", "fw-filter.service", "fw-web.service"],
                                        ["systemctl", "start", "fw-filter.service", "fw-web.service"]])
            server.close()
            await server.wait_closed()
        finally:
            env.cleanup()

    async def test_block_reports_unreachable_filter(self):
        env = Env()
        try:
            async def runner(cmd):
                return 0, ""
            tc = SystemTrafficControl(env.settings.filter_socket, [], timeout=0.5, runner=runner)
            warnings = await tc.block()
            self.assertEqual(len(warnings), 1)
            self.assertIn("не подтвердила", warnings[0])
        finally:
            env.cleanup()


if __name__ == "__main__":
    unittest.main()
