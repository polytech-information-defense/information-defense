"""Тестовое окружение: дерево файлов ПО МЭ во временном каталоге и заглушки."""

import json
import tempfile
from pathlib import Path
from typing import Any

from fw_integrity.config import Settings


class FakeEvents:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    async def emit(self, code, description, *, success, ctx=None, details=None) -> None:
        self.items.append({"code": int(code), "description": description, "success": success,
                           "ctx": ctx, "details": details or {}})

    def codes(self) -> list[int]:
        return [e["code"] for e in self.items]

    def clear(self) -> None:
        self.items.clear()


class FakeTraffic:
    def __init__(self) -> None:
        self.blocked = False
        self.calls: list[str] = []

    async def block(self) -> list[str]:
        self.blocked = True
        self.calls.append("block")
        return []

    async def unblock(self) -> list[str]:
        self.blocked = False
        self.calls.append("unblock")
        return []


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


RW = {"user": "admin", "role": "rw", "iface": "console"}
RO = {"user": "viewer", "role": "ro", "iface": "web", "ip": "10.0.0.5"}
SUB = {"subsystem": "filter"}


class Env:
    """Мини-дерево ПО МЭ: код, неизменяемый конфиг, изменяемые конфиги."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        r = self.root
        self.code_a = r / "usr/lib/fw/fw_filter/main.py"
        self.code_b = r / "usr/lib/fw/fw_mgmt/main.py"
        self.default_conf = r / "etc/fw/default.conf"
        self.startup_conf = r / "etc/fw/startup.conf"
        self.policy = r / "var/lib/fw/policy.json"
        self.config_path = r / "etc/fw/integrity.json"
        self.manifest_path = r / "etc/fw/integrity/manifest.json"
        for path, text in [
            (self.code_a, "print('filter')\n"),
            (self.code_b, "print('mgmt')\n"),
            (self.default_conf, "{}\n"),
            (self.startup_conf, '{"filter": []}\n'),
            (self.policy, '{"version": 1}\n'),
            (self.config_path, "{}\n"),
        ]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(json.dumps({
            "static": [f"{r}/usr/lib/fw/**", f"{r}/etc/fw/default.conf"],
            "config": [f"{r}/etc/fw/startup.conf", f"{r}/var/lib/fw/*.json"],
            "exclude": [],
        }))
        self.settings = Settings(
            config_path=self.config_path,
            manifest_path=self.manifest_path,
            state_dir=r / "state",
            socket_path=r / "run/integrity.sock",
            socket_group=None,
            log_socket=r / "run/log.sock",
            filter_socket=r / "run/filter.sock",
            emergency_stop_units=(),
            pending_timeout_s=60.0,
            request_timeout_s=1.0,
        )

    def cleanup(self) -> None:
        self._tmp.cleanup()
