"""Проверка состояния ОС по таблице настроек ОБР-02.

По ОБР-02 расхождение с таблицей при проверке целостности считается
нарушением целостности (ЦЛС-04). Проверяется:
    - net.ipv4.ip_forward = 0, net.ipv6.conf.all.forwarding = 0;
    - disable_ipv6 = 1 на обслуживаемых и служебных интерфейсах;
    - у обслуживаемых интерфейсов нет IPv4-адресов;
    - обслуживаемые интерфейсы не входят в мост/bond и над ними нет VLAN;
    - promisc on, MTU 1500;
    - gro, lro, gso, tso, rxvlan, txvlan выключены (ethtool -k);
    - в таблице netdev есть цепочка ingress с drop для каждого порта.

Если состояние не удаётся проверить (нет утилиты, ошибка команды), это тоже
нарушение: непроверенное состояние нельзя считать правильным.
"""

import json
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .checker import Reason, Violation
from .config import OsCheckSettings

Runner = Callable[[Sequence[str]], tuple[int, str]]

IFF_PROMISC = 0x100

ETHTOOL_FEATURES = {
    "gro": "generic-receive-offload",
    "lro": "large-receive-offload",
    "gso": "generic-segmentation-offload",
    "tso": "tcp-segmentation-offload",
    "rxvlan": "rx-vlan-offload",
    "txvlan": "tx-vlan-offload",
}


def default_runner(cmd: Sequence[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(list(cmd), capture_output=True, text=True, timeout=10, check=False)
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""
    return p.returncode, p.stdout


class OsStateChecker:
    def __init__(self, settings: OsCheckSettings, runner: Runner = default_runner,
                 proc_sys: Path = Path("/proc/sys"), sys_net: Path = Path("/sys/class/net")):
        self.s = settings
        self.run = runner
        self.proc_sys = Path(proc_sys)
        self.sys_net = Path(sys_net)

    def check(self) -> list[Violation]:
        if not self.s.enabled:
            return []
        out: list[Violation] = []
        out += self._sysctl()
        present_ports = [p for p in self.s.ports if (self.sys_net / p).exists()]
        # Отсутствующий порт -- не нарушение целостности: по ОБР-03 он
        # помечается недоступным, остальные интерфейсы работают.
        for port in present_ports:
            out += self._port(port)
        for iface in self.s.service_ifaces:
            if (self.sys_net / iface).exists():
                out += self._ipv6_disabled(iface)
        out += self._nft(present_ports)
        return out

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _v(name: str, detail: str) -> Violation:
        return Violation(f"os:{name}", Reason.OS_STATE, detail)

    @staticmethod
    def _read(path: Path) -> str | None:
        try:
            return path.read_text().strip()
        except OSError:
            return None

    def _sysctl(self) -> list[Violation]:
        out = []
        value = self._read(self.proc_sys / "net/ipv4/ip_forward")
        if value != "0":
            out.append(self._v("net.ipv4.ip_forward", f"ожидается 0, сейчас {value}"))
        f = self.proc_sys / "net/ipv6/conf/all/forwarding"
        if f.exists() and (value := self._read(f)) != "0":
            out.append(self._v("net.ipv6.conf.all.forwarding", f"ожидается 0, сейчас {value}"))
        return out

    def _ipv6_disabled(self, iface: str) -> list[Violation]:
        f = self.proc_sys / "net/ipv6/conf" / iface / "disable_ipv6"
        if f.exists() and (value := self._read(f)) != "1":
            return [self._v(f"{iface}.disable_ipv6", f"ожидается 1, сейчас {value}")]
        return []   # нет файла -- IPv6 в ядре выключен целиком

    def _port(self, port: str) -> list[Violation]:
        out = self._ipv6_disabled(port)
        base = self.sys_net / port

        flags = self._read(base / "flags")
        try:
            if not int(flags or "", 16) & IFF_PROMISC:
                out.append(self._v(f"{port}.promisc", "режим promisc выключен"))
        except ValueError:
            out.append(self._v(f"{port}.promisc", "не удалось прочитать флаги интерфейса"))

        mtu = self._read(base / "mtu")
        if mtu != str(self.s.expected_mtu):
            out.append(self._v(f"{port}.mtu", f"ожидается {self.s.expected_mtu}, сейчас {mtu}"))

        if (base / "master").exists():
            out.append(self._v(f"{port}.master", "интерфейс включён в мост или bond"))
        uppers = sorted(p.name.removeprefix("upper_") for p in base.glob("upper_*"))
        if uppers:
            out.append(self._v(f"{port}.upper", f"над интерфейсом созданы {', '.join(uppers)}"))

        rc, text = self.run(["ip", "-j", "-4", "addr", "show", "dev", port])
        try:
            if rc != 0:
                raise ValueError(f"код возврата {rc}")
            data = json.loads(text or "[]")
            addrs = [a.get("local") for item in data for a in item.get("addr_info", [])]
            if addrs:
                out.append(self._v(f"{port}.ipv4", f"назначены адреса {', '.join(map(str, addrs))}"))
        except ValueError as exc:
            out.append(self._v(f"{port}.ipv4", f"не удалось проверить адреса: {exc}"))

        rc, text = self.run(["ethtool", "-k", port])
        if rc != 0:
            out.append(self._v(f"{port}.ethtool", f"не удалось выполнить ethtool -k (код {rc})"))
        else:
            states = {}
            for line in text.splitlines():
                name, sep, rest = line.strip().partition(":")
                if sep:
                    states[name.strip()] = rest.strip()
            for short, long in ETHTOOL_FEATURES.items():
                value = states.get(long)
                if value is not None and not value.startswith("off"):
                    out.append(self._v(f"{port}.{short}", f"ожидается off, сейчас {value}"))
        return out

    def _nft(self, ports: list[str]) -> list[Violation]:
        if not ports:
            return []
        table = self.s.nft_table
        rc, text = self.run(["nft", "-j", "list", "table", "netdev", table])
        try:
            if rc != 0:
                raise ValueError(f"таблица netdev {table} не найдена (код {rc})")
            items: list[dict[str, Any]] = json.loads(text)["nftables"]
        except (ValueError, KeyError, TypeError) as exc:
            return [self._v(f"nft.{p}", str(exc)) for p in ports]

        chains: dict[str, dict[str, Any]] = {}
        rules: dict[str, list[list[Any]]] = {}
        for item in items:
            if "chain" in item:
                c = item["chain"]
                chains[c.get("name", "")] = c
            elif "rule" in item:
                r = item["rule"]
                rules.setdefault(r.get("chain", ""), []).append(r.get("expr", []))

        out = []
        for port in ports:
            if not any(self._chain_drops(name, c, rules.get(name, []), port)
                       for name, c in chains.items()):
                out.append(self._v(f"nft.{port}",
                                   f"нет цепочки ingress с drop для {port} в таблице netdev {table}"))
        return out

    @staticmethod
    def _chain_drops(name: str, chain: dict[str, Any], rules: list[list[Any]], port: str) -> bool:
        if chain.get("hook") != "ingress":
            return False
        devs = chain.get("dev", chain.get("devices", []))
        devs = [devs] if isinstance(devs, str) else list(devs or [])
        if port not in devs:
            return False
        drop_rule = [{"drop": None}]
        if rules and rules[0] == drop_rule:
            return True
        has_accept = any(any("accept" in e for e in expr if isinstance(e, dict)) for expr in rules)
        return chain.get("policy") == "drop" and not has_accept
