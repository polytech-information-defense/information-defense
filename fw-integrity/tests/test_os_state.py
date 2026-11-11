import json
import tempfile
import unittest
from pathlib import Path

from fw_integrity.config import OsCheckSettings
from fw_integrity.os_state import OsStateChecker

GOOD_ETHTOOL = """Features for eth1:
rx-checksumming: on
generic-segmentation-offload: off
tcp-segmentation-offload: off
generic-receive-offload: off
large-receive-offload: off [fixed]
rx-vlan-offload: off
tx-vlan-offload: off
"""


def nft_json(policy="accept", first_rule=({"drop": None},), devs=("eth1",)):
    items = [{"metainfo": {"version": "1.0.9"}},
             {"table": {"family": "netdev", "name": "fw"}},
             {"chain": {"family": "netdev", "table": "fw", "name": "in_eth1", "type": "filter",
                        "hook": "ingress", "prio": 0, "policy": policy,
                        "dev": devs[0] if len(devs) == 1 else list(devs)}}]
    if first_rule is not None:
        items.append({"rule": {"family": "netdev", "table": "fw", "chain": "in_eth1",
                               "expr": list(first_rule)}})
    return json.dumps({"nftables": items})


class FakeSystem:
    def __init__(self, root: Path):
        self.proc = root / "proc"
        self.net = root / "net"
        self.files = {
            "net/ipv4/ip_forward": "0",
            "net/ipv6/conf/all/forwarding": "0",
            "net/ipv6/conf/eth1/disable_ipv6": "1",
            "net/ipv6/conf/fwtap1/disable_ipv6": "1",
        }
        for rel, val in self.files.items():
            self.write_proc(rel, val)
        (self.net / "eth1").mkdir(parents=True)
        (self.net / "fwtap1").mkdir(parents=True)
        (self.net / "eth1/flags").write_text("0x1103\n")   # UP | BROADCAST | PROMISC | MULTICAST
        (self.net / "eth1/mtu").write_text("1500\n")
        self.outputs = {
            "ip": (0, json.dumps([{"ifname": "eth1", "addr_info": []}])),
            "ethtool": (0, GOOD_ETHTOOL),
            "nft": (0, nft_json()),
        }

    def write_proc(self, rel, val):
        p = self.proc / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(val + "\n")

    def runner(self, cmd):
        return self.outputs[cmd[0]]


class TestOsState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sys = FakeSystem(Path(self.tmp.name))
        settings = OsCheckSettings(enabled=True, ports=("eth1", "eth9"), service_ifaces=("fwtap1",))
        self.checker = OsStateChecker(settings, self.sys.runner, self.sys.proc, self.sys.net)

    def tearDown(self):
        self.tmp.cleanup()

    def names(self):
        return [v.path for v in self.checker.check()]

    def test_good_state(self):
        # eth9 отсутствует в ОС -- это не нарушение (ОБР-03)
        self.assertEqual(self.checker.check(), [])

    def test_disabled_check(self):
        c = OsStateChecker(OsCheckSettings(enabled=False), self.sys.runner, self.sys.proc, self.sys.net)
        self.sys.write_proc("net/ipv4/ip_forward", "1")
        self.assertEqual(c.check(), [])

    def test_ip_forward(self):
        self.sys.write_proc("net/ipv4/ip_forward", "1")
        self.assertEqual(self.names(), ["os:net.ipv4.ip_forward"])

    def test_ipv6_enabled_on_tap(self):
        self.sys.write_proc("net/ipv6/conf/fwtap1/disable_ipv6", "0")
        self.assertEqual(self.names(), ["os:fwtap1.disable_ipv6"])

    def test_promisc_and_mtu(self):
        (self.sys.net / "eth1/flags").write_text("0x1003\n")
        (self.sys.net / "eth1/mtu").write_text("9000\n")
        self.assertEqual(self.names(), ["os:eth1.promisc", "os:eth1.mtu"])

    def test_bridge_and_vlan(self):
        (self.sys.net / "eth1/master").write_text("")
        (self.sys.net / "eth1/upper_eth1.100").mkdir()
        self.assertEqual(self.names(), ["os:eth1.master", "os:eth1.upper"])

    def test_ipv4_address_on_port(self):
        self.sys.outputs["ip"] = (0, json.dumps([{"ifname": "eth1", "addr_info": [{"local": "10.0.0.1"}]}]))
        violations = self.checker.check()
        self.assertEqual([v.path for v in violations], ["os:eth1.ipv4"])
        self.assertIn("10.0.0.1", violations[0].detail)

    def test_offload_enabled(self):
        self.sys.outputs["ethtool"] = (0, GOOD_ETHTOOL.replace("generic-receive-offload: off",
                                                                "generic-receive-offload: on"))
        self.assertEqual(self.names(), ["os:eth1.gro"])

    def test_missing_tools_are_violations(self):
        self.sys.outputs = {"ip": (127, ""), "ethtool": (127, ""), "nft": (127, "")}
        self.assertEqual(self.names(), ["os:eth1.ipv4", "os:eth1.ethtool", "os:nft.eth1"])

    def test_nft_without_drop(self):
        self.sys.outputs["nft"] = (0, nft_json(first_rule=({"accept": None},)))
        self.assertEqual(self.names(), ["os:nft.eth1"])

    def test_nft_policy_drop_is_enough(self):
        self.sys.outputs["nft"] = (0, nft_json(policy="drop", first_rule=None))
        self.assertEqual(self.names(), [])

    def test_nft_devices_list(self):
        self.sys.outputs["nft"] = (0, nft_json(devs=("eth0", "eth1")))
        self.assertEqual(self.names(), [])


if __name__ == "__main__":
    unittest.main()
