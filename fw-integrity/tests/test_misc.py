import contextlib
import io
import json
import unittest
from pathlib import Path

from fw_integrity.cli import main
from fw_integrity.config import ConfigError, load_settings
from fw_integrity.constants import Kind
from fw_integrity.manifest import Manifest, ManifestError

from helpers import Env


class TestManifest(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.m = Manifest.load(self.env.manifest_path, extra_static=(self.env.config_path,))

    def tearDown(self):
        self.env.cleanup()

    def test_classify(self):
        r = self.env.root
        self.assertIs(self.m.classify(f"{r}/usr/lib/fw/a/b/c.py"), Kind.STATIC)
        self.assertIs(self.m.classify(f"{r}/var/lib/fw/policy.json"), Kind.CONFIG)
        self.assertIsNone(self.m.classify(f"{r}/var/lib/fw/sub/x.json"))   # * не проходит через /
        self.assertIs(self.m.classify(str(self.env.manifest_path)), Kind.STATIC)
        self.assertIs(self.m.classify(str(self.env.config_path)), Kind.STATIC)

    def test_exclude(self):
        m = Manifest(static=(f"{self.env.root}/usr/lib/fw/**",), config=(),
                     exclude=(f"{self.env.root}/usr/lib/fw/**/*.log",))
        self.assertIsNone(m.classify(f"{self.env.root}/usr/lib/fw/x/run.log"))

    def test_expand_includes_hidden(self):
        hidden = self.env.code_a.parent / ".x.py"
        hidden.write_text("x")
        self.assertIn(str(hidden), self.m.expand())

    def test_relative_pattern_rejected(self):
        self.env.manifest_path.write_text(json.dumps({"static": ["usr/lib"], "config": []}))
        with self.assertRaises(ManifestError):
            Manifest.load(self.env.manifest_path)


class TestSettings(unittest.TestCase):
    def test_defaults_when_missing(self):
        s = load_settings(Path("/nonexistent/integrity.json"))
        self.assertEqual(s.socket_path, Path("/run/fw/integrity.sock"))

    def test_load_and_validate(self):
        env = Env()
        try:
            env.config_path.write_text(json.dumps({
                "state_dir": "/tmp/x", "emergency_stop_units": ["a.service"],
                "os_check": {"enabled": True, "ports": ["eth1"]}}))
            s = load_settings(env.config_path)
            self.assertEqual(s.emergency_stop_units, ("a.service",))
            self.assertTrue(s.os_check.enabled)
            env.config_path.write_text(json.dumps({"unknown": 1}))
            with self.assertRaises(ConfigError):
                load_settings(env.config_path)
            env.config_path.write_text(json.dumps({"state_dir": "relative"}))
            with self.assertRaises(ConfigError):
                load_settings(env.config_path)
        finally:
            env.cleanup()


class TestCli(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        s = self.env.settings
        self.env.config_path.write_text(json.dumps({
            "manifest_path": str(s.manifest_path), "state_dir": str(s.state_dir),
            "socket_path": str(s.socket_path), "socket_group": None}))

    def tearDown(self):
        self.env.cleanup()

    def run_cli(self, *args) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--config", str(self.env.config_path), *args])
        return code, out.getvalue() + err.getvalue()

    def test_init_twice_needs_force(self):
        self.assertEqual(self.run_cli("init")[0], 0)
        code, text = self.run_cli("init")
        self.assertEqual(code, 1)
        self.assertIn("--force", text)
        self.assertEqual(self.run_cli("init", "--force")[0], 0)

    def test_gate_closed_before_first_check(self):
        self.run_cli("init")
        code, text = self.run_cli("gate")
        self.assertEqual(code, 1)

    def test_debug_command_without_daemon(self):
        code, text = self.run_cli("status")
        self.assertEqual(code, 1)
        self.assertIn("недоступен", text)


if __name__ == "__main__":
    unittest.main()
