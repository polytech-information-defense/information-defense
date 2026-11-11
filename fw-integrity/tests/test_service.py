import json
import unittest

from fw_integrity.constants import Event, Mode
from fw_integrity.protocol import ApiError
from fw_integrity.service import IntegrityService, gate, initialize_reference
from fw_integrity.store import ReferenceStore, StateStore

from helpers import RO, RW, SUB, Env, FakeClock, FakeEvents, FakeTraffic

BOOT = "boot-1"


class ServiceTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.env = Env()
        self.events = FakeEvents()
        self.traffic = FakeTraffic()
        self.clock = FakeClock()

    def tearDown(self) -> None:
        self.env.cleanup()

    def make_service(self) -> IntegrityService:
        return IntegrityService(self.env.settings, self.events, self.traffic,
                                clock=self.clock, boot_id=lambda: BOOT)

    def init(self) -> dict:
        return initialize_reference(self.env.settings)


class TestCheck(ServiceTestCase):
    async def test_init_counts_kinds(self):
        stats = self.init()
        # код (2), default.conf, сам манифест, файл настроек -- static; startup.conf, policy.json -- config
        self.assertEqual(stats, {"files": 7, "static": 5, "config": 2})

    async def test_startup_ok(self):
        self.init()
        svc = self.make_service()
        result = await svc.startup()
        self.assertTrue(result.ok)
        self.assertEqual(self.events.codes(), [Event.CHECK_OK])
        self.assertIs(svc.state.mode, Mode.NORMAL)
        self.assertEqual(gate(self.env.settings, boot_id=lambda: BOOT)[0], True)

    async def test_modified_static_file_enters_emergency(self):
        self.init()
        svc = self.make_service()
        await svc.startup()
        self.events.clear()
        self.env.code_a.write_text("print('evil')\n")
        result = await svc.run_check("periodic")
        self.assertFalse(result.ok)
        self.assertEqual([v.reason for v in result.violations], ["modified"])
        self.assertTrue(self.traffic.blocked)
        self.assertEqual(self.events.codes(), [Event.VIOLATION, Event.EMERGENCY_ENTER])
        self.assertEqual(self.events.items[0]["details"]["files"], [str(self.env.code_a)])
        # режим сохранён на диск, и gate не пустит фильтрацию
        self.assertIs(StateStore(self.env.settings.state_dir).load().mode, Mode.EMERGENCY)
        self.assertFalse(gate(self.env.settings, boot_id=lambda: BOOT)[0])

    async def test_missing_and_added_files(self):
        self.init()
        svc = self.make_service()
        self.env.code_b.unlink()
        intruder = self.env.code_a.parent / ".hidden.py"
        intruder.write_text("import os\n")
        result = await svc.startup()
        reasons = {v.path: str(v.reason) for v in result.violations}
        self.assertEqual(reasons, {str(self.env.code_b): "missing", str(intruder): "added"})

    async def test_violation_at_startup_blocks_immediately(self):
        """ЦЛС-07."""
        self.init()
        self.env.default_conf.write_text('{"tampered": true}\n')
        svc = self.make_service()
        await svc.startup()
        self.assertIs(svc.state.mode, Mode.EMERGENCY)
        self.assertEqual(self.traffic.calls, ["block"])

    async def test_no_reference_means_emergency(self):
        svc = self.make_service()
        result = await svc.startup()
        self.assertFalse(result.ok)
        self.assertEqual(str(result.violations[0].reason), "missing")
        self.assertIs(svc.state.mode, Mode.EMERGENCY)

    async def test_broken_manifest_means_emergency(self):
        self.init()
        self.env.manifest_path.write_text("{not json")
        svc = self.make_service()
        await svc.startup()
        self.assertIs(svc.state.mode, Mode.EMERGENCY)
        paths = [v["path"] for v in svc.state.violations]
        self.assertIn(str(self.env.manifest_path), paths)

    async def test_same_violation_not_repeated_in_emergency(self):
        self.init()
        svc = self.make_service()
        self.env.code_a.write_text("x\n")
        await svc.startup()
        self.events.clear()
        await svc.run_check("periodic")
        self.assertEqual(self.events.codes(), [])
        self.env.code_b.write_text("y\n")
        await svc.run_check("periodic")
        self.assertEqual(self.events.codes(), [Event.VIOLATION])

    async def test_corrupted_state_file_is_emergency(self):
        self.init()
        state = self.env.settings.state_dir / "state.json"
        state.write_text("garbage")
        self.assertIs(StateStore(self.env.settings.state_dir).load().mode, Mode.EMERGENCY)
        self.assertFalse(gate(self.env.settings, boot_id=lambda: BOOT)[0])

    async def test_gate_requires_check_in_current_boot(self):
        self.init()
        svc = self.make_service()
        await svc.startup()
        self.assertTrue(gate(self.env.settings, boot_id=lambda: BOOT)[0])
        self.assertFalse(gate(self.env.settings, boot_id=lambda: "boot-2")[0])


class TestRestore(ServiceTestCase):
    async def asyncSetUp(self):
        self.init()
        self.original = self.env.code_a.read_text()
        self.svc = self.make_service()
        self.env.code_a.write_text("print('evil')\n")
        self.intruder = self.env.code_a.parent / "backdoor.py"
        self.intruder.write_text("evil\n")
        await self.svc.startup()
        self.assertIs(self.svc.state.mode, Mode.EMERGENCY)
        self.events.clear()

    async def test_restore_all_and_recheck_leaves_emergency(self):
        res = await self.svc.handle("restore", {"all": True}, RW)
        self.assertEqual(res["restored"], [str(self.env.code_a)])
        self.assertEqual(len(res["quarantined"]), 1)
        self.assertFalse(self.intruder.exists())
        self.assertEqual(self.env.code_a.read_text(), self.original)

        check = await self.svc.handle("integrity_check", {}, RW)
        self.assertTrue(check["ok"])
        self.assertEqual(check["mode"], "normal")
        self.assertEqual(self.traffic.calls, ["block", "unblock"])
        self.assertEqual(self.events.codes(),
                         [Event.FILE_RESTORED, Event.FILE_RESTORED, Event.CHECK_OK, Event.EMERGENCY_LEAVE])
        self.assertEqual(self.events.items[0]["ctx"]["user"], "admin")

    async def test_restore_single_path(self):
        res = await self.svc.handle("restore", {"path": str(self.env.code_a)}, RW)
        self.assertEqual(res["restored"], [str(self.env.code_a)])

    async def test_restore_requires_rw(self):
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("restore", {"all": True}, RO)
        self.assertEqual(cm.exception.code, "forbidden")
        self.assertEqual(self.events.codes(), [Event.ACCESS_DENIED])

    async def test_restore_rejects_corrupted_backup(self):
        store = ReferenceStore(self.env.settings.state_dir)
        store.load()
        backup = store.backup_file(store.entries[str(self.env.code_a)].sha256)
        backup.write_text("corrupted")
        res = await self.svc.handle("restore", {"path": str(self.env.code_a)}, RW)
        self.assertEqual(res["restored"], [])
        self.assertIn("повреждена", res["failed"][0]["error"])

    async def test_restore_unknown_path(self):
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("restore", {"path": "/nonexistent"}, RW)
        self.assertEqual(cm.exception.code, "not_found")

    async def test_restore_bad_params(self):
        for params in ({}, {"all": True, "path": "/x"}, {"all": "yes"}, {"path": "relative"}):
            with self.subTest(params=params), self.assertRaises(ApiError) as cm:
                await self.svc.handle("restore", params, RW)
            self.assertEqual(cm.exception.code, "invalid_params")


class TestLegitimateUpdate(ServiceTestCase):
    async def asyncSetUp(self):
        self.init()
        self.svc = self.make_service()
        await self.svc.startup()
        self.events.clear()
        self.path = str(self.env.policy)

    async def test_begin_modify_commit(self):
        await self.svc.handle("begin_update", {"path": self.path}, SUB)
        self.env.policy.write_text('{"version": 2}\n')
        # проверка во время изменения файл пропускает
        result = await self.svc.run_check("periodic")
        self.assertTrue(result.ok)
        self.assertEqual(result.skipped, [self.path])
        res = await self.svc.handle("commit_update", {"path": self.path}, SUB)
        self.assertEqual(res["action"], "updated")
        self.assertEqual(self.events.codes()[-1], Event.REFERENCE_UPDATED)
        self.assertTrue((await self.svc.run_check("periodic")).ok)

    async def test_change_without_begin_is_violation(self):
        self.env.policy.write_text('{"version": 666}\n')
        result = await self.svc.run_check("periodic")
        self.assertFalse(result.ok)
        self.assertIs(self.svc.state.mode, Mode.EMERGENCY)

    async def test_pending_expires(self):
        await self.svc.handle("begin_update", {"path": self.path}, SUB)
        self.env.policy.write_text('{"version": 2}\n')
        self.clock.t += 61
        self.assertFalse((await self.svc.run_check("periodic")).ok)

    async def test_new_config_file(self):
        new = self.env.policy.parent / "system.json"
        await self.svc.handle("begin_update", {"path": str(new)}, SUB)
        new.write_text("{}\n")
        await self.svc.handle("commit_update", {"path": str(new)}, SUB)
        self.assertTrue((await self.svc.run_check("periodic")).ok)

    async def test_remove_config_file(self):
        await self.svc.handle("begin_update", {"path": self.path}, SUB)
        self.env.policy.unlink()
        res = await self.svc.handle("commit_update", {"path": self.path}, SUB)
        self.assertEqual(res["action"], "removed")
        self.assertTrue((await self.svc.run_check("periodic")).ok)

    async def test_abort(self):
        await self.svc.handle("begin_update", {"path": self.path}, SUB)
        res = await self.svc.handle("abort_update", {"path": self.path}, SUB)
        self.assertTrue(res["aborted"])
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("commit_update", {"path": self.path}, SUB)
        self.assertEqual(cm.exception.code, "invalid_state")

    async def test_static_file_cannot_be_updated(self):
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("begin_update", {"path": str(self.env.code_a)}, SUB)
        self.assertEqual(cm.exception.code, "invalid_params")

    async def test_admin_cannot_call_internal_commands(self):
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("begin_update", {"path": self.path}, RW)
        self.assertEqual(cm.exception.code, "forbidden")

    async def test_updates_refused_in_emergency(self):
        self.env.code_a.write_text("evil\n")
        await self.svc.run_check("periodic")
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("begin_update", {"path": self.path}, SUB)
        self.assertEqual(cm.exception.code, "invalid_state")


class TestParamsAndAccess(ServiceTestCase):
    async def asyncSetUp(self):
        self.init()
        self.svc = self.make_service()
        await self.svc.startup()
        self.events.clear()

    async def test_set_period(self):
        res = await self.svc.handle("set_params", {"period_min": 30}, RW)
        self.assertEqual(res, {"period_min": 30})
        self.assertEqual(self.events.items[-1]["code"], Event.PARAMS_CHANGED)
        self.assertEqual(self.events.items[-1]["details"]["period_min"], {"old": 10, "new": 30})
        self.assertTrue(self.svc.reschedule.is_set())
        saved = json.loads((self.env.settings.state_dir / "state.json").read_text())
        self.assertEqual(saved["period_min"], 30)

    async def test_set_period_validation(self):
        for value in (0, 1441, "10", True, 2.5, None):
            with self.subTest(value=value), self.assertRaises(ApiError) as cm:
                await self.svc.handle("set_params", {"period_min": value}, RW)
            self.assertEqual(cm.exception.code, "invalid_params")
        with self.assertRaises(ApiError):
            await self.svc.handle("set_params", {"period_min": 5, "extra": 1}, RW)

    async def test_bounds_allowed(self):
        for value in (1, 1440):
            await self.svc.handle("set_params", {"period_min": value}, RW)

    async def test_ro_can_view_but_not_change(self):
        status = await self.svc.handle("get_status", {}, RO)
        self.assertEqual(status["mode"], "normal")
        self.assertEqual(status["next_check_in_s"], 600)
        check = await self.svc.handle("integrity_check", {}, RO)   # функция 29 доступна ТЧ
        self.assertTrue(check["ok"])
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("set_params", {"period_min": 5}, RO)
        self.assertEqual(cm.exception.code, "forbidden")

    async def test_subsystem_can_apply_params(self):
        await self.svc.handle("set_params", {"period_min": 15}, {"subsystem": "mgmt"})

    async def test_no_context_is_forbidden(self):
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("get_status", {}, {})
        self.assertEqual(cm.exception.code, "forbidden")

    async def test_unknown_command(self):
        with self.assertRaises(ApiError) as cm:
            await self.svc.handle("format_disk", {}, RW)
        self.assertEqual(cm.exception.code, "unknown_command")



class TestPeriodic(ServiceTestCase):
    async def test_periodic_loop_runs_checks_and_stops(self):
        import asyncio
        import time

        from fw_integrity.daemon import periodic_checks

        self.init()
        svc = IntegrityService(self.env.settings, self.events, self.traffic, boot_id=lambda: BOOT)
        await svc.startup()
        svc.state.period_min = 0.001          # ~60 мс, только для теста (через API так нельзя)
        stop = asyncio.Event()
        task = asyncio.create_task(periodic_checks(svc, stop))
        start = time.monotonic()
        while self.events.codes().count(Event.CHECK_OK) < 4 and time.monotonic() - start < 5:
            await asyncio.sleep(0.02)
        stop.set()
        await asyncio.wait_for(task, 2)
        self.assertGreaterEqual(self.events.codes().count(Event.CHECK_OK), 4)
        triggers = {e["details"].get("trigger") for e in self.events.items}
        self.assertIn("periodic", triggers)

if __name__ == "__main__":
    unittest.main()
