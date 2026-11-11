"""Логика подсистемы контроля целостности.

Класс IntegrityService не зависит от сокетов и systemd: всё внешнее
(журнал, блокировка трафика, проверка ОС, часы) передаётся в конструктор.
Поэтому его можно целиком проверить тестами.

Команды API (таблица COMMANDS ниже):
    get_status       состояние подсистемы                        ТЧ, ЧЗ
    integrity_check  проверка по запросу (ЦЛС-03, функция 29)    ТЧ, ЧЗ
    list_violations  перечень нарушений (ЦЛС-05)                 ТЧ, ЧЗ
    get_params       период проверки                            ТЧ, ЧЗ
    set_params       изменить период (ЦЛС-03, функция 30)        ЧЗ, подсистема
    restore          восстановить файл(ы) из копии (ЦЛС-05)      ЧЗ
    begin_update     начать легитимное изменение (ЦЛС-02)        подсистема
    commit_update    завершить его и обновить эталон            подсистема
    abort_update     отменить его                               подсистема
"""

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from enum import Enum, auto
from typing import Any

from .actions import TrafficControl
from .checker import CheckResult, Reason, Violation, check_files
from .config import Settings
from .constants import PERIOD_MAX, PERIOD_MIN, ErrorCode, Event, Kind, Mode, Role
from .events import EventSink
from .manifest import Manifest, ManifestError
from .os_state import OsStateChecker
from .protocol import ApiError
from .store import BackupError, ReferenceStore, StateStore, StoreError
from .util import now_iso, read_boot_id

log = logging.getLogger(__name__)


class Access(Enum):
    READ = auto()       # администратор ТЧ или ЧЗ, подсистема
    WRITE = auto()      # администратор ЧЗ, подсистема (применение конфигурации)
    ADMIN = auto()      # только администратор ЧЗ
    INTERNAL = auto()   # только подсистема


type Command = Callable[[dict[str, Any], dict[str, Any]], Awaitable[Any]]


def _only(params: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(params) - allowed
    if unknown:
        raise ApiError(ErrorCode.INVALID_PARAMS, f"неизвестные параметры: {', '.join(sorted(unknown))}")


def _path(params: dict[str, Any]) -> str:
    value = params.get("path")
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise ApiError(ErrorCode.INVALID_PARAMS, "параметр path должен быть абсолютным путём")
    return os.path.normpath(value)


class IntegrityService:
    def __init__(self, settings: Settings, events: EventSink, traffic: TrafficControl,
                 os_checker: OsStateChecker | None = None, *,
                 clock: Callable[[], float] = time.monotonic,
                 boot_id: Callable[[], str | None] = read_boot_id):
        self.settings = settings
        self.events = events
        self.traffic = traffic
        self.os_checker = os_checker or OsStateChecker(settings.os_check)
        self.clock = clock
        self.boot_id = boot_id
        self.store = ReferenceStore(settings.state_dir)
        self.state_store = StateStore(settings.state_dir)
        self.state = self.state_store.load()
        self.manifest: Manifest | None = None
        self.pending: dict[str, float] = {}       # путь -> время begin_update
        self.lock = asyncio.Lock()
        self.reschedule = asyncio.Event()   # пересчитать срок следующей проверки
        self.last_check_mono: float | None = None
        self.commands: dict[str, tuple[Access, Command]] = {
            "get_status": (Access.READ, self.cmd_status),
            "integrity_check": (Access.READ, self.cmd_check),
            "list_violations": (Access.READ, self.cmd_violations),
            "get_params": (Access.READ, self.cmd_get_params),
            "set_params": (Access.WRITE, self.cmd_set_params),
            "restore": (Access.ADMIN, self.cmd_restore),
            "begin_update": (Access.INTERNAL, self.cmd_begin_update),
            "commit_update": (Access.INTERNAL, self.cmd_commit_update),
            "abort_update": (Access.INTERNAL, self.cmd_abort_update),
        }

    # ================================================================ запуск
    async def startup(self) -> CheckResult:
        """Проверка при запуске (ЦЛС-03). При нарушении -- сразу аварийный режим (ЦЛС-07)."""
        return await self.run_check("startup")

    # ================================================================ проверка
    def _load_manifest(self) -> Manifest:
        self.manifest = Manifest.load(self.settings.manifest_path,
                                      extra_static=(self.settings.config_path,))
        return self.manifest

    def _active_pending(self) -> set[str]:
        now = self.clock()
        for path, started in list(self.pending.items()):
            if now - started > self.settings.pending_timeout_s:
                log.warning("изменение %s не завершено за %.0f с, файл снова проверяется",
                            path, self.settings.pending_timeout_s)
                del self.pending[path]
        return set(self.pending)

    def _check_sync(self, skip: set[str]) -> CheckResult:
        """Сама проверка; выполняется в отдельном потоке, чтобы не блокировать сокет."""
        started = now_iso()
        violations: list[Violation] = []
        manifest: Manifest | None = None
        reference = None
        try:
            manifest = self._load_manifest()
        except ManifestError as exc:
            violations.append(Violation(str(self.settings.manifest_path), Reason.UNREADABLE, str(exc)))
        try:
            self.store.load()
            reference = dict(self.store.entries)
        except StoreError as exc:
            reason = Reason.UNREADABLE if self.store.exists() else Reason.MISSING
            violations.append(Violation(str(self.store.path), reason, str(exc)))
        checked = 0
        skipped: list[str] = []
        if reference is not None:
            present = manifest.expand() if manifest else {}
            checked, found, skipped = check_files(reference, present, skip)
            violations += found
        violations += self.os_checker.check()
        return CheckResult(started=started, finished=now_iso(), checked=checked,
                           violations=violations, skipped=skipped)

    async def run_check(self, trigger: str, ctx: dict[str, Any] | None = None) -> CheckResult:
        async with self.lock:
            try:
                result = await asyncio.to_thread(self._check_sync, self._active_pending())
            finally:
                self.last_check_mono = self.clock()
                self.reschedule.set()
            await self._apply_result(result, trigger, ctx)
        return result

    async def _apply_result(self, result: CheckResult, trigger: str, ctx: dict[str, Any] | None) -> None:
        st = self.state
        st.last_check = {"time": result.finished, "ok": result.ok, "checked": result.checked,
                         "violations": len(result.violations), "trigger": trigger}
        st.boot_id = self.boot_id()
        found = [v.to_dict() for v in result.violations]

        if result.ok:
            st.violations = []
            self._save_state()
            await self.events.emit(Event.CHECK_OK, "Проверка целостности завершена успешно",
                                   success=True, ctx=ctx,
                                   details={"trigger": trigger, "checked": result.checked})
            if st.mode is Mode.EMERGENCY:
                await self._leave_emergency(ctx)
            return

        changed = found != st.violations
        st.violations = found
        if st.mode is Mode.NORMAL:
            await self._enter_emergency(result, trigger, ctx)
        else:
            self._save_state()
            if changed:   # в аварийном режиме не повторяем одно и то же событие каждые N минут
                await self._emit_violation(result, trigger, ctx)

    async def _emit_violation(self, result: CheckResult, trigger: str, ctx: dict[str, Any] | None) -> None:
        await self.events.emit(
            Event.VIOLATION, "Выявлено нарушение целостности", success=False, ctx=ctx,
            details={"trigger": trigger,
                     "files": [v.path for v in result.violations],
                     "violations": [v.to_dict() for v in result.violations]})

    # ======================================================== аварийный режим
    async def _enter_emergency(self, result: CheckResult, trigger: str, ctx: dict[str, Any] | None) -> None:
        """ЦЛС-04: заблокировать трафик, зарегистрировать событие, перейти в аварийный режим.

        Режим сохраняется на диск ДО блокировки: если fw-filter попытаются
        перезапустить, проверка gate в его юните уже не пропустит запуск.
        """
        self.state.mode = Mode.EMERGENCY
        self.state.since = now_iso()
        self._save_state()
        warnings = await self.traffic.block()
        await self._emit_violation(result, trigger, ctx)
        await self.events.emit(Event.EMERGENCY_ENTER,
                               "Переход в режим аварийной поддержки, трафик заблокирован",
                               success=not warnings, ctx=ctx, details={"warnings": warnings})

    async def _leave_emergency(self, ctx: dict[str, Any] | None) -> None:
        """ЦЛС-06: повторная проверка успешна -- возобновить обработку трафика."""
        self.state.mode = Mode.NORMAL
        self.state.since = now_iso()
        self._save_state()
        warnings = await self.traffic.unblock()
        await self.events.emit(Event.EMERGENCY_LEAVE,
                               "Выход из режима аварийной поддержки, обработка трафика возобновлена",
                               success=not warnings, ctx=ctx, details={"warnings": warnings})

    def _save_state(self) -> None:
        self.state_store.save(self.state)

    # ================================================================ API
    async def handle(self, command: str, params: dict[str, Any], ctx: dict[str, Any]) -> Any:
        entry = self.commands.get(command)
        if entry is None:
            raise ApiError(ErrorCode.UNKNOWN_COMMAND, f"неизвестная команда {command!r}")
        access, func = entry
        await self._authorize(command, access, ctx)
        return await func(params, ctx)

    async def _authorize(self, command: str, access: Access, ctx: dict[str, Any]) -> None:
        role = ctx.get("role")
        subsystem = ctx.get("subsystem")
        allowed = {
            Access.READ: bool(subsystem) or role in (Role.RO, Role.RW),
            Access.WRITE: bool(subsystem) or role == Role.RW,
            Access.ADMIN: role == Role.RW and bool(ctx.get("user")),
            Access.INTERNAL: bool(subsystem),
        }[access]
        if not allowed:
            await self.events.emit(Event.ACCESS_DENIED,
                                   "Отказ в выполнении функции (недостаточно прав)",
                                   success=False, ctx=ctx, details={"command": command})
            raise ApiError(ErrorCode.FORBIDDEN, f"недостаточно прав для команды {command!r}")

    # ------------------------------------------------------------- просмотр
    async def cmd_status(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        _only(params, set())
        next_in = None
        if self.last_check_mono is not None:
            due = self.last_check_mono + self.state.period_min * 60
            next_in = max(0, round(due - self.clock()))
        return {
            "mode": str(self.state.mode),
            "since": self.state.since,
            "period_min": self.state.period_min,
            "last_check": self.state.last_check,
            "violations": len(self.state.violations),
            "pending_updates": sorted(self.pending),
            "next_check_in_s": next_in,
            "reference_files": len(self.store.entries),
        }

    async def cmd_check(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        _only(params, set())
        result = await self.run_check("request", ctx)
        return {**result.to_dict(), "mode": str(self.state.mode)}

    async def cmd_violations(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        _only(params, set())
        return {"mode": str(self.state.mode), "since": self.state.since,
                "violations": self.state.violations}

    async def cmd_get_params(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        _only(params, set())
        return {"period_min": self.state.period_min}

    # ------------------------------------------------------------ параметры
    async def cmd_set_params(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        _only(params, {"period_min"})
        if "period_min" not in params:
            raise ApiError(ErrorCode.INVALID_PARAMS, "не задан параметр period_min")
        value = params["period_min"]
        if isinstance(value, bool) or not isinstance(value, int) or not PERIOD_MIN <= value <= PERIOD_MAX:
            raise ApiError(ErrorCode.INVALID_PARAMS,
                           f"period_min должен быть целым числом от {PERIOD_MIN} до {PERIOD_MAX}")
        old = self.state.period_min
        if value != old:
            self.state.period_min = value
            self._save_state()
            self.reschedule.set()
            await self.events.emit(Event.PARAMS_CHANGED,
                                   "Изменение параметров контроля целостности",
                                   success=True, ctx=ctx,
                                   details={"period_min": {"old": old, "new": value}})
        return {"period_min": value}

    # --------------------------------------------------------- восстановление
    async def cmd_restore(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        """ЦЛС-05: восстановить файл (path) или все нарушенные файлы (all=true).

        Изменённый или удалённый файл восстанавливается из резервной копии,
        посторонний файл перемещается в карантин. Проверку после
        восстановления запускает администратор (integrity_check).
        """
        _only(params, {"path", "all"})
        restore_all = params.get("all", False)
        if not isinstance(restore_all, bool) or restore_all == ("path" in params):
            raise ApiError(ErrorCode.INVALID_PARAMS, "укажите либо path, либо all=true")
        single = None if restore_all else _path(params)

        async with self.lock:
            try:
                self.store.load()
            except StoreError as exc:
                raise ApiError(ErrorCode.INVALID_STATE, f"восстановление невозможно: {exc}") from None
            if restore_all:
                targets = [v["path"] for v in self.state.violations if v.get("reason") != Reason.OS_STATE]
            else:
                targets = [single]
            manifest = self.manifest
            restored, quarantined, failed = [], [], []
            for path in targets:
                if path in self.store.entries:
                    try:
                        await asyncio.to_thread(self.store.restore, path)
                    except (BackupError, OSError) as exc:
                        failed.append({"path": path, "error": str(exc)})
                        await self.events.emit(Event.FILE_RESTORED,
                                               "Восстановление файла из резервной копии",
                                               success=False, ctx=ctx,
                                               details={"path": path, "error": str(exc)})
                        continue
                    restored.append(path)
                    await self.events.emit(Event.FILE_RESTORED,
                                           "Восстановление файла из резервной копии",
                                           success=True, ctx=ctx, details={"path": path})
                elif os.path.isfile(path) and manifest is not None and manifest.classify(path):
                    moved = await asyncio.to_thread(self.store.quarantine, path)
                    quarantined.append({"path": path, "moved_to": str(moved)})
                    await self.events.emit(Event.FILE_RESTORED,
                                           "Посторонний файл перемещён в карантин",
                                           success=True, ctx=ctx,
                                           details={"path": path, "moved_to": str(moved)})
                elif single is not None:
                    raise ApiError(ErrorCode.NOT_FOUND, f"файл {path} не контролируется")
                else:
                    failed.append({"path": path, "error": "нет эталона и файла"})
        return {"restored": restored, "quarantined": quarantined, "failed": failed,
                "next": "выполните повторную проверку: integrity_check"}

    # ---------------------------------------------------- легитимные изменения
    async def cmd_begin_update(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        """ЦЛС-02: подсистема собирается изменить конфигурационный файл.

        Берём блокировку, чтобы не начать запись посреди идущей проверки.
        """
        _only(params, {"path"})
        path = _path(params)
        async with self.lock:
            if self.state.mode is Mode.EMERGENCY:
                raise ApiError(ErrorCode.INVALID_STATE,
                               "в аварийном режиме изменять контролируемые файлы нельзя")
            manifest = self.manifest
            if manifest is None:
                try:
                    manifest = self._load_manifest()
                except ManifestError as exc:
                    raise ApiError(ErrorCode.INVALID_STATE, str(exc)) from None
            if manifest.classify(path) is not Kind.CONFIG:
                raise ApiError(ErrorCode.INVALID_PARAMS,
                               f"{path} не является изменяемым конфигурационным файлом")
            self.pending[path] = self.clock()
        return {"path": path, "timeout_s": self.settings.pending_timeout_s}

    async def cmd_commit_update(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        _only(params, {"path"})
        path = _path(params)
        async with self.lock:
            if path not in self.pending:
                raise ApiError(ErrorCode.INVALID_STATE,
                               f"для {path} не было begin_update или оно истекло")
            if self.state.mode is Mode.EMERGENCY:
                raise ApiError(ErrorCode.INVALID_STATE,
                               "в аварийном режиме обновлять эталоны нельзя")
            try:
                self.store.load()
            except StoreError as exc:
                raise ApiError(ErrorCode.INVALID_STATE, str(exc)) from None
            if os.path.isfile(path):
                entry = await asyncio.to_thread(self.store.record, path, Kind.CONFIG)
                action, sha = "updated", entry.sha256
            else:
                self.store.remove(path)
                action, sha = "removed", None
            self.store.save()
            self.store.gc_backups()
            del self.pending[path]
        await self.events.emit(Event.REFERENCE_UPDATED,
                               "Обновление эталонных значений контрольных сумм",
                               success=True, ctx=ctx,
                               details={"path": path, "action": action, "sha256": sha})
        return {"path": path, "action": action, "sha256": sha}

    async def cmd_abort_update(self, params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        _only(params, {"path"})
        path = _path(params)
        return {"path": path, "aborted": self.pending.pop(path, None) is not None}


# ============================================================ без процесса
def initialize_reference(settings: Settings, *, force: bool = False) -> dict[str, int]:
    """Сформировать эталоны при установке ПО МЭ (ЦЛС-02).

    Выполняется командой ``fw-integrity init`` при остановленном процессе.
    После обновления ПО МЭ эталоны пересоздаются с ключом --force.
    """
    store = ReferenceStore(settings.state_dir)
    if store.exists() and not force:
        raise StoreError("эталоны уже сформированы; для пересоздания используйте --force")
    manifest = Manifest.load(settings.manifest_path, extra_static=(settings.config_path,))
    store.entries = {}
    files = manifest.expand()
    for path, kind in sorted(files.items()):
        store.record(path, kind)
    store.save()
    store.gc_backups()
    return {"files": len(files),
            "static": sum(k is Kind.STATIC for k in files.values()),
            "config": sum(k is Kind.CONFIG for k in files.values())}


def gate(settings: Settings, boot_id: Callable[[], str | None] = read_boot_id) -> tuple[bool, str]:
    """Можно ли запускать фильтрацию (ExecStartPre в fw-filter.service, ЦЛС-07).

    Разрешено, только если в текущей загрузке уже была успешная проверка
    и подсистема не в аварийном режиме.
    """
    st = StateStore(settings.state_dir).load()
    if st.mode is not Mode.NORMAL:
        return False, "ПО МЭ в режиме аварийной поддержки"
    if not st.last_check or not st.last_check.get("ok"):
        return False, "успешной проверки целостности ещё не было"
    current = boot_id()
    if current is not None and st.boot_id != current:
        return False, "в текущей загрузке проверка целостности ещё не выполнялась"
    return True, "проверка целостности пройдена"
