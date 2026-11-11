"""Хранилища подсистемы.

ReferenceStore -- эталонные SHA-256 и резервные копии (ЦЛС-01, ЦЛС-02, ЦЛС-05):
    <state_dir>/reference.json       эталоны: путь -> sha256, вид, размер, права
    <state_dir>/backup/<sha256>      резервная копия содержимого
    <state_dir>/quarantine/          посторонние файлы, убранные при восстановлении

StateStore -- текущий режим и параметры:
    <state_dir>/state.json           режим, нарушения, период, последняя проверка
"""

import contextlib
import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .constants import PERIOD_DEFAULT, Kind, Mode
from .hashing import sha256_file
from .util import atomic_write_json, fsync_dir, now_iso

CHUNK = 1 << 20


class StoreError(Exception):
    pass


class BackupError(StoreError):
    pass


@dataclass(slots=True)
class Entry:
    sha256: str
    kind: Kind
    size: int
    mode: int
    uid: int
    gid: int
    updated: str

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "kind": str(self.kind), "mode": oct(self.mode)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Entry":
        return cls(
            sha256=str(d["sha256"]),
            kind=Kind(d["kind"]),
            size=int(d["size"]),
            mode=int(d["mode"], 8) if isinstance(d["mode"], str) else int(d["mode"]),
            uid=int(d["uid"]),
            gid=int(d["gid"]),
            updated=str(d["updated"]),
        )


class ReferenceStore:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.path = self.dir / "reference.json"
        self.backup_dir = self.dir / "backup"
        self.quarantine_dir = self.dir / "quarantine"
        self.entries: dict[str, Entry] = {}

    # ----------------------------------------------------------- файл эталонов
    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.entries = {p: Entry.from_dict(e) for p, e in data["files"].items()}
        except FileNotFoundError:
            raise StoreError(f"эталоны не сформированы: нет {self.path} (выполните init)") from None
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise StoreError(f"файл эталонов повреждён: {exc}") from exc

    def save(self) -> None:
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_write_json(self.path, {
            "version": 1,
            "saved": now_iso(),
            "files": {p: e.to_dict() for p, e in sorted(self.entries.items())},
        })

    # --------------------------------------------------------- резервные копии
    def backup_file(self, sha: str) -> Path:
        return self.backup_dir / sha

    def _copy_to_backup(self, path: str) -> tuple[str, os.stat_result]:
        """Скопировать файл в хранилище копий, одновременно посчитав SHA-256.

        Хеш и копия получаются из одного чтения, поэтому эталон всегда
        соответствует сохранённой копии, даже если файл меняется.
        """
        self.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.backup_dir / f".incoming-{os.getpid()}"
        h = hashlib.sha256()
        with open(path, "rb") as src:
            st = os.fstat(src.fileno())
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as dst:
                while chunk := src.read(CHUNK):
                    h.update(chunk)
                    dst.write(chunk)
                dst.flush()
                os.fsync(dst.fileno())
        sha = h.hexdigest()
        target = self.backup_file(sha)
        if target.exists():
            tmp.unlink()
        else:
            os.replace(tmp, target)
            fsync_dir(self.backup_dir)
        return sha, st

    def record(self, path: str, kind: Kind) -> Entry:
        """Сформировать эталон файла и сохранить его резервную копию."""
        sha, st = self._copy_to_backup(path)
        entry = Entry(sha256=sha, kind=kind, size=st.st_size, mode=st.st_mode & 0o7777,
                      uid=st.st_uid, gid=st.st_gid, updated=now_iso())
        self.entries[path] = entry
        return entry

    def remove(self, path: str) -> None:
        self.entries.pop(path, None)

    def gc_backups(self) -> int:
        """Удалить копии, на которые не ссылается ни один эталон."""
        if not self.backup_dir.exists():
            return 0
        used = {e.sha256 for e in self.entries.values()}
        removed = 0
        for f in self.backup_dir.iterdir():
            if f.is_file() and f.name not in used:
                f.unlink()
                removed += 1
        return removed

    # ------------------------------------------------------------ восстановление
    def restore(self, path: str) -> Entry:
        """Восстановить файл из резервной копии (ЦЛС-05).

        Копия предварительно проверяется по эталону: повреждённая копия
        не восстанавливается.
        """
        entry = self.entries[path]
        backup = self.backup_file(entry.sha256)
        if not backup.exists():
            raise BackupError(f"резервная копия {path} отсутствует")
        if sha256_file(backup) != entry.sha256:
            raise BackupError(f"резервная копия {path} повреждена")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.fw-restore-{os.getpid()}")
        try:
            shutil.copyfile(backup, tmp)
            os.chmod(tmp, entry.mode)
            if os.geteuid() == 0:
                os.chown(tmp, entry.uid, entry.gid)
            with open(tmp, "rb") as f:
                os.fsync(f.fileno())
            os.replace(tmp, target)
            fsync_dir(target.parent)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
            raise
        return entry

    def quarantine(self, path: str) -> Path:
        """Убрать посторонний файл в карантин (а не удалять: он нужен для разбора)."""
        self.quarantine_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        stamp = now_iso().replace(":", "-")
        target = self.quarantine_dir / f"{stamp}{path.replace('/', '__')}"
        shutil.move(path, target)
        os.chmod(target, 0o600)
        return target


@dataclass(slots=True)
class State:
    mode: Mode = Mode.NORMAL
    since: str | None = None                       # время перехода в текущий режим
    violations: list[dict[str, Any]] = field(default_factory=list)
    period_min: int = PERIOD_DEFAULT
    last_check: dict[str, Any] | None = None
    boot_id: str | None = None                      # загрузка, в которую была проверка

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "mode": str(self.mode)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "State":
        return cls(
            mode=Mode(d.get("mode", Mode.NORMAL)),
            since=d.get("since"),
            violations=list(d.get("violations", [])),
            period_min=int(d.get("period_min", PERIOD_DEFAULT)),
            last_check=d.get("last_check"),
            boot_id=d.get("boot_id"),
        )


class StateStore:
    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "state.json"

    def load(self) -> State:
        """Прочитать состояние.

        Повреждённый файл трактуется как аварийный режим: если состояние
        неизвестно, трафик пропускать нельзя.
        """
        try:
            return State.from_dict(json.loads(self.path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            return State()
        except (OSError, ValueError, TypeError) as exc:
            return State(mode=Mode.EMERGENCY, since=now_iso(), violations=[{
                "path": str(self.path), "reason": "unreadable",
                "text": "файл не читается", "detail": f"файл состояния повреждён: {exc}"}])

    def save(self, state: State) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_write_json(self.path, state.to_dict())
