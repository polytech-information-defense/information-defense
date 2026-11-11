"""Сравнение контролируемых файлов с эталонами (ЦЛС-01)."""

from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .constants import Kind
from .hashing import sha256_file
from .store import Entry


class Reason(StrEnum):
    MODIFIED = "modified"        # содержимое не совпадает с эталоном
    MISSING = "missing"          # файл удалён
    ADDED = "added"              # посторонний файл в контролируемом месте
    UNREADABLE = "unreadable"    # файл не читается (права, ошибка ввода-вывода)
    OS_STATE = "os_state"        # настройка ОС не соответствует ОБР-02


REASON_TEXT = {
    Reason.MODIFIED: "содержимое изменено",
    Reason.MISSING: "файл отсутствует",
    Reason.ADDED: "посторонний файл",
    Reason.UNREADABLE: "файл не читается",
    Reason.OS_STATE: "настройка ОС не соответствует ОБР-02",
}


@dataclass(frozen=True, slots=True)
class Violation:
    path: str
    reason: Reason
    detail: str = ""

    @property
    def is_file(self) -> bool:
        return self.reason is not Reason.OS_STATE

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "reason": str(self.reason),
                "text": REASON_TEXT[self.reason], "detail": self.detail}


@dataclass(slots=True)
class CheckResult:
    started: str
    finished: str
    checked: int
    violations: list[Violation] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)   # файлы в процессе легитимного изменения

    @property
    def ok(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "started": self.started,
            "finished": self.finished,
            "checked": self.checked,
            "violations": [v.to_dict() for v in self.violations],
            "skipped": self.skipped,
        }


def check_files(reference: Mapping[str, Entry],
                present: Mapping[str, Kind],
                skip: Collection[str] = ()) -> tuple[int, list[Violation], list[str]]:
    """Сравнить файлы на диске с эталонами.

    reference -- эталоны; present -- файлы, найденные сейчас по манифесту;
    skip -- пути, которые прямо сейчас легитимно изменяются (begin_update).
    Возвращает (число проверенных файлов, нарушения, пропущенные пути).
    """
    violations: list[Violation] = []
    skipped: list[str] = []
    checked = 0
    for path, entry in sorted(reference.items()):
        if path in skip:
            skipped.append(path)
            continue
        checked += 1
        try:
            actual = sha256_file(path)
        except FileNotFoundError:
            violations.append(Violation(path, Reason.MISSING))
            continue
        except OSError as exc:
            violations.append(Violation(path, Reason.UNREADABLE, str(exc)))
            continue
        if actual != entry.sha256:
            violations.append(Violation(path, Reason.MODIFIED,
                                        f"эталон {entry.sha256[:16]}..., сейчас {actual[:16]}..."))
    for path in sorted(set(present) - set(reference)):
        if path in skip:
            skipped.append(path)
            continue
        violations.append(Violation(path, Reason.ADDED, f"вид по манифесту: {present[path]}"))
    return checked, violations, skipped
