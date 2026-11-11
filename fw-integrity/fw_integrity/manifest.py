"""Манифест: какие файлы контролируются (ЦЛС-01).

Формат (JSON):
    {
      "static":  ["/usr/lib/fw/**", "/etc/fw/default.conf", ...],
      "config":  ["/etc/fw/startup.conf", "/var/lib/fw/policy.json", ...],
      "exclude": []
    }

Шаблоны -- абсолютные пути с ``*`` и ``**`` (сопоставление через
``PurePath.full_match`` из Python 3.13). Файл, подходящий и под static,
и под config, считается static: менять его через API нельзя.
Сам манифест и файл настроек всегда контролируются как static.
"""

import glob
import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .constants import Kind


class ManifestError(ValueError):
    pass


def _patterns(data: dict, key: str, where: Path) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ManifestError(f"{where}: поле {key!r} должно быть списком строк")
    for pattern in value:
        if not pattern.startswith("/"):
            raise ManifestError(f"{where}: шаблон {pattern!r} должен быть абсолютным путём")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class Manifest:
    static: tuple[str, ...]
    config: tuple[str, ...]
    exclude: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path, extra_static: tuple[Path, ...] = ()) -> "Manifest":
        path = Path(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ManifestError(f"{path}: файл манифеста отсутствует") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError(f"{path}: не удалось прочитать манифест: {exc}") from exc
        if not isinstance(data, dict):
            raise ManifestError(f"{path}: манифест должен быть JSON-объектом")
        unknown = set(data) - {"static", "config", "exclude"}
        if unknown:
            raise ManifestError(f"{path}: неизвестные поля {sorted(unknown)}")
        static = _patterns(data, "static", path)
        always = tuple(str(p) for p in (path, *extra_static))
        return cls(
            static=static + tuple(p for p in always if p not in static),
            config=_patterns(data, "config", path),
            exclude=_patterns(data, "exclude", path),
        )

    def classify(self, path: str) -> Kind | None:
        """Вид файла по манифесту или None, если файл не контролируется."""
        p = PurePosixPath(path)
        if any(p.full_match(x) for x in self.exclude):
            return None
        if any(p.full_match(x) for x in self.static):
            return Kind.STATIC
        if any(p.full_match(x) for x in self.config):
            return Kind.CONFIG
        return None

    def expand(self) -> dict[str, Kind]:
        """Все существующие сейчас файлы, подходящие под шаблоны.

        Скрытые файлы тоже учитываются: подброшенный ``.evil.py``
        должен обнаруживаться так же, как обычный.
        """
        found: dict[str, Kind] = {}
        for pattern in (*self.static, *self.config):
            for match in glob.glob(pattern, recursive=True, include_hidden=True):
                if not os.path.isfile(match):
                    continue
                path = os.path.abspath(match)
                kind = self.classify(path)
                if kind is not None:
                    found[path] = kind
        return found
