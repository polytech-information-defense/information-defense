"""SHA-256 файлов (ЦЛС-01)."""

import hashlib
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()
