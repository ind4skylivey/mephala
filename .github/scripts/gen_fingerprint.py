#!/usr/bin/env python3
# mephala (proprietary) | Fingerprint: MEPAHLA-FP-2025-REPLACE-ME-WITH-256BIT-HEX
# Copyright (c) 2025 ind4skylivey
# All rights reserved. Unauthorized use, copying, modification, distribution, or sale is prohibited.
"""Generate canonical fingerprint for all Python files in the repository."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List


EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".idea",
    ".vscode",
}

FIXED_TAG = "MEPAHLA-FP-2025-REPLACE-ME-WITH-256BIT-HEX"
FINGERPRINT_FILE = ".fingerprint"


def iter_python_files(root: Path) -> Iterable[Path]:
    """Yield all .py files under root, excluding configured directories."""
    for path in root.rglob("*.py"):
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        yield path


def compute_fingerprint(paths: List[Path], root: Path) -> str:
    """Compute deterministic SHA256 over relative path and content."""
    hasher = hashlib.sha256()
    for path in sorted(paths):
        rel = path.relative_to(root).as_posix()
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def write_fingerprint(root: Path) -> None:
    python_files = list(iter_python_files(root))
    fingerprint_sha256 = compute_fingerprint(python_files, root)
    payload = {
        "fingerprint_sha256": fingerprint_sha256,
        "fixed_tag": FIXED_TAG,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "file_count": len(python_files),
    }
    (root / FINGERPRINT_FILE).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    write_fingerprint(repo_root)


if __name__ == "__main__":
    main()
