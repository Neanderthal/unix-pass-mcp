"""Append-only action log. Records tool + pass-name + outcome, never secrets.

Architecture §6.5. Rotates when the log exceeds ~1 MB.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

_DEFAULT_LOG_PATH = "~/.local/state/unix-pass-mcp/audit.log"
_MAX_LOG_BYTES = 1_000_000
_KEEP_ROTATIONS = 3


def _log_path() -> Path | None:
    raw = os.environ.get("PASS_MCP_AUDIT_LOG", _DEFAULT_LOG_PATH)
    if raw.strip() == "":
        return None  # explicitly disabled
    return Path(raw).expanduser()


def _rotate(path: Path) -> None:
    # audit.log.N → drop; audit.log.{i} → audit.log.{i+1}; audit.log → audit.log.1
    rotations = [path.with_name(f"{path.name}.{i}") for i in range(1, _KEEP_ROTATIONS + 1)]
    if rotations[-1].exists():
        rotations[-1].unlink()
    for i in range(_KEEP_ROTATIONS - 1, 0, -1):
        if rotations[i - 1].exists():
            rotations[i - 1].rename(rotations[i])
    path.rename(rotations[0])


def log(action: str, *, name: str | None = None, ok: bool = True, **extra: Any) -> None:
    """Append one JSONL record. Never raises; audit failures are not fatal."""
    path = _log_path()
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > _MAX_LOG_BYTES:
            _rotate(path)
        record = {
            "ts": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "action": action,
            "name": name,
            "ok": ok,
            **{k: v for k, v in extra.items() if v is not None},
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        # Audit is best-effort; never block the caller.
        pass
