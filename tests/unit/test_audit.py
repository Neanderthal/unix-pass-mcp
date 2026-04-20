from __future__ import annotations

import json
from pathlib import Path

import pytest

from unix_pass_mcp import audit


@pytest.fixture
def audit_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    p = tmp_path / "audit.log"
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", str(p))
    return p


def test_log_writes_jsonl(audit_path: Path) -> None:
    audit.log("show", name="email/work", ok=True)
    audit.log("show", name="email/work", ok=False, error="not_found")
    lines = audit_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    rec1 = json.loads(lines[0])
    rec2 = json.loads(lines[1])
    assert rec1["action"] == "show"
    assert rec1["name"] == "email/work"
    assert rec1["ok"] is True
    assert rec2["ok"] is False
    assert rec2["error"] == "not_found"


def test_log_disabled_when_env_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", "")
    audit.log("show", name="x")
    assert not list(tmp_path.iterdir())


def test_log_creates_parent_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "deep" / "path" / "audit.log"
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", str(p))
    audit.log("show", name="x")
    assert p.exists()


def test_log_swallows_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Point at a path that can't be created (under a regular file).
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", str(blocker / "nope.log"))
    audit.log("show", name="x")  # must not raise


def test_log_rotates_when_oversized(audit_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "_MAX_LOG_BYTES", 100)
    for i in range(50):
        audit.log("show", name=f"entry-{i}")
    rotated = audit_path.with_name(audit_path.name + ".1")
    assert rotated.exists()
    # Current log exists and is smaller than rotated cutoff.
    assert audit_path.exists()


def test_log_drops_oldest_rotation(audit_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "_MAX_LOG_BYTES", 50)
    for i in range(200):
        audit.log("show", name=f"e{i}")
    rotations = sorted(audit_path.parent.glob(audit_path.name + ".*"))
    assert len(rotations) <= audit._KEEP_ROTATIONS
