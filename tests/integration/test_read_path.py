"""Integration: full M1 read path against a real GPG-encrypted store."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from unix_pass_mcp import server
from unix_pass_mcp.errors import NotFound


def _seed(store_dir: Path, name: str, body: str) -> None:
    subprocess.run(
        ["pass", "insert", "--multiline", "--force", name],
        input=body,
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PASSWORD_STORE_DIR": str(store_dir)},
        timeout=20,
    )


def test_store_info_against_real_store(real_store: Path) -> None:
    info = server.store_info()
    assert info["exists"] is True
    assert info["recipients_by_subdir"][""]  # at least one recipient
    assert info["gpg_agent_available"] is True


def test_list_after_insert(real_store: Path) -> None:
    _seed(real_store, "github.com", "hunter2\nUsername: alice\n")
    _seed(real_store, "team/shared", "team-secret\n")
    result = server.list_entries()
    assert "github.com" in result["names"]
    assert "team/shared" in result["names"]


def test_show_decrypts(real_store: Path) -> None:
    _seed(real_store, "github.com", "hunter2\nURL: https://github.com\n")
    result = server.show("github.com")
    assert result["value"] == "hunter2"


def test_show_field_decrypts(real_store: Path) -> None:
    _seed(real_store, "github.com", "hunter2\nURL: https://github.com\nUsername: alice\n")
    result = server.show_field("github.com", field="username")
    assert result["value"] == "alice"


def test_show_metadata_does_not_leak_password(real_store: Path) -> None:
    _seed(real_store, "github.com", "supersecret\nURL: x\n")
    result = server.show_metadata("github.com")
    assert "supersecret" not in str(result)
    assert result["fields"] == {"URL": "x"}


def test_find_against_real_store(real_store: Path) -> None:
    _seed(real_store, "github.com", "p\n")
    _seed(real_store, "gitlab.com", "p\n")
    _seed(real_store, "amazon.com", "p\n")
    result = server.find_entries(query="git")
    assert set(result["names"]) == {"github.com", "gitlab.com"}


def test_show_not_found_raises(real_store: Path) -> None:
    with pytest.raises(NotFound):
        server.show("does/not/exist")
