"""Integration: git tools against a real `pass git`-initialized store."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from unix_pass_mcp import server
from unix_pass_mcp.errors import NotAGitRepo


@pytest.fixture(autouse=True)
def _enable_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", "1")


def _git_init_store(store_dir: Path) -> None:
    """`pass git init` initializes the store as a git repo and makes the first commit.

    We also need to set a local user.name/user.email so commits don't fail in CI.
    """
    env = {**os.environ, "PASSWORD_STORE_DIR": str(store_dir)}
    subprocess.run(
        ["pass", "git", "init"], capture_output=True, check=True, env=env, timeout=15
    )
    subprocess.run(
        ["git", "-C", str(store_dir), "config", "user.email", "test@example.invalid"],
        check=True,
        env=env,
        timeout=5,
    )
    subprocess.run(
        ["git", "-C", str(store_dir), "config", "user.name", "test"],
        check=True,
        env=env,
        timeout=5,
    )


def test_git_status_refuses_before_init(real_store: Path) -> None:
    with pytest.raises(NotAGitRepo):
        server.git_status()


def test_git_status_clean_after_init(real_store: Path) -> None:
    _git_init_store(real_store)
    info = server.git_status()
    assert info["clean"] is True
    assert info["ahead"] == 0
    assert info["behind"] == 0
    assert info["dirty_files"] == []


def test_inserts_produce_commits(real_store: Path) -> None:
    _git_init_store(real_store)
    server.insert("github.com", "hunter2")
    server.insert("gitlab.com", "secret")
    log = server.git_log(limit=10)
    # 1 initial commit from `pass git init` + 2 inserts = 3 commits.
    assert log["count"] >= 3
    subjects = " | ".join(c["subject"] for c in log["commits"])
    assert "github.com" in subjects
    assert "gitlab.com" in subjects


def test_git_status_dirty_after_manual_edit(real_store: Path) -> None:
    _git_init_store(real_store)
    server.insert("github.com", "hunter2")
    # Manually drop a file the way an out-of-band edit would.
    (real_store / "rogue.gpg").write_bytes(b"x")
    info = server.git_status()
    assert info["clean"] is False
    paths = {f["path"] for f in info["dirty_files"]}
    assert "rogue.gpg" in paths


def test_store_info_reports_remotes(real_store: Path) -> None:
    _git_init_store(real_store)
    subprocess.run(
        [
            "git",
            "-C",
            str(real_store),
            "remote",
            "add",
            "origin",
            "git@example.invalid:u/store.git",
        ],
        check=True,
        timeout=5,
    )
    info = server.store_info()
    assert info["git_remotes"] == [
        {"name": "origin", "url": "git@example.invalid:u/store.git"},
    ]


def test_git_pull_refuses_without_network_gate(real_store: Path) -> None:
    _git_init_store(real_store)
    from unix_pass_mcp.errors import NetworkDisabled

    with pytest.raises(NetworkDisabled):
        server.git_pull()


def test_git_push_pull_against_local_bare_remote(
    real_store: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end network ops using a local bare repo as the remote."""
    monkeypatch.setenv("PASS_MCP_ALLOW_NETWORK", "1")
    _git_init_store(real_store)

    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(bare)], check=True, timeout=5)
    subprocess.run(
        ["git", "-C", str(real_store), "remote", "add", "origin", str(bare)],
        check=True,
        timeout=5,
    )
    # Ensure local branch is named main so push is unambiguous.
    subprocess.run(
        ["git", "-C", str(real_store), "branch", "-M", "main"], check=True, timeout=5
    )

    server.insert("github.com", "hunter2")
    push_result = server.git_push()
    assert push_result["ok"] is True

    pull_result = server.git_pull()
    assert pull_result["ok"] is True
    # The "up to date" message may live on stdout or stderr depending on the
    # git version; we only care that the operation succeeded.
