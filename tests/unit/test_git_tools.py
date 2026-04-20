"""Tool wiring tests for git_status / git_log / git_pull / git_push (mocked)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from unix_pass_mcp import pass_cli, server
from unix_pass_mcp.errors import NetworkDisabled, NotAGitRepo


@pytest.fixture(autouse=True)
def _common_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_REQUIRE_AGENT", "0")
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", "")
    monkeypatch.delenv("PASS_MCP_ALLOWED_PATHS", raising=False)
    monkeypatch.delenv("PASS_MCP_ALLOW_NETWORK", raising=False)


@pytest.fixture
def network_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_NETWORK", "1")


@pytest.fixture
def stub_pass(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"calls": [], "responses": {}, "stderr": {}, "rc": {}}

    def fake_run_or_raise(args: list[str], *, stdin: str | None = None, timeout: float = 15.0):
        state["calls"].append({"args": list(args), "stdin": stdin})
        return pass_cli.CommandResult(
            args=("/bin/pass", *args),
            returncode=0,
            stdout=state["responses"].get(tuple(args), ""),
            stderr="",
        )

    def fake_run(args: list[str], *, stdin: str | None = None, timeout: float = 15.0, **kw):
        state["calls"].append({"args": list(args), "stdin": stdin})
        key = tuple(args)
        return pass_cli.CommandResult(
            args=("/bin/pass", *args),
            returncode=state["rc"].get(key, 0),
            stdout=state["responses"].get(key, ""),
            stderr=state["stderr"].get(key, ""),
        )

    monkeypatch.setattr(pass_cli, "run_or_raise", fake_run_or_raise)
    monkeypatch.setattr(pass_cli, "run", fake_run)
    return state


# ── git_status ───────────────────────────────────────────────────────────────


def test_git_status_refuses_when_not_a_repo(initialized_store: Path) -> None:
    with pytest.raises(NotAGitRepo):
        server.git_status()


def test_git_status_returns_structured_info(
    stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / ".git").mkdir()
    stub_pass["responses"][("git", "status", "--porcelain=v2", "--branch")] = (
        "# branch.head main\n# branch.upstream origin/main\n# branch.ab +0 -0\n"
    )
    result = server.git_status()
    assert result["clean"] is True
    assert result["branch"] == "main"
    assert result["upstream"] == "origin/main"
    assert result["ahead"] == 0
    assert result["behind"] == 0
    assert result["dirty_files"] == []


def test_git_status_reports_dirty(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    (initialized_store / ".git").mkdir()
    stub_pass["responses"][("git", "status", "--porcelain=v2", "--branch")] = (
        "# branch.head main\n1 .M N... 100644 100644 100644 abc def changed.gpg\n? new.gpg\n"
    )
    result = server.git_status()
    assert result["clean"] is False
    assert {f["path"] for f in result["dirty_files"]} == {"changed.gpg", "new.gpg"}


# ── git_log ──────────────────────────────────────────────────────────────────


def test_git_log_default_limit(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    (initialized_store / ".git").mkdir()
    stub_pass["responses"][("git", "log", "--oneline", "--no-decorate", "-n", "20")] = (
        "abc1234 Added github.com\ndef5678 Added gitlab.com\n"
    )
    result = server.git_log()
    assert result["count"] == 2
    assert result["commits"][0]["hash"] == "abc1234"


def test_git_log_custom_limit(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    (initialized_store / ".git").mkdir()
    stub_pass["responses"][("git", "log", "--oneline", "--no-decorate", "-n", "5")] = ""
    server.git_log(limit=5)
    args = stub_pass["calls"][0]["args"]
    assert args == ["git", "log", "--oneline", "--no-decorate", "-n", "5"]


def test_git_log_rejects_bad_limit(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    (initialized_store / ".git").mkdir()
    from unix_pass_mcp.errors import PassError

    with pytest.raises(PassError):
        server.git_log(limit=0)
    with pytest.raises(PassError):
        server.git_log(limit=500)


# ── git_pull / git_push (gated) ──────────────────────────────────────────────


def test_git_pull_refuses_without_network_gate(
    stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / ".git").mkdir()
    with pytest.raises(NetworkDisabled):
        server.git_pull()
    assert stub_pass["calls"] == []


def test_git_push_refuses_without_network_gate(
    stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / ".git").mkdir()
    with pytest.raises(NetworkDisabled):
        server.git_push()
    assert stub_pass["calls"] == []


def test_git_pull_uses_ff_only(
    network_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / ".git").mkdir()
    stub_pass["responses"][("git", "pull", "--ff-only")] = "Already up to date.\n"
    result = server.git_pull()
    assert result["ok"] is True
    assert "Already up to date" in result["output"]
    assert stub_pass["calls"][0]["args"] == ["git", "pull", "--ff-only"]


def test_git_push_basic(
    network_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / ".git").mkdir()
    stub_pass["responses"][("git", "push")] = "Everything up-to-date\n"
    result = server.git_push()
    assert result["ok"] is True
    assert stub_pass["calls"][0]["args"] == ["git", "push"]


def test_git_pull_failure_returns_ok_false(
    network_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / ".git").mkdir()
    key = ("git", "pull", "--ff-only")
    stub_pass["rc"][key] = 1
    stub_pass["stderr"][key] = "fatal: Not possible to fast-forward, aborting.\n"
    result = server.git_pull()
    assert result["ok"] is False
    assert "fast-forward" in result["stderr"]


def test_git_pull_refuses_when_not_a_repo(
    network_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(NotAGitRepo):
        server.git_pull()


def test_git_push_refuses_when_not_a_repo(
    network_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(NotAGitRepo):
        server.git_push()


def test_all_git_tools_registered() -> None:
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert names >= {"git_status", "git_log", "git_pull", "git_push"}


def test_store_info_includes_git_remotes(initialized_store: Path) -> None:
    git = initialized_store / ".git"
    git.mkdir()
    (git / "config").write_text(
        '[remote "origin"]\n\turl = git@github.com:u/store.git\n',
        encoding="utf-8",
    )
    result = server.store_info()
    assert result["git_remotes"] == [
        {"name": "origin", "url": "git@github.com:u/store.git"},
    ]


def test_store_info_git_remotes_empty_when_no_repo(initialized_store: Path) -> None:
    result = server.store_info()
    assert result["git_remotes"] == []
