from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from unix_pass_mcp import pass_cli, server
from unix_pass_mcp.errors import (
    AgentUnavailable,
    InvalidPassName,
    NotFound,
    PathNotAllowed,
)


@pytest.fixture(autouse=True)
def _disable_agent_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Most tests don't need the gpg-agent preflight."""
    monkeypatch.setenv("PASS_MCP_REQUIRE_AGENT", "0")
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", "")  # silence audit


@pytest.fixture
def stub_pass(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace pass_cli.run_or_raise with a stub. Returns the call log."""
    state: dict[str, Any] = {"calls": [], "responses": {}, "errors": {}}

    def fake_run_or_raise(args: list[str], *, stdin: str | None = None, timeout: float = 15.0):
        state["calls"].append({"args": list(args), "stdin": stdin})
        key = tuple(args)
        if key in state["errors"]:
            raise state["errors"][key]
        stdout = state["responses"].get(key, "")
        return pass_cli.CommandResult(
            args=("/bin/pass", *args), returncode=0, stdout=stdout, stderr=""
        )

    monkeypatch.setattr(pass_cli, "run_or_raise", fake_run_or_raise)
    return state


# ── store_info / list / find (no decryption) ─────────────────────────────────


def test_store_info_handles_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(tmp_path / "absent"))
    result = server.store_info()
    assert result["exists"] is False


def test_list_walks_store(initialized_store: Path) -> None:
    (initialized_store / "github.com.gpg").write_bytes(b"x")
    sub = initialized_store / "team"
    sub.mkdir()
    (sub / "shared.gpg").write_bytes(b"x")
    (initialized_store / ".git").mkdir()
    (initialized_store / ".git" / "should-not-appear.gpg").write_bytes(b"x")

    result = server.list_entries()
    assert result["names"] == ["github.com", "team/shared"]
    assert result["count"] == 2


def test_list_with_subfolder(initialized_store: Path) -> None:
    sub = initialized_store / "team"
    sub.mkdir()
    (sub / "shared.gpg").write_bytes(b"x")
    (initialized_store / "github.com.gpg").write_bytes(b"x")
    result = server.list_entries(subfolder="team")
    assert result["names"] == ["team/shared"]


def test_list_subfolder_validation() -> None:
    with pytest.raises(InvalidPassName):
        server.list_entries(subfolder="../escape")


def test_find_substring_match(initialized_store: Path) -> None:
    (initialized_store / "github.com.gpg").write_bytes(b"x")
    (initialized_store / "gitlab.com.gpg").write_bytes(b"x")
    (initialized_store / "amazon.com.gpg").write_bytes(b"x")
    result = server.find_entries(query="git")
    assert set(result["names"]) == {"github.com", "gitlab.com"}


def test_find_empty_query_returns_empty(initialized_store: Path) -> None:
    (initialized_store / "github.com.gpg").write_bytes(b"x")
    assert server.find_entries(query="")["names"] == []


# ── show / show_field / show_metadata ────────────────────────────────────────


def test_show_returns_first_line(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "github.com")] = "hunter2\nUsername: alice\n"
    result = server.show("github.com")
    assert result == {"value": "hunter2", "line": 1, "sensitive": True}


def test_show_returns_specific_line(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "github.com")] = "hunter2\nUsername: alice\nURL: x\n"
    result = server.show("github.com", line=2)
    assert result["value"] == "Username: alice"


def test_show_line_out_of_range(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "github.com")] = "only-line\n"
    with pytest.raises(NotFound):
        server.show("github.com", line=5)


def test_show_validates_name(stub_pass: dict[str, Any]) -> None:
    with pytest.raises(InvalidPassName):
        server.show("../etc/passwd")
    assert stub_pass["calls"] == []


def test_show_field_present(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "site")] = "pw\nURL: https://x\nUsername: alice\n"
    result = server.show_field("site", field="username")  # case-insensitive
    assert result["value"] == "alice"
    assert result["present"] is True


def test_show_field_absent(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "site")] = "pw\nURL: x\n"
    result = server.show_field("site", field="otpauth")
    assert result["value"] is None
    assert result["present"] is False


def test_show_metadata_omits_password(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "site")] = "supersecret\nURL: https://x\n"
    result = server.show_metadata("site")
    assert "password_present" in result
    assert result["password_present"] is True
    assert result["fields"] == {"URL": "https://x"}
    assert "supersecret" not in str(result)


# ── gating ───────────────────────────────────────────────────────────────────


def test_path_allowlist_enforced_on_show(
    stub_pass: dict[str, Any], initialized_store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOWED_PATHS", "work/*")
    with pytest.raises(PathNotAllowed):
        server.show("personal/banking")
    assert stub_pass["calls"] == []


def test_agent_preflight_when_required(
    monkeypatch: pytest.MonkeyPatch, initialized_store: Path
) -> None:
    monkeypatch.delenv("PASS_MCP_REQUIRE_AGENT", raising=False)  # default = required
    monkeypatch.setattr(pass_cli, "gpg_agent_available", lambda timeout=2.0: False)
    with pytest.raises(AgentUnavailable):
        server.show("github.com")


# ── tool registration ────────────────────────────────────────────────────────


def test_all_m1_tools_registered() -> None:
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert names >= {"store_info", "list", "find", "show", "show_field", "show_metadata"}
