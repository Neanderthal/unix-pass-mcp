"""M5 hardening + ergonomics: grep, simulate, strict startup."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from unix_pass_mcp import pass_cli, server
from unix_pass_mcp.errors import PassError, WritesDisabled


@pytest.fixture(autouse=True)
def _common_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_REQUIRE_AGENT", "0")
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", "")
    monkeypatch.delenv("PASS_MCP_ALLOWED_PATHS", raising=False)


@pytest.fixture
def writes_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", "1")


@pytest.fixture
def stub_pass(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"calls": [], "responses": {}, "errors": {}}

    def fake(args: list[str], *, stdin: str | None = None, timeout: float = 15.0):
        state["calls"].append({"args": list(args), "stdin": stdin, "timeout": timeout})
        key = tuple(args)
        if key in state["errors"]:
            raise state["errors"][key]
        return pass_cli.CommandResult(
            args=("/bin/pass", *args),
            returncode=0,
            stdout=state["responses"].get(key, ""),
            stderr="",
        )

    monkeypatch.setattr(pass_cli, "run_or_raise", fake)
    return state


# ── grep ─────────────────────────────────────────────────────────────────────


def test_grep_refuses_without_confirmation(stub_pass: dict[str, Any]) -> None:
    with pytest.raises(PassError) as exc:
        server.grep("alice")
    assert exc.value.code == "confirmation_required"
    assert stub_pass["calls"] == []


def test_grep_runs_with_confirmation(stub_pass: dict[str, Any]) -> None:
    stub_pass["responses"][("grep", "alice")] = (
        "github.com:\nUsername: alice\ngitlab.com:\nUsername: alice\nNote: alice was here\n"
    )
    result = server.grep("alice", confirm_decrypt_all=True)
    assert result["count"] == 3
    assert result["matches"] == [
        {"name": "github.com", "line": "Username: alice"},
        {"name": "gitlab.com", "line": "Username: alice"},
        {"name": "gitlab.com", "line": "Note: alice was here"},
    ]
    assert result["sensitive"] is True


def test_grep_case_insensitive_flag(stub_pass: dict[str, Any]) -> None:
    stub_pass["responses"][("grep", "-i", "alice")] = ""
    server.grep("Alice", confirm_decrypt_all=True, case_insensitive=True)
    assert stub_pass["calls"][0]["args"] == ["grep", "-i", "Alice"]


def test_grep_uses_long_timeout(stub_pass: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_GREP_TIMEOUT_SECONDS", "30")
    stub_pass["responses"][("grep", "x")] = ""
    server.grep("x", confirm_decrypt_all=True)
    assert stub_pass["calls"][0]["timeout"] == 30.0


def test_grep_default_timeout_is_120(stub_pass: dict[str, Any]) -> None:
    stub_pass["responses"][("grep", "x")] = ""
    server.grep("x", confirm_decrypt_all=True)
    assert stub_pass["calls"][0]["timeout"] == 120.0


def test_grep_validates_pattern(stub_pass: dict[str, Any]) -> None:
    with pytest.raises(PassError):
        server.grep("", confirm_decrypt_all=True)
    with pytest.raises(PassError):
        server.grep("x" * 300, confirm_decrypt_all=True)
    assert stub_pass["calls"] == []


def test_grep_empty_result(stub_pass: dict[str, Any]) -> None:
    stub_pass["responses"][("grep", "missing")] = ""
    result = server.grep("missing", confirm_decrypt_all=True)
    assert result["count"] == 0
    assert result["matches"] == []
    assert result["redacted_entries"] == 0


def test_grep_drops_matches_outside_allowlist(
    stub_pass: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without this filter, grep is a path-allowlist escape: pass-grep walks the
    whole store regardless of PASS_MCP_ALLOWED_PATHS, and decrypted lines from
    out-of-scope entries leak back to the agent.
    """
    monkeypatch.setenv("PASS_MCP_ALLOWED_PATHS", "web/*")
    stub_pass["responses"][("grep", "alice")] = (
        "web/github.com:\n"
        "Username: alice\n"
        "personal/banking/chase:\n"
        "Username: alice\n"
        "Note: alice was here\n"
    )
    result = server.grep("alice", confirm_decrypt_all=True)
    assert [m["name"] for m in result["matches"]] == ["web/github.com"]
    assert result["count"] == 1
    assert result["redacted_entries"] == 1
    # The decrypted out-of-scope line must not appear anywhere in the result.
    assert "banking" not in str(result)


def test_grep_no_filter_when_allowlist_unset(stub_pass: dict[str, Any]) -> None:
    stub_pass["responses"][("grep", "x")] = "personal/banking:\nx\n"
    result = server.grep("x", confirm_decrypt_all=True)
    assert result["count"] == 1
    assert result["redacted_entries"] == 0


# ── simulate on set_field ────────────────────────────────────────────────────


def test_set_field_simulate_does_not_call_pass_to_write(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\nURL: old\n"
    result = server.set_field("site", field="URL", value="new", simulate=True)
    assert result["simulated"] is True
    assert result["changed"] is True
    assert "URL: new" in result["after"]
    assert "URL: old" in result["before"]
    # Only one call: the show. No insert.
    assert [c["args"][0] for c in stub_pass["calls"]] == ["show"]


def test_set_field_simulate_idempotent_change_marked_unchanged(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\nURL: keep\n"
    result = server.set_field("site", field="URL", value="keep", simulate=True)
    assert result["changed"] is False
    assert result["before"] == result["after"]


def test_set_field_simulate_still_requires_writes_gate(
    stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    with pytest.raises(WritesDisabled):
        server.set_field("site", field="URL", value="x", simulate=True)


# ── simulate on unset_field ──────────────────────────────────────────────────


def test_unset_field_simulate_shows_diff(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\nURL: x\nUsername: alice\n"
    result = server.unset_field("site", field="URL", simulate=True)
    assert result["simulated"] is True
    assert result["removed"] is True
    assert result["changed"] is True
    assert "URL" not in result["after"]
    assert "Username: alice" in result["after"]
    assert [c["args"][0] for c in stub_pass["calls"]] == ["show"]


def test_unset_field_simulate_noop_when_absent(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\nURL: x\n"
    result = server.unset_field("site", field="Email", simulate=True)
    assert result["removed"] is False
    assert result["changed"] is False
    assert result["before"] == result["after"]


# ── grep parser ──────────────────────────────────────────────────────────────


def test_grep_parser_handles_multiple_matches_per_entry() -> None:
    text = "a:\nfoo\nbar\nb:\nbaz\n"
    out = server._parse_grep_output(text)
    assert out == [
        {"name": "a", "line": "foo"},
        {"name": "a", "line": "bar"},
        {"name": "b", "line": "baz"},
    ]


def test_grep_parser_handles_nested_names() -> None:
    text = "team/shared:\nUsername: alice\n"
    out = server._parse_grep_output(text)
    assert out == [{"name": "team/shared", "line": "Username: alice"}]


def test_grep_parser_empty() -> None:
    assert server._parse_grep_output("") == []


# ── tool registration ───────────────────────────────────────────────────────


def test_grep_registered() -> None:
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert "grep" in names


# ── strict startup ──────────────────────────────────────────────────────────


def test_strict_startup_passes_under_safe_conditions(
    initialized_store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(initialized_store, 0o700)
    monkeypatch.delenv("PASS_MCP_ALLOW_UNSAFE", raising=False)
    monkeypatch.setenv("PASSWORD_STORE_UMASK", "077")
    server._strict_startup_checks()  # must not raise / exit


def test_strict_startup_refuses_world_readable_store(
    initialized_store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(initialized_store, 0o755)  # noqa: S103 — intentional: testing the world-readable detection
    monkeypatch.delenv("PASS_MCP_ALLOW_UNSAFE", raising=False)
    with pytest.raises(SystemExit) as exc:
        server._strict_startup_checks()
    assert exc.value.code == 2


def test_strict_startup_refuses_weak_umask(
    initialized_store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(initialized_store, 0o700)
    monkeypatch.delenv("PASS_MCP_ALLOW_UNSAFE", raising=False)
    monkeypatch.setenv("PASSWORD_STORE_UMASK", "022")
    with pytest.raises(SystemExit) as exc:
        server._strict_startup_checks()
    assert exc.value.code == 2


def test_strict_startup_bypassable(
    initialized_store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(initialized_store, 0o755)  # noqa: S103 — intentional: testing the world-readable detection
    monkeypatch.setenv("PASS_MCP_ALLOW_UNSAFE", "1")
    server._strict_startup_checks()  # bypass active → no exit
