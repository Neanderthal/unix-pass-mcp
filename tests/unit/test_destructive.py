"""Unit tests for M3b destructive ops: init, reencrypt."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from unix_pass_mcp import pass_cli, server
from unix_pass_mcp.errors import (
    DestructiveDisabled,
    InvalidPassName,
    NotFound,
    PassError,
    WritesDisabled,
)


@pytest.fixture(autouse=True)
def _common_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_REQUIRE_AGENT", "0")
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", "")
    monkeypatch.delenv("PASS_MCP_ALLOWED_PATHS", raising=False)


@pytest.fixture
def writes_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", "1")


@pytest.fixture
def destructive_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", "1")
    monkeypatch.setenv("PASS_MCP_ALLOW_DESTRUCTIVE", "1")


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


@pytest.fixture
def has_secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend the user has a secret key for any gpg-id passed in."""
    monkeypatch.setattr(pass_cli, "gpg_has_secret_key", lambda gid, **kw: True)


@pytest.fixture
def no_secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pass_cli, "gpg_has_secret_key", lambda gid, **kw: False)


# ── gates ────────────────────────────────────────────────────────────────────


def test_init_refuses_without_writes(initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.init(["alice@example.com"])


def test_init_refuses_without_destructive_when_only_writes_on(
    writes_on: None, initialized_store: Path
) -> None:
    with pytest.raises(DestructiveDisabled):
        server.init(["alice@example.com"])


def test_reencrypt_refuses_without_destructive(writes_on: None, initialized_store: Path) -> None:
    with pytest.raises(DestructiveDisabled):
        server.reencrypt()


# ── init: validation ───────────────────────────────────────────────────────


def test_init_rejects_non_list_gpg_ids(
    destructive_on: None, has_secret_key: None, initialized_store: Path
) -> None:
    with pytest.raises(PassError) as exc:
        server.init("alice@example.com")  # type: ignore[arg-type]
    assert exc.value.code == "invalid_argument"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "a\nb",
        "a;rm -rf /",
        "a|cat",
        "a`whoami`",
        "a$VAR",
        "-rf",
        "a\x00b",
        "x" * 300,
    ],
)
def test_init_rejects_malicious_gpg_ids(
    destructive_on: None, has_secret_key: None, stub_pass: dict[str, Any], bad: str
) -> None:
    with pytest.raises(PassError):
        server.init([bad])
    assert stub_pass["calls"] == []


def test_init_validates_subfolder(
    destructive_on: None, has_secret_key: None, stub_pass: dict[str, Any]
) -> None:
    with pytest.raises(InvalidPassName):
        server.init(["alice@example.com"], subfolder="../escape")
    assert stub_pass["calls"] == []


# ── init: lock-out pre-flight ────────────────────────────────────────────────


def test_init_refuses_when_user_has_no_secret_key(
    destructive_on: None, no_secret_key: None, stub_pass: dict[str, Any]
) -> None:
    with pytest.raises(PassError) as exc:
        server.init(["stranger@example.com"])
    assert exc.value.code == "would_lock_out"
    assert stub_pass["calls"] == []


def test_init_force_overrides_lockout_check(
    destructive_on: None, no_secret_key: None, stub_pass: dict[str, Any]
) -> None:
    server.init(["stranger@example.com"], force=True)
    assert stub_pass["calls"][0]["args"] == ["init", "stranger@example.com"]


def test_init_passes_with_at_least_one_secret_key(
    destructive_on: None, monkeypatch: pytest.MonkeyPatch, stub_pass: dict[str, Any]
) -> None:
    seen: list[str] = []

    def has_key(gid: str, **kw: Any) -> bool:
        seen.append(gid)
        return gid == "me@example.com"

    monkeypatch.setattr(pass_cli, "gpg_has_secret_key", has_key)
    server.init(["stranger@example.com", "me@example.com"])
    # Pre-flight stops as soon as one matches.
    assert "me@example.com" in seen
    assert stub_pass["calls"][0]["args"] == ["init", "stranger@example.com", "me@example.com"]


# ── init: pass invocation ────────────────────────────────────────────────────


def test_init_root(destructive_on: None, has_secret_key: None, stub_pass: dict[str, Any]) -> None:
    result = server.init(["alice@example.com"])
    assert stub_pass["calls"][0]["args"] == ["init", "alice@example.com"]
    assert result["ok"] is True
    assert result["subfolder"] is None
    assert result["gpg_ids"] == ["alice@example.com"]


def test_init_subfolder(
    destructive_on: None, has_secret_key: None, stub_pass: dict[str, Any]
) -> None:
    server.init(["alice@example.com"], subfolder="team")
    assert stub_pass["calls"][0]["args"] == ["init", "--path", "team", "alice@example.com"]


def test_init_uses_long_timeout(
    destructive_on: None, has_secret_key: None, stub_pass: dict[str, Any]
) -> None:
    server.init(["alice@example.com"])
    assert stub_pass["calls"][0]["timeout"] == 120.0


# ── init: empty gpg_ids = remove subfolder .gpg-id ───────────────────────────


def test_init_empty_list_removes_subfolder_gpg_id(
    destructive_on: None, stub_pass: dict[str, Any]
) -> None:
    result = server.init([], subfolder="team")
    assert stub_pass["calls"][0]["args"] == ["init", "--path", "team", ""]
    assert result["removed"] is True


def test_init_empty_list_root_refused(destructive_on: None, stub_pass: dict[str, Any]) -> None:
    with pytest.raises(PassError) as exc:
        server.init([])
    assert exc.value.code == "invalid_argument"
    assert stub_pass["calls"] == []


# ── reencrypt ────────────────────────────────────────────────────────────────


def test_reencrypt_refuses_when_no_gpg_id(
    destructive_on: None, has_secret_key: None, initialized_store: Path
) -> None:
    (initialized_store / ".gpg-id").unlink()
    with pytest.raises(NotFound):
        server.reencrypt()


def test_reencrypt_uses_current_gpg_ids(
    destructive_on: None, has_secret_key: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / ".gpg-id").write_text("alice@example.com\nbob@example.com\n")
    result = server.reencrypt()
    assert stub_pass["calls"][0]["args"] == [
        "init",
        "alice@example.com",
        "bob@example.com",
    ]
    assert result["gpg_ids"] == ["alice@example.com", "bob@example.com"]


def test_reencrypt_subfolder(
    destructive_on: None, has_secret_key: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    sub = initialized_store / "team"
    sub.mkdir()
    (sub / ".gpg-id").write_text("team@example.com\n")
    server.reencrypt(subfolder="team")
    assert stub_pass["calls"][0]["args"] == [
        "init",
        "--path",
        "team",
        "team@example.com",
    ]


def test_reencrypt_validates_subfolder(destructive_on: None, stub_pass: dict[str, Any]) -> None:
    with pytest.raises(InvalidPassName):
        server.reencrypt(subfolder="../escape")
    assert stub_pass["calls"] == []


def test_reencrypt_skips_comments_and_blanks(
    destructive_on: None, has_secret_key: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / ".gpg-id").write_text(
        "# this is the team key\n\nalice@example.com\n   \n# end\n"
    )
    server.reencrypt()
    assert stub_pass["calls"][0]["args"] == ["init", "alice@example.com"]


def test_destructive_tools_registered() -> None:
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert names >= {"init", "reencrypt"}
