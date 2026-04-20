from __future__ import annotations

import pytest

from unix_pass_mcp import security
from unix_pass_mcp.errors import (
    DestructiveDisabled,
    InvalidPassName,
    PathNotAllowed,
    WritesDisabled,
)


@pytest.mark.parametrize(
    "name",
    [
        "foo",
        "foo/bar",
        "foo/bar/baz",
        "Email/user@example.com",
        "github.com",
        "192.168.1.1",
        "_private",
        "a-b.c_d@e",
    ],
)
def test_valid_names_pass(name: str) -> None:
    assert security.validate_pass_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "/leading",
        "trailing/",
        "../escape",
        "a/../b",
        "a/./b",
        "a//b",
        "-rf",
        "--force",
        "name\x00",
        "name\nwith newline",
        "name with space",
        "name;rm -rf /",
        "name|cat",
        "name`whoami`",
        "name$VAR",
        "name?",
        "name*",
        "x" * 257,
    ],
)
def test_invalid_names_rejected(name: str) -> None:
    with pytest.raises(InvalidPassName):
        security.validate_pass_name(name)


def test_subfolder_none_returns_none() -> None:
    assert security.validate_subfolder(None) is None
    assert security.validate_subfolder("") is None


def test_path_allowlist_unset_allows_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PASS_MCP_ALLOWED_PATHS", raising=False)
    security.assert_path_allowed("anything/at/all")


def test_path_allowlist_blocks_outside(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOWED_PATHS", "work/*,personal/notes/*")
    security.assert_path_allowed("work/github")
    security.assert_path_allowed("personal/notes/foo")
    with pytest.raises(PathNotAllowed):
        security.assert_path_allowed("personal/banking")


def test_path_allowlist_exact_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOWED_PATHS", "exact-name")
    security.assert_path_allowed("exact-name")
    with pytest.raises(PathNotAllowed):
        security.assert_path_allowed("exact-name-but-longer")


def test_writes_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PASS_MCP_ALLOW_WRITES", raising=False)
    with pytest.raises(WritesDisabled):
        security.require_writes()
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", "1")
    security.require_writes()


def test_destructive_requires_both_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", "1")
    monkeypatch.delenv("PASS_MCP_ALLOW_DESTRUCTIVE", raising=False)
    with pytest.raises(DestructiveDisabled):
        security.require_destructive()
    monkeypatch.setenv("PASS_MCP_ALLOW_DESTRUCTIVE", "1")
    security.require_destructive()


def test_destructive_without_writes_fails_at_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PASS_MCP_ALLOW_WRITES", raising=False)
    monkeypatch.setenv("PASS_MCP_ALLOW_DESTRUCTIVE", "1")
    with pytest.raises(WritesDisabled):
        security.require_destructive()


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE", "On"])
def test_env_flag_truthy(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", value)
    assert security.writes_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
def test_env_flag_falsy(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", value)
    assert security.writes_enabled() is False
