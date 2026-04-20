"""Unit tests for the M2 write surface.

These mock `pass_cli.run_or_raise` so they exercise pure orchestration: the
write gate, pre-existence checks, body validation, stdin transport, and
audit/error mapping. End-to-end re-encryption behaviour lives in
`tests/integration/`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from unix_pass_mcp import pass_cli, server
from unix_pass_mcp.errors import (
    AlreadyExists,
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
def stub_pass(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"calls": [], "responses": {}, "errors": {}}

    def fake(args: list[str], *, stdin: str | None = None, timeout: float = 15.0):
        state["calls"].append({"args": list(args), "stdin": stdin})
        key = tuple(args)
        if key in state["errors"]:
            raise state["errors"][key]
        stdout = state["responses"].get(key, "")
        return pass_cli.CommandResult(
            args=("/bin/pass", *args), returncode=0, stdout=stdout, stderr=""
        )

    monkeypatch.setattr(pass_cli, "run_or_raise", fake)
    return state


# ── write gate ───────────────────────────────────────────────────────────────


def test_insert_refuses_without_writes_gate(initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.insert("foo", "pw")


def test_insert_multiline_refuses_without_writes_gate(initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.insert_multiline("foo", "pw\n")


def test_set_field_refuses_without_writes_gate(initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.set_field("foo", "URL", "x")


def test_unset_field_refuses_without_writes_gate(initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.unset_field("foo", "URL")


def test_generate_refuses_without_writes_gate(initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.generate("foo")


def test_mv_refuses_without_writes_gate(initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.mv("a", "b")


def test_cp_refuses_without_writes_gate(initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.cp("a", "b")


# ── insert ───────────────────────────────────────────────────────────────────


def test_insert_creates_new(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    result = server.insert("github.com", "hunter2")
    assert result == {"name": "github.com", "ok": True}
    call = stub_pass["calls"][0]
    assert call["args"] == ["insert", "--echo", "github.com"]
    assert call["stdin"] == "hunter2\n"


def test_insert_refuses_overwrite_without_force(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "github.com.gpg").write_bytes(b"x")
    with pytest.raises(AlreadyExists):
        server.insert("github.com", "hunter2")
    assert stub_pass["calls"] == []  # never reached pass


def test_insert_force_overwrites(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "github.com.gpg").write_bytes(b"x")
    server.insert("github.com", "hunter2", force=True)
    call = stub_pass["calls"][0]
    assert call["args"] == ["insert", "--echo", "--force", "github.com"]


def test_insert_rejects_newline_in_password(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(PassError) as exc:
        server.insert("foo", "line1\nline2")
    assert exc.value.code == "invalid_argument"
    assert stub_pass["calls"] == []


def test_insert_rejects_nul_in_password(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(PassError):
        server.insert("foo", "abc\x00def")
    assert stub_pass["calls"] == []


def test_insert_rejects_oversized_password(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(PassError):
        server.insert("foo", "x" * 100_000)
    assert stub_pass["calls"] == []


def test_insert_validates_pass_name(writes_on: None, stub_pass: dict[str, Any]) -> None:
    with pytest.raises(InvalidPassName):
        server.insert("../escape", "pw")
    assert stub_pass["calls"] == []


# ── insert_multiline ─────────────────────────────────────────────────────────


def test_insert_multiline_writes_full_body(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    body = "hunter2\nURL: https://x\nUsername: alice\n"
    server.insert_multiline("foo", body)
    call = stub_pass["calls"][0]
    assert call["args"] == ["insert", "--multiline", "foo"]
    assert call["stdin"] == body


def test_insert_multiline_appends_trailing_newline(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    server.insert_multiline("foo", "no-trailing-newline")
    assert stub_pass["calls"][0]["stdin"] == "no-trailing-newline\n"


def test_insert_multiline_allows_newlines_in_body(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    server.insert_multiline("foo", "line1\nline2\nline3\n")
    assert stub_pass["calls"][0]["stdin"] == "line1\nline2\nline3\n"


def test_insert_multiline_rejects_nul_body(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(PassError):
        server.insert_multiline("foo", "abc\x00def")
    assert stub_pass["calls"] == []


# ── set_field / unset_field ──────────────────────────────────────────────────


def test_set_field_round_trip(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\nURL: old\n"
    result = server.set_field("site", field="URL", value="new")
    assert result["ok"] is True
    assert result["fields_count"] == 1
    write_call = stub_pass["calls"][1]
    assert write_call["args"] == ["insert", "--multiline", "--force", "site"]
    assert "URL: new" in write_call["stdin"]
    assert "URL: old" not in write_call["stdin"]


def test_set_field_appends_when_missing(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\n"
    server.set_field("site", field="Username", value="alice")
    body = stub_pass["calls"][1]["stdin"]
    assert body.startswith("pw\n")
    assert "Username: alice" in body


def test_set_field_preserves_password(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "supersecret\nURL: x\n"
    server.set_field("site", field="URL", value="y")
    body = stub_pass["calls"][1]["stdin"]
    assert body.startswith("supersecret\n")


def test_set_field_rejects_newline_in_value(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\n"
    with pytest.raises(PassError) as exc:
        server.set_field("site", field="URL", value="a\nb")
    assert exc.value.code == "invalid_argument"


def test_set_field_propagates_not_found(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    stub_pass["errors"][("show", "missing")] = NotFound("nope")
    with pytest.raises(NotFound):
        server.set_field("missing", field="URL", value="x")


def test_unset_field_removes_existing(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\nURL: x\nUsername: alice\n"
    result = server.unset_field("site", field="URL")
    assert result == {"name": "site", "field": "URL", "removed": True}
    body = stub_pass["calls"][1]["stdin"]
    assert "URL" not in body
    assert "Username: alice" in body


def test_unset_field_noop_when_absent(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\nURL: x\n"
    result = server.unset_field("site", field="Username")
    assert result["removed"] is False
    # No re-insert call was made.
    assert all(c["args"][0] != "insert" for c in stub_pass["calls"])


# ── generate ─────────────────────────────────────────────────────────────────


def test_generate_creates_new_with_defaults(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    stub_pass["responses"][("show", "foo")] = "Xy7%fGen3rated$Pw\n"
    result = server.generate("foo")
    assert stub_pass["calls"][0]["args"] == ["generate", "foo", "25"]
    assert result["value"] == "Xy7%fGen3rated$Pw"
    assert result["sensitive"] is True


def test_generate_no_symbols_flag(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    stub_pass["responses"][("show", "foo")] = "abc\n"
    server.generate("foo", length=12, no_symbols=True)
    assert stub_pass["calls"][0]["args"] == ["generate", "--no-symbols", "foo", "12"]


def test_generate_in_place_requires_existing(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(NotFound):
        server.generate("foo", in_place=True)
    assert stub_pass["calls"] == []


def test_generate_in_place_on_existing(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "foo.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "foo")] = "newpw\nURL: kept\n"
    result = server.generate("foo", in_place=True, length=20)
    assert "--in-place" in stub_pass["calls"][0]["args"]
    assert result["value"] == "newpw"


def test_generate_refuses_overwrite_without_force(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "foo.gpg").write_bytes(b"x")
    with pytest.raises(AlreadyExists):
        server.generate("foo")
    assert stub_pass["calls"] == []


def test_generate_force_overwrites(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "foo.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "foo")] = "abc\n"
    server.generate("foo", force=True, length=10)
    assert "--force" in stub_pass["calls"][0]["args"]


def test_generate_rejects_in_place_and_force_together(
    writes_on: None, stub_pass: dict[str, Any]
) -> None:
    with pytest.raises(PassError) as exc:
        server.generate("foo", in_place=True, force=True)
    assert exc.value.code == "invalid_argument"


@pytest.mark.parametrize("length", [0, -1, 1025, 99999])
def test_generate_rejects_bad_length(
    writes_on: None, stub_pass: dict[str, Any], length: int
) -> None:
    with pytest.raises(PassError):
        server.generate("foo", length=length)
    assert stub_pass["calls"] == []


# ── mv / cp ──────────────────────────────────────────────────────────────────


def test_mv_basic(writes_on: None, stub_pass: dict[str, Any], initialized_store: Path) -> None:
    (initialized_store / "old.gpg").write_bytes(b"x")
    server.mv("old", "new")
    assert stub_pass["calls"][0]["args"] == ["mv", "old", "new"]


def test_mv_refuses_overwrite_without_force(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "old.gpg").write_bytes(b"x")
    (initialized_store / "new.gpg").write_bytes(b"x")
    with pytest.raises(AlreadyExists):
        server.mv("old", "new")
    assert stub_pass["calls"] == []


def test_mv_force(writes_on: None, stub_pass: dict[str, Any], initialized_store: Path) -> None:
    (initialized_store / "old.gpg").write_bytes(b"x")
    (initialized_store / "new.gpg").write_bytes(b"x")
    server.mv("old", "new", force=True)
    assert stub_pass["calls"][0]["args"] == ["mv", "--force", "old", "new"]


def test_mv_refuses_when_src_missing(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(NotFound):
        server.mv("nope", "new")
    assert stub_pass["calls"] == []


def test_cp_basic(writes_on: None, stub_pass: dict[str, Any], initialized_store: Path) -> None:
    (initialized_store / "src.gpg").write_bytes(b"x")
    server.cp("src", "dst")
    assert stub_pass["calls"][0]["args"] == ["cp", "src", "dst"]


def test_mv_works_on_directory_src(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "team").mkdir()
    (initialized_store / "team" / "shared.gpg").write_bytes(b"x")
    server.mv("team", "group")
    assert stub_pass["calls"][0]["args"] == ["mv", "team", "group"]


# ── adversarial / surface coverage ───────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        "../etc/passwd",
        "-rf",
        "--force",
        "name with space",
        "name\nwith newline",
        "name\x00null",
        "/absolute",
        "trailing/",
        "",
        "x" * 300,
    ],
)
def test_write_tools_reject_malicious_names(
    writes_on: None, stub_pass: dict[str, Any], name: str
) -> None:
    for fn, args in (
        (server.insert, (name, "pw")),
        (server.insert_multiline, (name, "body\n")),
        (server.generate, (name,)),
        (server.mv, (name, "ok")),
        (server.cp, (name, "ok")),
    ):
        with pytest.raises((InvalidPassName, PassError)):
            fn(*args)
    assert stub_pass["calls"] == []


def test_all_m2_tools_registered() -> None:
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert names >= {
        "insert",
        "insert_multiline",
        "set_field",
        "unset_field",
        "generate",
        "mv",
        "cp",
    }
