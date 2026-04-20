"""Tool-level tests for the OTP surface (mocked subprocess)."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

from unix_pass_mcp import pass_cli, server
from unix_pass_mcp.errors import NotFound, PassError, WritesDisabled

_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
_VALID_URI = f"otpauth://totp/GitHub:alice?secret={_SECRET}&issuer=GitHub"


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


# ── otp ──────────────────────────────────────────────────────────────────────


def test_otp_returns_code_and_metadata(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "site")] = f"pw\nURL: x\n{_VALID_URI}\n"
    result = server.otp_tool("site")
    assert result["sensitive"] is True
    assert len(result["code"]) == 6
    assert result["code"].isdigit()
    assert result["period"] == 30
    assert result["digits"] == 6
    assert result["algorithm"] == "SHA1"
    assert result["issuer"] == "GitHub"
    assert result["account"] == "alice"
    assert 1 <= result["seconds_remaining"] <= 30


def test_otp_raises_when_no_otpauth(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "site")] = "pw\nURL: x\n"
    with pytest.raises(PassError) as exc:
        server.otp_tool("site")
    assert exc.value.code == "no_otpauth"


def test_otp_propagates_not_found(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["errors"][("show", "missing")] = NotFound("nope")
    with pytest.raises(NotFound):
        server.otp_tool("missing")


# ── otp_uri ──────────────────────────────────────────────────────────────────


def test_otp_uri_returns_raw(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "site")] = f"pw\n{_VALID_URI}\n"
    result = server.otp_uri("site")
    assert result["uri"] == _VALID_URI
    assert result["sensitive"] is True


def test_otp_uri_validates_before_returning(
    stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    bad = "otpauth://hotp/x?secret=AAAA"
    stub_pass["responses"][("show", "site")] = f"pw\n{bad}\n"
    with pytest.raises(PassError) as exc:
        server.otp_uri("site")
    assert exc.value.code == "invalid_otpauth"


def test_otp_uri_no_otpauth(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    stub_pass["responses"][("show", "site")] = "pw\nURL: x\n"
    with pytest.raises(PassError) as exc:
        server.otp_uri("site")
    assert exc.value.code == "no_otpauth"


# ── otp_set ──────────────────────────────────────────────────────────────────


def test_otp_set_refuses_without_writes(stub_pass: dict[str, Any], initialized_store: Path) -> None:
    with pytest.raises(WritesDisabled):
        server.otp_set("site", _VALID_URI)


def test_otp_set_appends_when_missing(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    stub_pass["responses"][("show", "site")] = "pw\nURL: x\n"
    result = server.otp_set("site", _VALID_URI)
    assert result["replaced"] is False
    body = stub_pass["calls"][1]["stdin"]
    assert body.startswith("pw\n")
    assert "URL: x" in body
    assert _VALID_URI in body


def test_otp_set_replaces_existing(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    (initialized_store / "site.gpg").write_bytes(b"x")
    old = f"otpauth://totp/old?secret={_SECRET}"
    stub_pass["responses"][("show", "site")] = f"pw\n{old}\nURL: x\n"
    result = server.otp_set("site", _VALID_URI)
    assert result["replaced"] is True
    body = stub_pass["calls"][1]["stdin"]
    assert old not in body
    assert _VALID_URI in body
    assert "URL: x" in body


def test_otp_set_validates_uri_before_decrypt(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    with pytest.raises(PassError) as exc:
        server.otp_set("site", "not a uri")
    assert exc.value.code == "invalid_otpauth"
    assert stub_pass["calls"] == []


def test_otp_set_propagates_not_found(
    writes_on: None, stub_pass: dict[str, Any], initialized_store: Path
) -> None:
    stub_pass["errors"][("show", "missing")] = NotFound("nope")
    with pytest.raises(NotFound):
        server.otp_set("missing", _VALID_URI)


def test_otp_tools_registered() -> None:
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert names >= {"otp", "otp_uri", "otp_set"}
