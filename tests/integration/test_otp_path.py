"""Integration: OTP read/write against a real GPG-encrypted store."""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

import pytest

from unix_pass_mcp import server
from unix_pass_mcp.errors import PassError

_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
_URI = f"otpauth://totp/GitHub:alice@example.com?secret={_SECRET}&issuer=GitHub"


@pytest.fixture(autouse=True)
def _enable_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", "1")


def _read_decrypted(store_dir: Path, name: str) -> str:
    proc = subprocess.run(
        ["pass", "show", name],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PASSWORD_STORE_DIR": str(store_dir)},
        timeout=20,
    )
    return proc.stdout


def test_otp_set_then_read(real_store: Path) -> None:
    server.insert_multiline("github.com/alice", "hunter2\nURL: x\nUsername: alice\n")
    result = server.otp_set("github.com/alice", _URI)
    assert result["ok"] is True
    assert result["replaced"] is False
    decrypted = _read_decrypted(real_store, "github.com/alice")
    assert _URI in decrypted
    assert decrypted.startswith("hunter2")
    assert "URL: x" in decrypted
    assert "Username: alice" in decrypted


def test_otp_returns_six_digit_code(real_store: Path) -> None:
    server.insert_multiline("github.com/alice", f"pw\n{_URI}\n")
    result = server.otp_tool("github.com/alice")
    assert len(result["code"]) == 6
    assert result["code"].isdigit()
    assert result["issuer"] == "GitHub"
    assert result["account"] == "alice@example.com"


def test_otp_uri_returns_stored_value(real_store: Path) -> None:
    server.insert_multiline("github.com/alice", f"pw\n{_URI}\n")
    result = server.otp_uri("github.com/alice")
    assert result["uri"] == _URI


def test_otp_set_replaces_existing_uri(real_store: Path) -> None:
    old = f"otpauth://totp/old?secret={_SECRET}"
    server.insert_multiline("github.com/alice", f"pw\nURL: x\n{old}\n")
    new = f"otpauth://totp/GitHub:alice?secret={_SECRET}&period=60"
    result = server.otp_set("github.com/alice", new)
    assert result["replaced"] is True
    decrypted = _read_decrypted(real_store, "github.com/alice")
    assert old not in decrypted
    assert new in decrypted
    assert "URL: x" in decrypted


def test_otp_no_uri_raises(real_store: Path) -> None:
    server.insert("github.com/alice", "pw")
    with pytest.raises(PassError) as exc:
        server.otp_tool("github.com/alice")
    assert exc.value.code == "no_otpauth"


def test_otp_compatible_with_pass_otp_extension(real_store: Path) -> None:
    """Validate parity: a URI inserted via pass-otp itself decodes the same way.

    Skipped automatically if pass-otp isn't on the system. We use the otp.bash
    extension's `insert` subcommand to write the URI, then read it back via our
    server tool — both should agree on the code.
    """
    import shutil

    if not shutil.which("pass") or not Path("/usr/lib/password-store/extensions/otp.bash").exists():
        pytest.skip("pass-otp extension not installed")

    server.insert("github.com/alice", "pw")
    # `pass otp append -f` adds the URI to the existing entry; `insert` would
    # replace the whole file (losing our password line).
    subprocess.run(
        ["pass", "otp", "append", "-f", "-e", "github.com/alice"],
        input=_URI + "\n",
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PASSWORD_STORE_DIR": str(real_store)},
        timeout=20,
    )
    server_result = server.otp_tool("github.com/alice")
    extension_proc = subprocess.run(
        ["pass", "otp", "github.com/alice"],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PASSWORD_STORE_DIR": str(real_store)},
        timeout=20,
    )
    extension_code = extension_proc.stdout.strip()
    # Codes can differ by one window if we cross a 30s boundary between calls;
    # accept that case.
    assert server_result["code"] == extension_code or server_result["seconds_remaining"] <= 2
