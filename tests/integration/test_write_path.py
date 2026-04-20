"""Integration: full M2 write surface against a real GPG-encrypted store."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from unix_pass_mcp import server
from unix_pass_mcp.errors import AlreadyExists, NotFound


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


def test_insert_then_show(real_store: Path) -> None:
    server.insert("github.com", "hunter2")
    assert _read_decrypted(real_store, "github.com").startswith("hunter2")


def test_insert_force_overwrites(real_store: Path) -> None:
    server.insert("foo", "first")
    server.insert("foo", "second", force=True)
    assert _read_decrypted(real_store, "foo").startswith("second")


def test_insert_refuses_overwrite_without_force(real_store: Path) -> None:
    server.insert("foo", "first")
    with pytest.raises(AlreadyExists):
        server.insert("foo", "second")


def test_insert_multiline_writes_full_body(real_store: Path) -> None:
    body = "topsecret\nURL: https://x\nUsername: alice\n"
    server.insert_multiline("site", body)
    decrypted = _read_decrypted(real_store, "site")
    assert decrypted.startswith("topsecret")
    assert "URL: https://x" in decrypted
    assert "Username: alice" in decrypted


def test_set_field_preserves_password_and_other_fields(real_store: Path) -> None:
    server.insert_multiline("site", "topsecret\nURL: old\nUsername: alice\n")
    server.set_field("site", field="URL", value="new")
    decrypted = _read_decrypted(real_store, "site")
    assert decrypted.startswith("topsecret\n")
    assert "URL: new" in decrypted
    assert "URL: old" not in decrypted
    assert "Username: alice" in decrypted


def test_set_field_appends_new_field(real_store: Path) -> None:
    server.insert("site", "pw")
    server.set_field("site", field="Email", value="a@b.com")
    decrypted = _read_decrypted(real_store, "site")
    assert "Email: a@b.com" in decrypted


def test_unset_field_removes_one(real_store: Path) -> None:
    server.insert_multiline("site", "pw\nURL: x\nUsername: a\n")
    result = server.unset_field("site", field="URL")
    assert result["removed"] is True
    decrypted = _read_decrypted(real_store, "site")
    assert "URL" not in decrypted
    assert "Username: a" in decrypted


def test_unset_field_noop_when_absent(real_store: Path) -> None:
    server.insert_multiline("site", "pw\nURL: x\n")
    result = server.unset_field("site", field="Email")
    assert result["removed"] is False


def test_generate_creates_with_length(real_store: Path) -> None:
    result = server.generate("foo", length=20)
    assert result["length"] == 20
    assert result["sensitive"] is True
    decrypted = _read_decrypted(real_store, "foo")
    assert decrypted.strip() == result["value"]


def test_generate_no_symbols_is_alphanumeric(real_store: Path) -> None:
    result = server.generate("foo", length=30, no_symbols=True)
    assert result["value"].isalnum()


def test_generate_in_place_preserves_metadata(real_store: Path) -> None:
    server.insert_multiline("foo", "oldpw\nURL: kept\nUsername: alice\n")
    result = server.generate("foo", length=15, in_place=True)
    decrypted = _read_decrypted(real_store, "foo")
    assert decrypted.startswith(result["value"])
    assert "URL: kept" in decrypted
    assert "Username: alice" in decrypted


def test_generate_force_replaces_metadata(real_store: Path) -> None:
    server.insert_multiline("foo", "oldpw\nURL: kept\n")
    server.generate("foo", length=15, force=True)
    decrypted = _read_decrypted(real_store, "foo")
    assert "URL" not in decrypted


def test_generate_in_place_requires_existing(real_store: Path) -> None:
    with pytest.raises(NotFound):
        server.generate("missing", in_place=True)


def test_mv_renames_and_keeps_value(real_store: Path) -> None:
    server.insert_multiline("old", "pw\nURL: x\n")
    server.mv("old", "new")
    decrypted = _read_decrypted(real_store, "new")
    assert decrypted.startswith("pw")
    assert "URL: x" in decrypted
    with pytest.raises(subprocess.CalledProcessError):
        _read_decrypted(real_store, "old")


def test_mv_refuses_overwrite_without_force(real_store: Path) -> None:
    server.insert("a", "x")
    server.insert("b", "y")
    with pytest.raises(AlreadyExists):
        server.mv("a", "b")


def test_mv_force_overwrites(real_store: Path) -> None:
    server.insert("a", "x")
    server.insert("b", "y")
    server.mv("a", "b", force=True)
    assert _read_decrypted(real_store, "b").startswith("x")


def test_cp_keeps_source(real_store: Path) -> None:
    server.insert_multiline("src", "pw\nURL: x\n")
    server.cp("src", "dst")
    assert _read_decrypted(real_store, "src").startswith("pw")
    assert _read_decrypted(real_store, "dst").startswith("pw")


def test_mv_across_subdirs_with_different_recipients(real_store: Path) -> None:
    """Move into a subfolder with a distinct .gpg-id; pass should re-encrypt.

    We mint a *second* throwaway key, write a per-subfolder .gpg-id pointing at
    it, and verify that mv triggers re-encryption such that decryption with the
    original key still works (because we have access to both keys in this test
    GNUPGHOME).
    """
    # Generate a second key in the same temporary GNUPGHOME.
    batch = (
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 2048\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 2048\n"
        "Name-Real: unix-pass-mcp test 2\n"
        "Name-Email: test2@unix-pass-mcp.invalid\n"
        "Expire-Date: 1d\n"
        "%commit\n"
    )
    subprocess.run(
        ["gpg", "--batch", "--gen-key"],
        input=batch,
        text=True,
        capture_output=True,
        check=True,
        timeout=120,
    )
    listing = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    fingerprints = [
        line.split(":")[9] for line in listing.stdout.splitlines() if line.startswith("fpr:")
    ]
    second_key = fingerprints[-1]

    # Set up subfolder with its own .gpg-id pointing at the second key.
    sub = real_store / "team"
    sub.mkdir()
    (sub / ".gpg-id").write_text(second_key + "\n", encoding="utf-8")

    server.insert("toplevel", "secret-value")
    server.mv("toplevel", "team/shared")
    decrypted = _read_decrypted(real_store, "team/shared")
    assert decrypted.startswith("secret-value")

    # The moved file should now be encrypted to the second key. Inspect packet
    # output to confirm the recipient changed.
    packets = subprocess.run(
        ["gpg", "--list-packets", str(sub / "shared.gpg")],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert second_key[-16:].lower() in packets.stdout.lower()
