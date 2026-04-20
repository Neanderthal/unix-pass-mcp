"""Integration: init + reencrypt against real GPG.

Exercises the full key-rotation flow: mint a second throwaway key, init the
store with it, and verify previously-stored entries are still decryptable
(because gpg-agent has the new key's secret in this ephemeral GNUPGHOME).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from unix_pass_mcp import server
from unix_pass_mcp.errors import NotFound, PassError


@pytest.fixture(autouse=True)
def _enable_destructive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASS_MCP_ALLOW_WRITES", "1")
    monkeypatch.setenv("PASS_MCP_ALLOW_DESTRUCTIVE", "1")


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


def _gen_second_key() -> str:
    """Mint a second throwaway key in the active GNUPGHOME. Returns fingerprint."""
    batch = (
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 2048\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 2048\n"
        "Name-Real: unix-pass-mcp test rotated\n"
        "Name-Email: rotated@unix-pass-mcp.invalid\n"
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
    return fingerprints[-1]


def test_reencrypt_with_unchanged_recipients_is_idempotent(real_store: Path) -> None:
    """`pass init <same-id>` is a documented no-op when recipients haven't changed.

    `reencrypt` calls `pass init` with the existing .gpg-id, so on an unchanged
    store it returns ok=True without rewriting. The user-observable contract is:
    entries remain decryptable after the call.
    """
    server.insert("foo", "secret-value")
    result = server.reencrypt()
    assert result["ok"] is True
    assert _read_decrypted(real_store, "foo").startswith("secret-value")


def test_init_with_new_key_re_encrypts(real_store: Path) -> None:
    server.insert("github.com", "hunter2")
    server.insert("gitlab.com", "secret")
    second_fpr = _gen_second_key()

    result = server.init([second_fpr])
    assert result["ok"] is True
    # Both entries still decryptable (we have the new key's secret).
    assert _read_decrypted(real_store, "github.com").startswith("hunter2")
    assert _read_decrypted(real_store, "gitlab.com").startswith("secret")
    # Root .gpg-id now points at the new key.
    assert (real_store / ".gpg-id").read_text().strip() == second_fpr


def test_init_subfolder_only_affects_subtree(real_store: Path) -> None:
    server.insert("top", "top-pw")
    server.insert("team/shared", "team-pw")
    second_fpr = _gen_second_key()

    server.init([second_fpr], subfolder="team")
    # team/ has its own .gpg-id with the new key.
    assert (real_store / "team" / ".gpg-id").read_text().strip() == second_fpr
    # Root .gpg-id is unchanged.
    assert second_fpr not in (real_store / ".gpg-id").read_text()
    # Both entries still decrypt (we hold both keys here).
    assert _read_decrypted(real_store, "top").startswith("top-pw")
    assert _read_decrypted(real_store, "team/shared").startswith("team-pw")


def test_init_refuses_lockout(real_store: Path) -> None:
    """gpg-id we don't hold a secret for should be refused (without force=true)."""
    fake_fpr = "DEADBEEF" * 5  # 40 hex chars but not a real key
    with pytest.raises(PassError) as exc:
        server.init([fake_fpr])
    assert exc.value.code == "would_lock_out"


def test_init_remove_subfolder_gpg_id(real_store: Path) -> None:
    second_fpr = _gen_second_key()
    server.init([second_fpr], subfolder="team")
    assert (real_store / "team" / ".gpg-id").exists()
    server.init([], subfolder="team")
    assert not (real_store / "team" / ".gpg-id").exists()


def test_reencrypt_subfolder_after_recipient_change(real_store: Path) -> None:
    """When recipients DO change, init re-encrypts. reencrypt against the
    *current* (post-change) .gpg-id then becomes a no-op — confirming the file
    is encrypted to the new key set.
    """
    server.insert("team/shared", "team-secret")
    second_fpr = _gen_second_key()
    # First init switches recipients → file IS rewritten under the new key.
    bytes_before_switch = (real_store / "team" / "shared.gpg").read_bytes()
    server.init([second_fpr], subfolder="team")
    bytes_after_switch = (real_store / "team" / "shared.gpg").read_bytes()
    assert bytes_after_switch != bytes_before_switch
    # reencrypt at the new state is now a no-op; entry still decrypts.
    server.reencrypt(subfolder="team")
    assert _read_decrypted(real_store, "team/shared").startswith("team-secret")


def test_reencrypt_refuses_when_no_gpg_id(real_store: Path) -> None:
    # Remove root .gpg-id to simulate a malformed store.
    (real_store / ".gpg-id").unlink()
    with pytest.raises(NotFound):
        server.reencrypt()
