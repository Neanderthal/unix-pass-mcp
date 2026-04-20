"""Integration tests against a real `pass` + `gpg` install.

Auto-skip rules:
    * `PASS_MCP_INTEGRATION` env var must be set to a truthy value
    * `pass` and `gpg` must be on PATH

Each test gets an ephemeral `GNUPGHOME` and `PASSWORD_STORE_DIR`. We generate
a throwaway passphrase-less key (`rsa1024`) inside the temp `GNUPGHOME` and
init the store against it. The key never lives on disk outside `tmp_path`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

INTEGRATION_FLAG = "PASS_MCP_INTEGRATION"


def _integration_enabled() -> bool:
    return os.environ.get(INTEGRATION_FLAG, "").strip().lower() in {"1", "true", "yes", "on"}


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


pytestmark = [
    pytest.mark.skipif(not _integration_enabled(), reason=f"{INTEGRATION_FLAG} not set"),
    pytest.mark.skipif(not _have("pass"), reason="`pass` not installed"),
    pytest.mark.skipif(not _have("gpg"), reason="`gpg` not installed"),
]


def _gen_key(gnupghome: Path) -> str:
    """Generate an ephemeral RSA key in `gnupghome`. Returns the key fingerprint."""
    batch = (
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 2048\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 2048\n"
        "Name-Real: unix-pass-mcp test\n"
        "Name-Email: test@unix-pass-mcp.invalid\n"
        "Expire-Date: 1d\n"
        "%commit\n"
    )
    env = {
        "GNUPGHOME": str(gnupghome),
        "PATH": os.environ["PATH"],
    }
    subprocess.run(
        ["gpg", "--batch", "--gen-key"],
        input=batch,
        text=True,
        capture_output=True,
        check=True,
        env=env,
        timeout=120,
    )
    listing = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        timeout=10,
    )
    for line in listing.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise RuntimeError("could not extract key fingerprint")


@pytest.fixture
def real_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    gnupghome = tmp_path / "gnupg"
    gnupghome.mkdir(mode=0o700)
    store = tmp_path / "store"
    monkeypatch.setenv("GNUPGHOME", str(gnupghome))
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(store))
    monkeypatch.setenv("PASS_MCP_AUDIT_LOG", "")
    fpr = _gen_key(gnupghome)
    subprocess.run(
        ["pass", "init", fpr],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PASSWORD_STORE_DIR": str(store), "GNUPGHOME": str(gnupghome)},
        timeout=20,
    )
    yield store
