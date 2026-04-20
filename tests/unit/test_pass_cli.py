from __future__ import annotations

import pytest

from unix_pass_mcp import pass_cli


def test_build_env_filters_unrelated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASSWORD_STORE_DIR", "/x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me")
    env = pass_cli.build_env()
    assert env["PASSWORD_STORE_DIR"] == "/x"
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_build_env_pins_default_umask(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PASSWORD_STORE_UMASK", raising=False)
    env = pass_cli.build_env()
    assert env["PASSWORD_STORE_UMASK"] == "077"


def test_build_env_respects_caller_umask(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASSWORD_STORE_UMASK", "027")
    env = pass_cli.build_env()
    assert env["PASSWORD_STORE_UMASK"] == "027"


def test_sanitize_stderr_strips_armored_blocks() -> None:
    raw = (
        "gpg: decryption ok\n"
        "-----BEGIN PGP MESSAGE-----\n"
        "hQEMAxxx...secret...\n"
        "-----END PGP MESSAGE-----\n"
        "gpg: WARNING: trailing\n"
    )
    cleaned = pass_cli._sanitize_stderr(raw)
    assert "secret" not in cleaned
    assert "BEGIN" not in cleaned
    assert "decryption ok" in cleaned
    assert "trailing" in cleaned


def test_sanitize_stderr_truncates() -> None:
    huge = "a" * 5000
    assert len(pass_cli._sanitize_stderr(huge)) <= 2000


def test_version_regex_matches_pass_banner() -> None:
    banner = "=" * 44 + "\n=" + " " * 18 + "v1.7.4" + " " * 18 + "=\n"
    match = pass_cli._VERSION_RE.search(banner)
    assert match is not None
    assert match.group(0) == "v1.7.4"
