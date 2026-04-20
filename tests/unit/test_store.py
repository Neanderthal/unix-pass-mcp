from __future__ import annotations

from pathlib import Path

import pytest

from unix_pass_mcp import store


def test_resolve_store_dir_uses_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(tmp_path))
    assert store.resolve_store_dir() == tmp_path.resolve()


def test_resolve_store_dir_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PASSWORD_STORE_DIR", raising=False)
    assert store.resolve_store_dir() == (Path.home() / ".password-store").resolve()


def test_collect_missing_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(tmp_path / "nope"))
    info = store.collect()
    assert info.exists is False
    assert any("does not exist" in w for w in info.warnings)


def test_collect_uninitialized_store_warns(fake_store: Path) -> None:
    info = store.collect()
    assert info.exists is True
    assert info.recipients_by_subdir == {}
    assert any("uninitialized" in w for w in info.warnings)


def test_collect_reads_root_gpg_id(initialized_store: Path) -> None:
    info = store.collect()
    assert info.recipients_by_subdir == {"": ["test@example.com"]}


def test_collect_reads_nested_gpg_id(initialized_store: Path) -> None:
    sub = initialized_store / "team"
    sub.mkdir()
    (sub / ".gpg-id").write_text("team@example.com\nshared@example.com\n", encoding="utf-8")
    info = store.collect()
    assert info.recipients_by_subdir[""] == ["test@example.com"]
    assert info.recipients_by_subdir["team"] == ["team@example.com", "shared@example.com"]


def test_collect_skips_dot_git(initialized_store: Path) -> None:
    git = initialized_store / ".git"
    git.mkdir()
    (git / ".gpg-id").write_text("should-not-appear@example.com\n", encoding="utf-8")
    info = store.collect()
    assert ".git" not in info.recipients_by_subdir
    assert all("git" not in k for k in info.recipients_by_subdir)


def test_collect_detects_git_repo(initialized_store: Path) -> None:
    (initialized_store / ".git").mkdir()
    info = store.collect()
    assert info.is_git_repo is True


def test_collect_detects_signing_env(
    initialized_store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PASSWORD_STORE_SIGNING_KEY", "AAAA" * 10)
    info = store.collect()
    assert info.signing_required is True
    assert info.signing_key_fingerprints == ["AAAA" * 10]


def test_collect_warns_on_weak_umask(
    initialized_store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PASSWORD_STORE_UMASK", "022")
    info = store.collect()
    assert any("umask" in w.lower() for w in info.warnings)


def test_collect_accepts_strict_umask(
    initialized_store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PASSWORD_STORE_UMASK", "077")
    info = store.collect()
    assert all("umask" not in w.lower() for w in info.warnings)


def test_is_at_least_077_table() -> None:
    assert store._is_at_least_077("077") is True
    assert store._is_at_least_077("0177") is True  # extra setuid bit, group/other still 077
    assert store._is_at_least_077("022") is False
    assert store._is_at_least_077("000") is False
