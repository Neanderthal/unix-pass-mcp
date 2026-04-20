"""Test fixtures shared across unit and integration suites."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def fake_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Empty store dir wired into PASSWORD_STORE_DIR for the test."""
    store = tmp_path / "store"
    store.mkdir()
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(store))
    monkeypatch.delenv("PASSWORD_STORE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("PASSWORD_STORE_UMASK", raising=False)
    yield store


@pytest.fixture
def initialized_store(fake_store: Path) -> Path:
    """Store with a root .gpg-id (no actual GPG key required)."""
    (fake_store / ".gpg-id").write_text("test@example.com\n", encoding="utf-8")
    os.chmod(fake_store, 0o700)
    return fake_store
