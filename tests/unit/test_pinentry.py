from __future__ import annotations

from pathlib import Path

import pytest

from unix_pass_mcp import store


@pytest.fixture
def gnupghome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "gnupg"
    home.mkdir()
    monkeypatch.setenv("GNUPGHOME", str(home))
    return home


def _write_conf(home: Path, body: str) -> Path:
    conf = home / "gpg-agent.conf"
    conf.write_text(body, encoding="utf-8")
    return conf


# ── parsing ──────────────────────────────────────────────────────────────────


def test_no_conf_classified_as_missing(gnupghome: Path) -> None:
    info = store._collect_pinentry()
    assert info.kind == "missing"
    assert info.program is None
    assert info.config_path is None


def test_conf_without_pinentry_program_is_missing(gnupghome: Path) -> None:
    _write_conf(gnupghome, "default-cache-ttl 600\n# pinentry-program /usr/bin/pinentry-curses\n")
    info = store._collect_pinentry()
    assert info.kind == "missing"
    assert info.program is None
    assert info.config_path is not None


def test_pinentry_curses_classified_as_tty(gnupghome: Path) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-curses\n")
    info = store._collect_pinentry()
    assert info.kind == "tty"
    assert info.program == "/usr/bin/pinentry-curses"


def test_pinentry_tty_classified_as_tty(gnupghome: Path) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-tty\n")
    info = store._collect_pinentry()
    assert info.kind == "tty"


@pytest.mark.parametrize(
    "program",
    [
        "/usr/bin/pinentry-gnome3",
        "/usr/bin/pinentry-qt",
        "/usr/bin/pinentry-qt5",
        "/usr/bin/pinentry-qt6",
        "/usr/bin/pinentry-gtk-2",
        "/usr/bin/pinentry-gtk2",
        "/usr/bin/pinentry-x11",
        "/usr/bin/pinentry-mac",
        "/usr/bin/pinentry-fltk",
    ],
)
def test_gui_pinentries_classified_as_gui(gnupghome: Path, program: str) -> None:
    _write_conf(gnupghome, f"pinentry-program {program}\n")
    info = store._collect_pinentry()
    assert info.kind == "gui", f"expected gui for {program}"


def test_unknown_pinentry_classified_as_unknown(gnupghome: Path) -> None:
    _write_conf(gnupghome, "pinentry-program /opt/weird/pinentry-custom\n")
    info = store._collect_pinentry()
    assert info.kind == "unknown"


def test_last_pinentry_program_wins(gnupghome: Path) -> None:
    _write_conf(
        gnupghome,
        "pinentry-program /usr/bin/pinentry-curses\npinentry-program /usr/bin/pinentry-gnome3\n",
    )
    info = store._collect_pinentry()
    assert info.kind == "gui"


def test_comments_and_blank_lines_ignored(gnupghome: Path) -> None:
    _write_conf(
        gnupghome,
        "# this is a comment\n\n   \npinentry-program /usr/bin/pinentry-qt\n# more\n",
    )
    info = store._collect_pinentry()
    assert info.kind == "gui"


def test_bare_pinentry_with_symlink_to_curses(
    gnupghome: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = tmp_path / "pinentry-curses"
    real.write_text("#!/bin/sh\n")
    link = tmp_path / "pinentry"
    link.symlink_to(real)
    _write_conf(gnupghome, f"pinentry-program {link}\n")
    info = store._collect_pinentry()
    assert info.kind == "tty"
    assert info.program_resolved is not None
    assert "pinentry-curses" in info.program_resolved


# ── usable verdict ───────────────────────────────────────────────────────────


def test_tty_pinentry_unusable_without_tty(
    gnupghome: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-curses\n")
    monkeypatch.setattr(store, "_has_tty", lambda: False)
    monkeypatch.setattr(store, "_has_display", lambda: True)
    info = store._collect_pinentry()
    assert info.usable is False


def test_tty_pinentry_usable_with_tty(gnupghome: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-curses\n")
    monkeypatch.setattr(store, "_has_tty", lambda: True)
    monkeypatch.setattr(store, "_has_display", lambda: False)
    info = store._collect_pinentry()
    assert info.usable is True


def test_gui_pinentry_usable_with_display(gnupghome: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-gnome3\n")
    monkeypatch.setattr(store, "_has_tty", lambda: False)
    monkeypatch.setattr(store, "_has_display", lambda: True)
    info = store._collect_pinentry()
    assert info.usable is True


def test_gui_pinentry_unusable_without_display(
    gnupghome: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-gnome3\n")
    monkeypatch.setattr(store, "_has_tty", lambda: True)
    monkeypatch.setattr(store, "_has_display", lambda: False)
    info = store._collect_pinentry()
    assert info.usable is False


def test_has_display_reads_wayland(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    assert store._has_display() is True


def test_has_display_reads_x11(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setenv("DISPLAY", ":0")
    assert store._has_display() is True


def test_has_display_neither(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert store._has_display() is False


# ── warnings ─────────────────────────────────────────────────────────────────


def test_warning_for_tty_pinentry_no_tty(gnupghome: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-curses\n")
    monkeypatch.setattr(store, "_has_tty", lambda: False)
    monkeypatch.setattr(store, "_has_display", lambda: True)
    info = store._collect_pinentry()
    warnings = store._pinentry_warnings(info)
    assert any("TTY-only" in w for w in warnings)
    assert any("gpg-agent.conf" in w for w in warnings)


def test_warning_for_gui_pinentry_no_display(
    gnupghome: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-gnome3\n")
    monkeypatch.setattr(store, "_has_tty", lambda: True)
    monkeypatch.setattr(store, "_has_display", lambda: False)
    info = store._collect_pinentry()
    warnings = store._pinentry_warnings(info)
    assert any("GUI-only" in w for w in warnings)
    assert any("DISPLAY" in w for w in warnings)


def test_no_warning_when_pinentry_usable(gnupghome: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-gnome3\n")
    monkeypatch.setattr(store, "_has_tty", lambda: False)
    monkeypatch.setattr(store, "_has_display", lambda: True)
    info = store._collect_pinentry()
    assert store._pinentry_warnings(info) == []


def test_warning_for_unknown_pinentry(gnupghome: Path) -> None:
    _write_conf(gnupghome, "pinentry-program /opt/weird/pinentry-custom\n")
    info = store._collect_pinentry()
    warnings = store._pinentry_warnings(info)
    assert any("unrecognized" in w for w in warnings)


# ── store_info integration ───────────────────────────────────────────────────


def test_store_info_includes_pinentry(
    initialized_store: Path,
    gnupghome: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-gnome3\n")
    monkeypatch.setattr(store, "_has_tty", lambda: True)
    monkeypatch.setattr(store, "_has_display", lambda: True)
    info = store.collect()
    assert info.pinentry is not None
    assert info.pinentry.kind == "gui"
    assert info.pinentry.usable is True


def test_store_info_warnings_include_pinentry_problem(
    initialized_store: Path,
    gnupghome: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-curses\n")
    monkeypatch.setattr(store, "_has_tty", lambda: False)
    monkeypatch.setattr(store, "_has_display", lambda: True)
    info = store.collect()
    assert any("TTY-only" in w for w in info.warnings)


def test_pinentry_check_runs_even_when_store_missing(
    tmp_path: Path,
    gnupghome: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(tmp_path / "absent"))
    _write_conf(gnupghome, "pinentry-program /usr/bin/pinentry-curses\n")
    monkeypatch.setattr(store, "_has_tty", lambda: False)
    monkeypatch.setattr(store, "_has_display", lambda: True)
    info = store.collect()
    assert info.exists is False
    assert info.pinentry is not None
    assert info.pinentry.kind == "tty"
    assert any("TTY-only" in w for w in info.warnings)
