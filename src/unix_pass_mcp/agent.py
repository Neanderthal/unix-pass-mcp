"""Warm the gpg-agent cache without depending on TTY-bound pinentry.

When the user has `pinentry-curses`/`pinentry-tty` configured but the MCP
server has no controlling TTY, ordinary `pass show` decryption fails because
pinentry can't prompt. This module provides an alternative path:

    desktop password dialog (zenity / kdialog)
        → gpg --pinentry-mode loopback --passphrase-fd 0
            → secret key unlocked by gpg-agent → cached normally

After a successful warmup, subsequent `pass show` calls hit the agent's
in-memory cache and succeed without any pinentry interaction. The cache TTL
is whatever `default-cache-ttl` is set to in `gpg-agent.conf` (default 600s).

Security notes (architecture §6 addendum):
    * The passphrase is read from the desktop dialog's stdout and immediately
      handed to gpg via stdin — never argv, never written to disk by us.
    * The LLM is not in the data path. The user types into a real desktop
      window owned by zenity/kdialog.
    * We pass a tightly-scoped env to both the dialog and gpg (DISPLAY family
      + GNUPGHOME + HOME + PATH only).
    * `gpg`/`zenity`/`kdialog` invocations live here, not in `pass_cli.py`,
      because the chokepoint rule is specifically about the `pass` binary.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import AgentUnavailable, PassError, Timeout
from .store import resolve_store_dir

_DIALOG_TIMEOUT = 120.0
_DECRYPT_TIMEOUT = 30.0
_DESKTOP_ENV_VARS = (
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
)
_GPG_ENV_VARS = ("GNUPGHOME", "HOME", "PATH", "LANG", "LC_ALL", "GPG_TTY")


@dataclass(frozen=True)
class DialogSpec:
    binary: str
    args: tuple[str, ...]


def find_passphrase_dialog() -> DialogSpec | None:
    """First available desktop password dialog, in preference order."""
    candidates: list[DialogSpec] = [
        DialogSpec(
            binary="zenity",
            args=(
                "--password",
                "--title=unix-pass-mcp",
                "--text=Enter GPG passphrase to unlock the password store",
            ),
        ),
        DialogSpec(
            binary="kdialog",
            args=(
                "--password",
                "Enter GPG passphrase to unlock the password store",
                "--title",
                "unix-pass-mcp",
            ),
        ),
    ]
    for spec in candidates:
        if shutil.which(spec.binary) is not None:
            full = shutil.which(spec.binary) or spec.binary
            return DialogSpec(binary=full, args=spec.args)
    return None


def _desktop_env() -> dict[str, str]:
    """Subset of env relevant for opening a desktop dialog + invoking gpg."""
    keep = (*_DESKTOP_ENV_VARS, *_GPG_ENV_VARS)
    return {k: v for k, v in os.environ.items() if k in keep}


def prompt_passphrase(spec: DialogSpec) -> str | None:
    """Open a GUI password prompt. Returns the passphrase, or None if cancelled.

    Raises PassError on dialog malfunction (binary missing, etc.). A non-zero
    exit from the dialog is treated as a user cancellation, which is a normal
    outcome — not an error.
    """
    try:
        proc = subprocess.run(
            [spec.binary, *spec.args],
            capture_output=True,
            text=True,
            env=_desktop_env(),
            timeout=_DIALOG_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise Timeout(f"passphrase dialog ({spec.binary}) timed out") from exc
    except FileNotFoundError as exc:
        raise PassError(f"dialog binary not found: {spec.binary}", code="no_dialog") from exc
    if proc.returncode != 0:
        # zenity/kdialog return 1 on Cancel, 5 on timeout, etc. Treat all
        # non-zero exits as "user did not provide a passphrase".
        return None
    # Strip exactly one trailing newline (both dialogs append one).
    passphrase = proc.stdout
    if passphrase.endswith("\n"):
        passphrase = passphrase[:-1]
    return passphrase or None


def find_warmup_target() -> Path | None:
    """Pick the smallest `.gpg` file in the store as a decryption probe.

    Smaller files decrypt faster. Returns None if the store has no entries —
    in that case there's nothing to unlock against and nothing to show anyway.
    """
    store_dir = resolve_store_dir()
    if not store_dir.exists():
        return None
    smallest: tuple[int, Path] | None = None
    for path in store_dir.rglob("*.gpg"):
        if any(part.startswith(".") for part in path.relative_to(store_dir).parts):
            continue  # skip .git, .extensions, etc.
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if smallest is None or size < smallest[0]:
            smallest = (size, path)
    return smallest[1] if smallest else None


def warm_agent_with_passphrase(passphrase: str, target: Path) -> bool:
    """Decrypt `target` via loopback pinentry. Returns True iff gpg exits 0.

    On success, gpg-agent caches the unlocked secret key for default-cache-ttl
    seconds. The plaintext output is captured (so it doesn't leak to a tty) and
    immediately discarded.
    """
    gpg = shutil.which("gpg")
    if gpg is None:
        raise PassError("`gpg` binary not found on PATH", code="gpg_missing")
    try:
        proc = subprocess.run(
            [
                gpg,
                "--batch",
                "--no-tty",
                "--quiet",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--decrypt",
                str(target),
            ],
            input=passphrase,
            capture_output=True,
            text=True,
            env=_desktop_env(),
            timeout=_DECRYPT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise Timeout("gpg loopback decrypt timed out") from exc
    finally:
        # Best-effort scrub of the local stdout buffer. Python strings are
        # immutable so we can only drop references; the OS process boundary is
        # the real protection here.
        del passphrase
    return proc.returncode == 0


def unlock(*, has_display: bool) -> dict[str, object]:
    """High-level orchestrator. Returns a result dict; does not raise on
    user-facing failures (cancellation, wrong passphrase) — those are normal
    outcomes encoded in the result.
    """
    if not has_display:
        raise PassError(
            "no DISPLAY or WAYLAND_DISPLAY available — the server can't open a "
            "desktop dialog. Run the MCP host inside a desktop session, or "
            "configure pinentry-curses and launch from a terminal.",
            code="no_display",
        )
    spec = find_passphrase_dialog()
    if spec is None:
        raise PassError(
            "no GUI password dialog found — install `zenity` or `kdialog`, "
            "or switch pinentry-program in ~/.gnupg/gpg-agent.conf to a GUI "
            "variant (pinentry-gnome3 / pinentry-qt / pinentry-gtk-2).",
            code="no_dialog",
        )
    target = find_warmup_target()
    if target is None:
        raise PassError(
            "password store has no entries to decrypt — cannot warm the agent "
            "cache. Insert at least one entry first.",
            code="empty_store",
        )

    passphrase = prompt_passphrase(spec)
    if passphrase is None:
        return {"ok": False, "reason": "cancelled"}

    try:
        ok = warm_agent_with_passphrase(passphrase, target)
    finally:
        del passphrase

    if not ok:
        return {"ok": False, "reason": "wrong_passphrase_or_decrypt_failed"}
    return {
        "ok": True,
        "method": "loopback+desktop_dialog",
        "dialog": Path(spec.binary).name,
        "warmup_target_size_bytes": target.stat().st_size,
    }


def is_key_cached() -> bool | None:
    """Best-effort check: any unlocked key in the agent? Returns None if unknown.

    Uses `gpg-connect-agent keyinfo --list /bye`; lines starting with `S KEYINFO`
    have a 7th column = `1` when the key is currently cached.
    """
    binary = shutil.which("gpg-connect-agent")
    if binary is None:
        return None
    try:
        proc = subprocess.run(
            [binary, "keyinfo --list", "/bye"],
            capture_output=True,
            text=True,
            env=_desktop_env(),
            timeout=3.0,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 7 and parts[0] == "S" and parts[1] == "KEYINFO" and parts[6] == "1":
            return True
    return False


def require_agent_running() -> None:
    """Sanity check before unlock: agent socket must be reachable."""
    from . import pass_cli

    if not pass_cli.gpg_agent_available():
        raise AgentUnavailable("gpg-agent is not running; start it first")
