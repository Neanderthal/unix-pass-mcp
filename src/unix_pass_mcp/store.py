"""Read-only introspection of a `pass` store.

Walks the password-store directory to discover `.gpg-id` files and reports
which recipients encrypt each subtree. Never decrypts anything.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import pass_cli
from .errors import StoreMisconfigured

# pinentry binaries shipped by GnuPG / distros, classified by what they need.
# `tty` flavours block on /dev/tty — fatal for an MCP server with no TTY.
# `gui` flavours need DISPLAY / WAYLAND_DISPLAY — fine for desktop MCP clients.
_PINENTRY_TTY = frozenset({"pinentry-curses", "pinentry-tty"})
_PINENTRY_GUI = frozenset(
    {
        "pinentry-gnome3",
        "pinentry-gtk-2",
        "pinentry-gtk2",
        "pinentry-qt",
        "pinentry-qt5",
        "pinentry-qt6",
        "pinentry-x11",
        "pinentry-mac",
        "pinentry-fltk",
    }
)
# A bare `pinentry` is the distro-default symlink — `_classify_pinentry`
# resolves it via Path.resolve() before classifying the underlying binary.


def resolve_store_dir() -> Path:
    raw = os.environ.get("PASSWORD_STORE_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".password-store").resolve()


@dataclass(frozen=True)
class PinentryInfo:
    """Result of inspecting gpg-agent's pinentry configuration.

    `kind` is one of `tty`, `gui`, `unknown`, or `missing` (no config / no binary).
    `usable` is the headless verdict: `tty` pinentries are unusable from an MCP
    server, `gui` pinentries are usable iff DISPLAY/WAYLAND_DISPLAY is set.
    """

    program: str | None
    program_resolved: str | None
    kind: str
    config_path: str | None
    has_tty: bool
    has_display: bool
    usable: bool


@dataclass(frozen=True)
class StoreInfo:
    store_dir: str
    exists: bool
    is_git_repo: bool
    recipients_by_subdir: dict[str, list[str]] = field(default_factory=dict)
    signing_required: bool = False
    signing_key_fingerprints: list[str] = field(default_factory=list)
    gpg_agent_available: bool = False
    pinentry: PinentryInfo | None = None
    pass_version: str | None = None
    umask: str = "077"
    git_remotes: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _read_gpg_id(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def _walk_recipients(store_dir: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for dirpath, dirnames, filenames in os.walk(store_dir):
        # Don't descend into the git metadata or hidden extension dirs.
        dirnames[:] = [d for d in dirnames if d not in {".git", ".extensions"}]
        if ".gpg-id" in filenames:
            relative = os.path.relpath(dirpath, store_dir)
            key = "" if relative == "." else relative.replace(os.sep, "/")
            out[key] = _read_gpg_id(Path(dirpath) / ".gpg-id")
    return out


def _signing_info(store_dir: Path) -> tuple[bool, list[str]]:
    fingerprints_env = os.environ.get("PASSWORD_STORE_SIGNING_KEY", "").split()
    has_sig_files = any(store_dir.rglob(".gpg-id.sig")) if store_dir.exists() else False
    return bool(fingerprints_env or has_sig_files), fingerprints_env


def _gnupghome() -> Path:
    raw = os.environ.get("GNUPGHOME")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".gnupg"


def _read_pinentry_program(conf_path: Path) -> str | None:
    """Last `pinentry-program …` line wins, mirroring gpg-agent's own parsing."""
    try:
        text = conf_path.read_text(encoding="utf-8")
    except OSError:
        return None
    program: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^pinentry-program\s+(.+?)\s*$", line)
        if match:
            program = match.group(1)
    return program


def _classify_pinentry(program: str | None) -> tuple[str, str | None]:
    """Return (kind, resolved_program). Resolves symlinks before classifying."""
    if not program:
        return "missing", None

    try:
        link_target = Path(program).resolve(strict=False)
    except OSError:
        link_target = Path(program)
    resolved_basename = link_target.name
    basename = Path(program).name

    if basename in _PINENTRY_TTY or resolved_basename in _PINENTRY_TTY:
        return "tty", str(link_target)
    if basename in _PINENTRY_GUI or resolved_basename in _PINENTRY_GUI:
        return "gui", str(link_target)
    return "unknown", str(link_target)


def _has_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _has_tty() -> bool:
    """True iff any of stdin/stdout/stderr is a TTY (i.e. a /dev/tty exists)."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            if stream is not None and stream.isatty():
                return True
        except (ValueError, OSError):
            continue
    # Fallback: try to open /dev/tty directly. Pinentry-curses does the same.
    try:
        with open("/dev/tty"):
            return True
    except OSError:
        return False


def _collect_pinentry() -> PinentryInfo:
    conf = _gnupghome() / "gpg-agent.conf"
    program = _read_pinentry_program(conf) if conf.exists() else None
    kind, resolved = _classify_pinentry(program)
    has_tty = _has_tty()
    has_display = _has_display()
    if kind == "tty":
        usable = has_tty
    elif kind == "gui":
        usable = has_display
    elif kind == "missing":
        # gpg-agent will fall back to its compiled-in default; we can't predict
        # without invoking gpg-agent, so call it usable iff *either* environment
        # affordance exists. Verdict gets a "verify" warning regardless.
        usable = has_tty or has_display
    else:
        usable = has_tty or has_display
    return PinentryInfo(
        program=program,
        program_resolved=resolved,
        kind=kind,
        config_path=str(conf) if conf.exists() else None,
        has_tty=has_tty,
        has_display=has_display,
        usable=usable,
    )


def _pinentry_warnings(info: PinentryInfo) -> list[str]:
    warnings: list[str] = []
    if info.kind == "tty" and not info.has_tty:
        warnings.append(
            f"pinentry-program is {info.program!r} (TTY-only) but the server has no controlling "
            "TTY — decryption will hang/fail. Switch to a graphical pinentry "
            "(pinentry-gnome3 / pinentry-qt / pinentry-gtk-2) in ~/.gnupg/gpg-agent.conf, "
            "then `gpgconf --kill gpg-agent`."
        )
    elif info.kind == "gui" and not info.has_display:
        warnings.append(
            f"pinentry-program is {info.program!r} (GUI-only) but neither DISPLAY nor "
            "WAYLAND_DISPLAY is set in the server's environment — the dialog can't open. "
            "Either pass DISPLAY through to the MCP server or switch to pinentry-curses "
            "and run inside a terminal."
        )
    elif info.kind == "missing" and not (info.has_tty or info.has_display):
        warnings.append(
            "no pinentry-program in gpg-agent.conf and no TTY or DISPLAY available — "
            "decryption will fail. Configure pinentry-program explicitly."
        )
    elif info.kind == "unknown":
        warnings.append(
            f"pinentry-program {info.program!r} is unrecognized; "
            "verify it can prompt without a TTY before relying on this server."
        )
    return warnings


def _world_readable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH))


def collect() -> StoreInfo:
    store_dir = resolve_store_dir()
    pinentry = _collect_pinentry()
    pinentry_warnings = _pinentry_warnings(pinentry)

    if not store_dir.exists():
        return StoreInfo(
            store_dir=str(store_dir),
            exists=False,
            is_git_repo=False,
            gpg_agent_available=pass_cli.gpg_agent_available(),
            pinentry=pinentry,
            pass_version=pass_cli.pass_version(),
            warnings=[f"store directory does not exist: {store_dir}", *pinentry_warnings],
        )

    warnings: list[str] = list(pinentry_warnings)
    if _world_readable(store_dir):
        warnings.append("store directory is world-accessible (mode bits o+rwx)")

    umask = os.environ.get("PASSWORD_STORE_UMASK", "077")
    if not _is_at_least_077(umask):
        warnings.append(f"PASSWORD_STORE_UMASK={umask!r} is weaker than 077")

    recipients = _walk_recipients(store_dir)
    if "" not in recipients:
        warnings.append("no root .gpg-id found — store is uninitialized; run `pass init <gpg-id>`")

    signing_required, fingerprints = _signing_info(store_dir)
    is_git = (store_dir / ".git").is_dir()
    if is_git:
        # Local import to avoid an import cycle (git_cmd imports store).
        from . import git_cmd

        git_remotes = git_cmd.remotes(store_dir)
    else:
        git_remotes = []

    return StoreInfo(
        store_dir=str(store_dir),
        exists=True,
        is_git_repo=is_git,
        recipients_by_subdir=recipients,
        signing_required=signing_required,
        signing_key_fingerprints=fingerprints,
        gpg_agent_available=pass_cli.gpg_agent_available(),
        pinentry=pinentry,
        pass_version=pass_cli.pass_version(),
        umask=umask,
        git_remotes=git_remotes,
        warnings=warnings,
    )


def entry_path(name: str) -> Path:
    """Filesystem path of the encrypted entry file (may not exist)."""
    return resolve_store_dir() / f"{name}.gpg"


def entry_exists(name: str) -> bool:
    return entry_path(name).is_file()


def directory_exists(name: str) -> bool:
    """Whether the pass-name resolves to a (subfolder) directory."""
    return (resolve_store_dir() / name).is_dir()


def list_names(subfolder: str | None = None) -> list[str]:
    """Walk the store and return pass-names (relative, no .gpg suffix), sorted.

    Avoids invoking `pass ls` (which depends on tree(1)). Skips .git, .extensions
    and any other dotfiles.
    """
    root = resolve_store_dir()
    if subfolder:
        root = root / subfolder
    if not root.exists() or not root.is_dir():
        return []
    base = resolve_store_dir()
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for fn in sorted(filenames):
            if not fn.endswith(".gpg") or fn.startswith("."):
                continue
            full = Path(dirpath) / fn
            rel = full.relative_to(base).as_posix()
            out.append(rel[:-4])  # strip .gpg
    return out


def find_names(query: str, subfolder: str | None = None) -> list[str]:
    """Case-insensitive substring match against the leaf name (mirrors `pass find`)."""
    needle = query.lower()
    return [name for name in list_names(subfolder) if needle in name.rsplit("/", 1)[-1].lower()]


def _is_at_least_077(umask: str) -> bool:
    try:
        value = int(umask, 8)
    except ValueError as exc:
        raise StoreMisconfigured(f"invalid PASSWORD_STORE_UMASK: {umask!r}") from exc
    # 077 means: deny all bits for group+other. Anything weaker has bits unset
    # in the lower 6 positions, i.e. (value & 0o077) != 0o077.
    return (value & 0o077) == 0o077
