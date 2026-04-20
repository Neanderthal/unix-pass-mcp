"""Input validation and capability gates.

Architecture §6. Every tool handler in `server.py` must pass its pass-name
through `validate_pass_name` *and* `assert_path_allowed` before any
`pass_cli.run` call.
"""

from __future__ import annotations

import fnmatch
import os
import re

from .errors import (
    DestructiveDisabled,
    InvalidPassName,
    NetworkDisabled,
    PathNotAllowed,
    WritesDisabled,
)

_VALID_NAME = re.compile(r"^[A-Za-z0-9._@\-][A-Za-z0-9._@/\-]*$")
_MAX_NAME_LEN = 256


def validate_pass_name(name: str) -> str:
    """Return `name` verbatim if valid, else raise InvalidPassName.

    Rejects anything that could break the subprocess boundary, escape the
    store directory, or look like a CLI flag.
    """
    if not isinstance(name, str) or not name:
        raise InvalidPassName("pass-name must be a non-empty string")
    if len(name) > _MAX_NAME_LEN:
        raise InvalidPassName(f"pass-name longer than {_MAX_NAME_LEN} chars")
    if name.startswith("-"):
        raise InvalidPassName("pass-name may not start with '-' (would be parsed as a flag)")
    if name.startswith("/") or name.endswith("/"):
        raise InvalidPassName("pass-name may not start or end with '/'")
    if "\x00" in name or any(ord(c) < 0x20 for c in name):
        raise InvalidPassName("pass-name contains control characters")
    if "//" in name:
        raise InvalidPassName("pass-name contains empty path segment")
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise InvalidPassName("pass-name contains '.' or '..' segment")
    if not _VALID_NAME.match(name):
        raise InvalidPassName(f"pass-name contains disallowed characters: {name!r}")
    return name


def validate_subfolder(subfolder: str | None) -> str | None:
    """Subfolders follow the same rules as names; None/empty means root."""
    if subfolder is None or subfolder == "":
        return None
    return validate_pass_name(subfolder)


def _allowed_globs() -> list[str]:
    raw = os.environ.get("PASS_MCP_ALLOWED_PATHS", "").strip()
    if not raw:
        return []
    return [g.strip() for g in raw.split(",") if g.strip()]


def assert_path_allowed(name: str) -> None:
    """Honour PASS_MCP_ALLOWED_PATHS, if set. No-op when unset (= all allowed).

    Each allowlist entry is an fnmatch glob matched against the full pass-name.
    Prefix matches are supported by using `foo/*`.
    """
    globs = _allowed_globs()
    if not globs:
        return
    for pattern in globs:
        if fnmatch.fnmatchcase(name, pattern):
            return
    raise PathNotAllowed(
        f"pass-name {name!r} is outside PASS_MCP_ALLOWED_PATHS",
    )


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def writes_enabled() -> bool:
    return _env_flag("PASS_MCP_ALLOW_WRITES")


def destructive_enabled() -> bool:
    return _env_flag("PASS_MCP_ALLOW_DESTRUCTIVE")


def network_enabled() -> bool:
    return _env_flag("PASS_MCP_ALLOW_NETWORK")


def require_writes() -> None:
    if not writes_enabled():
        raise WritesDisabled(
            "write operations require PASS_MCP_ALLOW_WRITES=1",
        )


def require_destructive() -> None:
    # Destructive implies write; require both gates so users opt in twice.
    require_writes()
    if not destructive_enabled():
        raise DestructiveDisabled(
            "destructive operations require PASS_MCP_ALLOW_DESTRUCTIVE=1",
        )


def require_network() -> None:
    if not network_enabled():
        raise NetworkDisabled(
            "git network operations (pull/push) require PASS_MCP_ALLOW_NETWORK=1",
        )
