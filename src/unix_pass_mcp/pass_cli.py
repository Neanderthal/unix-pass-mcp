"""Single chokepoint for invoking the `pass` binary.

Nothing else in the package may import `subprocess`. Adding `pass` calls
elsewhere will break the security model documented in
`.claude/rules/architecture.md` §6.2.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass

from .errors import (
    AgentUnavailable,
    AlreadyExists,
    GpgError,
    NotFound,
    PassError,
    StoreMisconfigured,
    Timeout,
)

# Env vars that pass(1) reads. We only ever propagate these from the caller's
# environment — never anything else — so an MCP-host env leak can't affect
# pass behaviour beyond what's explicitly documented.
_PASS_ENV_PASSTHROUGH = (
    "PASSWORD_STORE_DIR",
    "PASSWORD_STORE_KEY",
    "PASSWORD_STORE_GPG_OPTS",
    "PASSWORD_STORE_UMASK",
    "PASSWORD_STORE_GENERATED_LENGTH",
    "PASSWORD_STORE_CHARACTER_SET",
    "PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS",
    "PASSWORD_STORE_SIGNING_KEY",
    "PASSWORD_STORE_ENABLE_EXTENSIONS",
    "PASSWORD_STORE_EXTENSIONS_DIR",
    "GNUPGHOME",
    "HOME",
    "PATH",
    "LANG",
    "LC_ALL",
    "TERM",
    "GPG_TTY",
)


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def find_pass_binary() -> str:
    path = shutil.which("pass")
    if path is None:
        raise StoreMisconfigured(
            "`pass` binary not found on PATH; install zx2c4/password-store",
        )
    return path


def build_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _PASS_ENV_PASSTHROUGH}
    # Default umask to 077 if caller hasn't pinned one. Architecture §6.7.
    env.setdefault("PASSWORD_STORE_UMASK", "077")
    if extra:
        env.update(extra)
    return env


def run(
    args: list[str],
    *,
    stdin: str | None = None,
    timeout: float = 15.0,
    env_extra: Mapping[str, str] | None = None,
    check: bool = False,
) -> CommandResult:
    """Invoke `pass <args...>` with shell=False and a strict env.

    Never raises on non-zero exit unless `check=True`; callers map exit codes
    to specific PassError subclasses where they have context.
    """
    binary = find_pass_binary()
    full = [binary, *args]
    env = build_env(env_extra)
    try:
        proc = subprocess.run(
            full,
            input=stdin,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise Timeout(f"`pass {args[0] if args else ''}` timed out after {timeout}s") from exc

    result = CommandResult(
        args=tuple(full),
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=_sanitize_stderr(proc.stderr or ""),
    )
    if check and result.returncode != 0:
        raise GpgError(f"pass exited {result.returncode}: {result.stderr.strip()[:400]}")
    return result


def _sanitize_stderr(text: str) -> str:
    """Drop anything that looks like armored GPG output and truncate.

    Cheap defense against accidental secret echo via stderr.
    """
    safe_lines = []
    in_block = False
    for line in text.splitlines():
        if "-----BEGIN" in line:
            in_block = True
            continue
        if "-----END" in line:
            in_block = False
            continue
        if in_block:
            continue
        safe_lines.append(line)
    out = "\n".join(safe_lines)
    return out[:2000]


def gpg_agent_available(timeout: float = 2.0) -> bool:
    """True iff `gpg-connect-agent /bye` exits 0."""
    binary = shutil.which("gpg-connect-agent")
    if binary is None:
        return False
    try:
        proc = subprocess.run(
            [binary, "/bye"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode == 0


def map_error(args: list[str], result: CommandResult) -> PassError:
    """Translate a non-zero `pass` exit into a typed PassError.

    `args` is the argv passed to `run` (excluding the binary). Pattern-matches
    on stderr; falls back to a generic GpgError. Stderr has already been
    sanitized of armored blocks by `_sanitize_stderr`.
    """
    stderr = result.stderr.strip()
    lower = stderr.lower()
    if "is not in the password store" in lower or "no such file" in lower:
        return NotFound(stderr or "entry not found")
    if "already exists" in lower or "would overwrite" in lower:
        return AlreadyExists(stderr or "entry already exists")
    if "no secret key" in lower or "decryption failed" in lower:
        return GpgError(stderr or "decryption failed")
    if "gpg-agent" in lower or "no pinentry" in lower or "inappropriate ioctl" in lower:
        return AgentUnavailable(stderr or "gpg-agent unavailable")
    return GpgError(f"pass {' '.join(args[:1])} exited {result.returncode}: {stderr[:400]}")


def run_or_raise(
    args: list[str],
    *,
    stdin: str | None = None,
    timeout: float = 15.0,
) -> CommandResult:
    """Run pass and raise the appropriate PassError on non-zero exit."""
    result = run(args, stdin=stdin, timeout=timeout)
    if result.returncode != 0:
        raise map_error(args, result)
    return result


_VERSION_RE = re.compile(r"v\d+\.\d+(?:\.\d+)?")


def pass_version() -> str | None:
    try:
        result = run(["--version"], timeout=3.0)
    except (StoreMisconfigured, Timeout):
        return None
    match = _VERSION_RE.search(result.stdout)
    return match.group(0) if match else None
