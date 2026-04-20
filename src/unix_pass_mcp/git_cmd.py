"""Wrappers around `pass git <subcommand>`.

Whitelisted subcommands per `.claude/rules/architecture.md` §6.4:
    status, log, pull, push.

We deliberately omit `diff` (binary noise on .gpg files), `fetch` (subset of
`pull`), `remote -v` (folded into `store_info.git_remotes`), and anything
that mutates history or config (`config`, `reset`, `checkout`, `rebase`,
`filter-branch`). Free-form `pass git <anything>` remains available on the
host shell — the MCP just doesn't drive it.

`pass git <args>` runs git inside the password-store directory and inherits
its environment from `pass`. We never assemble git argv from caller-provided
strings; every `git_*` orchestrator builds a fixed argv internally.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import pass_cli, store
from .errors import NotAGitRepo, PassError


def assert_git_repo() -> None:
    if not (store.resolve_store_dir() / ".git").exists():
        raise NotAGitRepo(
            "store is not a git repository; run `pass git init` in a real "
            "terminal to enable git operations",
        )


# ── status ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class StatusInfo:
    clean: bool
    branch: str | None
    upstream: str | None
    ahead: int
    behind: int
    dirty_files: list[dict[str, str]]


def parse_status_porcelain(text: str) -> StatusInfo:
    """Parse `git status --porcelain=v2 --branch` output.

    The v2 porcelain format guarantees stable, scriptable output. Header lines
    start with `# branch.*`; entry lines start with `1`/`2`/`u`/`?`.
    """
    branch: str | None = None
    upstream: str | None = None
    ahead = 0
    behind = 0
    dirty: list[dict[str, str]] = []

    for raw in text.splitlines():
        if not raw:
            continue
        if raw.startswith("# branch.head "):
            value = raw[len("# branch.head ") :].strip()
            branch = value if value != "(detached)" else None
        elif raw.startswith("# branch.upstream "):
            upstream = raw[len("# branch.upstream ") :].strip()
        elif raw.startswith("# branch.ab "):
            # Format: "# branch.ab +<ahead> -<behind>"
            match = re.match(r"# branch\.ab \+(\d+) -(\d+)", raw)
            if match:
                ahead = int(match.group(1))
                behind = int(match.group(2))
        elif raw.startswith(("1 ", "2 ", "u ")):
            # Ordinary changed / renamed / unmerged entry. Path is at the end.
            parts = raw.split(" ", 8)
            if len(parts) >= 9:
                xy = parts[1]  # e.g. "M." or ".M" or "MM"
                path = parts[8]
                dirty.append({"status": xy, "path": path})
        elif raw.startswith("? "):
            dirty.append({"status": "??", "path": raw[2:]})

    return StatusInfo(
        clean=not dirty and ahead == 0 and behind == 0,
        branch=branch,
        upstream=upstream,
        ahead=ahead,
        behind=behind,
        dirty_files=dirty,
    )


def status() -> StatusInfo:
    assert_git_repo()
    result = pass_cli.run_or_raise(["git", "status", "--porcelain=v2", "--branch"])
    return parse_status_porcelain(result.stdout)


# ── log ──────────────────────────────────────────────────────────────────────


_LOG_LINE = re.compile(r"^([0-9a-f]{7,40})\s+(.*)$")


def parse_oneline_log(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        match = _LOG_LINE.match(line)
        if match:
            out.append({"hash": match.group(1), "subject": match.group(2)})
    return out


def log(limit: int = 20) -> list[dict[str, str]]:
    assert_git_repo()
    if not 1 <= limit <= 200:
        raise PassError("log limit must be between 1 and 200", code="invalid_argument")
    result = pass_cli.run_or_raise(
        ["git", "log", "--oneline", "--no-decorate", "-n", str(limit)],
    )
    return parse_oneline_log(result.stdout)


# ── remotes (helper for store_info) ──────────────────────────────────────────


def remotes(store_dir: Path) -> list[dict[str, str]]:
    """Read remotes from `.git/config` directly. Returns [{name, url}, ...].

    Direct file read avoids adding a `git remote` to the chokepoint and works
    even if the agent gate hasn't been satisfied yet.
    """
    config = store_dir / ".git" / "config"
    try:
        text = config.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[dict[str, str]] = []
    current_name: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('[remote "') and line.endswith('"]'):
            current_name = line[len('[remote "') : -2]
        elif line.startswith("["):
            current_name = None
        elif current_name and line.startswith("url"):
            # `url = <value>` or `url=<value>`
            match = re.match(r"url\s*=\s*(.+?)\s*$", line)
            if match:
                out.append({"name": current_name, "url": match.group(1)})
    return out


# ── network (gated separately by security.require_network) ───────────────────


@dataclass(frozen=True)
class NetworkResult:
    ok: bool
    output: str
    stderr: str


_NETWORK_TIMEOUT = 60.0


def _run_network(args: list[str]) -> NetworkResult:
    result = pass_cli.run(["git", *args], timeout=_NETWORK_TIMEOUT)
    return NetworkResult(
        ok=result.returncode == 0,
        # `pass git pull/push` writes plenty to both streams; truncate.
        output=result.stdout[:4000],
        stderr=result.stderr[:4000],
    )


def pull() -> NetworkResult:
    assert_git_repo()
    return _run_network(["pull", "--ff-only"])


def push() -> NetworkResult:
    assert_git_repo()
    return _run_network(["push"])
