"""Error hierarchy for unix-pass-mcp.

Each error has a stable string `code` so MCP clients can branch on it without
parsing messages. See `.claude/rules/architecture.md` §8.
"""

from __future__ import annotations


class PassError(Exception):
    code: str = "pass_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": str(self)}


class InvalidPassName(PassError):
    code = "invalid_pass_name"


class PathNotAllowed(PassError):
    code = "path_not_allowed"


class WritesDisabled(PassError):
    code = "writes_disabled"


class DestructiveDisabled(PassError):
    code = "destructive_disabled"


class NetworkDisabled(PassError):
    code = "network_disabled"


class NotAGitRepo(PassError):
    code = "not_a_git_repo"


class NotFound(PassError):
    code = "not_found"


class AlreadyExists(PassError):
    code = "already_exists"


class GpgError(PassError):
    code = "gpg_error"


class AgentUnavailable(PassError):
    code = "agent_unavailable"


class Timeout(PassError):
    code = "timeout"


class StoreMisconfigured(PassError):
    code = "store_misconfigured"
