# unix-pass-mcp

MCP server wrapping the Unix `pass` password manager. Python 3.11+, FastMCP. Single chokepoint over `subprocess`; nothing else may shell out.

## Commands

```bash
uv sync --extra dev                                         # install
uv run unix-pass-mcp                                        # run (stdio)
uv run ruff check && uv run ruff format --check             # lint
uv run pytest -q tests/unit                                 # fast
PASS_MCP_INTEGRATION=1 uv run pytest -q tests/integration   # real gpg
```

## Rules

- [Architecture & security](./.claude/rules/architecture.md) — components, tool surface, error model, security model. Update when adding/changing tools or env vars.
- [Agent workflow](./.claude/rules/agent-workflow.md) — how to drive this MCP from an LLM agent (Claude Desktop / Code / Agent SDK / any MCP host) together with a browser MCP for autonomous account creation and profile filling. Load into the agent's system prompt.
- Global rules live in `~/.claude/rules/`: refactoring, debugging, git-workflow, code-style, testing.

## Status

See [`ROADMAP.md`](./ROADMAP.md). M0 + M1 + M2 done (read + safe writes). M3 (destructive + git) next.

## Conventions specific to this repo

- Every `pass` invocation goes through `pass_cli.run` / `run_or_raise`. Never import `subprocess` elsewhere.
- Every tool handler validates with `security.validate_pass_name` and `security.assert_path_allowed` *before* any subprocess call.
- Mutating tools call `security.require_writes()`; destructive ones call `security.require_destructive()`. Never bypass.
- Audit log records action + pass-name + outcome only — never values, never field contents.
- Integration tests must mint their own throwaway GPG key in an ephemeral `GNUPGHOME`. Never touch the user's real `~/.gnupg` or `~/.password-store`.
