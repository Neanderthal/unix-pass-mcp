# Roadmap

Milestone-driven. Each milestone is independently shippable and adds capability without weakening defaults.

**Status:** M0 ✅ · M1 ✅ · M2 ✅ · M3 next

---

## M0 — Skeleton ✅

Make the project installable and the test loop fast.

- [x] `pyproject.toml` with `mcp`, `pytest`, `pytest-asyncio`, `ruff`
- [x] Package layout per `.claude/rules/architecture.md` §2
- [x] FastMCP server entry; `unix-pass-mcp` console script
- [x] `store_info` tool (no decryption — exercises plumbing only)
- [x] CI: `ruff check`, `ruff format --check`, `pytest` (Python 3.11/3.12/3.13 matrix)
- [x] `README.md` quickstart

**Verified**: `uv run unix-pass-mcp` registers; MCP `initialize` + `tools/list` + `store_info` succeed against a real store over stdio.

---

## M1 — Read-only core ✅

Everything a user/agent needs to *consume* an existing store. Default install posture.

- [x] `pass_cli.run` chokepoint with timeout, env merge, sanitized error mapping (`run_or_raise` + `map_error`)
- [x] `security.validate_pass_name` + path allowlist (`PASS_MCP_ALLOWED_PATHS`)
- [x] Tools: `list`, `find`, `show`, `show_field`, `show_metadata` (`tree` deferred — `list` returns flat names which is more LLM-friendly; revisit if needed)
- [x] `fields.py` parser with round-trip property tests
- [x] gpg-agent preflight; `AgentUnavailable` surfaced cleanly (`PASS_MCP_REQUIRE_AGENT=0` to disable)
- [x] Audit log (action + name only; rotates at 1 MB; `PASS_MCP_AUDIT_LOG=` to disable)
- [x] Integration tests with throwaway GPG key (auto-skip without `PASS_MCP_INTEGRATION=1`)

**Verified**: 106 unit tests + 7 integration tests against real GPG, all green. `PASS_MCP_ALLOW_WRITES` is unset and no write tool exists yet — LLMs can browse and read but cannot mutate.

---

## M2 — Safe writes ✅

Mutating tools that don't destroy data.

- [x] `insert`, `insert_multiline` (stdin-only secret transport, never argv)
- [x] `generate` (length 1-1024, `no_symbols`, `in_place` vs `force` mutually exclusive)
- [x] `set_field`, `unset_field` (round-trip via show + insert -m -f; preserves password)
- [x] `mv`, `cp` (re-encryption to destination subdir's recipients verified end-to-end)
- [x] Write gate: `PASS_MCP_ALLOW_WRITES=1`
- [x] Pre-existence checks so `pass` never hangs on a TTY-less overwrite prompt
- [x] Adversarial input suite (malicious names, oversized bodies, embedded NULs, leading dashes)

**Verified**: 213 unit tests + 25 integration tests against real GPG (including cross-recipient mv re-encryption), all green. `rm`/`init` still refuse — destructive gate (M3) not yet wired.

Bonus shipped this milestone:
- `unlock_agent` tool — pops a desktop password dialog (zenity/kdialog) and warms gpg-agent's cache via loopback pinentry. Solves the headless-MCP + TTY-only-pinentry deadlock without modifying `gpg-agent.conf`.
- Pinentry detection in `store_info` — classifies the configured pinentry as `tty`/`gui`/`unknown`/`missing` and emits actionable warnings.

---

## M3 — Destructive ops & git (1–2 days)

- [ ] `rm` (`--recursive`, always `--force`)
- [ ] `init` / `reencrypt`
- [ ] `git` tool with whitelisted subcommands (status, log, diff, pull, push, fetch, remote -v)
- [ ] Destructive gate: `PASS_MCP_ALLOW_DESTRUCTIVE=1`
- [ ] Optional network gate: `PASS_MCP_ALLOW_NETWORK=1` for push/pull/fetch

**Done when**: an opted-in user can fully administer the store.

---

## M4 — OTP & extensions (1 day)

- [ ] `otp` tool — only registered if `pass-otp` is detected on PATH; else returns capability error
- [ ] `extension` tool (generic) gated behind `PASSWORD_STORE_ENABLE_EXTENSIONS=true` — passes through to a whitelisted extension name

**Done when**: TOTP codes can be retrieved on stores that have `pass-otp` installed.

---

## M5 — Hardening & ergonomics (1–2 days)

- [ ] `grep` with explicit `confirm_decrypt_all` and longer timeout
- [ ] Multi-store: `store: "red"|"blue"` arg → dir mapping from env (`PASS_MCP_STORE_<NAME>=/path`)
- [ ] Structured MCP error codes documented in `.claude/rules/api.md`
- [ ] `simulate=true` flag on every write tool — returns the diff that *would* apply, never calls `pass`
- [ ] Refuse to start if `PASSWORD_STORE_UMASK` is weaker than `077`
- [ ] Refuse to start if store dir is world-readable

**Done when**: an audit checklist (see §6 of architecture doc) passes against the running server.

---

## M6 — Distribution (½ day)

- [ ] `claude_desktop_config.json` snippet in README
- [ ] `mcp install` compatibility (`unix-pass-mcp` works as `stdio` server)
- [ ] PyPI publish workflow (tag → build → upload)
- [ ] Optional: `Dockerfile` for sandboxed execution (mounts `~/.password-store` and `~/.gnupg` read-only by default)

**Done when**: a user can `pipx install unix-pass-mcp` and add three lines to their MCP client config.

---

## Backlog (un-prioritized)

- HTTP/SSE transport with token auth (only behind a reverse proxy)
- Per-tool rate limits (defense-in-depth against runaway agents)
- `pass-import` integration as a one-shot CLI (not an MCP tool)
- Webhook on store change (post-commit git hook → notification)
- Read-only "shadow" mode: tool *names* identical to write tools but always `simulate=true` — useful for agent dry-runs
- Telemetry opt-in (counts only, no names)

---

## Explicit non-roadmap

- GPG key generation/management
- Clipboard or screen-output of secrets
- QR code rendering
- Replacing `gpg-agent`
- Storing the master GPG passphrase anywhere

These belong to other tools. `unix-pass-mcp` only orchestrates `pass(1)`.
