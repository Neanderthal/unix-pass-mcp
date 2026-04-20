# Roadmap

Milestone-driven. Each milestone is independently shippable and adds capability without weakening defaults.

**Status:** M0 ✅ · M1 ✅ · M2 ✅ · M3a git ✅ · M3b init/reencrypt ✅ · M4 ✅ · M5 ✅ · M6 distribution next

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

## M3a — Git tools ✅

- [x] `git_status` — porcelain v2 parsing → `{clean, branch, upstream, ahead, behind, dirty_files}`
- [x] `git_log` — oneline parsing → `[{hash, subject}, …]`, limit 1–200
- [x] `git_pull` — `--ff-only` (no merge commits, no rebase). Network-gated.
- [x] `git_push` — no force. Network-gated.
- [x] `git_remotes` — folded into `store_info` (read directly from `.git/config`, no subprocess)
- [x] Network gate: `PASS_MCP_ALLOW_NETWORK=1`

**Verified**: 288 unit tests + 38 integration tests (incl. push/pull against a local bare repo), all green.

Deliberately omitted vs. original plan:
- `git_diff` — `.gpg` files diff as binary; the file-list summary is in `git_status` already.
- `git_fetch` — strict subset of `pull`; one tool is enough.
- `git_remote -v` — `store_info.git_remotes` covers it.
- All write-history operations (`config`, `reset`, `checkout`, `rebase`, `filter-branch`) — never useful via an LLM.

## M3b — Destructive ops ✅ (init / reencrypt)

- [x] `init(gpg_ids, subfolder?, force?)` — initialize root or subfolder; lock-out pre-flight (refuses if user has no secret key for any new recipient unless `force=true`); empty `gpg_ids` removes a subfolder's `.gpg-id`
- [x] `reencrypt(subfolder?)` — convenience wrapper that re-runs `init` with the current `.gpg-id`. Honest about being a no-op when recipients haven't changed (`pass init`'s built-in optimization)
- [x] Destructive gate: `PASS_MCP_ALLOW_DESTRUCTIVE=1`

Deferred:
- [ ] `rm` — still pending. Decision needed: do we want `rm -r` exposed at all? An LLM with the destructive gate enabled could wipe the store.

**Verified**: 336 unit tests + 45 integration tests (incl. real key rotation with two ephemeral GPG keys), all green.

---

## M4 — OTP ✅

- [x] `otp` tool — compute current TOTP code from `otpauth://` line in entry. Returns code + `seconds_remaining` + `period`/`digits`/`algorithm`/`issuer`/`account`. Marked sensitive.
- [x] `otp_uri` tool — return the raw URI (sensitive; contains the secret). Validates before echoing.
- [x] `otp_set` tool — append or replace the otpauth URI on an existing entry. Write-gated.
- [x] Native RFC 6238 (SHA1/SHA256/SHA512) — pure stdlib, no `pass-otp` dependency at runtime.
- [x] Compatible with stores authored by `pass-otp` / browserpass / any tool that follows the [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) — recognized in line 1 (URI-only entries) or any subsequent body line.

**Verified**: 256 unit tests (including all RFC 6238 Appendix B vectors across 3 algorithms) + 31 integration tests (including direct parity with the real `pass-otp` extension). Cross-tool compatibility confirmed: a URI written via `pass otp append` is read identically by `otp_tool`.

Deferred from original M4 plan:
- Generic `extension` tool — too easy to abuse via prompt injection. Specific extensions (otp, audit, …) get specific tools instead.

---

## M5 — Hardening & ergonomics ✅

- [x] `grep` with explicit `confirm_decrypt_all` and configurable long timeout (`PASS_MCP_GREP_TIMEOUT_SECONDS`, default 120s)
- [x] Structured MCP error codes documented in [`.claude/rules/api.md`](./.claude/rules/api.md)
- [x] `simulate=true` flag on `set_field` / `unset_field` — returns the would-be body without calling `pass` (most useful where the agent can't predict the output; for `insert`/`generate`/`mv` the agent already knows what it's about to write)
- [x] Refuse to start if `PASSWORD_STORE_UMASK` is weaker than `077` (bypass: `PASS_MCP_ALLOW_UNSAFE=1`)
- [x] Refuse to start if store dir is world-readable (same bypass)

**Verified**: 308 unit tests, all green. Audit-from-architecture-doc checklist passes against the running server.

Deferred from original M5 plan:
- **Multi-store via `PASS_MCP_STORE_<NAME>=/path`** — the "spawn one MCP server per store" pattern works perfectly today (just two entries in `claude_desktop_config.json` with different `PASSWORD_STORE_DIR`). Adding a `store=` arg to every tool would thread through 22 handlers and complicate path-allowlist semantics. Will ship if a real cross-store-in-one-conversation workflow appears.

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
