# API reference: tools, error codes, env vars

Complete machine-readable surface of `unix-pass-mcp`. Source of truth for
agents that branch on result shapes.

---

## Tools (22 total)

### Read-only

| Tool | Args | Notes |
|---|---|---|
| `store_info` | – | Inspect store: path, recipients, git/agent/pinentry status, remotes, warnings. Never decrypts. |
| `list` | `subfolder?` | Sorted flat list of pass-names. |
| `find` | `query`, `subfolder?` | Substring match on leaf names (case-insensitive). |
| `show` | `name`, `line=1` | Decrypt one line (default = password). **sensitive**. |
| `show_field` | `name`, `field` | Decrypt one `Key: value` field (case-insensitive). **sensitive**. |
| `show_metadata` | `name` | Entry shape only — never returns the password value. |
| `grep` | `pattern`, `confirm_decrypt_all=false`, `case_insensitive=false` | Decrypts every entry. **sensitive**. Refuses without confirm flag. |
| `unlock_agent` | `target?` | Pop desktop dialog → loopback gpg → warm agent cache. Optional `target` is a pass-name to decrypt against (validated + path-allowlist-checked); without it, picks the smallest in-scope entry. |
| `otp` | `name` | Compute current TOTP code + `seconds_remaining`. **sensitive**. |
| `otp_uri` | `name` | Return raw `otpauth://` URI. **sensitive**. |
| `git_status` | – | Porcelain v2 → `{clean, branch, upstream, ahead, behind, dirty_files}`. |
| `git_log` | `limit=20` | `[{hash, subject}, …]`, max 200. |

### Write (require `PASS_MCP_ALLOW_WRITES=1`)

| Tool | Args | Notes |
|---|---|---|
| `insert` | `name`, `password`, `force=false` | Single-line entry. Stdin transport. |
| `insert_multiline` | `name`, `body`, `force=false` | Full body (line 1 = password). |
| `set_field` | `name`, `field`, `value`, `simulate=false` | Update one metadata field. `simulate=true` returns diff without writing. |
| `unset_field` | `name`, `field`, `simulate=false` | Remove a metadata field. `simulate=true` returns diff without writing. |
| `generate` | `name`, `length=25`, `no_symbols=false`, `in_place=false`, `force=false` | Generate password. **sensitive** return. |
| `mv` | `src`, `dst`, `force=false` | Rename (re-encrypts on subdir change). |
| `cp` | `src`, `dst`, `force=false` | Copy (re-encrypts on subdir change). |
| `otp_set` | `name`, `uri` | Append/replace otpauth URI on existing entry. |

### Network (require `PASS_MCP_ALLOW_NETWORK=1`)

| Tool | Args | Notes |
|---|---|---|
| `git_pull` | – | `git pull --ff-only` (refuses divergence). |
| `git_push` | – | `git push` (never `--force`). |

### Destructive (require `PASS_MCP_ALLOW_DESTRUCTIVE=1` *and* writes)

| Tool | Args | Notes |
|---|---|---|
| `init` | `gpg_ids`, `subfolder?`, `force=false` | Re-encrypts every entry in scope. Lock-out pre-flight refuses unless `force=true`. Empty `gpg_ids` list removes a subfolder's `.gpg-id`. |
| `reencrypt` | `subfolder?` | Convenience wrapper: re-runs `init` with current `.gpg-id`. No-op when recipients are unchanged. |

`rm` is intentionally not shipped yet.

---

## Error codes

Every `PassError` subclass carries a stable `code` field. Branch on this, not on the message.

| `code` | Class | When |
|---|---|---|
| `pass_error` | `PassError` | Generic — catch-all for anything not classified below. |
| `invalid_pass_name` | `InvalidPassName` | Pass-name fails the regex / length / `..` / leading-`-` checks. |
| `invalid_argument` | `PassError` (custom code) | Other argument validation failure (bad `field`, bad `length`, NUL in body, newline in single-line value, …). |
| `invalid_otpauth` | `PassError` | otpauth URI is malformed: wrong scheme/type, missing/bad secret, unsupported algorithm, out-of-range digits/period. |
| `path_not_allowed` | `PathNotAllowed` | `name` is outside `PASS_MCP_ALLOWED_PATHS`. Stop — out of scope. |
| `writes_disabled` | `WritesDisabled` | A write tool was called without `PASS_MCP_ALLOW_WRITES=1`. Stop — capability not granted. |
| `destructive_disabled` | `DestructiveDisabled` | A destructive tool was called without `PASS_MCP_ALLOW_DESTRUCTIVE=1`. |
| `network_disabled` | `NetworkDisabled` | `git_pull`/`git_push` called without `PASS_MCP_ALLOW_NETWORK=1`. |
| `confirmation_required` | `PassError` | `grep` called without `confirm_decrypt_all=true`. Re-call with the flag if intended. |
| `not_found` | `NotFound` | Pass-name doesn't exist (or `mv`/`cp` source missing). |
| `already_exists` | `AlreadyExists` | Destination/target exists; pass `force=true` only on explicit user confirmation. |
| `no_otpauth` | `PassError` | Entry has no `otpauth://` line. Use `otp_set` to add one. |
| `not_a_git_repo` | `NotAGitRepo` | git tool called against a store that isn't a git repo. Run `pass git init` in a real terminal. |
| `would_lock_out` | `PassError` | `init` called with recipients for which the user has no secret key on this machine. Pass `force=true` if delegating access. |
| `agent_unavailable` | `AgentUnavailable` | gpg-agent isn't running or pinentry can't prompt. Try `unlock_agent`, or fix `gpg-agent.conf`. |
| `gpg_error` | `GpgError` | Decryption failed — usually wrong key or expired secret. Stderr (sanitized) included in message. |
| `gpg_missing` | `PassError` | `gpg` binary missing on PATH. |
| `no_dialog` | `PassError` | `unlock_agent` couldn't find zenity/kdialog. Install one or switch pinentry-program. |
| `no_display` | `PassError` | `unlock_agent` has no DISPLAY/WAYLAND_DISPLAY. Run host inside a desktop session. |
| `empty_store` | `PassError` | `unlock_agent` has nothing to decrypt against. Insert one entry first. |
| `timeout` | `Timeout` | Subprocess exceeded its timeout. |
| `store_misconfigured` | `StoreMisconfigured` | `pass` binary missing, or `PASSWORD_STORE_UMASK` not parseable. |

### Triage shorthand

- **Stop and ask the user** for: `path_not_allowed`, `writes_disabled`, `destructive_disabled`, `network_disabled`, `agent_unavailable`, `no_dialog`, `no_display`, `store_misconfigured`. These mean the user has not granted the capability — don't try to work around them.
- **Branch logic** for: `not_found` (try `find` to suggest alternatives), `already_exists` (only retry with `force=true` on explicit user OK), `no_otpauth` (offer `otp_set`).
- **Retry once** for: `timeout` (transient), `gpg_error` (re-call `unlock_agent` first).
- **Recover with another tool** for: `confirmation_required` (re-call with the flag), `not_a_git_repo` (use FS-only tools instead).

---

## Environment variables

### Server-specific

| Var | Default | Effect |
|---|---|---|
| `PASS_MCP_ALLOW_WRITES` | unset | Required for any mutating tool. |
| `PASS_MCP_ALLOW_DESTRUCTIVE` | unset | Required for `rm`/`init`/`reencrypt` (M3b+). |
| `PASS_MCP_ALLOW_NETWORK` | unset | Required for `git_pull`/`git_push`. |
| `PASS_MCP_ALLOW_UNSAFE` | unset | Bypass strict startup checks (world-readable store, weak umask). Don't. |
| `PASS_MCP_ALLOWED_PATHS` | unset (= all) | Comma-separated fnmatch globs scoping accessible pass-names. |
| `PASS_MCP_REQUIRE_AGENT` | `1` | Refuse to decrypt if gpg-agent unreachable. Set to `0` for batch ops after `unlock_agent`. |
| `PASS_MCP_AUDIT_LOG` | `~/.local/state/unix-pass-mcp/audit.log` | JSONL action log. Empty string = disable. |
| `PASS_MCP_GREP_TIMEOUT_SECONDS` | `120` | Per-call timeout for `grep` (decrypts whole store). |

### Pass-through (read by `pass` itself)

`PASSWORD_STORE_DIR`, `PASSWORD_STORE_KEY`, `PASSWORD_STORE_UMASK` (default `077`; never overridden), `PASSWORD_STORE_GENERATED_LENGTH`, `PASSWORD_STORE_CHARACTER_SET`, `PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS`, `PASSWORD_STORE_SIGNING_KEY`, `PASSWORD_STORE_ENABLE_EXTENSIONS`, `PASSWORD_STORE_EXTENSIONS_DIR`.

Explicitly **not** propagated:
- `PASSWORD_STORE_GPG_OPTS` — interpolated raw into every `gpg` call by `pass`; flags like `--recipient`, `--output`, or `--keyring` are enough for a hostile env to redirect decryption or re-encrypt to an attacker. Wrap `gpg` with a PATH shim if you need custom flags.
- `PASSWORD_STORE_X_SELECTION`, `PASSWORD_STORE_CLIP_TIME` — clipboard tools dropped (meaningless over MCP).

---

## Sensitive-output convention

Tools whose return values contain decrypted secrets carry `meta.sensitive = true` in their MCP tool annotation **and** include `"sensitive": true` in the result body. MCP hosts that respect annotations should refuse to log/cache these. Agent rule: don't include sensitive return values in tool calls or responses other than the immediate consumer (e.g. the browser fill).

Sensitive tools: `show`, `show_field`, `generate`, `otp`, `otp_uri`, `grep`, plus `set_field`/`unset_field` when `simulate=true` (the `before`/`after` body fields contain the password line).
