# Architecture & Design

MCP server exposing the Unix `pass` password manager to Claude (and any MCP client).
Wraps the `pass(1)` CLI; never re-implements GPG or storage logic.

---

## 1. Goals & non-goals

**Goals**
- Full coverage of `pass(1)` operations that make sense over an RPC boundary.
- Hard security defaults: read-only by default, no shell, strict input validation, no secrets in logs.
- Honour every `PASSWORD_STORE_*` env var that affects behaviour.
- Work with both single-key and multi-recipient stores (per-subdir `.gpg-id`).

**Non-goals**
- No clipboard handling (`--clip`) — meaningless across an RPC boundary.
- No QR code rendering (`-q`).
- No interactive `$EDITOR` flow — replaced with field-level edit primitives.
- Not a GPG key manager — assumes `gpg-agent` is configured.
- Not a sync daemon — `git push/pull` is exposed but not scheduled.

---

## 2. Component layout

```
src/unix_pass_mcp/
├── __init__.py
├── server.py        # FastMCP entry, tool registration, lifespan
├── pass_cli.py      # subprocess wrapper around `pass` (the only place that calls it)
├── security.py      # name validation, write/destructive gates, allowed-path checks
├── fields.py        # parse/serialize multiline `Key: value` body
├── store.py         # introspection: PASSWORD_STORE_DIR, .gpg-id resolution, gpg-agent probe
├── errors.py        # PassError hierarchy (mapped to MCP tool errors)
└── audit.py         # rotating action log (action + pass-name only, no secrets)
tests/
├── unit/            # subprocess-mocked
├── integration/     # real GPG; auto-skip if no test key
└── conftest.py
```

**Single chokepoint**: every `pass` invocation goes through `pass_cli.run(args, *, stdin=None, timeout=...)`. Nothing else may import `subprocess`. Enforced by ruff `S404` allowlist in `pass_cli.py` only.

---

## 3. Tool surface

All tools are async (FastMCP handles transport). Sensitive return values carry `meta = {"sensitive": true}` so MCP hosts can refuse to cache/log.

### Read tools (always available)

| Tool | Args | Returns | Notes |
|---|---|---|---|
| `store_info` | – | `{store_dir, recipients_by_subdir, gpg_agent_status, signing_required}` | Health/preflight |
| `list` | `subfolder?` | `[pass-name, ...]` flat | Walks tree, strips `.gpg` |
| `tree` | `subfolder?` | string (tree art from `pass ls`) | UI-friendly |
| `find` | `query` | `[pass-name, ...]` | Wraps `pass find` |
| `show` | `name`, `line=1` | `{value, sensitive: true}` | Default returns line 1 = password |
| `show_field` | `name`, `field` | `{value}` or `{value: null}` | Parses `Key: value`, case-insensitive key |
| `show_metadata` | `name` | `{password_present: bool, fields: {k:v}, raw_lines: int}` | Never returns the password itself |
| `grep` | `pattern`, `subfolder?`, `confirm_decrypt_all=false` | `[{name, line}]` | Refuses unless confirmed; warns about cost |
| `otp` | `name` | `{code, seconds_remaining}` | Only if `pass-otp` installed; else 501 |

### Write tools (require `PASS_MCP_ALLOW_WRITES=1`)

| Tool | Args | Notes |
|---|---|---|
| `insert` | `name`, `password`, `force=false` | Always uses `--echo --force?`; content via stdin |
| `insert_multiline` | `name`, `body`, `force=false` | `pass insert -m -f?` with body on stdin |
| `set_field` | `name`, `field`, `value` | Round-trip: show → modify field → insert -m -f |
| `unset_field` | `name`, `field` | Same round-trip |
| `generate` | `name`, `length=20`, `no_symbols=false`, `in_place=false`, `force=false` | Returns generated value (sensitive) |
| `mv` | `src`, `dst`, `force=false` | Triggers re-encryption to dst's `.gpg-id` |
| `cp` | `src`, `dst`, `force=false` | Same |
| `git` | `subcommand`, `args=[]` | Whitelisted subcommands only — see §6.4 |

### Destructive tools (require `PASS_MCP_ALLOW_DESTRUCTIVE=1` *and* writes)

| Tool | Args | Notes |
|---|---|---|
| `rm` | `name`, `recursive=false` | Always `--force` (interactive prompt would hang) |
| `init` | `gpg_ids=[...]`, `subfolder?` | Re-encrypts entire (sub)tree |
| `reencrypt` | `subfolder?` | Convenience: re-runs `init` with current `.gpg-id` |

---

## 4. Data flow: typical `set_field` call

```
client → set_field(name="email/work", field="username", value="alice")
  ↓
security.validate_pass_name("email/work")
security.require_writes()
security.assert_path_allowed("email/work")
  ↓
fields.parse(pass_cli.run(["show", "email/work"]).stdout)
  → {password: "...", fields: {URL: "..."}}
fields.set("username", "alice")
  ↓
pass_cli.run(["insert", "-m", "-f", "email/work"], stdin=serialized_body)
  ↓
audit.log(action="set_field", name="email/work", field="username", ok=True)
  ↓
return {ok: true, fields_count: 2}
```

Password value never leaves `fields.py` memory; `audit.py` receives only the field name.

---

## 5. Configuration (env vars)

### MCP-server-specific

| Var | Default | Effect |
|---|---|---|
| `PASS_MCP_ALLOW_WRITES` | unset | Required for any mutating tool |
| `PASS_MCP_ALLOW_DESTRUCTIVE` | unset | Required for `rm`/`init`/`reencrypt` |
| `PASS_MCP_ALLOWED_PATHS` | unset (= all) | Comma-separated glob allowlist; e.g. `"work/*,personal/notes/*"` |
| `PASS_MCP_TIMEOUT_SECONDS` | `15` | Per-call subprocess timeout |
| `PASS_MCP_GREP_TIMEOUT_SECONDS` | `120` | Longer timeout for `grep` |
| `PASS_MCP_AUDIT_LOG` | `~/.local/state/unix-pass-mcp/audit.log` | Action log path; set empty to disable |
| `PASS_MCP_REQUIRE_AGENT` | `1` | Preflight fails if no gpg-agent / no cached key |

### Passed through to `pass`

`PASSWORD_STORE_DIR`, `PASSWORD_STORE_KEY`, `PASSWORD_STORE_GPG_OPTS`, `PASSWORD_STORE_UMASK` (default 077; never overridden), `PASSWORD_STORE_GENERATED_LENGTH`, `PASSWORD_STORE_CHARACTER_SET`, `PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS`, `PASSWORD_STORE_SIGNING_KEY`, `PASSWORD_STORE_ENABLE_EXTENSIONS`, `PASSWORD_STORE_EXTENSIONS_DIR`.

Explicitly **not** propagated: `PASSWORD_STORE_X_SELECTION`, `PASSWORD_STORE_CLIP_TIME` (clipboard tools dropped).

---

## 6. Security model

### 6.1 pass-name validation
Regex: `^[A-Za-z0-9._@-][A-Za-z0-9._@/-]*$`, length ≤ 256, no `..` segment, no trailing `/`, no leading `/`. Rejected names raise `InvalidPassName` before any subprocess call.

### 6.2 No shell, ever
`pass_cli.run` uses `subprocess.run(args, shell=False, text=True, env=..., timeout=..., stdin=PIPE_or_None, stdout=PIPE, stderr=PIPE, check=False)`. ruff `S602/S605` enforced.

### 6.3 Stdin-only secret transport
Passwords/bodies for `insert*` go via stdin, never argv (visible in `/proc/<pid>/cmdline`).

### 6.4 Git subcommand whitelist
`git` tool accepts only: `status`, `log` (with `--oneline -n N` only), `diff` (no path args by default), `pull`, `push`, `fetch`, `remote` (`-v` only). No `git config`, `git filter-branch`, `git checkout`, `git reset`. Free-form git remains available via `pass git` on the host shell.

### 6.5 Output sanitization
- `show*` results carry `meta.sensitive = true`.
- `pass_cli.run` strips/truncates stderr before raising (drops anything that looks like a base64 / armored block; keeps known gpg error patterns).
- `audit.py` writes only: timestamp, tool, pass-name (or glob), ok/err, error class. Never values, never field values.

### 6.6 Path allowlist
If `PASS_MCP_ALLOWED_PATHS` is set, every pass-name (incl. `src`/`dst` of `mv`/`cp`) is matched against fnmatch globs. Mismatch → `PathNotAllowed`.

### 6.7 Umask
`PASSWORD_STORE_UMASK` defaults to `077`; the server refuses to start if the user has set it weaker than `077`.

### 6.8 gpg-agent preflight
On startup (and lazily before first decrypt), probe `gpg-connect-agent` for a cached key. If `PASS_MCP_REQUIRE_AGENT=1` and no agent, server reports degraded health and write/destructive tools refuse.

---

## 7. Multiline body format (canonical)

Per upstream convention (browserpass / pass-git-helper compatible):

```
<password>          ← line 1, mandatory
URL: <url>
Username: <username>
otpauth://totp/...  ← consumed by pass-otp
<free text>         ← lines without `Key:` are preserved as-is
```

`fields.py` rules:
- Line 1 is always treated as the password (never parsed as a field).
- A "field line" matches `^[A-Za-z][A-Za-z0-9_-]*:\s*` (case-insensitive lookup, original case preserved on write).
- Non-matching lines are kept verbatim (round-trip safe).
- `set_field` updates an existing field in place; appends if missing.
- `unset_field` removes the line entirely.

---

## 8. Error model

```
PassError                        # base
├── InvalidPassName              # 400-class
├── PathNotAllowed               # 403-class
├── WritesDisabled               # 403-class
├── DestructiveDisabled          # 403-class
├── NotFound                     # 404-class (pass exit 1 + "not in the password store")
├── AlreadyExists                # 409-class (overwrite without --force)
├── GpgError                     # 500-class — sanitized stderr
├── AgentUnavailable             # 503-class
└── Timeout                      # 504-class
```

Each maps to a structured MCP error with stable `code` field for clients to branch on.

---

## 9. Lifecycle

1. **Startup**: parse env, locate `pass` binary, probe gpg-agent, resolve `PASSWORD_STORE_DIR`, read all `.gpg-id` files (cached for the session). Refuse to start if store dir missing.
2. **Per-call**: validate inputs → security gates → subprocess → parse → audit → return.
3. **Shutdown**: flush audit log; no other state.

No background tasks, no file watchers, no in-memory password cache.

---

## 10. Testing strategy

- **Unit (`tests/unit/`)**: mock `pass_cli.run`; cover validation, field parsing, gate logic, error mapping.
- **Integration (`tests/integration/`)**: spin up an ephemeral `PASSWORD_STORE_DIR`, generate a throwaway GPG key (rsa1024, no passphrase, expires immediately after run), exercise real `pass`. Auto-skip if `gpg` missing or `PASS_MCP_INTEGRATION=0`.
- **Property tests**: `fields.py` round-trip — `parse(serialize(parse(s))) == parse(s)` for arbitrary line-wise inputs.
- **Security tests**: dedicated suite of malicious pass-names (`../etc/passwd`, `; rm -rf /`, `name\x00x`, `-rf`, leading `--`).

---

## 11. Open questions

- Do we expose `init` at all? It's powerful and rare. Default: behind `PASS_MCP_ALLOW_DESTRUCTIVE` only; consider a build flag to compile it out.
- Should `git push/pull` require its own gate (`PASS_MCP_ALLOW_NETWORK`)? Pushes leak commit metadata to a remote.
- Multi-store support: today we honour `PASSWORD_STORE_DIR`. Could accept `store: "red"|"blue"` per-call mapping to different dirs. Defer until requested.
