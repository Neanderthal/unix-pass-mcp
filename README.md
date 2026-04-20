# unix-pass-mcp

MCP server that exposes the [Unix `pass`](https://www.passwordstore.org/) password manager to MCP clients (Claude Code, Claude Desktop, any other host).

> **Status:** M2 — read + safe-write surface complete. 213 unit tests + 25 real-GPG integration tests, all green. Destructive ops (M3) on the [roadmap](./ROADMAP.md).

## Why

`pass` is a thin wrapper around `gpg(1)` and the filesystem. Anything that can shell out can use it — but exposing it raw to an LLM is a recipe for `rm -rf` regret. This server provides:

- A typed MCP surface over the safe subset of `pass`.
- **Read-only by default**; writes and destructive ops behind explicit env opt-ins.
- Strict input validation (no shell, no path escapes, no stdin smuggling of secrets).
- Sanitized error output, append-only audit log, and gpg-agent preflight.

See [`.claude/rules/architecture.md`](./.claude/rules/architecture.md) for the full design and security model.

## Requirements

### Required

| Component | Why | Notes |
|---|---|---|
| Python ≥ 3.11 | Runtime | 3.11 / 3.12 / 3.13 tested in CI |
| [`pass`](https://www.passwordstore.org/) on `PATH` | The wrapped binary | `pass --version` must work |
| `gpg` (GnuPG ≥ 2.2) on `PATH` | Decryption | Used directly only by `unlock_agent` |
| `gpg-agent` | Passphrase caching | The server probes `gpg-connect-agent /bye` at startup and refuses to decrypt if no agent is reachable. Started automatically by GnuPG on first use. |
| A configured GPG key | Required for decryption / `pass init` | Must have its trust level set to "ultimate" — see [Arch wiki](https://wiki.archlinux.org/title/Pass#Encryption_failed:_Unusable_public_key) |
| An initialized password store | The thing being managed | `pass init <gpg-id>` if you don't have one |

The server can never serve an interactive passphrase prompt itself — `pass`/`gpg` will hang. You need **one** of:

1. A **GUI pinentry** configured in `~/.gnupg/gpg-agent.conf` — `pinentry-gnome3`, `pinentry-qt`, `pinentry-qt5`, or `pinentry-gtk-2`. The first decrypt of each cache window pops a desktop dialog. Recommended.
2. **`zenity` or `kdialog`** installed — call the `unlock_agent` MCP tool once per cache window to warm gpg-agent. Use this if you can't change `gpg-agent.conf`.
3. A pre-warmed agent — run `pass show <name>` in a real terminal before talking to the MCP. Cache expires per `default-cache-ttl` (default 600s).

### OS install hints

```bash
# Arch / Manjaro
sudo pacman -S pass gnupg pinentry zenity         # zenity optional, for unlock_agent

# Debian / Ubuntu
sudo apt install pass gnupg pinentry-gnome3 zenity

# Fedora
sudo dnf install pass gnupg2 pinentry-gnome3 zenity

# macOS (Homebrew)
brew install pass gnupg pinentry-mac
```

### Optional

| Component | Enables |
|---|---|
| [`pass-otp`](https://github.com/tadfisher/pass-otp) | M4 `otp` tool (TOTP code retrieval) |
| `git` | Auto-commit on writes if your store is a git repo (M3 will expose `git status`/`log`/`pull`/`push`) |
| `tree(1)` | Not needed — the server walks the FS directly instead of calling `pass ls` |

### Development

| Component | Why |
|---|---|
| [`uv`](https://docs.astral.sh/uv/) | Recommended installer / runner |
| `gpg` with key-generation support | Integration tests mint throwaway keys in an ephemeral `GNUPGHOME` |

## Install

```bash
uv sync --extra dev          # for development
uv pip install .             # for use
```

## Run

```bash
uv run unix-pass-mcp         # speaks MCP over stdio
```

### Wire into Claude Desktop

`~/.config/Claude/claude_desktop_config.json` (or the platform equivalent):

```json
{
  "mcpServers": {
    "pass": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/unix-pass-mcp", "unix-pass-mcp"],
      "env": {
        "PASSWORD_STORE_DIR": "/home/you/.password-store"
      }
    }
  }
}
```

### Wire into Claude Code

```bash
claude mcp add pass -- uv run --directory /absolute/path/to/unix-pass-mcp unix-pass-mcp
```

## Tools

### Read-only (always available)

| Tool | Description |
|---|---|
| `store_info` | Inspect the store: path, recipients per subdir, git/agent/pinentry/signing status, warnings. No decryption. |
| `list` | List pass-names (optionally scoped to a subfolder). No decryption. |
| `find` | Substring search over leaf names. No decryption. |
| `show` | Decrypt and return one line of an entry (default = line 1 = password). Marked sensitive. |
| `show_field` | Decrypt and return one named metadata field (`URL`, `Username`, `otpauth`, …). Case-insensitive. |
| `show_metadata` | Decrypt and return only the entry shape (which fields exist, their values, line count). Password value is never returned. |
| `unlock_agent` | Pop a desktop password dialog (zenity/kdialog) and warm gpg-agent's cache via loopback pinentry. Use when `store_info` reports `pinentry-curses` + no controlling TTY. The LLM never sees the passphrase. |

### Writes (gated behind `PASS_MCP_ALLOW_WRITES=1`)

| Tool | Description |
|---|---|
| `insert` | Create or overwrite a single-line entry. Password via stdin (never argv). Refuses overwrite without `force=true`. |
| `insert_multiline` | Create or overwrite a full-body entry (line 1 = password, rest = `Key: value` metadata). |
| `set_field` | Update one `Key: value` field on an existing entry; preserves password and other lines. |
| `unset_field` | Remove all lines matching a field key (case-insensitive). No-op if absent. |
| `generate` | Generate a new password (length 1–1024, optional `no_symbols`). `in_place=true` keeps metadata; `force=true` overwrites everything. Returns the generated value (sensitive). |
| `mv` | Rename or move an entry/subfolder. Re-encrypts to the destination subfolder's recipients if they differ. |
| `cp` | Copy an entry/subfolder, with the same re-encryption semantics. |

### Coming next

- **M3 (destructive + git):** `rm`, `init`, `reencrypt`, `git` — gated behind `PASS_MCP_ALLOW_DESTRUCTIVE=1`
- **M4 (extensions):** `otp` (if `pass-otp` is installed)

## Configuration

Server-specific env vars:

| Var | Default | Effect |
|---|---|---|
| `PASS_MCP_ALLOW_WRITES` | unset | Required for any mutating tool (M2+) |
| `PASS_MCP_ALLOW_DESTRUCTIVE` | unset | Required for `rm`/`init`/`reencrypt` (M3+) |
| `PASS_MCP_ALLOWED_PATHS` | unset (= all) | Comma-separated fnmatch globs scoping which entries the server may touch |
| `PASS_MCP_REQUIRE_AGENT` | `1` | Refuse to decrypt if `gpg-agent` is not reachable |
| `PASS_MCP_AUDIT_LOG` | `~/.local/state/unix-pass-mcp/audit.log` | Append-only JSONL log of actions; set to empty string to disable |
| `PASS_MCP_TIMEOUT_SECONDS` | `15` | Per-call subprocess timeout |

Standard `pass` env vars are passed through (`PASSWORD_STORE_DIR`, `PASSWORD_STORE_KEY`, `PASSWORD_STORE_GPG_OPTS`, `PASSWORD_STORE_UMASK`, …). See `.claude/rules/architecture.md` §5 for the full list.

## Security posture

- **No shell.** Every `pass` invocation goes through one chokepoint (`pass_cli.run`) using `subprocess.run` with `shell=False` and an arg list.
- **Strict input validation.** Pass-names match `^[A-Za-z0-9._@-][A-Za-z0-9._@/-]*$`, ≤256 chars, no `..`, no leading `-`, no control chars.
- **Path allowlist.** `PASS_MCP_ALLOWED_PATHS` lets you scope the server to e.g. `"work/*,personal/notes/*"` so an LLM can never reach your banking entries.
- **Sensitive output flagged.** `show` and `show_field` carry `meta.sensitive = true` so MCP hosts can refuse to log/cache.
- **Stderr sanitization.** Anything between `-----BEGIN`/`-----END` markers is stripped before raising errors; output is truncated to 2 KB.
- **Audit log records names only.** Never values, never field contents.
- **Umask honoured.** Defaults to `077`; the server warns if a weaker mask is set.

## Development

```bash
uv run ruff check
uv run ruff format --check
uv run pytest -q tests/unit                  # 106 fast tests
PASS_MCP_INTEGRATION=1 uv run pytest -q tests/integration  # 7 real-GPG tests
```

The integration suite mints a throwaway RSA key in an ephemeral `GNUPGHOME` (1-day expiry, no passphrase) and exercises real `pass`. CI runs both tiers across Python 3.11/3.12/3.13.

## License

MIT
