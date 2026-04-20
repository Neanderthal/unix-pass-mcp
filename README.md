<div align="center">

```
██╗   ██╗███╗   ██╗██╗██╗  ██╗    ██████╗  █████╗ ███████╗███████╗    ███╗   ███╗ ██████╗██████╗
██║   ██║████╗  ██║██║╚██╗██╔╝    ██╔══██╗██╔══██╗██╔════╝██╔════╝    ████╗ ████║██╔════╝██╔══██╗
██║   ██║██╔██╗ ██║██║ ╚███╔╝     ██████╔╝███████║███████╗███████╗    ██╔████╔██║██║     ██████╔╝
██║   ██║██║╚██╗██║██║ ██╔██╗     ██╔═══╝ ██╔══██║╚════██║╚════██║    ██║╚██╔╝██║██║     ██╔═══╝
╚██████╔╝██║ ╚████║██║██╔╝ ██╗    ██║     ██║  ██║███████║███████║    ██║ ╚═╝ ██║╚██████╗██║
 ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝     ╚═╝ ╚═════╝╚═╝
```

**The Unix [`pass`](https://www.passwordstore.org/) password manager — exposed over the Model Context Protocol.**

Read-only by default. Writes, key administration, and network ops behind explicit env opt-ins.
Single-chokepoint subprocess. Strict input validation. No shell, no clipboard, no secrets in logs.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![MCP 1.21](https://img.shields.io/badge/MCP-1.21-purple)
![Tests: 346 unit + 45 integration](https://img.shields.io/badge/tests-346%20unit%20%2B%2045%20integration-brightgreen)

</div>

---

> **Status — M5 complete.** Read · safe-write · key administration · TOTP/OTP · git · hardening surfaces all shipped.
> **24 tools, 346 unit tests + 45 real-GPG integration tests, all green.**
> Distribution (M6) is next on the [roadmap](./ROADMAP.md).

## Table of contents

- [Why this exists](#why-this-exists)
- [Quickstart](#quickstart)
- [Requirements](#requirements)
- [Install](#install)
- [Wire into an MCP host](#wire-into-an-mcp-host)
- [Tools](#tools)
- [Configuration](#configuration)
- [Security posture](#security-posture)
- [Development](#development)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Why this exists

`pass` is a thin wrapper around `gpg(1)` and the filesystem. Anything that can shell out can use it — but exposing it raw to an LLM is a recipe for `rm -rf` regret. This server provides:

- A typed **MCP surface** over the safe subset of `pass`.
- **Read-only by default**; writes and destructive ops behind explicit env opt-ins.
- **Strict input validation** — no shell, no path escapes, no stdin smuggling of secrets.
- **Sanitized error output**, append-only audit log, and gpg-agent preflight.

See [`.claude/rules/architecture.md`](./.claude/rules/architecture.md) for the full design and security model.

---

## Quickstart

```bash
# 1. Install
uv pip install .

# 2. Run (speaks MCP over stdio)
uv run unix-pass-mcp

# 3. Wire into Claude Code
claude mcp add pass -- uv run --directory /absolute/path/to/unix-pass-mcp unix-pass-mcp
```

That gets you the **read-only** surface. To enable mutations:

```bash
PASS_MCP_ALLOW_WRITES=1 \
PASS_MCP_ALLOWED_PATHS=web/* \
uv run unix-pass-mcp
```

---

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

### Pinentry — pick one

The server can never serve an interactive passphrase prompt itself — `pass`/`gpg` will hang. You need **one** of:

1. A **GUI pinentry** configured in `~/.gnupg/gpg-agent.conf` — `pinentry-gnome3`, `pinentry-qt`, `pinentry-qt5`, or `pinentry-gtk-2`. The first decrypt of each cache window pops a desktop dialog. *Recommended.*
2. **`zenity` or `kdialog`** installed — call the `unlock_agent` MCP tool once per cache window to warm gpg-agent. Use this if you can't change `gpg-agent.conf`.
3. A **pre-warmed agent** — run `pass show <name>` in a real terminal before talking to the MCP. Cache expires per `default-cache-ttl` (default 600s).

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
| [`pass-otp`](https://github.com/tadfisher/pass-otp) | Cross-tool compatibility for `otp` (the server has a native RFC 6238 implementation, no runtime dependency) |
| `git` | Auto-commit on writes if your store is a git repo, plus `git_status` / `git_log` / `git_pull` / `git_push` |

### Development

| Component | Why |
|---|---|
| [`uv`](https://docs.astral.sh/uv/) | Recommended installer / runner |
| `gpg` with key-generation support | Integration tests mint throwaway keys in an ephemeral `GNUPGHOME` |

---

## Install

```bash
uv sync --extra dev          # for development
uv pip install .             # for use
```

---

## Wire into an MCP host

### Claude Desktop

Add to `~/.config/Claude/claude_desktop_config.json` (or the platform equivalent):

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

### Claude Code

```bash
claude mcp add pass -- uv run --directory /absolute/path/to/unix-pass-mcp unix-pass-mcp
```

### Driving an autonomous agent

For account creation / profile filling workflows that combine `unix-pass-mcp` with a browser-controlling MCP, load [`.claude/rules/agent-workflow.md`](./.claude/rules/agent-workflow.md) into the agent's system prompt. It defines the canonical naming convention (`web/<domain>/<handle>`), body format, and signup/login/rotation loops.

---

## Tools

24 tools, grouped by capability gate.

### Read-only — always available

| Tool | Description |
|---|---|
| `store_info` | Inspect the store: path, recipients per subdir, git/agent/pinentry/signing status, warnings. No decryption. |
| `list` | List pass-names (optionally scoped to a subfolder). No decryption. |
| `find` | Substring search over leaf names. No decryption. |
| `show` | Decrypt and return one line of an entry (default = line 1 = password). Marked sensitive. |
| `show_field` | Decrypt and return one named metadata field (`URL`, `Username`, `otpauth`, …). Case-insensitive. |
| `show_metadata` | Decrypt and return only the entry shape (which fields exist, their values, line count). Password value is never returned. |
| `unlock_agent` | Pop a desktop password dialog (zenity/kdialog) and warm gpg-agent's cache via loopback pinentry. Optional `target` for multi-recipient stores. The LLM never sees the passphrase. |
| `grep` | Search inside the decrypted body of every entry. Slow + costly (decrypts whole store) — requires `confirm_decrypt_all=true`. Marked sensitive. Honours `PASS_MCP_ALLOWED_PATHS`. |
| `otp` | Compute the current TOTP code from an entry's `otpauth://` line. Returns code + `seconds_remaining`. Marked sensitive. Native RFC 6238 — no `pass-otp` runtime dependency. |
| `otp_uri` | Return the raw `otpauth://` URI (contains the secret). Use only when re-enrolling the same secret elsewhere. |

### Writes — gated behind `PASS_MCP_ALLOW_WRITES=1`

| Tool | Description |
|---|---|
| `insert` | Create or overwrite a single-line entry. Password via stdin (never argv). Refuses overwrite without `force=true`. |
| `insert_multiline` | Create or overwrite a full-body entry (line 1 = password, rest = `Key: value` metadata). |
| `set_field` | Update one `Key: value` field; preserves password and other lines. `simulate=true` returns the would-be body without writing. |
| `unset_field` | Remove all lines matching a field key (case-insensitive). No-op if absent. `simulate=true` for dry-run. |
| `generate` | Generate a new password (length 1–1024, optional `no_symbols`). `in_place=true` keeps metadata; `force=true` overwrites everything. Returns the generated value (sensitive). |
| `mv` | Rename or move an entry/subfolder. Re-encrypts to the destination subfolder's recipients if they differ. |
| `cp` | Copy an entry/subfolder, with the same re-encryption semantics. |
| `otp_set` | Append or replace the `otpauth://` URI on an existing entry. Validates the URI before writing. |

### Git — `git_status` and `git_log` always; `git_pull` and `git_push` need `PASS_MCP_ALLOW_NETWORK=1`

| Tool | Description |
|---|---|
| `git_status` | Structured status: `{clean, branch, upstream, ahead, behind, dirty_files}`. Refuses if the store isn't a git repo. |
| `git_log` | Recent commits as `[{hash, subject}, …]`. `limit` defaults to 20 (max 200). |
| `git_pull` | `git pull --ff-only` — refuses divergence, no merge commits, no rebase. |
| `git_push` | `git push` — never `--force`. |

### Destructive — gated behind `PASS_MCP_ALLOW_DESTRUCTIVE=1`

| Tool | Description |
|---|---|
| `init` | Initialize the store (or a subfolder) with new GPG recipients. Re-encrypts every entry in scope. Refuses if the user has no secret key for any of the new recipients, unless `force=true`. Empty `gpg_ids` list removes a subfolder's `.gpg-id`. |
| `reencrypt` | Re-run `init` with the *current* recipients. Useful after subkey rotation. No-op when recipients haven't changed. |

> Full machine-readable surface — every arg, every error code — lives in [`.claude/rules/api.md`](./.claude/rules/api.md).

---

## Configuration

Server-specific env vars:

| Var | Default | Effect |
|---|---|---|
| `PASS_MCP_ALLOW_WRITES` | unset | Required for any mutating tool |
| `PASS_MCP_ALLOW_DESTRUCTIVE` | unset | Required for `init` / `reencrypt` |
| `PASS_MCP_ALLOW_NETWORK` | unset | Required for `git_pull` / `git_push` |
| `PASS_MCP_ALLOW_UNSAFE` | unset | Bypass strict startup checks (world-readable store, weak umask). **Don't.** |
| `PASS_MCP_ALLOWED_PATHS` | unset (= all) | Comma-separated fnmatch globs scoping which entries the server may touch |
| `PASS_MCP_GREP_TIMEOUT_SECONDS` | `120` | Per-call timeout for `grep` (decrypts whole store) |
| `PASS_MCP_REQUIRE_AGENT` | `1` | Refuse to decrypt if `gpg-agent` is not reachable |
| `PASS_MCP_AUDIT_LOG` | `~/.local/state/unix-pass-mcp/audit.log` | Append-only JSONL log of actions; set to empty string to disable |
| `PASS_MCP_TIMEOUT_SECONDS` | `15` | Per-call subprocess timeout |

Standard `pass` env vars are passed through (`PASSWORD_STORE_DIR`, `PASSWORD_STORE_KEY`, `PASSWORD_STORE_UMASK`, …). See [`.claude/rules/architecture.md`](./.claude/rules/architecture.md) §5 for the full list.

**Not** propagated:
- `PASSWORD_STORE_GPG_OPTS` — lets a hostile env inject `gpg` flags like `--recipient` (silent re-encryption to attacker) or `--output` (decryption exfiltration).
- `PASSWORD_STORE_X_SELECTION`, `PASSWORD_STORE_CLIP_TIME` — clipboard tools dropped (meaningless over MCP).

---

## Security posture

| | |
|---|---|
| **No shell.** | Every `pass` invocation goes through one chokepoint (`pass_cli.run`) using `subprocess.run` with `shell=False` and an arg list. Audited by ruff `S404` allowlist on a single file. |
| **Strict input validation.** | Pass-names match `^[A-Za-z0-9._@-][A-Za-z0-9._@/-]*$`, ≤256 chars, no `..`, no leading `-`, no control chars. gpg-ids match a positive allowlist. |
| **Path allowlist.** | `PASS_MCP_ALLOWED_PATHS` lets you scope the server to e.g. `"work/*,personal/notes/*"` so an LLM can never reach your banking entries. Honoured by `grep` and `unlock_agent` too — no scope escapes. |
| **Sensitive output flagged.** | `show`, `show_field`, `generate`, `otp`, `otp_uri`, `grep`, and simulated field ops carry `meta.sensitive = true` so MCP hosts can refuse to log/cache. |
| **Stderr sanitization.** | Anything between `-----BEGIN`/`-----END` markers is stripped before raising errors; output is truncated to 2 KB. |
| **Audit log records names only.** | Never values, never field contents, never grep patterns. |
| **Stdin isolation.** | Every subprocess runs with `stdin=DEVNULL` unless the caller is actively piping content. Protects FastMCP's stdio JSON-RPC framing from accidental child-process reads. |
| **Strict startup.** | Refuses to start if `PASSWORD_STORE_UMASK` is weaker than `077` or the store dir is world-readable. Bypass with `PASS_MCP_ALLOW_UNSAFE=1` (don't). |

---

## Development

```bash
uv run ruff check
uv run ruff format --check
uv run pytest -q tests/unit                                 # 346 fast tests
PASS_MCP_INTEGRATION=1 uv run pytest -q tests/integration   # 45 real-GPG tests
```

The integration suite mints a throwaway RSA key in an ephemeral `GNUPGHOME` (1-day expiry, no passphrase) and exercises real `pass`. CI runs both tiers across Python 3.11 / 3.12 / 3.13.

---

## Disclaimer

`unix-pass-mcp` is a bridge between your password store and a non-deterministic large language model — and, in most realistic deployments, between your password store and every other MCP server that shares the same model session (browser automation, shell execution, web requests). Even with every gate disabled by default, the *purpose* of installing this server is to grant an LLM access to your secrets. The following are not bugs:

- An LLM **can** be prompted (by you, by a hostile webpage your browser MCP loads, by a poisoned tool result) to decrypt any entry within `PASS_MCP_ALLOWED_PATHS` and forward it to another tool in the same session.
- With `PASS_MCP_ALLOW_WRITES=1`, an LLM can overwrite, rename, or generate-over entries in scope.
- With `PASS_MCP_ALLOW_DESTRUCTIVE=1`, an LLM can re-encrypt your store to a different recipient set, or remove a subfolder's `.gpg-id`.
- With `PASS_MCP_ALLOW_NETWORK=1`, an LLM can push commits — including credential changes — to your configured git remote.

The capability gates, path allowlist, audit log, sensitive-output flags, and validation hardening reduce the **blast radius** of mistakes and prompt injection. They do **not** make it safe to point an unsupervised agent at a production credential store. Treat the security posture documented above as best-effort engineering against a hostile and rapidly-evolving threat model, not a formal guarantee.

You are solely responsible for:

- Which capability gates you enable, and on which stores.
- The trust boundary of the MCP host you run this against — what it logs, caches, ships to telemetry, or lets other servers see.
- Backing up `~/.password-store` (and `~/.gnupg`) before granting destructive or network access.
- Reviewing `~/.local/state/unix-pass-mcp/audit.log` periodically.
- Recovering from any mistake an agent makes — there is no undo.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. THE AUTHORS AND CONTRIBUTORS SHALL NOT BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY — INCLUDING BUT NOT LIMITED TO DATA LOSS, CREDENTIAL COMPROMISE, STORE LOCK-OUT, UNINTENDED DISCLOSURE OF SECRETS, OR LOSS OF SERVICE — WHETHER ARISING FROM BUGS, PROMPT INJECTION, MISCONFIGURATION, OR ANY OTHER USE OR MISUSE OF THE SOFTWARE. See the [LICENSE](./LICENSE) for the full MIT terms.

This project is not affiliated with, endorsed by, or sponsored by Anthropic, the maintainers of `pass(1)` (Jason A. Donenfeld and contributors), the GnuPG project, or any MCP host vendor. All trademarks are the property of their respective owners.

---

## License

MIT — see [LICENSE](./LICENSE).
