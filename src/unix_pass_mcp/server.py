"""FastMCP server entry point for unix-pass-mcp.

Tool surface defined in `.claude/rules/architecture.md` §3. M1 ships every
read-only tool. Write/destructive tools land in M2/M3.

Convention for handlers:
    1. validate inputs (security.validate_pass_name / validate_subfolder)
    2. enforce path allowlist (security.assert_path_allowed)
    3. enforce capability gate if mutating (require_writes / require_destructive)
    4. call pass_cli.run_or_raise (or read FS via store)
    5. audit.log on success and error
    6. return structured dict
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import agent, audit, fields, git_cmd, otp, pass_cli, security, store
from .errors import AgentUnavailable, AlreadyExists, NotFound, PassError

mcp = FastMCP(
    name="unix-pass-mcp",
    instructions=(
        "Read/write access to the Unix `pass` password manager. "
        "Write tools refuse unless PASS_MCP_ALLOW_WRITES=1; destructive tools "
        "additionally require PASS_MCP_ALLOW_DESTRUCTIVE=1. Call `store_info` "
        "first to confirm the store is reachable and gpg-agent is running."
    ),
)


# ── helpers ──────────────────────────────────────────────────────────────────


def _require_agent_if_configured() -> None:
    """gpg-agent preflight. Skipped if PASS_MCP_REQUIRE_AGENT=0."""
    if os.environ.get("PASS_MCP_REQUIRE_AGENT", "1").strip() in {"0", "false", "no", "off"}:
        return
    if not pass_cli.gpg_agent_available():
        raise AgentUnavailable(
            "gpg-agent is not running; start it (e.g. `gpg-connect-agent /bye`) "
            "or set PASS_MCP_REQUIRE_AGENT=0 to disable this check"
        )


def _decrypt(name: str) -> fields.ParsedEntry:
    """Validate name, decrypt via `pass show`, return parsed entry.

    Raises PassError on any failure; caller is responsible for audit logging.
    """
    security.validate_pass_name(name)
    security.assert_path_allowed(name)
    _require_agent_if_configured()
    result = pass_cli.run_or_raise(["show", name])
    return fields.parse(result.stdout)


# ── tools ────────────────────────────────────────────────────────────────────


@mcp.tool(
    name="store_info",
    description=(
        "Inspect the configured password store without decrypting anything. "
        "Returns store path, recipient keys per subdirectory (from .gpg-id files), "
        "git/agent/signing status, and any configuration warnings. "
        "Call this first to confirm the store is reachable and healthy."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
)
def store_info() -> dict[str, Any]:
    info = store.collect()
    return asdict(info)


@mcp.tool(
    name="list",
    description=(
        "List all pass-names (entries) in the store, optionally scoped to a subfolder. "
        "Returns a flat sorted list of names without the .gpg suffix. Does not decrypt."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
)
def list_entries(subfolder: str | None = None) -> dict[str, Any]:
    sub = security.validate_subfolder(subfolder)
    names = store.list_names(sub)
    audit.log("list", name=sub, count=len(names))
    return {"names": names, "count": len(names), "subfolder": sub}


@mcp.tool(
    name="find",
    description=(
        "Find pass-names whose leaf name contains `query` (case-insensitive substring). "
        "Mirrors `pass find`. Does not decrypt."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
)
def find_entries(query: str, subfolder: str | None = None) -> dict[str, Any]:
    if not isinstance(query, str) or not query:
        return {"names": [], "count": 0, "query": query}
    sub = security.validate_subfolder(subfolder)
    names = store.find_names(query, sub)
    audit.log("find", name=sub, query=query, count=len(names))
    return {"names": names, "count": len(names), "query": query, "subfolder": sub}


@mcp.tool(
    name="show",
    description=(
        "Decrypt and return the password (line 1) for a pass-name. "
        "Pass `line` to return a different line (1-indexed). The returned `value` is "
        "sensitive; clients should not log or cache it."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    meta={"sensitive": True},
)
def show(name: str, line: int = 1) -> dict[str, Any]:
    if not isinstance(line, int) or line < 1:
        raise PassError("`line` must be a positive integer", code="invalid_argument")
    try:
        entry = _decrypt(name)
        all_lines = [entry.password, *entry.lines]
        if line > len(all_lines):
            raise NotFound(f"entry has only {len(all_lines)} line(s)")
        audit.log("show", name=name, line=line)
        return {"value": all_lines[line - 1], "line": line, "sensitive": True}
    except PassError as exc:
        audit.log("show", name=name, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="show_field",
    description=(
        "Decrypt the entry and return one named metadata field "
        "(e.g. `URL`, `Username`, `otpauth`). Field lookup is case-insensitive. "
        "Returns null `value` if the field is absent. The password line is never returned."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    meta={"sensitive": True},
)
def show_field(name: str, field: str) -> dict[str, Any]:
    if not isinstance(field, str) or not field:
        raise PassError("`field` must be a non-empty string", code="invalid_argument")
    try:
        entry = _decrypt(name)
        value = entry.get_field(field)
        audit.log("show_field", name=name, field=field, present=value is not None)
        return {"field": field, "value": value, "present": value is not None, "sensitive": True}
    except PassError as exc:
        audit.log("show_field", name=name, field=field, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="unlock_agent",
    description=(
        "Warm gpg-agent's secret-key cache by popping a desktop password dialog "
        "(zenity / kdialog) and decrypting one entry via loopback pinentry. After "
        "this succeeds, subsequent `show` calls work without TTY-bound pinentry "
        "until the agent's cache TTL expires (default 600s, set via `default-cache-ttl` "
        "in ~/.gnupg/gpg-agent.conf). Use this when `store_info` reports "
        "pinentry-curses + no controlling TTY. The passphrase travels: "
        "desktop dialog → our process → gpg stdin. The LLM never sees it. "
        "Optional `target` is a pass-name to decrypt against — useful when the "
        "store has multiple `.gpg-id` recipients and you want to warm a "
        "specific key. If omitted, the smallest in-scope entry is used."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True),
)
def unlock_agent(target: str | None = None) -> dict[str, object]:
    agent.require_agent_running()
    info = store.collect()
    has_display = info.pinentry is not None and info.pinentry.has_display
    target_path: Path | None = None
    if target is not None:
        security.validate_pass_name(target)
        security.assert_path_allowed(target)
        target_path = store.resolve_store_dir() / f"{target}.gpg"
        if not target_path.is_file():
            raise NotFound(f"entry {target!r} does not exist")
    try:
        result = agent.unlock(
            has_display=has_display,
            target=target_path,
            name_allowed=security.path_allowed,
        )
    except PassError as exc:
        audit.log("unlock_agent", ok=False, error=exc.code, target=target)
        raise
    audit.log("unlock_agent", ok=bool(result.get("ok")), target=target)
    return result


@mcp.tool(
    name="show_metadata",
    description=(
        "Decrypt the entry but return only its non-sensitive shape: which metadata "
        "fields exist (with their values), whether a password is present, and the "
        "raw line count. Useful to inspect entry structure without surfacing the password."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
)
def show_metadata(name: str) -> dict[str, Any]:
    try:
        entry = _decrypt(name)
        view = fields.metadata_view(entry)
        audit.log("show_metadata", name=name)
        return {"name": name, **view}
    except PassError as exc:
        audit.log("show_metadata", name=name, ok=False, error=exc.code)
        raise


# ── write tools (gated by PASS_MCP_ALLOW_WRITES=1) ──────────────────────────


_MAX_BODY_BYTES = 64 * 1024  # 64 KiB; pass entries larger than this are pathological


def _validate_body(body: str, *, allow_newlines: bool) -> None:
    if not isinstance(body, str):
        raise PassError("body must be a string", code="invalid_argument")
    if "\x00" in body:
        raise PassError("body contains NUL byte", code="invalid_argument")
    if not allow_newlines and ("\n" in body or "\r" in body):
        raise PassError(
            "single-line value must not contain newlines; use insert_multiline instead",
            code="invalid_argument",
        )
    if len(body.encode("utf-8")) > _MAX_BODY_BYTES:
        raise PassError(
            f"body exceeds {_MAX_BODY_BYTES} bytes",
            code="invalid_argument",
        )


def _insert_via_stdin(name: str, body: str, *, multiline: bool, force: bool) -> None:
    """Centralized writer. Always uses --echo (no double prompt) or --multiline.

    Pre-checks for existence when force=False so we never trigger pass's
    interactive overwrite prompt on a TTY-less server.
    """
    if not force and store.entry_exists(name):
        raise AlreadyExists(f"{name} already exists; pass force=true to overwrite")
    args = ["insert"]
    if multiline:
        args.append("--multiline")
    else:
        args.append("--echo")
    if force:
        args.append("--force")
    args.append(name)
    # `pass insert --echo` reads exactly one line from stdin; we send the
    # password followed by a single newline. `--multiline` reads until EOF.
    stdin = body if multiline else (body + "\n")
    pass_cli.run_or_raise(args, stdin=stdin)


@mcp.tool(
    name="insert",
    description=(
        "Create or overwrite a single-line entry. The password is passed via stdin "
        "(never argv) so it never appears in /proc/<pid>/cmdline. Refuses if the "
        "entry exists unless `force=true`. Requires PASS_MCP_ALLOW_WRITES=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False),
)
def insert(name: str, password: str, force: bool = False) -> dict[str, Any]:
    security.require_writes()
    security.validate_pass_name(name)
    security.assert_path_allowed(name)
    _validate_body(password, allow_newlines=False)
    try:
        _insert_via_stdin(name, password, multiline=False, force=force)
        audit.log("insert", name=name, force=force)
        return {"name": name, "ok": True}
    except PassError as exc:
        audit.log("insert", name=name, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="insert_multiline",
    description=(
        "Create or overwrite a multi-line entry. Line 1 is the password; subsequent "
        "lines should follow `Key: value` convention (URL, Username, otpauth, …). "
        "Body is passed via stdin. Refuses if the entry exists unless `force=true`. "
        "Requires PASS_MCP_ALLOW_WRITES=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False),
)
def insert_multiline(name: str, body: str, force: bool = False) -> dict[str, Any]:
    security.require_writes()
    security.validate_pass_name(name)
    security.assert_path_allowed(name)
    _validate_body(body, allow_newlines=True)
    if not body.endswith("\n"):
        body = body + "\n"
    try:
        _insert_via_stdin(name, body, multiline=True, force=force)
        audit.log("insert_multiline", name=name, force=force, bytes=len(body))
        return {"name": name, "ok": True, "bytes": len(body)}
    except PassError as exc:
        audit.log("insert_multiline", name=name, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="set_field",
    description=(
        "Set or update one `Key: value` metadata field on an existing entry, "
        "preserving the password and all other lines. Field lookup is case-insensitive; "
        "existing case is preserved on update, new fields are appended in the requested "
        "case. Refuses if the entry does not exist (use `insert_multiline` to create). "
        "Pass `simulate=true` to compute the would-be body without writing — useful for "
        "agent dry-runs. Requires PASS_MCP_ALLOW_WRITES=1 (also for simulate)."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True),
)
def set_field(name: str, field: str, value: str, simulate: bool = False) -> dict[str, Any]:
    security.require_writes()
    if not isinstance(field, str) or not field:
        raise PassError("`field` must be a non-empty string", code="invalid_argument")
    _validate_body(value, allow_newlines=False)
    try:
        entry = _decrypt(name)  # also validates name + path
        before_body = fields.serialize(entry)
        entry.set_field(field, value)
        body = fields.serialize(entry)
        if simulate:
            audit.log("set_field", name=name, field=field, simulated=True)
            return {
                "name": name,
                "field": field,
                "simulated": True,
                "ok": True,
                "fields_count": len(entry.fields),
                "before": before_body,
                "after": body,
                "changed": before_body != body,
                "sensitive": True,
            }
        _insert_via_stdin(name, body, multiline=True, force=True)
        audit.log("set_field", name=name, field=field)
        return {"name": name, "field": field, "ok": True, "fields_count": len(entry.fields)}
    except ValueError as exc:
        audit.log("set_field", name=name, field=field, ok=False, error="invalid_argument")
        raise PassError(str(exc), code="invalid_argument") from exc
    except PassError as exc:
        audit.log("set_field", name=name, field=field, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="unset_field",
    description=(
        "Remove all lines matching `field` (case-insensitive) from an existing entry, "
        "preserving the password and all other lines. No-op if the field is absent. "
        "Pass `simulate=true` for a dry-run. Requires PASS_MCP_ALLOW_WRITES=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True),
)
def unset_field(name: str, field: str, simulate: bool = False) -> dict[str, Any]:
    security.require_writes()
    if not isinstance(field, str) or not field:
        raise PassError("`field` must be a non-empty string", code="invalid_argument")
    try:
        entry = _decrypt(name)
        before_body = fields.serialize(entry)
        removed = entry.unset_field(field)
        if simulate:
            after_body = fields.serialize(entry)
            audit.log("unset_field", name=name, field=field, simulated=True, removed=removed)
            return {
                "name": name,
                "field": field,
                "simulated": True,
                "removed": removed,
                "before": before_body,
                "after": after_body,
                "changed": before_body != after_body,
                "sensitive": True,
            }
        if not removed:
            audit.log("unset_field", name=name, field=field, removed=False)
            return {"name": name, "field": field, "removed": False}
        body = fields.serialize(entry)
        _insert_via_stdin(name, body, multiline=True, force=True)
        audit.log("unset_field", name=name, field=field, removed=True)
        return {"name": name, "field": field, "removed": True}
    except PassError as exc:
        audit.log("unset_field", name=name, field=field, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="generate",
    description=(
        "Generate a new password for `name`. `length` defaults to PASSWORD_STORE_GENERATED_LENGTH "
        "(or 25). `no_symbols=true` restricts to alphanumerics. `in_place=true` replaces only "
        "the first line of an existing entry (preserving metadata) and needs the entry to exist. "
        "`force=true` overwrites any existing entry from scratch. Without either flag, refuses if "
        "the entry already exists. Returns the generated password (sensitive). "
        "Requires PASS_MCP_ALLOW_WRITES=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False),
    meta={"sensitive": True},
)
def generate(
    name: str,
    length: int = 25,
    no_symbols: bool = False,
    in_place: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    security.require_writes()
    security.validate_pass_name(name)
    security.assert_path_allowed(name)
    if not isinstance(length, int) or length < 1 or length > 1024:
        raise PassError("`length` must be an integer between 1 and 1024", code="invalid_argument")
    if in_place and force:
        raise PassError("`in_place` and `force` are mutually exclusive", code="invalid_argument")

    exists = store.entry_exists(name)
    if in_place and not exists:
        raise NotFound(f"{name} does not exist; cannot use in_place=true on a missing entry")
    if not in_place and not force and exists:
        raise AlreadyExists(f"{name} already exists; pass force=true or in_place=true")

    args = ["generate"]
    if no_symbols:
        args.append("--no-symbols")
    if in_place:
        args.append("--in-place")
    elif force:
        args.append("--force")
    args.append(name)
    args.append(str(length))

    try:
        pass_cli.run_or_raise(args)
        # Re-decrypt to retrieve the value rather than parsing pass's stdout
        # (which is locale/colorization-sensitive).
        entry = _decrypt(name)
        audit.log("generate", name=name, length=length, no_symbols=no_symbols, in_place=in_place)
        return {
            "name": name,
            "value": entry.password,
            "length": len(entry.password),
            "no_symbols": no_symbols,
            "in_place": in_place,
            "sensitive": True,
        }
    except PassError as exc:
        audit.log("generate", name=name, ok=False, error=exc.code)
        raise


# ── OTP / TOTP ───────────────────────────────────────────────────────────────


@mcp.tool(
    name="otp",
    description=(
        "Compute the current TOTP code for an entry containing an `otpauth://` line "
        "(pass-otp / browserpass convention). Returns the code plus `seconds_remaining` "
        "in the current window — if it's very low (<5s), wait for the next window before "
        "submitting. Marked sensitive."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True),
    meta={"sensitive": True},
)
def otp_tool(name: str) -> dict[str, Any]:
    try:
        entry = _decrypt(name)
        uri = entry.get_otpauth_uri()
        if uri is None:
            raise PassError(
                f"{name} has no otpauth:// line; use otp_set to add one",
                code="no_otpauth",
            )
        params = otp.parse_otpauth_uri(uri)
        result = otp.compute_totp(params)
        audit.log("otp", name=name, period=result.period, digits=result.digits)
        return {
            "code": result.code,
            "seconds_remaining": result.seconds_remaining,
            "period": result.period,
            "digits": result.digits,
            "algorithm": result.algorithm,
            "issuer": result.issuer,
            "account": result.account,
            "sensitive": True,
        }
    except PassError as exc:
        audit.log("otp", name=name, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="otp_uri",
    description=(
        "Return the raw `otpauth://` URI stored on the entry (contains the secret). "
        "Use this only when you need to re-enroll the same secret elsewhere; for "
        "submitting a code, prefer `otp`. Marked sensitive."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    meta={"sensitive": True},
)
def otp_uri(name: str) -> dict[str, Any]:
    try:
        entry = _decrypt(name)
        uri = entry.get_otpauth_uri()
        if uri is None:
            raise PassError(f"{name} has no otpauth:// line", code="no_otpauth")
        # Validate before handing back so we never echo a malformed URI.
        otp.parse_otpauth_uri(uri)
        audit.log("otp_uri", name=name)
        return {"name": name, "uri": uri, "sensitive": True}
    except PassError as exc:
        audit.log("otp_uri", name=name, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="otp_set",
    description=(
        "Add or replace the `otpauth://` URI on an existing entry, preserving the "
        "password and all other lines. The URI is validated before write. Refuses if "
        "the entry does not exist (use `insert` first). Requires PASS_MCP_ALLOW_WRITES=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True),
)
def otp_set(name: str, uri: str) -> dict[str, Any]:
    security.require_writes()
    if not isinstance(uri, str) or not uri:
        raise PassError("`uri` must be a non-empty string", code="invalid_argument")
    # Validate before decrypting so a bad URI fails fast without an audit
    # log entry that could be confused with a successful write.
    otp.parse_otpauth_uri(uri)
    try:
        entry = _decrypt(name)
        replaced = entry.set_otpauth_uri(uri.strip())
        body = fields.serialize(entry)
        _insert_via_stdin(name, body, multiline=True, force=True)
        audit.log("otp_set", name=name, replaced=replaced)
        return {"name": name, "ok": True, "replaced": replaced}
    except ValueError as exc:
        audit.log("otp_set", name=name, ok=False, error="invalid_argument")
        raise PassError(str(exc), code="invalid_argument") from exc
    except PassError as exc:
        audit.log("otp_set", name=name, ok=False, error=exc.code)
        raise


def _move_or_copy(action: str, src: str, dst: str, *, force: bool) -> dict[str, Any]:
    security.require_writes()
    security.validate_pass_name(src)
    security.validate_pass_name(dst)
    security.assert_path_allowed(src)
    security.assert_path_allowed(dst)
    if not store.entry_exists(src) and not store.directory_exists(src):
        raise NotFound(f"{src} does not exist")
    # Pre-check: pass mv/cp prompts on overwrite without --force; that would
    # hang us. Refuse cleanly if the destination is taken and force=False.
    if not force and (store.entry_exists(dst) or store.directory_exists(dst)):
        raise AlreadyExists(f"{dst} already exists; pass force=true to overwrite")
    args = [action]
    if force:
        args.append("--force")
    args.extend([src, dst])
    try:
        pass_cli.run_or_raise(args)
        audit.log(action, name=src, dst=dst, force=force)
        return {"src": src, "dst": dst, "ok": True}
    except PassError as exc:
        audit.log(action, name=src, dst=dst, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="mv",
    description=(
        "Rename or move an entry/subfolder. Re-encrypts to the destination subfolder's "
        "recipients if they differ. Refuses if the destination exists unless `force=true`. "
        "Requires PASS_MCP_ALLOW_WRITES=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False),
)
def mv(src: str, dst: str, force: bool = False) -> dict[str, Any]:
    return _move_or_copy("mv", src, dst, force=force)


@mcp.tool(
    name="cp",
    description=(
        "Copy an entry/subfolder. Re-encrypts to the destination subfolder's recipients "
        "if they differ. Refuses if the destination exists unless `force=true`. "
        "Requires PASS_MCP_ALLOW_WRITES=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False),
)
def cp(src: str, dst: str, force: bool = False) -> dict[str, Any]:
    return _move_or_copy("cp", src, dst, force=force)


# ── grep (slow, opt-in) ──────────────────────────────────────────────────────


# `pass grep` (see /usr/bin/pass cmd_grep) always emits header lines via
#     printf "\e[94m%s\e[1m%s\e[0m:\n" "<dir/>" "<leaf>"
# i.e. ANSI-coloured "blue dir, bold leaf, reset, colon, newline". It also
# pipes the body through `grep --color=always`, which wraps matched substrings
# in further escape sequences. We can't disable either: the colour flags are
# hard-coded in the pass shell script. So:
#   * recognise the colour envelope as the header marker (deterministic — content
#     lines never start with \e[94m followed by \e[0m:),
#   * strip ANSI from content lines before handing them back to the agent,
#   * also accept the bare "<name>:" form so tests/fixtures don't have to embed
#     escape sequences.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_COLOR_HEADER_RE = re.compile(r"^\x1b\[94m(.*?)\x1b\[1m(.*?)\x1b\[0m:$")
_BARE_HEADER_RE = re.compile(r"^([A-Za-z0-9._@\-][A-Za-z0-9._@/\-]*):$")


def _parse_grep_output(text: str) -> list[dict[str, str]]:
    """Parse `pass grep` stdout into [{name, line}, ...].

    pass-grep output structure:
        <ANSI><dir/><ANSI><leaf><ANSI>:
        <matched line, possibly with ANSI escapes from grep --color=always>
        [more matched lines...]
        <next header>
        ...
    """
    out: list[dict[str, str]] = []
    current: str | None = None
    for raw in text.splitlines():
        if not raw:
            continue
        color_match = _COLOR_HEADER_RE.match(raw)
        if color_match:
            current = color_match.group(1) + color_match.group(2)
            continue
        bare_match = _BARE_HEADER_RE.match(raw)
        if bare_match and current != bare_match.group(1):
            # Bare-form header. The `current` guard avoids promoting a content
            # line that happens to be a duplicate of the most recent header.
            current = bare_match.group(1)
            continue
        if current is not None:
            out.append({"name": current, "line": _ANSI_RE.sub("", raw)})
    return out


@mcp.tool(
    name="grep",
    description=(
        "Search inside the decrypted body of every entry for a regex pattern. "
        "**Slow and expensive** — decrypts the entire store, warming many secret "
        "keys in gpg-agent's cache. Caller must pass `confirm_decrypt_all=true` "
        "to acknowledge. Returns matched lines (sensitive — they're decrypted "
        "content). Honours PASS_MCP_GREP_TIMEOUT_SECONDS (default 120s)."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True),
    meta={"sensitive": True},
)
def grep(
    pattern: str, confirm_decrypt_all: bool = False, case_insensitive: bool = False
) -> dict[str, Any]:
    if not isinstance(pattern, str) or not pattern:
        raise PassError("`pattern` must be a non-empty string", code="invalid_argument")
    if len(pattern) > 256:
        raise PassError("`pattern` longer than 256 chars", code="invalid_argument")
    if not confirm_decrypt_all:
        raise PassError(
            "grep decrypts every entry in the store. Pass confirm_decrypt_all=true "
            "to acknowledge the cost (gpg-agent will cache secret keys for entries "
            "you might not have intended to access).",
            code="confirmation_required",
        )
    _require_agent_if_configured()
    timeout = float(os.environ.get("PASS_MCP_GREP_TIMEOUT_SECONDS", "120"))
    args: list[str] = ["grep"]
    if case_insensitive:
        args.append("-i")
    args.append(pattern)
    try:
        # Force no color so our parser doesn't see ANSI escapes.
        result = pass_cli.run_or_raise(args, timeout=timeout)
        raw_matches = _parse_grep_output(result.stdout)
        # Honour PASS_MCP_ALLOWED_PATHS even though `pass grep` itself ignores
        # it. Without this, an LLM scoped to `web/*` could call grep and read
        # decrypted lines from `personal/banking/*`.
        if security.allowlist_active():
            matches = [m for m in raw_matches if security.path_allowed(m["name"])]
            redacted_entries = len({m["name"] for m in raw_matches} - {m["name"] for m in matches})
        else:
            matches = raw_matches
            redacted_entries = 0
        audit.log(
            "grep",
            pattern_len=len(pattern),
            match_count=len(matches),
            redacted_entries=redacted_entries,
        )
        return {
            "matches": matches,
            "count": len(matches),
            "pattern": pattern,
            "case_insensitive": case_insensitive,
            "redacted_entries": redacted_entries,
            "sensitive": True,
        }
    except PassError as exc:
        audit.log("grep", ok=False, error=exc.code)
        raise


# ── git tools ────────────────────────────────────────────────────────────────


@mcp.tool(
    name="git_status",
    description=(
        "Inspect git state of the password store. Returns whether the working "
        "tree is clean, current branch, upstream, ahead/behind counts, and any "
        "dirty paths. Refuses if the store is not a git repository (run "
        "`pass git init` first)."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True),
)
def git_status() -> dict[str, Any]:
    try:
        info = git_cmd.status()
        audit.log("git_status", clean=info.clean, ahead=info.ahead, behind=info.behind)
        return asdict(info)
    except PassError as exc:
        audit.log("git_status", ok=False, error=exc.code)
        raise


@mcp.tool(
    name="git_log",
    description=(
        "Return recent commits in the password store as `[{hash, subject}, ...]`. "
        "`limit` defaults to 20 (max 200). Useful for auditing what changed and when."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True),
)
def git_log(limit: int = 20) -> dict[str, Any]:
    try:
        commits = git_cmd.log(limit=limit)
        audit.log("git_log", count=len(commits))
        return {"commits": commits, "count": len(commits)}
    except PassError as exc:
        audit.log("git_log", ok=False, error=exc.code)
        raise


@mcp.tool(
    name="git_pull",
    description=(
        "Sync remote commits into the local store via `git pull --ff-only` (no merge "
        "commits, no rebase — refuses if local has diverged). Requires "
        "PASS_MCP_ALLOW_NETWORK=1 because it reaches out to a remote. Returns "
        "`{ok, output, stderr}`. On failure the agent should call `git_status` to "
        "diagnose."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False),
)
def git_pull() -> dict[str, Any]:
    security.require_network()
    try:
        result = git_cmd.pull()
        audit.log("git_pull", ok=result.ok)
        return asdict(result)
    except PassError as exc:
        audit.log("git_pull", ok=False, error=exc.code)
        raise


@mcp.tool(
    name="git_push",
    description=(
        "Push local commits to the configured upstream. Requires "
        "PASS_MCP_ALLOW_NETWORK=1. Returns `{ok, output, stderr}`. Does not force-push."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True),
)
def git_push() -> dict[str, Any]:
    security.require_network()
    try:
        result = git_cmd.push()
        audit.log("git_push", ok=result.ok)
        return asdict(result)
    except PassError as exc:
        audit.log("git_push", ok=False, error=exc.code)
        raise


def _strict_startup_checks() -> None:
    """Refuse to start under demonstrably-unsafe conditions.

    Bypass with `PASS_MCP_ALLOW_UNSAFE=1` (do not). The bypass exists so an
    operator can recover a misconfigured store via the MCP — not for steady-
    state use. Architecture §6.7.
    """
    import sys

    if security._env_flag("PASS_MCP_ALLOW_UNSAFE"):
        return
    store_dir = store.resolve_store_dir()
    if store_dir.exists() and store._world_readable(store_dir):
        sys.stderr.write(
            f"unix-pass-mcp: refusing to start: store directory {store_dir} is "
            f"world-accessible (mode bits o+rwx).\n"
            f"  Fix: `chmod -R go-rwx {store_dir}`, or bypass with "
            f"PASS_MCP_ALLOW_UNSAFE=1.\n"
        )
        sys.exit(2)
    umask = os.environ.get("PASSWORD_STORE_UMASK", "077")
    if not store._is_at_least_077(umask):
        sys.stderr.write(
            f"unix-pass-mcp: refusing to start: PASSWORD_STORE_UMASK={umask!r} "
            f"is weaker than 077; new files would be readable by group/other.\n"
            f"  Fix: `unset PASSWORD_STORE_UMASK` (defaults to 077), or bypass "
            f"with PASS_MCP_ALLOW_UNSAFE=1.\n"
        )
        sys.exit(2)


# Positive allowlist for gpg-id values. Real recipients fall into one of:
#   - 40-char fingerprint (hex)               D85F E022 9E97 ... (with/without spaces)
#   - 8/16-char short / long key ID (hex)     DEADBEEF, DEADBEEFDEADBEEF, 0xDEADBEEF
#   - email                                   alice+ops@example.com
#   - free-form user-id substring             "Alice Smith"
# A whitelist beats a denylist here: previously we tried to enumerate shell
# metacharacters, which is fragile (forget one and you have an injection).
# subprocess is invoked with shell=False so this is defence-in-depth — the
# allowlist exists to reject typo-class garbage cleanly with `invalid_argument`
# instead of letting `gpg` complain about an unknown recipient.
_VALID_GPG_ID = re.compile(r"^[A-Za-z0-9._@+\- ]+$")


def _validate_gpg_id(gpg_id: str) -> str:
    if not isinstance(gpg_id, str) or not gpg_id:
        raise PassError("gpg-id must be a non-empty string", code="invalid_argument")
    if len(gpg_id) > 256:
        raise PassError("gpg-id longer than 256 chars", code="invalid_argument")
    if gpg_id.startswith("-"):
        raise PassError(
            "gpg-id may not start with '-' (would be parsed as a flag)",
            code="invalid_argument",
        )
    if not _VALID_GPG_ID.match(gpg_id):
        raise PassError(
            f"gpg-id contains disallowed characters (allowed: letters, digits, "
            f"`. _ @ + -` and space): {gpg_id!r}",
            code="invalid_argument",
        )
    return gpg_id


def _read_subdir_gpg_ids(subfolder: str | None) -> list[str]:
    """Read the `.gpg-id` for the given (sub)folder. Empty list if missing."""
    base = store.resolve_store_dir()
    target = base / subfolder / ".gpg-id" if subfolder else base / ".gpg-id"
    if not target.is_file():
        return []
    text = target.read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


@mcp.tool(
    name="init",
    description=(
        "Initialize the password store (or a subfolder) with the given GPG recipient(s). "
        "Re-encrypts every existing entry in scope to the new recipient set — this is "
        "DESTRUCTIVE. Pass an empty `gpg_ids` list to remove the .gpg-id file for the "
        "subfolder (entries inherit the parent's recipients). "
        "Refuses if the user has no secret key for any of the new recipients (would lock "
        "the user out); pass `force=true` to override (e.g. team scenarios where you're "
        "delegating access). Requires PASS_MCP_ALLOW_DESTRUCTIVE=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
)
def init(gpg_ids: list[str], subfolder: str | None = None, force: bool = False) -> dict[str, Any]:
    security.require_destructive()
    sub = security.validate_subfolder(subfolder)
    if not isinstance(gpg_ids, list):
        raise PassError("`gpg_ids` must be a list of strings", code="invalid_argument")

    # Empty list = remove the .gpg-id (per pass(1): single empty-string id removes it).
    if len(gpg_ids) == 0:
        if sub is None:
            raise PassError(
                "cannot remove the root .gpg-id (would leave the store unencryptable); "
                "specify a subfolder",
                code="invalid_argument",
            )
        args = ["init", "--path", sub, ""]
        try:
            pass_cli.run_or_raise(args)
            audit.log("init", subfolder=sub, removed=True)
            return {"subfolder": sub, "ok": True, "removed": True, "gpg_ids": []}
        except PassError as exc:
            audit.log("init", subfolder=sub, ok=False, error=exc.code)
            raise

    validated = [_validate_gpg_id(gid) for gid in gpg_ids]
    if not force and not any(pass_cli.gpg_has_secret_key(gid) for gid in validated):
        raise PassError(
            f"none of the given gpg-ids have a secret key on this machine: "
            f"{validated!r}. Re-encrypting would lock you out of the store. "
            f"Pass force=true if this is intentional (e.g. delegating to a team).",
            code="would_lock_out",
        )

    args = ["init"]
    if sub is not None:
        args.extend(["--path", sub])
    args.extend(validated)
    try:
        pass_cli.run_or_raise(args, timeout=120.0)  # re-encryption can take a while
        audit.log(
            "init",
            subfolder=sub,
            recipient_count=len(validated),
            forced=force,
        )
        return {"subfolder": sub, "ok": True, "gpg_ids": validated}
    except PassError as exc:
        audit.log("init", subfolder=sub, ok=False, error=exc.code)
        raise


@mcp.tool(
    name="reencrypt",
    description=(
        "Re-run `pass init` against the *current* `.gpg-id` recipients (no key change). "
        "Use after subkey rotation or to repair a store where some files are "
        "encrypted to outdated recipients. Note: `pass init` is a no-op when each "
        "file's existing recipients already match the .gpg-id — there is no way to "
        "force a fresh ciphertext without changing the recipient set. "
        "Requires PASS_MCP_ALLOW_DESTRUCTIVE=1."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True),
)
def reencrypt(subfolder: str | None = None) -> dict[str, Any]:
    security.require_destructive()
    sub = security.validate_subfolder(subfolder)
    current = _read_subdir_gpg_ids(sub)
    if not current:
        raise NotFound(f"no .gpg-id at {('root' if sub is None else sub)!r}; cannot reencrypt")
    # Re-use init's safety checks (won't raise would_lock_out since current ids
    # are by definition the ones we used to read the store).
    return init(current, subfolder=sub, force=False)


def main() -> None:
    _strict_startup_checks()
    mcp.run("stdio")


if __name__ == "__main__":
    main()
