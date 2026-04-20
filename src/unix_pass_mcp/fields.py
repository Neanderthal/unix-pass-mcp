"""Parse and serialize the canonical `pass` multi-line body format.

Line 1 is the password (opaque). Subsequent lines may be `Key: value` fields,
freeform text, or empty. Round-trip-safe: parse → serialize yields byte-equal
output for any entry we produced ourselves, and preserves unknown lines for
anything hand-authored.

See architecture §7 for the conventions (browserpass / pass-git-helper
compatible).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FIELD_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9_\-]*):\s?(.*)$")


@dataclass
class ParsedEntry:
    password: str
    lines: list[str] = field(default_factory=list)

    # Derived views ----------------------------------------------------------

    @property
    def fields(self) -> dict[str, str]:
        """Case-insensitive view: last occurrence wins (matches `pass` behavior)."""
        out: dict[str, str] = {}
        seen_ci: dict[str, str] = {}
        for line in self.lines:
            match = _FIELD_LINE.match(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2)
            canonical = seen_ci.setdefault(key.lower(), key)
            out[canonical] = value
        return out

    # Mutators ---------------------------------------------------------------

    def get_field(self, key: str) -> str | None:
        target = key.lower()
        value: str | None = None
        for line in self.lines:
            match = _FIELD_LINE.match(line)
            if match and match.group(1).lower() == target:
                value = match.group(2)
        return value

    def set_field(self, key: str, value: str) -> None:
        """Update existing field in place (preserving original case), else append."""
        if not _FIELD_LINE.match(f"{key}: {value}".split("\n", 1)[0]):
            raise ValueError(f"invalid field key: {key!r}")
        if "\n" in value or "\r" in value:
            raise ValueError("field value must not contain newlines")
        target = key.lower()
        for idx, line in enumerate(self.lines):
            match = _FIELD_LINE.match(line)
            if match and match.group(1).lower() == target:
                original_key = match.group(1)
                self.lines[idx] = f"{original_key}: {value}"
                return
        self.lines.append(f"{key}: {value}")

    def unset_field(self, key: str) -> bool:
        """Remove *all* lines matching `key` (case-insensitive). Returns True if any removed."""
        target = key.lower()
        before = len(self.lines)
        self.lines = [
            line
            for line in self.lines
            if not (
                (match := _FIELD_LINE.match(line)) is not None and match.group(1).lower() == target
            )
        ]
        return len(self.lines) < before


def parse(text: str) -> ParsedEntry:
    """Split a decrypted entry body into password + remaining lines.

    The password is always the content of line 1 (verbatim, no trim). Every
    line after that is kept as-is so round-tripping never mangles custom
    formatting. A trailing newline at end-of-file is discarded on parse and
    re-added on serialize.
    """
    if text == "":
        return ParsedEntry(password="", lines=[])
    # Strip at most one trailing newline (matches how `pass show` emits).
    if text.endswith("\n"):
        text = text[:-1]
    parts = text.split("\n")
    password = parts[0]
    rest = parts[1:]
    return ParsedEntry(password=password, lines=rest)


def serialize(entry: ParsedEntry) -> str:
    """Inverse of `parse`. Always ends with a trailing newline."""
    pieces = [entry.password, *entry.lines]
    return "\n".join(pieces) + "\n"


def metadata_view(entry: ParsedEntry) -> dict[str, object]:
    """Safe projection for `show_metadata`: no password, no free-text bodies."""
    return {
        "password_present": bool(entry.password),
        "fields": entry.fields,
        "raw_lines": len(entry.lines) + 1,  # +1 for password line
    }
