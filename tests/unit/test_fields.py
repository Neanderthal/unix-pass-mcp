from __future__ import annotations

import pytest

from unix_pass_mcp import fields


def test_parse_password_only() -> None:
    entry = fields.parse("hunter2\n")
    assert entry.password == "hunter2"
    assert entry.lines == []
    assert entry.fields == {}


def test_parse_canonical_multiline() -> None:
    text = (
        "YwrZSNH35z164ym9pI\n"
        "URL: *.amazon.com/*\n"
        "Username: AmazonianChicken@example.com\n"
        "Phone Support PIN #: 84719\n"  # not a field — has space in key
    )
    entry = fields.parse(text)
    assert entry.password == "YwrZSNH35z164ym9pI"
    assert entry.fields == {
        "URL": "*.amazon.com/*",
        "Username": "AmazonianChicken@example.com",
    }
    # The non-field line is preserved as a raw line.
    assert "Phone Support PIN #: 84719" in entry.lines


def test_parse_empty_password_allowed() -> None:
    entry = fields.parse("\nURL: x\n")
    assert entry.password == ""
    assert entry.fields == {"URL": "x"}


def test_parse_empty_text() -> None:
    entry = fields.parse("")
    assert entry.password == ""
    assert entry.lines == []


def test_serialize_round_trip() -> None:
    text = "hunter2\nURL: x\nUsername: alice\nfree text\n\notpauth://totp/foo\n"
    entry = fields.parse(text)
    assert fields.serialize(entry) == text


def test_serialize_adds_trailing_newline() -> None:
    entry = fields.parse("just-a-pass")  # no trailing \n
    assert fields.serialize(entry) == "just-a-pass\n"


def test_set_field_updates_in_place_preserving_case() -> None:
    entry = fields.parse("pw\nURL: old\nUsername: alice\n")
    entry.set_field("url", "new")  # lowercase key
    assert entry.lines[0] == "URL: new"  # original case preserved
    assert entry.get_field("URL") == "new"


def test_set_field_appends_when_missing() -> None:
    entry = fields.parse("pw\nURL: x\n")
    entry.set_field("Username", "alice")
    assert entry.lines[-1] == "Username: alice"


def test_set_field_rejects_newline_in_value() -> None:
    entry = fields.parse("pw\n")
    with pytest.raises(ValueError):
        entry.set_field("URL", "line1\nline2")


def test_unset_field_removes_all_matches() -> None:
    entry = fields.parse("pw\nURL: a\nurl: b\nUsername: alice\n")
    assert entry.unset_field("URL") is True
    assert entry.fields == {"Username": "alice"}


def test_unset_field_returns_false_when_absent() -> None:
    entry = fields.parse("pw\nURL: x\n")
    assert entry.unset_field("Email") is False


def test_metadata_view_omits_password() -> None:
    entry = fields.parse("hunter2\nURL: x\n")
    view = fields.metadata_view(entry)
    assert view == {"password_present": True, "fields": {"URL": "x"}, "raw_lines": 2}
    assert "hunter2" not in str(view)


def test_field_value_with_colon_in_value() -> None:
    entry = fields.parse("pw\nURL: https://example.com:8443/path\n")
    assert entry.fields["URL"] == "https://example.com:8443/path"


def test_field_with_no_space_after_colon() -> None:
    entry = fields.parse("pw\nURL:nospace\n")
    assert entry.fields["URL"] == "nospace"


@pytest.mark.parametrize(
    "text",
    [
        "p\n",
        "p\nURL: x\n",
        "p\nURL: x\nUsername: u\n",
        "p\n\nfree\nlines\nURL: x\n",
        "\n",
        "\nURL: x\n",
    ],
)
def test_round_trip_property(text: str) -> None:
    once = fields.parse(text)
    twice = fields.parse(fields.serialize(once))
    assert once.password == twice.password
    assert once.lines == twice.lines
