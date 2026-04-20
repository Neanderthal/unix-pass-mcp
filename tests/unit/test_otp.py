from __future__ import annotations

import base64

import pytest

from unix_pass_mcp import otp
from unix_pass_mcp.errors import PassError


# RFC 6238 Appendix B test vectors. Secrets per algorithm:
#   SHA1   = "12345678901234567890"
#   SHA256 = "12345678901234567890123456789012"
#   SHA512 = "1234567890123456789012345678901234567890123456789012345678901234"
def _b32(s: bytes) -> str:
    return base64.b32encode(s).decode().rstrip("=")


_SHA1_KEY = _b32(b"12345678901234567890")
_SHA256_KEY = _b32(b"12345678901234567890123456789012")
_SHA512_KEY = _b32(b"1234567890123456789012345678901234567890123456789012345678901234")


@pytest.mark.parametrize(
    ("now", "algorithm", "key", "expected_8"),
    [
        # SHA1 vectors
        (59, "SHA1", _SHA1_KEY, "94287082"),
        (1111111109, "SHA1", _SHA1_KEY, "07081804"),
        (1111111111, "SHA1", _SHA1_KEY, "14050471"),
        (1234567890, "SHA1", _SHA1_KEY, "89005924"),
        (2000000000, "SHA1", _SHA1_KEY, "69279037"),
        # SHA256 vectors
        (59, "SHA256", _SHA256_KEY, "46119246"),
        (1111111109, "SHA256", _SHA256_KEY, "68084774"),
        (2000000000, "SHA256", _SHA256_KEY, "90698825"),
        # SHA512 vectors
        (59, "SHA512", _SHA512_KEY, "90693936"),
        (1111111109, "SHA512", _SHA512_KEY, "25091201"),
    ],
)
def test_rfc6238_vectors(now: int, algorithm: str, key: str, expected_8: str) -> None:
    uri = f"otpauth://totp/test?secret={key}&algorithm={algorithm}&digits=8&period=30"
    params = otp.parse_otpauth_uri(uri)
    result = otp.compute_totp(params, now=float(now))
    assert result.code == expected_8


def test_default_digits_and_period() -> None:
    uri = f"otpauth://totp/test?secret={_SHA1_KEY}"
    params = otp.parse_otpauth_uri(uri)
    assert params.digits == 6
    assert params.period == 30
    assert params.algorithm == "SHA1"


def test_six_digit_truncation_matches_eight_digit_vector() -> None:
    # The 8-digit code 94287082 modulo 10**6 = 287082.
    uri = f"otpauth://totp/test?secret={_SHA1_KEY}"
    result = otp.compute_totp(otp.parse_otpauth_uri(uri), now=59.0)
    assert result.code == "287082"


def test_seconds_remaining() -> None:
    uri = f"otpauth://totp/test?secret={_SHA1_KEY}"
    params = otp.parse_otpauth_uri(uri)
    # At t=0 we just entered window; full period remaining.
    result = otp.compute_totp(params, now=0.0)
    assert result.seconds_remaining == 30
    # At t=29 we're at the very end; 1 second remaining.
    result = otp.compute_totp(params, now=29.0)
    assert result.seconds_remaining == 1
    # At t=30 we entered next window; full period remaining again.
    result = otp.compute_totp(params, now=30.0)
    assert result.seconds_remaining == 30


def test_issuer_and_account_from_label() -> None:
    uri = f"otpauth://totp/GitHub:alice@example.com?secret={_SHA1_KEY}"
    params = otp.parse_otpauth_uri(uri)
    assert params.issuer == "GitHub"
    assert params.account == "alice@example.com"


def test_issuer_query_param_overrides_label() -> None:
    uri = f"otpauth://totp/Foo:alice?secret={_SHA1_KEY}&issuer=GitHub"
    params = otp.parse_otpauth_uri(uri)
    assert params.issuer == "GitHub"


def test_account_only_label() -> None:
    uri = f"otpauth://totp/alice?secret={_SHA1_KEY}"
    params = otp.parse_otpauth_uri(uri)
    assert params.account == "alice"
    assert params.issuer is None


def test_unpadded_lowercase_secret() -> None:
    # Most issuers strip padding; some include spaces or hyphens.
    raw = "gezdgnbvgy3tqojqgezdgnbvgy3tqojq"
    uri = f"otpauth://totp/test?secret={raw}"
    params = otp.parse_otpauth_uri(uri)
    result = otp.compute_totp(params, now=59.0)
    assert result.code == "287082"


def test_secret_with_spaces_and_hyphens() -> None:
    raw = "GEZD-GNBV GY3T-QOJQ GEZD-GNBV GY3T-QOJQ"
    uri = f"otpauth://totp/test?secret={raw}"
    params = otp.parse_otpauth_uri(uri)
    result = otp.compute_totp(params, now=59.0)
    assert result.code == "287082"


# ── error paths ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "uri",
    [
        "",
        "   ",
        "https://example.com",
        "otpauth://hotp/?secret=AAAA",  # HOTP not supported
        "otpauth://totp/x",  # missing secret
        "otpauth://totp/x?secret=",  # empty secret
        "otpauth://totp/x?secret=NOT-VALID-B32!@#",
        f"otpauth://totp/x?secret={_SHA1_KEY}&algorithm=MD5",
        f"otpauth://totp/x?secret={_SHA1_KEY}&digits=99",
        f"otpauth://totp/x?secret={_SHA1_KEY}&digits=abc",
        f"otpauth://totp/x?secret={_SHA1_KEY}&period=0",
        f"otpauth://totp/x?secret={_SHA1_KEY}&period=99999",
    ],
)
def test_invalid_uris_rejected(uri: str) -> None:
    with pytest.raises(PassError) as exc:
        otp.parse_otpauth_uri(uri)
    assert exc.value.code == "invalid_otpauth"


def test_compute_with_explicit_now_is_deterministic() -> None:
    uri = f"otpauth://totp/x?secret={_SHA1_KEY}"
    params = otp.parse_otpauth_uri(uri)
    a = otp.compute_totp(params, now=12345.0)
    b = otp.compute_totp(params, now=12345.0)
    assert a == b
