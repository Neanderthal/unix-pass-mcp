"""TOTP (RFC 6238) computation against `otpauth://` URIs stored in pass entries.

We implement TOTP natively rather than shelling out to `pass-otp`:

    * Same convention — the URI is a line in the entry body, written by
      pass-otp, browserpass, or any other tool that follows the Key URI Format.
    * Pure stdlib (`hmac`, `hashlib`, `base64`, `struct`, `urllib.parse`).
    * Richer return values — pass-otp's stdout is just the 6 digits; we also
      report `seconds_remaining`, `period`, `digits`, `algorithm` so the agent
      can decide whether to wait for the next window before submitting.

Spec: https://datatracker.ietf.org/doc/html/rfc6238
URI:  https://github.com/google/google-authenticator/wiki/Key-Uri-Format
"""

from __future__ import annotations

import base64
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from .errors import PassError

_SUPPORTED_ALGORITHMS: dict[str, str] = {
    "SHA1": "sha1",
    "SHA256": "sha256",
    "SHA512": "sha512",
}
_DEFAULT_DIGITS = 6
_DEFAULT_PERIOD = 30
_DEFAULT_ALGORITHM = "SHA1"


@dataclass(frozen=True)
class OtpParams:
    secret_b32: str  # base32-encoded shared secret, no padding stripping
    algorithm: str  # "SHA1" / "SHA256" / "SHA512"
    digits: int  # 6 or 8 (others rare but tolerated 4..10)
    period: int  # window length in seconds (default 30)
    issuer: str | None  # display only
    account: str | None  # display only


def parse_otpauth_uri(uri: str) -> OtpParams:
    """Validate and decode an `otpauth://totp/...` URI.

    Raises PassError(code="invalid_otpauth") on any malformed input. We are
    deliberately strict: an MCP server should not silently accept garbage and
    later return wrong codes that look right.
    """
    if not isinstance(uri, str) or not uri.strip():
        raise PassError("otpauth URI must be a non-empty string", code="invalid_otpauth")

    parts = urlsplit(uri.strip())
    if parts.scheme != "otpauth":
        raise PassError(
            f"otpauth URI must use scheme 'otpauth' (got {parts.scheme!r})", code="invalid_otpauth"
        )
    if parts.netloc.lower() != "totp":
        # HOTP exists but isn't useful for browser autofill flows.
        raise PassError(
            f"only 'totp' type supported (got {parts.netloc!r})", code="invalid_otpauth"
        )

    label = unquote(parts.path.lstrip("/"))
    issuer_from_label: str | None = None
    account: str | None = None
    if ":" in label:
        issuer_from_label, account = label.split(":", 1)
        issuer_from_label = issuer_from_label.strip() or None
        account = account.strip() or None
    elif label:
        account = label

    params = parse_qs(parts.query, keep_blank_values=False, strict_parsing=False)
    secret_values = params.get("secret", [])
    if not secret_values or not secret_values[0]:
        raise PassError("otpauth URI is missing the `secret` parameter", code="invalid_otpauth")
    secret = secret_values[0].strip()
    # Validate base32 early so we surface a clear error here, not at compute time.
    _decode_base32(secret)

    algorithm = (params.get("algorithm", [_DEFAULT_ALGORITHM])[0] or "").upper()
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise PassError(
            f"unsupported HMAC algorithm {algorithm!r} (allowed: SHA1, SHA256, SHA512)",
            code="invalid_otpauth",
        )

    try:
        digits = int(params.get("digits", [str(_DEFAULT_DIGITS)])[0])
        period = int(params.get("period", [str(_DEFAULT_PERIOD)])[0])
    except ValueError as exc:
        raise PassError(
            f"otpauth URI has non-integer digits/period: {exc}", code="invalid_otpauth"
        ) from exc
    if not 4 <= digits <= 10:
        raise PassError(f"digits must be between 4 and 10 (got {digits})", code="invalid_otpauth")
    if not 1 <= period <= 600:
        raise PassError(
            f"period must be between 1 and 600 seconds (got {period})", code="invalid_otpauth"
        )

    issuer_from_query = params.get("issuer", [None])[0]
    issuer = issuer_from_query or issuer_from_label

    return OtpParams(
        secret_b32=secret,
        algorithm=algorithm,
        digits=digits,
        period=period,
        issuer=issuer,
        account=account,
    )


def _decode_base32(secret: str) -> bytes:
    """Decode a (possibly unpadded, possibly lowercase) base32 string."""
    cleaned = secret.replace(" ", "").replace("-", "").upper()
    # base64.b32decode requires padding to a multiple of 8.
    pad = (-len(cleaned)) % 8
    cleaned += "=" * pad
    try:
        return base64.b32decode(cleaned, casefold=False)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise PassError(
            f"otpauth secret is not valid base32: {exc}", code="invalid_otpauth"
        ) from exc


@dataclass(frozen=True)
class OtpCode:
    code: str
    seconds_remaining: int
    period: int
    digits: int
    algorithm: str
    issuer: str | None
    account: str | None


def compute_totp(params: OtpParams, *, now: float | None = None) -> OtpCode:
    """Compute the current TOTP code per RFC 6238."""
    if now is None:
        now = time.time()
    secret = _decode_base32(params.secret_b32)
    counter = int(now // params.period)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret, counter_bytes, _SUPPORTED_ALGORITHMS[params.algorithm]).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = str(truncated % (10**params.digits)).zfill(params.digits)
    seconds_remaining = params.period - int(now % params.period)
    return OtpCode(
        code=code,
        seconds_remaining=seconds_remaining,
        period=params.period,
        digits=params.digits,
        algorithm=params.algorithm,
        issuer=params.issuer,
        account=params.account,
    )
