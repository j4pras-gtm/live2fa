"""RFC 6238 TOTP implementation."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, unquote, urlparse


_ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def _decode_secret(secret: str) -> bytes:
    value = secret.strip().replace(" ", "").replace("-", "").upper()
    if value.startswith("OTPAUTH://"):
        parsed = urlparse(value)
        if parsed.scheme.lower() != "otpauth" or parsed.netloc.lower() != "totp":
            raise ValueError("Only otpauth://totp/... URIs are supported")
        query = parse_qs(parsed.query)
        encoded = query.get("secret", [""])[0]
        if not encoded:
            raise ValueError("otpauth URI does not contain a secret")
        value = unquote(encoded).replace(" ", "").replace("-", "").upper()
    if not value:
        raise ValueError("secret must not be empty")
    try:
        return base64.b32decode(value + "=" * ((8 - len(value) % 8) % 8), casefold=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("secret must be a valid Base32 value") from exc


def generate_totp(secret: str, *, now: float | None = None, digits: int = 6,
                 period: int = 30, algorithm: str = "SHA1") -> tuple[str, int]:
    """Return (code, seconds_remaining) for an RFC 6238 TOTP secret."""
    if digits not in (6, 7, 8):
        raise ValueError("digits must be 6, 7, or 8")
    if not 15 <= period <= 300:
        raise ValueError("period must be between 15 and 300 seconds")
    algorithm = algorithm.upper()
    if algorithm not in _ALGORITHMS:
        raise ValueError("algorithm must be SHA1, SHA256, or SHA512")

    timestamp = time.time() if now is None else now
    counter = int(timestamp // period)
    key = _decode_secret(secret)
    message = struct.pack(">Q", counter)
    digest = hmac.new(key, message, _ALGORITHMS[algorithm]).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code = str(binary % (10 ** digits)).zfill(digits)
    remaining = period - (int(timestamp) % period)
    return code, remaining
