"""RFC 6238 time-based one-time codes, standard library only.

auth's authenticator codes are SHA-1, 30-second steps, six digits (RFC 6238's
defaults). `code_at` takes the digest and the length as well, so the RFC's own
test vectors (Appendix B: SHA-1, SHA-256 and SHA-512, eight digits) can be
checked against exactly the function that makes the real codes.

auth accepts each step once per account (`totp_last_step`) and charges a refused
code to the lockout budget, so a run sends exactly one code and never retries.
`mint` waits for the next step when fewer than `MIN_SECONDS_LEFT` remain in the
current one, so the code cannot expire between here and auth.

Nothing here prints, logs or raises with the secret or a code in its message.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from collections.abc import Callable

STEP_SECONDS = 30
DIGITS = 6
#: The fewest seconds a minted code may have left in its step.
MIN_SECONDS_LEFT = 8


class SecretUnusable(ValueError):
    """The secret is not base32. The message never carries the secret."""


def decode_base32(secret: str) -> bytes:
    """RFC 4648 base32, tolerant of spaces, padding and case."""
    cleaned = "".join(secret.split()).rstrip("=").upper()
    if not cleaned:
        raise SecretUnusable("the TOTP secret is empty")
    try:
        key = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except (ValueError, TypeError):
        raise SecretUnusable("the TOTP secret is not base32") from None
    if not key:
        raise SecretUnusable("the TOTP secret is empty")
    return key


def code_at(key: bytes, counter: int, *, digits: int = DIGITS, digest: Callable = hashlib.sha1) -> str:
    """RFC 4226's HOTP value for one counter, leading zeros kept."""
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % 10**digits).zfill(digits)


def step_at(epoch_seconds: float) -> int:
    return int(epoch_seconds // STEP_SECONDS)


def code_for_time(secret: str, epoch_seconds: float) -> str:
    """auth's code (SHA-1, 30 s, six digits) for the step covering a time."""
    return code_at(decode_base32(secret), step_at(epoch_seconds))


def mint(
    secret: str,
    *,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    min_seconds_left: float = MIN_SECONDS_LEFT,
) -> str:
    """One code with at least `min_seconds_left` left in its step."""
    key = decode_base32(secret)  # refuse an unusable secret before any wait
    at = now()
    left = STEP_SECONDS - (at - step_at(at) * STEP_SECONDS)
    if left < min_seconds_left:
        sleep(left + 0.2)
        at = now()
    return code_at(key, step_at(at))
