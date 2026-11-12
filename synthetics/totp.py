"""RFC 6238 time-based one-time codes, standard library only.

auth's authenticator codes are SHA-1, 30-second steps, six digits (RFC 6238's
defaults). `code_at` takes the digest and the length as well, so the RFC's own
test vectors (Appendix B: SHA-1, SHA-256 and SHA-512, eight digits) can be
checked against exactly the function that makes the real codes.

auth accepts each step once per account (`totp_last_step`) and charges a refused
code to the lockout budget, so a run sends exactly one code and never retries.
`mint` (the staff journeys) waits for the next step when fewer than
`MIN_SECONDS_LEFT` remain in the current one, so the code cannot expire between
here and auth. `fresh` (the broker robot) always waits for the next step, so it
never sends a step an earlier run spent.

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
#: How many steps late auth and the CRM still accept a code (each takes one step
#: either side: auth-notary's `TOTP_WINDOW_STEPS`, auth/domain/clocks.py; the CRM's
#: `VALID_STEPS`, engine/app/lattice/modules/identity/totp.py). A code minted with
#: MIN_SECONDS_LEFT is so accepted for 38 s at least.
ACCEPTED_LATE_STEPS = 1


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


def accepted_for(epoch_seconds: float) -> float:
    """How much longer a code for the step covering this time is accepted: the rest of
    its step and ACCEPTED_LATE_STEPS more. `mfa_verify` never reaches auth after that,
    where the code would be refused and charged to the lockout budget."""
    return (step_at(epoch_seconds) + 1 + ACCEPTED_LATE_STEPS) * STEP_SECONDS - epoch_seconds


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


#: How far past a step's start `fresh` waits, so the code is that step's on any clock near this one.
FRESH_MARGIN_S = 0.2


class NoTime(Exception):
    """The wait for a fresh step would not leave the run any time to send its code."""


def wait_for_fresh(epoch_seconds: float) -> float:
    """Seconds from this time until FRESH_MARGIN_S into the next step: more than 0.2 and at most 30.2."""
    return (step_at(epoch_seconds) + 1) * STEP_SECONDS + FRESH_MARGIN_S - epoch_seconds


def fresh(secret: str, *, now: Callable[[], float], sleep: Callable[[float], None], budget: float) -> str:
    """The code of the step that begins after now, once it has begun: never the step current when asked.

    The broker robot's rule (bodyfirst tasks/signin-robots SECURITY-REVIEW.md SR-16). auth accepts a step once
    per account and refuses any step at or below the last it accepted, charging the refusal to the factor
    lockout. A run that started after an earlier run sent its code asks here later than that code's step began,
    so the step it waits for begins later still: it never sends a step an earlier run spent, whether that run was
    the schedule's, a hand-started one or a retry. It costs up to 30.2 s of waiting, and the code then has the
    rest of its step and one more of accepted life (`accepted_for`, at least 59.8 s). Two runs asking inside the
    same wait (two executions started together) can still meet: auth refuses the second, which is that run's
    `credentials` and one factor failure (SR-16, accepted). `NoTime` when the wait is not shorter than `budget`
    (what the run's deadline has left), with no wait and no code.
    """
    key = decode_base32(secret)  # refuse an unusable secret before any wait
    at = now()
    wait = wait_for_fresh(at)
    if wait >= budget:
        raise NoTime
    sleep(wait)
    return code_at(key, step_at(at) + 1)
