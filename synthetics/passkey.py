"""The member robot's passkey: one WebAuthn assertion per run, signed with `cryptography`.

**Never hand-written signing** (bodyfirst tasks/signin-robots SECURITY-REVIEW.md SR-13, blocker B7; ruling
SR-OR-1). A slip in hand-written ECDSA, a reused or biased nonce, leaks the private key while every signature
still verifies. So the P-256 signature is `cryptography`'s, the version auth-notary makes the key with and
verifies assertions with, installed hash-locked from wheels (synthetics/requirements.lock). **This is the only
module in the package that imports it** (tests/synthetics/test_image_policy.py holds that).

**The key is auth's software passkey.** auth's attended job makes it (auth-notary `auth/domain/synthetic.py`,
`_enrol_a_passkey`; `auth/domain/credentials/webauthn.py`, `new_software_passkey` and `software_registration`),
registers it through the challenge door as a browser registers one, and writes the private half to the robot's
secret as `{"credential_id", "private_jwk", "user_handle", "rp_id", "origin"}` (`load` reads exactly that). It
registered with attestation `none`, the counter zero and the flags UP, UV, BE and BS (a synced passkey, `aal2`).

**The assertion** is WebAuthn L3 §7.2 from the client's side, as `navigator.credentials.get()` and `toJSON()`
write it:

- `authenticatorData` = SHA-256(rpId) || flags || the sign count (four bytes, big-endian). The flags are the
  registration's own: UP and UV, and BE and BS, because auth refuses an assertion whose BE is not the one it
  stored (`flags_agree`). The sign count is zero, for ever: auth accepts zero against zero every time
  (`counter_is_fresh`), while a count that did not strictly rise would read as a cloned key and revoke the
  credential and every session behind it. A robot that cannot remember a count between runs keeps zero.
- `clientDataJSON` = `{"type":"webauthn.get","challenge":<the login's challenge>,"origin":<the portal
  origin>,"crossOrigin":false}`, compact.
- `signature` = ECDSA P-256 with SHA-256 over `authenticatorData` || SHA-256(`clientDataJSON`), DER-encoded
  (what `cryptography` returns).
- `userHandle` is sent: the login offers no credential list (`allowCredentials: []`), so auth finds the account
  by it.

Every bytes field is base64url without padding. Nothing here prints, logs or puts a key, a handle or a signature
in an exception's message; the `Passkey` withholds its repr.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

#: WebAuthn L3 §6.1's flags: user present, user verified, backup eligible, backed up. auth-notary's
#: `SOFTWARE_FLAGS` (`auth/domain/credentials/webauthn.py`), which its job registers the robot's key with.
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAGS = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS
#: Zero for ever (auth's `counter_is_fresh` admits zero against zero; see the module's note).
SIGN_COUNT = 0

#: The credential's fields, exactly: auth's `_enrol_a_passkey` writes these five, and an RFC 7517 EC private key.
FIELDS = frozenset({"credential_id", "private_jwk", "user_handle", "rp_id", "origin"})
JWK_FIELDS = frozenset({"kty", "crv", "x", "y", "d"})
#: Each P-256 coordinate and the private scalar: 32 bytes.
COORDINATE_BYTES = 32
#: auth makes a 32-byte credential id and a 16-byte user handle (WebAuthn L3 §14.6.1 allows up to 64); anything
#: outside these bounds is not one of its passkeys.
CREDENTIAL_ID_BYTES = (16, 1023)
USER_HANDLE_BYTES = (1, 64)
#: A login challenge: auth mints 32 bytes; WebAuthn asks for at least 16.
CHALLENGE_BYTES = (16, 64)
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")


class Unusable(ValueError):
    """The stored credential is not a usable passkey (the run's `config`). Never carries a value."""


class Unsigned(Exception):
    """The signature could not be made (the run's `passkey` error). Never carries a value."""


def b64url_decode(text: object, *, size: tuple[int, int]) -> bytes:
    """Unpadded base64url (RFC 4648 §5) whose bytes are `size[0]` to `size[1]` long, or `Unusable`."""
    if not isinstance(text, str) or not _BASE64URL.fullmatch(text) or len(text) % 4 == 1:
        raise Unusable("not base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise Unusable("not base64url") from None
    if not size[0] <= len(raw) <= size[1]:
        raise Unusable("the wrong length")
    return raw


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, repr=False)
class Passkey:
    """The robot's software passkey, in memory for one run."""

    credential_id: bytes
    user_handle: bytes
    rp_id: str
    origin: str
    key: ec.EllipticCurvePrivateKey

    def __repr__(self) -> str:
        return "Passkey(<withheld>)"


def _private_key(jwk: object) -> ec.EllipticCurvePrivateKey:
    """RFC 7517's EC private key on P-256, its public point checked against the scalar by `cryptography`."""
    if not isinstance(jwk, dict) or set(jwk) != JWK_FIELDS or jwk["kty"] != "EC" or jwk["crv"] != "P-256":
        raise Unusable("not a P-256 private JWK")
    exact = (COORDINATE_BYTES, COORDINATE_BYTES)
    x, y, d = (int.from_bytes(b64url_decode(jwk[name], size=exact), "big") for name in ("x", "y", "d"))
    try:
        return ec.EllipticCurvePrivateNumbers(d, ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())).private_key()
    except ValueError:  # a point off the curve, or one the scalar does not make
        raise Unusable("not a P-256 private key") from None


def load(value: object) -> Passkey:
    """The `passkey` object of the member robot's secret, exactly auth's five fields, or `Unusable`."""
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise Unusable("not the passkey's fields")
    rp_id, origin = value["rp_id"], value["origin"]
    if not isinstance(rp_id, str) or not rp_id or not isinstance(origin, str) or not origin:
        raise Unusable("no relying party")
    return Passkey(
        credential_id=b64url_decode(value["credential_id"], size=CREDENTIAL_ID_BYTES),
        user_handle=b64url_decode(value["user_handle"], size=USER_HANDLE_BYTES),
        rp_id=rp_id,
        origin=origin,
        key=_private_key(value["private_jwk"]),
    )


def challenge_of(text: object) -> bytes:
    """A login's `webauthn.challenge`, or `Unusable` (the answer's `shape`)."""
    return b64url_decode(text, size=CHALLENGE_BYTES)


def authenticator_data(rp_id: str) -> bytes:
    """SHA-256(rpId) || flags || the sign count: 37 bytes, with no attested credential data or extensions."""
    return hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([FLAGS]) + SIGN_COUNT.to_bytes(4, "big")


def client_data(challenge: bytes, origin: str) -> bytes:
    """The `webauthn.get` client data, compact JSON, in the order WebAuthn L3 §5.8.1.1 serialises it."""
    return json.dumps(
        {"type": "webauthn.get", "challenge": b64url_encode(challenge), "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")


def assertion(passkey: Passkey, challenge: bytes) -> dict[str, Any]:
    """The `PublicKeyCredential` JSON auth's `/auth/mfa/verify` takes as `assertion`, for one login challenge.

    The origin and rpId are the passkey's own, which the journey has already held equal to the portal origin
    and to the rpId the login asked for.
    """
    data = authenticator_data(passkey.rp_id)
    client = client_data(challenge, passkey.origin)
    try:
        signature = passkey.key.sign(data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    except Exception:  # noqa: BLE001 - whatever the library raised, its text never leaves here
        raise Unsigned("the assertion could not be signed") from None
    credential_id = b64url_encode(passkey.credential_id)
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": b64url_encode(client),
            "authenticatorData": b64url_encode(data),
            "signature": b64url_encode(signature),
            "userHandle": b64url_encode(passkey.user_handle),
        },
        "clientExtensionResults": {},
    }
