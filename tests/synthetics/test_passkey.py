"""synthetics/passkey.py: the member robot's assertion, signed, then verified as auth verifies it.

The fixture (fixtures/member-credentials.json and member-registration.json) is the member robot's secret and its
registration exactly as auth-notary's attended job makes them (`_enrol_a_passkey`, `software_registration`,
`Values.payload()`, with the robot's address beside the password): a test key, never a real one. The verifier is
synthetic_fakes.verify_assertion, written apart from the runner, against the public key read out of the
registration's attestation object with the fakes' own CBOR reader.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
sys.path.insert(0, str(HERE))

import synthetic_fakes as fakes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

from synthetics import passkey  # noqa: E402

ORIGIN = "https://portal.trellistpa.com"
RP_ID = "portal.trellistpa.com"
CHALLENGE = hashlib.sha256(b"a login's ceremony").digest()
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def stored_value() -> dict:
    return copy.deepcopy(fakes.MEMBER_CREDENTIALS["passkey"])


class TheFixture(unittest.TestCase):
    """The fixture is in auth's own shapes, so the runner reads what auth's job will write."""

    def test_the_secret_is_auths_payload_byte_for_byte(self):
        raw = (fakes.FIXTURES / "member-credentials.json").read_bytes()
        value = json.loads(raw)
        # Values.payload(): compact JSON, keys sorted, the passkey an object (auth's own json.loads of it).
        self.assertEqual(raw, json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
        self.assertEqual(set(value), {"email", "password", "passkey"})
        self.assertEqual(set(value["passkey"]), passkey.FIELDS)
        self.assertEqual(set(value["passkey"]["private_jwk"]), passkey.JWK_FIELDS)
        self.assertEqual((value["passkey"]["origin"], value["passkey"]["rp_id"]), (ORIGIN, RP_ID))

    def test_the_registration_is_software_registrations_shape(self):
        registration = fakes.MEMBER_REGISTRATION["registration"]
        self.assertEqual(set(registration), {"id", "rawId", "type", "authenticatorAttachment", "response",
                                             "clientExtensionResults"})
        self.assertEqual(set(registration["response"]), {"clientDataJSON", "attestationObject", "transports"})
        stored = fakes.registered(registration)
        # auth's SOFTWARE_FLAGS | AT, the counter zero, the rp the secret names, the same credential and key.
        self.assertEqual(stored["flags"], 0x5D)
        self.assertEqual(stored["sign_count"], 0)
        self.assertEqual(stored["rp_id_hash"], hashlib.sha256(RP_ID.encode()).digest())
        value = fakes.MEMBER_CREDENTIALS["passkey"]
        self.assertEqual(fakes.b64url(stored["credential_id"]), value["credential_id"])
        self.assertEqual(registration["id"], value["credential_id"])
        self.assertEqual(fakes.MEMBER_REGISTRATION["user_handle"], value["user_handle"])
        key = passkey.load(value).key
        self.assertEqual(stored["public_key"].public_numbers(), key.public_key().public_numbers())
        client = json.loads(fakes.unb64url(registration["response"]["clientDataJSON"]))
        self.assertEqual((client["type"], client["origin"], client["crossOrigin"]), ("webauthn.create", ORIGIN, False))


class SignThenVerify(unittest.TestCase):
    def setUp(self) -> None:
        self.key = passkey.load(stored_value())
        self.stored = fakes.registered(fakes.MEMBER_REGISTRATION["registration"])
        self.handle = fakes.unb64url(fakes.MEMBER_REGISTRATION["user_handle"])

    def verify(self, signed: dict, **changes) -> str:
        arguments = dict(challenge=CHALLENGE, origin=ORIGIN, rp_id=RP_ID, stored=self.stored,
                         user_handle=self.handle)
        arguments.update(changes)
        return fakes.verify_assertion(signed, **arguments)

    def test_it_verifies_against_the_key_auth_stored(self):
        self.assertEqual(self.verify(passkey.assertion(self.key, CHALLENGE)), "")

    def test_bound_to_its_challenge_origin_and_relying_party(self):
        signed = passkey.assertion(self.key, CHALLENGE)
        self.assertEqual(self.verify(signed, challenge=hashlib.sha256(b"another").digest()), "client data")
        self.assertEqual(self.verify(signed, origin="https://portal.elsewhere.invalid"), "origin")
        self.assertEqual(self.verify(signed, rp_id="elsewhere.invalid"), "rp")

    def test_a_changed_byte_does_not_verify(self):
        for field in ("clientDataJSON", "authenticatorData"):
            with self.subTest(field=field):
                signed = passkey.assertion(self.key, CHALLENGE)
                raw = bytearray(fakes.unb64url(signed["response"][field]))
                raw[-1] ^= 0x01
                signed["response"][field] = fakes.b64url(bytes(raw))
                self.assertNotEqual(self.verify(signed), "")

    def test_another_key_does_not_verify(self):
        other = stored_value()
        fresh = ec.generate_private_key(ec.SECP256R1()).private_numbers()
        other["private_jwk"] = {
            "kty": "EC", "crv": "P-256",
            "x": fakes.b64url(fresh.public_numbers.x.to_bytes(32, "big")),
            "y": fakes.b64url(fresh.public_numbers.y.to_bytes(32, "big")),
            "d": fakes.b64url(fresh.private_value.to_bytes(32, "big")),
        }
        self.assertEqual(self.verify(passkey.assertion(passkey.load(other), CHALLENGE)), "malformed or unsigned")

    def test_the_bytes_exactly(self):
        signed = passkey.assertion(self.key, CHALLENGE)
        self.assertEqual(list(signed), ["id", "rawId", "type", "authenticatorAttachment", "response",
                                        "clientExtensionResults"])
        self.assertEqual(list(signed["response"]), ["clientDataJSON", "authenticatorData", "signature", "userHandle"])
        value = fakes.MEMBER_CREDENTIALS["passkey"]
        self.assertEqual((signed["id"], signed["rawId"]), (value["credential_id"], value["credential_id"]))
        self.assertEqual((signed["type"], signed["authenticatorAttachment"], signed["clientExtensionResults"]),
                         ("public-key", "platform", {}))
        self.assertEqual(signed["response"]["userHandle"], value["user_handle"])
        # 32 bytes of SHA-256(rpId), the flags UP UV BE BS (0x1D), the counter 0: 37 bytes, nothing more.
        self.assertEqual(fakes.unb64url(signed["response"]["authenticatorData"]),
                         hashlib.sha256(RP_ID.encode()).digest() + b"\x1d" + b"\x00\x00\x00\x00")
        self.assertEqual(
            fakes.unb64url(signed["response"]["clientDataJSON"]),
            b'{"type":"webauthn.get","challenge":"' + fakes.b64url(CHALLENGE).encode()
            + b'","origin":"https://portal.trellistpa.com","crossOrigin":false}')
        for field in ("clientDataJSON", "authenticatorData", "signature", "userHandle"):
            self.assertNotIn("=", signed["response"][field], "base64url without padding")
        r, s = decode_dss_signature(fakes.unb64url(signed["response"]["signature"]))  # DER
        self.assertTrue(0 < r < P256_ORDER and 0 < s < P256_ORDER)

    def test_the_flags_and_counter_are_the_registrations(self):
        # auth refuses a BE other than the stored one (flags_agree), and a counter that is not zero against zero.
        self.assertEqual(passkey.FLAGS, 0x1D)
        self.assertEqual(passkey.FLAGS & self.stored["flags"] & 0x18, 0x18)
        self.assertEqual(passkey.SIGN_COUNT, 0)
        self.assertEqual(self.stored["sign_count"], 0)

    def test_the_passkey_withholds_itself(self):
        text = repr(self.key) + str(self.key)
        self.assertEqual(repr(self.key), "Passkey(<withheld>)")
        value = fakes.MEMBER_CREDENTIALS["passkey"]
        for secret in (value["private_jwk"]["d"], value["credential_id"], value["user_handle"]):
            self.assertNotIn(secret, text)


class Refusals(unittest.TestCase):
    def refuse(self, value: object) -> None:
        with self.assertRaises(passkey.Unusable) as raised:
            passkey.load(value)
        d = fakes.MEMBER_CREDENTIALS["passkey"]["private_jwk"]["d"]
        self.assertNotIn(d, str(raised.exception))

    def test_fields(self):
        self.refuse(None)
        self.refuse([])
        for missing in passkey.FIELDS:
            with self.subTest(missing=missing):
                value = stored_value()
                del value[missing]
                self.refuse(value)
        value = stored_value()
        value["sign_count"] = 0
        self.refuse(value)

    def test_the_jwk(self):
        for change in ({"kty": "RSA"}, {"crv": "P-384"}, {"d": "not base64url!"}, {"x": "AAAA"},
                       {"d": fakes.b64url(b"\x00" * 32)}, {"alg": "ES256"}):
            with self.subTest(change=change):
                value = stored_value()
                value["private_jwk"].update(change)
                self.refuse(value)

    def test_a_public_point_the_scalar_does_not_make(self):
        value = stored_value()
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        value["private_jwk"]["x"] = fakes.b64url(other.x.to_bytes(32, "big"))
        value["private_jwk"]["y"] = fakes.b64url(other.y.to_bytes(32, "big"))
        self.refuse(value)

    def test_ids(self):
        for field, bad in (("credential_id", ""), ("credential_id", "AAAA"), ("credential_id", "a="),
                           ("user_handle", ""), ("user_handle", "A"), ("user_handle", fakes.b64url(b"x" * 65)),
                           ("rp_id", ""), ("origin", 7)):
            with self.subTest(field=field, bad=bad):
                value = stored_value()
                value[field] = bad
                self.refuse(value)

    def test_a_challenge(self):
        for bad in (None, "", "not base64url!", fakes.b64url(b"short"), fakes.b64url(b"x" * 65)):
            with self.subTest(bad=bad), self.assertRaises(passkey.Unusable):
                passkey.challenge_of(bad)
        self.assertEqual(passkey.challenge_of(fakes.b64url(CHALLENGE)), CHALLENGE)

    def test_a_signing_failure_says_nothing(self):
        key = passkey.load(stored_value())

        class Broken:
            def sign(self, *_args):
                raise RuntimeError(fakes.MEMBER_CREDENTIALS["passkey"]["private_jwk"]["d"])

        broken = passkey.Passkey(credential_id=key.credential_id, user_handle=key.user_handle, rp_id=key.rp_id,
                                 origin=key.origin, key=Broken())
        with self.assertRaises(passkey.Unsigned) as raised:
            passkey.assertion(broken, CHALLENGE)
        self.assertTrue(raised.exception.__suppress_context__, "raised from None: no traceback carries the text")
        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn(fakes.MEMBER_CREDENTIALS["passkey"]["private_jwk"]["d"], str(raised.exception))


if __name__ == "__main__":
    unittest.main()
