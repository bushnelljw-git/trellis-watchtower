"""The website verifies IAP's assertion against a pinned copy of Google's key set baked into the image, so the running
service needs no internet path: cloud/iap_keys.json is an ES256 JWK set with at least one usable key, grafana.ini reads
it with jwk_set_file (never jwk_set_url), the Dockerfile puts it where grafana.ini looks, and
scripts/refresh_iap_keys.sh only writes it when asked.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import base64
import configparser
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
KEYS = ROOT / "cloud" / "iap_keys.json"
INI = ROOT / "cloud" / "grafana.ini"
DOCKERFILE = ROOT / "cloud" / "Dockerfile"
REFRESH = ROOT / "scripts" / "refresh_iap_keys.sh"
IN_IMAGE = "/etc/grafana/iap_keys.json"

# P-256 (FIPS 186-4 D.1.2.3): y^2 = x^3 - 3x + b mod p.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def coordinate(value: str) -> int:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    assert len(raw) == 32, "a P-256 coordinate is 32 bytes"
    return int.from_bytes(raw, "big")


def jwt_section() -> configparser.SectionProxy:
    parser = configparser.ConfigParser(interpolation=None, comment_prefixes=(";", "#"), strict=False)
    parser.read_string(INI.read_text())
    return parser["auth.jwt"]


class PinnedKeys(unittest.TestCase):
    def test_the_file_is_an_es256_jwk_set(self) -> None:
        document = json.loads(KEYS.read_text())
        keys = document["keys"]
        self.assertIsInstance(keys, list)
        self.assertGreaterEqual(len(keys), 1, "no key: every sign-in would be refused")
        kids = [key["kid"] for key in keys]
        self.assertEqual(len(kids), len(set(kids)), "a kid appears twice")
        for key in keys:
            with self.subTest(kid=key.get("kid")):
                self.assertEqual((key["kty"], key["crv"], key["alg"], key.get("use", "sig")),
                                 ("EC", "P-256", "ES256", "sig"))
                self.assertTrue(isinstance(key["kid"], str) and key["kid"])
                x, y = coordinate(key["x"]), coordinate(key["y"])
                self.assertEqual((y * y - (x * x * x - 3 * x + B)) % P, 0, "the point is not on P-256")
                self.assertNotIn("d", key, "a private key part")

    def test_the_file_names_its_source_and_day(self) -> None:
        document = json.loads(KEYS.read_text())
        self.assertEqual(document["source"], "https://www.gstatic.com/iap/verify/public_key-jwk")
        self.assertRegex(document["pinned_at"], r"^\d{4}-\d{2}-\d{2}$")

    def test_grafana_reads_the_file_and_fetches_nothing(self) -> None:
        jwt = jwt_section()
        self.assertEqual(jwt.get("jwk_set_file"), IN_IMAGE)
        self.assertNotIn("jwk_set_url", jwt)
        self.assertNotIn("key_file", jwt)
        self.assertNotIn("gstatic", INI.read_text().split("[auth.jwt]", 1)[1].split("\n[", 1)[0])

    def test_the_image_puts_the_file_where_grafana_looks(self) -> None:
        self.assertIn(f"COPY iap_keys.json {IN_IMAGE}\n", DOCKERFILE.read_text())


class Refresh(unittest.TestCase):
    """scripts/refresh_iap_keys.sh, from saved copies (--from), never the network."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.pinned = self.dir / "iap_keys.json"
        shutil.copy(KEYS, self.pinned)

    def run_refresh(self, document: object, *extra: str) -> subprocess.CompletedProcess[str]:
        saved = self.dir / "fetched.json"
        saved.write_text(json.dumps(document))
        return subprocess.run(["bash", str(REFRESH), "--from", str(saved), "--file", str(self.pinned), *extra],
                              capture_output=True, text=True, check=False)

    def test_the_same_set_changes_nothing(self) -> None:
        keys = json.loads(KEYS.read_text())["keys"]
        before = self.pinned.read_bytes()
        result = self.run_refresh({"keys": list(reversed(keys))})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("nothing to do", result.stdout)
        self.assertEqual(self.pinned.read_bytes(), before)

    def test_a_rotation_is_reported_and_written_only_with_write(self) -> None:
        keys = json.loads(KEYS.read_text())["keys"]
        rotated = [dict(keys[0], kid="rotated-in")] + keys[1:]
        before = self.pinned.read_bytes()
        result = self.run_refresh({"keys": rotated})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("added ['rotated-in']", result.stdout)
        self.assertIn(f"removed ['{keys[0]['kid']}']", result.stdout)
        self.assertEqual(self.pinned.read_bytes(), before, "written without --write")
        result = self.run_refresh({"keys": rotated}, "--write")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        written = json.loads(self.pinned.read_text())
        self.assertIn("rotated-in", [key["kid"] for key in written["keys"]])
        self.assertEqual(written["source"], "https://www.gstatic.com/iap/verify/public_key-jwk")

    def test_unusable_keys_are_dropped_and_a_set_with_none_is_refused(self) -> None:
        good = json.loads(KEYS.read_text())["keys"][0]
        bad = [dict(good, alg="RS256"), dict(good, crv="P-384"), dict(good, kid=""),
               dict(good, y=good["x"]), {"kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB"}]
        before = self.pinned.read_bytes()
        result = self.run_refresh({"keys": bad}, "--write")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("no usable ES256 P-256 key", result.stderr)
        self.assertEqual(self.pinned.read_bytes(), before)
        result = self.run_refresh({"keys": bad + [good]}, "--write")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([key["kid"] for key in json.loads(self.pinned.read_text())["keys"]], [good["kid"]])


if __name__ == "__main__":
    unittest.main()
