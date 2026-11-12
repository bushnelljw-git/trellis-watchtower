"""synthetics/totp.py against RFC 6238 Appendix B, and its waiting rule."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from synthetics import totp  # noqa: E402

# RFC 6238 Appendix B: the time, then the eight-digit codes for SHA-1, SHA-256 and SHA-512.
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]
# The RFC's seeds: ASCII "1234567890" repeated to 20, 32 and 64 bytes.
SEED_SHA1 = b"12345678901234567890"
SEED_SHA256 = b"12345678901234567890123456789012"
SEED_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"
SEED_SHA1_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class Rfc6238(unittest.TestCase):
    def test_appendix_b(self):
        for at, sha1, sha256, sha512 in VECTORS:
            counter = at // 30
            with self.subTest(time=at):
                self.assertEqual(totp.code_at(SEED_SHA1, counter, digits=8, digest=hashlib.sha1), sha1)
                self.assertEqual(totp.code_at(SEED_SHA256, counter, digits=8, digest=hashlib.sha256), sha256)
                self.assertEqual(totp.code_at(SEED_SHA512, counter, digits=8, digest=hashlib.sha512), sha512)

    def test_auths_six_digit_codes_from_a_base32_secret(self):
        # auth's codes: SHA-1, 30 s, six digits, so the last six of the RFC's SHA-1 column.
        for at, sha1, _sha256, _sha512 in VECTORS:
            with self.subTest(time=at):
                self.assertEqual(totp.code_for_time(SEED_SHA1_BASE32, at), sha1[-6:])

    def test_base32_is_tolerant_of_spacing_case_and_padding(self):
        for written in ("gezdgnbvgy3tqojqgezdgnbvgy3tqojq", "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
                        SEED_SHA1_BASE32 + "===="):
            with self.subTest(written=written):
                self.assertEqual(totp.decode_base32(written), SEED_SHA1)

    def test_an_unusable_secret_never_echoes_itself(self):
        for bad in ("", "   ", "not-base32-!!", "1890"):
            with self.subTest(bad=bad):
                with self.assertRaises(totp.SecretUnusable) as raised:
                    totp.decode_base32(bad)
                if bad.strip():
                    self.assertNotIn(bad, str(raised.exception))


class Minting(unittest.TestCase):
    def test_enough_time_left_no_wait(self):
        slept = []
        code = totp.mint(SEED_SHA1_BASE32, now=lambda: 59.0 - 29, sleep=slept.append)  # 29 s left
        self.assertEqual(slept, [])
        self.assertEqual(code, totp.code_at(SEED_SHA1, 1))

    def test_too_little_left_waits_for_the_next_step(self):
        clock = iter([58.0, 60.3])  # 2 s left in step 1, then step 2
        slept = []
        code = totp.mint(SEED_SHA1_BASE32, now=lambda: next(clock), sleep=slept.append)
        self.assertEqual(len(slept), 1)
        self.assertAlmostEqual(slept[0], 2.2, places=3)
        self.assertEqual(code, totp.code_at(SEED_SHA1, 2))

    def test_a_code_is_accepted_for_the_rest_of_its_step_and_one_more(self):
        # auth and the CRM take a code one step late: a code minted with 8 s left lives 38 s, 29 s left 59 s.
        self.assertEqual(totp.ACCEPTED_LATE_STEPS, 1)
        self.assertAlmostEqual(totp.accepted_for(60 + 22.0), 38.0)
        self.assertAlmostEqual(totp.accepted_for(60 + 1.0), 59.0)
        self.assertAlmostEqual(totp.accepted_for(60 + 29.5), 30.5)

    def test_a_bad_secret_fails_before_any_wait(self):
        slept = []
        with self.assertRaises(totp.SecretUnusable):
            totp.mint("!!", now=lambda: 58.0, sleep=slept.append)
        self.assertEqual(slept, [])


class Clock:
    """A wall clock that a pause moves on."""

    def __init__(self, at: float) -> None:
        self.at = at
        self.slept: list[float] = []

    def now(self) -> float:
        return self.at

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.at += seconds


class Fresh(unittest.TestCase):
    """The broker robot's code (SR-16): always the step after the one current when asked."""

    def test_always_the_next_step_even_with_the_whole_step_left(self):
        for at, wait in [(60.0, 30.2), (61.0, 29.2), (89.9, 0.3), (75.0, 15.2)]:
            with self.subTest(at=at):
                clock = Clock(at)
                code = totp.fresh(SEED_SHA1_BASE32, now=clock.now, sleep=clock.sleep, budget=90)
                self.assertEqual(code, totp.code_at(SEED_SHA1, 3), "step 3 starts at 90 s")
                self.assertEqual(len(clock.slept), 1)
                self.assertAlmostEqual(clock.slept[0], wait, places=6)
                self.assertAlmostEqual(totp.wait_for_fresh(at), wait, places=6)
                self.assertEqual(totp.step_at(clock.at), 3, "the wait ends inside the step the code is for")

    def test_a_run_after_another_never_sends_its_step(self):
        # One run's code is sent as its step begins; any run that asks after that waits for a later step.
        clock = Clock(1000.0)
        first = totp.fresh(SEED_SHA1_BASE32, now=clock.now, sleep=clock.sleep, budget=90)
        sent_at = clock.at
        for later in (0.0, 0.1, 5.0, 29.0):
            with self.subTest(later=later):
                again = Clock(sent_at + later)
                code = totp.fresh(SEED_SHA1_BASE32, now=again.now, sleep=again.sleep, budget=90)
                self.assertNotEqual(code, first)
                self.assertGreater(totp.step_at(again.at), totp.step_at(sent_at))

    def test_the_code_then_has_its_step_and_one_more(self):
        clock = Clock(61.0)
        totp.fresh(SEED_SHA1_BASE32, now=clock.now, sleep=clock.sleep, budget=90)
        self.assertAlmostEqual(totp.accepted_for(clock.now()), 59.8, places=6)

    def test_no_time_for_the_wait_is_no_wait_and_no_code(self):
        clock = Clock(61.0)  # a 29.2 s wait
        for budget in (29.2, 10.0, 0.0, -1.0):
            with self.subTest(budget=budget), self.assertRaises(totp.NoTime):
                totp.fresh(SEED_SHA1_BASE32, now=clock.now, sleep=clock.sleep, budget=budget)
        self.assertEqual(clock.slept, [])
        totp.fresh(SEED_SHA1_BASE32, now=clock.now, sleep=clock.sleep, budget=29.3)
        self.assertEqual(len(clock.slept), 1)

    def test_a_bad_secret_fails_before_any_wait(self):
        clock = Clock(61.0)
        with self.assertRaises(totp.SecretUnusable):
            totp.fresh("!!", now=clock.now, sleep=clock.sleep, budget=90)
        self.assertEqual(clock.slept, [])


if __name__ == "__main__":
    unittest.main()
