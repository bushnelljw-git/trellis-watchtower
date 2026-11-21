"""security/scan-exceptions.yaml, held to the rules tpa-platform's builder reads it by.

The builder's exceptions step (tpa-platform's cloudbuild/pipeline.py, read_exceptions) reads the file line by line with
its own strict subset of YAML and refuses the whole file, so no image of this repository can be built, on the first
line it doesn't take. Production window 48 (2026-11-21) stopped there: 795a396 had written "Re-checked 2026-11-21: ..."
into ten reasons, and a value holding ": " is refused. Neither `make lint` nor the builder's start check read the file
that way, so this does, with no tpa-platform checkout: the same refusals, written out again here.

- The file is printable ASCII and newlines only, at most 64 KiB.
- Every line that isn't blank or a comment is "- key: value" (starting an entry) or "  key: value" (inside one), or
  the list is [] alone.
- A key is one of id, package, reason and expires, once each per entry, and every entry has all four.
- A value is plain text: it doesn't start with a quote, a flow or indicator character (- ? : , [ ] { } # & * ! | > ' "
  % @ `), and it holds no ": " and no " #", and doesn't end with a space or a colon.
- The id is a CVE or GitHub advisory id, the package one package name, expires a real YYYY-MM-DD date, at most 50
  entries, and no entry has expired as of today (UTC), as the builder counts it.
"""

from __future__ import annotations

import datetime
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXCEPTIONS = ROOT / "security" / "scan-exceptions.yaml"
#: As tpa-platform's cloudbuild/pipeline.py names them (EXCEPTION_KEYS, EXCEPTION_LIMIT, ADVISORY, PACKAGE).
KEYS = ("id", "package", "reason", "expires")
LIMIT = 50
ADVISORY = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")
PACKAGE = re.compile(r"[A-Za-z0-9._+:@/-]+")
FIELD = re.compile(r"([a-z]+): ([^ ].*)")
LEADING = "-?:,[]{}#&*!|>'\"%@`"


def problems(raw: bytes, today: datetime.date) -> list[str]:
    """Every reason the builder would refuse this file, by line (it stops at the first; this lists them all)."""
    found: list[str] = []
    if len(raw) > 1 << 16:
        found.append("over 64 KiB")
    for number, line in enumerate(raw.split(b"\n"), 1):
        if any(byte != 0x0A and not 0x20 <= byte <= 0x7E for byte in line):
            found.append(f"line {number} holds something other than printable ASCII")
    lines = [(number, line) for number, line in enumerate(raw.decode("ascii", "replace").split("\n"), 1)
             if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return found + ["no list (an empty one is [] alone on its line)"]
    if [line for _, line in lines] == ["[]"]:
        return found
    entries: list[tuple[int, dict[str, str]]] = []
    for number, line in lines:
        if line.startswith("- "):
            entries.append((number, {}))
        elif not (line.startswith("  ") and entries):
            found.append(f"line {number} isn't part of a list of entries")
            continue
        match = FIELD.fullmatch(line[2:])
        if not match:
            found.append(f"line {number} isn't one 'key: value' pair")
            continue
        key, value = match.groups()
        entry = entries[-1][1]
        if key not in KEYS:
            found.append(f"line {number} has the key {key!r}")
        elif key in entry:
            found.append(f"line {number} gives {key} a second time")
        if value[0] in LEADING:
            found.append(f"line {number}'s value starts with {value[0]!r}")
        if value != value.rstrip():
            found.append(f"line {number}'s value ends with a space")
        if value.endswith(":"):
            found.append(f"line {number}'s value ends with a colon")
        if ": " in value:
            found.append(f"line {number}'s value holds ': ' (write the date without a colon after it)")
        if " #" in value:
            found.append(f"line {number}'s value holds ' #'")
        entry.setdefault(key, value)
    if len(entries) > LIMIT:
        found.append(f"{len(entries)} entries, over {LIMIT}")
    for start, entry in entries:
        missing = [key for key in KEYS if key not in entry]
        if missing:
            found.append(f"the entry at line {start} has no {' and no '.join(missing)}")
            continue
        if not ADVISORY.fullmatch(entry["id"]):
            found.append(f"the entry at line {start}: {entry['id']!r} isn't a CVE or GHSA id")
        if not PACKAGE.fullmatch(entry["package"]) or len(entry["package"]) > 128:
            found.append(f"the entry at line {start}: {entry['package']!r} isn't one package name")
        try:
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", entry["expires"]):
                raise ValueError
            expires = datetime.date.fromisoformat(entry["expires"])
        except ValueError:
            found.append(f"the entry at line {start}: expires {entry['expires']!r} isn't a YYYY-MM-DD date")
            continue
        if expires < today:
            found.append(f"the entry at line {start} ({entry['id']} in {entry['package']}) expired on {expires}")
    return found


def entry(reason: str = "Not reachable.", expires: str = "2026-12-31", key: str = "reason") -> bytes:
    return f"- id: CVE-2026-12345\n  package: openssl\n  {key}: {reason}\n  expires: {expires}\n".encode()


DAY = datetime.date(2026, 11, 21)


class TheFile(unittest.TestCase):
    def test_the_builder_would_read_every_entry(self):
        today = datetime.datetime.now(datetime.timezone.utc).date()
        self.assertEqual(problems(EXCEPTIONS.read_bytes(), today), [])

    def test_it_is_a_regular_file(self):
        self.assertTrue(EXCEPTIONS.is_file() and not EXCEPTIONS.is_symlink())


class TheRules(unittest.TestCase):
    """Each refusal, on a one-entry file, so a check that stops refusing is caught here."""

    def test_a_plain_entry_and_an_empty_list_pass(self):
        self.assertEqual(problems(entry(), DAY), [])
        self.assertEqual(problems(b"# none\n[]\n", DAY), [])

    def test_a_colon_and_space_in_a_value(self):
        self.assertEqual(problems(entry("Re-checked 2026-11-21: no fix."), DAY),
                         ["line 3's value holds ': ' (write the date without a colon after it)"])

    def test_a_comment_in_a_value(self):
        self.assertEqual(problems(entry("Not reachable #42."), DAY), ["line 3's value holds ' #'"])

    def test_a_leading_quote_or_flow_character(self):
        for first in "'\"[{&*!|>%@`-?:,#":
            with self.subTest(first=first):
                self.assertIn(f"line 3's value starts with {first!r}", problems(entry(first + "x"), DAY))

    def test_a_trailing_space_or_colon(self):
        self.assertEqual(problems(entry("Not reachable. "), DAY), ["line 3's value ends with a space"])
        self.assertEqual(problems(entry("Not reachable:"), DAY), ["line 3's value ends with a colon"])

    def test_anything_but_printable_ascii(self):
        for text in ("Not reachable—really.", "Not\treachable."):
            with self.subTest(text=text):
                self.assertIn("line 3 holds something other than printable ASCII", problems(entry(text), DAY))
        self.assertIn("line 2 holds something other than printable ASCII",
                      problems(entry().replace(b"\n  reason", b"\r\n  reason"), DAY))

    def test_four_keys_once_each(self):
        self.assertEqual(problems(entry(key="why"), DAY),
                         ["line 3 has the key 'why'", "the entry at line 1 has no reason"])
        self.assertIn("line 5 gives reason a second time", problems(entry() + b"  reason: Again.\n", DAY))
        self.assertEqual(problems(b"- id: CVE-2026-12345\n  package: openssl\n  expires: 2026-12-31\n", DAY),
                         ["the entry at line 1 has no reason"])
        self.assertIn("line 2 isn't part of a list of entries",
                      problems(b"- id: CVE-2026-12345\n package: openssl\n", DAY))
        self.assertIn("line 3 isn't one 'key: value' pair", problems(entry().replace(b"reason: ", b"reason:"), DAY))

    def test_an_expired_or_unreadable_date(self):
        self.assertEqual(problems(entry(expires="2026-11-20"), DAY),
                         ["the entry at line 1 (CVE-2026-12345 in openssl) expired on 2026-11-20"])
        self.assertEqual(problems(entry(expires="2026-11-21"), DAY), [])
        self.assertEqual(problems(entry(expires="2026-02-30"), DAY),
                         ["the entry at line 1: expires '2026-02-30' isn't a YYYY-MM-DD date"])

    def test_the_id_and_the_package(self):
        bad = entry().replace(b"CVE-2026-12345", b"CVE-26-1").replace(b"openssl", b"open ssl")
        self.assertEqual(problems(bad, DAY), ["the entry at line 1: 'CVE-26-1' isn't a CVE or GHSA id",
                                              "the entry at line 1: 'open ssl' isn't one package name"])


if __name__ == "__main__":
    unittest.main()
