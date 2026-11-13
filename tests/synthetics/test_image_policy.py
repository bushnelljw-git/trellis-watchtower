"""synthetics/Dockerfile against tpa-platform's image policy, read statically (no Docker).

`make synthetics-image-check` builds and starts the image; this holds the Dockerfile's shape on every
`make check`: a pinned base, the package's every module copied, the standard library plus one package
(cryptography, for the member robot's passkey, and the two it requires, hash-locked as auth-notary locks
them, installed from wheels alone in a build stage), the strip script byte for byte tpa-platform's and the
last build step, then 10001:10001 and exec form.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "synthetics"
DOCKERFILE = PACKAGE / "Dockerfile"
STRIP = ROOT / "scripts" / "image_strip.py"
#: tpa-platform origin/master df51e3e0 scripts/image_strip.py (and auth-notary's, the same file). Moving it means
#: copying theirs again, byte for byte, and checking its PURGE list against the base.
STRIP_SHA256 = "e57c22c371e2e12546138beeed89b2bf8efe3d8df41a71884f390129ca8f0da2"
LOCK = PACKAGE / "requirements.lock"
#: The one third-party package the runner imports, and the one module that imports it (bodyfirst
#: tasks/signin-robots SECURITY-REVIEW.md SR-13: the passkey is signed by a vetted library, never by hand).
PACKAGE_IMPORTED = "cryptography"
IMPORTED_BY = "passkey.py"
#: What the lock installs: cryptography and what it requires (cffi, which requires pycparser), nothing else.
LOCKED = {"cryptography": "50.0.1", "cffi": "2.1.1", "pycparser": "3.0"}
#: auth-notary's lock the three are copied from, byte for byte (synthetics/requirements.lock's header).
AUTH_COMMIT = "eddeeadda804d762b7bf0e52b56b2e953a895f38"
AUTH_LOCK = "requirements/auth.lock.txt"
AUTH_LOCK_BLOB = "69ad035eb23fe660b2b170776b26b0d1708a675e"
BASE = "python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f"
#: The one list of Debian fixes the pinned base doesn't carry yet, the same pins as records-service's Dockerfile and
#: tpa-platform's images (DSA-6613-1). Remove an entry here and in the Dockerfile together once the base has it.
SECURITY_UPGRADES = ("zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1",)
UPGRADE_STEP = re.compile(r'^SECURITY_UPGRADES="([^"]*)" && (.*)$')
#: The build stage's one install: the lock's wheels alone, each checked against its hash, into a folder of its own.
INSTALL = ('["python", "-I", "-m", "pip", "install", "--no-cache-dir", "--disable-pip-version-check", "--no-input", '
           '"--require-hashes", "--only-binary", ":all:", "--no-deps", "--target", "/deps", "-r", '
           '"/tmp/requirements.lock"]')
ENTRY = re.compile(r"^([a-z0-9][a-z0-9._-]*)==(\S+) \\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", re.M)


def lock_entries(text: str) -> dict[str, str]:
    """Each `name==version` entry of a uv lock, its whole text (the pin and its hash lines)."""
    return {match.group(1): match.group(0) for match in ENTRY.finditer(text)}


def instructions() -> list[tuple[str, str]]:
    """(INSTRUCTION, arguments) with continuation lines joined and comments dropped."""
    joined: list[str] = []
    pending = ""
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        if not pending and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        joined.append(pending + line)
        pending = ""
    assert not pending
    return [(text.split(None, 1)[0].upper(), " ".join(text.split(None, 1)[1].split())) for text in joined]


def stages() -> list[list[tuple[str, str]]]:
    """The Dockerfile's stages, each its instructions from its FROM."""
    found: list[list[tuple[str, str]]] = []
    for name, args in instructions():
        if name == "FROM":
            found.append([])
        found[-1].append((name, args))
    return found


class Dockerfile(unittest.TestCase):
    def test_two_stages_on_one_base_pinned_by_digest(self):
        deps, image = stages()
        self.assertEqual(deps[0], ("FROM", f"{BASE} AS deps"))
        self.assertEqual(image[0], ("FROM", BASE))
        self.assertRegex(BASE, r"^python:3\.12-slim@sha256:[0-9a-f]{64}$")

    def test_the_build_stage_installs_the_lock_and_nothing_else(self):
        deps, _image = stages()
        self.assertEqual(deps[1:], [("COPY", "synthetics/requirements.lock /tmp/requirements.lock"),
                                    ("RUN", INSTALL)])

    def test_every_module_is_copied_after_the_locked_packages_and_nothing_else(self):
        _deps, image = stages()
        copies = [args for name, args in image if name == "COPY"]
        self.assertEqual(copies[0], "--from=deps /deps/ /usr/local/lib/python3.12/site-packages/")
        self.assertEqual(len(copies), 2)
        *sources, target = copies[1].split()
        self.assertEqual(target, "/usr/local/lib/python3.12/site-packages/synthetics/")
        self.assertEqual(sorted(sources), sorted(f"synthetics/{p.name}" for p in PACKAGE.glob("*.py")))

    def test_pip_check_before_the_strip(self):
        _deps, image = stages()
        runs = [args for name, args in image if name == "RUN"]
        self.assertEqual(runs[-2], '["python", "-I", "-m", "pip", "check"]')

    def test_the_strip_is_the_last_build_step_then_the_user(self):
        steps = stages()[-1]
        names = [name for name, _ in steps]
        runs = [i for i, name in enumerate(names) if name == "RUN"]
        last = steps[runs[-1]][1]
        self.assertEqual(
            last,
            '--mount=type=bind,source=scripts/image_strip.py,target=/tmp/image_strip.py '
            '["python", "-I", "-B", "/tmp/image_strip.py"]',
        )
        after = names[runs[-1] + 1:]
        self.assertEqual(after, ["USER", "ENTRYPOINT"])
        self.assertEqual(steps[runs[-1] + 1][1], "10001:10001")
        self.assertEqual(steps[-1][1], '["python", "-I", "-m", "synthetics"]')
        self.assertNotIn("CMD", names)
        self.assertNotIn("HEALTHCHECK", names)
        # python -I ignores every PYTHON* variable, so an ENV here would only mislead.
        self.assertNotIn("ENV", names)

    def test_no_other_package_installer(self):
        # The build stage's one pip install (above) is the lock's, and the final stage's one security-upgrade step
        # (below) only upgrades packages the base has; nothing else installs anything, anywhere.
        text = "\n".join(args for _name, args in instructions() if args != INSTALL and not UPGRADE_STEP.match(args))
        self.assertNotRegex(text, r"pip\W+install|\binstall\b|apt-get|apk add|curl|wget")

    # --- security upgrades (DSA-6613-1: CVE-2026-85091, CVE-2026-76844), as records-service's ----------------------

    def upgrade_steps(self):
        _deps, image = stages()
        return [(n, m) for n, (name, args) in enumerate(image) if name == "RUN" and (m := UPGRADE_STEP.match(args))]

    def test_the_security_upgrade_step_carries_the_one_list_of_pins(self):
        steps = self.upgrade_steps()
        self.assertEqual(len(steps), 1, 'exactly one RUN SECURITY_UPGRADES="..." step, in the final stage')
        pins = steps[0][1].group(1).split()
        self.assertEqual(tuple(pins), SECURITY_UPGRADES)
        for pin in pins:
            self.assertRegex(pin, r"^[a-z0-9][a-z0-9+.\-]*=[A-Za-z0-9:.+~\-]+$")

    def test_the_security_upgrade_step_installs_and_verifies_each_pin(self):
        (_, match), = self.upgrade_steps()
        body = match.group(2)
        self.assertIn("apt-get update", body)
        self.assertIn("apt-get install -y --no-install-recommends --only-upgrade $SECURITY_UPGRADES", body)
        self.assertIn("dpkg-query -W -f='${Version}' \"${pin%%=*}\"", body)
        self.assertIn('"${pin#*=}"', body)
        self.assertIn("exit 1", body)
        self.assertLess(body.index("apt-get install"), body.index("dpkg-query"))
        self.assertLess(body.index("dpkg-query"), body.index("apt-get clean"))
        self.assertTrue(body.rstrip().endswith("rm -rf /var/lib/apt/lists/*"))

    def test_the_security_upgrade_step_comes_first_in_the_final_stage(self):
        (at, _), = self.upgrade_steps()
        _deps, image = stages()
        self.assertEqual(at, 1, "right after the final stage's FROM, before the copies, pip check and the strip")

    def test_the_strip_script_is_tpa_platforms(self):
        self.assertEqual(hashlib.sha256(STRIP.read_bytes()).hexdigest(), STRIP_SHA256)

    def test_the_context_is_the_package_its_lock_and_the_strip_script(self):
        ignore = (PACKAGE / "Dockerfile.dockerignore").read_text(encoding="utf-8")
        rules = [line for line in ignore.splitlines() if line and not line.startswith("#")]
        self.assertEqual(rules, ["*", "!synthetics/*.py", "!synthetics/requirements.lock", "!scripts/image_strip.py"])


class TheLock(unittest.TestCase):
    """synthetics/requirements.lock: exactly cryptography and what it requires, auth-notary's entries byte for byte."""

    def test_exactly_the_three_each_pinned_with_hashes(self):
        text = LOCK.read_text(encoding="utf-8")
        entries = lock_entries(text)
        self.assertEqual({name: entry.split("==", 1)[1].split()[0] for name, entry in entries.items()}, LOCKED)
        for name, entry in entries.items():
            with self.subTest(package=name):
                self.assertGreaterEqual(entry.count("--hash=sha256:"), 1)
        # Nothing in the file but the header and these entries: no index, no option, no other requirement.
        body = "".join(line + "\n" for line in text.splitlines() if not line.startswith("#"))
        self.assertEqual(body, "".join(entries[name] for name in sorted(entries)))

    def test_the_entries_are_auth_notarys(self):
        sibling = Path(os.environ.get("AUTH_NOTARY_DIR") or ROOT.parent / "auth-notary")
        if not (sibling / ".git").exists():
            self.skipTest(f"no auth-notary checkout at {sibling}; the lock is used as pinned")

        def git(*args: str) -> str:
            return subprocess.run(["git", "-C", str(sibling), *args], capture_output=True, text=True,
                                  check=True, timeout=30).stdout

        spec = f"{AUTH_COMMIT}:{AUTH_LOCK}"
        try:
            self.assertEqual(git("rev-parse", spec).strip(), AUTH_LOCK_BLOB, "the pinned blob")
        except subprocess.CalledProcessError:
            self.skipTest("the sibling checkout does not have the pinned commit; fetch there first")
        ours = lock_entries(LOCK.read_text(encoding="utf-8"))
        pinned = lock_entries(git("show", spec))
        for name in LOCKED:
            with self.subTest(package=name):
                self.assertEqual(ours[name], pinned[name], "byte for byte the pinned lock's entry")
        try:
            current = lock_entries(git("show", f"origin/master:{AUTH_LOCK}"))
        except subprocess.CalledProcessError:
            self.skipTest("the sibling checkout has no origin/master")
        for name in LOCKED:
            with self.subTest(package=name, ref="origin/master"):
                self.assertEqual(ours[name], current.get(name),
                                 "auth-notary moved its pin on origin/master: copy its entries and the pins again")


class StandardLibraryPlusOnePackage(unittest.TestCase):
    def test_every_import(self):
        for module in sorted(PACKAGE.glob("*.py")):
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    with self.subTest(module=module.name, imports=name):
                        allowed = top in sys.stdlib_module_names or top == "synthetics" or (
                            top == PACKAGE_IMPORTED and module.name == IMPORTED_BY)
                        self.assertTrue(allowed, f"{module.name} imports {name}: not the standard library, and not "
                                                 f"{PACKAGE_IMPORTED} in {IMPORTED_BY}")

    def test_the_one_package_is_imported_where_it_is_used(self):
        text = (PACKAGE / IMPORTED_BY).read_text(encoding="utf-8")
        self.assertIn("from cryptography.hazmat.primitives.asymmetric import ec", text)
        self.assertNotRegex(text, r"\bimport (secrets|random)\b", "the nonce is the library's, never ours")

    def test_nothing_prints_but_the_entry_point(self):
        for module in sorted(PACKAGE.glob("*.py")):
            text = module.read_text(encoding="utf-8")
            with self.subTest(module=module.name):
                self.assertNotRegex(text, r"\bprint\(|import logging|sys\.stderr|import traceback|traceback\.")
                if module.name != "__main__.py":
                    self.assertNotRegex(text, r"sys\.stdout")


if __name__ == "__main__":
    unittest.main()
