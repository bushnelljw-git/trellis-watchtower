"""synthetics/Dockerfile against tpa-platform's image policy, read statically (no Docker).

`make synthetics-image-check` builds and starts the image; this holds the Dockerfile's shape on every
`make check`: a pinned base, the package's every module copied, standard library only, the strip
script byte for byte tpa-platform's and the last build step, then 10001:10001 and exec form.
"""

from __future__ import annotations

import ast
import hashlib
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


class Dockerfile(unittest.TestCase):
    def test_one_base_pinned_by_digest(self):
        froms = [args for name, args in instructions() if name == "FROM"]
        self.assertEqual(len(froms), 1)
        self.assertRegex(froms[0], r"^python:3\.12-slim@sha256:[0-9a-f]{64}$")

    def test_every_module_is_copied_and_nothing_else(self):
        copies = [args for name, args in instructions() if name == "COPY"]
        self.assertEqual(len(copies), 1)
        *sources, target = copies[0].split()
        self.assertEqual(target, "/usr/local/lib/python3.12/site-packages/synthetics/")
        self.assertEqual(sorted(sources), sorted(f"synthetics/{p.name}" for p in PACKAGE.glob("*.py")))

    def test_the_strip_is_the_last_build_step_then_the_user(self):
        steps = instructions()
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

    def test_no_package_installer(self):
        text = "\n".join(args for _name, args in instructions())
        self.assertNotRegex(text, r"pip\s+install|apt-get|apk add|curl|wget")

    def test_the_strip_script_is_tpa_platforms(self):
        self.assertEqual(hashlib.sha256(STRIP.read_bytes()).hexdigest(), STRIP_SHA256)

    def test_the_context_is_the_package_and_the_strip_script(self):
        ignore = (PACKAGE / "Dockerfile.dockerignore").read_text(encoding="utf-8")
        rules = [line for line in ignore.splitlines() if line and not line.startswith("#")]
        self.assertEqual(rules, ["*", "!synthetics/*.py", "!scripts/image_strip.py"])


class StandardLibraryOnly(unittest.TestCase):
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
                        self.assertTrue(top in sys.stdlib_module_names or top == "synthetics",
                                        f"{module.name} imports {name}, not the standard library")

    def test_nothing_prints_but_the_entry_point(self):
        for module in sorted(PACKAGE.glob("*.py")):
            text = module.read_text(encoding="utf-8")
            with self.subTest(module=module.name):
                self.assertNotRegex(text, r"\bprint\(|import logging|sys\.stderr|import traceback|traceback\.")
                if module.name != "__main__.py":
                    self.assertNotRegex(text, r"sys\.stdout")


if __name__ == "__main__":
    unittest.main()
