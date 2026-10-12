"""cloud/Dockerfile's pins, read statically (no Docker).

`make cloud-image-check` builds and runs the image; this holds what makes the build reproducible and fetched only by
hash on every `make check`: every base pinned by digest, Grafana's source by its commit, its modules by its own
go.sum (-mod=readonly, no toolchain download), the zlib package by sha256 and installed with no repository, the
rebuilt binaries' module list held to the official one's, and no build argument.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "cloud" / "Dockerfile"
#: Grafana's public v12.4.12 release commit (git ls-remote: refs/tags/v12.4.12^{}).
GRAFANA_COMMIT = "60d1cb9522f234508f98e9c88295cc920c965d10"


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


def stages() -> dict[str, list[tuple[str, str]]]:
    """Each stage's instructions, by its name (the last, unnamed one is ``image``)."""
    named: dict[str, list[tuple[str, str]]] = {}
    current: list[tuple[str, str]] = []
    for name, args in instructions():
        if name == "FROM":
            current = [(name, args)]
            stage = re.search(r" AS ([a-z][a-z0-9-]*)$", args)
            named[stage.group(1) if stage else "image"] = current
        else:
            current.append((name, args))
    return named


class Pins(unittest.TestCase):
    def test_every_base_is_pinned_and_the_image_is_grafanas(self):
        seen: dict[str, str] = {}
        for name, args in instructions():
            if name != "FROM":
                continue
            base, _, stage = args.partition(" AS ")
            pinned = re.fullmatch(r"[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}", base)
            self.assertTrue(base == "scratch" or base in seen or pinned, f"FROM {args} is not pinned")
            if stage:
                seen[stage] = seen.get(base, base)
        self.assertEqual(stages()["image"][0][1], "grafana")
        self.assertRegex(seen["grafana"], r"^grafana/grafana:12\.4\.12@sha256:[0-9a-f]{64}$")
        self.assertRegex(seen["grafana-build"], r"^golang:1\.26\.9-alpine3\.24@sha256:[0-9a-f]{64}$")

    def test_every_fetch_carries_its_hash(self):
        adds = [args for name, args in instructions() if name == "ADD"]
        self.assertEqual(len(adds), 3)
        for args in adds:
            self.assertRegex(args, r"^--checksum=(sha256:[0-9a-f]{64}|[0-9a-f]{40}) https://")
        self.assertIn(f"--checksum={GRAFANA_COMMIT} https://github.com/grafana/grafana.git#v12.4.12 /", adds)

    def test_no_build_argument(self):
        self.assertNotIn("ARG", [name for name, _ in instructions()])


class GrafanaBuild(unittest.TestCase):
    def setUp(self):
        steps = stages()["grafana-build"]
        self.env = next(args for name, args in steps if name == "ENV")
        self.run = next(args for name, args in steps if name == "RUN")

    def test_modules_only_from_grafanas_own_sums_and_the_pinned_go(self):
        for setting in ("CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly",
                        "GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org"):
            self.assertIn(setting, self.env.split())
        self.assertIn('test "$(go env GOVERSION)" = "go1.26.9";', self.run)

    def test_built_as_grafanas_release_build_and_stamped_with_the_commit_built(self):
        self.assertIn('go build -buildvcs=false -trimpath -ldflags "$stamps"', self.run)
        self.assertIn(f"-X main.commit={GRAFANA_COMMIT}", self.run)
        self.assertIn("-X main.version=12.4.12", self.run)
        self.assertIn("for cmd in grafana grafana-server grafana-cli; do", self.run)

    def test_the_module_list_is_held_to_the_official_binarys(self):
        self.assertIn("COPY --from=grafana /usr/share/grafana/bin/ /w/official/",
                      [f"{name} {args}" for name, args in stages()["grafana-build"]])
        self.assertIn('cmp "/w/$cmd.official" "/w/$cmd.rebuilt";', self.run)
        self.assertIn('test "$(go version "/out/$cmd")" = "/out/$cmd: go1.26.9";', self.run)


class Image(unittest.TestCase):
    def test_zlib_from_the_hashed_package_alone_then_the_rebuilt_binaries(self):
        steps = stages()["image"]
        runs = [args for name, args in steps if name == "RUN"]
        self.assertTrue(runs[0].startswith("--mount=type=bind,from=zlib,target=/mnt/zlib "))
        self.assertIn('apk --repositories-file=/dev/null add --no-cache "/mnt/zlib/$(apk --print-arch)/'
                      'zlib-1.3.2-r1.apk";', runs[0])
        self.assertNotRegex(" ".join(runs[1:]), r"\bapk\b")
        self.assertIn(("COPY", "--from=grafana-build /out/grafana /out/grafana-server /out/grafana-cli "
                               "/usr/share/grafana/bin/"), steps)

    def test_runs_as_10001(self):
        names = [name for name, _ in stages()["image"]]
        self.assertEqual(names[-3:], ["USER", "EXPOSE", "ENTRYPOINT"])
        self.assertEqual(stages()["image"][-3][1], "10001:10001")


if __name__ == "__main__":
    unittest.main()
