"""cloud/Dockerfile's pins, read statically (no Docker).

`make cloud-image-check` builds and runs the image; this holds what makes the build reproducible and fetched only by
hash on every `make check`: every base pinned by digest, Grafana's source by its commit, its modules by its own
go.sum (-mod=readonly, no toolchain download) and the one it raises (go-jose) by its pinned go.sum lines, the Alpine
packages by sha256 and installed with no repository, the rebuilt binaries' module list held to the official one's but
for the raised line, and no build argument.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "cloud" / "Dockerfile"
#: Grafana's public v12.4.14 release commit (git ls-remote: refs/tags/v12.4.14^{}).
GRAFANA_COMMIT = "3c98af3ba0773ad12a8a54b1faec7dc62d8d6725"
#: The Alpine 3.24 packages installed over the base's (tpa-platform's builds 4122c0b2, b5453d1f and ef0194fb), each fetched for
#: both architectures by its sha256 from Alpine's own repository.
PACKAGES = ("zlib-1.3.2-r1", "musl-1.2.6-r3", "musl-utils-1.2.6-r3", "brotli-libs-1.2.1-r0",
            "curl-8.23.0-r0", "libcurl-8.23.0-r0")
ARCHES = ("x86_64", "aarch64")
#: The module raised in grafana (build ef0194fb: go-jose v4 HIGH, fixed in v4.1.6): the official binary's version, the
#: fixed one, and the fixed one's go.sum hashes as sum.golang.org lists them (its zip, then its go.mod).
RAISED = {
    "github.com/go-jose/go-jose/v4": (
        "v4.1.4", "v4.1.6", "h1:sNRkftxFJxwsILiQukqp5z83QBSmntVwmgRY7AqBDO4=",
        "h1:x4oUasVrzR7071A4TnHLGSPpNOm2a21K9Kf04k1rs08="),
}


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
        self.assertRegex(seen["grafana"], r"^grafana/grafana:12\.4\.14@sha256:[0-9a-f]{64}$")
        self.assertRegex(seen["grafana-build"], r"^golang:1\.26\.10-alpine3\.24@sha256:[0-9a-f]{64}$")

    def test_every_fetch_carries_its_hash(self):
        adds = [args for name, args in instructions() if name == "ADD"]
        self.assertEqual(len(adds), 1 + len(PACKAGES) * len(ARCHES))
        for args in adds:
            self.assertRegex(args, r"^--checksum=(sha256:[0-9a-f]{64}|[0-9a-f]{40}) https://")
        self.assertIn(f"--checksum={GRAFANA_COMMIT} https://github.com/grafana/grafana.git#v12.4.14 /", adds)

    def test_each_package_for_both_architectures_from_alpine_324_main(self):
        adds = [args for name, args in stages()["zlib"] if name == "ADD"]
        fetched = []
        for args in adds:
            m = re.fullmatch(r"--checksum=sha256:[0-9a-f]{64} https://dl-cdn\.alpinelinux\.org/alpine/v3\.24/main/"
                             r"(x86_64|aarch64)/([a-z0-9.-]+)\.apk /\1/\2\.apk", args)
            self.assertIsNotNone(m, args)
            fetched.append(m.groups())
        self.assertEqual(sorted(fetched), sorted((arch, package) for arch in ARCHES for package in PACKAGES))
        self.assertEqual(len({args.split()[0] for args in adds}), len(adds), "two packages share a sha256")

    def test_the_start_checks_five_stages_by_name(self):
        # tpa-platform's scripts/image_start_check.sh stands in grafana-build only on exactly this shape.
        froms = [args for name, args in instructions() if name == "FROM"]
        self.assertEqual(len(froms), 5)
        self.assertEqual(sorted(stage for stage in stages() if stage != "image"),
                         ["grafana", "grafana-build", "grafana-source", "zlib"])
        self.assertEqual(froms[-1], "grafana")

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
        self.assertIn('test "$(go env GOVERSION)" = "go1.26.10";', self.run)
        # Nothing may resolve a module or skip a checksum: no go get, tidy or -mod=mod, no sum database bypass.
        text = DOCKERFILE.read_text(encoding="utf-8")
        for shortcut in ("-mod=mod", "go get", "go mod tidy", "GONOSUMDB", "GONOPROXY", "GOPRIVATE", "GOINSECURE",
                         "GOSUMDB=off", "GOFLAGS=-insecure"):
            self.assertNotIn(shortcut, text)

    def test_go_jose_raised_with_its_pinned_sums(self):
        edit = "go mod edit " + " ".join(f"-require={path}@{new}" for path, (_, new, _, _) in RAISED.items()) + ";"
        self.assertIn(edit, self.run)
        self.assertEqual(self.run.count("go mod edit"), 1)
        sums = " ".join(f"'{path} {new} {zip_h1}' '{path} {new}/go.mod {mod_h1}'"
                        for path, (_, new, zip_h1, mod_h1) in RAISED.items())
        self.assertIn(f"printf '%s\\n' {sums} >> go.sum;", self.run)
        # Raised before anything is built.
        self.assertLess(self.run.index(">> go.sum;"), self.run.index("go build"))

    def test_built_as_grafanas_release_build_and_stamped_with_the_commit_built(self):
        self.assertIn('go build -buildvcs=false -trimpath -ldflags "$stamps"', self.run)
        self.assertIn(f"-X main.commit={GRAFANA_COMMIT}", self.run)
        self.assertIn("-X main.version=12.4.14", self.run)
        self.assertIn("for cmd in grafana grafana-server grafana-cli; do", self.run)

    def test_the_module_list_is_held_to_the_official_binarys(self):
        self.assertIn("COPY --from=grafana /usr/share/grafana/bin/ /w/official/",
                      [f"{name} {args}" for name, args in stages()["grafana-build"]])
        self.assertIn('cmp "/w/$cmd.official" "/w/$cmd.rebuilt";', self.run)
        self.assertIn('test "$(go version "/out/$cmd")" = "/out/$cmd: go1.26.10";', self.run)
        self.assertIn('go version -m "/out/$cmd" | sed 1d > "/w/$cmd.rebuilt";', self.run)

    def test_the_official_list_changes_by_the_raised_line_alone(self):
        # Exactly one rewrite per raised module, from the official version and hash to the pinned ones, then every
        # line printed: the official list as it is, but for that line.
        program = " ".join(f'$3 == "{path}" && $4 == "{old}" {{ $4 = "{new}"; $5 = "{zip_h1}" }};'
                           for path, (old, new, zip_h1, _) in RAISED.items()) + " { print }"
        self.assertIn(f"""go version -m "/w/official/$cmd" | sed 1d | awk -F '\\t' -v OFS='\\t' ' {program}' """
                      '> "/w/$cmd.official";', self.run)


class Image(unittest.TestCase):
    def test_the_hashed_packages_alone_then_the_rebuilt_binaries(self):
        steps = stages()["image"]
        runs = [args for name, args in steps if name == "RUN"]
        self.assertTrue(runs[0].startswith("--mount=type=bind,from=zlib,target=/mnt/apk "))
        files = " ".join(f'"/mnt/apk/$arch/{package}.apk"' for package in PACKAGES)
        self.assertIn(f'arch="$(apk --print-arch)"; apk --repositories-file=/dev/null add --no-cache {files};',
                      runs[0])
        self.assertEqual(runs[0].count("apk --repositories-file"), 1)
        self.assertNotRegex(" ".join(runs[1:]), r"\bapk\b")
        self.assertIn(("COPY", "--from=grafana-build /out/grafana /out/grafana-server /out/grafana-cli "
                               "/usr/share/grafana/bin/"), steps)

    def test_every_package_of_the_four_origins_is_the_fixed_one(self):
        # As the scan reads them: by origin (brotli for brotli-libs), from apk's installed database.
        run = [args for name, args in stages()["image"] if name == "RUN"][0]
        expected = " ".join(sorted(PACKAGES)) + " "
        self.assertIn("""test "$(awk -F: '/^P:/ { p = $2 }; /^V:/ { v = $2 }; /^o:(brotli|curl|musl|zlib)$/ """
                      """{ print p "-" v }' /lib/apk/db/installed | sort | tr '\\n' ' ')" = """
                      f'"{expected}"', run)
        self.assertTrue(run.endswith(f'= "{expected}"'))

    def test_runs_as_10001(self):
        names = [name for name, _ in stages()["image"]]
        self.assertEqual(names[-3:], ["USER", "EXPOSE", "ENTRYPOINT"])
        self.assertEqual(stages()["image"][-3][1], "10001:10001")


if __name__ == "__main__":
    unittest.main()
