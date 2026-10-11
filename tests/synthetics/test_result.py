"""The result line, pinned byte for byte (golden): tpa-platform's `synthetic_results` log metric
reads it, so a change here is a change to that lane's contract and to synthetics/README.md."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from synthetics import result  # noqa: E402

GOLDEN_PASS = (
    '{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"staff-sign-in","outcome":"pass",'
    '"code":"ok","step":"none","status_class":"2xx","elapsed_ms":4210,"steps_ms":{"config":0,"secrets":0,'
    '"iap_token":38,"ops_shell":61,"ops_release":22,"login":180,"mfa_verify":96,"me":41,"desk_version":133,'
    '"logout":35,"portal_shell":58}}'
)
GOLDEN_FAIL = (
    '{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"ops-desk","outcome":"fail",'
    '"code":"status","step":"live_queue","status_class":"5xx","elapsed_ms":15022,"steps_ms":{"config":0,'
    '"secrets":0,"iap_token":40,"login":171,"mfa_verify":90,"live_queue":15001}}'
)
GOLDEN_ERROR = (
    '{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"staff-sign-in","outcome":"error",'
    '"code":"runner","step":"login","status_class":"none","elapsed_ms":212,"steps_ms":{"config":0,"secrets":0,'
    '"iap_token":41,"ops_shell":60,"ops_release":21,"login":88}}'
)
GOLDEN_SKIP = (
    '{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"crm","outcome":"skipped",'
    '"code":"not_configured","step":"none","status_class":"none","elapsed_ms":0,"steps_ms":{}}'
)

PASS_FIELDS = dict(
    job="staff-sign-in", outcome="pass", code="ok", step="none", status_class="2xx", elapsed_ms=4210,
    steps_ms={"config": 0, "secrets": 0, "iap_token": 38, "ops_shell": 61, "ops_release": 22, "login": 180,
              "mfa_verify": 96, "me": 41, "desk_version": 133, "logout": 35, "portal_shell": 58},
)


class Golden(unittest.TestCase):
    def test_pass(self):
        self.assertEqual(result.render(**PASS_FIELDS), GOLDEN_PASS)

    def test_fail(self):
        self.assertEqual(result.render(
            job="ops-desk", outcome="fail", code="status", step="live_queue", status_class="5xx",
            elapsed_ms=15022,
            steps_ms={"config": 0, "secrets": 0, "iap_token": 40, "login": 171, "mfa_verify": 90,
                      "live_queue": 15001}), GOLDEN_FAIL)

    def test_error(self):
        self.assertEqual(result.render(
            job="staff-sign-in", outcome="error", code="runner", step="login", status_class="none",
            elapsed_ms=212,
            steps_ms={"config": 0, "secrets": 0, "iap_token": 41, "ops_shell": 60, "ops_release": 21,
                      "login": 88}), GOLDEN_ERROR)

    def test_skip(self):
        self.assertEqual(result.render(job="crm", outcome="skipped", code="not_configured", step="none",
                                       status_class="none", elapsed_ms=0, steps_ms={}), GOLDEN_SKIP)

    def test_readme_carries_the_same_lines(self):
        readme = (ROOT / "synthetics" / "README.md").read_text(encoding="utf-8")
        for golden in (GOLDEN_PASS, GOLDEN_FAIL, GOLDEN_ERROR, GOLDEN_SKIP):
            self.assertIn(golden, readme)
        for values in (result.JOBS, result.OUTCOMES, result.CODES, result.STEPS, result.STATUS_CLASSES):
            for value in values:
                self.assertIn(f"`{value}`", readme)

    def test_status_class(self):
        for status, expected in [(200, "2xx"), (204, "2xx"), (302, "3xx"), (401, "4xx"), (503, "5xx"),
                                 (None, "none"), (99, "none"), (600, "none")]:
            self.assertEqual(result.status_class(status), expected)


LABELS_FILE = Path(__file__).resolve().parent / "tpa_metric_labels.txt"
#: What tpa-platform's `synthetic_results` metric extracts as labels (design §3, piece 5).
METRIC_LABELS = {"job", "outcome", "code", "status_class"}
ALLOWLIST = re.compile(r'contains\(\[([^\]]*)\],\s*label\)')


def vendored_labels() -> tuple[dict[str, str], list[str]]:
    pins = dict(line.split("=", 1) for line in LABELS_FILE.read_text(encoding="utf-8").splitlines()
                if line and not line.startswith("#"))
    return pins, pins["labels"].split(",")


def labels_in(variables_tf: str) -> list[str]:
    found = ALLOWLIST.findall(variables_tf)
    assert len(found) == 1, "exactly one label allowlist in variables.tf"
    return re.findall(r'"([^"]+)"', found[0])


class Labels(unittest.TestCase):
    """The result line's labels against tpa-platform's own allowlist (docs/infra/monitoring.md §2)."""

    def test_the_metric_labels_are_on_the_vendored_allowlist(self):
        _pins, labels = vendored_labels()
        self.assertLessEqual(METRIC_LABELS, set(labels))
        self.assertNotIn("step", labels, "step is a field of the line, not a label (README)")

    def test_the_vendored_allowlist_is_tpa_platforms(self):
        sibling = Path(os.environ.get("TPA_PLATFORM_DIR") or ROOT.parent / "tpa-platform")
        if not (sibling / ".git").exists():
            self.skipTest(f"no tpa-platform checkout at {sibling}; the vendored list is used as pinned")
        pins, labels = vendored_labels()

        def git(*args: str) -> str:
            return subprocess.run(["git", "-C", str(sibling), *args], capture_output=True, text=True,
                                  check=True, timeout=30).stdout

        spec = f"{pins['commit']}:{pins['path']}"
        self.assertEqual(git("rev-parse", spec).strip(), pins["blob"], "the pinned blob")
        self.assertEqual(labels_in(git("show", spec)), labels, "the vendored list is the pinned blob's")
        try:
            current = git("show", f"origin/master:{pins['path']}")
        except subprocess.CalledProcessError:
            self.skipTest("the sibling checkout has no origin/master")
        self.assertEqual(labels_in(current), labels,
                         "tpa-platform's label allowlist moved on origin/master: re-vendor tpa_metric_labels.txt")


class Refusals(unittest.TestCase):
    def refuse(self, **changes):
        fields = dict(PASS_FIELDS, **changes)
        with self.assertRaises(result.Unrenderable) as raised:
            result.render(**fields)
        for value in changes.values():
            if isinstance(value, str) and value not in ("pass", "fail", "skipped", "ok", "none"):
                self.assertNotIn(value, str(raised.exception))

    def test_off_the_lists(self):
        self.refuse(job="https://ops.example.com/members/123")
        self.refuse(code="Traceback (most recent call last)")
        self.refuse(outcome="error")
        self.refuse(status_class="503")
        self.refuse(outcome="fail", code="status", step="prn_0a5e")
        self.refuse(steps_ms={"/auth/me": 3})
        self.refuse(steps_ms={"none": 3})

    def test_outcome_and_code_agree(self):
        self.refuse(code="status")
        self.refuse(outcome="skipped", code="ok")
        self.refuse(outcome="fail", code="ok", step="login")
        self.refuse(outcome="fail", code="paused", step="login")
        # A broken runner is never a check's verdict, and a check's verdict never the runner's error.
        self.refuse(outcome="fail", code="config", step="config")
        self.refuse(outcome="fail", code="runner", step="login")
        self.refuse(outcome="error", code="status", step="login")
        self.refuse(outcome="error", code="ok")

    def test_every_code_has_one_outcome(self):
        self.assertEqual(set(result.OUTCOME_OF), set(result.CODES))
        self.assertEqual({c for c, o in result.OUTCOME_OF.items() if o == "error"}, {"config", "iap_token", "runner"})
        self.assertEqual({c for c, o in result.OUTCOME_OF.items() if o == "pass"}, {"ok"})
        self.assertEqual({c for c, o in result.OUTCOME_OF.items() if o == "skipped"}, {"paused", "not_configured"})

    def test_steps(self):
        # A failure names its step; a pass or a skip names none; an error names where it broke, if anywhere.
        self.refuse(outcome="fail", code="status", step="none")
        self.refuse(step="login")
        self.refuse(outcome="skipped", code="paused", step="login")
        result.render(**dict(PASS_FIELDS, outcome="error", code="runner", step="none", status_class="none"))

    def test_durations_are_whole_milliseconds(self):
        self.refuse(elapsed_ms=-1)
        self.refuse(elapsed_ms=1.5)
        self.refuse(elapsed_ms=True)
        self.refuse(elapsed_ms="12")
        self.refuse(steps_ms={"login": "secret-value"})


if __name__ == "__main__":
    unittest.main()
