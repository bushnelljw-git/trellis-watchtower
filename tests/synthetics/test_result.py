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
sys.path.insert(0, str(ROOT / "scripts"))

import catalogue as cat  # noqa: E402

from synthetics import result  # noqa: E402

GOLDEN_PASS = (
    '{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"staff-sign-in","outcome":"pass",'
    '"code":"ok","step":"none","status_class":"2xx","elapsed_ms":5222,"steps_ms":{"config":0,"egress":1012,'
    '"secrets":0,"iap_token":38,"ops_shell":61,"ops_release":22,"login":180,"mfa_verify":96,"me":41,'
    '"desk_version":133,"logout":35,"portal_shell":58}}'
)
GOLDEN_FAIL = (
    '{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"ops-desk","outcome":"fail",'
    '"code":"status","step":"live_queue","status_class":"5xx","elapsed_ms":16031,"steps_ms":{"config":0,'
    '"egress":1009,"secrets":0,"iap_token":40,"login":171,"mfa_verify":90,"live_queue":15001}}'
)
GOLDEN_ERROR = (
    '{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"staff-sign-in","outcome":"error",'
    '"code":"runner","step":"login","status_class":"none","elapsed_ms":1223,"steps_ms":{"config":0,'
    '"egress":1011,"secrets":0,"iap_token":41,"ops_shell":60,"ops_release":21,"login":88}}'
)
GOLDEN_EGRESS = (
    '{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"ops-desk","outcome":"error",'
    '"code":"egress","step":"egress","status_class":"none","elapsed_ms":120004,"steps_ms":{"config":0,'
    '"egress":120003}}'
)
GOLDEN_SKIP = (
    '{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"crm","outcome":"skipped",'
    '"code":"not_configured","step":"none","status_class":"none","elapsed_ms":0,"steps_ms":{}}'
)

# The sign-in robots (ruling SR-OR-1): a member's pass, a broker switched off (no verdict), a member whose
# /auth/me named more than its hat (a failure), and a passkey the runner could not sign (its error).
GOLDEN_MEMBER_PASS = (
    '{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"member-sign-in","outcome":"pass",'
    '"code":"ok","step":"none","status_class":"2xx","elapsed_ms":2310,"steps_ms":{"config":0,"egress":1008,'
    '"secrets":3,"portal_shell":58,"portal_release":21,"portal_bundle":44,"login":402,"mfa_verify":231,"me":38,'
    '"logout":30}}'
)
GOLDEN_BROKER_DISABLED = (
    '{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"broker-sign-in","outcome":"skipped",'
    '"code":"disabled","step":"none","status_class":"none","elapsed_ms":1561,"steps_ms":{"config":0,"egress":1007,'
    '"secrets":0,"portal_shell":61,"portal_release":20,"portal_bundle":40,"login":398}}'
)
GOLDEN_WIDENED = (
    '{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"member-sign-in","outcome":"fail",'
    '"code":"widened","step":"me","status_class":"2xx","elapsed_ms":2287,"steps_ms":{"config":0,"egress":1010,'
    '"secrets":3,"portal_shell":57,"portal_release":22,"portal_bundle":43,"login":405,"mfa_verify":229,"me":36}}'
)
GOLDEN_PASSKEY = (
    '{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"member-sign-in","outcome":"error",'
    '"code":"passkey","step":"mfa_verify","status_class":"none","elapsed_ms":1989,"steps_ms":{"config":0,'
    '"egress":1009,"secrets":3,"portal_shell":59,"portal_release":21,"portal_bundle":42,"login":401,'
    '"mfa_verify":1}}'
)
ROBOT_STEPS = ("config", "egress", "secrets", "portal_shell", "portal_release", "portal_bundle", "login",
               "mfa_verify", "me", "logout")


def robot_timings(*ms: int) -> dict[str, int]:
    """A sign-in robot's steps_ms: the steps it ran, in order, with these times."""
    return dict(zip(ROBOT_STEPS[: len(ms)], ms, strict=True))

PASS_FIELDS = dict(
    job="staff-sign-in", outcome="pass", code="ok", step="none", status_class="2xx", elapsed_ms=5222,
    steps_ms={"config": 0, "egress": 1012, "secrets": 0, "iap_token": 38, "ops_shell": 61, "ops_release": 22,
              "login": 180, "mfa_verify": 96, "me": 41, "desk_version": 133, "logout": 35, "portal_shell": 58},
)


class Golden(unittest.TestCase):
    def test_pass(self):
        self.assertEqual(result.render(**PASS_FIELDS), GOLDEN_PASS)

    def test_fail(self):
        self.assertEqual(result.render(
            job="ops-desk", outcome="fail", code="status", step="live_queue", status_class="5xx",
            elapsed_ms=16031,
            steps_ms={"config": 0, "egress": 1009, "secrets": 0, "iap_token": 40, "login": 171, "mfa_verify": 90,
                      "live_queue": 15001}), GOLDEN_FAIL)

    def test_error(self):
        self.assertEqual(result.render(
            job="staff-sign-in", outcome="error", code="runner", step="login", status_class="none",
            elapsed_ms=1223,
            steps_ms={"config": 0, "egress": 1011, "secrets": 0, "iap_token": 41, "ops_shell": 60,
                      "ops_release": 21, "login": 88}), GOLDEN_ERROR)

    def test_egress(self):
        # The warm-up's budget spent (Cloud NAT's cold start never ended): the runner's error, not a verdict.
        self.assertEqual(result.render(
            job="ops-desk", outcome="error", code="egress", step="egress", status_class="none",
            elapsed_ms=120004, steps_ms={"config": 0, "egress": 120003}), GOLDEN_EGRESS)

    def test_skip(self):
        self.assertEqual(result.render(job="crm", outcome="skipped", code="not_configured", step="none",
                                       status_class="none", elapsed_ms=0, steps_ms={}), GOLDEN_SKIP)

    def test_the_sign_in_robots(self):
        self.assertEqual(result.render(
            job="member-sign-in", outcome="pass", code="ok", step="none", status_class="2xx", elapsed_ms=2310,
            steps_ms=robot_timings(0, 1008, 3, 58, 21, 44, 402, 231, 38, 30)), GOLDEN_MEMBER_PASS)
        self.assertEqual(result.render(
            job="broker-sign-in", outcome="skipped", code="disabled", step="none", status_class="none",
            elapsed_ms=1561, steps_ms=robot_timings(0, 1007, 0, 61, 20, 40, 398)), GOLDEN_BROKER_DISABLED)
        self.assertEqual(result.render(
            job="member-sign-in", outcome="fail", code="widened", step="me", status_class="2xx", elapsed_ms=2287,
            steps_ms=robot_timings(0, 1010, 3, 57, 22, 43, 405, 229, 36)), GOLDEN_WIDENED)
        self.assertEqual(result.render(
            job="member-sign-in", outcome="error", code="passkey", step="mfa_verify", status_class="none",
            elapsed_ms=1989, steps_ms=robot_timings(0, 1009, 3, 59, 21, 42, 401, 1)), GOLDEN_PASSKEY)
        self.assertEqual(result.OUTCOME_OF["denied"], "fail")

    def test_readme_carries_the_same_lines(self):
        readme = (ROOT / "synthetics" / "README.md").read_text(encoding="utf-8")
        for golden in (GOLDEN_PASS, GOLDEN_FAIL, GOLDEN_ERROR, GOLDEN_EGRESS, GOLDEN_SKIP, GOLDEN_MEMBER_PASS,
                       GOLDEN_BROKER_DISABLED, GOLDEN_WIDENED, GOLDEN_PASSKEY):
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

    def test_every_code_and_outcome_passes_the_metrics_extractor(self):
        """The extractors of tpa-platform's metric, as vendored (cloud/catalogue/monitoring.yml): a value one
        does not match reaches the metric as an empty label."""
        extractors = cat.Catalogue().synthetics["synthetic_results"]["extractors"]
        for label, values in (("code", result.CODES), ("outcome", result.OUTCOMES)):
            pattern = re.fullmatch(r'REGEXP_EXTRACT\(jsonPayload\.\w+, "(.*)"\)', extractors[label]).group(1)
            for value in values:
                self.assertRegex(value, pattern, f"{label} {value}")

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
        # Switched off is no verdict (never a failure), and a passkey the runner could not sign is its own error.
        self.refuse(outcome="fail", code="disabled", step="login")
        self.refuse(outcome="fail", code="passkey", step="mfa_verify")
        self.refuse(outcome="skipped", code="widened")
        self.refuse(outcome="fail", code="runner", step="login")
        self.refuse(outcome="fail", code="egress", step="egress")
        self.refuse(outcome="error", code="status", step="login")
        self.refuse(outcome="error", code="ok")

    def test_every_code_has_one_outcome(self):
        self.assertEqual(set(result.OUTCOME_OF), set(result.CODES))
        self.assertEqual({c for c, o in result.OUTCOME_OF.items() if o == "error"},
                         {"config", "egress", "iap_token", "runner", "passkey"})
        self.assertEqual({c for c, o in result.OUTCOME_OF.items() if o == "pass"}, {"ok"})
        self.assertEqual({c for c, o in result.OUTCOME_OF.items() if o == "skipped"},
                         {"paused", "not_configured", "disabled"})

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
