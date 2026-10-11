"""The one result line a run writes, and the closed lists every value in it comes from.

tpa-platform's log metric `synthetic_results` reads this line from the job's
stdout (Cloud Logging's jsonPayload): its filter is
`jsonPayload.message="synthetic_result"`, and its labels are `job`, `outcome`,
`code` and `status_class`, all on tpa-platform's docs/infra/monitoring.md §2
closed label list. tests/synthetics/test_result.py pins the line byte for byte,
and synthetics/README.md carries the same format for that lane.

Every value is either one of the closed lists below or a whole number of
milliseconds. `render` refuses anything else, so no id, URL, address, token,
cookie, code, password, response body or exception text can reach the line.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

MESSAGE = "synthetic_result"

JOBS = ("staff-sign-in", "ops-desk", "crm")

OUTCOMES = ("pass", "fail", "skipped")

#: Why a run ended as it did. `ok` is the only pass; `paused` and
#: `not_configured` the only skips; the rest are failures.
CODES = (
    "ok",
    "paused",
    "not_configured",
    "config",
    "iap_token",
    "iap",
    "connect",
    "tls",
    "timeout",
    "redirect",
    "status",
    "credentials",
    "locked",
    "rate_limited",
    "csrf",
    "shape",
    "internal",
)
PASS_CODES = ("ok",)
SKIP_CODES = ("paused", "not_configured")

#: The steps, in the order the journeys take them. `none` is a run that did not
#: fail (a pass, or a skip before any step).
STEPS = (
    "none",
    "config",
    "secrets",
    "iap_token",
    "ops_shell",
    "ops_release",
    "crm_shell",
    "login",
    "mfa_verify",
    "me",
    "desk_version",
    "live_queue",
    "desk_version_employers",
    "logout",
    "portal_shell",
)

STATUS_CLASSES = ("2xx", "3xx", "4xx", "5xx", "none")

SEVERITY = {"pass": "INFO", "skipped": "INFO", "fail": "ERROR"}


class Unrenderable(ValueError):
    """A value outside the closed lists. Never carries the value itself."""


def status_class(status: int | None) -> str:
    if status is None or not 200 <= status <= 599:
        return "none"
    return f"{status // 100}xx"


def _ms(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Unrenderable("a duration is not a whole, non-negative number of milliseconds")
    return value


def render(
    *,
    job: str,
    outcome: str,
    code: str,
    step: str,
    status_class: str,
    elapsed_ms: int,
    steps_ms: Mapping[str, int],
) -> str:
    """The line, keys in this fixed order, compact JSON, no trailing newline."""
    if job not in JOBS:
        raise Unrenderable("job is not on the closed list")
    if outcome not in OUTCOMES:
        raise Unrenderable("outcome is not on the closed list")
    if code not in CODES:
        raise Unrenderable("code is not on the closed list")
    if outcome == "pass" and code not in PASS_CODES:
        raise Unrenderable("a pass carries code ok")
    if outcome == "skipped" and code not in SKIP_CODES:
        raise Unrenderable("a skip carries code paused or not_configured")
    if outcome == "fail" and code in PASS_CODES + SKIP_CODES:
        raise Unrenderable("a failure carries a failure code")
    if step not in STEPS:
        raise Unrenderable("step is not on the closed list")
    if (outcome == "fail") == (step == "none"):
        raise Unrenderable("a failure names its step, and only a failure does")
    if status_class not in STATUS_CLASSES:
        raise Unrenderable("status_class is not on the closed list")
    timings = {}
    for name, value in steps_ms.items():
        if name not in STEPS or name == "none":
            raise Unrenderable("a timed step is not on the closed list")
        timings[name] = _ms(value)
    line = {
        "severity": SEVERITY[outcome],
        "level": SEVERITY[outcome],
        "message": MESSAGE,
        "job": job,
        "outcome": outcome,
        "code": code,
        "step": step,
        "status_class": status_class,
        "elapsed_ms": _ms(elapsed_ms),
        "steps_ms": timings,
    }
    return json.dumps(line, separators=(",", ":"), ensure_ascii=True)

