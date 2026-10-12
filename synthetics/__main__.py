"""`python -m synthetics journey <staff-sign-in|ops-desk|crm> [--no-iap]`.

One run, one result line on stdout (result.py), nothing on stderr but argparse's
usage on a bad command line.

Exit status (the orchestrator's ruling, 2026-10-11, following design §3): **0
whenever the journey ran to a verdict**, `pass`, `fail` or `skipped`, because the
result line alone drives `synthetic-failing`. **Non-zero only when the runner
itself broke**, so the job's own `jobs-failed` means "the job is broken" and one
failure never pages twice:
- 1: an `error` line (`config`: a setting or the mounted credentials unusable;
  `egress`: the run's own network path to the edge never came up; `runner`: an
  unexpected exception), or the line could not be written at all;
- 2: a bad command line (argparse; no line, since no journey was named).

- `SYNTHETICS_PAUSED` true (a database stopped on purpose): `skipped` / `paused`
  at once, before the egress warm-up, with no connection or request of any kind.
- `--no-iap`: the local mode, for this machine's own stack (https://localhost:4310),
  which has no IAP. No metadata call, no `Proxy-Authorization`, and every base URL
  must be a loopback host.

No exception escapes: anything unexpected is `error` / `runner` at the step it
happened in, with no exception text anywhere.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Mapping, Sequence
from typing import TextIO

from synthetics import result
from synthetics.client import StepFailure
from synthetics.journeys import JOURNEYS, Run, Skip, Tools, truthy


def parse(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="synthetics", description="Run one synthetic journey.")
    commands = parser.add_subparsers(dest="command", required=True)
    journey = commands.add_parser("journey", help="run one journey and write its result line")
    journey.add_argument("name", choices=sorted(JOURNEYS))
    journey.add_argument("--no-iap", action="store_true",
                         help="local mode: no IAP token; loopback base URLs only")
    return parser.parse_args(list(argv))


def run(
    name: str,
    env: Mapping[str, str],
    *,
    use_iap: bool,
    tools: Tools | None = None,
    stream: TextIO | None = None,
) -> int:
    started = time.monotonic()
    state = Run(job=name)
    outcome, code, step, status = "pass", "ok", "none", None
    try:
        if truthy(env, "SYNTHETICS_PAUSED"):
            raise Skip("paused")
        JOURNEYS[name](state, env, use_iap=use_iap, tools=tools or Tools())
        status = state.last_status
    except Skip as skipped:
        outcome, code = "skipped", skipped.code
    except StepFailure as failed:
        code, step, status = failed.code, state.step, failed.status
        outcome = result.OUTCOME_OF.get(code, "error")
    except Exception:  # noqa: BLE001 - one line, never a traceback (it could carry a value)
        outcome, code, step, status = "error", "runner", state.step, None
    elapsed_ms = int((time.monotonic() - started) * 1000)
    try:
        line = result.render(job=name, outcome=outcome, code=code, step=step,
                             status_class=result.status_class(status), elapsed_ms=elapsed_ms,
                             steps_ms=state.steps_ms)
    except result.Unrenderable:
        # A value off the closed lists is a bug here: still exactly one line, as the runner's error.
        outcome = "error"
        line = result.render(job=name, outcome="error", code="runner",
                             step=step if step in result.STEPS else "none",
                             status_class="none", elapsed_ms=elapsed_ms, steps_ms={})
    out = stream if stream is not None else sys.stdout
    try:
        out.write(line + "\n")
        out.flush()
    except (OSError, ValueError):
        return 1  # the line could not be written: the runner is broken, whatever the verdict
    return 1 if outcome == "error" else 0


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = parse(sys.argv[1:] if argv is None else argv)
    return run(args.name, os.environ if env is None else env, use_iap=not args.no_iap)


if __name__ == "__main__":
    sys.exit(main())
