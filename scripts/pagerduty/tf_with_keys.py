#!/usr/bin/env python3
"""trellis-watchtower: run one `terraform plan` or `terraform apply` with the PagerDuty keys in its environment.

tpa-platform's Terraform makes each TPA project's `pagerduty` notification channel (D-142, D-143). The apply that
first creates the channels, or replaces one to rotate its key, needs the three services' "Google Cloud Monitoring"
integration keys as `pagerduty_service_keys`. This script reads them from PagerDuty and runs the command it is given
with one variable added to that command's environment:

    TF_VAR_pagerduty_service_keys = {"app": "…", "phi": "…", "cc": "…"}

    app  <-  "TPA beta · Portal & API"
    phi  <-  "TPA beta · Member records"
    cc   <-  "TPA beta · Call centre"

The keys go into the child's environment and nowhere else: never on a command line, never in a file, never printed.
The child gets this process's environment without PAGERDUTY_TOKEN. Before Terraform runs, the script prints one line
on stderr saying which keys it found, and stops if any service or integration is missing.

Usage:
  scripts/pagerduty/tf_with_keys.py -- terraform -chdir=infra/envs/beta plan
  scripts/pagerduty/tf_with_keys.py -- terraform -chdir=infra/envs/beta apply
  scripts/pagerduty/tf_with_keys.py -- terraform -chdir=infra/envs/beta apply \\
      '-replace=module.monitoring_app.google_monitoring_notification_channel.pagerduty[0]'
  scripts/pagerduty/tf_with_keys.py --env production -- terraform -chdir=infra/envs/production apply

Only `terraform [-chdir=DIR] plan|apply [-flag | -flag=value …]` runs. Refused: any other program or subcommand, an
argument that is not a flag (write `-replace=ADDR`, not `-replace ADDR`), `-out` (a saved plan holds the keys), and
any TF_LOG* setting (Terraform's debug log writes the API requests, keys included). The directory Terraform runs in
(-chdir, else the current one) must be named for --env (`beta`, or `beta-…`), so one environment's keys never reach
another's channels.

--env (default beta) picks the service names: "TPA <env> · …". A production set is `--env production`.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pdlib as d  # noqa: E402
from pdlib import PagerDuty, Refused, err  # noqa: E402

VARIABLE = "TF_VAR_pagerduty_service_keys"
ROLES = ("app", "phi", "cc")
DESIGN_PREFIX = "TPA beta · "
ENV_RE = re.compile(r"^[a-z][a-z0-9]*$")
# tpa-platform's variable validation: each value is a PagerDuty integration key, 32 letters and digits.
KEY_RE = re.compile(r"^[A-Za-z0-9]{32}$")
SUBCOMMANDS = ("plan", "apply")
USAGE = "usage: tf_with_keys.py [--env ENV] -- terraform [-chdir=DIR] plan|apply [-flag=value …]"


def service_names(env: str) -> dict[str, str]:
    """Each role's PagerDuty service name for this environment: pdlib's design, with "beta" swapped for `env`."""
    names = {}
    for cfg in d.SERVICES:
        if not cfg["name"].startswith(DESIGN_PREFIX):
            raise RuntimeError(f"pdlib's service {cfg['name']!r} does not start {DESIGN_PREFIX!r}")
        names[cfg["role"]] = f"TPA {env} · " + cfg["name"][len(DESIGN_PREFIX):]
    if tuple(names) != ROLES:
        raise RuntimeError(f"pdlib's roles are {tuple(names)}, not {ROLES}")
    return names


def parse_args(argv: list[str]) -> tuple[str, list[str]]:
    """(env, command) from `[--env ENV] -- COMMAND…`."""
    if "--" not in argv:
        raise Refused(f"no `--` before the command. {USAGE}")
    split = argv.index("--")
    ours, command = argv[:split], argv[split + 1:]
    env = "beta"
    while ours:
        flag = ours.pop(0)
        if flag in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        if flag == "--env" and ours:
            env = ours.pop(0)
        elif flag.startswith("--env="):
            env = flag.split("=", 1)[1]
        else:
            raise Refused(f"unknown option {flag!r}. {USAGE}")
    if not ENV_RE.match(env):
        raise Refused(f"--env {env!r} is not an environment name (lower-case letters and digits)")
    return env, command


def check_command(command: list[str], env: str) -> None:
    """Allow `terraform [-chdir=DIR] plan|apply [-flag | -flag=value …]` only, run in a directory named for `env`."""
    if not command or Path(command[0]).name != "terraform":
        raise Refused(f"only terraform runs here, not {(command or ['nothing'])[0]!r}. {USAGE}")
    rest = command[1:]
    chdir = None
    while rest and rest[0].startswith("-chdir="):
        chdir = rest.pop(0).split("=", 1)[1]
    if not rest or rest[0] not in SUBCOMMANDS:
        raise Refused(f"only `terraform plan` and `terraform apply` run here, not {(rest or ['nothing'])[0]!r}")
    for arg in rest[1:]:
        if not arg.startswith("-") or arg in ("-", "--"):
            raise Refused(f"{arg!r} is not a flag: write flags as -name=value (a saved plan file is not taken)")
        if re.match(r"^--?out(=|$)", arg):
            raise Refused("-out writes a plan file, and a saved plan holds the keys: run plan without -out")
    name = Path(chdir or ".").resolve().name
    if name != env and not name.startswith(env + "-"):
        raise Refused(f"terraform would run in {name!r}, which is not a {env} root: --env {env} keys go only to "
                      f"infra/envs/{env} (or {env}-…); pass --env for that environment")


def check_environment() -> None:
    logs = sorted(k for k, v in os.environ.items() if k.startswith("TF_LOG") and v.strip())
    if logs:
        raise Refused(f"{', '.join(logs)} is set: Terraform's debug log writes the API requests, the keys included. "
                      "Unset it for this run")


def read_keys(pd: PagerDuty, names: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """(keys found, why each missing one is missing). Every key is registered as a secret before anything prints."""
    keys, missing = {}, {}
    for role, name in names.items():
        try:
            _, key = d.service_integration_key(pd, name)
        except Refused as e:
            missing[role] = str(e)
            continue
        if not KEY_RE.match(key):
            missing[role] = f'"{name}": its integration key is not 32 letters and digits (not shown)'
            continue
        keys[role] = key
    return keys, missing


def main() -> int:
    env, command = parse_args(sys.argv[1:])
    check_command(command, env)
    check_environment()
    names = service_names(env)

    pd = PagerDuty(d.pagerduty_token())
    keys, missing = read_keys(pd, names)
    found = ", ".join(f"{role} {'missing' if role in missing else 'present'}" for role in ROLES)
    err(f"tf_with_keys: PagerDuty keys ({env}): {found}")
    if missing:
        raise Refused("terraform not run: " + "; ".join(f"{role}: {why}" for role, why in missing.items()))

    child = d.child_env()
    child[VARIABLE] = json.dumps({role: keys[role] for role in ROLES}, separators=(",", ":"))
    sys.stdout.flush()
    sys.stderr.flush()
    os.execvpe(command[0], command, child)
    return 1  # not reached: execvpe replaces this process or raises


if __name__ == "__main__":
    d.run_main(main)
