#!/usr/bin/env python3
"""trellis-watchtower: point each TPA Google Cloud project's PagerDuty notification channel at its service.

Run by a person who has Monitoring rights on the three TPA projects (roles/monitoring.notificationChannelEditor or
monitoring.editor on each). For each project it reads that project's PagerDuty service's integration key
("Google Cloud Monitoring" integration, made by pd_setup.py) and creates, or corrects, one Cloud Monitoring
notification channel of type `pagerduty` there, named "PagerDuty · <service name>":

    --app  PROJECT   ->  "TPA beta · Portal & API"
    --phi  PROJECT   ->  "TPA beta · Member records"
    --cc   PROJECT   ->  "TPA beta · Call centre"

The integration key goes only in the HTTPS request body to monitoring.googleapis.com: never on a command line, never in
a file, never printed. Google returns it masked; where the masked value shows any of it, it is compared, and an
unreadable one is left alone unless --rekey sends the key again. The access token comes from
`gcloud auth print-access-token` (run with no secret on its command line) and is never printed either.

Output: progress on stderr; on stdout only the line tpa-platform's terraform.tfvars takes,

    alert_pagerduty_channel_ids = { app = "123", phi = "456", cc = "789" }

with null for a channel a dry run would create.

Usage:
  scripts/pagerduty/gcp_channels.py --app P --phi P --cc P            dry run: read both sides, print the plan
  scripts/pagerduty/gcp_channels.py --app P --phi P --cc P --apply    create or correct the three channels
  ... --rekey                                                         also send the key again to existing channels

The PHI project sits inside the VPC Service Controls perimeter: its channel can be made only by a member of
grp-platform-admin from the break-glass access level (tpa-platform's ing-monitoring rule), or the call is refused.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pdlib as d  # noqa: E402
from pdlib import ApiError, PagerDuty, Refused, err  # noqa: E402

MONITORING_API = "https://monitoring.googleapis.com"
# Each role's project id must end so; a key can then never land in another project's channel by a swapped argument.
PROJECT_SUFFIX = {"app": "-tpa-app", "phi": "-tpa-phi", "cc": "-cc"}
PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


def channel_name(service_name: str) -> str:
    return f"PagerDuty · {service_name}"


def desired_channel(role: str, service_name: str, key: str) -> dict:
    return {
        "type": "pagerduty",
        "displayName": channel_name(service_name),
        "description": (f'Pages the PagerDuty service "{service_name}". Made by trellis-watchtower '
                        "scripts/pagerduty/gcp_channels.py (docs/PAGERDUTY.md)."),
        "labels": {"service_key": key},
        "userLabels": {"owner": "trellis-watchtower", "pagerduty": role},
        "enabled": True,
    }


def key_matches(masked: str, key: str) -> bool | None:
    """Whether Google's (masked) service_key agrees with the key: True, False, or None when nothing is visible."""
    if not masked:
        return False
    if masked == key:
        return True
    visible = [(i, c) for i, c in enumerate(masked) if c != "*"]
    if not visible:
        return None
    if len(masked) == len(key):
        return all(key[i] == c for i, c in visible)
    return key.endswith(masked.lstrip("*"))


def access_token() -> str:
    try:
        got = subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise Refused("gcloud is not installed") from None
    except subprocess.TimeoutExpired:
        raise Refused("gcloud auth print-access-token timed out") from None
    token = got.stdout.strip()
    if got.returncode != 0 or not token:
        raise Refused("gcloud has no signed-in account: run `gcloud auth login` as a person with Monitoring rights")
    return d.secret(token)


class Monitoring:
    def __init__(self, token: str, writes: bool):
        self.base = d.base_url("MONITORING_API_URL", MONITORING_API)
        self.writes = writes
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def channels(self, project: str) -> list[dict]:
        found, page = [], ""
        while True:
            params = {"filter": 'type="pagerduty"', "pageSize": 1000}
            if page:
                params["pageToken"] = page
            url = f"{self.base}/v3/projects/{project}/notificationChannels?" + urllib.parse.urlencode(params)
            body = d.http_json("GET", url, self.headers) or {}
            found.extend(body.get("notificationChannels") or [])
            page = body.get("nextPageToken") or ""
            if not page:
                return found

    def create(self, project: str, channel: dict) -> dict:
        if not self.writes:
            raise RuntimeError("dry run attempted a create")
        return d.http_json("POST", f"{self.base}/v3/projects/{project}/notificationChannels", self.headers, channel)

    def patch(self, name: str, channel: dict, fields: list[str]) -> dict:
        if not self.writes:
            raise RuntimeError("dry run attempted a patch")
        url = f"{self.base}/v3/{name}?" + urllib.parse.urlencode({"updateMask": ",".join(fields)})
        return d.http_json("PATCH", url, self.headers, channel)


def numeric_id(name: str) -> str:
    return name.rsplit("/", 1)[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for role, cfg in zip(("app", "phi", "cc"), d.SERVICES):
        parser.add_argument(f"--{role}", required=True, metavar="PROJECT_ID",
                            help=f'the project paging "{cfg["name"]}"')
    parser.add_argument("--apply", action="store_true", help="create or correct the channels (default: dry run)")
    parser.add_argument("--rekey", action="store_true", help="send the integration key again to existing channels")
    args = parser.parse_args()

    projects = {"app": args.app, "phi": args.phi, "cc": args.cc}
    for role, project in projects.items():
        if not PROJECT_RE.match(project) or not project.endswith(PROJECT_SUFFIX[role]):
            raise Refused(f"--{role} {project!r} is not a {role} project id (it must end {PROJECT_SUFFIX[role]})")
    if len(set(projects.values())) != 3:
        raise Refused("the three project ids must differ")

    err("gcp_channels: " + ("APPLY: creating or correcting the channels below." if args.apply else
                            "dry run: reads only; --apply makes the changes below."))
    pd = PagerDuty(d.pagerduty_token())
    services = {cfg["role"]: cfg for cfg in d.SERVICES}
    keys = {}
    for role in projects:
        _, keys[role] = d.service_integration_key(pd, services[role]["name"])
        err(f'pagerduty  "{services[role]["name"]}": integration key read (not shown)')

    try:
        token = access_token()
    except Refused as e:
        if args.apply:
            raise
        err(f"google     cannot read Google Cloud ({e}); the plan below assumes no channel exists yet")
        token = None
    mon = Monitoring(token or "", writes=args.apply)

    # Read all three projects before writing anything.
    plans = {}
    for role, project in projects.items():
        name = services[role]["name"]
        want = desired_channel(role, name, keys[role])
        existing = None
        if token:
            try:
                same = [c for c in mon.channels(project) if c.get("displayName") == want["displayName"]]
            except ApiError as e:
                if args.apply:
                    raise Refused(f"cannot read the channels in {project}: {e}") from None
                err(f"google     {project}: cannot read its channels ({e}); assuming none")
                same = []
            if len(same) > 1:
                raise Refused(f'{project} has {len(same)} channels named "{want["displayName"]}": remove the extras')
            existing = same[0] if same else None
        plans[role] = (project, want, existing)

    ids, refused = {}, 0
    for role, (project, want, existing) in plans.items():
        what = f'{project}: channel "{want["displayName"]}"'
        if existing is None:
            if args.apply:
                made = mon.create(project, want)
                ids[role] = numeric_id(made["name"])
                err(f"created    {what} (id {ids[role]})")
            else:
                ids[role] = None
                err(f"create     {what}")
            continue
        ids[role] = numeric_id(existing["name"])
        fields = []
        if existing.get("description") != want["description"]:
            fields.append("description")
        if existing.get("userLabels") != want["userLabels"]:
            fields.append("user_labels")
        if existing.get("enabled") is False:
            fields.append("enabled")
        match = key_matches((existing.get("labels") or {}).get("service_key", ""), keys[role])
        if args.rekey or match is False:
            fields.append("labels")
        note = "" if match is not None or args.rekey else " (Google shows none of its key; --rekey sends it again)"
        if not fields:
            err(f"ok         {what} (id {ids[role]}){note}")
        elif args.apply:
            body = {**want, "name": existing["name"]}
            if "labels" not in fields:
                body.pop("labels")  # the key travels only when it is being set
            try:
                mon.patch(existing["name"], body, fields)
                err(f"updated    {what} (id {ids[role]}): {', '.join(fields)}")
            except ApiError as e:
                refused += 1
                err(f"refused    {what}: {e}")
        else:
            err(f"update     {what} (id {ids[role]}): {', '.join(fields)}")

    def show(v):
        return "null" if v is None else f'"{v}"'

    d.out("alert_pagerduty_channel_ids = { " + ", ".join(f"{r} = {show(ids[r])}" for r in ("app", "phi", "cc")) + " }")
    return 1 if refused else 0


if __name__ == "__main__":
    d.run_main(main)
