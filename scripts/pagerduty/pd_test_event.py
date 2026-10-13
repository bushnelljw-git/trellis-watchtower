#!/usr/bin/env python3
"""trellis-watchtower: send one test event to a TPA PagerDuty service, shaped like Cloud Monitoring's, and read back
what PagerDuty made of it.

The event goes through the service's own "Google Cloud Monitoring" integration on the Events API v1, the way a
Monitoring `pagerduty` channel sends it, with `details.incident.severity` set as a Monitoring alert policy sets it and
a subject of its own in `details.incident.documentation.subject`. The script then finds the incident, prints its
urgency, the alert's severity, the priority and the title, compares them with the design (docs/PAGERDUTY.md), and
resolves it through the same integration, so the escalation's second level never fires. Every title says
"PagerDuty setup check, please ignore". The test pages whoever is on call, the way a real alert would: that is the
point.

Usage:
  scripts/pagerduty/pd_test_event.py --role app --severity Warning            dry run: show the event, send nothing
  scripts/pagerduty/pd_test_event.py --role app --severity Critical --send    send it, read it back, resolve it
  ... --keep        leave the incident open (to see the page arrive on a phone); resolve it in PagerDuty afterwards
  ... --monitoring-subject   send Monitoring's own subject ("[ALERT - …]"), as for a policy without one: the title
                    must then be "policy · condition"

--role is app, phi or cc. --severity is the text Monitoring would send at details.incident.severity, in any letter case:
Critical, error, WARNING, "No severity" and so on. The rules ignore case, so every casing must give the same result.
Exit 0 when PagerDuty did what the design says, 1 when it did not.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pdlib as d  # noqa: E402
from pdlib import PagerDuty, Refused, out  # noqa: E402

SUMMARY = "TEST — PagerDuty setup check, please ignore"
TITLE = f"test{d.TITLE_SEPARATOR}PagerDuty setup check, please ignore"
CONDITION = "test condition"


def expected(severity: str) -> tuple[str, str, str | None]:
    """(urgency, alert severity, priority name) the design gives a Monitoring severity, in any letter case."""
    for r in d.SEVERITY_RULES:
        if r["monitoring"].lower() == severity.strip().lower():
            return d.EXPECTED_URGENCY[r["severity"]], r["severity"], r["priority"]
    return "high", "critical", None  # PagerDuty's default severity for an event with none mapped


def subject(severity: str, service_name: str, monitoring_subject: bool) -> str:
    """The policy's documentation.subject as Monitoring sends it, its tag in front: the test's own, in tpa-platform's
    "<environment> · <what happened>" shape, or one shaped like Monitoring's default."""
    if monitoring_subject:
        return f"[ALERT - {severity}] {CONDITION} on trellis-watchtower test"
    return f"[ALERT - {severity}] {TITLE} ({severity}, {service_name})"


def expected_title(severity: str, service_name: str, monitoring_subject: bool) -> str:
    """The incident title the design gives (pdlib.py, "The incident's title"): the subject without its tag, or else
    "policy · condition"."""
    if monitoring_subject:
        return f"{SUMMARY}{d.TITLE_SEPARATOR}{CONDITION}"
    return f"{TITLE} ({severity}, {service_name})"


def monitoring_event(key: str, incident_key: str, severity: str, service_name: str,
                     monitoring_subject: bool = False) -> dict:
    """An Events API v1 trigger as a Monitoring pagerduty channel sends it (Monitoring's payload, version 1.2). Its
    description, Monitoring's long summary, is the title only until the orchestration retitles it."""
    now = int(time.time())
    description = f"{SUMMARY}: Monitoring's own summary of a {severity} test on {service_name} | Policy: {SUMMARY}"
    return {
        "service_key": key,
        "event_type": "trigger",
        "incident_key": incident_key,
        "description": description,
        "client": "trellis-watchtower pd_test_event.py",
        "details": {
            "version": "1.2",
            "incident": {
                "incident_id": incident_key,
                "scoping_project_id": "trellis-watchtower-test",
                "scoping_project_number": 0,
                "url": "",
                "started_at": now,
                "ended_at": None,
                "state": "open",
                "summary": description,
                "apigee_url": "",
                "observed_value": "1",
                "resource": {"type": "global", "labels": {}},
                "resource_type_display_name": "Global",
                "resource_display_name": "trellis-watchtower test",
                "metric": {"type": "custom.googleapis.com/trellis_watchtower/test", "displayName": "test",
                           "labels": {}},
                "metadata": {"system_labels": {}, "user_labels": {}},
                "policy_name": SUMMARY,
                "policy_user_labels": {},
                "documentation": {"content": "A test from trellis-watchtower scripts/pagerduty/pd_test_event.py. "
                                             "Nothing is wrong.", "mime_type": "text/markdown",
                                  "subject": subject(severity, service_name, monitoring_subject)},
                "condition": {"name": "test", "displayName": CONDITION},
                "condition_name": CONDITION,
                "threshold_value": "0",
                "severity": severity,
            },
        },
    }


def send_event(body: dict) -> dict:
    url = d.base_url("PAGERDUTY_EVENTS_URL", d.PAGERDUTY_EVENTS) + "/generic/2010-04-15/create_event.json"
    return d.http_json("POST", url, {"Content-Type": "application/json"}, body) or {}


def find_incident(pd: PagerDuty, service_id: str, incident_key: str, since: datetime, wait: float):
    """The incident holding the alert with this key, and that alert, polling up to `wait` seconds."""
    deadline = time.monotonic() + wait
    while True:
        incidents = pd.list("/incidents", "incidents", {
            "service_ids[]": service_id, "since": since.isoformat(),
            "statuses[]": ["triggered", "acknowledged", "resolved"],
        })
        for inc in incidents:
            for alert in pd.list(f"/incidents/{inc['id']}/alerts", "alerts"):
                if alert.get("alert_key") == incident_key or inc.get("incident_key") == incident_key:
                    return pd.get(f"/incidents/{inc['id']}")["incident"], alert
        if time.monotonic() > deadline:
            return None, None
        time.sleep(3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--role", required=True, choices=[s["role"] for s in d.SERVICES])
    parser.add_argument("--severity", required=True, help='e.g. Critical, warning, ERROR, "No severity"')
    parser.add_argument("--send", action="store_true", help="send the event (default: dry run)")
    parser.add_argument("--keep", action="store_true", help="leave the incident open")
    parser.add_argument("--monitoring-subject", action="store_true",
                        help='send Monitoring\'s own subject ("[ALERT - …]"): the title must be "policy · condition"')
    parser.add_argument("--wait", type=float, default=60, help="seconds to wait for PagerDuty (default 60)")
    args = parser.parse_args()

    cfg = next(s for s in d.SERVICES if s["role"] == args.role)
    want_urgency, want_severity, want_priority = expected(args.severity)
    want_title = expected_title(args.severity, cfg["name"], args.monitoring_subject)
    pd = PagerDuty(d.pagerduty_token())
    service, key = d.service_integration_key(pd, cfg["name"])
    incident_key = f"tw-test-{uuid.uuid4().hex[:12]}"
    event = monitoring_event(key, incident_key, args.severity, cfg["name"], args.monitoring_subject)
    out(f'pd_test_event: "{cfg["name"]}", Monitoring severity "{args.severity}"; the design gives urgency '
        f'{want_urgency}, severity {want_severity}, priority {want_priority or "none"}, title "{want_title}"')
    if not args.send:
        shown = {k: v for k, v in event.items() if k != "service_key"}
        out("dry run: this event would be sent (service_key not shown); --send sends it")
        out(json.dumps(shown, indent=1, ensure_ascii=False))
        return 0

    since = datetime.now(timezone.utc) - timedelta(minutes=1)
    sent = send_event(event)
    out(f"sent       trigger, incident key {incident_key}: {sent.get('status', '?')}")
    incident, alert = find_incident(pd, service["id"], incident_key, since, args.wait)
    if incident is None:
        out(f"NOT FOUND  no incident within {args.wait:.0f} s")
        send_event({"service_key": key, "event_type": "resolve", "incident_key": incident_key})
        return 1
    got = (incident.get("urgency"), alert.get("severity"), (incident.get("priority") or {}).get("summary"))
    title = incident.get("title")
    out(f"observed   incident #{incident.get('incident_number')}: urgency {got[0]}, alert severity {got[1]}, "
        f"priority {got[2] or 'none'}, status {incident.get('status')}")
    out(f'           title "{title}"')
    ok = got == (want_urgency, want_severity, want_priority) and title == want_title
    out("as designed" if ok else f"NOT as designed: wanted urgency {want_urgency}, severity {want_severity}, "
                                 f'priority {want_priority or "none"}, title "{want_title}"')

    if args.keep:
        out("kept open (--keep): resolve it in PagerDuty when done")
        return 0 if ok else 1
    send_event({"service_key": key, "event_type": "resolve", "incident_key": incident_key,
                "description": f"{SUMMARY}: resolved by the test"})
    deadline = time.monotonic() + args.wait
    while True:
        status = pd.get(f"/incidents/{incident['id']}")["incident"].get("status")
        if status == "resolved" or time.monotonic() > deadline:
            break
        time.sleep(3)
    out(f"resolved   incident #{incident.get('incident_number')}: status {status}")
    return 0 if ok and status == "resolved" else 1


if __name__ == "__main__":
    d.run_main(main)
