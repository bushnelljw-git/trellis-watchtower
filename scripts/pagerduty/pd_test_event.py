#!/usr/bin/env python3
"""trellis-watchtower: send one test event to a TPA PagerDuty service, shaped like Cloud Monitoring's, and read back
what PagerDuty made of it.

The event goes through the integration the route names (pdlib.ROUTE; TW_PAGERDUTY_ROUTE=monitoring|transformer
overrides it for one run):
  transformer  Monitoring's own notification, {"incident": {…}, "version": "1.2"}, posted to the "Google Cloud
               Monitoring (titled)" integration's address, where PagerDuty runs monitoring_transform.js on it. The
               title must be the one that code gives: the subject without Monitoring's tag;
  monitoring   an Events API v1 event through the plain "Google Cloud Monitoring" integration, the way a Monitoring
               `pagerduty` channel sends it. The title is then Monitoring's own long summary.
Either way `incident.severity` is set as a Monitoring alert policy sets it, with a subject of its own in
`incident.documentation.subject`. The script then finds the incident, prints its urgency, the alert's severity, the
priority and the title, compares them with the design (docs/PAGERDUTY.md), and resolves it through the same
integration, so the escalation's second level never fires. Every title says
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


def expected_title(severity: str, service_name: str, monitoring_subject: bool, route: str = "monitoring") -> str:
    """The incident title the design gives (pdlib.py, "The incident's title"): the subject without its tag, or else
    "policy · condition". Through the titled integration, what its code gives. Through the plain one, nothing
    retitles it without the AIOps add-on (pdlib.AIOPS): Monitoring's own summary."""
    if route == "transformer":
        return d.transformer_title(monitoring_incident("", severity, service_name, monitoring_subject))
    if not d.AIOPS:
        return description(severity, service_name)
    if monitoring_subject:
        return f"{SUMMARY}{d.TITLE_SEPARATOR}{CONDITION}"
    return f"{TITLE} ({severity}, {service_name})"


def description(severity: str, service_name: str) -> str:
    """Monitoring's long generated summary, which is the incident's title unless the orchestration retitles it."""
    return f"{SUMMARY}: Monitoring's own summary of a {severity} test on {service_name} | Policy: {SUMMARY}"


def monitoring_incident(incident_key: str, severity: str, service_name: str, monitoring_subject: bool = False,
                        closed: bool = False) -> dict:
    """Monitoring's incident object (its payload, version 1.2) for the test: open, or closed for the resolve."""
    now = int(time.time())
    return {
        "incident_id": incident_key,
        "scoping_project_id": "trellis-watchtower-test",
        "scoping_project_number": 0,
        "url": "",
        "started_at": now,
        "ended_at": now if closed else None,
        "state": "closed" if closed else "open",
        "summary": description(severity, service_name),
        "apigee_url": "",
        "observed_value": "1",
        "resource": {"type": "global", "labels": {}},
        "resource_type_display_name": "Global",
        "resource_display_name": "trellis-watchtower test",
        "metric": {"type": "custom.googleapis.com/trellis_watchtower/test", "displayName": "test", "labels": {}},
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
    }


def monitoring_notification(incident_key: str, severity: str, service_name: str, monitoring_subject: bool = False,
                            closed: bool = False) -> dict:
    """Monitoring's own notification, as the titled integration's code reads it."""
    return {"incident": monitoring_incident(incident_key, severity, service_name, monitoring_subject, closed),
            "version": "1.2"}


def monitoring_event(key: str, incident_key: str, severity: str, service_name: str,
                     monitoring_subject: bool = False) -> dict:
    """An Events API v1 trigger as a Monitoring pagerduty channel sends it (Monitoring's payload, version 1.2). Its
    description, Monitoring's long summary, is the title only until the orchestration retitles it."""
    return {
        "service_key": key,
        "event_type": "trigger",
        "incident_key": incident_key,
        "description": description(severity, service_name),
        "client": "trellis-watchtower pd_test_event.py",
        "details": {
            "version": "1.2",
            "incident": monitoring_incident(incident_key, severity, service_name, monitoring_subject),
        },
    }


def send_event(body: dict) -> dict:
    url = d.base_url("PAGERDUTY_EVENTS_URL", d.PAGERDUTY_EVENTS) + "/generic/2010-04-15/create_event.json"
    return d.http_json("POST", url, {"Content-Type": "application/json"}, body) or {}


def send_notification(key: str, body: dict) -> dict:
    """Post Monitoring's notification to the titled integration's own address. The key is part of the address, which
    is never printed."""
    url = d.base_url("PAGERDUTY_EVENTS_URL", d.PAGERDUTY_EVENTS) + f"/integration/{key}/enqueue"
    answer = d.http_json("POST", url, {"Content-Type": "application/json"}, body)
    return answer if isinstance(answer, dict) else {}


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
    route = d.route()
    titled = route == "transformer"
    want_title = expected_title(args.severity, cfg["name"], args.monitoring_subject, route)
    pd = PagerDuty(d.pagerduty_token())
    service, key = d.service_integration_key(pd, cfg["name"], route)
    incident_key = f"tw-test-{uuid.uuid4().hex[:12]}"
    if titled:
        event = monitoring_notification(incident_key, args.severity, cfg["name"], args.monitoring_subject)
    else:
        event = monitoring_event(key, incident_key, args.severity, cfg["name"], args.monitoring_subject)
    out(f'pd_test_event: "{cfg["name"]}", Monitoring severity "{args.severity}", route {route} (the '
        f'"{d.route_integration(route)}" integration); the design gives urgency '
        f'{want_urgency}, severity {want_severity}, priority {want_priority or "none"}, title "{want_title}"')
    if not args.send:
        shown = {k: v for k, v in event.items() if k != "service_key"}
        out("dry run: this notification would be posted to the integration's address (its key not shown); --send "
            "sends it" if titled else "dry run: this event would be sent (service_key not shown); --send sends it")
        out(json.dumps(shown, indent=1, ensure_ascii=False))
        return 0

    def resolve(words: str | None = None) -> None:
        if titled:
            send_notification(key, monitoring_notification(incident_key, args.severity, cfg["name"],
                                                           args.monitoring_subject, closed=True))
        else:
            send_event({"service_key": key, "event_type": "resolve", "incident_key": incident_key,
                        **({"description": words} if words else {})})

    since = datetime.now(timezone.utc) - timedelta(minutes=1)
    sent = send_notification(key, event) if titled else send_event(event)
    out(f"sent       trigger, incident key {incident_key}: {sent.get('status') or 'accepted'}")
    incident, alert = find_incident(pd, service["id"], incident_key, since, args.wait)
    if incident is None:
        out(f"NOT FOUND  no incident within {args.wait:.0f} s")
        resolve()
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
    resolve(f"{SUMMARY}: resolved by the test")
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
