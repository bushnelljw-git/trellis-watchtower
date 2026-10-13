"""The incident titles (pdlib.py, "The incident's title"): pd_setup.py's title rules against the fake PagerDuty
(fakes.py), which applies them the way the design reads PagerDuty's orchestration. An automated gate only.

Run: python3 -m unittest discover -s tests/pagerduty -v
"""

from __future__ import annotations

import copy
import unittest

import fakes
from test_pd_setup import SUMMARY_STEADY_DRY, Base, pd_setup

SERVICES = ("TPA beta · Portal & API", "TPA beta · Member records", "TPA beta · Call centre")

# Each service's orchestration as it was live before the titles (read back 2026-10-13): the severity rules alone, in
# "start". The fake's priority ids stand in for the account's.
TODAY = [
    {"label": "Monitoring Critical: severity critical, P1", "actions": {"priority": "PRI1", "severity": "critical"},
     "conditions": [{"expression": "event.custom_details.incident.severity matches regex "
                                   "'(?i)^[[:space:]]*Critical[[:space:]]*$'"}]},
    {"label": "Monitoring Error: severity error, P2", "actions": {"priority": "PRI2", "severity": "error"},
     "conditions": [{"expression": "event.custom_details.incident.severity matches regex "
                                   "'(?i)^[[:space:]]*Error[[:space:]]*$'"}]},
    {"label": "Monitoring Warning: severity warning, P3", "actions": {"priority": "PRI3", "severity": "warning"},
     "conditions": [{"expression": "event.custom_details.incident.severity matches regex "
                                   "'(?i)^[[:space:]]*Warning[[:space:]]*$'"}]},
]

# Incident #31 (2026-10-13) as Monitoring sent it, trimmed to what the rules read. Metric and resource labels only.
DESCRIPTION = (
    "tpa_jobs_alerts for trellistpa-beta-tpa-app Cloud Run Job labels {project_id=trellistpa-beta-tpa-app} with metric "
    "labels {code=workload_orphan, job=workload_audit} is above the threshold of 0.000 with a value of 2.000. | "
    "Violation started: Oct 13, 2026 at 5:06AM UTC (less than 1 sec ago) | Policy: beta: a job raised an alert | "
    "Condition: from a scheduled run | View incident: https://console.cloud.google.com/monitoring/alerting/alerts/"
    "0.odrmjpnp1qpp?channelType=pagerduty&project=trellistpa-beta-tpa-app"
)
MONITORING_SUBJECT = ("[ALERT - Warning] from a scheduled run on trellistpa-beta-tpa-app Cloud Run Job labels "
                      "{project_id=trellistpa-beta-tpa-app}")
CONTENT = ("A tpa-jobs run raised one of its registry's alerts (tpa_jobs/registry.py): a failed or skipped tenant, a "
           "dead letter, a lag, a breach count, an orphan.")
URL = ("https://console.cloud.google.com/monitoring/alerting/alerts/0.odrmjpnp1qpp?channelType=pagerduty&"
       "project=trellistpa-beta-tpa-app")
SUBJECT = "beta · tpa-jobs workload_audit raised workload_orphan"
NAMES = "beta: a job raised an alert · from a scheduled run"
UNSET = object()


def monitoring(subject=MONITORING_SUBJECT, **fields) -> dict:
    """Incident #31's v1 trigger. `subject` is documentation.subject; each keyword replaces a field of
    details.incident; UNSET removes one."""
    incident = {
        "condition_name": "from a scheduled run",
        "documentation": {"content": CONTENT, "mime_type": "text/markdown", "subject": subject},
        "incident_id": "0.odrmjpnp1qpp",
        "metric": {"displayName": "tpa_jobs_alerts", "labels": {"code": "workload_orphan", "job": "workload_audit"},
                   "type": "logging.googleapis.com/user/tpa_jobs_alerts"},
        "observed_value": "2.000",
        "policy_name": "beta: a job raised an alert",
        "policy_user_labels": {"environment": "beta", "managed_by": "terraform", "routing": "normal"},
        "resource": {"labels": {"project_id": "trellistpa-beta-tpa-app"}, "type": "cloud_run_job"},
        "severity": "Warning",
        "state": "open",
        "threshold_value": "0",
        "url": URL,
    }
    if subject is UNSET:
        del incident["documentation"]["subject"]
    for k, v in fields.items():
        if v is UNSET:
            incident.pop(k, None)
        else:
            incident[k] = v
    return {"event_type": "trigger", "incident_key": "0.odrmjpnp1qpp", "description": DESCRIPTION,
            "details": {"incident": incident, "version": "1.2"}}


def orchestration_puts(state, since=0) -> list[dict]:
    return [r for r in state.writes()[since:]
            if r["path"].startswith("/pd/event_orchestrations/services/") and not r["path"].endswith("/active")]


def today(sid: str) -> dict:
    return {"type": "service", "parent": {"id": sid, "type": "service_reference"},
            "sets": [{"id": "start", "rules": copy.deepcopy(TODAY)}], "catch_all": {"actions": {}}}


class ThePlanAgainstToday(Base):
    """The live account today: each service has the severity rules only. The plan, the apply, and steady after."""

    def setUp(self):
        super().setUp()
        self.apply()
        for name in SERVICES:
            sid = self.service_id(name)
            self.state.orchestrations[sid] = self.state.store_orchestration(today(sid))

    def test_the_plan_shows_the_change_rule_by_rule_and_writes_nothing(self):
        before = len(self.state.writes())
        result = self.pd()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.state.writes()), before, "a dry run must make no write")
        self.assertRegex(self.summary(result), r"^summary: 0 to create, 3 to update, \d+ ok, 0 kept, 0 refused, ")
        lines = result.stdout.splitlines()
        for name in SERVICES:
            at = lines.index(next(x for x in lines if x.startswith(f'update      event orchestration on "{name}"')))
            self.assertIn("[Critical -> critical P1; Error -> error P2; Warning -> warning P3 (any letter case); "
                          "anything else keeps the default (critical); title: the policy's subject, else policy · "
                          "condition]", lines[at])
            got = lines[at + 1:at + 8]
            if name == SERVICES[0]:
                note, = [x for x in lines if "Advanced Event Orchestration" in x]
                self.assertEqual(note, "          (the titles need Advanced Event Orchestration, which no PagerDuty "
                                       "API shows before an update; --apply reads each update's warnings and, if "
                                       "there are any, puts the previous orchestration back and refuses)")
                self.assertEqual(lines[at + 8], note, "printed once, after the first update")
            self.assertEqual(got, [
                '              ~ start: "Monitoring Critical: severity critical, P1" (route_to added)',
                '              ~ start: "Monitoring Error: severity error, P2" (route_to added)',
                '              ~ start: "Monitoring Warning: severity warning, P3" (route_to added)',
                '              + start: "Any other severity: keeps the default (critical), on to the titles"',
                '              + titles: "Title: the policy\'s own subject"',
                '              + titles: "Title: policy · condition (the policy has no subject of its own)"',
                '              + titles: "Title: as Monitoring wrote it (no policy or condition name)"',
            ])

    def test_apply_keeps_the_severity_rules_exactly_then_is_steady(self):
        before = len(self.state.writes())
        first = self.pd("--apply")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertRegex(self.summary(first), r"^summary: created 0, updated 3, ")
        self.assertEqual(len(orchestration_puts(self.state, before)), 3, "no warnings, so nothing is put back")
        for name in SERVICES:
            sid = self.service_id(name)
            self.assertEqual([s["id"] for s in self.state.orchestrations[sid]["sets"]], ["start", "titles"])
            kept = [(r["label"], r["conditions"], pd_setup._set_actions(r["actions"]), r["disabled"])
                    for r in self.rules(sid)[:3]]
            self.assertEqual(kept, [(t["label"], t["conditions"], {**t["actions"], "route_to": "titles"}, False)
                                    for t in TODAY],
                             "the severity rules must be today's, with only the route on to the titles added")
            self.assertEqual(pd_setup._set_actions(self.state.orchestrations[sid]["catch_all"]["actions"]), {})
        writes = len(self.state.writes())
        self.assertRegex(self.summary(self.pd()), SUMMARY_STEADY_DRY)
        again = self.pd("--apply")
        self.assertEqual(len(self.state.writes()), writes, "a re-run with --apply must write nothing")
        self.assertRegex(self.summary(again), r"^summary: created 0, updated 0, ")

    def test_a_changed_title_rule_and_a_rule_a_person_added_are_named(self):
        self.pd("--apply")
        sid = self.service_id("TPA beta · Call centre")
        self.rules(sid, "titles")[0]["actions"]["extractions"][0]["template"] = "{{variables.subject}}!"
        self.rules(sid, "titles").insert(0, {"id": "rX", "label": "Someone's rule", "conditions": [],
                                             "actions": {"annotate": "x"}, "disabled": False})
        result = self.pd()
        self.assertIn('              ~ titles: "Title: the policy\'s own subject" (extractions changed)', result.stdout)
        self.assertIn('              - titles: "Someone\'s rule"', result.stdout)
        self.assertRegex(self.summary(result), r"^summary: 0 to create, 1 to update, ")

    def test_a_rule_that_moved_and_changed_says_both(self):
        sid = self.service_id("TPA beta · Portal & API")
        path = self.state.orchestrations[sid]
        path["sets"].append({"id": "old", "rules": [path["sets"][0]["rules"].pop(0)]})
        path["sets"][1]["rules"][0]["actions"]["priority"] = "PRI4"
        result = self.pd()
        self.assertIn('              ~ start: "Monitoring Critical: severity critical, P1" (moved from set "old", '
                      "priority changed, route_to added)", result.stdout)


class TheTitleRules(Base):
    """Monitoring's events through the rules exactly as pd_setup.py stored them in the fake."""

    def setUp(self):
        super().setUp()
        self.apply()
        self.sid = self.service_id("TPA beta · Portal & API")

    def through(self, body) -> tuple[dict, dict]:
        """The event after the orchestration ({summary, custom_details}) and the severity and priority it set."""
        return self.state.orchestrate(self.sid, body)

    def test_the_titles_set_exactly(self):
        (subject, names, kept) = self.rules(self.sid, "titles")
        incident = "event.custom_details.incident"
        self.assertEqual(subject["conditions"], [{"expression": (
            f"{incident}.documentation.subject matches regex '[^[:space:]]' and not "
            f"({incident}.documentation.subject matches regex '^[[]ALERT - ')")}])
        self.assertEqual(names["conditions"], [{"expression": (
            f"{incident}.policy_name matches regex '[^[:space:]]' and "
            f"{incident}.condition_name matches regex '[^[:space:]]'")}])
        self.assertEqual(kept["conditions"], [], "the last title rule matches every event")
        variables = [(v["name"], v["path"], v["value"]) for r in (subject, names) for v in r["actions"]["variables"]]
        self.assertEqual(variables,
                         [("subject", f"{incident}.documentation.subject", "^[[:space:]]*(.+)"),
                          ("policy", f"{incident}.policy_name", "^[[:space:]]*(.+)"),
                          ("condition", f"{incident}.condition_name", "^[[:space:]]*(.+)")])
        self.assertEqual([x["template"] for r in (subject, names) for x in r["actions"]["extractions"]
                          if x["target"] == "event.summary"],
                         ["{{variables.subject}}", "{{variables.policy}} · {{variables.condition}}"])
        details = [(x["target"], x["source"], x["regex"]) for x in kept["actions"]["extractions"]]
        self.assertEqual(details, [
            ("event.custom_details.what_to_check", f"{incident}.documentation.content", "^[[:space:]]*(.+)"),
            ("event.custom_details.console", f"{incident}.url",
             "^https://console[.]cloud[.]google[.]com/[^[:space:]]+"),
            ("event.custom_details.observed", f"{incident}.observed_value", "^[[:space:]]*(.+)"),
            ("event.custom_details.threshold", f"{incident}.threshold_value", "^[[:space:]]*(.+)"),
        ])
        for rule in (subject, names):
            self.assertEqual([x for x in rule["actions"]["extractions"] if x["target"] != "event.summary"],
                             kept["actions"]["extractions"], "every title rule copies the same details")

    def test_only_the_title_and_details_change_never_the_dedup_key(self):
        for rule in pd_setup.title_rules():
            a = rule["actions"]
            self.assertEqual(set(a) - {"variables", "extractions"}, set(), rule["label"])
            for x in a["extractions"]:
                self.assertRegex(x["target"], r"^event\.(summary|custom_details\.[a-z_]+)$")

    def test_the_policys_own_subject_is_the_title(self):
        event, outcome = self.through(monitoring(subject=SUBJECT))
        self.assertEqual(event["summary"], SUBJECT)
        self.assertEqual(outcome, {"severity": "warning", "priority": "PRI3"})
        details = event["custom_details"]
        self.assertEqual({k: details[k] for k in ("what_to_check", "console", "observed", "threshold")},
                         {"what_to_check": CONTENT, "console": URL, "observed": "2.000", "threshold": "0"})
        self.assertEqual(details["incident"]["policy_name"], "beta: a job raised an alert", "the payload is kept")

    def test_monitorings_own_subject_gives_policy_and_condition(self):
        event, outcome = self.through(monitoring())
        self.assertEqual(event["summary"], NAMES)
        self.assertEqual(outcome, {"severity": "warning", "priority": "PRI3"})
        self.assertEqual(event["custom_details"]["console"], URL)

    def test_a_missing_or_blank_subject_gives_policy_and_condition(self):
        for subject in (UNSET, "", "   ", "\n"):
            event, _ = self.through(monitoring(subject=subject))
            self.assertEqual(event["summary"], NAMES, repr(subject))

    def test_a_subject_that_only_mentions_alert_later_is_kept(self):
        text = "beta · the [ALERT - x] word inside is not Monitoring's"
        self.assertEqual(self.through(monitoring(subject=text))[0]["summary"], text)

    def test_without_the_names_monitorings_title_is_kept_and_severity_still_applies(self):
        for fields in ({"policy_name": UNSET}, {"condition_name": UNSET}, {"policy_name": " "}):
            event, outcome = self.through(monitoring(subject=UNSET, **fields))
            self.assertEqual(event["summary"], DESCRIPTION, fields)
            self.assertEqual(outcome, {"severity": "warning", "priority": "PRI3"}, fields)
            self.assertEqual(event["custom_details"]["what_to_check"], CONTENT)

    def test_a_policy_with_no_severity_still_gets_its_title(self):
        event, outcome = self.through(monitoring(subject=SUBJECT, severity="No severity"))
        self.assertEqual(event["summary"], SUBJECT)
        self.assertEqual(outcome, {}, "no severity rule matched: PagerDuty's default severity, critical, no priority")
        for severity, want in (("CRITICAL", "PRI1"), ("error", "PRI2")):
            event, outcome = self.through(monitoring(subject=SUBJECT, severity=severity))
            self.assertEqual((event["summary"], outcome["priority"]), (SUBJECT, want), severity)

    def test_details_come_only_from_the_payload(self):
        event, _ = self.through(monitoring(subject=SUBJECT, url="https://example.com/x",
                                           documentation={"content": "\n\n  First line.\nSecond line.",
                                                          "subject": SUBJECT}))
        self.assertEqual(event["custom_details"]["what_to_check"], "First line.")
        self.assertNotIn("console", event["custom_details"], "only Google's own console link is lifted")
        event, _ = self.through(monitoring(subject=SUBJECT, url=UNSET, observed_value=UNSET))
        self.assertNotIn("console", event["custom_details"])
        self.assertNotIn("observed", event["custom_details"])
        self.assertEqual(event["custom_details"]["threshold"], "0")

    def test_the_fake_refuses_what_pagerduty_would(self):
        """The fake's own checks, so the model the rules pass is not looser than the design's reading."""
        bad = pd_setup.desired_orchestration(self.sid, {"P1": "PRI1", "P2": "PRI2", "P3": "PRI3"})
        bad["sets"][0]["rules"][0]["actions"]["route_to"] = "nowhere"
        with self.assertRaises(fakes.Fail):
            self.state.store_orchestration(bad)
        bad = pd_setup.desired_orchestration(self.sid, {"P1": "PRI1", "P2": "PRI2", "P3": "PRI3"})
        bad["sets"][1]["rules"][1]["actions"]["extractions"][0]["template"] = "{{variables.subject}}"
        with self.assertRaises(fakes.Fail):
            self.state.store_orchestration(bad)


class WithoutAdvancedOrchestration(Base):
    """An account without Advanced Event Orchestration: PagerDuty takes the update, answers with warnings and runs
    "start" alone. The script puts the previous orchestration back, refuses, and the severity rules keep running."""

    state_options = {"advanced_orchestration": False}

    def setUp(self):
        super().setUp()
        self.first = self.pd("--apply", "--add-rules")

    def outcome(self, name, **fields):
        return self.state.orchestrate(self.service_id(name), monitoring(subject=SUBJECT, **fields))

    def test_new_services_get_the_severity_rules_alone_and_the_run_fails(self):
        self.assertEqual(self.first.returncode, 1, self.first.stdout + self.first.stderr)
        self.assertRegex(self.summary(self.first), r"^summary: created 23, updated 0, ok \d+, kept 0, refused 3, ")
        for name in SERVICES:
            self.assertIn(f'refused     event orchestration on "{name}"  [this PagerDuty plan lacks Advanced Event '
                          "Orchestration; titles left out, the severity rules alone put in (PagerDuty: "
                          "forbidden_feature: Advanced Event Orchestration is not on this account: only rules in the "
                          "'start' set will be evaluated;", self.first.stdout)
            sid = self.service_id(name)
            self.assertEqual(pd_setup.orchestration_shape(self.state.orchestrations[sid]),
                             pd_setup.orchestration_shape(pd_setup.severity_only(sid, {"P1": "PRI1", "P2": "PRI2",
                                                                                        "P3": "PRI3"})))
            self.assertTrue(self.state.active[sid])
            event, outcome = self.outcome(name)
            self.assertEqual((event["summary"], outcome), (DESCRIPTION, {"severity": "warning", "priority": "PRI3"}))

    def test_an_update_is_put_back_and_refused_and_severity_still_runs(self):
        for name in SERVICES:
            sid = self.service_id(name)
            self.state.orchestrations[sid] = self.state.store_orchestration(today(sid))
        before = len(self.state.writes())
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertRegex(self.summary(result), r"^summary: created 0, updated 0, ok \d+, kept 0, refused 3, ")
        self.assertIn('refused     event orchestration on "TPA beta · Member records"  [this PagerDuty plan lacks '
                      "Advanced Event Orchestration; titles unchanged, the previous orchestration restored "
                      "(PagerDuty: forbidden_feature:", result.stdout)
        puts = orchestration_puts(self.state, before)
        self.assertEqual(len(puts), 6, "each service: the update, then the previous orchestration put back")
        for name in SERVICES:
            sid = self.service_id(name)
            self.assertEqual([s["id"] for s in self.state.orchestrations[sid]["sets"]], ["start"])
            kept = [(r["label"], r["conditions"], pd_setup._set_actions(r["actions"]), r["disabled"])
                    for r in self.rules(sid)]
            self.assertEqual(kept, [(t["label"], t["conditions"], t["actions"], False) for t in TODAY],
                             "today's severity rules, exactly")
            for severity, want in (("Warning", "PRI3"), ("critical", "PRI1"), ("ERROR", "PRI2")):
                self.assertEqual(self.outcome(name, severity=severity)[1]["priority"], want, (name, severity))
            self.assertEqual(self.outcome(name, severity="No severity")[1], {}, "the default, critical")

    def test_the_plan_still_plans_it_and_writes_nothing(self):
        before = len(self.state.writes())
        result = self.pd()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.state.writes()), before)
        self.assertIn("(the titles need Advanced Event Orchestration", result.stdout)


class RestoreFails(Base):
    """The update is taken with warnings and putting the previous orchestration back fails: the run says so, and the
    severity rules, which are in "start", still run."""

    state_options = {"advanced_orchestration": False, "fail_orchestration_put": 2}

    def test_the_severity_rules_still_run(self):
        result = self.pd("--apply", "--add-rules")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('refused     event orchestration on "TPA beta · Portal & API"  [this PagerDuty plan lacks '
                      "Advanced Event Orchestration (PagerDuty: forbidden_feature:", result.stdout)
        self.assertIn("putting the previous orchestration back FAILED (HTTP 500:", result.stdout)
        sid = self.service_id("TPA beta · Portal & API")
        self.assertEqual([s["id"] for s in self.state.orchestrations[sid]["sets"]], ["start", "titles"])
        event, outcome = self.state.orchestrate(sid, monitoring(subject=SUBJECT, severity="warning"))
        self.assertEqual((event["summary"], outcome), (DESCRIPTION, {"severity": "warning", "priority": "PRI3"}),
                         "only start runs: no title, the severity as designed")


if __name__ == "__main__":
    unittest.main()
