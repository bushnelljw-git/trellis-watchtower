"""scripts/pagerduty/monitoring_transform.js, the code of the titled integration, run under node with a stub PD object
(run_transform.js): an automated gate only. The live proof is pd_test_event.py --send (docs/PAGERDUTY.md).

Without node these tests cannot run, and say so loudly: they are skipped, never passed.

Run: python3 -m unittest discover -s tests/pagerduty -v
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import unittest

import fakes
from test_pd_setup import ROOT, pdlib

JS = pdlib.TRANSFORM_FILE
DASHBOARDS = ROOT / "cloud" / "dashboards"
NO_NODE = "node is not installed: the titled integration's JavaScript was NOT run"
BASE = pdlib.WATCHTOWER_URL

# A Monitoring notification as it reached the titled integration (2026-11-12), trimmed of the condition's own
# definition. Metric and resource labels only.
SAMPLE = {
    "incident": {
        "condition_name": "a lag raised in every five minutes for thirty, from a drain tick",
        "documentation": {
            "content": "A tpa-jobs drain or run raised a lag alert in every five minutes for thirty.",
            "mime_type": "text/markdown",
            "subject": "[ALERT - Warning] beta · tpa-jobs cutoff_freeze behind: cutoff_freeze_behind",
        },
        "ended_at": None,
        "incident_id": "cet-probe-1794490176",
        "metadata": {"system_labels": {}, "user_labels": {}},
        "metric": {"displayName": "tpa_jobs_alerts", "labels": {"job": "cutoff_freeze", "code": "cutoff_freeze_behind"},
                   "type": "logging.googleapis.com/user/tpa_jobs_alerts"},
        "observed_value": "1.000",
        "policy_name": "beta: a job stayed behind for thirty minutes",
        "policy_user_labels": {"environment": "beta", "managed_by": "terraform", "routing": "p2"},
        "resource": {"labels": {"project_id": "trellistpa-beta-tpa-app"}, "type": "cloud_run_revision"},
        "resource_id": "",
        "resource_name": "trellistpa-beta-tpa-app Cloud Run Revision labels {project_id=trellistpa-beta-tpa-app}",
        "resource_type_display_name": "Cloud Run Revision",
        "scoping_project_id": "trellistpa-beta-tpa-app",
        "scoping_project_number": 411977351492,
        "severity": "Warning",
        "started_at": 1794482919,
        "state": "open",
        "summary": "tpa_jobs_alerts for trellistpa-beta-tpa-app Cloud Run Revision labels "
                   "{project_id=trellistpa-beta-tpa-app} with metric labels {code=cutoff_freeze_behind, "
                   "job=cutoff_freeze} is above the threshold of 0.000 with a value of 1.000.",
        "threshold_value": "0",
        "url": "https://console.cloud.google.com/monitoring/alerting/alerts/0.oexfwbhlmrz9?channelType=pagerduty&"
               "project=trellistpa-beta-tpa-app",
    },
    "version": "1.2",
}
TITLE = "Tpa-jobs cutoff_freeze behind: cutoff_freeze_behind"
UNSET = object()


def setUpModule():
    if fakes.NODE is None:
        print(f"\n{'!' * 100}\nWARNING: {NO_NODE}.\n{'!' * 100}", file=sys.stderr, flush=True)


def notification(**fields) -> dict:
    """The sample with fields of its incident replaced (UNSET removes one; a dotted name reaches one level in)."""
    body = copy.deepcopy(SAMPLE)
    for name, value in fields.items():
        target, _, leaf = name.rpartition("__")
        holder = body["incident"][target] if target else body["incident"]
        if value is UNSET:
            holder.pop(leaf, None)
        else:
            holder[leaf] = value
    return body


def dashboard_uids() -> dict[str, str]:
    """uid -> file name, for every page in cloud/dashboards."""
    return {json.loads(path.read_text())["uid"]: path.name for path in sorted(DASHBOARDS.glob("*.json"))}


@unittest.skipIf(fakes.NODE is None, NO_NODE)
class Transform(unittest.TestCase):
    maxDiff = None

    def run_js(self, body) -> dict:
        ran = fakes.run_transform(pdlib.transformer_code(), body)
        self.assertIsNone(ran["error"], ran["error"])
        self.assertEqual(ran["cef"], [], "emitCEFEvents loses the summary (seen live): never used")
        return ran

    def event(self, body) -> dict:
        ran = self.run_js(body)
        self.assertIsNone(ran["failed"])
        (event,) = ran["events"]
        return event

    def test_the_sample_is_a_trigger_with_the_subject_as_its_title(self):
        event = self.event(SAMPLE)
        self.assertEqual(event["event_type"], "trigger")
        self.assertEqual(event["description"], TITLE)
        self.assertEqual(event["incident_key"], "cet-probe-1794490176")
        self.assertEqual(event["client"], "Watchtower: Jobs")
        self.assertEqual(event["client_url"], f"{BASE}/d/tw-cloud-jobs")

    def test_the_details_in_reading_order(self):
        details = self.event(SAMPLE)["details"]
        i = SAMPLE["incident"]
        self.assertEqual(list(details.items()), [
            ("what_happened", TITLE),
            ("what_to_check", i["documentation"]["content"]),
            ("dashboard", f"{BASE}/d/tw-cloud-jobs"),
            ("overview", f"{BASE}/d/tw-cloud-overview"),
            ("project", "trellistpa-beta-tpa-app"),
            ("severity", "Warning"),
            ("measured", "1.000 (threshold 0)"),
            ("where", "Cloud Run Revision"),
            ("metric", "logging.googleapis.com/user/tpa_jobs_alerts {code=cutoff_freeze_behind, job=cutoff_freeze}"),
            ("policy", "beta: a job stayed behind for thirty minutes"),
            ("condition", "a lag raised in every five minutes for thirty, from a drain tick"),
            ("started", "2026-11-12T11:28:39Z"),
            ("console", i["url"]),
            ("monitoring_summary", i["summary"]),
            ("incident", i),
        ])

    def test_the_incident_object_is_passed_on_unchanged_where_the_severity_rules_read_it(self):
        """pd_setup.py's rules match event.custom_details.incident.severity: v1 details become custom_details."""
        details = self.event(SAMPLE)["details"]
        self.assertEqual(details["incident"], SAMPLE["incident"])
        self.assertEqual(pdlib.SEVERITY_FIELD, "event.custom_details.incident.severity")
        self.assertEqual(pdlib.INCIDENT_FIELD, "event.custom_details.incident")
        self.assertEqual(details["incident"]["severity"], "Warning")

    def test_the_links(self):
        self.assertEqual(self.event(SAMPLE)["contexts"], [
            {"type": "link", "href": f"{BASE}/d/tw-cloud-jobs", "text": "Watchtower: Jobs"},
            {"type": "link", "href": f"{BASE}/d/tw-cloud-overview", "text": "Watchtower: overview"},
            {"type": "link", "href": SAMPLE["incident"]["url"], "text": "Cloud Monitoring incident"},
        ])
        bare = self.event({"incident": {"incident_id": "x", "summary": "s"}})
        self.assertEqual(bare["contexts"], [
            {"type": "link", "href": f"{BASE}/d/tw-cloud-overview", "text": "Watchtower: overview"}])
        self.assertEqual(bare["client_url"], f"{BASE}/d/tw-cloud-overview")
        self.assertEqual(bare["details"]["dashboard"], bare["details"]["overview"])

    def test_closed_is_a_resolve_with_the_same_key(self):
        event = self.event(notification(state="closed", ended_at=1794483519))
        self.assertEqual(event["event_type"], "resolve")
        self.assertEqual(event["incident_key"], self.event(SAMPLE)["incident_key"])
        self.assertEqual(event["description"], TITLE)
        self.assertEqual(event["details"]["ended"], "2026-11-12T11:38:39Z")
        for state in ("open", "OPEN", "", None, "acknowledged"):
            self.assertEqual(self.event(notification(state=state))["event_type"], "trigger", state)
        self.assertEqual(self.event(notification(state=" Closed "))["event_type"], "resolve")

    def test_without_a_subject_the_title_is_policy_and_condition(self):
        names = ("beta: a job stayed behind for thirty minutes · a lag raised in every five minutes for thirty, "
                 "from a drain tick")
        self.assertEqual(self.event(notification(documentation__subject=UNSET))["description"], names)
        self.assertEqual(self.event(notification(documentation=UNSET))["description"], names)
        self.assertEqual(self.event(notification(documentation__subject="  "))["description"], names)

    def test_monitorings_own_subject_is_not_used(self):
        """A policy without a subject is sent Monitoring's, "<condition> on <resource>": long, and not ours."""
        own = "[ALERT - Warning] from a scheduled run on trellistpa-beta-tpa-app Cloud Run Job labels {project_id=x}"
        event = self.event(notification(documentation__subject=own))
        self.assertEqual(event["description"], "beta: a job stayed behind for thirty minutes · a lag raised in "
                                               "every five minutes for thirty, from a drain tick")

    def test_one_leading_tag_is_dropped_whatever_it_says(self):
        for subject, title in [
            ("[RESOLVED] beta · engine p95 above 2 s", "Engine p95 above 2 s"),
            ("[ALERT - No severity] beta · engine p95 above 2 s", "Engine p95 above 2 s"),
            ("beta · engine p95 above 2 s", "Engine p95 above 2 s"),
            ("[ALERT - Warning] beta · alert policy or channel changed: "
             "google.monitoring.v3.NotificationChannelService.DeleteNotificationChannel",
             "Alert policy or channel changed: delete notification channel"),
            ("[ALERT] [x] beta · two tags", None),  # one tag at most: what is left is not our shape
            ("production-full · records 5xx", "Records 5xx"),
            # The production root's word once it no longer reads beta (tpa-platform display_environment = "TPA").
            ("[ALERT - Warning] TPA · URGENT missed run: tpa-jobs-workload-audit",
             "URGENT missed run: tpa-jobs-workload-audit"),
            ("TPA · engine p95 above 2 s", "Engine p95 above 2 s"),
            ("[ALERT - Warning] Something on a resource", None),  # Monitoring's own subject is still not ours
        ]:
            with self.subTest(subject=subject):
                got = self.event(notification(documentation__subject=subject))["description"]
                self.assertEqual(got, title or "beta: a job stayed behind for thirty minutes · a lag raised in "
                                               "every five minutes for thirty, from a drain tick")

    def test_without_names_the_title_is_monitorings_summary_then_a_plain_one(self):
        bare = notification(documentation=UNSET, policy_name=UNSET)
        self.assertEqual(self.event(bare)["description"], SAMPLE["incident"]["summary"])
        event = self.event({"incident": {"state": "open"}})
        self.assertEqual(event["description"], "Cloud Monitoring alert")
        self.assertNotIn("incident_key", event, "with nothing to key on, PagerDuty makes the key")

    def test_a_long_title_is_cut(self):
        event = self.event(notification(documentation__subject="beta · " + "x" * 2000))
        self.assertEqual(len(event["description"]), 250)
        self.assertTrue(event["description"].endswith("x..."))
        self.assertLess(250, 1024, "PagerDuty's limit for a v1 description")

    def test_without_an_incident_id_the_key_is_policy_and_condition(self):
        event = self.event(notification(incident_id=UNSET))
        self.assertEqual(event["incident_key"], "beta: a job stayed behind for thirty minutes / a lag raised in every "
                                                "five minutes for thirty, from a drain tick")
        closed = self.event(notification(incident_id=UNSET, state="closed"))
        self.assertEqual(closed["incident_key"], event["incident_key"])

    def test_a_body_without_an_incident_fails_and_pages_nobody(self):
        for body in ({}, {"version": "1.2"}, {"incident": "open"}, {"incident": None}, {"incident": [1]}, None,
                     "not json", 7, [], {"details": {"version": "1.2"}}):
            with self.subTest(body=body):
                ran = self.run_js(body)
                self.assertEqual(ran["events"], [])
                self.assertEqual(ran["failed"], "not a Cloud Monitoring notification: no incident object in the body")

    def test_a_v1_event_carrying_the_incident_in_its_details_is_read_too(self):
        """Should a Monitoring channel post its Events API v1 body to the integration, the same title comes out."""
        v1 = {"service_key": "k", "event_type": "trigger", "description": "long", "details": SAMPLE}
        self.assertEqual(self.event(v1), self.event(SAMPLE))
        self.assertEqual(self.event(json.dumps(SAMPLE)), self.event(SAMPLE), "a body that arrives as text")

    def test_empty_fields_are_left_out(self):
        details = self.event({"incident": {"incident_id": "x", "policy_name": "p", "condition_name": "c", "url": " ",
                                           "observed_value": "3", "started_at": "soon",
                                           "metric": {"labels": {}}}})["details"]
        self.assertEqual(list(details), ["what_happened", "dashboard", "overview", "measured", "policy", "condition",
                                         "incident"])
        self.assertEqual(details["measured"], "3")

    def test_python_expects_the_title_the_code_gives(self):
        """pd_test_event.py's expected title is pdlib.transformer_title: the two must agree."""
        cases = [SAMPLE, notification(documentation=UNSET), notification(documentation=UNSET, policy_name=UNSET),
                 notification(documentation__subject="[RESOLVED] beta · x"),
                 notification(documentation__subject="[ALERT - Warning] TPA · URGENT a thing: which"),
                 notification(documentation__subject="[ALERT - Warning] Something on a resource"),
                 notification(documentation__subject="beta · " + "y" * 400),
                 notification(documentation__subject=None, policy_name="  p ", condition_name=" c "),
                 {"incident": {}, "version": "1.2"}, {"incident": {"summary": 7}}]
        for body in cases:
            with self.subTest(subject=(body["incident"].get("documentation") or {}).get("subject")):
                if not body["incident"]:
                    continue  # an empty object is no incident to the code; Python is never asked for one
                self.assertEqual(pdlib.transformer_title(body["incident"]), self.event(body)["description"])


@unittest.skipIf(fakes.NODE is None, NO_NODE)
class WatchtowerPages(unittest.TestCase):
    """The page an alert links to, from the alert alone: the first match wins."""

    def page(self, incident: dict) -> str:
        ran = fakes.run_transform(pdlib.transformer_code(), {"incident": incident})
        (event,) = ran["events"]
        prefix = f"{BASE}/d/"
        self.assertTrue(event["details"]["dashboard"].startswith(prefix))
        self.assertEqual(event["details"]["overview"], f"{prefix}tw-cloud-overview")
        self.assertEqual(event["contexts"][0]["href"], event["details"]["dashboard"])
        return event["details"]["dashboard"][len(prefix):]

    def test_first_match_wins(self):
        app = {"labels": {"project_id": "trellistpa-beta-tpa-app"}, "type": "cloud_run_revision"}
        for expected, incident in [
            ("tw-cloud-jobs", {"metric": {"type": "logging.googleapis.com/user/tpa_jobs_alerts"}, "resource": app}),
            ("tw-cloud-jobs", {"resource": {"type": "cloud_run_job", "labels": {"project_id": "x-tpa-phi"}}}),
            ("tw-cloud-jobs", {"resource": {"type": "cloud_scheduler_job", "labels": {}}}),
            ("tw-cloud-jobs", {"policy_name": "beta: tpa-jobs drains stopped", "resource": app}),
            ("tw-cloud-jobs", {"metric": {"type": "x/tpa_jobs_alerts"},
                               "resource": {"type": "cloudsql_database", "labels": {}}}),
            ("tw-cloud-databases", {"metric": {"type": "cloudsql.googleapis.com/database/up"},
                                    "resource": {"type": "cloudsql_database",
                                                 "labels": {"project_id": "trellistpa-beta-tpa-phi"}}}),
            ("tw-cloud-sign-in", {"metric": {"type": "logging.googleapis.com/user/auth_lockouts"}, "resource": {
                "type": "cloud_run_revision", "labels": {"service_name": "auth", "project_id": "p-tpa-app"}}}),
            ("tw-cloud-sign-in", {"documentation": {"subject": "[ALERT - Error] beta · Sign-in messages waiting"},
                                  "resource": app}),
            ("tw-cloud-service-auth", {"metric": {"type": "run.googleapis.com/request_count"}, "resource": {
                "type": "cloud_run_revision", "labels": {"service_name": "auth", "project_id": "p-tpa-app"}}}),
            ("tw-cloud-service-records", {"resource": {"type": "cloud_run_revision", "labels": {
                "service_name": "records", "project_id": "trellistpa-beta-tpa-phi"}}}),
            ("tw-cloud-service-svc-voice", {"resource": {"labels": {"service_name": "svc-voice",
                                                                    "project_id": "trellistpa-beta-cc"}}}),
            ("tw-cloud-portal-api", {"resource": {"labels": {"service_name": "a-service-with-no-page",
                                                             "project_id": "trellistpa-beta-tpa-app"}}}),
            ("tw-cloud-portal-api", {"resource": app}),
            ("tw-cloud-records", {"resource": {"labels": {"project_id": "trellistpa-beta-tpa-phi"}}}),
            ("tw-cloud-callcentre", {"resource": {"labels": {"project_id": "trellistpa-beta-cc"}}}),
            ("tw-cloud-records", {"scoping_project_id": "trellistpa-production-tpa-phi"}),
            ("tw-cloud-overview", {"resource": {"labels": {"project_id": "trellistpa-beta-tpa-app-2"}}}),
            ("tw-cloud-overview", {"resource": {"labels": {"service_name": "constructor"}}}),
            ("tw-cloud-overview", {"summary": "nothing to go on"}),
        ]:
            with self.subTest(incident=incident):
                self.assertEqual(self.page({"incident_id": "x", **incident}), expected)


class PagesExist(unittest.TestCase):
    """Every page the code can link to is a page of the watchtower (cloud/dashboards): a renamed dashboard fails
    here. Read from the file's text, so it runs without node."""

    def setUp(self):
        self.code = JS.read_text(encoding="utf-8")
        self.uids = dashboard_uids()

    def service_pages(self) -> list[str]:
        (block,) = re.findall(r"var SERVICE_PAGES = \[(.*?)\];", self.code, re.S)
        return re.findall(r'"([^"]+)"', block)

    def test_the_service_pages_are_the_service_files(self):
        on_disk = sorted(p.name[len("service-"):-len(".json")] for p in DASHBOARDS.glob("service-*.json"))
        self.assertEqual(sorted(self.service_pages()), on_disk)
        self.assertIn('var SERVICE_UID = "tw-cloud-service-";', self.code)
        for name in self.service_pages():
            self.assertEqual(self.uids.get(f"tw-cloud-service-{name}"), f"service-{name}.json")

    def test_every_uid_the_code_can_emit_exists(self):
        named = set(re.findall(r'"(tw-cloud-[a-z0-9-]+)"', self.code)) - {"tw-cloud-service-"}
        self.assertEqual(named, {"tw-cloud-overview", "tw-cloud-jobs", "tw-cloud-databases", "tw-cloud-sign-in",
                                 "tw-cloud-portal-api", "tw-cloud-records", "tw-cloud-callcentre"})
        can_emit = named | {f"tw-cloud-service-{name}" for name in self.service_pages()}
        self.assertEqual(can_emit - set(self.uids), set())
        self.assertEqual(len(re.findall(r"\buid: ", self.code)), len(named) + 1, "a uid written some other way")

    def test_the_address_is_put_in_once_and_nowhere_else(self):
        self.assertEqual(self.code.count(pdlib.WATCHTOWER_PLACEHOLDER), 1)
        self.assertNotIn("http", self.code.replace("https://console", ""), "no address but the placeholder's")
        stored = pdlib.transformer_code()
        self.assertNotIn(pdlib.WATCHTOWER_PLACEHOLDER, stored)
        self.assertIn(f'var WATCHTOWER = "{pdlib.WATCHTOWER_URL}";', stored)
        self.assertRegex(pdlib.WATCHTOWER_URL, r"^https://[a-z0-9.-]+$")


class Es5(unittest.TestCase):
    """PagerDuty's transformer runtime is ES5: the file must not use anything newer, in any form."""

    def code(self) -> str:
        """The code without its comment lines."""
        return "\n".join(line for line in JS.read_text(encoding="utf-8").splitlines()
                         if not line.lstrip().startswith("//"))

    def test_nothing_newer_than_es5(self):
        code = self.code()
        for pattern, what in [(r"=>", "an arrow function"), (r"`", "a template string"), (r"\blet\s", "let"),
                              (r"\bconst\s", "const"), (r"\bclass\s", "class"), (r"\.\.\.[A-Za-z_(\[]", "a spread"),
                              (r"\basync\b|\bawait\b", "async"), (r",\s*[\]})]", "a trailing comma"),
                              (r"\bfor\s*\([^)]*\bof\b", "for-of"),
                              (r"\.(includes|startsWith|endsWith|padStart|repeat|assign|entries|values|find|trim)\(",
                               "a method newer than ES5"),
                              (r"\brequire\(|\bconsole\.|\bprocess\.", "something PagerDuty's runtime lacks")]:
            with self.subTest(what=what):
                self.assertIsNone(re.search(pattern, code), f"{JS.name} uses {what}")

    def test_ascii_only(self):
        text = JS.read_text(encoding="utf-8")
        self.assertEqual([c for c in text if ord(c) > 126 or (ord(c) < 32 and c != "\n")], [])
        self.assertFalse(any(line != line.rstrip() for line in text.splitlines()), "no space at a line's end")
        self.assertEqual(pdlib.normalise_code(text), text.strip())

    @unittest.skipIf(fakes.NODE is None, NO_NODE)
    def test_node_parses_it(self):
        done = subprocess.run([fakes.NODE, "--check", str(JS)], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)

    @unittest.skipIf(fakes.NODE is None, NO_NODE)
    def test_it_runs_in_strict_mode_with_nothing_but_pd(self):
        """The stub's context holds PD alone: a stray global or an undeclared variable would throw here."""
        ran = fakes.run_transform('"use strict";\n' + pdlib.transformer_code(), SAMPLE)
        self.assertIsNone(ran["error"], ran["error"])
        self.assertEqual(len(ran["events"]), 1)


if __name__ == "__main__":
    unittest.main()
