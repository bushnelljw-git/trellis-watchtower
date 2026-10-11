"""scripts/pagerduty/pd_setup.py against a fake PagerDuty (fakes.py): an automated gate only.

Run: python3 -m unittest discover -s tests/pagerduty -v
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import fakes

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SCRIPTS = ROOT / "scripts" / "pagerduty"
sys.path.insert(0, str(SCRIPTS))
import pd_setup  # noqa: E402
import pdlib  # noqa: E402

SUMMARY_STEADY_DRY = r"^summary: 0 to create, 0 to update, \d+ ok, 0 kept, 0 refused, 3 by hand$"


def run(server, script, *args, token=fakes.TOKEN, path_prefix=None):
    env = {k: v for k, v in os.environ.items() if k not in ("PAGERDUTY_TOKEN",)}
    env.update({
        "PAGERDUTY_API_URL": server.url("pd"),
        "PAGERDUTY_EVENTS_URL": server.url("events"),
        "MONITORING_API_URL": server.url("gcp"),
        "PAGERDUTY_SLACK_API_URL": server.url("slack"),
    })
    if token is not None:
        env["PAGERDUTY_TOKEN"] = token
    if path_prefix:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], capture_output=True, text=True, env=env,
                          timeout=120)


class Base(unittest.TestCase):
    state_options: dict = {}
    extra_secrets: list[str] = []

    def setUp(self):
        self.state = fakes.FakeState(**self.state_options)
        self.server = fakes.Server(self.state).__enter__()
        self.outputs: list[str] = []

    def tearDown(self):
        self.server.__exit__(None, None, None)
        self.assert_no_secret_printed()

    def pd(self, *args, **kw):
        result = run(self.server, "pd_setup.py", *args, **kw)
        self.outputs += [result.stdout, result.stderr]
        return result

    def apply(self, *extra):
        """The first live setup: --apply --add-rules (a plain --apply never creates a notification rule)."""
        result = self.pd("--apply", "--add-rules", *extra)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def assert_no_secret_printed(self):
        keys = [i["integration_key"] for items in self.state.integrations.values() for i in items]
        for text in self.outputs:
            for value in [fakes.TOKEN, fakes.GOOGLE_TOKEN, fakes.KEY_PREFIX, *keys, *self.extra_secrets]:
                self.assertNotIn(value, text)

    def summary(self, result) -> str:
        return [line for line in result.stdout.splitlines() if line.startswith("summary:")][-1]

    def service_id(self, name):
        return next(s for s, v in self.state.services.items() if v["name"] == name)


class DryRunAndIdempotency(Base):
    def test_dry_run_writes_nothing_and_plans_the_design(self):
        result = self.pd()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.writes(), [], "a dry run must make no write")
        for line in [
            'create    team "TPA Platform"',
            'create    schedule "TPA primary on-call"',
            'create    escalation policy "TPA Platform"',
            'create    service "TPA beta · Portal & API"',
            'create      alert grouping on "TPA beta · Member records"',
            'create    service "TPA beta · Call centre"',
            'create    business service "Trellis TPA (beta)"',
            'kept      notification rule Jonathan Bushnell: high urgency -> Slack "slack" at 0 min  [missing, not '
            'added: rules are created only with --add-rules]',
            'ok        notification rule Jonathan Bushnell: high urgency -> email "Default" at 0 min',
        ]:
            self.assertIn(line, result.stdout)
        self.assertIn("summary: 24 to create, 0 to update, 4 ok, 2 kept, 0 refused, 3 by hand", result.stdout)
        with_rules = self.pd("--add-rules")
        self.assertIn('create    notification rule Jonathan Bushnell: high urgency -> Slack "slack" at 0 min',
                      with_rules.stdout)
        self.assertIn("summary: 26 to create", with_rules.stdout)
        self.assertEqual(self.state.writes(), [])
        self.assertIn('by hand     Slack: "TPA beta · Call centre"  [not connected: a person connects it to '
                      '#tpa-beta-alerts', result.stdout)

    def test_apply_then_rerun_changes_nothing(self):
        first = self.apply()
        self.assertIn("summary: created 26, updated 0", first.stdout)
        writes_after_first = len(self.state.writes())

        again = self.pd()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertRegex(self.summary(again), SUMMARY_STEADY_DRY)

        third = self.pd("--apply")
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertEqual(len(self.state.writes()), writes_after_first, "a re-run with --apply must write nothing")
        self.assertRegex(self.summary(third), r"^summary: created 0, updated 0, ok \d+, kept 0, refused 0, by hand 3$")

    def test_drift_is_corrected_then_steady(self):
        self.apply()
        sid = self.service_id("TPA beta · Member records")
        self.state.services[sid]["acknowledgement_timeout"] = 600
        self.state.orchestrations[sid]["sets"][0]["rules"].pop()
        drift = self.pd()
        self.assertIn('update    service "TPA beta · Member records"  [acknowledgement timeout]', drift.stdout)
        self.assertIn('update      event orchestration on "TPA beta · Member records"', drift.stdout)
        self.apply()
        self.assertEqual(self.state.services[sid]["acknowledgement_timeout"], 1800)
        self.assertRegex(self.summary(self.pd()), SUMMARY_STEADY_DRY)

    def test_the_old_case_sensitive_rules_are_replaced(self):
        self.apply()
        sid = self.service_id("TPA beta · Portal & API")
        for rule in self.state.orchestrations[sid]["sets"][0]["rules"]:
            word = re.search(r"\*(\w+)\[", rule["conditions"][0]["expression"]).group(1)
            rule["conditions"] = [{"expression": f"event.custom_details.incident.severity matches part '{word}'"}]
        self.assertIn('update      event orchestration on "TPA beta · Portal & API"', self.pd().stdout)
        self.apply()
        self.assertIn("matches regex", self.state.orchestrations[sid]["sets"][0]["rules"][0]["conditions"][0]
                      ["expression"])


class TheDesign(Base):
    def setUp(self):
        super().setUp()
        self.apply()
        self.by_name = {v["name"]: v for v in self.state.services.values()}

    def test_team_schedule_and_escalation(self):
        (team_id, team), = self.state.teams.items()
        self.assertEqual(team["name"], "TPA Platform")
        self.assertEqual(self.state.members[team_id], {"PJON": "manager", "PRAF": "manager"})

        (schedule,) = self.state.schedules.values()
        self.assertEqual(schedule["time_zone"], "America/Chicago")
        (layer,) = schedule["schedule_layers"]
        self.assertEqual([u["user"]["id"] for u in layer["users"]], ["PJON"])
        self.assertEqual(layer["rotation_turn_length_seconds"], 7 * 24 * 3600)
        self.assertEqual(layer["rotation_virtual_start"], "2026-10-05T14:00:00Z")  # Monday 09:00 CDT

        ep = next(p for p in self.state.policies.values() if p["name"] == "TPA Platform")
        self.assertEqual(ep["num_loops"], 2)
        self.assertEqual([t["id"] for t in ep["teams"]], [team_id])
        rules = [(r["escalation_delay_in_minutes"], [(t["type"], t["id"]) for t in r["targets"]])
                 for r in ep["escalation_rules"]]
        self.assertEqual(rules, [(15, [("schedule_reference", schedule["id"])]), (15, [("user_reference", "PRAF")])])

    def test_services_and_their_grouping_settings(self):
        ep = next(p for p in self.state.policies.values() if p["name"] == "TPA Platform")
        for name in ("TPA beta · Portal & API", "TPA beta · Member records", "TPA beta · Call centre"):
            svc = self.by_name[name]
            self.assertEqual(svc["escalation_policy"]["id"], ep["id"])
            self.assertEqual(svc["incident_urgency_rule"], {"type": "constant", "urgency": "severity_based"})
            self.assertEqual(svc["acknowledgement_timeout"], 1800)
            self.assertIsNone(svc["auto_resolve_timeout"])
            self.assertNotIn("alert_grouping_parameters", svc, "the deprecated service field is never sent")
            (setting,) = [g for g in self.state.grouping.values() if svc["id"] in [s["id"] for s in g["services"]]]
            self.assertEqual((setting["name"], setting["type"]), (name, "intelligent"))
            (integ,) = self.state.integrations[svc["id"]]
            self.assertEqual(integ["vendor"]["id"], "PUCLE3C")
            self.assertEqual(integ["type"], "generic_events_api_inbound_integration")
            self.assertTrue(self.state.active[svc["id"]])

    def test_orchestration_rules_exact_conditions(self):
        for svc in (self.by_name[n] for n in ("TPA beta · Portal & API", "TPA beta · Call centre")):
            path = self.state.orchestrations[svc["id"]]
            (start,) = path["sets"]
            self.assertEqual(start["id"], "start")
            got = [([c["expression"] for c in r["conditions"]], r["actions"]["severity"], r["actions"]["priority"])
                   for r in start["rules"]]
            field = "event.custom_details.incident.severity matches regex"
            self.assertEqual(got, [
                ([f"{field} '(?i)^[[:space:]]*Critical[[:space:]]*$'"], "critical", "PRI1"),
                ([f"{field} '(?i)^[[:space:]]*Error[[:space:]]*$'"], "error", "PRI2"),
                ([f"{field} '(?i)^[[:space:]]*Warning[[:space:]]*$'"], "warning", "PRI3"),
            ])
            catch_all = {k: v for k, v in path["catch_all"]["actions"].items() if v not in (None, False, [], {})}
            self.assertEqual(catch_all, {}, "anything unmapped must keep PagerDuty's default severity")

    def test_the_rules_ignore_letter_case(self):
        """Every casing Monitoring might send, through the rules exactly as written to PagerDuty."""
        sid = self.by_name["TPA beta · Portal & API"]["id"]
        rules = self.state.orchestrations[sid]["sets"][0]["rules"]

        def outcome(severity):
            details = {"incident": {"severity": severity}}
            for rule in rules:
                if all(fakes.FakeState.pcl(c["expression"], details) for c in rule["conditions"]):
                    return rule["actions"]["severity"]
            return "default"

        for text in ("warning", "WARNING", "Warning", " warning ", "wArNiNg", "Warning\t", "Warning\n", "\tWarning"):
            self.assertEqual(outcome(text), "warning", repr(text))
        for text in ("critical", "CRITICAL", "Critical"):
            self.assertEqual(outcome(text), "critical", text)
        for text in ("error", "ERROR", "Error"):
            self.assertEqual(outcome(text), "error", text)
        for text in ("no severity", "No severity", "warnings", "not critical", "", "Warning x", "Warning\nx"):
            self.assertEqual(outcome(text), "default", repr(text))

    def test_business_service(self):
        (b,) = self.state.business.values()
        self.assertEqual(b["name"], "Trellis TPA (beta)")
        supported = sorted(self.state.services[s]["name"] for s, bid in self.state.dependencies if bid == b["id"])
        self.assertEqual(supported, ["TPA beta · Call centre", "TPA beta · Member records", "TPA beta · Portal & API"])

    def test_notification_rules_add_slack_and_keep_email(self):
        jon = {(r["contact_method"]["type"], r["urgency"], r["start_delay_in_minutes"])
               for r in self.state.users["PJON"]["notification_rules"]}
        self.assertEqual(jon, {("email_contact_method", "high", 0), ("email_contact_method", "low", 0),
                               ("slack_contact_method", "high", 0), ("slack_contact_method", "low", 0)})
        self.assertEqual(len(self.state.users["PRAF"]["notification_rules"]), 2)
        self.assertEqual(self.state.users["POTHER"]["notification_rules"], [])

    def test_default_service_and_policy_untouched_and_nothing_deleted(self):
        touched = [r for r in self.state.writes() if "PDEFSVC" in r["path"] or "PDEFEP" in r["path"]]
        self.assertEqual(touched, [])
        self.assertEqual([r for r in self.state.requests if r["method"] == "DELETE"], [])
        self.assertEqual(self.state.services["PDEFSVC"]["incident_urgency_rule"]["urgency"], "high")

    def test_token_only_in_the_authorization_header(self):
        for r in self.state.requests:
            self.assertNotIn(fakes.TOKEN, r["path"] + r["query"] + r["raw"])


class Fallbacks(Base):
    state_options = {"refuse_intelligent": True, "rich_contacts": True}

    def test_refused_intelligent_grouping_falls_back_to_time_based_and_is_steady(self):
        result = self.apply()
        self.assertIn("PagerDuty refused intelligent alert grouping", result.stdout)
        self.assertEqual(len(self.state.grouping), 3)
        for setting in self.state.grouping.values():
            self.assertEqual((setting["type"], setting["config"]), ("time", {"timeout": 10}))
        self.assertRegex(self.summary(self.pd()), SUMMARY_STEADY_DRY)
        retry = self.pd("--retry-intelligent-grouping")
        self.assertIn("update      alert grouping on", retry.stdout)

    def test_new_contact_methods_get_rules_phone_and_sms_at_high_only(self):
        self.apply()
        jon = {(r["contact_method"]["type"], r["urgency"], r["start_delay_in_minutes"])
               for r in self.state.users["PJON"]["notification_rules"]}
        self.assertEqual(jon, {
            ("email_contact_method", "high", 0), ("email_contact_method", "low", 0),
            ("slack_contact_method", "high", 0), ("slack_contact_method", "low", 0),
            ("push_notification_contact_method", "high", 0), ("push_notification_contact_method", "low", 0),
            ("sms_contact_method", "high", 0), ("phone_contact_method", "high", 3),
        })

    def test_a_plain_apply_never_creates_a_rule(self):
        before = len(self.state.users["PJON"]["notification_rules"])
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(len(self.state.users["PJON"]["notification_rules"]), before)
        self.assertIn("kept      notification rule Jonathan Bushnell: high urgency -> phone call", result.stdout)
        self.assertEqual([r for r in self.state.writes() if "notification_rules" in r["path"]], [])

    def test_a_methods_only_rule_removed_is_not_put_back(self):
        self.apply()
        self.state.delete_rule("PJON", "CMJPHONE", "high")  # the phone's only rule: the person wants no calls
        self.pd("--apply")
        rules = self.state.users["PJON"]["notification_rules"]
        self.assertNotIn("CMJPHONE", {r["contact_method"]["id"] for r in rules})

    def test_a_persons_own_rule_is_kept(self):
        self.state.add_rule("PJON", "CMJSMS", "high", 5)
        result = self.pd("--apply")
        self.assertIn("kept      notification rule Jonathan Bushnell: high urgency -> SMS", result.stdout)
        sms_high = [r for r in self.state.users["PJON"]["notification_rules"]
                    if r["contact_method"]["id"] == "CMJSMS" and r["urgency"] == "high"]
        self.assertEqual([r["start_delay_in_minutes"] for r in sms_high], [5])


class GroupingErrorThatIsNotAboutIntelligent(Base):
    state_options = {"grouping_error": (400, "Alert grouping time window must be at most 3600")}

    def test_no_fallback_on_an_unrelated_error(self):
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertNotIn("refused intelligent alert grouping", result.stdout)
        self.assertIn("refused     alert grouping on", result.stdout)
        self.assertEqual(self.state.grouping, {})


class PersonDeletedRule(Base):
    def setUp(self):
        super().setUp()
        self.apply()
        self.state.delete_rule("PJON", "CMJSLACK", "low")

    def test_a_deleted_rule_is_not_put_back(self):
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('kept      notification rule Jonathan Bushnell: low urgency -> Slack "slack" at 0 min  [missing, '
                      "not added", result.stdout)
        self.assertNotIn(("CMJSLACK", "low"), {(r["contact_method"]["id"], r["urgency"])
                                               for r in self.state.users["PJON"]["notification_rules"]})

    def test_add_rules_puts_it_back_on_request(self):
        result = self.pd("--apply", "--add-rules")
        self.assertIn('created   notification rule Jonathan Bushnell: low urgency -> Slack', result.stdout)


class ScheduleWithTwoLayers(Base):
    def test_refused_and_left_unchanged(self):
        self.apply()
        (schedule,) = self.state.schedules.values()
        schedule["schedule_layers"].append({**schedule["schedule_layers"][0], "id": "PLEXTRA", "name": "Extra"})
        before = len(self.state.writes())
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('refused   schedule "TPA primary on-call"  [2 active layers', result.stdout)
        self.assertEqual(len(self.state.writes()), before)


class RenamedService(Base):
    def test_renamed_with_a_new_description_is_still_refused(self):
        self.apply()
        sid = self.service_id("TPA beta · Member records")
        self.state.services[sid].update(name="Records (old)", description="something else")
        before = len(self.state.writes())
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('refused   service "TPA beta · Member records"  [not created: "Records (old)" carries its '
                      "integration (renamed?)", result.stdout)
        self.assertEqual(len(self.state.writes()), before)

    def test_a_renamed_service_is_not_duplicated(self):
        self.apply()
        sid = self.service_id("TPA beta · Call centre")
        self.state.services[sid]["name"] = "Call centre (old)"
        before = len(self.state.writes())
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('refused   service "TPA beta · Call centre"  [not created: "Call centre (old)" carries its '
                      "integration and description", result.stdout)
        self.assertEqual(len(self.state.writes()), before)
        self.assertEqual(sum(1 for s in self.state.services.values() if s["description"].startswith("The beta call")),
                         1)


class ParentRefused(Base):
    state_options = {"refuse_team_create": True}

    def test_the_run_stops_and_no_url_is_built_from_a_placeholder(self):
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('stopped: team "TPA Platform" was refused', result.stdout)
        for r in self.state.requests:
            self.assertNotIn("<", r["path"])
            self.assertNotIn("%3C", r["path"] + r["query"])
        self.assertEqual([r for r in self.state.writes() if r["method"] != "POST" or r["path"] != "/pd/teams"], [])

    def test_placeholder_guard(self):
        client = pdlib.PagerDuty("x", writes=True)
        with self.assertRaises(RuntimeError):
            client.write("PUT", "/teams/<new team>/users/P1", {})


class SlackReport(Base):
    def setUp(self):
        super().setUp()
        self.apply()
        self.ids = {v["name"]: k for k, v in self.state.services.items()}

    def connection(self, name, **config):
        full = {"events": ["incident.triggered", "incident.acknowledged", "incident.escalated", "incident.resolved",
                           "incident.reassigned"], "urgency": None, "priorities": ["*"]}
        return {"source_id": self.ids[name], "channel_name": "tpa-beta-alerts", "config": {**full, **config}}

    def test_connections_are_reported_never_made(self):
        self.state.slack_connections = [
            self.connection("TPA beta · Portal & API"),
            self.connection("TPA beta · Member records", events=["incident.triggered", "incident.resolved"],
                            urgency="high", priorities=["PRI1"]),
        ]
        result = self.pd()
        self.assertIn('ok          Slack: "TPA beta · Portal & API" connected to #tpa-beta-alerts', result.stdout)
        self.assertIn('by hand     Slack: "TPA beta · Member records" connected to #tpa-beta-alerts  [in PagerDuty, '
                      'set events: add acknowledged, escalated, reassigned; urgency: both high and low (it is high '
                      'only); priorities: all]', result.stdout)
        self.assertIn('by hand     Slack: "TPA beta · Call centre"  [not connected', result.stdout)
        self.assertEqual([r for r in self.state.requests if r["path"].startswith("/slack") and r["method"] != "GET"],
                         [])

    def test_an_empty_priority_filter_is_a_gap(self):
        self.state.slack_connections = [self.connection("TPA beta · Portal & API", priorities=[])]
        self.assertIn("priorities: all]", self.pd().stdout)
        self.assertEqual(pd_setup.slack_gaps({"events": [], "priorities": None}, ["PRI1"])[-1], "priorities: all")
        self.assertNotIn("priorities: all", pd_setup.slack_gaps({"priorities": ["PRI1", "PRI2"]}, ["PRI1", "PRI2"]))


class Secrets(Base):
    extra_secrets = ["wrong-token-0000"]

    def test_keychain_is_read_when_no_env_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "security.log"
            fake = Path(tmp) / "security"
            fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\necho "{fakes.TOKEN}"\n')
            fake.chmod(0o755)
            result = self.pd(token=None, path_prefix=tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.read_text().strip(), "find-generic-password -s tpa-pagerduty-api -w")

    def test_a_401_that_echoes_the_token_never_prints_it(self):
        result = self.pd(token="wrong-token-0000")
        self.assertEqual(result.returncode, 1)
        self.assertIn("HTTP 401", result.stderr)
        self.assertIn("<redacted>", result.stderr, "the fake echoed the token; it must come out scrubbed")

    def test_api_url_override_must_be_loopback(self):
        env = {**os.environ, "PAGERDUTY_API_URL": "https://example.com", "PAGERDUTY_TOKEN": fakes.TOKEN}
        result = subprocess.run([sys.executable, str(SCRIPTS / "pd_setup.py")], capture_output=True, text=True,
                                env=env, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn("may only be https://api.pagerduty.com or a loopback address", result.stderr)

    def test_scrub_replaces_registered_secrets(self):
        pdlib.secret("abcdef123456")
        self.assertEqual(pdlib.scrub("key abcdef123456 end"), "key <redacted> end")
        pdlib.register_secrets({"integrations": [{"integration_key": "zzzz99998888"}]})
        self.assertEqual(pdlib.scrub("zzzz99998888"), "<redacted>")

    def test_child_processes_never_get_the_token(self):
        os.environ["PAGERDUTY_TOKEN"] = "child-env-check-1234"
        try:
            self.assertNotIn("PAGERDUTY_TOKEN", pdlib.child_env())
        finally:
            del os.environ["PAGERDUTY_TOKEN"]


class Redirects(Base):
    state_options = {"redirect_pd": True}

    def test_a_redirect_is_never_followed(self):
        result = self.pd()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("HTTP 302", result.stderr)
        self.assertEqual([r for r in self.state.requests if r["path"].startswith("/capture")], [],
                         "the Authorization header must not follow a redirect")


if __name__ == "__main__":
    unittest.main()
