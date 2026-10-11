"""scripts/pagerduty/pd_setup.py against a fake PagerDuty (fakes.py): an automated gate only.

Run: python3 -m unittest discover -s tests/pagerduty -v
"""

from __future__ import annotations

import os
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
import pdlib  # noqa: E402


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

    def assert_no_secret_printed(self):
        keys = [i["integration_key"] for items in self.state.integrations.values() for i in items]
        for text in self.outputs:
            for value in [fakes.TOKEN, fakes.GOOGLE_TOKEN, fakes.KEY_PREFIX, *keys]:
                self.assertNotIn(value, text)

    def summary(self, result) -> str:
        return [line for line in result.stdout.splitlines() if line.startswith("summary:")][-1]


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
            'create    service "TPA beta · Member records"',
            'create    service "TPA beta · Call centre"',
            'create    business service "Trellis TPA (beta)"',
            'create    notification rule Jonathan Bushnell: high urgency -> Slack "slack" at 0 min',
            'ok        notification rule Jonathan Bushnell: high urgency -> email "Default" at 0 min',
        ]:
            self.assertIn(line, result.stdout)
        self.assertIn("summary: 23 to create, 0 to update, 4 ok, 0 kept, 3 by hand", result.stdout)
        self.assertIn('by hand     Slack: "TPA beta · Call centre"  [not connected: a person connects it to '
                      '#tpa-beta-alerts', result.stdout)

    def test_apply_then_rerun_changes_nothing(self):
        first = self.pd("--apply")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn("summary: created 23, updated 0", first.stdout)
        writes_after_first = len(self.state.writes())

        again = self.pd()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertRegex(self.summary(again), r"^summary: 0 to create, 0 to update, \d+ ok, 0 kept, 3 by hand$")

        third = self.pd("--apply")
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertEqual(len(self.state.writes()), writes_after_first, "a re-run with --apply must write nothing")
        self.assertRegex(self.summary(third),
                         r"^summary: created 0, updated 0, ok \d+, kept 0, refused 0, by hand 3$")

    def test_drift_is_corrected_then_steady(self):
        self.pd("--apply")
        sid = next(s for s, v in self.state.services.items() if v["name"] == "TPA beta · Member records")
        self.state.services[sid]["acknowledgement_timeout"] = 600
        self.state.orchestrations[sid]["sets"][0]["rules"].pop()
        drift = self.pd()
        self.assertIn('update    service "TPA beta · Member records"  [acknowledgement timeout]', drift.stdout)
        self.assertIn('update      event orchestration on "TPA beta · Member records"', drift.stdout)
        self.assertEqual(self.pd("--apply").returncode, 0)
        self.assertEqual(self.state.services[sid]["acknowledgement_timeout"], 1800)
        self.assertRegex(self.summary(self.pd()), r"^summary: 0 to create, 0 to update")


class TheDesign(Base):
    def setUp(self):
        super().setUp()
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
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

    def test_services(self):
        ep = next(p for p in self.state.policies.values() if p["name"] == "TPA Platform")
        for name in ("TPA beta · Portal & API", "TPA beta · Member records", "TPA beta · Call centre"):
            svc = self.by_name[name]
            self.assertEqual(svc["escalation_policy"]["id"], ep["id"])
            self.assertEqual(svc["incident_urgency_rule"], {"type": "constant", "urgency": "severity_based"})
            self.assertEqual(svc["acknowledgement_timeout"], 1800)
            self.assertIsNone(svc["auto_resolve_timeout"])
            self.assertEqual(svc["alert_grouping_parameters"], {"type": "intelligent"})
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
            self.assertEqual(got, [
                (["event.custom_details.incident.severity matches part 'Critical'"], "critical", "PRI1"),
                (["event.custom_details.incident.severity matches part 'Error'"], "error", "PRI2"),
                (["event.custom_details.incident.severity matches part 'Warning'"], "warning", "PRI3"),
            ])
            catch_all = {k: v for k, v in path["catch_all"]["actions"].items() if v not in (None, False, [], {})}
            self.assertEqual(catch_all, {}, "anything unmapped must keep PagerDuty's default severity")

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


class SlackReport(Base):
    def test_connections_are_reported_never_made(self):
        self.pd("--apply")
        ids = {v["name"]: k for k, v in self.state.services.items()}
        self.state.slack_connections = [
            {"source_id": ids["TPA beta · Portal & API"], "channel_name": "tpa-beta-alerts",
             "config": {"events": ["incident.triggered", "incident.acknowledged", "incident.escalated",
                                   "incident.resolved", "incident.reassigned"], "urgency": None,
                        "priorities": ["*"]}},
            {"source_id": ids["TPA beta · Member records"], "channel_name": "tpa-beta-alerts",
             "config": {"events": ["incident.triggered", "incident.resolved"], "urgency": "high",
                        "priorities": ["PRI1"]}},
        ]
        result = self.pd()
        self.assertIn('ok          Slack: "TPA beta · Portal & API" connected to #tpa-beta-alerts', result.stdout)
        self.assertIn('by hand     Slack: "TPA beta · Member records" connected to #tpa-beta-alerts  [in PagerDuty, '
                      'set events: add acknowledged, escalated, reassigned; urgency: both high and low (it is high '
                      'only); priorities: all]', result.stdout)
        self.assertIn('by hand     Slack: "TPA beta · Call centre"  [not connected', result.stdout)
        self.assertEqual([r for r in self.state.requests if r["path"].startswith("/slack") and r["method"] != "GET"],
                         [])


class Fallbacks(Base):
    state_options = {"refuse_intelligent": True, "rich_contacts": True}

    def test_refused_intelligent_grouping_falls_back_to_time_based_and_is_steady(self):
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PagerDuty refused intelligent alert grouping", result.stdout)
        ours = [s for s in self.state.services.values() if s["name"].startswith("TPA beta")]
        self.assertEqual(len(ours), 3)
        for svc in ours:
            self.assertEqual(svc["alert_grouping_parameters"], {"type": "time", "config": {"timeout": 10}})
        self.assertRegex(self.summary(self.pd()), r"^summary: 0 to create, 0 to update")
        retry = self.pd("--retry-intelligent-grouping")
        self.assertIn("[alert grouping]", retry.stdout)

    def test_phone_and_sms_only_at_high_urgency(self):
        self.pd("--apply")
        jon = {(r["contact_method"]["type"], r["urgency"], r["start_delay_in_minutes"])
               for r in self.state.users["PJON"]["notification_rules"]}
        self.assertEqual(jon, {
            ("email_contact_method", "high", 0), ("email_contact_method", "low", 0),
            ("slack_contact_method", "high", 0), ("slack_contact_method", "low", 0),
            ("push_notification_contact_method", "high", 0), ("push_notification_contact_method", "low", 0),
            ("sms_contact_method", "high", 0), ("phone_contact_method", "high", 3),
        })

    def test_a_persons_own_rule_is_kept(self):
        self.state.add_rule("PJON", "CMJSMS", "high", 5)
        result = self.pd("--apply")
        self.assertIn("kept      notification rule Jonathan Bushnell: high urgency -> SMS", result.stdout)
        sms_high = [r for r in self.state.users["PJON"]["notification_rules"]
                    if r["contact_method"]["id"] == "CMJSMS" and r["urgency"] == "high"]
        self.assertEqual([r["start_delay_in_minutes"] for r in sms_high], [5])


class Secrets(Base):
    def test_keychain_is_read_when_no_env_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "security.log"
            fake = Path(tmp) / "security"
            fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\necho "{fakes.TOKEN}"\n')
            fake.chmod(0o755)
            result = self.pd(token=None, path_prefix=tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.read_text().strip(), "find-generic-password -s tpa-pagerduty-api -w")

    def test_wrong_token_fails_without_printing_it(self):
        result = self.pd(token="wrong-token-0000")
        self.outputs.append(result.stdout + result.stderr)
        self.assertEqual(result.returncode, 1)
        self.assertIn("HTTP 401", result.stderr)
        self.assertNotIn("wrong-token-0000", result.stdout + result.stderr)

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


if __name__ == "__main__":
    unittest.main()
