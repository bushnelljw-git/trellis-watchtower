"""scripts/pagerduty/gcp_channels.py and pd_test_event.py against the fakes (fakes.py): an automated gate only.

Run: python3 -m unittest discover -s tests/pagerduty -v
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

import fakes
from test_pd_setup import SCRIPTS, Base, run

sys.path.insert(0, str(SCRIPTS))
import gcp_channels  # noqa: E402

PROJECTS = ["--app", "tw-beta-tpa-app", "--phi", "tw-beta-tpa-phi", "--cc", "tw-beta-cc"]
TFVARS = re.compile(r'^alert_pagerduty_channel_ids = \{ app = "(\d+)", phi = "(\d+)", cc = "(\d+)" \}$')


class WithGcloud(Base):
    gcloud_fails = False

    def setUp(self):
        super().setUp()
        self.assertEqual(self.pd("--apply").returncode, 0)
        self.tmp = tempfile.TemporaryDirectory()
        self.gcloud_log = Path(self.tmp.name) / "gcloud.log"
        gcloud = Path(self.tmp.name) / "gcloud"
        body = "exit 1" if self.gcloud_fails else f'echo "{fakes.GOOGLE_TOKEN}"'
        gcloud.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{self.gcloud_log}"\n{body}\n')
        gcloud.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()
        super().tearDown()

    def channels(self, *args):
        result = run(self.server, "gcp_channels.py", *PROJECTS, *args, path_prefix=self.tmp.name)
        self.outputs += [result.stdout, result.stderr]
        return result

    def keys(self):
        return {self.state.services[sid]["name"]: items[0]["integration_key"]
                for sid, items in self.state.integrations.items() if items}

    def stored(self):
        return {p: {c["displayName"]: c["_key"] for c in chans.values()} for p, chans in self.state.channels.items()}


class Channels(WithGcloud):
    def test_dry_run_writes_nothing_and_prints_nulls(self):
        result = self.channels()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.writes("/gcp"), [])
        self.assertEqual(result.stdout.strip(), "alert_pagerduty_channel_ids = { app = null, phi = null, cc = null }")
        self.assertIn('create     tw-beta-tpa-phi: channel "PagerDuty · TPA beta · Member records"', result.stderr)

    def test_apply_creates_each_projects_channel_with_its_own_key_then_is_steady(self):
        first = self.channels("--apply")
        self.assertEqual(first.returncode, 0, first.stderr)
        ids = TFVARS.match(first.stdout.strip())
        self.assertIsNotNone(ids, first.stdout)
        keys = self.keys()
        self.assertEqual(self.stored(), {
            "tw-beta-tpa-app": {"PagerDuty · TPA beta · Portal & API": keys["TPA beta · Portal & API"]},
            "tw-beta-tpa-phi": {"PagerDuty · TPA beta · Member records": keys["TPA beta · Member records"]},
            "tw-beta-cc": {"PagerDuty · TPA beta · Call centre": keys["TPA beta · Call centre"]},
        })
        writes = len(self.state.writes("/gcp"))
        self.assertEqual(writes, 3)

        again = self.channels("--apply")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(len(self.state.writes("/gcp")), writes, "a re-run must write nothing")
        self.assertEqual(again.stdout, first.stdout)

    def test_key_only_in_request_bodies_never_in_urls_or_argv(self):
        self.channels("--apply")
        for r in self.state.requests:
            for key in self.keys().values():
                self.assertNotIn(key, r["path"] + r["query"])
        self.assertEqual(self.gcloud_log.read_text().splitlines(), ["auth print-access-token"])

    def test_a_changed_key_is_sent_again_with_only_the_labels_mask(self):
        self.channels("--apply")
        chans = self.state.channels["tw-beta-tpa-app"]
        (ch,) = chans.values()
        ch["_key"] = "stalekey0000000000000000000wxyz"
        result = self.channels("--apply")
        self.assertIn("updated    tw-beta-tpa-app", result.stderr)
        patch = [r for r in self.state.writes("/gcp") if r["method"] == "PATCH"]
        self.assertEqual(len(patch), 1)
        self.assertEqual(patch[0]["query"], "updateMask=labels")
        self.assertEqual(ch["_key"], self.keys()["TPA beta · Portal & API"])

    def test_wrongly_named_project_is_refused(self):
        result = run(self.server, "gcp_channels.py", "--app", "tw-beta-tpa-phi", "--phi", "tw-beta-tpa-app",
                     "--cc", "tw-beta-cc", path_prefix=self.tmp.name)
        self.assertEqual(result.returncode, 2)
        self.assertIn("is not a app project id", result.stderr)


class FullyMasked(WithGcloud):
    state_options = {"mask": "all"}

    def test_an_unreadable_key_is_left_alone_unless_rekey(self):
        self.channels("--apply")
        steady = self.channels("--apply")
        self.assertIn("Google shows none of its key; --rekey sends it again", steady.stderr)
        self.assertEqual(len(self.state.writes("/gcp")), 3)
        self.channels("--apply", "--rekey")
        self.assertEqual(len(self.state.writes("/gcp")), 6)


class NoAccess(WithGcloud):
    state_options = {"forbidden_projects": ["tw-beta-tpa-phi"]}

    def test_dry_run_reports_a_project_it_cannot_read(self):
        result = self.channels()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tw-beta-tpa-phi: cannot read its channels (HTTP 403", result.stderr)

    def test_apply_writes_nothing_when_a_project_cannot_be_read(self):
        result = self.channels("--apply")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.state.writes("/gcp"), [])


class NoGcloudLogin(WithGcloud):
    gcloud_fails = True

    def test_dry_run_still_plans_and_apply_refuses(self):
        dry = self.channels()
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("cannot read Google Cloud", dry.stderr)
        self.assertEqual(self.channels("--apply").returncode, 2)


class KeyComparison(unittest.TestCase):
    def test_key_matches(self):
        key = "0123456789abcdef0123456789abcdef"
        self.assertTrue(gcp_channels.key_matches(key, key))
        self.assertTrue(gcp_channels.key_matches("*" * 28 + "cdef", key))
        self.assertTrue(gcp_channels.key_matches("****cdef", key))
        self.assertFalse(gcp_channels.key_matches("*" * 28 + "0000", key))
        self.assertFalse(gcp_channels.key_matches("", key))
        self.assertIsNone(gcp_channels.key_matches("*" * 32, key))


class TestEvents(Base):
    """pd_test_event.py: the fake applies the orchestration the way the design describes."""

    def setUp(self):
        super().setUp()
        self.assertEqual(self.pd("--apply").returncode, 0)

    def event(self, *args):
        result = run(self.server, "pd_test_event.py", *args)
        self.outputs += [result.stdout, result.stderr]
        return result

    def test_dry_run_sends_nothing_and_hides_the_key(self):
        result = self.event("--role", "phi", "--severity", "Warning")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r for r in self.state.requests if r["path"].startswith("/events")], [])
        self.assertIn('"severity": "Warning"', result.stdout)
        self.assertNotIn("\"service_key\":", result.stdout)

    def test_warning_is_low_urgency_warning_p3_and_is_resolved(self):
        result = self.event("--role", "cc", "--severity", "Warning", "--send", "--wait", "5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("urgency low, alert severity warning, priority P3", result.stdout)
        self.assertIn("as designed", result.stdout)
        self.assertIn("status resolved", result.stdout)

    def test_critical_is_high_urgency_critical_p1(self):
        result = self.event("--role", "app", "--severity", "Critical", "--send", "--wait", "5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("urgency high, alert severity critical, priority P1", result.stdout)

    def test_no_severity_keeps_the_default_and_pages_high(self):
        result = self.event("--role", "app", "--severity", "No severity", "--send", "--wait", "5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("urgency high, alert severity critical, priority none", result.stdout)

    def test_summaries_say_test(self):
        self.event("--role", "app", "--severity", "Error", "--send", "--wait", "5")
        (incident,) = self.state.incidents.values()
        self.assertTrue(incident["title"].startswith("TEST — PagerDuty setup check, please ignore"))


if __name__ == "__main__":
    unittest.main()
