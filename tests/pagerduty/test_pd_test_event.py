"""scripts/pagerduty/pd_test_event.py against the fakes (fakes.py): an automated gate only.

Run: python3 -m unittest discover -s tests/pagerduty -v
"""

from __future__ import annotations

import unittest

from test_pd_setup import Base, run


class TestEvents(Base):
    """pd_test_event.py: the fake applies the orchestration the way the design describes."""

    def setUp(self):
        super().setUp()
        self.apply()

    def event(self, *args):
        result = run(self.server, "pd_test_event.py", *args)
        self.outputs += [result.stdout, result.stderr]
        return result

    def test_dry_run_sends_nothing_and_hides_the_key(self):
        result = self.event("--role", "phi", "--severity", "Warning")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r for r in self.state.requests if r["path"].startswith("/events")], [])
        self.assertIn('"severity": "Warning"', result.stdout)
        self.assertNotIn('"service_key":', result.stdout)

    def test_warning_in_every_casing_is_low_urgency_warning_p3_and_is_resolved(self):
        for text in ("warning", "WARNING", "Warning"):
            result = self.event("--role", "cc", "--severity", text, "--send", "--wait", "5")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("urgency low, alert severity warning, priority P3", result.stdout, text)
            self.assertIn("as designed", result.stdout)
            self.assertIn("status resolved", result.stdout)

    def test_critical_in_every_casing_is_high_urgency_critical_p1(self):
        for text in ("critical", "CRITICAL", "Critical"):
            result = self.event("--role", "app", "--severity", text, "--send", "--wait", "5")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("urgency high, alert severity critical, priority P1", result.stdout, text)

    def test_no_severity_keeps_the_default_and_pages_high(self):
        result = self.event("--role", "app", "--severity", "no severity", "--send", "--wait", "5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("urgency high, alert severity critical, priority none", result.stdout)

    def test_summaries_say_test(self):
        self.event("--role", "app", "--severity", "error", "--send", "--wait", "5")
        (incident,) = self.state.incidents.values()
        self.assertTrue(incident["title"].startswith("TEST — PagerDuty setup check, please ignore"))


if __name__ == "__main__":
    unittest.main()
