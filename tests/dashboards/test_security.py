"""The Security page: it is what scripts/gen_security.py writes, it holds PLAN §5's local panels, an empty velocity
panel reads "none yet", the velocity contract's words agree everywhere they are written, and Home leads to it.

Run: python3 -m unittest discover -s tests/dashboards -v   (also run by `make lint` and `make check`)
"""

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import dashboard_lint  # noqa: E402
import gen_home  # noqa: E402

SECURITY = ROOT / "grafana" / "dashboards" / "security.json"
HOME = ROOT / "grafana" / "dashboards" / "home.json"
ALLOY = ROOT / "alloy" / "config.alloy"
PROM_RULES = ROOT / "prometheus" / "rules" / "home.yml"
LOKI_RULES = ROOT / "loki" / "rules" / "fake" / "home.yml"


def every_panel(dashboard):
    for p in dashboard["panels"]:
        yield p
        yield from p.get("panels") or []


def alternation(after: str, text: str) -> list[str]:
    """The words of the first `^(a|b|c)$` alternation that follows `after` in text."""
    m = re.search(re.escape(after) + r'[^\n]*?"\^\(?(?:velocity_\()?([a-z0-9_| ]+)\)?\$"', text)
    if m is None:
        raise AssertionError(f"no alternation after {after!r}")
    return m.group(1).split("|")


class SecurityPageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = json.loads(SECURITY.read_text())
        cls.home = json.loads(HOME.read_text())

    def test_security_is_what_the_generator_writes(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_security.py"), "--check"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_uid_and_tags(self):
        self.assertEqual(self.page["uid"], "tw-security")
        self.assertIn("trellis-watchtower", self.page["tags"])  # so the Dashboards menu on every page lists it

    def test_every_local_panel_of_the_plan(self):
        # PLAN §5's local column: 1-3, 5 (velocity), 4, 6-11, 15, and SPEC §7's other lines (settings changes, the
        # people's acts, the meter failing). 12-14, 16 and 17 are named in the "not on this page yet" text.
        titles = {p.get("title") for p in every_panel(self.page)}
        for title in ["Flags, holds and freezes", "By role and measure", "Calls refused while held or frozen",
                      "Freezes", "Holds", "Flags", "Report only", "Meter failed", "Limit changes",
                      "Holds lifted, freezes cleared",
                      "Alerts", "Reveals served by operation", "Sign-in failures and lockouts",
                      "Step-up failures", "Sessions revoked and logins suspended", "Refusals by gate and code",
                      "Rate limited by operation", "Staff member reads", "Findings",
                      "Anomaly findings by rule"]:
            self.assertIn(title, titles)
        text = " ".join(p["options"]["content"] for p in every_panel(self.page) if p.get("type") == "text")
        for later in ["S2", "RS-343", "IAP", "Cloud Armor", "perimeter", "secrets and keys"]:
            self.assertIn(later, text)

    def test_an_empty_velocity_panel_reads_none_yet(self):
        # Until records writes its velocity lines (its slice R1), these panels are empty: they must say so plainly.
        velocity = [p for p in every_panel(self.page)
                    if any("velocity" in t.get("expr", "") for t in p.get("targets") or [])
                    and "ALERTS" not in json.dumps(p.get("targets"))]
        self.assertGreaterEqual(len(velocity), 10)
        for p in velocity:
            defaults = p["fieldConfig"]["defaults"]
            if p["type"] == "stat":
                zero = defaults["mappings"][0]["options"]["0"]["text"]
                # A failure counter reads "none"; every state and act reads "none yet".
                self.assertEqual(zero, "none" if p["title"] == "Meter failed" else "none yet", p["title"])
                self.assertTrue(defaults["noValue"].startswith("?"), p["title"])  # blind is not "none"
            else:
                self.assertEqual(defaults["noValue"], "none yet", p["title"])

    def test_a_tile_never_reads_none_when_blind(self):
        # A count tile is 0 only when the service logged something in the range; otherwise it has no value ("?").
        for p in every_panel(self.page):
            if p.get("type") == "stat" and p["datasource"]["uid"] == "loki":
                expr = p["targets"][0]["expr"]
                self.assertIn(" or 0 * sum(count_over_time({stack=\"tpa\", service=", expr, p["title"])
                self.assertNotIn("vector(0)", expr, p["title"])

    def test_the_velocity_words_agree_everywhere(self):
        # One contract (SPEC §7), written in four places: the Alloy rebuild, the recorded series, the page and the
        # lint's vetted template. A word added in one place only would read "other" or nothing.
        alloy = ALLOY.read_text()
        self.assertEqual(alternation('v_reason }}', alloy), list(gen_home.VELOCITY_REASONS))
        self.assertEqual(alternation('v_code }}', alloy), ["flag", "hold", "freeze", "settings_changed", "meter_failed",
                                                          "freeze_unwritten", "lift", "clear_signed", "cleared"])
        self.assertEqual(alternation('v_decision }}', alloy), ["enforce", "report"])
        self.assertEqual(alternation('v_message }}', alloy), [
            "velocity", "velocity settings changed", "velocity meter failed", "velocity freeze unwritten",
            "velocity hold lifted", "velocity freeze half signed", "velocity freeze cleared"])
        self.assertEqual(len(gen_home.VELOCITY_MEASURES), 6)
        measure = dict(dashboard_lint.VETTED_LABEL_FORMATS)["measure"]
        self.assertIn("^(" + "|".join(gen_home.VELOCITY_REASONS) + ")$", measure)
        self.assertIn('code=~"velocity_(flag|hold|freeze)"', gen_home.VELOCITY_STATES)
        # The rebuild keeps only role names: the internal roles records knows (records/catalogue/registry.py).
        roles = alternation('v_role }}', alloy)
        self.assertEqual(sorted(roles), sorted([
            "tpa_admin", "claims_examiner", "claims_supervisor", "eligibility_specialist", "member_services",
            "care_navigator", "finance", "compliance_officer", "plan_administrator", "ops_agent", "ops_supervisor",
            "ops_admin"]))

    def test_the_rebuild_copies_no_identifier(self):
        # The velocity rebuild names its kept fields; none of them identifies a person, tenant, session or member.
        block = ALLOY.read_text().split("// 4b.")[1].split("// 5.")[0]
        kept = set(re.findall(r'set \$d "([a-z_]+)"', block)) | set(re.findall(r'dict "([a-z_]+)"', block))
        self.assertEqual(kept, {"service", "ts", "level", "message", "request_id", "op", "code", "decision",
                                "reason", "role", "rows", "status", "gate", "exc"})
        for name in ("principal_id", "tenant_id", "sid", "jti", "member", "subject_member_id", "door", "roles"):
            self.assertNotIn(f'"{name}"', block.split("stage.template")[1], name)


class SecurityAlertsTest(unittest.TestCase):
    def test_the_two_alerts_and_their_severity(self):
        rules = PROM_RULES.read_text()
        frozen = rules[rules.index("alert: StaffAccountFrozen"):].split("- alert:")[0]
        held = rules[rules.index("alert: StaffAccountHeld"):].split("- alert:")[0]
        self.assertIn('severity: "page"', frozen)
        self.assertIn('severity: "warning"', held)
        # A freeze line with no decision is enforced: the red alert asks `!= report`, never `= enforce`.
        self.assertIn('decision!=\\"report\\"', frozen)
        self.assertIn("tw:velocity_lines:count10m", LOKI_RULES.read_text())

    def test_home_shows_them_red_and_amber_and_leads_to_the_page(self):
        home = json.loads(HOME.read_text())
        hero = next(p for p in home["panels"] if p.get("id") == 1)
        refs = {t["refId"]: t for t in hero["targets"]}
        self.assertIn('alertname!~"ProbeDown|DatabaseReportedDown|AuthNotReady|WorkerStale|StaffAccountHeld"',
                      refs["AL"]["expr"])
        self.assertIn('alertname=~"StaffAccountHeld"', refs["AW"]["expr"])
        self.assertIn('"dash", "tw-security", "service", "StaffAccountFrozen|StaffAccountHeld"', refs["AL"]["expr"])
        colours = {o["matcher"]["options"]: {x["id"]: x["value"] for x in o["properties"]}
                   for o in hero["fieldConfig"]["overrides"]}
        self.assertEqual(colours["ALx"]["color"]["fixedColor"], gen_home.DOWN)
        self.assertEqual(colours["AWx"]["color"]["fixedColor"], gen_home.WARN)
        drill = next(p for p in home["panels"] if p.get("title") == "Drill down")
        self.assertIn('href="/d/tw-security"', drill["panels"][0]["options"]["content"])


if __name__ == "__main__":
    unittest.main()
