"""The hourly mail check's three tiles on beta's overview (tpa-platform D-400, beta's mailcheck.tf).

Email checks reads the inbox's counters through the app datasource (the app project's metrics scope reads the inbox
project) the way the urgent policies read them: each lane ✓ arriving or ✕ none over the 2 h 15 min window, and the
inbox's refusals in the day. Last check: each lane's newest arrival as a time ago. Email delivery reads records' stored
SendGrid events through the PHI datasource: delivered; bounced or dropped, and spam reports, of real emails. Each
tile's steps are run here over frames shaped as Cloud Monitoring answers, through tests/cloud/grafana_model.py; the same
frames were rendered in a throwaway Grafana 12.4.11 with testdata (the pixel check of 2026-11-13).
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import catalogue as cat  # noqa: E402
import cloud_dashboards as gen  # noqa: E402
import grafana_model as model  # noqa: E402
from test_resources import RENDERED  # noqa: E402
from test_signin import END, latest, row_tiles, shown  # noqa: E402

MINUTE = 60_000
TILES = ("Email checks", "Last check", "Email delivery (24 h)")


def _tile(env: str, title: str) -> dict | None:
    return next((p for p in row_tiles(RENDERED[env]["overview"])[1] if p["title"] == title), None)


def _filters(panel: dict) -> list[list[str]]:
    return [t["timeSeriesList"]["filters"] for t in panel["targets"]]


class MailCheckTilesTest(unittest.TestCase):
    def setUp(self):
        model.NONE_IN_ARITHMETIC.clear()
        self.checks, self.last, self.delivery = (_tile("beta", t) for t in TILES)

    def tearDown(self):
        self.assertEqual(model.NONE_IN_ARITHMETIC, [])

    def test_beta_shows_all_three_and_production_none(self):
        for title, panel in zip(TILES, (self.checks, self.last, self.delivery)):
            self.assertIsNotNone(panel, title)
            self.assertIsNone(_tile("production", title), title)

    def test_each_tile_reads_one_datasource_and_its_counters(self):
        self.assertEqual((self.checks["datasource"]["uid"], self.last["datasource"]["uid"],
                          self.delivery["datasource"]["uid"]), (gen.APP, gen.APP, gen.PHI))
        arrived = ["metric.type", "=", "logging.googleapis.com/user/mail_check_arrived", "AND", "resource.type", "=",
                   "gae_app"]
        self.assertEqual(_filters(self.checks), [
            arrived + ["AND", "metric.label.lane", "=", "invites"], arrived + ["AND", "metric.label.lane", "=", "notices"],
            arrived, ["metric.type", "=", "logging.googleapis.com/user/mail_check_refused", "AND", "resource.type", "=",
                      "gae_app"]])
        self.assertEqual([t["timeSeriesList"]["alignmentPeriod"] for t in self.checks["targets"]],
                         [f"+{gen.MAIL_CHECK_WINDOW_S}s", f"+{gen.MAIL_CHECK_WINDOW_S}s", "+86400s", "+86400s"])
        self.assertEqual(_filters(self.last), [arrived + ["AND", "metric.label.lane", "=", lane] for lane in gen.MAIL_LANES])
        self.assertEqual({t["timeSeriesList"]["alignmentPeriod"] for t in self.last["targets"]}, {"+60s"})
        events = ["metric.type", "=", "logging.googleapis.com/user/records_vendor_events", "AND", "resource.type", "=",
                  "cloud_run_revision"]
        real = ["AND", "metric.label.lane", "=~", gen.REAL_EMAIL_KINDS]
        self.assertEqual(_filters(self.delivery), [
            events + ["AND", "metric.label.outcome", "=", "delivered"],
            events + ["AND", "metric.label.outcome", "=~", "bounce|dropped"] + real,
            events + ["AND", "metric.label.outcome", "=", "spamreport"] + real])
        for panel in (self.checks, self.last, self.delivery):
            self.assertEqual(panel["timeFrom"], "24h", panel["title"])

    def test_the_window_and_the_real_kinds_are_the_policies(self):
        """The status is read over mail-check-<lane>-missing's own window, and the amber counts over
        email-delivery-failed's own kinds, each read from the vendored catalogue."""
        catalogue = cat.Catalogue()
        for lane in gen.MAIL_LANES:
            query = catalogue.promql(f"mail-check-{lane}-missing", "mail_check")
            windows = set(re.findall(r'lane="' + lane + r'"\}\[(\d+)m\]', query))
            self.assertEqual(windows, {str(gen.MAIL_CHECK_WINDOW_S // 60)}, lane)
        flt = catalogue.folded("email-delivery-failed", "email_delivery", "filter")
        kinds = re.search(r'metric\.labels\.lane = one_of\(([^)]*)\)', flt)
        self.assertIsNotNone(kinds)
        self.assertEqual(set(re.findall(r'"([a-z_]+)"', kinds.group(1))), set(gen.REAL_EMAIL_KINDS.split("|")))

    def test_all_read_at_the_rows_fixed_sizes(self):
        for p in (self.checks, self.last, self.delivery):
            self.assertEqual(p["options"]["text"], {"valueSize": gen.SIGNIN_VALUE_SIZE,
                                                    "titleSize": gen.SIGNIN_NAME_SIZE}, p["title"])

    def test_a_lane_in_the_window_arrives_and_one_out_of_it_is_red(self):
        got = shown(self.checks, latest(self.checks, {"invites window": 2, "arrivals count": 30}))
        self.assertEqual(got, {"invites": "✓ arriving", "notices": "✕ none in 2 h 15 min", "refused (24 h)": 0})
        got = shown(self.checks, latest(self.checks, {"invites window": 1, "notices window": 2, "arrivals count": 48,
                                                      "refused count": 3}))
        self.assertEqual(got, {"invites": "✓ arriving", "notices": "✓ arriving", "refused (24 h)": 3})

    def test_an_older_window_is_never_read_as_now(self):
        frames = [model.frame("A", "invites window", [1], [END - 3 * 135 * MINUTE]),
                  model.frame("C", "arrivals count", [5], [END])]
        self.assertEqual(shown(self.checks, frames)["invites"], "✕ none in 2 h 15 min")

    def test_refusals_alone_read_both_lanes_red(self):
        got = shown(self.checks, latest(self.checks, {"refused count": 4}))
        self.assertEqual(got, {"invites": "✕ none in 2 h 15 min", "notices": "✕ none in 2 h 15 min",
                               "refused (24 h)": 4})

    def test_nothing_at_all_is_the_tiles_own_words(self):
        self.assertEqual(shown(self.checks, []), {})
        self.assertEqual(self.checks["fieldConfig"]["defaults"]["noValue"], "No check arrived in 24 h")
        self.assertEqual(shown(self.last, []), {})

    def test_last_check_shows_each_lanes_newest_arrival_as_a_time_ago(self):
        frames = [model.frame("A", "invites", [1, 0, 1], [END - 67 * MINUTE, END - 30 * MINUTE, END - 7 * MINUTE]),
                  model.frame("B", "notices", [1], [END - 6 * MINUTE])]
        self.assertEqual(shown(self.last, frames), {"invites": END - 7 * MINUTE, "notices": END - 6 * MINUTE})
        units = {o["matcher"]["options"]: {x["id"]: x["value"] for x in o["properties"]}
                 for o in self.last["fieldConfig"]["overrides"]}
        self.assertEqual({lane: units[lane]["unit"] for lane in gen.MAIL_LANES},
                         {lane: "dateTimeFromNow" for lane in gen.MAIL_LANES})
        # A frame of empty minutes only (Cloud Monitoring writes none for a counter, but if it did): the lane's value
        # is null, which Grafana draws as the tile's own words, never as a time.
        frames = [model.frame("B", "notices", [0, 0], [END - 9 * MINUTE, END - 8 * MINUTE])]
        self.assertEqual(shown(self.last, frames), {"notices": None})

    def test_delivery_counts_the_days_reports(self):
        got = shown(self.delivery, latest(self.delivery, {"delivered count": 57, "bounced count": 4, "spam count": 1}))
        self.assertEqual(got, {"delivered": 57, "bounced or dropped": 4, "spam reports": 1})
        got = shown(self.delivery, latest(self.delivery, {"delivered count": 12}))
        self.assertEqual(got, {"delivered": 12, "bounced or dropped": 0, "spam reports": 0})
        self.assertEqual(shown(self.delivery, []), {})

    def test_the_words_name_the_alerts_and_say_beta_nowhere(self):
        for p, names in ((self.checks, ("mail-check-invites-missing", "mail-check-notices-missing",
                                        "mail_check_arrived", "mail_check_refused")),
                         (self.last, ("mail_check_arrived",)),
                         (self.delivery, ("email-delivery-failed", "records_vendor_events"))):
            for name in names:
                self.assertIn(name, p["description"], (p["title"], name))
            self.assertNotIn("beta", (p["title"] + p["description"]).lower())


if __name__ == "__main__":
    unittest.main()
