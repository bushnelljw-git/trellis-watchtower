"""The administrator-feed importer on the cloud pages, treated as every other scheduled job is.

The owner, 2026-10-25: "Ok, i think we need to update watchtower with the enrollment portal and we need it treated just
like all the other services. Same with feed-ingest if its not already Both will be deployed in GCP". tpa-platform's
beta builds the importer's scheduled Everon sync (`feed-ingest-everon-sync`, infra/envs/beta/feedingest.tf) behind
`feed_ingest_enabled` (false by default) and pauses its schedule while `feed_ingest_paused` (true by default);
production-full builds none of it. So the pages give it what every other scheduled job has, on beta's pages alone: a
deadline tile (the overview's Scheduled runs and the Jobs page), its failures among the app area's problems (the area
tile and What's wrong now) and in the Portal & API row's 24-hour jobs stat, its own row on the Jobs page beside
job_resources, and records' side of its runs (`source_sync_alerts`) on Member records. Its tile reads "not deployed"
while beta has not built it and "paused" while its schedule is paused, in no colour, never red and never green
(TPA_NOT_DEPLOYED_JOBS and TPA_PAUSED_JOBS, which tpa-platform's watch.tf writes from those two switches).

Each fact is checked against its source: tpa-platform's Terraform and catalogue at the catalogue's pinned commit
(cloud/catalogue/SOURCE, read as tests/cloud/test_resources.py reads it), and the pages as each environment renders
them. tests/cloud/test_render.py holds the render's words for each state.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE))

import catalogue as cat  # noqa: E402
import cloud_dashboards as gen  # noqa: E402
import dashboard_lint as lint  # noqa: E402
from test_catalogue import NAMES  # noqa: E402
from test_resources import CHECKOUT_PRESENT, INFRA, INFRA_SOURCE, RENDERED, sections  # noqa: E402

IMPORTER = gen.IMPORTER
TILE = gen.deadline_title(IMPORTER)
CATALOGUE = cat.Catalogue()
# tpa-platform's half (watch.tf writing the importer's state into the website's environment): at the catalogue's
# pinned commit since tpa-platform's watch/feed-ingest (D-181). True would hold a pin that predates it.
WATCH_STATE_AHEAD_OF_THE_PIN = False


def deadline(job: str) -> tuple:
    return next(d for d in gen.DEADLINES if d[1] == job)


def panels(dashboard: dict) -> list[dict]:
    """Every panel but the rows, a shut row's included."""
    return [p for p in lint.panels(dashboard) if p["type"] != "row"]


def job_filters(panel: dict) -> list[str]:
    return [v for t in panel.get("targets") or [] for k, _op, v in lint.query_facts(t["timeSeriesList"])["filters"]
            if k == "resource.label.job_name"]


class TerraformTest(unittest.TestCase):
    """The generator's facts of the importer are tpa-platform's own, at the catalogue's pinned commit."""

    def setUp(self):
        if INFRA is None and CHECKOUT_PRESENT:
            self.fail(INFRA_SOURCE)
        if INFRA is None:
            self.skipTest(f"SKIPPED LOUDLY: {INFRA_SOURCE}; the importer's facts are not checked against tpa-platform")
        self.feed = INFRA.show("infra/envs/beta/feedingest.tf")
        self.main = INFRA.show("infra/envs/beta/main.tf")

    def local(self, name: str) -> str:
        found = re.search(rf'^  {name}\s*=\s*"([^"]*)"', self.feed, re.M)
        self.assertIsNotNone(found, name)
        return found.group(1)

    def test_the_job_and_its_schedule_are_one_name(self):
        self.assertEqual(self.local("feed_ingest_job"), IMPORTER)
        self.assertRegex(self.feed, rf'name\s+=\s+"{IMPORTER}"')
        # The Cloud Scheduler job's name is the key the scheduler takes (main.tf's scheduler_app).
        self.assertIn("(local.feed_ingest_job) = {", self.main)
        self.assertIn("paused           = var.feed_ingest_paused", self.main)

    def test_the_deadline_is_its_missed_run(self):
        seconds = int(self.local("feed_ingest_missed_run_after").removesuffix("s"))
        _ds, _job, minutes, _deps = deadline(IMPORTER)
        self.assertEqual(minutes * 60, seconds)
        self.assertIn("var.feed_ingest_enabled && !var.feed_ingest_paused ?", self.feed)

    def test_its_tile_quiets_on_what_its_missed_run_is_gated_on(self):
        # The missed run is written into the app project only while auth-db and tpa-db run (main.tf's inputs).
        ds, _job, _minutes, deps = deadline(IMPORTER)
        self.assertEqual(ds, gen.APP)
        self.assertIn('{ for k, r in local.feed_ingest_missed_runs : k => r if contains(roles, "app") && '
                      "!local.database_stopped.auth_db && !local.database_stopped.tpa_db }", self.main)
        self.assertEqual(set(deps), {IMPORTER, "auth-db", "tpa-db"})

    def test_the_sections_are_read_as_the_roles_beta_places_them_in(self):
        for section, role in cat.SECTIONS.items():
            local = {"feed_ingest": "feed_ingest_policies", "feed_ingest_records": "feed_ingest_records_log_metrics"}
            self.assertRegex(self.main, rf"in local\.{local[section]} : name => \w+ if contains\(roles, \"{role}\"\)",
                             section)

    def test_records_count_is_made_on_beta_whatever_the_switch_says(self):
        # The Member records chart over it is never a failed query on beta (tpa-platform D-181).
        self.assertIn("feed_ingest_records_log_metrics = local.monitoring.feed_ingest_records.log_metrics", self.feed)
        self.assertRegex(self.feed, r"feed_ingest_records_policies\s*=\s*\{[^}]*if var\.feed_ingest_enabled \}")

    def test_production_full_builds_none_of_it(self):
        # Its inventory renders feed-ingest's image-signing rows (the bootstrap's key), and nothing of the importer.
        text = INFRA.root_text("production")
        self.assertNotIn("feed_ingest", text)
        self.assertNotIn(IMPORTER, text)
        self.assertNotIn("sa-feed-ingest", text)
        self.assertEqual(set(gen.BETA_ONLY_JOBS), {IMPORTER})

    def test_tpa_platform_writes_the_importers_state(self):
        watch = INFRA.show("infra/envs/beta/watch.tf")
        if WATCH_STATE_AHEAD_OF_THE_PIN:
            self.assertFalse("TPA_NOT_DEPLOYED_JOBS" in watch, "the pinned watch.tf writes the importer's state now: "
                             "set WATCH_STATE_AHEAD_OF_THE_PIN False")
            return
        squashed = " ".join(watch.split())
        for line in ('TPA_PAUSED_JOBS = join(",", local.watch_paused_jobs)',
                     'TPA_NOT_DEPLOYED_JOBS = join(",", local.watch_not_deployed_jobs)',
                     "watch_paused_jobs = sort(concat(tolist(var.tpa_jobs_paused), var.feed_ingest_enabled && "
                     "var.feed_ingest_paused ? [local.feed_ingest_job] : []))",
                     "watch_not_deployed_jobs = var.feed_ingest_enabled ? [] : [local.feed_ingest_job]"):
            self.assertIn(line, squashed, line)


class CatalogueTest(unittest.TestCase):
    def test_the_failed_run_policy_reads_the_job(self):
        failed = CATALOGUE.policy("feed-ingest-failed", section="feed_ingest")
        self.assertIn(f'resource.labels.job_name = "{IMPORTER}"', CATALOGUE.text)
        self.assertEqual(set(failed["conditions"]), {"-0"})
        self.assertIn(IMPORTER, NAMES["app"]["job_name"])
        self.assertIn(IMPORTER, NAMES["app"]["job_id"])

    def test_records_count_is_the_phi_roles_and_charted_with_cloud_phi(self):
        self.assertIn("source_sync_alerts", CATALOGUE.roles["phi"])
        found = [(page, p["title"], t["datasource"]["uid"]) for page in ("records",) for p in panels(
            RENDERED["beta"][page]) for t in p.get("targets") or []
                 if "user/source_sync_alerts" in json.dumps(t["timeSeriesList"])]
        self.assertEqual(found, [("records", "Sync alerts records raised", "cloud-phi")])
        # production-full makes no such counter: its Member records page has no such chart (a failed query there).
        self.assertNotIn("source_sync_alerts", json.dumps(RENDERED["production"]["records"]))


class PagesTest(unittest.TestCase):
    def tile(self, env: str, page: str) -> dict | None:
        return next((p for p in panels(RENDERED[env][page]) if p["title"] == TILE), None)

    def test_a_deadline_tile_on_betas_overview_and_jobs_page_and_none_in_production(self):
        _ds, _job, minutes, _deps = deadline(IMPORTER)
        window = minutes + gen.METRIC_DELAY_MINUTES
        for page in ("overview", "jobs"):
            tile = self.tile("beta", page)
            self.assertIsNotNone(tile, page)
            [target] = tile["targets"]
            facts = lint.query_facts(target["timeSeriesList"])
            self.assertEqual(facts["metric"], gen.RUN_JOBS)
            self.assertIn(("resource.label.job_name", "=~", IMPORTER), facts["filters"])
            self.assertIn(("metric.label.result", "=", "succeeded"), facts["filters"])
            self.assertEqual(tile["timeFrom"], f"{window}m")
            self.assertIsNone(self.tile("production", page), page)
        # It is a tile among the others, in the scheduled runs row.
        row = next(ps for title, ps in sections(RENDERED["beta"]["overview"]).items() if title.startswith("Scheduled"))
        self.assertIn(TILE, [p["title"] for p in row])
        self.assertEqual(TILE, "feed-ingest", "a title that fits a tile four columns wide")

    def test_its_failures_are_the_app_areas_problems_in_both_environments(self):
        for env in RENDERED:
            for p in panels(RENDERED[env]["overview"]):
                if p["title"] in ("Portal & sign-in", "What's wrong · Portal & sign-in"):
                    self.assertIn(f"tpa-jobs-.*|migrate-auth|auth-.*|{IMPORTER}", job_filters(p), (env, p["title"]))

    def test_the_portal_rows_24_hour_jobs_stat_counts_it_in_beta(self):
        row = next(ps for title, ps in sections(RENDERED["beta"]["overview"]).items()
                   if title.startswith("Portal & API"))
        stat = next(p for p in row if p["title"] == "App jobs (24 h)")
        self.assertEqual(job_filters(stat), [f"{gen.TPA_JOBS}|{IMPORTER}"])
        schedules = [v for t in stat["targets"] for k, _o, v in lint.query_facts(t["timeSeriesList"])["filters"]
                     if k == "resource.label.job_id"]
        self.assertEqual(schedules, [f"{gen.TPA_SCHEDULES}|{IMPORTER}"])
        self.assertIn("`feed-ingest-failed` on one", stat["description"])

    def test_its_own_row_on_betas_jobs_page(self):
        rows = sections(RENDERED["beta"]["jobs"])
        mine = rows[f"The administrator-feed importer ({IMPORTER}; beta)"]
        self.assertEqual([p["title"] for p in mine], ["Executions, by result", "Its schedule could not start it",
                                                      "Its run, while it runs"])
        for p in mine:
            values = [v for t in p["targets"] for k, _o, v in lint.query_facts(t["timeSeriesList"])["filters"]
                      if k in ("resource.label.job_name", "resource.label.job_id")]
            self.assertEqual(values, [IMPORTER], p["title"])
            self.assertEqual({t["datasource"]["uid"] for t in p["targets"]}, {"cloud-app"})
        self.assertNotIn(f"The administrator-feed importer ({IMPORTER}; beta)", sections(RENDERED["production"]["jobs"]))
        # The app project's job resources are every job's there, the importer's among them (no job filter).
        resources = next(title for title in rows if title.startswith("Job resources: app project"))
        self.assertIn("the importer", resources)

    def test_its_tile_names_every_quiet_reason_it_can_read(self):
        tile = self.tile("beta", "overview")
        self.assertIn("\"not deployed\"", tile["description"])
        self.assertIn("TPA_NOT_DEPLOYED_JOBS", tile["description"])
        self.assertIn("TPA_PAUSED_JOBS", tile["description"])
        self.assertIn("`feed-ingest-failed`", tile["description"])
        self.assertIn(f"`{IMPORTER}`", tile["description"])
        raw = (ROOT / "cloud" / "dashboards" / "overview.json").read_text()
        self.assertIn(f"@@R,{IMPORTER},auth-db,tpa-db,@@MISSED@@", raw)


if __name__ == "__main__":
    unittest.main()
