"""cloud/render-dashboards.sh settles the dashboards from the service's environment: each query's project, the
uptime wording per environment, the call-centre parts (left out with no call-centre project), and the tiles of a job
not built, a paused job or a stopped database (neutral "not deployed" / "paused" / "database stopped"). It refuses
anything it does not know.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import cloud_dashboards as gen  # noqa: E402

SCRIPT = ROOT / "cloud" / "render-dashboards.sh"
DASHBOARDS = ROOT / "cloud" / "dashboards"
BETA = {"TPA_APP_PROJECT_ID": "beta-tpa-app", "TPA_CRM_PROJECT_ID": "beta-tpa-app",
        "TPA_PHI_PROJECT_ID": "beta-tpa-phi", "TPA_CC_PROJECT_ID": "beta-callcentre", "TPA_ENVIRONMENT": "beta"}
PRODUCTION = {"TPA_APP_PROJECT_ID": "prod-tpa-app", "TPA_CRM_PROJECT_ID": "prod-crm",
              "TPA_PHI_PROJECT_ID": "prod-tpa-phi", "TPA_CC_PROJECT_ID": "", "TPA_ENVIRONMENT": "production"}
# Beta's documented resting state: every database stopped between sessions, the two O143 sweeps paused, and the
# administrator-feed importer not built (feed_ingest_enabled false, its default).
RESTING = {"TPA_PAUSED_JOBS": "nightly-anomalies,accumulator-reconcile",
           "TPA_NOT_DEPLOYED_JOBS": "feed-ingest-everon-sync",
           "TPA_STOPPED_DATABASES": "auth_db,tpa_db,crm_db,cc_db"}
IMPORTER = gen.IMPORTER
TILE = gen.deadline_title(IMPORTER)   # "feed-ingest": the whole job name does not fit a tile
QUIET = lambda word: ("value_and_name", word, word, ["text", "text"])  # noqa: E731
AS_BUILT = ("auto", "", "MISSED", ["red", "green"])


def stat(dashboard: dict, row: str | None, title: str) -> dict:
    """The panel titled `title`, under the row whose title starts with `row` (any row when None), a shut row's
    panels included."""
    current = None
    for panel in dashboard["panels"]:
        inside = [panel, *(panel.get("panels") or [])] if panel["type"] == "row" else [panel]
        for p in inside:
            if p["type"] == "row":
                current = p["title"]
            elif p["title"] == title and (row is None or (current or "").startswith(row)):
                return p
    raise KeyError((row, title))


def lint_panels(dashboard: dict) -> list[dict]:
    """Every panel, a shut row's included."""
    return [p for panel in dashboard["panels"] for p in [panel, *(panel.get("panels") or [])]]


def shown(panel: dict) -> tuple:
    """What a stat tile shows with no data, and its colours."""
    d = panel["fieldConfig"]["defaults"]
    return (panel["options"]["textMode"], d.get("displayName"), d.get("noValue"),
            [s["color"] for s in d["thresholds"]["steps"]])


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src, self.dst = self.tmp / "src", self.tmp / "dst"
        shutil.copytree(DASHBOARDS, self.src, ignore=shutil.ignore_patterns("*.md"))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def render(self, env: dict, **extra):
        base = {k: v for k, v in os.environ.items() if not k.startswith("TPA_")}
        return subprocess.run(["sh", str(SCRIPT), "--render-only", str(self.src), str(self.dst)],
                              env={**base, **env, **extra}, capture_output=True, text=True)

    def rendered(self, env: dict, **extra) -> dict[str, dict]:
        result = self.render(env, **extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {p.name: json.loads(p.read_text()) for p in self.dst.glob("*.json")}

    def projects(self, pages: dict[str, dict]) -> dict[str, set[str]]:
        found: dict[str, set[str]] = {}
        for dashboard in pages.values():
            for panel in dashboard["panels"]:
                for target in panel.get("targets") or []:
                    found.setdefault(target["datasource"]["uid"], set()).add(target["timeSeriesList"]["projectName"])
        return found

    # ---- projects, environment, call centre --------------------------------------------------------------------
    def test_beta_every_query_gets_its_datasource_project(self):
        pages = self.rendered(BETA)
        self.assertEqual(sorted(pages), sorted(p.name for p in self.src.glob("*.json")))
        self.assertEqual(self.projects(pages), {"cloud-app": {"beta-tpa-app"}, "cloud-crm": {"beta-tpa-app"},
                                                "cloud-phi": {"beta-tpa-phi"}, "cloud-cc": {"beta-callcentre"}})
        self.assertIn("incidents?project=beta-tpa-phi", json.dumps(pages["overview.json"]))
        text = "".join(p.read_text() for p in self.dst.glob("*.json"))
        self.assertNotIn("__TPA_", text)
        self.assertNotIn("@@", text)

    def test_production_leaves_out_the_call_centre_and_words_uptime_for_public_hosts(self):
        pages = self.rendered(PRODUCTION)
        self.assertNotIn("callcentre.json", pages)
        # The Call centre page and its services' own pages, and nothing else.
        self.assertEqual(sorted(p.name for p in self.src.glob("*.json")),
                         sorted([*pages, *(f"{page}.json" for page in gen.CC_ONLY)]))
        self.assertIn("service-svc-voice.json", [f"{page}.json" for page in gen.CC_ONLY])
        self.assertNotIn("cloud-cc", self.projects(pages))
        self.assertEqual(self.projects(pages)["cloud-crm"], {"prod-crm"})
        overview = pages["overview.json"]
        self.assertNotIn("Call centre", [p["title"].split(" (")[0] for p in overview["panels"] if p["type"] == "row"])
        self.assertNotIn("call centre](", json.dumps(overview))
        uptime = stat(overview, "Right now", "Uptime")["description"]
        self.assertIn("public host", uptime)
        self.assertNotIn("IAP", uptime)
        self.assertNotIn("cc-db", [p["title"].split(" ")[0] for p in pages["databases.json"]["panels"]
                                   if p["type"] == "row"])

    def test_beta_words_uptime_for_iap(self):
        uptime = stat(self.rendered(BETA)["overview.json"], "Right now", "Uptime")["description"]
        self.assertIn("behind IAP", uptime)
        self.assertNotIn("public host", uptime)

    def test_production_tiles_are_never_quiet(self):
        overview = self.rendered(PRODUCTION)["overview.json"]
        self.assertEqual(shown(stat(overview, "Scheduled", "nightly-anomalies")),
                         ("auto", "", "MISSED", ["red", "green"]))
        self.assertEqual(shown(stat(overview, "Sign-in", "5xx (1 h)")), ("auto", "", "0", ["text", "orange", "red"]))

    def test_a_number_settles_per_environment_as_a_number(self):
        # records' instance ceiling: beta's Terraform asks for `ceiling-records`; production-full does not.
        raw = (self.src / "service-records.json").read_text()
        self.assertIn('"@@N@@15.5@@20@@"', raw)
        for env, want in ((BETA, [15.5, 20]), (PRODUCTION, [15.5, 15.5])):
            page = self.rendered(env)["service-records.json"]
            panel = stat(page, "Resources", "Instances (total, active, idle)")
            steps = panel["fieldConfig"]["defaults"]["thresholds"]["steps"]
            self.assertEqual([s["value"] for s in steps[1:]], want)
            self.assertTrue(all(isinstance(s["value"], (int, float)) for s in steps[1:]), "a number, not a string")
            mode = panel["fieldConfig"]["defaults"]["custom"]["thresholdsStyle"]["mode"]
            self.assertEqual(mode, "line" if env is BETA else "off")
            if env is PRODUCTION:
                self.assertEqual({s["color"] for s in steps}, {"transparent"})

    # ---- paused sweeps and stopped databases --------------------------------------------------------------------
    def test_resting_beta_reads_paused_and_database_stopped_in_no_colour(self):
        pages = self.rendered(BETA, **RESTING)
        overview = pages["overview.json"]
        self.assertEqual(shown(stat(overview, "Scheduled", "nightly-anomalies")),
                         ("value_and_name", "paused", "paused", ["text", "text"]))
        self.assertEqual(shown(stat(overview, "Scheduled", "accumulator-reconcile")),
                         ("value_and_name", "paused", "paused", ["text", "text"]))
        # A sweep not paused still needs auth-db and tpa-db, both stopped.
        self.assertEqual(shown(stat(overview, "Scheduled", "erisa-clocks")),
                         ("value_and_name", "database stopped", "database stopped", ["text", "text"]))
        self.assertEqual(shown(stat(overview, "Scheduled", "records-chain-head"))[2], "database stopped")
        for row in ("Portal & API", "Sign-in", "Member records", "Call centre", "CRM"):
            for title in ("5xx (1 h)", "Error groups (24 h)"):
                self.assertEqual(shown(stat(overview, row, title))[:3], ("value_and_name", "database stopped",
                                                                         "database stopped"), (row, title))
        self.assertEqual(shown(stat(overview, "Portal & API", "Jobs (24 h)")),
                         ("value_and_name", "database stopped", "database stopped", ["text", "text"]))
        # The importer is not built: its tile says so, whatever its databases say.
        self.assertEqual(shown(stat(overview, "Scheduled", TILE)), QUIET("not deployed"))
        self.assertEqual(shown(stat(pages["jobs.json"], None, TILE)), QUIET("not deployed"))
        self.assertEqual(stat(overview, "Sign-in", "auth-db")["fieldConfig"]["defaults"]["noValue"],
                         "database stopped")
        # The Jobs page's deadline tiles are the same tiles.
        self.assertEqual(shown(stat(pages["jobs.json"], None, "nightly-anomalies"))[2], "paused")
        self.assertNotIn("@@", json.dumps(pages))

    def test_one_stopped_database_quiets_only_its_readers(self):
        overview = self.rendered(BETA, TPA_STOPPED_DATABASES="crm-db")["overview.json"]
        self.assertEqual(shown(stat(overview, "CRM", "5xx (1 h)"))[2], "database stopped")
        self.assertEqual(shown(stat(overview, "CRM", "CRM jobs (24 h)"))[2], "database stopped")
        self.assertEqual(stat(overview, "CRM", "crm-db")["fieldConfig"]["defaults"]["noValue"], "database stopped")
        self.assertEqual(shown(stat(overview, "Sign-in", "5xx (1 h)")), ("auto", "", "0", ["text", "orange", "red"]))
        self.assertEqual(stat(overview, "Sign-in", "auth-db")["fieldConfig"]["defaults"]["noValue"], "not reporting")
        self.assertEqual(shown(stat(overview, "Scheduled", "auth-publisher"))[2], "MISSED")

    def test_paused_wins_over_stopped(self):
        overview = self.rendered(BETA, **RESTING)["overview.json"]
        self.assertEqual(shown(stat(overview, "Scheduled", "nightly-anomalies"))[2], "paused")

    # ---- the administrator-feed importer (OWNER-EV-12): not deployed, paused, running --------------------------
    def importer_tiles(self, **env) -> list[tuple]:
        pages = self.rendered(BETA, **env)
        return [shown(stat(pages["overview.json"], "Scheduled", TILE)), shown(stat(pages["jobs.json"], None, TILE))]

    def test_the_importer_not_built_reads_not_deployed_in_no_colour(self):
        self.assertEqual(self.importer_tiles(TPA_NOT_DEPLOYED_JOBS=IMPORTER), [QUIET("not deployed")] * 2)
        overview = self.rendered(BETA, TPA_NOT_DEPLOYED_JOBS=IMPORTER)["overview.json"]
        # Nothing else is quieted: another job, and the app area's jobs stat that counts the importer's failures.
        self.assertEqual(shown(stat(overview, "Scheduled", "erisa-clocks")), AS_BUILT)
        self.assertEqual(shown(stat(overview, "Portal & API", "Jobs (24 h)"))[:3],
                         ("value_and_name", "", "0"))
        self.assertIn('"not deployed"', stat(overview, "Scheduled", TILE)["description"])
        self.assertIn(f"`{IMPORTER}`", stat(overview, "Scheduled", TILE)["description"])

    def test_the_importer_paused_reads_paused_in_no_colour(self):
        self.assertEqual(self.importer_tiles(TPA_PAUSED_JOBS=IMPORTER), [QUIET("paused")] * 2)
        both = self.importer_tiles(TPA_PAUSED_JOBS=f"nightly-anomalies,{IMPORTER}", TPA_STOPPED_DATABASES="auth-db")
        self.assertEqual(both, [QUIET("paused")] * 2, "paused wins over a stopped database")

    def test_the_importer_built_and_running_reads_as_every_other_job(self):
        # Neither list names it: MISSED in red with no successful run in its deadline, green with one.
        self.assertEqual(self.importer_tiles(), [AS_BUILT] * 2)
        self.assertEqual(self.importer_tiles(TPA_STOPPED_DATABASES="tpa-db"), [QUIET("database stopped")] * 2)

    def test_not_deployed_wins_over_a_stopped_database(self):
        self.assertEqual(self.importer_tiles(TPA_NOT_DEPLOYED_JOBS=IMPORTER, TPA_STOPPED_DATABASES="auth-db,tpa-db"),
                         [QUIET("not deployed")] * 2)

    def test_production_has_no_importer_tile(self):
        # production-full builds none of the importer, so its pages tile none of it (and no list can quiet one).
        pages = self.rendered(PRODUCTION)
        titles = [p["title"] for page in pages.values() for p in lint_panels(page)]
        self.assertNotIn(TILE, titles)
        # No query of the importer's own (the app area's job pattern names it among the others, and reads nothing).
        own = [p["title"] for page in pages.values() for p in lint_panels(page) for t in p.get("targets") or []
               if f'"=~", "{IMPORTER}"' in json.dumps(t) or f'"=", "{IMPORTER}"' in json.dumps(t)]
        self.assertEqual(own, [])
        self.assertEqual([t for t in titles if "importer" in t], ["Administrator sync (the importer's runs, records' "
                                                                  "side)"], "records' own line alone")
        self.assertIn("nightly-anomalies", [p["title"] for p in lint_panels(pages["jobs.json"])])
        self.assertIn("nightly-anomalies", [p["title"] for p in lint_panels(pages["overview.json"])])
        sync = stat(pages["records.json"], "Administrator sync", "Sync alerts records raised")["description"]
        self.assertIn("production-full builds none of the importer", sync)
        beta = stat(self.rendered(BETA)["records.json"], "Administrator sync", "Sync alerts records raised")
        self.assertIn("Zero too while the importer is not deployed", beta["description"])
        self.assertIn("reads zero until records logs that line (TP-249)", beta["description"])

    def test_names_are_trimmed_and_underscores_read_as_hyphens(self):
        overview = self.rendered(BETA, TPA_STOPPED_DATABASES=" auth_db , tpa-db ,")["overview.json"]
        self.assertEqual(shown(stat(overview, "Sign-in", "5xx (1 h)"))[2], "database stopped")
        self.assertEqual(shown(stat(overview, "Member records", "5xx (1 h)"))[2], "database stopped")

    # ---- refusals -----------------------------------------------------------------------------------------------
    def assertRefused(self, env: dict, message: str, **extra):
        result = self.render(env, **extra)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertEqual(list(self.dst.glob("*.json")), [], "nothing is written when a value is refused")

    def test_an_unknown_paused_sweep_is_refused(self):
        self.assertRefused(BETA, "TPA_PAUSED_JOBS names 'nightly-anomlies', which is not one of",
                           TPA_PAUSED_JOBS="accumulator-reconcile,nightly-anomlies")

    def test_a_job_that_is_not_a_sweep_is_refused(self):
        self.assertRefused(BETA, "TPA_PAUSED_JOBS names 'auth-publisher'", TPA_PAUSED_JOBS="auth-publisher")

    def test_only_a_switched_job_can_be_not_deployed(self):
        # A sweep is always built; a typo, a database or the schedule's own wording are refused.
        for name in ("nightly-anomalies", "feed-ingest", "feed-ingest-everon", "tpa-db", "auth-publisher"):
            self.assertRefused(BETA, f"TPA_NOT_DEPLOYED_JOBS names '{name}', which is not one of",
                               TPA_NOT_DEPLOYED_JOBS=f"{IMPORTER},{name}")
        self.assertRefused(BETA, f"TPA_STOPPED_DATABASES names '{IMPORTER}'", TPA_STOPPED_DATABASES=IMPORTER)

    def test_a_job_both_not_deployed_and_paused_is_refused(self):
        self.assertRefused(BETA, f"TPA_NOT_DEPLOYED_JOBS and TPA_PAUSED_JOBS both name '{IMPORTER}'",
                           TPA_NOT_DEPLOYED_JOBS=IMPORTER, TPA_PAUSED_JOBS=f"nightly-anomalies,{IMPORTER}")

    def test_an_unknown_database_is_refused(self):
        self.assertRefused(BETA, "TPA_STOPPED_DATABASES names 'records-db'", TPA_STOPPED_DATABASES="auth-db,records-db")

    def test_a_name_with_regex_or_sed_characters_is_refused(self):
        self.assertRefused(BETA, "TPA_STOPPED_DATABASES names 'auth-db/g;s/x'",
                           TPA_STOPPED_DATABASES="auth-db/g;s/x")

    def test_production_refuses_paused_sweeps_and_stopped_databases(self):
        # Production pauses and stops nothing, so a quiet tile there would hide a real failure.
        self.assertRefused(PRODUCTION, "TPA_PAUSED_JOBS must be empty with TPA_ENVIRONMENT=production",
                           TPA_PAUSED_JOBS="nightly-anomalies")
        self.assertRefused(PRODUCTION, "TPA_STOPPED_DATABASES must be empty with TPA_ENVIRONMENT=production",
                           TPA_STOPPED_DATABASES="tpa-db")
        self.assertRefused(PRODUCTION, "TPA_NOT_DEPLOYED_JOBS must be empty with TPA_ENVIRONMENT=production",
                           TPA_NOT_DEPLOYED_JOBS=IMPORTER)
        # Refused before the names are read: even one the image would not know.
        self.assertRefused(PRODUCTION, "TPA_STOPPED_DATABASES must be empty", TPA_STOPPED_DATABASES=",")
        self.assertEqual(self.render(PRODUCTION, TPA_PAUSED_JOBS="", TPA_NOT_DEPLOYED_JOBS="",
                                     TPA_STOPPED_DATABASES="").returncode, 0)

    def test_an_unknown_environment_is_refused(self):
        self.assertRefused({**BETA, "TPA_ENVIRONMENT": "staging"}, "TPA_ENVIRONMENT must be 'beta' or 'production'")
        self.assertRefused({k: v for k, v in BETA.items() if k != "TPA_ENVIRONMENT"},
                           "TPA_ENVIRONMENT must be 'beta' or 'production'")

    def test_a_required_project_missing_is_refused(self):
        self.assertRefused({k: v for k, v in BETA.items() if k != "TPA_PHI_PROJECT_ID"},
                           "TPA_PHI_PROJECT_ID must be a Google Cloud project id")

    def test_anything_but_a_project_id_is_refused(self):
        for bad in ['beta-tpa-app"}', "beta/tpa", "Beta-Tpa-App", "x", "beta-tpa-app-", "a" * 31]:
            self.assertRefused({**BETA, "TPA_APP_PROJECT_ID": bad},
                               "TPA_APP_PROJECT_ID must be a Google Cloud project id")

    def test_a_placeholder_or_token_left_unsettled_is_refused(self):
        (self.src / "stray.json").write_text('{"x": "__TPA_VAULT_PROJECT_ID__"}')
        self.assertRefused(BETA, "a placeholder or token above was left unsettled")
        (self.src / "stray.json").write_text('{"x": "@@Q,auth-db,@@odd@@"}')
        result = self.render(BETA)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("left unsettled", result.stderr)


if __name__ == "__main__":
    unittest.main()
