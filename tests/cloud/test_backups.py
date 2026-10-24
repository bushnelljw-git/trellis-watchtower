"""Backups and point-in-time recovery, a check on every main page (D-173; the owner, 2026-10-24: "Make the window 7 days
for all foour", "Update the trellis-watchtower as a check and it should be on all the main dashboards and we should
have alerting"). The alerting is tpa-platform's monitoring module, four policies per Cloud SQL instance; these pages
read the same counters, each red when its condition holds:

- `<db>-backup-missing` (urgent) reads `sql_automated_backups`, successful automated backups. tpa-platform's review
  (the coordinator, 2026-10-24) rebuilds it to open only after the day's backup window: beta's successful backups land
  up to 26.1 hours apart, so a 25-hour window would read 0 on a healthy day. The pages read 30 hours, red when none
  came while the instance reported (nearly) all of them;
- `<db>-pitr-logs-stalled` (urgent): no `log_archive_success_count` in 30 minutes (ten-minute sums below one held
  twenty minutes, or none reported for thirty);
- `<db>-pitr-log-archive-failed`: a `log_archive_failure_count` in fifteen minutes;
- `<db>-backup-failed`: a `sql_backup_failures` in five minutes (a failed automated backup included).

A failure is its own red value on each tile, and turns the tile's status red (the coordinator's ruling).

Where each is read:
- the overview: each database's backups (30 h) and point-in-time logs (30 min) tiles under its tile in Databases, and
  again in What's wrong now; a failed backup or archive is a problem row of its area (the area's tile counts it);
- Databases, and the page of the area that owns each instance: a backups and point-in-time recovery row.

The policies are read from tpa-platform's module at the catalogue's pinned commit (tests/cloud/test_resources.py's
checkout rule: no checkout skips loudly, a checkout without the commit fails).

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE))

import cloud_dashboards as gen  # noqa: E402
import dashboard_lint as lint  # noqa: E402
from test_resources import (CHECKOUT_PRESENT, DASHBOARDS, ENVIRONMENTS, INFRA, INFRA_SOURCE,  # noqa: E402
                            RENDER, RENDERED, Infra, sections)

LOG = "logging.googleapis.com/user/"
SQL_UP = "cloudsql.googleapis.com/database/up"
SHIPPED = "cloudsql.googleapis.com/database/replication/log_archive_success_count"
FAILED = "cloudsql.googleapis.com/database/replication/log_archive_failure_count"
BACKUPS, BACKUP_FAILURES = LOG + "sql_automated_backups", LOG + "sql_backup_failures"
DATASOURCE = {"auth-db": "cloud-app", "tpa-db": "cloud-phi", "crm-db": "cloud-crm", "cc-db": "cloud-cc"}
OWNER = {"auth-db": "sign-in", "tpa-db": "records", "crm-db": "crm", "cc-db": "callcentre"}
AREA = {"auth-db": "Portal & sign-in", "tpa-db": "Member records", "crm-db": "CRM", "cc-db": "Call centre"}


def module_backup_policies(infra: Infra) -> dict:
    """The monitoring module's four per-instance policies (infra/modules/monitoring/main.tf), as BACKUP_POLICIES
    holds them: what each reads, and the windows of the three the pages read as the policy does (backup-missing is
    being rebuilt, so only its counter is held)."""
    text = infra.show("infra/modules/monitoring/main.tf")
    local = lambda name: re.search(rf'^\s*{name}\s*=\s*"([^"]+)"', text, re.M).group(1)

    def body(name):
        return infra.block(text, f'"${{db}}-{name}" =>')

    def get(block, key):
        return re.search(rf'^\s*{key}\s*=\s*"?([^"\n]+?)"?\s*$', block, re.M).group(1)

    def metric(block):
        m = re.search(r'metric\.type = \\"(\$\{local\.([a-z_]+)\}|[^\\]+)\\"', block)
        return local(m.group(2)) if m.group(2) else m.group(1)

    out = {}
    missing = body("backup-missing")
    assert "user_sql_automated_backups" in missing or 'user/sql_automated_backups' in missing, missing[:300]
    out["backup-missing"] = {"metric": BACKUPS}
    stalled = body("pitr-logs-stalled")
    threshold, absent = infra.block(stalled, "threshold = "), infra.block(stalled, "absent = ")
    assert get(threshold, "comparison") == "COMPARISON_LT", get(threshold, "comparison")
    assert metric(absent) == metric(threshold)
    out["pitr-logs-stalled"] = {"metric": metric(threshold), "period": get(threshold, "alignment_period"),
                                "aligner": get(threshold, "per_series_aligner"),
                                "reducer": get(threshold, "cross_series_reducer"),
                                "below": int(get(threshold, "threshold_value")), "duration": get(threshold, "duration"),
                                "absent": get(absent, "duration")}
    for name in ("pitr-log-archive-failed", "backup-failed"):
        threshold = infra.block(body(name), "threshold = ")
        assert get(threshold, "comparison") == "COMPARISON_GT", (name, get(threshold, "comparison"))
        assert get(threshold, "duration") == "0s", (name, get(threshold, "duration"))
        out[name] = {"metric": metric(threshold), "period": get(threshold, "alignment_period"),
                     "aligner": get(threshold, "per_series_aligner"),
                     "reducer": get(threshold, "cross_series_reducer"), "above": int(get(threshold, "threshold_value"))}
    return out


def dbs(env: str) -> list[str]:
    return [db for db in gen.DATABASES if db != "cc-db" or env == "beta"]


def tsl(target: dict) -> dict:
    return target["timeSeriesList"]


def facts(target: dict) -> dict:
    return lint.query_facts(tsl(target))


def aggregation(target: dict) -> tuple:
    t = tsl(target)
    return t["perSeriesAligner"], t["alignmentPeriod"], t["crossSeriesReducer"]


def calcs(panel: dict) -> dict[str, dict]:
    return {t["options"].get("alias"): t["options"] for t in panel.get("transformations", [])
            if t["id"] == "calculateField"}


def status_steps(panel: dict) -> dict[float, str]:
    props = next(o["properties"] for o in panel["fieldConfig"]["overrides"] if o["matcher"]["options"] == "status")
    steps = next(x["value"]["steps"] for x in props if x["id"] == "thresholds")
    return {s["value"]: s["color"] for s in steps}


def status_words(panel: dict) -> dict[str, str]:
    props = next(o["properties"] for o in panel["fieldConfig"]["overrides"] if o["matcher"]["options"] == "status")
    mapping = next(x["value"][0]["options"] for x in props if x["id"] == "mappings")
    return {k: v["text"] for k, v in mapping.items()}


# ---- The checks --------------------------------------------------------------------------------------------------
def check_backups_tile(panel: dict, db: str, where: str) -> list[str]:
    """The backups tile: 30 hours of `sql_automated_backups` and `sql_backup_failures` on the instance alone, and its
    minutes reported; ✕ none (red) only once it reported 29 of the 30 hours with none; a failure red."""
    problems = []
    hours = gen.BACKUP_HOURS
    if panel.get("timeFrom") != f"{hours}h":
        problems.append(f"{where}: reads {panel.get('timeFrom')}, not {hours} hours")
    by_alias = {t["aliasBy"]: t for t in panel["targets"]}
    want = {"minutes reported": SQL_UP, "backups": BACKUPS, "failed": BACKUP_FAILURES}
    if {a: facts(t)["metric"] for a, t in by_alias.items()} != want:
        problems.append(f"{where}: reads {sorted((a, facts(t)['metric']) for a, t in by_alias.items())}")
    if "minutes reported" in by_alias and tsl(by_alias["minutes reported"])["perSeriesAligner"] != "ALIGN_COUNT":
        problems.append(f"{where}: its minutes reported are not counted")
    problems += check_one_instance(panel, db, where)
    c = calcs(panel)
    ran = c.get("ran the window /", {}).get("binary", {})
    if (ran.get("left", {}).get("matcher", {}).get("options"), ran.get("right")) != (
            "minutes reported", {"fixed": str(gen.BACKUP_RAN_MINUTES)}):
        problems.append(f"{where}: the window is not {gen.BACKUP_RAN_MINUTES} minutes reported: {ran}")
    if [c.get("missing", {}).get("binary", {}).get(k, {}).get("matcher", {}).get("options") for k in
            ("left", "right")] != ["ran the window", "no backup"]:
        problems.append(f"{where}: ✕ none is not the window reported with no backup")
    problems += check_status(panel, where, gen.BACKUP_STATUS, "missing ×4", "a failure ×2")
    return problems


def check_pitr_tile(panel: dict, db: str, where: str) -> list[str]:
    """The point-in-time logs tile: 30 minutes of archives shipped, the latest 15 of failed ones read as
    `<db>-pitr-log-archive-failed` reads them; ✕ (red) only once it reported 20 of the 30 minutes with none, as
    `<db>-pitr-logs-stalled` opens."""
    stalled, failed = gen.BACKUP_POLICIES["pitr-logs-stalled"], gen.BACKUP_POLICIES["pitr-log-archive-failed"]
    problems = []
    window = gen.seconds(stalled["absent"]) // 60
    if panel.get("timeFrom") != f"{window}m":
        problems.append(f"{where}: reads {panel.get('timeFrom')}, not `{db}-pitr-logs-stalled`'s {window} minutes")
    by_alias = {t["aliasBy"]: t for t in panel["targets"]}
    want = {"minutes reported": SQL_UP, "shipped": SHIPPED, "failed": FAILED}
    if {a: facts(t)["metric"] for a, t in by_alias.items()} != want:
        problems.append(f"{where}: reads {sorted((a, facts(t)['metric']) for a, t in by_alias.items())}")
    if "failed" in by_alias and aggregation(by_alias["failed"]) != (failed["aligner"], "+" + failed["period"],
                                                                     failed["reducer"]):
        problems.append(f"{where}: failed archives read {aggregation(by_alias['failed'])}, not as "
                        f"`{db}-pitr-log-archive-failed` reads them")
    for alias, reducer in (("shipped", "sum"), ("minutes reported", "sum"), ("failed", "lastNotNull")):
        ref = by_alias.get(alias, {}).get("refId")
        reduce = [t for t in panel["transformations"] if t["id"] == "reduce" and
                  t.get("filter", {}).get("options") == ref]
        if [t["options"]["reducers"] for t in reduce] != [[reducer]]:
            problems.append(f"{where}: {alias} is not reduced by {reducer}")
    problems += check_one_instance(panel, db, where)
    c = calcs(panel)
    ran = c.get("ran /", {}).get("binary", {})
    held = gen.seconds(stalled["duration"]) // 60
    if (ran.get("left", {}).get("matcher", {}).get("options"), ran.get("right")) != ("minutes reported",
                                                                                   {"fixed": str(held)}):
        problems.append(f"{where}: ran is not {held} minutes reported (the threshold's hold): {ran}")
    problems += check_status(panel, where, gen.PITR_STATUS, "stalled ×4", "a failure ×2")
    return problems


def check_one_instance(panel: dict, db: str, where: str) -> list[str]:
    problems = []
    for t in panel["targets"]:
        if ("resource.label.database_id", "=", f"*:{db}") not in facts(t)["filters"]:
            problems.append(f"{where}: {t['aliasBy']} does not read {db} alone")
        if t["datasource"]["uid"] != DATASOURCE[db]:
            problems.append(f"{where}: {t['aliasBy']} on {t['datasource']['uid']}, not {DATASOURCE[db]}")
    return problems


def check_status(panel: dict, where: str, codes: dict, urgent: str, warning: str) -> list[str]:
    """Red for a missing backup or a stall (4) and for a failure (2), teal for all right, neutral before the
    instance has run the window; the status is the worst of them; the failed count red on its own from one."""
    problems = []
    steps = status_steps(panel)
    if steps != {None: gen.NEUTRAL, 1: gen.TEAL, 2: gen.RED, 4: gen.RED}:
        problems.append(f"{where}: status colours {steps}: red for none or stalled and for a failure")
    failed = next((x["value"]["steps"] for o in panel["fieldConfig"]["overrides"]
                   if o["matcher"]["options"] == "failed or none" for x in o["properties"] if x["id"] == "thresholds"),
                  None)
    if failed != [{"color": gen.NEUTRAL, "value": None}, {"color": gen.RED, "value": 1}]:
        problems.append(f"{where}: the failed count is not red from one: {failed}")
    if status_words(panel) != {str(k): w for k, (w, _c) in codes.items()}:
        problems.append(f"{where}: status words {status_words(panel)}")
    status = calcs(panel).get("status", {}).get("reduce", {})
    if status.get("reducer") != "max" or not {urgent, warning} <= set(status.get("include", [])):
        problems.append(f"{where}: the status is not the worst of {urgent} and {warning}")
    return problems


def tiles_of(panels: list[dict], db: str) -> tuple[dict | None, dict | None]:
    backups = next((p for p in panels if p["title"] == f"{db} backups ({gen.BACKUP_HOURS} h)"), None)
    logs = next((p for p in panels if p["title"] == f"{db} point-in-time logs"), None)
    return backups, logs


def check_overview(overview: dict, env: str) -> list[str]:
    problems = []
    rows = sections(overview)
    wrong = next(ps for t, ps in rows.items() if t.startswith("What's wrong now"))
    for name, panels in (("Databases", rows[gen.DATABASES_ROW]), ("What's wrong now", wrong)):
        for db in dbs(env):
            backups, logs = tiles_of(panels, db)
            where = f"{env} overview {name}: {db}"
            if backups is None or logs is None:
                problems.append(f"{where}: no backups or no point-in-time logs tile")
                continue
            problems += check_backups_tile(backups, db, f"{where} backups")
            problems += check_pitr_tile(logs, db, f"{where} logs")
    # A failed backup or archive is a problem of its area, counted by its tile and named in What's wrong now.
    for p in lint.panels(overview):
        db = next((d for d, a in AREA.items() if p["title"] in (a, f"What's wrong · {a}")), None)
        if db is None:
            continue
        for alias, metric, policy in ((f"✕ backup failed · {db}", BACKUP_FAILURES, "backup-failed"),
                                      (f"✕ point-in-time log archive failed · {db}", FAILED,
                                       "pitr-log-archive-failed")):
            t = next((t for t in p["targets"] if t["aliasBy"] == alias), None)
            if t is None or facts(t)["metric"] != metric or tsl(t)["groupBys"] or \
                    ("resource.label.database_id", "=", f"*:{db}") not in facts(t)["filters"] or \
                    aggregation(t)[0] != gen.BACKUP_POLICIES[policy]["aligner"]:
                problems.append(f"{env} overview: {p['title']} does not count `{db}-{policy}`'s failures as {alias!r}")
    return problems


def check_backup_row(page: str, dashboard: dict, db: str, env: str) -> list[str]:
    rows = {t: ps for t, ps in sections(dashboard).items() if t.startswith(f"{db}: backups and point-in-time")}
    where = f"{env} {page}: {db}"
    if len(rows) != 1:
        return [f"{where}: {len(rows)} backups rows"]
    panels = next(iter(rows.values()))
    problems = []
    backups = next((p for p in panels if p["title"] == f"Backups in the last {gen.BACKUP_HOURS} hours"), None)
    logs = next((p for p in panels if p["title"] == "Point-in-time logs (30 min)"), None)
    problems += check_backups_tile(backups, db, f"{where} backups") if backups else [f"{where}: no backups tile"]
    problems += check_pitr_tile(logs, db, f"{where} logs") if logs else [f"{where}: no logs tile"]
    series = [p for p in panels if p["type"] == "timeseries"]
    read = {facts(t)["metric"] for p in series for t in p["targets"]}
    if read != {SHIPPED, FAILED, BACKUPS, BACKUP_FAILURES}:
        problems.append(f"{where}: its series read {sorted(read)}")
    failed = gen.BACKUP_POLICIES["pitr-log-archive-failed"]
    for p in series:
        for t in p["targets"]:
            problems += check_one_instance({"targets": [t]}, db, f"{where}: {p['title']}")
            if facts(t)["metric"] == FAILED and aggregation(t) != (failed["aligner"], "+" + failed["period"],
                                                                  failed["reducer"]):
                problems.append(f"{where}: {p['title']} reads failed archives {aggregation(t)}")
    if not any(facts(t)["metric"] == SHIPPED and tsl(t)["alignmentPeriod"] == "+3600s" for p in series
               for t in p["targets"]):
        problems.append(f"{where}: no point-in-time logs shipped per hour")
    return problems


def render(env: str, **extra) -> dict[str, dict]:
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "src", Path(tmp) / "dst"
        shutil.copytree(DASHBOARDS, src, ignore=shutil.ignore_patterns("*.md"))
        base = {k: v for k, v in os.environ.items() if not k.startswith("TPA_")}
        done = subprocess.run(["sh", str(RENDER), "--render-only", str(src), str(dst)],
                              env={**base, **ENVIRONMENTS[env], **extra}, capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        return {p.stem: json.loads(p.read_text()) for p in dst.glob("*.json")}


class SourceTest(unittest.TestCase):
    """The generator's copy of the module's four policies is the module's own, at the catalogue's commit."""

    def setUp(self):
        if INFRA is None and CHECKOUT_PRESENT:
            self.fail(INFRA_SOURCE)
        if INFRA is None:
            self.skipTest(f"SKIPPED LOUDLY: {INFRA_SOURCE}; the backup policies are not checked against tpa-platform")

    def test_the_four_policies_are_the_modules(self):
        self.assertEqual(gen.BACKUP_POLICIES, module_backup_policies(INFRA))

    def test_the_counters_are_the_catalogues(self):
        # The shared log counters each policy reads are in the vendored catalogue's shared list.
        import catalogue as cat
        shared = set(cat.Catalogue().shared)
        self.assertLessEqual({"sql_automated_backups", "sql_backup_failures"}, shared)


class BackupsTest(unittest.TestCase):
    def test_the_windows(self):
        self.assertEqual((gen.BACKUP_HOURS, gen.BACKUP_RAN_MINUTES, gen.PITR_MINUTES, gen.PITR_RAN_MINUTES,
                          gen.PITR_FAILED_MINUTES), (30, 1740, 30, 20, 15))
        # A healthy instance always has a backup in the window: beta's longest gap between two successful backups.
        self.assertGreater(gen.BACKUP_HOURS * 60, 26.14 * 60 + 60)

    def test_the_overview_shows_each_databases_backups_and_logs(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_overview(pages["overview"], env), [], env)

    def test_databases_and_each_area_page_have_a_backups_row(self):
        for env, pages in RENDERED.items():
            for db in dbs(env):
                for page in ("databases", OWNER[db]):
                    self.assertEqual(check_backup_row(page, pages[page], db, env), [], (env, db, page))

    def test_a_stopped_database_is_neutral_never_red(self):
        pages = render("beta", TPA_STOPPED_DATABASES="tpa_db")
        overview = sections(pages["overview"])[gen.DATABASES_ROW]
        for p in (*tiles_of(overview, "tpa-db"),
                  *(p for t, ps in sections(pages["records"]).items() if t.startswith("tpa-db: backups")
                    for p in ps if p["type"] == "stat")):
            d = p["fieldConfig"]["defaults"]
            self.assertEqual(d["noValue"], "database stopped", p["title"])
            self.assertEqual(set(status_steps(p).values()), {gen.NEUTRAL}, p["title"])
        # Another database's tiles are as built.
        backups, _logs = tiles_of(overview, "auth-db")
        self.assertEqual(backups["fieldConfig"]["defaults"]["noValue"], "not reporting")
        self.assertEqual(status_steps(backups)[4], gen.RED)
        self.assertEqual(status_steps(backups)[2], gen.RED)

    def test_production_shows_every_tile_as_built(self):
        overview = sections(RENDERED["production"]["overview"])[gen.DATABASES_ROW]
        for db in dbs("production"):
            for p in tiles_of(overview, db):
                self.assertEqual(status_steps(p)[4], gen.RED, (db, p["title"]))
        self.assertNotIn("cc-db backups", json.dumps(RENDERED["production"]["overview"]))


class MutationTest(unittest.TestCase):
    def overview(self, env="beta"):
        return copy.deepcopy(RENDERED[env]["overview"])

    def tile(self, page, title):
        return next(p for p in sections(page)[gen.DATABASES_ROW] if p["title"] == title)

    def test_25_hours_instead_of_30(self):
        page = self.overview()
        self.tile(page, "auth-db backups (30 h)")["timeFrom"] = "25h"
        self.assertIn("beta overview Databases: auth-db backups: reads 25h, not 30 hours", check_overview(page, "beta"))

    def test_none_red_before_the_instance_ran_the_window(self):
        page = self.overview()
        tile = self.tile(page, "tpa-db backups (30 h)")
        next(t for t in tile["transformations"] if t["options"].get("alias") == "ran the window /")["options"][
            "binary"]["right"] = {"fixed": "60"}
        self.assertTrue(any("the window is not 1740 minutes reported" in p for p in check_overview(page, "beta")))

    def test_failed_archives_over_another_window(self):
        page = self.overview("production")
        tile = self.tile(page, "crm-db point-in-time logs")
        next(t for t in tile["targets"] if t["aliasBy"] == "failed")["timeSeriesList"]["alignmentPeriod"] = "+300s"
        self.assertTrue(any("crm-db logs: failed archives read" in p for p in check_overview(page, "production")))

    def test_a_failed_backup_in_amber(self):
        page = self.overview()
        tile = self.tile(page, "cc-db backups (30 h)")
        props = next(o["properties"] for o in tile["fieldConfig"]["overrides"] if o["matcher"]["options"] == "status")
        next(s for s in next(x for x in props if x["id"] == "thresholds")["value"]["steps"]
             if s["value"] == 2)["color"] = gen.AMBER
        self.assertTrue(any("cc-db backups: status colours" in p for p in check_overview(page, "beta")))

    def test_a_failed_archive_count_not_red(self):
        page = self.overview()
        tile = self.tile(page, "auth-db point-in-time logs")
        props = next(o["properties"] for o in tile["fieldConfig"]["overrides"]
                     if o["matcher"]["options"] == "failed or none")
        next(x for x in props if x["id"] == "thresholds")["value"]["steps"][1]["color"] = gen.AMBER
        self.assertTrue(any("auth-db logs: the failed count is not red" in p for p in check_overview(page, "beta")))

    def test_another_databases_backups(self):
        page = self.overview()
        tile = self.tile(page, "auth-db point-in-time logs")
        tile["targets"][1]["timeSeriesList"]["filters"][-1] = "*:tpa-db"
        self.assertTrue(any("shipped does not read auth-db alone" in p for p in check_overview(page, "beta")))

    def test_an_area_that_does_not_count_a_failed_backup(self):
        page = self.overview()
        area = next(p for p in page["panels"] if p["title"] == "Member records")
        area["targets"] = [t for t in area["targets"] if t["aliasBy"] != "✕ backup failed · tpa-db"]
        self.assertIn("beta overview: Member records does not count `tpa-db-backup-failed`'s failures as "
                      "'✕ backup failed · tpa-db'", check_overview(page, "beta"))

    def test_a_page_without_its_backups_row(self):
        page = copy.deepcopy(RENDERED["beta"]["sign-in"])
        page["panels"] = [p for p in page["panels"] if not p["title"].startswith("auth-db: backups")]
        self.assertEqual(check_backup_row("sign-in", page, "auth-db", "beta"),
                         ["beta sign-in: auth-db: 0 backups rows"])


if __name__ == "__main__":
    unittest.main()
