"""The overview, calm (the owner, 2026-10-13: "This seems super busy, can we make it easier without losing the
stats?"): three open rows (Right now, Services, Databases) and everything else in rows shut by default, nothing lost.

- Right now: one status tile per area, linking to the area's pages, then uptime, the sign-in journeys, incidents.
- Services: one tile per service the environment runs, and none for one it does not (beta's switches, production-
  full's root), each the same shape; auth's and tpa-api's read their private check as `inside-down` does (no checker
  region passing), never a share of regions (two of three fail by design).
- Databases: one tile per instance the environment has.
- Every query the overview made before (tests/cloud/fixtures/overview-before-calm.json) is still made by the new
  overview or a page it links to, but for the few replaced on purpose, each checked for its replacement.

Pages are checked as each environment renders them (cloud/render-dashboards.sh: beta, and production with its
production/ overview). Titles fitting their panels is lint rule 10 (scripts/dashboard_lint.py), for every page.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import copy
import json
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
from test_resources import INFRA, INFRA_SOURCE, CHECKOUT_PRESENT, RENDERED, sections, shut  # noqa: E402

BEFORE = json.loads((HERE / "fixtures" / "overview-before-calm.json").read_text())
PRIVATE = "servicedirectory_service"
OPEN = ["Right now", "Services", "Databases"]
AREA_PAGES = {"Portal & sign-in": {"portal-api", "sign-in"}, "Member records": {"records"},
              "Call centre": {"callcentre"}, "CRM": {"crm"}}


def queries(dashboard: dict):
    for panel in lint.panels(dashboard):
        for target in panel.get("targets") or []:
            yield panel, target


def key(datasource: str, tsl: dict) -> tuple[str, str]:
    """A query as Grafana sends it, its project placeholder settled, its legend aside."""
    tsl = {k: v for k, v in tsl.items() if k != "projectName"}
    return datasource, json.dumps(tsl, sort_keys=True)


def facts(target: dict) -> dict:
    return lint.query_facts(target["timeSeriesList"])


def service_filter(tsl: dict) -> str | None:
    return next((v for k, _op, v in lint.query_facts(tsl)["filters"] if k == "resource.label.service_name"), None)


def services_row(overview: dict) -> list[dict]:
    return next(ps for title, ps in sections(overview).items() if title.startswith("Services"))


def inside_queries(dashboard: dict):
    return [(p, t) for p, t in queries(dashboard) if facts(t)["resource"] == PRIVATE]


INSIDE = INFRA.inside_policy() if INFRA else gen.INSIDE_POLICY
UPTIME = gen.UPTIME_POLICY
CATALOGUE = cat.Catalogue()
DB_ROLE = {"auth-db": "app", "tpa-db": "phi", "crm-db": "crm", "cc-db": "cc"}


def calcs(panel: dict) -> dict[str, dict]:
    """A panel's calculated fields by name: their options."""
    return {t["options"].get("alias"): t["options"] for t in panel.get("transformations", [])
            if t["id"] == "calculateField"}


def operands(options: dict) -> tuple:
    """A binary calculation's two sides: a field's name, or ("fixed", value)."""
    side = lambda v: ("fixed", v["fixed"]) if "fixed" in v else v["matcher"]["options"]
    return side(options["binary"]["left"]), options["binary"]["operator"], side(options["binary"]["right"])


def target_named(panel: dict, alias: str) -> dict | None:
    return next((t for t in panel.get("targets") or [] if t["aliasBy"] == alias), None)


def area_panels(overview: dict) -> list[dict]:
    """The area tiles and the What's-wrong tables: the panels that count an area's problems."""
    return [p for p in lint.panels(overview) if p["title"] in AREA_PAGES or p["title"].startswith("What's wrong · ")]


# ---- The checks --------------------------------------------------------------------------------------------------
def check_layout(overview: dict, env: str) -> list[str]:
    rows = [p for p in overview["panels"] if p["type"] == "row"]
    problems = []
    if [r["title"].split(":")[0] for r in rows[:3]] != OPEN or any(r["collapsed"] for r in rows[:3]):
        problems.append(f"{env}: the first rows are {[(r['title'], r['collapsed']) for r in rows[:3]]}, not "
                        f"{OPEN}, open")
    if not all(r["collapsed"] for r in rows[3:]):
        problems.append(f"{env}: open below Databases: {[r['title'] for r in rows[3:] if not r['collapsed']]}")
    right_now = sections(overview)[rows[0]["title"]]
    areas = [p for p in right_now if p["title"] in AREA_PAGES]
    want = [a for a in AREA_PAGES if a != "Call centre" or env == "beta"]
    if [p["title"] for p in areas] != want:
        problems.append(f"{env}: area tiles {[p['title'] for p in areas]}, not {want}")
    for p in areas:
        linked = {link["url"].split("/d/tw-cloud-")[1].split("?")[0] for link in p.get("links", [])}
        if linked != AREA_PAGES[p["title"]]:
            problems.append(f"{env}: {p['title']} links {sorted(linked)}, not {sorted(AREA_PAGES[p['title']])}")
    return problems


def check_services(overview: dict, env: str) -> list[str]:
    """A tile per service the environment runs, in SERVICES' order, the same shape each."""
    tiles = services_row(overview)
    want = [s for s in gen.SERVICES if s in gen.RUNS[env]]
    problems = [] if [p["title"] for p in tiles] == want else [
        f"{env}: service tiles {[p['title'] for p in tiles]}, not {want}"]
    for p in tiles:
        if p["gridPos"]["w"] != tiles[0]["gridPos"]["w"] or p["gridPos"]["h"] != tiles[0]["gridPos"]["h"]:
            problems.append(f"{env}: {p['title']}'s tile is {p['gridPos']}, not the others' size")
        names = {t["aliasBy"] for t in p["targets"]}
        if not {"answered 5xx", "instances"} <= names or (("inside" in names) != (p["title"] in gen.INSIDE_CHECKED)):
            problems.append(f"{env}: {p['title']} reads {sorted(names)}")
        if any(service_filter(t["timeSeriesList"]) not in (p["title"], None) for t in p["targets"]):
            problems.append(f"{env}: {p['title']} reads another service")
        if not any(f"/d/tw-cloud-service-{p['title']}?" in link["url"] for link in p.get("links", [])):
            problems.append(f"{env}: {p['title']} does not link its own page")
    return problems


def check_inside(dashboard: dict, name: str) -> list[str]:
    """Every private uptime check query reads it as `inside-down` does: each region's latest result over its window,
    the regions passing counted (or, beside it, the regions that answered); never a share of regions or a count of
    failures, which two of three regions give by design. And the service tiles turn it into ✕ down below one."""
    problems = []
    for p, t in inside_queries(dashboard):
        tsl = t["timeSeriesList"]
        if (tsl["perSeriesAligner"], tsl["alignmentPeriod"]) != (INSIDE["aligner"], "+" + INSIDE["period"]) or \
                tsl["crossSeriesReducer"] not in (INSIDE["reducer"], "REDUCE_COUNT"):
            problems.append(f"{name}: {p['title']} ({t['refId']}) reads the inside check "
                            f"{tsl['perSeriesAligner']}/{tsl['alignmentPeriod']}/{tsl['crossSeriesReducer']}, not "
                            f"inside-down's {INSIDE['aligner']}/{INSIDE['period']}/{INSIDE['reducer']}")
    for p in lint.panels(dashboard):
        if p["title"] in gen.INSIDE_CHECKED and any(t["aliasBy"] == "inside" for t in p.get("targets") or []):
            steps = {s["options"].get("alias"): s["options"] for s in p.get("transformations", [])
                     if s["id"] == "calculateField"}
            down = steps.get("failing", {}).get("binary", {})
            if (down.get("left"), down.get("right", {}).get("matcher", {}).get("options")) != (
                    {"fixed": str(INSIDE["below"])}, "passing") or "inside" not in json.dumps(steps.get("passing +1")):
                problems.append(f"{name}: {p['title']}'s ✕ down is not `inside-down`'s: no region passing")
    return problems


def linked(overview: dict) -> set[str]:
    """The pages the overview links to by name: its panels' links and its own (never the Pages or Services menus,
    which list every page by tag)."""
    urls = [link.get("url", "") for p in lint.panels(overview) for link in p.get("links") or []]
    urls += [link.get("url", "") for link in overview["links"] if link["type"] == "link"]
    return {u.split("/d/tw-cloud-", 1)[1].split("?")[0] for u in urls if "/d/tw-cloud-" in u}


# Replaced on purpose: the app area's jobs pattern, and beta's Portal & API 24-hour jobs stat, gained the
# administrator-feed importer (the owner, 2026-10-25: "we need it treated just like all the other services"), so a
# query the overview made with an old pattern is kept when the same query with the new one is made
# (test_the_app_jobs_gained_the_importer_alone holds each new pattern to its old one and the importer's name).
APP_JOBS_BEFORE = "tpa-jobs-.*|migrate-auth|auth-.*"
WIDENED = {APP_JOBS_BEFORE: next(a[4] for a in gen.AREAS if a[0] == "app"),
           gen.TPA_JOBS: f"{gen.TPA_JOBS}|{gen.IMPORTER}", gen.TPA_SCHEDULES: f"{gen.TPA_SCHEDULES}|{gen.IMPORTER}"}


def check_queries_kept(env: str, pages: dict[str, dict]) -> list[str]:
    """Each query the overview made before is made by the overview itself or a page it links to by name, unless
    replaced on purpose (and then its replacement is there)."""
    overview = pages["overview"]
    near = {"overview", *linked(overview)} & set(pages)
    have = {key(t["datasource"]["uid"], t["timeSeriesList"]) for name in near for _p, t in queries(pages[name])}
    tiles = {p["title"]: p for p in services_row(overview)}
    problems = []
    for q in BEFORE["queries"]:
        widened = {**q["timeSeriesList"], "filters": [WIDENED.get(v, v) for v in q["timeSeriesList"]["filters"]]}
        if env not in q["environments"] or key(q["datasource"], q["timeSeriesList"]) in have \
                or key(q["datasource"], widened) in have:
            continue
        tsl, where = q["timeSeriesList"], f"{env}: {q['panels'][0]}"
        resource = lint.query_facts(tsl)["resource"]
        service = service_filter(tsl)
        if resource == PRIVATE:
            # The inside check as a share of regions, or a count of failing ones: now read as inside-down reads it.
            if not all(any(t["aliasBy"] == "inside" for t in tiles.get(s, {}).get("targets", []))
                       for s in gen.INSIDE_CHECKED if s in gen.RUNS[env]):
                problems.append(f"{where}: the inside check is gone, with no tile reading it as inside-down does")
        elif service == "auth|auth-outbox-publisher":
            # auth and its messenger shared a tile; each has its own.
            if not {"auth", "auth-outbox-publisher"} <= set(tiles):
                problems.append(f"{where}: auth and its messenger have no tiles")
        elif service in gen.SERVICES and service not in gen.RUNS[env]:
            continue   # a service this environment does not run gets no tile
        else:
            problems.append(f"{where} ({q['datasource']}): {tsl['filters'][2]} {tsl['filters'][4:]} "
                            f"{tsl['perSeriesAligner']} {tsl['alignmentPeriod']} is on no page the overview links")
    return problems


def check_service_status(overview: dict, env: str) -> list[str]:
    """Each service tile: kept warm (KEPT_WARM), none running is ✕ down, red, and so is nothing arrived; otherwise
    none running is idle. A crash or an out-of-memory kill of its own in 15 minutes is ⚠ crashing, never ✓ up or
    idle, red only while those policies are urgent."""
    problems = []
    crash = gen.RED if any(CATALOGUE.policy(n).get("urgent") == "true" for n in ("run-crash-loop", "run-oom")) \
        else gen.AMBER
    for p in services_row(overview):
        service, where = p["title"], f"{env} {p['title']}"
        warm = service in gen.KEPT_WARM[env]
        c = calcs(p)
        defaults = p["fieldConfig"]["defaults"]
        if defaults["noValue"] != ("✕ down" if warm else "idle") or \
                defaults["thresholds"]["steps"][0]["color"] != (gen.RED if warm else gen.NEUTRAL):
            problems.append(f"{where}: with nothing arrived it reads {defaults['noValue']!r} in "
                            f"{defaults['thresholds']['steps'][0]['color']}")
        none_running = c.get("no instance ×4")
        if warm != bool(none_running) or (warm and operands(c["idle"]) != (("fixed", "1"), "-", "running")):
            problems.append(f"{where}: none running is {'not ' if warm else ''}✕ down")
        if c.get("instances or none", {}).get("reduce", {}).get("include") != ["instances"]:
            problems.append(f"{where}: an instance count that did not arrive is not read as none")
        exits = {t["aliasBy"]: t for t in p["targets"] if t["aliasBy"] in ("crashed", "killed for memory")}
        metrics = {facts(t)["metric"].rsplit("/", 1)[1] for t in exits.values()}
        if metrics != {"run_crash_exits", "run_oom_kills"} or any(
                service_filter(t["timeSeriesList"]) != service or t["timeSeriesList"]["alignmentPeriod"] != "+900s"
                for t in exits.values()):
            problems.append(f"{where}: does not read its own crashes and kills over 15 minutes")
        status = c.get("status", {}).get("reduce", {})
        if status.get("reducer") != "max" or "crashing ×3" not in status.get("include", []):
            problems.append(f"{where}: crashing does not outrank ✓ up and idle")
        steps = next(x["value"]["steps"] for o in p["fieldConfig"]["overrides"] if o["matcher"]["options"] == "status"
                     for x in o["properties"] if x["id"] == "thresholds")
        if next((s_["color"] for s_ in steps if s_["value"] == 3), None) != crash:
            problems.append(f"{where}: ⚠ crashing is not {crash}")
    return problems


def check_database_down(overview: dict) -> list[str]:
    """Each area's database down minutes, read as `<db>-down` reads database/up (its aligner, window and reducer,
    below one), and only where a point says so: that policy has no absence condition, so a minute with no point is not
    down (the down minute is the minutes it wrote a point, less up; never 1 less up)."""
    problems = []
    for p in area_panels(overview):
        up = next((t for t in p["targets"] if t["aliasBy"].endswith(" up") and "database/up" in facts(t)["metric"]), None)
        if up is None:
            problems.append(f"{p['title']}: reads no database")
            continue
        db = up["aliasBy"].removesuffix(" up")
        policy = CATALOGUE.policy(f"{db}-down", DB_ROLE[db])
        down = CATALOGUE.threshold(f"{db}-down", DB_ROLE[db])
        if [k for c in policy["conditions"].values() for k in c if k != "name"] != ["threshold"] or \
                (down["comparison"], down["threshold_value"]) != ("COMPARISON_LT", 1):
            problems.append(f"{p['title']}: `{db}-down` is no longer one threshold below 1; read it again")
        tsl = up["timeSeriesList"]
        if (tsl["perSeriesAligner"], tsl["alignmentPeriod"], tsl["crossSeriesReducer"]) != (
                down["per_series_aligner"], "+" + down["alignment_period"], down["cross_series_reducer"]):
            problems.append(f"{p['title']}: {db} up is read {tsl['perSeriesAligner']}/{tsl['alignmentPeriod']}/"
                            f"{tsl['crossSeriesReducer']}, not as `{db}-down` reads it")
        points = target_named(p, f"{db} points")
        if points is None or facts(points)["filters"] != facts(up)["filters"] or \
                (points["timeSeriesList"]["perSeriesAligner"], points["timeSeriesList"]["alignmentPeriod"]) != (
                    "ALIGN_COUNT", tsl["alignmentPeriod"]):
            problems.append(f"{p['title']}: {db}'s points are not counted from the same series, minute by minute")
        c = calcs(p)
        minutes = c.get(f"✕ {db} down (minutes)")
        if minutes is None or operands(minutes) != (f"{db} wrote", "-", f"{db} up") or \
                operands(c.get(f"{db} wrote +1", {"binary": {"left": {"fixed": ""}, "operator": "",
                                                              "right": {"fixed": ""}}}))[0] != f"{db} points":
            problems.append(f"{p['title']}: {db}'s down minutes are not the minutes it wrote a point less up "
                            f"({operands(minutes) if minutes else None})")
    return problems


def check_warm_in_areas(overview: dict, env: str) -> list[str]:
    """Each area counts its kept-warm services' minutes with no instance, read as `<service> has no instance` reads
    instance_count, in that policy's five-minute spells."""
    problems = []
    spell = int(gen.NO_INSTANCE_POLICY["duration"].removesuffix("s")) // 60
    for p in area_panels(overview):
        services = {service_filter(t["timeSeriesList"]) for t in p["targets"]} | {
            s_ for t in p["targets"] for s_ in (service_filter(t["timeSeriesList"]) or "").split("|")}
        for service in gen.KEPT_WARM[env]:
            if service not in services:
                continue
            q_ = target_named(p, f"{service} instances")
            tsl = (q_ or {}).get("timeSeriesList", {})
            if (tsl.get("perSeriesAligner"), tsl.get("alignmentPeriod"), tsl.get("crossSeriesReducer")) != (
                    gen.NO_INSTANCE_POLICY["aligner"], "+" + gen.NO_INSTANCE_POLICY["period"],
                    gen.NO_INSTANCE_POLICY["reducer"]):
                problems.append(f"{env} {p['title']}: {service}'s instances are not read as its no-instance policy "
                                f"reads them")
            c = calcs(p)
            if p["title"] in AREA_PAGES:
                spells = c.get(f"✕ no instance · {service} (spells)")
                if spells is None or operands(spells)[1:] != ("/", ("fixed", str(spell))):
                    problems.append(f"{env} {p['title']}: {service} is not counted in {spell}-minute spells")
            elif f"✕ no instance · {service} (minutes)" not in c:
                problems.append(f"{env} {p['title']}: {service}'s minutes with no instance are not listed")
    return problems


def check_uptime_now(overview: dict) -> list[str]:
    """The Uptime tile's `now`: the hosts as their outage policy reads them, ✕ down in red past its threshold."""
    tile = next(p for p in lint.panels(overview) if p["title"] == "Uptime")
    now = target_named(tile, "now")
    if now is None:
        return ["Uptime: no `now`"]
    tsl, problems = now["timeSeriesList"], []
    policy = UPTIME
    if (tsl["perSeriesAligner"], tsl["alignmentPeriod"], tsl["crossSeriesReducer"]) != (
            policy["aligner"], "+" + policy["period"], policy["reducer"]) or \
            (tsl.get("secondaryPerSeriesAligner"), tsl.get("secondaryCrossSeriesReducer")) != ("ALIGN_MAX", "REDUCE_MAX"):
        problems.append(f"Uptime: now is read {tsl['perSeriesAligner']}/{tsl['alignmentPeriod']}/"
                        f"{tsl['crossSeriesReducer']}, not as the outage policy reads it, worst host")
    latest = [t for t in tile.get("transformations", []) if t.get("filter", {}).get("options") == now["refId"]]
    if [(t["id"], t["options"].get("mode"), t["options"].get("reducers")) for t in latest] != [
            ("reduce", "reduceFields", ["lastNotNull"])]:
        problems.append("Uptime: now is not its latest point (the tile's range is the day's)")
    props = next(o["properties"] for o in tile["fieldConfig"]["overrides"] if o["matcher"]["options"] == "now")
    steps = next(x["value"]["steps"] for x in props if x["id"] == "thresholds")
    red = [s_["value"] for s_ in steps if s_["color"] == gen.RED]
    if red != [policy["above"] + 1]:
        problems.append(f"Uptime: now reads red from {red}, not past the outage policy's {policy['above']}")
    return problems


class OverviewTest(unittest.TestCase):
    def test_three_open_rows_then_the_detail_shut(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_layout(pages["overview"], env), [], env)

    def test_a_tile_per_service_the_environment_runs_and_none_for_one_it_does_not(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_services(pages["overview"], env), [], env)
        self.assertNotIn("connectors", [p["title"] for p in services_row(RENDERED["beta"]["overview"])])
        self.assertIn("connectors", [p["title"] for p in services_row(RENDERED["production"]["overview"])])

    def test_the_inside_check_is_read_as_inside_down_reads_it(self):
        for env, pages in RENDERED.items():
            for name, page in pages.items():
                self.assertEqual(check_inside(page, f"{env} {name}"), [])
        for env in RENDERED:
            self.assertTrue(inside_queries(RENDERED[env]["overview"]), env)

    def test_the_app_jobs_gained_the_importer_alone(self):
        self.assertEqual(WIDENED[APP_JOBS_BEFORE], f"{APP_JOBS_BEFORE}|{gen.IMPORTER}")
        for before in WIDENED:
            self.assertIn(json.dumps(before), json.dumps(BEFORE), "the fixture's queries moved; update WIDENED")
        # Beta's Portal & API stat reads the widened pattern; production's, which builds no importer, the old one.
        for env, jobs in (("beta", WIDENED[gen.TPA_JOBS]), ("production", gen.TPA_JOBS)):
            row = next(ps for title, ps in sections(RENDERED[env]["overview"]).items() if title.startswith("Portal"))
            stat_ = next(p for p in row if p["title"] == ("Jobs (24 h)" if env == "beta" else "tpa-jobs (24 h)"))
            self.assertEqual([v for k, _op, v in facts(stat_["targets"][0])["filters"]
                              if k == "resource.label.job_name"], [jobs], env)

    def test_every_query_the_overview_made_is_still_made(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_queries_kept(env, pages), [], env)

    def test_each_service_tile_reads_warm_and_crashing_as_their_policies_do(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_service_status(pages["overview"], env), [], env)

    def test_database_down_is_db_downs_rule(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_database_down(pages["overview"]), [], env)

    def test_kept_warm_services_with_no_instance_are_area_problems(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_warm_in_areas(pages["overview"], env), [], env)
        portal = next(p for p in area_panels(RENDERED["production"]["overview"]) if p["title"] == "Portal & sign-in")
        self.assertIn("✕ no instance · auth (spells)", calcs(portal))

    def test_a_public_outage_reads_red_now(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_uptime_now(pages["overview"]), [], env)

    def test_a_database_tile_each(self):
        # Moved on purpose (D-173, 2026-10-24): each database's status is its tile and, under it, its backups (30 h)
        # and its point-in-time logs (30 min). A stat reads one time range, and a log counter's series comes back only
        # with a point inside it, so a backup a day old cannot be read in the database tile's fifteen minutes: the
        # row holds three tiles per database, in the same columns, each linking to Databases.
        for env, pages in RENDERED.items():
            tiles = sections(pages["overview"])[gen.DATABASES_ROW]
            dbs = ["auth-db", "tpa-db", "cc-db", "crm-db"] if env == "beta" else ["auth-db", "tpa-db", "crm-db"]
            want = dbs + [f"{db} backups ({gen.BACKUP_HOURS} h)" for db in dbs] + [
                f"{db} logs shipped" for db in dbs]
            self.assertEqual([p["title"] for p in tiles], want, env)
            for p in tiles:
                self.assertIn("/d/tw-cloud-databases?", json.dumps(p["links"]))
            # The columns: each database's three tiles one above the other.
            for db in dbs:
                column = {p["gridPos"]["x"] for p in tiles if p["title"].split(" ")[0] == db}
                self.assertEqual(len(column), 1, (env, db))

    def test_explanations_are_descriptions_not_text(self):
        # The one text panel left on the overview is the incidents link; its explanation is its description.
        for env, pages in RENDERED.items():
            texts = [p for p in lint.panels(pages["overview"]) if p["type"] == "text"]
            self.assertEqual([p["title"] for p in texts], ["Incidents"], env)
            self.assertLess(len(texts[0]["options"]["content"]), 80)
            self.assertIn("PagerDuty", texts[0]["description"])


class RunsTest(unittest.TestCase):
    """Which services each environment runs: production is what production-full's root builds; beta is a part of
    what its root can build (its switches)."""

    def setUp(self):
        if INFRA is None and CHECKOUT_PRESENT:
            self.fail(INFRA_SOURCE)
        if INFRA is None:
            self.skipTest(f"SKIPPED LOUDLY: {INFRA_SOURCE}")

    def test_production_runs_what_its_root_builds(self):
        self.assertEqual(set(gen.RUNS["production"]), set(INFRA.services("production")) & set(gen.SERVICES))

    def test_beta_runs_part_of_what_its_root_can_build(self):
        self.assertLessEqual(set(gen.RUNS["beta"]), set(INFRA.services("beta")))

    def test_the_inside_rule_is_the_modules(self):
        self.assertEqual(gen.INSIDE_POLICY, INFRA.inside_policy())

    def test_kept_warm_is_what_terraform_keeps_warm_and_the_deployments_tfvars_add(self):
        for env in gen.RUNS:
            minimum = INFRA.min_instances(env)
            self.assertEqual(set(gen.TERRAFORM_WARM[env]), {s for s in gen.RUNS[env] if minimum.get(s, 0) >= 1}, env)
            self.assertEqual(set(gen.KEPT_WARM[env]), set(gen.TERRAFORM_WARM[env]) | set(gen.DEPLOYMENT_WARM[env]))
            # A deployment's tfvars can raise only a minimum its root reads from service_min_instances.
            keys = INFRA.min_defaults(env) if gen.DEPLOYMENT_WARM[env] else {}
            for service in gen.DEPLOYMENT_WARM[env]:
                self.assertIn(service, gen.RUNS[env], env)
                self.assertIn(service.replace("-", "_"), keys, f"{env}: {service} has no service_min_instances key")

    def test_every_service_with_a_no_instance_policy_is_kept_warm(self):
        for env in gen.RUNS:
            self.assertLessEqual(INFRA.no_instance_policies(env) & set(gen.RUNS[env]), set(gen.KEPT_WARM[env]), env)

    def test_every_service_the_root_builds_has_a_tile_or_a_reason(self):
        for env in gen.RUNS:
            built = set(INFRA.services(env))
            self.assertLessEqual(built, set(gen.RUNS[env]) | set(gen.NOT_RUN[env]),
                                 f"{env}: Terraform builds a Cloud Run service with no tile and no NOT_RUN reason")
            self.assertFalse(set(gen.RUNS[env]) & set(gen.NOT_RUN[env]), env)
            self.assertLessEqual(set(gen.NOT_RUN[env]), built, f"{env}: NOT_RUN names a service it does not build")

    def test_the_no_instance_and_uptime_rules_are_the_modules(self):
        warm = INFRA.module_policy("no_instance")
        self.assertEqual({k: warm[k] for k in ("aligner", "period", "reducer", "duration")},
                         {k: gen.NO_INSTANCE_POLICY[k] for k in ("aligner", "period", "reducer", "duration")})
        self.assertEqual((warm["comparison"], warm["value"]), ("COMPARISON_LT", gen.NO_INSTANCE_POLICY["below"]))
        uptime = INFRA.module_policy("uptime")
        self.assertEqual({k: uptime[k] for k in ("aligner", "period", "reducer")},
                         {k: gen.UPTIME_POLICY[k] for k in ("aligner", "period", "reducer")})
        self.assertEqual((uptime["comparison"], uptime["value"]), ("COMPARISON_GT", gen.UPTIME_POLICY["above"]))


class DeploymentWarmTest(unittest.TestCase):
    """Beta's own terraform.tfvars (untracked: read by the orchestrating session on 2026-10-13) keeps auth, records,
    tpa-api and svc-ops warm too: at none running each reads ✕ down, never idle, and counts in its area."""

    def test_betas_tfvars_warm_services_are_kept_warm(self):
        self.assertLessEqual({"auth", "records", "tpa-api", "svc-ops"}, set(gen.KEPT_WARM["beta"]))

    def test_they_read_down_with_none_running(self):
        tiles = {p["title"]: p for p in services_row(RENDERED["beta"]["overview"])}
        for service in ("auth", "records", "tpa-api", "svc-ops"):
            self.assertEqual(tiles[service]["fieldConfig"]["defaults"]["noValue"], "✕ down", service)
            self.assertIn("no instance ×4", calcs(tiles[service]), service)
        areas = {p["title"]: calcs(p) for p in area_panels(RENDERED["beta"]["overview"]) if p["title"] in AREA_PAGES}
        for area, service in (("Portal & sign-in", "auth"), ("Portal & sign-in", "tpa-api"),
                              ("Member records", "records"), ("Call centre", "svc-ops")):
            self.assertIn(f"✕ no instance · {service} (spells)", areas[area], service)


class MutationTest(unittest.TestCase):
    def overview(self, env="beta"):
        return copy.deepcopy(RENDERED[env]["overview"])

    def test_a_share_of_regions_for_the_inside_check(self):
        page = self.overview()
        tile = next(p for p in services_row(page) if p["title"] == "auth")
        target = next(t for t in tile["targets"] if t["aliasBy"] == "inside")
        target["timeSeriesList"].update(perSeriesAligner="ALIGN_FRACTION_TRUE", alignmentPeriod="+900s",
                                        crossSeriesReducer="REDUCE_MEAN")
        self.assertEqual(check_inside(page, "beta overview"),
                         [f"beta overview: auth ({target['refId']}) reads the inside check ALIGN_FRACTION_TRUE/+900s/"
                          "REDUCE_MEAN, not inside-down's ALIGN_NEXT_OLDER/60s/REDUCE_COUNT_TRUE"])

    def test_a_tile_for_a_service_beta_does_not_run(self):
        page = self.overview()
        row = next(p for p in page["panels"] if p["title"].startswith("Services"))
        services = next(i for i, p in enumerate(page["panels"]) if p is row)
        page["panels"].insert(services + 1, {**copy.deepcopy(page["panels"][services + 1]), "title": "connectors"})
        self.assertTrue(any("service tiles" in p for p in check_services(page, "beta")))

    def test_a_query_dropped(self):
        pages = copy.deepcopy(RENDERED["beta"])
        for d in pages.values():
            for p in lint.panels(d):
                if p.get("title") == "Uptime by host (15 m)":
                    p["targets"] = []
        self.assertTrue(any("is on no page" in p for p in check_queries_kept("beta", pages)))

    def test_database_down_back_to_one_less_up(self):
        page = self.overview()
        tile = next(p for p in page["panels"] if p["title"] == "Member records")
        step = next(t for t in tile["transformations"] if t["options"].get("alias") == "✕ tpa-db down (minutes)")
        step["options"]["binary"]["left"] = {"fixed": "1"}
        self.assertEqual(check_database_down(page),
                         ["Member records: tpa-db's down minutes are not the minutes it wrote a point less up "
                          "((('fixed', '1'), '-', 'tpa-db up'))"])

    def test_a_kept_warm_service_reading_idle(self):
        page = self.overview()
        tile = next(p for p in services_row(page) if p["title"] == "auth-outbox-publisher")
        tile["fieldConfig"]["defaults"]["noValue"] = "idle"
        tile["transformations"] = [t for t in tile["transformations"]
                                   if t["options"].get("alias") not in ("idle", "no instance ×4")]
        self.assertEqual(len(check_service_status(page, "beta")), 2)

    def test_crashes_not_read(self):
        page = self.overview("production")
        tile = next(p for p in services_row(page) if p["title"] == "records")
        tile["targets"] = [t for t in tile["targets"] if t["aliasBy"] != "crashed"]
        self.assertIn("production records: does not read its own crashes and kills over 15 minutes",
                      check_service_status(page, "production"))

    def test_an_area_row_left_open(self):
        page = self.overview()
        next(p for p in page["panels"] if p["type"] == "row" and p["collapsed"])["collapsed"] = False
        self.assertTrue(any("open below Databases" in p for p in check_layout(page, "beta")))


if __name__ == "__main__":
    unittest.main()
