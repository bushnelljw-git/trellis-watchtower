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


def check_queries_kept(env: str, pages: dict[str, dict]) -> list[str]:
    """Each query the overview made before is made by a page of this environment, unless replaced on purpose (and
    then its replacement is there)."""
    have = {key(t["datasource"]["uid"], t["timeSeriesList"]) for d in pages.values() for _p, t in queries(d)}
    overview = pages["overview"]
    tiles = {p["title"]: p for p in services_row(overview)}
    problems = []
    for q in BEFORE["queries"]:
        if env not in q["environments"] or key(q["datasource"], q["timeSeriesList"]) in have:
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
                            f"{tsl['perSeriesAligner']} {tsl['alignmentPeriod']} is on no page")
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

    def test_every_query_the_overview_made_is_still_made(self):
        for env, pages in RENDERED.items():
            self.assertEqual(check_queries_kept(env, pages), [], env)

    def test_a_database_tile_each(self):
        for env, pages in RENDERED.items():
            tiles = sections(pages["overview"])["Databases: up, CPU, memory, disk"]
            want = ["auth-db", "tpa-db", "cc-db", "crm-db"] if env == "beta" else ["auth-db", "tpa-db", "crm-db"]
            self.assertEqual([p["title"] for p in tiles], want, env)
            for p in tiles:
                self.assertIn("/d/tw-cloud-databases?", json.dumps(p["links"]))

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


class MutationTest(unittest.TestCase):
    def overview(self, env="beta"):
        return copy.deepcopy(RENDERED[env]["overview"])

    def test_a_share_of_regions_for_the_inside_check(self):
        page = self.overview()
        tile = next(p for p in services_row(page) if p["title"] == "auth")
        inside = next(t for t in tile["targets"] if t["aliasBy"] == "inside")["timeSeriesList"]
        inside.update(perSeriesAligner="ALIGN_FRACTION_TRUE", alignmentPeriod="+900s", crossSeriesReducer="REDUCE_MEAN")
        self.assertEqual(check_inside(page, "beta overview"),
                         ["beta overview: auth (C) reads the inside check ALIGN_FRACTION_TRUE/+900s/REDUCE_MEAN, not "
                          "inside-down's ALIGN_NEXT_OLDER/60s/REDUCE_COUNT_TRUE"])

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

    def test_an_area_row_left_open(self):
        page = self.overview()
        next(p for p in page["panels"] if p["type"] == "row" and p["collapsed"])["collapsed"] = False
        self.assertTrue(any("open below Databases" in p for p in check_layout(page, "beta")))


if __name__ == "__main__":
    unittest.main()
