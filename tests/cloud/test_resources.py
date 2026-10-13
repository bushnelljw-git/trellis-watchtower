"""Every Cloud Run service's resource primitives are on the cloud pages, drawn with the lines the pager uses.

The owner (2026-10-13): "Where are all the primitives for each service?" Each area page carries a Resources row for
each Cloud Run service it covers (CPU, memory, instances, concurrency, start-up, instances billed, and containers
killed for memory, crashed or failing to start); each service has a page of its own, linked from the overview; the
databases show their disk space in bytes against their size; the app, PHI and call-centre projects' Cloud NAT and the
PHI project's buckets are on the pages that own them; the Jobs page shows each project's task attempts, run lengths,
CPU and memory. Every red line is checked against the vendored catalogue's own threshold, and against the way its
condition aggregates (aligner, window, reducer), so the line means what the pager means.

The checks are functions returning problems, run on the real pages and, in MutationTest, on broken copies.

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
DASHBOARDS = ROOT / "cloud" / "dashboards"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE))

import catalogue as cat  # noqa: E402
import dashboard_lint as lint  # noqa: E402
from test_catalogue import NAMES  # noqa: E402

CATALOGUE = cat.Catalogue()
RUN = "run.googleapis.com/container/"
CPU, MEMORY, INSTANCES = RUN + "cpu/utilizations", RUN + "memory/utilizations", RUN + "instance_count"
CONCURRENCY, STARTUP, BILLABLE = RUN + "max_request_concurrencies", RUN + "startup_latencies", RUN + "billable_instance_time"
LOG = "logging.googleapis.com/user/"
FAILURES = {LOG + "run_oom_kills", LOG + "run_crash_exits", LOG + "run_system_errors"}
PRIMITIVES = {CPU, MEMORY, INSTANCES, CONCURRENCY, STARTUP, BILLABLE, *FAILURES}
DATASOURCE = {"app": "cloud-app", "phi": "cloud-phi", "crm": "cloud-crm", "cc": "cloud-cc"}
# Which page holds which services' Resources rows, written out here rather than read from the generator, and held
# to the catalogue test's list of every project's Cloud Run services.
AREAS = {"portal-api": ("app", {"web", "tpa-api", "model-gateway", "tpa-jobs-drains"}),
         "sign-in": ("app", {"auth", "auth-outbox-publisher"}),
         "records": ("phi", {"records", "connectors"}),
         "callcentre": ("cc", {"svc-voice", "svc-ops", "svc-twilio-rest"}),
         "crm": ("crm", {"crm-web", "engine"})}
DATABASE_PAGES = {"auth-db": ("app", "sign-in"), "tpa-db": ("phi", "records"), "crm-db": ("crm", "crm"),
                  "cc-db": ("cc", "callcentre")}
NAT_PAGES = {"portal-api": "app", "records": "phi", "callcentre": "cc"}
JOB_PROJECTS = ("cloud-app", "cloud-phi", "cloud-cc", "cloud-crm")


def load(name: str) -> dict:
    return json.loads((DASHBOARDS / f"{name}.json").read_text())


def sections(dashboard: dict) -> dict[str, list[dict]]:
    """Row title -> the panels under it."""
    out: dict[str, list[dict]] = {}
    current = None
    for panel in dashboard["panels"]:
        if panel["type"] == "row":
            current = panel["title"]
            out[current] = []
        elif current is not None:
            out[current].append(panel)
    return out


def resource_rows(dashboard: dict) -> dict[str, list[dict]]:
    """Service -> the panels of its Resources row."""
    return {title.split(" · ", 1)[1].split(":", 1)[0]: panels for title, panels in sections(dashboard).items()
            if title.startswith("Resources · ")}


def metric(target: dict) -> str:
    return lint.query_facts(target["timeSeriesList"])["metric"]


def filters(target: dict) -> dict[str, tuple[str, str]]:
    return {k: (op, v) for k, op, v in lint.query_facts(target["timeSeriesList"])["filters"]}


def red_lines(panel: dict) -> list[float]:
    return [s["value"] for s in panel["fieldConfig"]["defaults"]["thresholds"]["steps"]
            if s["value"] is not None and s["color"] == "red"]


def reads(panel: dict, metric_type: str) -> bool:
    return any(metric(t) == metric_type for t in panel.get("targets") or [])


def aggregated_as(target: dict, policy: dict) -> list[str]:
    """How a query differs from the policy condition whose line its panel draws."""
    tsl = target["timeSeriesList"]
    want = {"perSeriesAligner": policy["per_series_aligner"], "alignmentPeriod": "+" + policy["alignment_period"],
            "crossSeriesReducer": policy["cross_series_reducer"]}
    return [f"{k} {tsl.get(k)} is not the policy's {v}" for k, v in want.items() if tsl.get(k) != v]


# ---- The checks --------------------------------------------------------------------------------------------------
def check_resources(page: str, dashboard: dict) -> list[str]:
    """The page's Resources rows: one per service it covers, each reading every primitive of that service alone on
    the project's datasource, with the CPU, memory and concurrency lines the catalogue's policies use."""
    role, services = AREAS[page] if page in AREAS else (None, None)
    rows = resource_rows(dashboard)
    problems = []
    if services is not None and set(rows) != services:
        problems.append(f"{page}: Resources rows for {sorted(rows)}, not {sorted(services)}")
    for service, panels in rows.items():
        where = f"{page}: Resources · {service}"
        targets = [t for p in panels for t in p.get("targets") or []]
        missing = PRIMITIVES - {metric(t) for t in targets}
        if missing:
            problems.append(f"{where}: reads none of {sorted(missing)}")
        for t in targets:
            if filters(t).get("resource.label.service_name") not in (("=", service), ("=~", service)):
                problems.append(f"{where}: {metric(t)} does not read {service} alone: {filters(t)}")
            if role and t["datasource"]["uid"] != DATASOURCE[role]:
                problems.append(f"{where}: {metric(t)} on {t['datasource']['uid']}, not {DATASOURCE[role]}")
        for metric_type, name in ((CPU, "run-cpu-high"), (MEMORY, "run-memory-high")):
            policy = CATALOGUE.threshold(name)
            panel = next((p for p in panels if reads(p, metric_type)), None)
            if panel is None:
                continue
            if red_lines(panel) != [policy["threshold_value"]]:
                problems.append(f"{where}: {panel['title']} draws red at {red_lines(panel)}, not `{name}`'s "
                                f"{policy['threshold_value']}")
            p99 = next((t for t in panel["targets"] if t["aliasBy"] == "p99"), None)
            if p99 is None:
                problems.append(f"{where}: {panel['title']} has no p99")
            else:
                problems += [f"{where}: {panel['title']}: {d}" for d in aggregated_as(p99, policy)]
            if panel["fieldConfig"]["defaults"]["custom"].get("thresholdsStyle", {}).get("mode") != "line":
                problems.append(f"{where}: {panel['title']} does not draw its thresholds as lines")
        policy = CATALOGUE.threshold("run-concurrency-high")
        panel = next((p for p in panels if reads(p, CONCURRENCY)), None)
        if panel is not None:
            setting = panel["fieldConfig"]["defaults"]["custom"].get("axisSoftMax")
            want = [policy["threshold_value"]] if setting and policy["threshold_value"] < setting else []
            if red_lines(panel) != want:
                problems.append(f"{where}: concurrency draws red at {red_lines(panel)}, not {want} (its setting "
                                f"{setting}, `run-concurrency-high` {policy['threshold_value']})")
            p99 = next((t for t in panel["targets"] if t["aliasBy"] == "p99"), None)
            problems += [f"{where}: concurrency: {d}" for d in (aggregated_as(p99, policy) if p99 else ["no p99"])]
    return problems


def check_project(page: str, dashboard: dict) -> list[str]:
    """The project's instances against the quota line, and its Cloud NAT with `nat-port-exhaustion`'s lines."""
    problems = []
    quota = CATALOGUE.threshold("run-instances-near-quota")
    panels = [p for p in lint.panels(dashboard) if p["title"] == "Cloud Run instances, every service"]
    if len(panels) != 1:
        problems.append(f"{page}: {len(panels)} project instance panels")
    for panel in panels:
        if red_lines(panel) != [quota["threshold_value"]]:
            problems.append(f"{page}: the project's instances draw red at {red_lines(panel)}, not "
                            f"`run-instances-near-quota`'s {quota['threshold_value']}")
        problems += [f"{page}: project instances: {d}" for d in aggregated_as(panel["targets"][0], quota)]
    nat = [p for p in lint.panels(dashboard) if any(metric(t).startswith("router.googleapis.com/nat/")
                                                     for t in p.get("targets") or [])]
    if page not in NAT_PAGES:
        return problems + ([f"{page}: has Cloud NAT panels"] if nat else [])
    if not nat or {t["datasource"]["uid"] for p in nat for t in p["targets"]} != {DATASOURCE[NAT_PAGES[page]]}:
        return problems + [f"{page}: no Cloud NAT panels on {DATASOURCE[NAT_PAGES[page]]}"]
    read = {metric(t) for p in nat for t in p["targets"]}
    for name in ("allocated_ports", "port_usage", "new_connections_count", "dropped_sent_packets_count",
                 "dropped_received_packets_count", "nat_allocation_failed"):
        if f"router.googleapis.com/nat/{name}" not in read:
            problems.append(f"{page}: Cloud NAT's {name} is not charted")
    for condition, metric_type in ((0, "nat_allocation_failed"), (1, "dropped_sent_packets_count")):
        policy = CATALOGUE.threshold("nat-port-exhaustion", condition=condition)
        panel = next(p for p in nat if reads(p, f"router.googleapis.com/nat/{metric_type}"))
        if red_lines(panel) != [policy["threshold_value"]]:
            problems.append(f"{page}: {panel['title']} draws red at {red_lines(panel)}, not "
                            f"`nat-port-exhaustion`'s {policy['threshold_value']}")
        paged = [t for t in panel["targets"] if metric(t).endswith(metric_type) and
                 filters(t).get("metric.label.reason", ("=", "OUT_OF_RESOURCES")) == ("=", "OUT_OF_RESOURCES")]
        problems += [f"{page}: {panel['title']}: {d}" for t in paged[:1] for d in aggregated_as(t, policy)]
    return problems


def check_database(name: str, page: str, dashboard: dict) -> list[str]:
    """One instance's disk space, in percent with `<name>-disk`'s line and in bytes against its size, and its I/O."""
    role = DATABASE_PAGES[name][0]
    policy = CATALOGUE.threshold(f"{name}-disk", role)
    rows = {t: ps for t, ps in sections(dashboard).items() if t.startswith(f"{name} (")}
    if len(rows) != 1:
        return [f"{page}: {len(rows)} sections for {name}"]
    panels = next(iter(rows.values()))
    problems = []
    read = {metric(t) for p in panels for t in p.get("targets") or []}
    for suffix in ("disk/utilization", "disk/bytes_used", "disk/quota", "disk/read_ops_count", "disk/write_ops_count",
                   "disk/read_bytes_count", "disk/write_bytes_count", "cpu/utilization", "memory/utilization",
                   "postgresql/num_backends", "up"):
        if f"cloudsql.googleapis.com/database/{suffix}" not in read:
            problems.append(f"{page}: {name}: {suffix} is not charted")
    for p in panels:
        for t in p.get("targets") or []:
            if filters(t).get("resource.label.database_id") != ("=", f"*:{name}"):
                problems.append(f"{page}: {name}: {p['title']} does not read {name} alone")
            if t["datasource"]["uid"] != DATASOURCE[role]:
                problems.append(f"{page}: {name}: {p['title']} on {t['datasource']['uid']}")
    percent = next((p for p in panels if p["title"] == "Disk space used (%)"), None)
    if percent is None or red_lines(percent) != [policy["threshold_value"]]:
        problems.append(f"{page}: {name}: disk space (%) does not draw `{name}-disk`'s {policy['threshold_value']}")
    else:
        problems += [f"{page}: {name}: disk space (%): {d}" for d in aggregated_as(percent["targets"][0], policy)]
    size = next((p for p in panels if reads(p, "cloudsql.googleapis.com/database/disk/quota")), None)
    factors = [c["options"]["binary"]["right"]["fixed"] for c in (size or {}).get("transformations", [])
               if c["id"] == "calculateField"]
    if factors != [f"{policy['threshold_value']:g}"]:
        problems.append(f"{page}: {name}: the bytes panel's alert line is {factors} of the size, not "
                        f"`{name}-disk`'s {policy['threshold_value']}")
    return problems


def check_jobs(dashboard: dict, projects=JOB_PROJECTS) -> list[str]:
    problems = []
    rows = {t: ps for t, ps in sections(dashboard).items() if t.startswith("Job resources: ")}
    by_project: dict[str, set[str]] = {}
    for panels in rows.values():
        for p in panels:
            for t in p.get("targets") or []:
                by_project.setdefault(t["datasource"]["uid"], set()).add(metric(t))
    want = {"run.googleapis.com/job/completed_task_attempt_count", "run.googleapis.com/job/running_task_attempts",
            CPU, MEMORY, LOG + "run_oom_kills", LOG + "run_system_errors"}
    for project in projects:
        missing = want - by_project.get(project, set())
        if missing:
            problems.append(f"jobs: {project}: {sorted(missing)} not charted")
    return problems


NOTE = "Cloud Run services have no disk"


class ResourcesTest(unittest.TestCase):
    def test_the_areas_cover_every_cloud_run_service(self):
        covered = set().union(*(services for _role, services in AREAS.values()))
        self.assertEqual(covered, set().union(*(n["service_name"] for n in NAMES.values())))
        for page, (role, services) in AREAS.items():
            self.assertLessEqual(services, NAMES[role]["service_name"], page)

    def test_every_area_page_has_each_services_resources(self):
        for page in AREAS:
            self.assertEqual(check_resources(page, load(page)), [], page)

    def test_every_area_page_says_a_service_has_no_disk(self):
        for page in [*AREAS, *(f"service-{s}" for _r, ss in AREAS.values() for s in ss)]:
            self.assertIn(NOTE, json.dumps(load(page)), page)

    def test_projects_quota_and_cloud_nat(self):
        for page in ("portal-api", "records", "callcentre", "crm"):
            self.assertEqual(check_project(page, load(page)), [], page)

    def test_the_nat_condition_reads_the_reason_the_dashboard_filters(self):
        self.assertIn('metric.labels.reason = "OUT_OF_RESOURCES"', CATALOGUE.text)

    def test_the_phi_projects_buckets(self):
        panels = [p for p in lint.panels(load("records")) if any(
            metric(t).startswith("storage.googleapis.com/") for t in p.get("targets") or [])]
        self.assertEqual({metric(t) for p in panels for t in p["targets"]},
                         {"storage.googleapis.com/storage/total_bytes", "storage.googleapis.com/storage/object_count"})
        for p in panels:
            for t in p["targets"]:
                self.assertEqual(t["timeSeriesList"]["groupBys"], ["resource.label.bucket_name"])

    def test_every_database_on_the_databases_page_and_its_owners(self):
        for name, (_role, owner) in DATABASE_PAGES.items():
            for page in ("databases", owner):
                self.assertEqual(check_database(name, page, load(page)), [], (name, page))
        no_cc = json.loads((DASHBOARDS / "no-cc" / "databases.json").read_text())
        for name in ("auth-db", "tpa-db", "crm-db"):
            self.assertEqual(check_database(name, "no-cc/databases", no_cc), [], name)

    def test_the_jobs_page_shows_each_projects_task_resources(self):
        self.assertEqual(check_jobs(load("jobs")), [])
        no_cc = json.loads((DASHBOARDS / "no-cc" / "jobs.json").read_text())
        self.assertEqual(check_jobs(no_cc, ("cloud-app", "cloud-phi", "cloud-crm")), [])

    def test_every_service_has_its_own_page_with_the_same_resources_row(self):
        for page, (_role, services) in AREAS.items():
            area = resource_rows(load(page))
            for service in services:
                own = load(f"service-{service}")
                self.assertEqual(own["uid"], f"tw-cloud-service-{service}")
                self.assertIn("cloud-service", own["tags"])
                self.assertNotIn("cloud", own["tags"], "the Pages menu lists the area pages alone")
                self.assertEqual(check_resources(f"service-{service}", own), [])
                self.assertEqual(list(resource_rows(own)), [service])
                strip = lambda ps: [{k: v for k, v in p.items() if k not in ("links", "gridPos", "id")} for p in ps]
                self.assertEqual(strip(resource_rows(own)[service]), strip(area[service]), service)
                # The way back: the area's page, by the menu and by the row's first panel.
                self.assertIn(f"/d/tw-cloud-{page}", json.dumps(own["links"]))
        self.assertEqual(sorted(p.stem for p in DASHBOARDS.glob("service-*.json")),
                         sorted(f"service-{s}" for _r, ss in AREAS.values() for s in ss))

    def test_every_service_page_is_linked(self):
        overview = json.dumps([p.get("links", []) for p in lint.panels(load("overview"))])
        no_cc = json.dumps([p.get("links", []) for p in lint.panels(
            json.loads((DASHBOARDS / "no-cc" / "overview.json").read_text()))])
        for page, (role, services) in AREAS.items():
            area = resource_rows(load(page))
            for service in services:
                url = f"/d/tw-cloud-service-{service}?"
                self.assertIn(url, overview, f"the overview does not link {service}'s page")
                self.assertEqual(url in no_cc, role != "cc", service)
                self.assertIn(url, json.dumps(area[service][0].get("links")), (page, service))
        for path in [*DASHBOARDS.glob("*.json"), *DASHBOARDS.glob("no-cc/*.json")]:
            menus = [link for link in json.loads(path.read_text())["links"] if link["title"] == "Services"]
            self.assertEqual([(m["type"], m["tags"], m["asDropdown"]) for m in menus],
                             [("dashboards", ["cloud-service"], True)], path)


class MutationTest(unittest.TestCase):
    """The checks catch a page that loses a service's row, a line moved off the catalogue's, or a window that is not
    the policy's."""

    def test_a_missing_resources_row(self):
        page = load("portal-api")
        title = next(p["title"] for p in page["panels"] if p["title"].startswith("Resources · tpa-api"))
        start = next(i for i, p in enumerate(page["panels"]) if p["title"] == title)
        end = next(i for i, p in enumerate(page["panels"]) if i > start and p["type"] == "row")
        del page["panels"][start:end]
        self.assertIn("portal-api: Resources rows for ['model-gateway', 'tpa-jobs-drains', 'web'], not "
                      "['model-gateway', 'tpa-api', 'tpa-jobs-drains', 'web']", check_resources("portal-api", page))

    def test_a_cpu_line_off_the_catalogue(self):
        page = load("sign-in")
        cpu = next(p for p in resource_rows(page)["auth"] if reads(p, CPU))
        cpu["fieldConfig"]["defaults"]["thresholds"]["steps"][1]["value"] = 0.8
        self.assertEqual(check_resources("sign-in", page),
                         ["sign-in: Resources · auth: CPU (p99, p95, p50) draws red at [0.8], not `run-cpu-high`'s 0.9"])

    def test_a_memory_window_that_is_not_the_policys(self):
        page = load("records")
        memory = next(p for p in resource_rows(page)["records"] if reads(p, MEMORY))
        memory["targets"][0]["timeSeriesList"]["alignmentPeriod"] = "grafana-auto"
        self.assertEqual(check_resources("records", page),
                         ["records: Resources · records: Memory (p99, p95, p50): alignmentPeriod grafana-auto is not "
                          "the policy's +300s"])

    def test_a_query_reading_another_service(self):
        page = load("crm")
        row = resource_rows(page)["engine"]
        row[2]["targets"][0]["timeSeriesList"]["filters"][-1] = "crm-web"
        self.assertTrue(any("does not read engine alone" in p for p in check_resources("crm", page)))

    def test_a_disk_line_off_the_catalogue(self):
        page = copy.deepcopy(load("databases"))
        for p in page["panels"]:
            if p["title"] == "Disk space used (%)" and "tpa-db" in json.dumps(p["targets"]):
                p["fieldConfig"]["defaults"]["thresholds"]["steps"][1]["value"] = 0.9
        self.assertEqual(check_database("tpa-db", "databases", page),
                         ["databases: tpa-db: disk space (%) does not draw `tpa-db-disk`'s 0.85"])

    def test_a_nat_drop_line_off_the_catalogue(self):
        page = load("portal-api")
        for p in page["panels"]:
            if p["title"] == "NAT dropped packets":
                p["fieldConfig"]["defaults"]["thresholds"]["steps"][1]["value"] = 100
        self.assertEqual(check_project("portal-api", page),
                         ["portal-api: NAT dropped packets draws red at [100], not `nat-port-exhaustion`'s 10.0"])


if __name__ == "__main__":
    unittest.main()
