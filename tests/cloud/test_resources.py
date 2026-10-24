"""Every Cloud Run service's resource primitives are on the cloud pages, drawn with the lines the pager uses, in each
environment.

The owner (2026-10-13): "Where are all the primitives for each service?" Each area page carries a Resources row for
each Cloud Run service it covers (shut until opened; open on the service's own page): CPU, memory, instances (their
total as the `ceiling-` policies read it, and active and idle), concurrency, start-up, instances billed, and containers
killed for memory, crashed or failing to start. The databases show their disk space in bytes against their size; the
app, PHI and call-centre projects' Cloud NAT and the PHI project's buckets are on the pages that own them; the Jobs page
shows each project's task attempts, run lengths, CPU and memory.

The pages are checked as each environment renders them (cloud/render-dashboards.sh, beta and production), against
the source of every line:
- the vendored catalogue (run-cpu-high, run-memory-high, run-concurrency-high, run-instances-near-quota,
  nat-port-exhaustion, `<instance>-disk`);
- tpa-platform's Terraform, at the catalogue's pinned commit (cloud/catalogue/SOURCE), read from the tpa-platform
  checkout beside this repository (or $TPA_PLATFORM_CHECKOUT): each root's max_instances, concurrency, instance
  ceilings and max_connections (infra/envs/beta and infra/envs/production-full), and the monitoring module's own
  per-instance and per-ceiling policies (infra/modules/monitoring/main.tf). With no checkout at all the pins are
  skipped, said loudly, and the pages are checked against the generator's own copy only; a checkout that lacks the
  pinned commit fails them (fetch it), since a stale checkout would otherwise pass anything.
The line and the aggregation are both checked, so a line means what the pager means.

The checks are functions returning problems, run on the rendered pages and, in MutationTest, on broken copies.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import copy
import json
import math
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
DASHBOARDS = ROOT / "cloud" / "dashboards"
RENDER = ROOT / "cloud" / "render-dashboards.sh"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE))

import catalogue as cat  # noqa: E402
import cloud_dashboards as gen  # noqa: E402
import dashboard_lint as lint  # noqa: E402
from test_catalogue import NAMES  # noqa: E402

CATALOGUE = cat.Catalogue()
RUN = "run.googleapis.com/container/"
CPU, MEMORY, INSTANCES = RUN + "cpu/utilizations", RUN + "memory/utilizations", RUN + "instance_count"
CONCURRENCY, STARTUP, BILLABLE = RUN + "max_request_concurrencies", RUN + "startup_latencies", RUN + "billable_instance_time"
LOG = "logging.googleapis.com/user/"
FAILURES = {LOG + "run_oom_kills", LOG + "run_crash_exits", LOG + "run_system_errors"}
PRIMITIVES = {CPU, MEMORY, INSTANCES, CONCURRENCY, STARTUP, BILLABLE, *FAILURES}
SQL = "cloudsql.googleapis.com/database/"
DATASOURCE = {"app": "cloud-app", "phi": "cloud-phi", "crm": "cloud-crm", "cc": "cloud-cc"}
GREY = "#8c8c8c"
DEFAULT_MAX_INSTANCES = 100
# Which page holds which services' Resources rows, written out here rather than read from the generator, and held
# to the catalogue test's list of every project's Cloud Run services.
AREAS = {"portal-api": ("app", {"web", "tpa-api", "model-gateway", "tpa-jobs-drains", "watchtower"}),
         "sign-in": ("app", {"auth", "auth-outbox-publisher"}),
         "records": ("phi", {"records", "connectors"}),
         "callcentre": ("cc", {"svc-voice", "svc-ops", "svc-twilio-rest"}),
         "crm": ("crm", {"crm-web", "engine"})}
DATABASE_PAGES = {"auth-db": ("app", "sign-in"), "tpa-db": ("phi", "records"), "crm-db": ("crm", "crm"),
                  "cc-db": ("cc", "callcentre")}
NAT_PAGES = {"portal-api": "app", "records": "phi", "callcentre": "cc"}
JOB_PROJECTS = ("cloud-app", "cloud-phi", "cloud-cc", "cloud-crm")
ENVIRONMENTS = {"beta": {"TPA_APP_PROJECT_ID": "beta-tpa-app", "TPA_CRM_PROJECT_ID": "beta-tpa-app",
                         "TPA_PHI_PROJECT_ID": "beta-tpa-phi", "TPA_CC_PROJECT_ID": "beta-callcentre",
                         "TPA_ENVIRONMENT": "beta"},
                "production": {"TPA_APP_PROJECT_ID": "prod-tpa-app", "TPA_CRM_PROJECT_ID": "prod-crm",
                               "TPA_PHI_PROJECT_ID": "prod-tpa-phi", "TPA_CC_PROJECT_ID": "",
                               "TPA_ENVIRONMENT": "production"}}
ROOTS = {"beta": "infra/envs/beta", "production": "infra/envs/production-full"}


# ---- tpa-platform's Terraform, at the catalogue's pinned commit ----------------------------------------------------
class Infra:
    """What tpa-platform's Terraform says, read with `git show <pinned commit>:<path>` from a local checkout."""

    def __init__(self, checkout: Path, commit: str):
        self.checkout, self.commit = checkout, commit

    @classmethod
    def find(cls, checkout: Path | None = None) -> tuple["Infra | None", str, bool]:
        """(the reader, what it reads or why there is none, whether a checkout is there at all)."""
        checkout = checkout or Path(os.environ.get("TPA_PLATFORM_CHECKOUT", ROOT.parent / "tpa-platform"))
        commit = cat.source()["commit"]
        if not (checkout / ".git").exists():
            return None, f"no tpa-platform checkout at {checkout} (set TPA_PLATFORM_CHECKOUT)", False
        found = subprocess.run(["git", "-C", str(checkout), "cat-file", "-e", f"{commit}^{{commit}}"],
                               capture_output=True)
        if found.returncode:
            return None, (f"the tpa-platform checkout at {checkout} lacks the catalogue's pinned commit {commit[:8]}: "
                          f"run `git -C {checkout} fetch origin`"), True
        return cls(checkout, commit), f"tpa-platform at {commit[:8]} ({checkout})", True

    def show(self, path: str) -> str:
        return subprocess.run(["git", "-C", str(self.checkout), "show", f"{self.commit}:{path}"],
                              capture_output=True, text=True, check=True).stdout

    def root_text(self, env: str) -> str:
        names = subprocess.run(["git", "-C", str(self.checkout), "ls-tree", "--name-only", self.commit,
                                ROOTS[env] + "/"], capture_output=True, text=True, check=True).stdout.split()
        return "\n".join(self.show(n) for n in names if n.endswith(".tf"))

    @staticmethod
    def block(text: str, opening: str) -> str:
        """The text of the first `{...}` after `opening` (balanced braces)."""
        start = text.index(opening) + len(opening)
        depth, i = 0, text.index("{", start - 1)
        for j in range(i, len(text)):
            depth += {"{": 1, "}": -1}.get(text[j], 0)
            if depth == 0:
                return text[i:j + 1]
        raise ValueError(opening)

    def module_default(self, module: str, variable: str) -> int:
        text = self.show(f"infra/modules/{module}/variables.tf")
        return int(re.search(r"\bdefault\s*=\s*(\d+)", self.block(text, f'variable "{variable}"')).group(1))

    def services(self, env: str) -> dict[str, tuple[int, int]]:
        """Each Cloud Run service the root builds: (max_instances, concurrency), the module's default where unset."""
        out = {}
        defaults = (self.module_default("run-service", "max_instances"),
                    self.module_default("run-service", "concurrency"))
        for m in re.finditer(r'^module "[^"]+" \{\n(.*?)^\}', self.root_text(env), re.M | re.S):
            body = m.group(1)
            if not re.search(r'^\s*source\s*=\s*"[./]*modules/run-service"', body, re.M):
                continue
            name = re.search(r'^  name\s*=\s*"([a-z0-9-]+)"', body, re.M).group(1)
            values = []
            for key, default in zip(("max_instances", "concurrency"), defaults):
                set_ = re.search(rf"^  {key}\s*=\s*(.+?)\s*$", body, re.M)
                expr = self.local(env, set_.group(1)) if set_ else None
                if expr is not None and not expr.isdigit():
                    raise AssertionError(f"{env}: {name}'s {key} is `{set_.group(1)}`, not a number this reads")
                values.append(int(expr) if expr is not None else default)
            out[name] = tuple(values)
        return out

    # A switch whose "on" builds a service as something the pages do not chart it as: beta's code sender
    # (textcodes.tf, D-158) builds connectors with one instance and no ceiling, where the pages chart connectors as
    # its outbox lanes build it (B8's connectors_enabled: four, and `ceiling-connectors`). The two are never on
    # together (beta's variables.tf), so a limit behind it is read with the switch off.
    READ_OFF = ("var.beta_text_codes_enabled",)

    def local(self, env: str, expr: str) -> str:
        """`local.NAME` as the root's locals write it (a number, or `<switch> ? A : B`: A, or B for a READ_OFF
        switch); anything else as it is."""
        m = re.fullmatch(r"local\.([a-z_]+)", expr.strip())
        if not m:
            return expr.strip()
        body = re.search(rf"^  {m.group(1)}\s*=\s*(.+?)\s*$", self.root_text(env), re.M).group(1)
        cond = re.fullmatch(r"(var\.[a-z_]+)\s*\?\s*(\S+)\s*:\s*(\S+)", body)
        if cond:
            return cond.group(3) if cond.group(1) in self.READ_OFF else cond.group(2)
        return body

    def ceilings(self, env: str) -> dict[str, int]:
        """The services the root asks the module for a `ceiling-<service>` policy for (instance_ceilings)."""
        text, out = self.root_text(env), {}
        # A literal map, or a merge() of maps (production-full's app call since D-154: merge({ auth = 20, ... },
        # var.file_reader_enabled ? { file-reader = 10 } : {})), read with every switch on.
        for m in re.finditer(r"\binstance_ceilings(?:_by_role)?\s*=\s*(?:merge\()?\{", text):
            if m.group(0).endswith("merge({"):
                start = m.end() - 1
                body = text[start:text.index("\n", start)]
            else:
                body = self.block(text[m.start():], m.group(0))
            out.update({k: int(v) for k, v in re.findall(r"\b([a-z][a-z0-9-]*)\s*=\s*(\d+)\b", body)})
        return out

    def max_connections(self, env: str) -> dict[str, int]:
        """Each Cloud SQL instance's max_connections as the root's sql_max_connections computes it: its flag, else the
        shared-core value, else the band for its tier's memory, the tier being terraform.tfvars.example's (cc-db's
        commented example, for a staffed-call plan, included)."""
        text = self.root_text(env)

        def pairs(name):
            return dict(re.findall(r'"?([a-z0-9-]+)"?\s*=\s*(\d+)', self.block(text, f"{name} ")))
        flag, shared = pairs("sql_max_connections_flag"), pairs("sql_shared_core_connections")
        bands = [tuple(map(int, b)) for b in re.findall(r"\[(\d+),\s*(\d+)\]", re.search(
            r"sql_connection_bands\s*=\s*(\[.*\])", text).group(1))]
        tiers = {}
        current = None
        for line in self.show(ROOTS[env] + "/terraform.tfvars.example").splitlines():
            m = re.match(r"^\s*#?\s*([a-z][a-z0-9-]*-db) = \{", line)
            if m:
                current = m.group(1)
            m = re.match(r'^\s*#?\s*tier\s*=\s*"([^"]+)"', line)
            if m and current:
                tiers.setdefault(current, m.group(1))
        out = {}
        for db, tier in tiers.items():
            memory = re.fullmatch(r"db-custom-\d+-(\d+)", tier)
            band = next((n for floor, n in bands if memory and int(memory.group(1)) >= floor), None)
            value = int(flag[db]) if db in flag else int(shared[tier]) if tier in shared else band
            if value is not None:
                out[db] = value
        return out

    def sql_policies(self) -> dict[str, dict]:
        text = self.block(self.show("infra/modules/monitoring/main.tf"), "sql_thresholds =")
        out = {}
        for name in gen.SQL_POLICIES:
            body = self.block(text, f"{name} =")
            get = lambda key: re.search(rf'^\s*{key}\s*=\s*"?([^"\n]+?)"?\s*$', body, re.M).group(1)
            value = get("value")
            share = re.fullmatch(r"floor\(([0-9.]+) \* i\.max_connections\)", value)
            out[name] = {"metric": get("metric"), **({"share": float(share.group(1))} if share else
                                                     {"value": float(value)}),
                         "period": get("period"), "aligner": get("aligner"), "reducer": get("reducer")}
        return out

    def ceiling_policy(self) -> dict:
        body = self.block(self.show("infra/modules/monitoring/main.tf"), "ceiling_policies =")
        get = lambda key: re.search(rf"^\s*{key}\s*=\s*(.+?)\s*$", body, re.M).group(1)
        share = re.fullmatch(r"ceil\(([0-9.]+) \* max\) - 0\.5", get("threshold_value"))
        assert share, f"the ceiling's threshold is `{get('threshold_value')}`, not ceil(share * max) - 0.5"
        assert get("group_by_fields") == '["resource.label.service_name"]', get("group_by_fields")
        return {"metric": re.search(r'metric\.type = \\"([^\\]+)\\"', get("filter")).group(1),
                "share": float(share.group(1)), "period": get("alignment_period").strip('"'),
                "aligner": get("per_series_aligner").strip('"'), "reducer": get("cross_series_reducer").strip('"')}

    def module_policy(self, resource: str) -> dict:
        """A module policy's first threshold condition: its aligner, window, reducer, comparison, value, duration."""
        body = self.block(self.show("infra/modules/monitoring/main.tf"),
                          f'resource "google_monitoring_alert_policy" "{resource}"')
        get = lambda key: re.search(rf'^\s*{key}\s*=\s*"?([^"\n]+?)"?\s*$', body, re.M).group(1)
        return {"aligner": get("per_series_aligner"), "period": get("alignment_period"),
                "reducer": get("cross_series_reducer"), "comparison": get("comparison"),
                "value": int(float(get("threshold_value"))), "duration": get("duration")}

    def inside_policy(self) -> dict:
        """`inside-down` (the module's private checks' policy): its aligner, window, reducer and the count it opens
        below."""
        body = self.block(self.show("infra/modules/monitoring/main.tf"),
                          'resource "google_monitoring_alert_policy" "inside_down"')
        get = lambda key: re.search(rf'^\s*{key}\s*=\s*"?([^"\n]+?)"?\s*$', body, re.M).group(1)
        assert get("comparison") == "COMPARISON_LT", get("comparison")
        return {"aligner": get("per_series_aligner"), "period": get("alignment_period"),
                "reducer": get("cross_series_reducer"), "below": int(float(get("threshold_value")))}

    def min_defaults(self, env: str) -> dict[str, int]:
        """The root's `service_min_instances` defaults (its variables.tf), by key."""
        body = self.block(self.show(f"{ROOTS[env]}/variables.tf"), 'variable "service_min_instances"')
        return {k: int(v) for k, v in re.findall(r"^\s*([a-z_]+)\s*=\s*optional\(number,\s*(\d+)\)", body, re.M)}

    def value(self, env: str, expr: str) -> int:
        """A minimum as a root writes it, with the root's defaults and every switch on (a service the environment
        runs is built): a number; `var.service_min_instances.K`; `<switch> ? A : B` (A); a `max(...)`."""
        expr = expr.strip()
        if expr.isdigit():
            return int(expr)
        m = re.fullmatch(r"var\.service_min_instances\.([a-z_]+)", expr)
        if m:
            return self.min_defaults(env)[m.group(1)]
        m = re.fullmatch(r"[^?]+\?\s*(.+?)\s*:\s*(.+)", expr)
        if m:
            return self.value(env, m.group(1))
        raise AssertionError(f"{env}: cannot read the minimum `{expr}`")

    def min_instances(self, env: str) -> dict[str, int]:
        """Each Cloud Run service's min_instances as its root sets it (the run-service module's default, 0, where
        unset), read with value()."""
        default = self.module_default("run-service", "min_instances")
        out = {}
        for m in re.finditer(r'^module "[^"]+" \{\n(.*?)^\}', self.root_text(env), re.M | re.S):
            body = m.group(1)
            if not re.search(r'^\s*source\s*=\s*"[./]*modules/run-service"', body, re.M):
                continue
            name = re.search(r'^  name\s*=\s*"([a-z0-9-]+)"', body, re.M).group(1)
            set_ = re.search(r"^  min_instances\s*=\s*(.+?)\s*$", body, re.M)
            out[name] = self.value(env, set_.group(1)) if set_ else default
        return out

    def no_instance_policies(self, env: str) -> set[str]:
        """The services the root gives the module's `<service> has no instance` policy (its warm_services), with the
        root's defaults and every switch on: a literal list, or beta's map of minimums and its call centre's
        `<switch> && <minimum> >= 1 ? ["svc"] : []` list."""
        text, out = self.root_text(env), set()
        for literal in re.findall(r"^\s*warm_services\s*=\s*\[([^\]]*)\]", text, re.M):
            out |= set(re.findall(r'"([a-z0-9-]+)"', literal))
        if "warm_services = {" in text:
            for name, expr in re.findall(r"^\s*([a-z][a-z0-9-]*)\s*=\s*(var\.[^\n]+?|\d+)\s*$",
                                         self.block(text, "warm_services = {"), re.M):
                if self.value(env, expr) >= 1:
                    out.add(name)
        if "cc_warm_services = concat(" in text:
            body = text[text.index("cc_warm_services = concat("):]
            body = body[:body.index("\n  )")]
            for cond, name in re.findall(r"^\s*(.+?)\s*\?\s*\[\"([a-z0-9-]+)\"\]\s*:\s*\[\]", body, re.M):
                minimum = re.search(r"var\.service_min_instances\.([a-z_]+)\s*>=\s*1", cond)
                if not minimum or self.min_defaults(env)[minimum.group(1)] >= 1 or "||" in cond:
                    out.add(name)
        return out

    def latency_left_out(self, env: str) -> set[str]:
        """The services the root's monitoring calls leave out of `canary-latency` (latency_excluded_services), of
        those the pages chart (as limits() reads them: beta's file-reader, D-154, has no page)."""
        return {name for line in re.findall(r"\blatency_excluded_services\s*=\s*(.+)$", self.root_text(env), re.M)
                for name in re.findall(r'"([a-z0-9-]+)"', line) if name in gen.SERVICES}

    def limits(self) -> dict:
        """LIMITS as tpa-platform's roots set them, for the services and instances the dashboards chart."""
        out = {}
        for env in ROOTS:
            built = {s: v for s, v in self.services(env).items() if s in gen.SERVICES}
            out[env] = {"max_instances": {s: v[0] for s, v in built.items()},
                        "concurrency": {s: v[1] for s, v in built.items() if v[1] != gen.DEFAULT_CONCURRENCY},
                        "ceilings": {s: n for s, n in self.ceilings(env).items() if s in gen.SERVICES},
                        "max_connections": {d: n for d, n in self.max_connections(env).items()
                                            if d in gen.DATABASES}}
        return out


INFRA, INFRA_SOURCE, CHECKOUT_PRESENT = Infra.find()
if INFRA is None and not CHECKOUT_PRESENT:
    print(f"\ntest_resources: SKIPPING the tpa-platform pins: {INFRA_SOURCE}. The lines are checked against the "
          "generator's own copy only.", file=sys.stderr)
# What the lines must be: tpa-platform's own where it can be read, else the generator's.
LIMITS = INFRA.limits() if INFRA else gen.LIMITS
LATENCY_LEFT_OUT = {env: INFRA.latency_left_out(env) for env in ROOTS} if INFRA else \
    {env: set(names) for env, names in gen.LATENCY_LEFT_OUT.items()}
SQL_POLICIES = INFRA.sql_policies() if INFRA else gen.SQL_POLICIES
CEILING_POLICY = INFRA.ceiling_policy() if INFRA else gen.CEILING_POLICY


def render(env: str) -> dict[str, dict]:
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "src", Path(tmp) / "dst"
        shutil.copytree(DASHBOARDS, src, ignore=shutil.ignore_patterns("*.md"))
        base = {k: v for k, v in os.environ.items() if not k.startswith("TPA_")}
        done = subprocess.run(["sh", str(RENDER), "--render-only", str(src), str(dst)],
                              env={**base, **ENVIRONMENTS[env]}, capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        return {p.stem: json.loads(p.read_text()) for p in dst.glob("*.json")}


RENDERED = {env: render(env) for env in ENVIRONMENTS}


# ---- Reading a page ----------------------------------------------------------------------------------------------
def sections(dashboard: dict) -> dict[str, list[dict]]:
    """Row title -> the panels under it (a shut row's are inside it)."""
    out: dict[str, list[dict]] = {}
    current = None
    for panel in dashboard["panels"]:
        if panel["type"] == "row":
            current = panel["title"]
            out[current] = list(panel.get("panels") or [])
        elif current is not None:
            out[current].append(panel)
    return out


def shut(dashboard: dict) -> dict[str, bool]:
    return {p["title"]: p["collapsed"] for p in dashboard["panels"] if p["type"] == "row"}


def resource_rows(dashboard: dict) -> dict[str, list[dict]]:
    """Service -> the panels of its Resources row."""
    return {title.split(" · ", 1)[1].split(":", 1)[0]: panels for title, panels in sections(dashboard).items()
            if title.startswith("Resources · ")}


def metric(target: dict) -> str:
    return lint.query_facts(target["timeSeriesList"])["metric"]


def filters(target: dict) -> dict[str, tuple[str, str]]:
    return {k: (op, v) for k, op, v in lint.query_facts(target["timeSeriesList"])["filters"]}


def lines(panel: dict, colour: str = "red") -> list[float]:
    """The threshold lines a panel draws in a colour (none when it draws no threshold line)."""
    defaults = panel["fieldConfig"]["defaults"]
    if defaults.get("custom", {}).get("thresholdsStyle", {}).get("mode") != "line":
        return []
    return sorted(s["value"] for s in defaults["thresholds"]["steps"] if s["value"] is not None and s["color"] == colour)


def reads(panel: dict, metric_type: str) -> bool:
    return any(metric(t) == metric_type for t in panel.get("targets") or [])


def aggregated_as(target: dict, policy: dict) -> list[str]:
    """How a query differs from the policy condition whose line its panel draws (a catalogue threshold, or the
    module's own policy as SQL_POLICIES and CEILING_POLICY hold it)."""
    tsl = target["timeSeriesList"]
    if "alignment_period" in policy:
        want = (policy["per_series_aligner"], policy["alignment_period"], policy["cross_series_reducer"])
    else:
        want = (policy["aligner"], policy["period"], policy["reducer"])
    got = (tsl.get("perSeriesAligner"), tsl.get("alignmentPeriod"), tsl.get("crossSeriesReducer"))
    return [f"{k} {g} is not the policy's {w}" for k, g, w in zip(
        ("perSeriesAligner", "alignmentPeriod", "crossSeriesReducer"), got, (want[0], "+" + want[1], want[2]))
            if g != w]


# ---- The checks --------------------------------------------------------------------------------------------------
def check_resources(page: str, dashboard: dict, env: str) -> list[str]:
    """The page's Resources rows: one per service it covers, each reading every primitive of that service alone on
    the project's datasource, with the lines the catalogue's and the module's policies use in this environment, and
    the instances' total aggregated as `ceiling-<service>` reads it."""
    role, services = AREAS[page] if page in AREAS else (None, None)
    rows = resource_rows(dashboard)
    problems = []
    if services is not None and set(rows) != services:
        problems.append(f"{page}: Resources rows for {sorted(rows)}, not {sorted(services)}")
    for title, is_shut in shut(dashboard).items():
        if title.startswith("Resources · ") and is_shut != (page in AREAS):
            problems.append(f"{page}: `{title}` is {'shut' if is_shut else 'open'}; the area pages shut it, a "
                            "service's own page opens it")
    limits = LIMITS[env]
    for service, panels in rows.items():
        where = f"{env} {page}: Resources · {service}"
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
            if lines(panel) != [policy["threshold_value"]]:
                problems.append(f"{where}: {panel['title']} draws red at {lines(panel)}, not `{name}`'s "
                                f"{policy['threshold_value']}")
            p99 = next((t for t in panel["targets"] if t["aliasBy"] == "p99"), None)
            problems += [f"{where}: {panel['title']}: {d}" for d in (aggregated_as(p99, policy) if p99 else ["no p99"])]
        # Concurrency: run-concurrency-high's line where it is below the setting; the setting where it is built.
        busy = CATALOGUE.threshold("run-concurrency-high")
        built = service in limits["max_instances"]
        slots = limits["concurrency"].get(service, gen.DEFAULT_CONCURRENCY) if built else None
        panel = next((p for p in panels if reads(p, CONCURRENCY)), None)
        if panel is not None:
            want_red = [] if slots is not None and busy["threshold_value"] >= slots else [busy["threshold_value"]]
            if lines(panel) != want_red or lines(panel, GREY) != ([slots] if slots else []):
                problems.append(f"{where}: concurrency draws red {lines(panel)} and grey {lines(panel, GREY)}, not "
                                f"{want_red} and {[slots] if slots else []}")
            p99 = next((t for t in panel["targets"] if t["aliasBy"] == "p99"), None)
            problems += [f"{where}: concurrency: {d}" for d in (aggregated_as(p99, busy) if p99 else ["no p99"])]
        # Instances: the total as the ceiling policy reads it, its line, and max_instances.
        panel = next((p for p in panels if reads(p, INSTANCES)), None)
        if panel is not None:
            cap, ceiling = limits["max_instances"].get(service), limits["ceilings"].get(service)
            red = [math.ceil(CEILING_POLICY["share"] * ceiling) - 0.5] if ceiling else []
            grey = [cap] if cap is not None and cap < DEFAULT_MAX_INSTANCES and (not red or cap > red[0]) else []
            if lines(panel) != red or lines(panel, GREY) != grey:
                problems.append(f"{where}: instances draw red {lines(panel)} and grey {lines(panel, GREY)}, not "
                                f"{red} (`ceiling-{service}`) and {grey} (max_instances)")
            total = [t for t in panel["targets"] if t["aliasBy"] == "total"]
            if len(total) != 1:
                problems.append(f"{where}: instances have {len(total)} total series")
            for t in total:
                problems += [f"{where}: instances' total: {d}" for d in aggregated_as(t, CEILING_POLICY)]
                if metric(t) != CEILING_POLICY["metric"] or set(filters(t)) - {"metric.type", "resource.type",
                                                                                 "resource.label.service_name"}:
                    problems.append(f"{where}: instances' total does not read every instance of {service}")
                if t["timeSeriesList"]["groupBys"] != ["resource.label.service_name"]:
                    problems.append(f"{where}: instances' total is not grouped by service, as the policy groups it")
    return problems


def check_project(page: str, dashboard: dict) -> list[str]:
    """The project's instances against the quota line, and its Cloud NAT with `nat-port-exhaustion`'s lines."""
    problems = []
    quota = CATALOGUE.threshold("run-instances-near-quota")
    panels = [p for p in lint.panels(dashboard) if p["title"] == "Instances, every service"]
    if len(panels) != 1:
        problems.append(f"{page}: {len(panels)} project instance panels")
    for panel in panels:
        if lines(panel) != [quota["threshold_value"]]:
            problems.append(f"{page}: the project's instances draw red at {lines(panel)}, not "
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
        if lines(panel) != [policy["threshold_value"]]:
            problems.append(f"{page}: {panel['title']} draws red at {lines(panel)}, not "
                            f"`nat-port-exhaustion`'s {policy['threshold_value']}")
        paged = [t for t in panel["targets"] if metric(t).endswith(metric_type) and
                 filters(t).get("metric.label.reason", ("=", "OUT_OF_RESOURCES")) == ("=", "OUT_OF_RESOURCES")]
        problems += [f"{page}: {panel['title']}: {d}" for t in paged[:1] for d in aggregated_as(t, policy)]
    return problems


def check_database(name: str, page: str, dashboard: dict, env: str) -> list[str]:
    """One instance's disk space, in percent with `<name>-disk`'s line and in bytes against its size, its CPU, memory
    and connections with the module's lines (read as the module reads them), and its I/O."""
    role = DATABASE_PAGES[name][0]
    disk = CATALOGUE.threshold(f"{name}-disk", role)
    rows = {t: ps for t, ps in sections(dashboard).items() if t.startswith(f"{name} (")}
    if len(rows) != 1:
        return [f"{page}: {len(rows)} sections for {name}"]
    panels = next(iter(rows.values()))
    where = f"{env} {page}: {name}"
    problems = []
    read = {metric(t) for p in panels for t in p.get("targets") or []}
    for suffix in ("disk/utilization", "disk/bytes_used", "disk/quota", "disk/read_ops_count", "disk/write_ops_count",
                   "disk/read_bytes_count", "disk/write_bytes_count", "cpu/utilization", "memory/utilization",
                   "postgresql/num_backends", "up"):
        if SQL + suffix not in read:
            problems.append(f"{where}: {suffix} is not charted")
    for p in panels:
        for t in p.get("targets") or []:
            if filters(t).get("resource.label.database_id") != ("=", f"*:{name}"):
                problems.append(f"{where}: {p['title']} does not read {name} alone")
            if t["datasource"]["uid"] != DATASOURCE[role]:
                problems.append(f"{where}: {p['title']} on {t['datasource']['uid']}")
    percent = next((p for p in panels if p["title"] == "Disk space used (%)"), None)
    if percent is None or lines(percent) != [disk["threshold_value"]]:
        problems.append(f"{where}: disk space (%) does not draw `{name}-disk`'s {disk['threshold_value']}")
    else:
        problems += [f"{where}: disk space (%): {d}" for d in aggregated_as(percent["targets"][0], disk)]
    size = next((p for p in panels if reads(p, SQL + "disk/quota")), None)
    factors = [c["options"]["binary"]["right"]["fixed"] for c in (size or {}).get("transformations", [])
               if c["id"] == "calculateField"]
    if factors != [f"{disk['threshold_value']:g}"]:
        problems.append(f"{where}: the bytes panel's alert line is {factors} of the size, not "
                        f"`{name}-disk`'s {disk['threshold_value']}")
    cap = LIMITS[env]["max_connections"].get(name)
    for title, policies, grey in (
            ("CPU", ("cpu-high", "cpu-saturated"), []), ("Memory", ("memory-high",), []),
            ("Connections", ("connections-high", "connections-saturated"), [cap] if cap else [])):
        panel = next((p for p in panels if p["title"] == title), None)
        if panel is None:
            problems.append(f"{where}: no {title} panel")
            continue
        want = sorted(SQL_POLICIES[n]["value"] if "value" in SQL_POLICIES[n] else
                      math.floor(SQL_POLICIES[n]["share"] * cap) for n in policies if cap or "value" in SQL_POLICIES[n])
        if lines(panel) != want or lines(panel, GREY) != grey:
            problems.append(f"{where}: {title} draws red {lines(panel)} and grey {lines(panel, GREY)}, not the "
                            f"module's {want} and {grey}")
        problems += [f"{where}: {title}: {d}" for d in aggregated_as(panel["targets"][0], SQL_POLICIES[policies[0]])]
    return problems


def check_overview_databases(overview: dict, env: str) -> list[str]:
    """The overview's Databases tiles, one per instance the environment has, colour CPU and memory at the module's
    lines (connections are on Databases)."""
    problems = []
    tiles = sections(overview).get("Databases: up, CPU, memory, disk", [])
    want_names = [db for db in gen.DATABASES if db in LIMITS[env]["max_connections"] or db == "cc-db" and env == "beta"]
    if sorted(p["title"] for p in tiles) != sorted(want_names):
        problems.append(f"{env} overview: database tiles {sorted(p['title'] for p in tiles)}, not {sorted(want_names)}")
    for name, steps in ((p["title"], {o["matcher"]["options"]: next(
            (x["value"]["steps"] for x in o["properties"] if x["id"] == "thresholds"), None)
            for o in p["fieldConfig"]["overrides"]}) for p in tiles):
        want = {"B": [SQL_POLICIES["cpu-high"]["value"], SQL_POLICIES["cpu-saturated"]["value"]],
                "C": [SQL_POLICIES["memory-high"]["value"]]}
        for ref, values in want.items():
            got = [s["value"] for s in steps[ref] if s["value"] is not None and s["color"] != "transparent"]
            if got != values:
                problems.append(f"{env} overview: {name}'s {ref} tile colours at {got}, not the module's {values}")
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


# A service's own request line: its log metric and the catalogue policy (and role) that reads it. The pages that chart
# it: its area's page and its own.
OWN_LATENCY = {"tpa-api": ("tpa_api_latency", "tpa-api-latency", "app", "portal-api"),
               "engine": ("engine_latency", "engine-latency", "crm", "crm")}


def check_own_latency(page: str, dashboard: dict, service: str) -> list[str]:
    """The service's p95 and p50 from its own request line, on its project's datasource, aggregated as its policy
    reads it, with the policy's line."""
    metric_name, name, role, _area = OWN_LATENCY[service]
    policy = CATALOGUE.threshold(name, role)
    panels = [p for p in lint.panels(dashboard) if reads(p, LOG + metric_name)]
    if len(panels) != 1:
        return [f"{page}: {len(panels)} panels read `{metric_name}`"]
    panel, problems = panels[0], []
    by_alias = {t["aliasBy"]: t for t in panel["targets"]}
    if set(by_alias) != {"p95", "p50"}:
        problems.append(f"{page}: {service}'s own latency shows {sorted(by_alias)}, not p95 and p50")
    if lines(panel) != [policy["threshold_value"]]:
        problems.append(f"{page}: {service}'s own latency draws red at {lines(panel)}, not `{name}`'s "
                        f"{policy['threshold_value']}")
    if "p95" in by_alias:
        problems += [f"{page}: {service}'s own p95: {d}" for d in aggregated_as(by_alias["p95"], policy)]
    if {t["datasource"]["uid"] for t in panel["targets"]} != {DATASOURCE[role]}:
        problems.append(f"{page}: {service}'s own latency is not on {DATASOURCE[role]}")
    return problems


def check_cloud_run_p95(page: str, dashboard: dict, service: str, env: str) -> list[str]:
    """A service page's Cloud Run p95: `canary-latency`'s line where it reads the service, none where the root leaves
    it out, and, for a service holding streams open, a title that says the p95 includes them."""
    panel = next((p for p in dashboard["panels"] if p["title"].startswith("p95 latency (Cloud Run")), None)
    if panel is None:
        return [f"{page}: no Cloud Run p95"]
    want = [] if service in LATENCY_LEFT_OUT[env] else [2000]
    problems = [] if lines(panel) == want else [f"{env} {page}: Cloud Run p95 draws red at {lines(panel)}, not {want}"]
    if service in LATENCY_LEFT_OUT[env] and ("with its streams" not in panel["title"]
                                             or "includes its streams" not in panel["description"]):
        problems.append(f"{env} {page}: the Cloud Run p95 does not say it includes {service}'s streams")
    return problems


NOTE = "Cloud Run services have no disk"


def area_pages(env: str):
    return [page for page in AREAS if page in RENDERED[env]]


def service_pages(env: str):
    return [(page, s) for page, (_r, ss) in AREAS.items() for s in sorted(ss) if f"service-{s}" in RENDERED[env]]


class SourceTest(unittest.TestCase):
    """The generator's copies of tpa-platform's limits and module policies are tpa-platform's own."""

    def setUp(self):
        if INFRA is None and CHECKOUT_PRESENT:
            self.fail(INFRA_SOURCE)
        if INFRA is None:
            self.skipTest(f"SKIPPED LOUDLY: {INFRA_SOURCE}; the generator's limits are not checked against "
                          "tpa-platform")

    def test_each_environments_limits_are_its_terraforms(self):
        self.assertEqual(gen.LIMITS, INFRA.limits(), f"scripts/cloud_dashboards.py LIMITS differs from {INFRA_SOURCE}")

    def test_the_latency_exclusions_are_each_roots(self):
        for env in ROOTS:
            self.assertEqual(set(gen.LATENCY_LEFT_OUT[env]), INFRA.latency_left_out(env), env)

    def test_the_module_policies_are_the_modules(self):
        self.assertEqual(gen.SQL_POLICIES, INFRA.sql_policies())
        self.assertEqual(gen.CEILING_POLICY, INFRA.ceiling_policy())

    def test_the_reader_reads_what_it_should(self):
        # Known facts at the pinned commit, so a reader that silently reads nothing fails here.
        self.assertEqual(INFRA.services("beta")["svc-voice"], (1, 20))
        self.assertEqual(INFRA.services("production")["records"], (DEFAULT_MAX_INSTANCES, 80))
        self.assertIn("records", INFRA.ceilings("beta"))
        self.assertNotIn("records", INFRA.ceilings("production"))
        self.assertEqual(INFRA.max_connections("beta")["auth-db"], 100)


class PinGateTest(unittest.TestCase):
    """No checkout: the pins skip. A checkout without the pinned commit: the pins fail, with the fetch to run."""

    def test_no_checkout_is_a_skip(self):
        infra, why, present = Infra.find(Path(tempfile.gettempdir()) / "no-such-tpa-platform")
        self.assertEqual((infra, present), (None, False))
        self.assertIn("no tpa-platform checkout", why)

    def test_a_checkout_without_the_pinned_commit_is_a_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            infra, why, present = Infra.find(Path(tmp))
        self.assertEqual((infra, present), (None, True))
        self.assertIn(f"lacks the catalogue's pinned commit {cat.source()['commit'][:8]}", why)
        self.assertIn("fetch origin", why)


class ResourcesTest(unittest.TestCase):
    def test_the_areas_cover_every_cloud_run_service(self):
        covered = set().union(*(services for _role, services in AREAS.values()))
        self.assertEqual(covered, set().union(*(n["service_name"] for n in NAMES.values())))
        self.assertEqual(covered, set(gen.SERVICES))
        for page, (role, services) in AREAS.items():
            self.assertLessEqual(services, NAMES[role]["service_name"], page)

    def test_both_environments_render(self):
        self.assertIn("service-svc-voice", RENDERED["beta"])
        self.assertNotIn("service-svc-voice", RENDERED["production"])
        for env, pages in RENDERED.items():
            self.assertNotIn("@@", json.dumps(pages), env)

    def test_every_area_page_has_each_services_resources(self):
        for env in RENDERED:
            for page in area_pages(env):
                self.assertEqual(check_resources(page, RENDERED[env][page], env), [], (env, page))

    def test_production_draws_no_line_from_betas_terraform(self):
        # records: beta's ceiling (16 instances for ten minutes) and max_instances 20; production keeps Cloud Run's
        # default and has no `ceiling-records`, so nothing is drawn there.
        for env, red, grey in (("beta", [15.5], [20]), ("production", [], [])):
            row = resource_rows(RENDERED[env]["service-records"])["records"]
            panel = next(p for p in row if reads(p, INSTANCES))
            self.assertEqual((lines(panel), lines(panel, GREY)), (red, grey), env)
        # auth's ceiling is the same in both.
        for env in RENDERED:
            panel = next(p for p in resource_rows(RENDERED[env]["service-auth"])["auth"] if reads(p, INSTANCES))
            self.assertEqual((lines(panel), lines(panel, GREY)), ([15.5], [20]), env)

    def test_each_own_request_line_on_its_area_and_its_own_page(self):
        for env in RENDERED:
            for service, (_m, _n, _r, area) in OWN_LATENCY.items():
                for page in (area, f"service-{service}"):
                    self.assertEqual(check_own_latency(page, RENDERED[env][page], service), [], (env, page))

    def test_the_engines_cloud_run_p95_says_it_includes_its_streams(self):
        crm = next(p for p in RENDERED["beta"]["crm"]["panels"] if p["title"].startswith("p95 latency, by service"))
        self.assertIn("with its streams", crm["title"])
        self.assertIn("300 s", crm["description"])
        for env in RENDERED:
            own = RENDERED[env]["service-engine"]
            panel = next(p for p in own["panels"] if p["title"].startswith("p95 latency (Cloud Run"))
            self.assertIn("300 s", panel["description"], env)
            self.assertEqual(panel["title"], "p95 latency (Cloud Run, with its streams)")

    def test_each_service_pages_cloud_run_p95(self):
        for env in RENDERED:
            for _page, service in service_pages(env):
                self.assertEqual(check_cloud_run_p95(f"service-{service}", RENDERED[env][f"service-{service}"],
                                                     service, env), [], (env, service))

    def test_every_page_says_a_service_has_no_disk(self):
        for env in RENDERED:
            for page in [*area_pages(env), *(f"service-{s}" for _p, s in service_pages(env))]:
                self.assertIn(NOTE, json.dumps(RENDERED[env][page]), (env, page))

    def test_projects_quota_and_cloud_nat(self):
        for env in RENDERED:
            for page in ("portal-api", "records", "callcentre", "crm"):
                if page in RENDERED[env]:
                    self.assertEqual(check_project(page, RENDERED[env][page]), [], (env, page))

    def test_the_nat_condition_reads_the_reason_the_dashboard_filters(self):
        self.assertIn('metric.labels.reason = "OUT_OF_RESOURCES"', CATALOGUE.text)

    def test_the_phi_projects_buckets(self):
        panels = [p for p in lint.panels(RENDERED["beta"]["records"]) if any(
            metric(t).startswith("storage.googleapis.com/") for t in p.get("targets") or [])]
        self.assertEqual({metric(t) for p in panels for t in p["targets"]},
                         {"storage.googleapis.com/storage/total_bytes", "storage.googleapis.com/storage/object_count"})
        for p in panels:
            for t in p["targets"]:
                self.assertEqual(t["timeSeriesList"]["groupBys"], ["resource.label.bucket_name"])

    def test_every_database_on_the_databases_page_and_its_owners(self):
        for env, pages in RENDERED.items():
            for name, (_role, owner) in DATABASE_PAGES.items():
                for page in ("databases", owner):
                    if owner in pages and f"{name} (" in json.dumps([p["title"] for p in pages[page]["panels"]]):
                        self.assertEqual(check_database(name, page, pages[page], env), [], (env, name, page))
            self.assertEqual(check_overview_databases(pages["overview"], env), [], env)
        self.assertNotIn("cc-db (", json.dumps(RENDERED["production"]["databases"]))

    def test_the_jobs_page_shows_each_projects_task_resources(self):
        self.assertEqual(check_jobs(RENDERED["beta"]["jobs"]), [])
        self.assertEqual(check_jobs(RENDERED["production"]["jobs"], ("cloud-app", "cloud-phi", "cloud-crm")), [])

    def test_every_service_has_its_own_page_with_the_same_resources_row(self):
        strip = lambda ps: [{k: v for k, v in p.items() if k not in ("links", "gridPos", "id")} for p in ps]
        for env in RENDERED:
            for page, service in service_pages(env):
                own = RENDERED[env][f"service-{service}"]
                self.assertEqual(own["uid"], f"tw-cloud-service-{service}")
                self.assertIn("cloud-service", own["tags"])
                self.assertNotIn("cloud", own["tags"], "the Pages menu lists the area pages alone")
                self.assertEqual(check_resources(f"service-{service}", own, env), [])
                self.assertEqual(list(resource_rows(own)), [service])
                self.assertEqual(strip(resource_rows(own)[service]),
                                 strip(resource_rows(RENDERED[env][page])[service]), (env, service))
                # The way back: the area's page, by the menu and by the row's first panel.
                self.assertIn(f"/d/tw-cloud-{page}", json.dumps(own["links"]))
        self.assertEqual(sorted(p.stem for p in DASHBOARDS.glob("service-*.json")),
                         sorted(f"service-{s}" for s in gen.SERVICES))

    def test_every_service_page_is_linked(self):
        for env, pages in RENDERED.items():
            overview = json.dumps([p.get("links", []) for p in lint.panels(pages["overview"])])
            for page, service in service_pages(env):
                url = f"/d/tw-cloud-service-{service}?"
                # The overview tiles the services the environment runs, each linking its own page.
                self.assertEqual(url in overview, service in gen.RUNS[env], f"{env}: {service}'s page and the overview")
                self.assertIn(url, json.dumps(resource_rows(pages[page])[service][0].get("links")), (env, service))
            for name, dashboard in pages.items():
                menus = [link for link in dashboard["links"] if link["title"] == "Services"]
                self.assertEqual([(m["type"], m["tags"], m["asDropdown"]) for m in menus],
                                 [("dashboards", ["cloud-service"], True)], (env, name))
        self.assertNotIn("/d/tw-cloud-service-svc-voice?", json.dumps(RENDERED["production"]["overview"]))


class MutationTest(unittest.TestCase):
    """The checks catch a page that loses a service's row or its instances' total, a line moved off its source, or a
    window that is not the policy's."""

    def page(self, name, env="beta"):
        return copy.deepcopy(RENDERED[env][name])

    @staticmethod
    def steps(panel):
        return panel["fieldConfig"]["defaults"]["thresholds"]["steps"]

    def test_a_missing_resources_row(self):
        page = self.page("portal-api")
        page["panels"] = [p for p in page["panels"] if not p["title"].startswith("Resources · tpa-api")]
        self.assertIn("portal-api: Resources rows for ['model-gateway', 'tpa-jobs-drains', 'watchtower', 'web'], not "
                      "['model-gateway', 'tpa-api', 'tpa-jobs-drains', 'watchtower', 'web']",
                      check_resources("portal-api", page, "beta"))

    def test_an_open_row_on_an_area_page(self):
        page = self.page("sign-in")
        next(p for p in page["panels"] if p["title"].startswith("Resources · auth:"))["collapsed"] = False
        self.assertTrue(any("is open" in p for p in check_resources("sign-in", page, "beta")))

    def test_a_cpu_line_off_the_catalogue(self):
        page = self.page("sign-in")
        cpu = next(p for p in resource_rows(page)["auth"] if reads(p, CPU))
        self.steps(cpu)[1]["value"] = 0.8
        self.assertEqual(check_resources("sign-in", page, "beta"),
                         ["beta sign-in: Resources · auth: CPU (p99, p95, p50) draws red at [0.8], not "
                          "`run-cpu-high`'s 0.9"])

    def test_a_memory_window_that_is_not_the_policys(self):
        page = self.page("records")
        memory = next(p for p in resource_rows(page)["records"] if reads(p, MEMORY))
        memory["targets"][0]["timeSeriesList"]["alignmentPeriod"] = "grafana-auto"
        self.assertEqual(check_resources("records", page, "beta"),
                         ["beta records: Resources · records: Memory (p99, p95, p50): alignmentPeriod grafana-auto "
                          "is not the policy's +300s"])

    def test_a_query_reading_another_service(self):
        page = self.page("crm")
        resource_rows(page)["engine"][2]["targets"][0]["timeSeriesList"]["filters"][-1] = "crm-web"
        self.assertTrue(any("does not read engine alone" in p for p in check_resources("crm", page, "beta")))

    def test_the_ceiling_line_drawn_at_max_instances(self):
        page = self.page("service-records")
        panel = next(p for p in resource_rows(page)["records"] if reads(p, INSTANCES))
        next(s for s in self.steps(panel) if s["color"] == "red")["value"] = 20
        self.assertTrue(any("instances draw red [20]" in p for p in check_resources("service-records", page, "beta")))

    def test_instances_without_the_total_the_ceiling_reads(self):
        page = self.page("service-auth", "production")
        panel = next(p for p in resource_rows(page)["auth"] if reads(p, INSTANCES))
        panel["targets"] = [t for t in panel["targets"] if t["aliasBy"] != "total"]
        self.assertTrue(any("0 total series" in p for p in check_resources("service-auth", page, "production")))

    def test_the_total_aggregated_otherwise(self):
        page = self.page("service-auth")
        panel = next(p for p in resource_rows(page)["auth"] if reads(p, INSTANCES))
        next(t for t in panel["targets"] if t["aliasBy"] == "total")["timeSeriesList"]["alignmentPeriod"] = "grafana-auto"
        self.assertTrue(any("instances' total: alignmentPeriod grafana-auto" in p
                            for p in check_resources("service-auth", page, "beta")))

    def test_betas_ceiling_in_production(self):
        page = self.page("service-records", "production")
        panel = next(p for p in resource_rows(page)["records"] if reads(p, INSTANCES))
        panel["fieldConfig"]["defaults"]["custom"]["thresholdsStyle"]["mode"] = "line"
        self.steps(panel)[1].update(color="red", value=15.5)
        self.assertTrue(any("instances draw red [15.5]" in p
                            for p in check_resources("service-records", page, "production")))

    def test_a_disk_line_off_the_catalogue(self):
        page = self.page("databases")
        for p in sections(page)[next(t for t in sections(page) if t.startswith("tpa-db ("))]:
            if p["title"] == "Disk space used (%)":
                self.steps(p)[1]["value"] = 0.9
        self.assertEqual(check_database("tpa-db", "databases", page, "beta"),
                         ["beta databases: tpa-db: disk space (%) does not draw `tpa-db-disk`'s 0.85"])

    def test_a_database_cpu_line_off_the_module(self):
        page = self.page("sign-in")
        cpu = next(p for p in sections(page)[next(t for t in sections(page) if t.startswith("auth-db ("))]
                   if p["title"] == "CPU")
        self.steps(cpu)[1]["value"] = 0.7
        self.assertTrue(any("CPU draws red [0.7, 0.95]" in p for p in check_database("auth-db", "sign-in", page, "beta")))

    def test_connections_at_75_percent(self):
        page = self.page("databases", "production")
        panel = next(p for p in sections(page)[next(t for t in sections(page) if t.startswith("auth-db ("))]
                     if p["title"] == "Connections")
        self.steps(panel)[1]["value"] = 375
        self.assertTrue(any("Connections draws red [375, 475]" in p
                            for p in check_database("auth-db", "databases", page, "production")))

    def test_connections_on_grafanas_window(self):
        page = self.page("crm")
        panel = next(p for p in sections(page)[next(t for t in sections(page) if t.startswith("crm-db ("))]
                     if p["title"] == "Connections")
        panel["targets"][0]["timeSeriesList"]["alignmentPeriod"] = "grafana-auto"
        self.assertTrue(any("Connections: alignmentPeriod grafana-auto is not the policy's +60s" in p
                            for p in check_database("crm-db", "crm", page, "beta")))

    def test_the_engines_own_line_off_the_catalogue(self):
        page = self.page("crm")
        panel = next(p for p in page["panels"] if p["title"] == "engine p50, p95 (own request line)")
        self.steps(panel)[1]["value"] = 4000
        self.assertEqual(check_own_latency("crm", page, "engine"),
                         ["crm: engine's own latency draws red at [4000], not `engine-latency`'s 2000.0"])

    def test_the_engines_own_p95_on_grafanas_window(self):
        page = self.page("service-engine", "production")
        panel = next(p for p in page["panels"] if p["title"] == "engine p50, p95 (own request line)")
        next(t for t in panel["targets"] if t["aliasBy"] == "p95")["timeSeriesList"]["alignmentPeriod"] = "grafana-auto"
        self.assertEqual(check_own_latency("service-engine", page, "engine"),
                         ["service-engine: engine's own p95: alignmentPeriod grafana-auto is not the policy's +300s"])

    def test_a_canary_line_on_a_service_it_leaves_out(self):
        page = self.page("service-engine")
        panel = next(p for p in page["panels"] if p["title"].startswith("p95 latency (Cloud Run"))
        panel["fieldConfig"]["defaults"]["custom"]["thresholdsStyle"]["mode"] = "line"
        self.steps(panel).append({"color": "red", "value": 2000})
        self.assertEqual(check_cloud_run_p95("service-engine", page, "engine", "beta"),
                         ["beta service-engine: Cloud Run p95 draws red at [2000], not []"])

    def test_a_nat_drop_line_off_the_catalogue(self):
        page = self.page("portal-api")
        for p in page["panels"]:
            if p["title"] == "NAT dropped packets":
                self.steps(p)[1]["value"] = 100
        self.assertEqual(check_project("portal-api", page),
                         ["portal-api: NAT dropped packets draws red at [100], not `nat-port-exhaustion`'s 10.0"])


if __name__ == "__main__":
    unittest.main()
