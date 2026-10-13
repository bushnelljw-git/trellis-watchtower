#!/usr/bin/env python3
"""Write the cloud dashboards (cloud/dashboards/*.json) for the production Grafana image. Standard library only.

The dashboards are generated so that nine pages share one layout, one legend style and one way of writing each
query; edit this file, run it, and commit both. `make lint` runs it with --check, so a hand edit of the JSON fails.

Every query is Cloud Monitoring's filter form (Grafana's "Builder": a metric type, label filters, an aligner, a
reducer and the labels to group by), the shape tpa-platform's catalogue writes its own threshold policies in
(infra/monitoring.yml, vendored in cloud/catalogue/). Not PromQL: Grafana 12.4's Cloud Monitoring datasource turns a
failed PromQL request into an empty answer, so a broken panel would read as zero; the filter form shows the error.
Not MQL: Google has deprecated it. Every metric a query names is checked against the catalogue
(tests/cloud/test_catalogue.py) and every label against the allowlist (scripts/dashboard_lint.py). Each query names
its datasource's project as a placeholder, which the image fills in at start (cloud/render-dashboards.sh).

The image also settles three things at start, from the service's environment, so that one image serves every
environment: tiles of a sweep that is paused (TPA_PAUSED_JOBS) or of a database that is stopped
(TPA_STOPPED_DATABASES) read neutral "paused" or "database stopped" instead of red; the uptime tile's wording
(TPA_ENVIRONMENT), and the limits each environment's Terraform sets (a service's max_instances, its ceiling policy, a
database's max_connections: LIMITS); and, with no call-centre project (TPA_CC_PROJECT_ID empty, production-full), the
variants in cloud/dashboards/no-cc/ replace the pages that have a call-centre part, and the pages that read the call
centre alone are left out. Each such string is a token, `@@R,deps,@@normal@@`, `@@F,deps,@@quiet@@normal@@`,
`@@E@@production@@beta@@`, or, for a number, `"@@N@@production@@beta@@"` (its quotes go with it), that the render step
resolves (when_quiet, per_environment, per_env_number below).

Usage:
  scripts/cloud_dashboards.py           write cloud/dashboards/*.json
  scripts/cloud_dashboards.py --check   exit 1 when a committed dashboard differs from what this writes
"""

from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "cloud" / "dashboards"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalogue import Catalogue  # noqa: E402
from dashboard_lint import RESOURCE_LABELS, cloud_datasources, project_placeholder  # noqa: E402

PROJECT = {uid: project_placeholder(var) for uid, var in cloud_datasources().items()}
APP, CRM, PHI, CC = "cloud-app", "cloud-crm", "cloud-phi", "cloud-cc"

# ---- Names, from tpa-platform's beta roots (infra/envs/beta/{main,crm,callcentre}.tf) and its catalogue ----------
WEB_API = "web|tpa-api|model-gateway"           # the app tier's request services; model-gateway when it is built
APP_SERVICES = "web|tpa-api|model-gateway|tpa-jobs-drains"
AUTH_SERVICES = "auth|auth-outbox-publisher"
AUTH_JOBS = "migrate-auth|auth-.*"
TPA_JOBS = "tpa-jobs-.*"
PHI_SERVICES = "records|connectors"
PHI_JOBS = "migrate-tpa|seed-tpa|tpa-db-export|restore-drill|records-chain-head"
CRM_SERVICES = "crm-web|engine"
CRM_JOBS = "migrate-crm|seed-crm"
CC_SERVICES = "svc-voice|svc-ops|svc-twilio-rest"
TPA_SCHEDULES = "erisa-clocks|nightly-anomalies|stoploss-surveillance|accumulator-reconcile|workload-audit|member-access"
AUTH_SCHEDULES = "auth-.*"
PHI_SCHEDULES = "tpa-db-export|records-chain-head|restore-drill"
# What TPA_PAUSED_JOBS and TPA_STOPPED_DATABASES may name (render-dashboards.sh refuses anything else; the render
# test holds its lists to these): the sweeps tpa-platform's beta can pause (var.tpa_jobs_paused, keys of
# local.sweeps) and the four Cloud SQL instances (local.database_stopped, auth_db as auth-db).
SWEEPS = ("erisa-clocks", "nightly-anomalies", "stoploss-surveillance", "accumulator-reconcile", "workload-audit",
          "member-access")
DATABASES = ("auth-db", "tpa-db", "crm-db", "cc-db")
SWEEP_DBS = ("auth-db", "tpa-db")   # a sweep's run needs auth (its token) and records (tpa-db)
# Each scheduled job's missed-run deadline in minutes (beta's terraform.tfvars.example `missed_run_after`, about one
# and a half times its cadence; docs/infra/monitoring.md §5), and what it needs to run: its sweep's name while it can
# be paused, and the databases it reads (tpa-platform's database_dependent_jobs). The monthly verify and the
# quarterly drill have none.
DEADLINES = [(APP, "auth-publisher", 3, ("auth-db",)),
             (APP, "tpa-jobs-erisa-clocks", 23, ("erisa-clocks", *SWEEP_DBS)),
             (APP, "tpa-jobs-nightly-anomalies", 90, ("nightly-anomalies", *SWEEP_DBS)),
             (APP, "auth-sweeper", 90, ("auth-db",)),
             (APP, "tpa-jobs-stoploss-surveillance", 2160, ("stoploss-surveillance", *SWEEP_DBS)),
             (APP, "tpa-jobs-accumulator-reconcile", 2160, ("accumulator-reconcile", *SWEEP_DBS)),
             (APP, "tpa-jobs-workload-audit", 2160, ("workload-audit", *SWEEP_DBS)),
             (APP, "tpa-jobs-member-access", 2160, ("member-access", *SWEEP_DBS)),
             (APP, "auth-audit-head", 2160, ("auth-db",)), (APP, "auth-audit-verify", 2160, ("auth-db",)),
             (PHI, "tpa-db-export", 2160, ("tpa-db",)), (PHI, "records-chain-head", 2160, ("tpa-db",))]
# Cloud Run's job metrics can reach Cloud Monitoring up to 180 s after the run, so a deadline tile looks back its
# deadline plus this, or a run on time would read MISSED for up to three minutes.
METRIC_DELAY_MINUTES = 3

CATALOGUE = Catalogue()
# The CRM's error class is grouped only while the catalogue's extractor for it is anchored. On 2026-10-11 it is not
# ("...\nfor Jane Doe" gives class "Doe"), and tpa-platform is asked to anchor it as the call centre's is. Re-vendoring
# an anchored catalogue and running this brings the class back; tests/cloud/test_catalogue.py refuses it until then.
CRM_ERROR_LABELS = ("service_name",) + (() if "class" in CATALOGUE.unanchored_labels("crm", "errors") else ("class",))
CRM_CLASS = "class" in CRM_ERROR_LABELS
CRM_CLASS_NOTE = ("" if CRM_CLASS else " By service only: the catalogue's CRM class extractor is not "
                  "anchored, so its class could be a word out of free text (until tpa-platform anchors it).")

RUN_REQUESTS = "run.googleapis.com/request_count"
RUN_LATENCY = "run.googleapis.com/request_latencies"
RUN_INSTANCES = "run.googleapis.com/container/instance_count"
RUN_JOBS = "run.googleapis.com/job/completed_execution_count"
SQL_UP = "cloudsql.googleapis.com/database/up"
SQL_DISK = "cloudsql.googleapis.com/database/disk/utilization"
SQL_CPU = "cloudsql.googleapis.com/database/cpu/utilization"
SQL_MEMORY = "cloudsql.googleapis.com/database/memory/utilization"
SQL_BACKENDS = "cloudsql.googleapis.com/database/postgresql/num_backends"
UPTIME = "monitoring.googleapis.com/uptime_check/check_passed"
# Each Cloud Run service's and job's resource primitives (Google's own, per container; "Resources" below).
RUN_CPU = "run.googleapis.com/container/cpu/utilizations"
RUN_MEMORY = "run.googleapis.com/container/memory/utilizations"
RUN_CONCURRENCY = "run.googleapis.com/container/max_request_concurrencies"
RUN_STARTUP = "run.googleapis.com/container/startup_latencies"
RUN_BILLABLE = "run.googleapis.com/container/billable_instance_time"
RUN_TASKS = "run.googleapis.com/job/completed_task_attempt_count"
RUN_TASKS_RUNNING = "run.googleapis.com/job/running_task_attempts"
SQL_DISK_BYTES = "cloudsql.googleapis.com/database/disk/bytes_used"
SQL_DISK_SIZE = "cloudsql.googleapis.com/database/disk/quota"
SQL_READ_OPS = "cloudsql.googleapis.com/database/disk/read_ops_count"
SQL_WRITE_OPS = "cloudsql.googleapis.com/database/disk/write_ops_count"
SQL_READ_BYTES = "cloudsql.googleapis.com/database/disk/read_bytes_count"
SQL_WRITE_BYTES = "cloudsql.googleapis.com/database/disk/write_bytes_count"
NAT_PORTS = "router.googleapis.com/nat/allocated_ports"
NAT_PORTS_USED = "router.googleapis.com/nat/port_usage"
NAT_CONNECTIONS = "router.googleapis.com/nat/new_connections_count"
NAT_DROPPED_SENT = "router.googleapis.com/nat/dropped_sent_packets_count"
NAT_DROPPED_RECEIVED = "router.googleapis.com/nat/dropped_received_packets_count"
NAT_FAILED = "router.googleapis.com/nat/nat_allocation_failed"
GCS_BYTES = "storage.googleapis.com/storage/total_bytes"
GCS_OBJECTS = "storage.googleapis.com/storage/object_count"
REV, JOB, SQL, URL, SCHED, AUDITED = ("cloud_run_revision", "cloud_run_job", "cloudsql_database", "uptime_url",
                                      "cloud_scheduler_job", "audited_resource")
NAT, BUCKET = "nat_gateway", "gcs_bucket"
PRIVATE = "servicedirectory_service"   # a private uptime check (D-149: auth's and tpa-api's /ready, from inside)
# The home's status colours, as on the local home page: up is teal, not green (green and red sit 4.1 apart for a
# deuteranope, teal and red 13+); red for a failure, amber for "look", and the base text colour for no answer.
TEAL, RED, AMBER = "#14b8a6", "#d03b3b", "#fab219"
# Each synthetic journey's Cloud Run job (tpa-platform infra/envs/beta/synthetics.tf, local.synthetic_journeys) and
# what it proves.
JOURNEYS = (("synthetics-staff-sign-in", "J1 staff sign-in", "the portal, auth and a desk read that reaches tpa-db"),
            ("synthetics-ops-desk", "J2 ops desk", "the ops host, auth and the live queue in svc-ops"),
            ("synthetics-crm", "J3 CRM sign-in", "the CRM's own sign-in"))
AUTO = "grafana-auto"   # one aligned point per panel interval (at least the panel's 1m)


def log(name: str) -> str:
    """A log-based metric's Cloud Monitoring type."""
    return f"logging.googleapis.com/user/{name}"


def label(name: str) -> str:
    """A label as the filter form names it: a resource label or a metric label."""
    return f"resource.label.{name}" if name in RESOURCE_LABELS else f"metric.label.{name}"


def alias(*names: str, prefix: str = "") -> str:
    return prefix + " ".join("{{" + label(n) + "}}" for n in names)


class Re(str):
    """A regular-expression filter value (=~, Cloud Monitoring's monitoring.regex.full_match)."""


def q(metric: str, resource: str | None = None, *, align: str = "ALIGN_DELTA", period: str = AUTO,
      reduce: str = "REDUCE_SUM", by: tuple[str, ...] = (), name: str | None = None, groups: bool = False,
      **where) -> dict:
    """One filter-form query. `where` filters by label (a Re value matches a regular expression; a value holding
    `*` is Cloud Monitoring's starts_with/ends_with). `groups` adds a second aggregation that counts the series the
    first one leaves, one per group."""
    filters = ["metric.type", "=", metric]
    if resource:
        filters += ["AND", "resource.type", "=", resource]
    for key, value in where.items():
        filters += ["AND", label(key), "=~" if isinstance(value, Re) else "=", str(value)]
    tsl = {"filters": filters, "groupBys": [label(b) for b in by], "crossSeriesReducer": reduce,
           "perSeriesAligner": align, "alignmentPeriod": period, "view": "FULL", "preprocessor": "none"}
    if groups:
        tsl.update({"secondaryCrossSeriesReducer": "REDUCE_COUNT", "secondaryPerSeriesAligner": "ALIGN_SUM",
                    "secondaryAlignmentPeriod": period, "secondaryGroupBys": []})
    return {"tsl": tsl, "alias": name if name is not None else alias(*by)}


# ---- Queries used on more than one page ----------------------------------------------------------------------------
def requests(services, period=AUTO, by=("service_name",), **extra):
    return q(RUN_REQUESTS, REV, period=period, by=by, service_name=Re(services), **extra)


def five_xx(services, period=AUTO):
    return requests(services, period, response_code_class="5xx")


def p95(services, period=AUTO):
    """Cloud Run's p95 by service: its revisions' distributions merged, then the 95th percentile, as `canary-latency`
    (histogram_quantile over the buckets summed by service) reads it."""
    return q(RUN_LATENCY, REV, align="ALIGN_DELTA", period=period, reduce="REDUCE_PERCENTILE_95",
             by=("service_name",), service_name=Re(services))


def tpa_api_p95(period=AUTO):
    """tpa-api's own p95 (its request line), read as `tpa-api-latency` reads it."""
    return q(log("tpa_api_latency"), REV, align="ALIGN_PERCENTILE_95", period=period, reduce="REDUCE_MAX",
             by=("service_name",))


def instances(services, period=AUTO):
    return q(RUN_INSTANCES, REV, align="ALIGN_MAX", period=period, by=("service_name",), service_name=Re(services))


def executions(jobs=None, result=None, period=AUTO, by=("job_name", "result"), name=None):
    where = {}
    if jobs:
        where["job_name"] = Re(jobs)
    if result:
        where["result"] = result
    return q(RUN_JOBS, JOB, period=period, by=by, name=name, **where)


def schedule_failures(schedules=None, period=AUTO, by=("job_id", "code"), name=None):
    where = {"job_id": Re(schedules)} if schedules else {}
    return q(log("scheduler_failures"), SCHED, period=period, by=by, name=name, **where)


def db_up(instance, period=AUTO):
    return q(SQL_UP, SQL, align="ALIGN_MIN", period=period, reduce="REDUCE_MIN", by=("database_id",),
             name=f"{instance} up", database_id=f"*:{instance}")


def db_disk(instance, period=AUTO):
    return q(SQL_DISK, SQL, align="ALIGN_MEAN", period=period, reduce="REDUCE_MAX", by=("database_id",),
             name=f"{instance} disk", database_id=f"*:{instance}")


def db_resource(metric, instance, unit_name, period=AUTO, align="ALIGN_MEAN", reduce="REDUCE_MAX"):
    return q(metric, SQL, align=align, period=period, reduce=reduce, by=("database_id",),
             name=f"{instance} {unit_name}", database_id=f"*:{instance}")


def error_counts(metric, labels, period=AUTO, resources=(REV, JOB), groups=False, **where):
    """An error counter by the module's error group: the Cloud Run service (or job), then the counter's labels."""
    out = []
    for resource in resources:
        who = "service_name" if resource == REV else "job_name"
        out.append(q(log(metric), resource, period=period, by=(who, *labels), groups=groups,
                     name=("in services" if resource == REV else "in jobs") if groups else None, **where))
    return out


def crm_errors(period=AUTO, by=CRM_ERROR_LABELS, groups=False):
    """The CRM's counter is `crm_errors` where the CRM shares the app project (beta, R282: a later role's colliding
    name takes its role as a prefix) and `errors` in a CRM project of its own; each query finds the other empty."""
    return [q(log("crm_errors"), REV, period=period, by=by, groups=groups, name="groups" if groups else None),
            q(log("errors"), REV, period=period, by=by, groups=groups, name="groups" if groups else None,
              service_name=Re(CRM_SERVICES))]


# ---- Panels --------------------------------------------------------------------------------------------------------
def target(ds: str, query: dict, ref: str) -> dict:
    return {"refId": ref, "datasource": {"type": "stackdriver", "uid": ds}, "queryType": "timeSeriesList",
            "timeSeriesList": {"projectName": PROJECT[ds], **query["tsl"]}, "aliasBy": query["alias"]}


def thresholds(*steps) -> dict:
    """thresholds("green", (1, "orange"), (5, "red"))"""
    base, *rest = steps
    return {"mode": "absolute", "steps": [{"color": base, "value": None}] +
            [{"color": color, "value": value} for value, color in rest]}


def env_thresholds(base: str, steps: dict) -> dict:
    """thresholds() whose steps differ per environment: `steps` maps each environment to its [(value, colour)]. Each
    step's value and colour are settled at start (per_env_number, per_environment); an environment with fewer steps
    gets transparent ones, at a value it already has, so nothing more is drawn."""
    ordered = {env: sorted(steps.get(env) or []) for env in ENVIRONMENTS}
    width = max(len(v) for v in ordered.values())
    if width == 0:
        return thresholds(base)
    for env, values in ordered.items():
        filler = values[-1][0] if values else next(v for vs in ordered.values() for v, _c in vs)
        values += [(filler, "transparent")] * (width - len(values))
    return {"mode": "absolute", "steps": [{"color": base, "value": None}] + [
        {"color": per_environment(*(ordered[env][i][1] for env in ENVIRONMENTS)),
         "value": per_env_number({env: ordered[env][i][0] for env in ENVIRONMENTS})} for i in range(width)]}


def by_ref(ref: str, **props) -> dict:
    names = {"name": "displayName", "unit": "unit", "mappings": "mappings", "thresholds": "thresholds",
             "decimals": "decimals"}
    return {"matcher": {"id": "byFrameRefID", "options": ref},
            "properties": [{"id": names[k], "value": v} for k, v in props.items()]}


# Colour means a reading that needs attention. A counter writes no series while nothing happens, so a stat's "no
# value" text (shown in the base colour) is never a measurement, and a query that failed shows it too, beside
# Grafana's error triangle: so the base colour is neutral, never green.
NEUTRAL = "text"

def when_quiet(deps, normal: str, quiet: str | None = None) -> str:
    """A string render-dashboards.sh settles at start: `normal`, or, while one of `deps` (a sweep in
    TPA_PAUSED_JOBS, a database in TPA_STOPPED_DATABASES) is quiet, `quiet`, or by default the reason ("paused",
    "database stopped")."""
    names = "," + ",".join(deps) + ","
    for text in (normal, quiet or ""):
        assert "@" not in text, text
    return f"@@R{names}@@{normal}@@" if quiet is None else f"@@F{names}@@{quiet}@@{normal}@@"


def per_environment(production: str, beta: str) -> str:
    """A string render-dashboards.sh settles from TPA_ENVIRONMENT (`production` or `beta`)."""
    assert "@" not in production + beta
    return f"@@E@@{production}@@{beta}@@" if production != beta else beta


ENVIRONMENTS = ("production", "beta")   # TPA_ENVIRONMENT's two words, in the order the tokens hold them


def per_env_number(values: dict):
    """A number render-dashboards.sh settles from TPA_ENVIRONMENT: `values` maps each environment to a number, or to
    None (JSON null). The same in both: the number itself, with no token."""
    production, beta = (values.get(env) for env in ENVIRONMENTS)
    if production == beta:
        return production
    words = ["null" if v is None else f"{v:g}" for v in (production, beta)]
    assert all(re.fullmatch(r"null|-?[0-9]+(\.[0-9]+)?", w) for w in words), words
    return f"@@N@@{words[0]}@@{words[1]}@@"


def quieten(p: dict, deps) -> dict:
    """A tile that says it is quiet: while one of `deps` is paused or stopped it shows the reason (with its number,
    if it has one) and no colour, because a stopped database's readers fail on purpose and a paused sweep runs nothing.
    production-full, which pauses and stops nothing, always shows the tile as built."""
    # value_and_name, not name: with no data the "no value" text is the value, and "name" would hide it (the
    # pixels showed blank tiles); with data the number shows, in no colour, under the reason.
    p["options"]["textMode"] = when_quiet(deps, p["options"]["textMode"], "value_and_name")
    defaults = p["fieldConfig"]["defaults"]
    defaults["displayName"] = when_quiet(deps, defaults.get("displayName", ""))
    defaults["noValue"] = when_quiet(deps, defaults.get("noValue", ""))
    for step in defaults["thresholds"]["steps"]:
        step["color"] = when_quiet(deps, step["color"], NEUTRAL)
    for override in p["fieldConfig"]["overrides"]:
        for prop in override["properties"]:
            if prop["id"] == "displayName":
                prop["value"] = when_quiet(deps, prop["value"])
            elif prop["id"] == "thresholds":
                for step in prop["value"]["steps"]:
                    step["color"] = when_quiet(deps, step["color"], NEUTRAL)
    paused = [d for d in deps if d in SWEEPS]
    stopped = [d for d in deps if d in DATABASES]
    p["description"] += (" Reads \"paused\" or \"database stopped\", in no colour, while " +
                         " or ".join(f"`{d}`" for d in paused + stopped) + " is " +
                         ("paused or stopped" if paused and stopped else "paused" if paused else "stopped") +
                         " on purpose (the service's TPA_PAUSED_JOBS, TPA_STOPPED_DATABASES).")
    return p


UP_MAPPING = [{"type": "value", "options": {"0": {"text": "DOWN", "color": "red", "index": 0},
                                            "1": {"text": "up", "color": "green", "index": 1}}}]


def panel(kind: str, title: str, ds: str | None, queries, description: str, *, w: int, h: int, unit: str = "short",
          steps=None, decimals=None, no_value=None, mappings=None, overrides=None, options=None, custom=None,
          transformations=None, time_from=None, links=None) -> dict:
    queries = [queries] if isinstance(queries, dict) else list(queries)
    p = {"type": kind, "title": title, "description": description, "gridPos": {"h": h, "w": w, "x": 0, "y": 0}}
    if links:
        # The panel title's link icon (Grafana's panel links): a service's own page.
        p["links"] = links
    if ds:
        p["datasource"] = {"type": "stackdriver", "uid": ds}
        p["targets"] = [target(ds, query, chr(ord("A") + i)) for i, query in enumerate(queries)]
        p["interval"] = "1m"
    if time_from:
        # The window is in the title; Grafana's "Last 1 hour" label would take the title's room in a small panel.
        p["timeFrom"] = time_from
        p["hideTimeOverride"] = True
    defaults = {"unit": unit, "color": {"mode": "thresholds" if kind in ("stat", "state-timeline")
                                        else "palette-classic"},
                "thresholds": steps or thresholds(NEUTRAL), "mappings": mappings or []}
    if decimals is not None:
        defaults["decimals"] = decimals
    if no_value is not None:
        defaults["noValue"] = no_value
    if custom:
        defaults["custom"] = custom
    p["fieldConfig"] = {"defaults": defaults, "overrides": overrides or []}
    p["options"] = options or {}
    if transformations:
        p["transformations"] = transformations
    return p


def stat(title, ds, queries, description, *, w=4, h=5, calc="sum", text_mode="auto", value_size=None, deps=(), **kw):
    p = panel("stat", title, ds, queries, description, w=w, h=h, options={
        "reduceOptions": {"calcs": [calc], "fields": "", "values": False},
        **({"text": {"valueSize": value_size}} if value_size else {}),
        "orientation": "auto", "textMode": text_mode, "colorMode": "value", "graphMode": "none",
        "justifyMode": "auto", "wideLayout": True, "showPercentChange": False}, **kw)
    return quieten(p, deps) if deps else p


def series(title, ds, queries, description, *, w=12, h=8, bars=False, points=False, line=None, lines=(),
           soft_max=None, **kw):
    """A time series. `line` draws the pager's threshold in red; `lines` draws several, each (value, colour): red
    for a line the pager uses, GREY for a limit the service is set to; or, a dict, each environment's lines
    (env_thresholds). `soft_max` keeps the y axis up to a limit, so the lines show while the readings sit far below
    them (a dict: each environment's, None for none). `points` draws each reading as a dot, for a metric that writes
    only now and then (a start-up)."""
    if not isinstance(lines, dict):
        lines = {env: [(line, "red")] if line is not None else list(lines) for env in ENVIRONMENTS}
    shown = any(lines.values())
    custom = {"drawStyle": "points" if points else "bars" if bars else "line", "lineWidth": 1,
              "fillOpacity": 60 if bars else 10, "showPoints": "always" if points else "never", "spanNulls": False,
              "stacking": {"mode": "normal" if bars else "none", "group": "A"},
              "axisSoftMin": 0, "thresholdsStyle": {
                  "mode": per_environment(*("line" if lines[env] else "off" for env in ENVIRONMENTS))}}
    if points:
        custom["pointSize"] = 6
    soft_max = per_env_number(soft_max) if isinstance(soft_max, dict) else soft_max
    if soft_max is not None:
        custom["axisSoftMax"] = soft_max
    if shown:
        kw["steps"] = env_thresholds("transparent", lines)
    return panel("timeseries", title, ds, queries, description, w=w, h=h, custom=custom, options={
        "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["max", "lastNotNull"]},
        "tooltip": {"mode": "multi", "sort": "desc"}}, **kw)


def timeline(title, ds, queries, description, *, w=12, h=6, **kw):
    return panel("state-timeline", title, ds, queries, description, w=w, h=h, custom={"fillOpacity": 80},
                 options={"showValue": "never", "mergeValues": True, "alignValue": "left", "rowHeight": 0.8,
                          "legend": {"showLegend": False, "displayMode": "list", "placement": "bottom"},
                          "tooltip": {"mode": "single", "sort": "none"}}, **kw)


def table(title, ds, queries, description, *, columns: dict[str, str], w=12, h=8, count="Count", **kw):
    """One row per series: its labels as columns (renamed by `columns`, in that order) and the sum of its
    per-interval counts over the time range."""
    rename = {label(k): v for k, v in columns.items()}
    rename["Total"] = count
    order = {name: i for i, name in enumerate(list(columns.values()) + [count])}
    return panel("table", title, ds, queries, description, w=w, h=h, transformations=[
        {"id": "reduce", "options": {"mode": "seriesToRows", "reducers": ["sum"], "labelsToFields": True,
                                     "includeTimeField": False}},
        {"id": "organize", "options": {"excludeByName": {"Field": True, "resource.type": True},
                                       "renameByName": rename, "indexByName": order}}],
        options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                 "sortBy": [{"displayName": count, "desc": True}]},
        custom={"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False, "filterable": False}, **kw)


def text(title, content, *, w=24, h=4):
    return {"type": "text", "title": title, "gridPos": {"h": h, "w": w, "x": 0, "y": 0},
            "options": {"mode": "markdown", "content": content, "code": {"language": "plaintext",
                                                                          "showLineNumbers": False,
                                                                          "showMiniMap": False}}}


def row(title):
    return {"type": "row", "title": title, "collapsed": False, "panels": [], "gridPos": {"h": 1, "w": 24, "x": 0, "y": 0}}


def collapsed(items: list[dict]) -> list[dict]:
    """A row (the first item) shut by default, holding the panels after it: Grafana runs their queries only once a
    viewer opens it."""
    head, *inside = items
    assert head["type"] == "row" and all(p["type"] != "row" for p in inside)
    return [{**head, "collapsed": True, "panels": inside}]


def layout(items: list[dict]) -> list[dict]:
    """Place panels left to right, wrapping at 24 columns; a row starts a new line. A shut row's panels are placed
    under it as they will be when it opens, and the page goes on one line below it. Ids in order, nested included."""
    x = y = line_h = 0
    n = 0

    def place(p):
        nonlocal x, y, line_h, n
        g = p["gridPos"]
        if p["type"] == "row" or x + g["w"] > 24:
            y += line_h
            x = line_h = 0
        g["x"], g["y"] = x, y
        n += 1
        p["id"] = n
        if p["type"] == "row":
            y += 1
        else:
            x += g["w"]
            line_h = max(line_h, g["h"])

    for p in items:
        place(p)
        if p["type"] == "row" and p["collapsed"]:
            after = y
            for inner in p["panels"]:
                place(inner)
            x, y, line_h = 0, after, 0
    return items


PAGERDUTY = "https://app.pagerduty.com/incidents"
SERVICE_TAG = "cloud-service"   # a service's own page; the Services menu on every page lists them


def dashboard(uid: str, title: str, description: str, tags: list[str], items: list[dict], time: str = "now-6h",
              kind: str = "cloud", links: tuple[dict, ...] = ()) -> dict:
    """A page. `kind` is its tag: "cloud" for the pages the Pages menu lists, SERVICE_TAG for a service's own page,
    which the Services menu lists. `links` go after the menus (a service page's way back to its area's page)."""
    return {
        "uid": uid, "title": title, "description": description, "tags": ["trellis-watchtower", kind, *tags],
        "editable": False, "graphTooltip": 1, "refresh": "5m", "schemaVersion": 41, "version": 1,
        "timezone": "browser", "fiscalYearStartMonth": 0, "liveNow": False, "weekStart": "",
        "time": {"from": time, "to": "now"}, "timepicker": {"refresh_intervals": ["1m", "5m", "15m", "30m"]},
        "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                  "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                  "name": "Annotations & Alerts", "type": "dashboard"}]},
        "links": [
            {"title": "Overview", "type": "link", "url": "/d/tw-cloud-overview", "icon": "dashboard", "keepTime": True,
             "includeVars": False, "targetBlank": False, "tags": [], "asDropdown": False, "tooltip": ""},
            {"title": "Pages", "type": "dashboards", "tags": ["cloud"], "asDropdown": True, "keepTime": True,
             "includeVars": False, "targetBlank": False, "icon": "external link", "url": "", "tooltip": ""},
            {"title": "Services", "type": "dashboards", "tags": [SERVICE_TAG], "asDropdown": True, "keepTime": True,
             "includeVars": False, "targetBlank": False, "icon": "external link", "url": "",
             "tooltip": "Each Cloud Run service's own page: its CPU, memory, instances, concurrency and start-up"},
            {"title": "PagerDuty incidents", "type": "link", "url": PAGERDUTY, "icon": "bolt", "keepTime": False,
             "includeVars": False, "targetBlank": True, "tags": [], "asDropdown": False,
             "tooltip": "Open incidents page through PagerDuty; this site cannot list them"},
            *links],
        "templating": {"list": []},
        "panels": layout(items),
    }


# ---- Shared panels and wording -------------------------------------------------------------------------------------
NOTHING_BUT_METRICS = ("Every panel reads Cloud Monitoring metrics: Google's own, and the log-based counters "
                       "tpa-platform's catalogue defines, whose labels are a closed list. No panel reads a log line.")
STOPPED_DB = ("\"database stopped\": stopped on purpose between test sessions (beta's database_activation_policy "
              "NEVER; the service's TPA_STOPPED_DATABASES). \"not reporting\": no value, and not listed as stopped: "
              "not built (cc-db exists with the staffed desk only), or reporting nothing.")


def db_stat(title: str, ds: str, instance: str, *, w=4, h=5) -> dict:
    return stat(title, ds, [db_up(instance, "+60s"), db_disk(instance, "+300s")],
                f"Cloud SQL's own signals for {instance}: `database/up` (the urgent `{instance}-down` pages below 1 "
                f"for five minutes) and disk used (`{instance}-disk` at 85% for ten minutes). " + STOPPED_DB,
                w=w, h=h, calc="lastNotNull", text_mode="value_and_name", time_from="15m",
                no_value=when_quiet((instance,), "not reporting"),
                overrides=[by_ref("A", name="up", mappings=UP_MAPPING, unit="none",
                                  thresholds=thresholds("red", (1, "green"))),
                           by_ref("B", name="disk", unit="percentunit", decimals=0,
                                  thresholds=thresholds("green", (0.75, "orange"), (0.85, "red")))])


def jobs_stat(title: str, ds: str, jobs: str, schedules: str | None, deps) -> dict:
    queries = [executions(jobs, "failed", "+3600s", by=(), name="failed")]
    if schedules:
        queries.append(schedule_failures(schedules, "+3600s", by=(), name="schedule failed"))
    return stat(title, ds, queries, "Last 24 h: executions that failed after their retries (`jobs-failed`)" +
                (", and schedules that could not start their job (`scheduler-failed`)" if schedules else "") +
                ". A missed run is the Scheduled runs row above.", time_from="24h", no_value="0",
                text_mode="value_and_name", steps=thresholds(NEUTRAL, (1, "red")), deps=deps)


def groups_stat(title: str, ds: str, queries: list[dict], counter: str, deps) -> dict:
    return stat(title, ds, queries,
                f"Error groups of `{counter}` seen in the last 24 h: one per Cloud Run service or job and the "
                "counter's labels, the same group the new-group and spike policies read. The Errors page lists them.",
                calc="lastNotNull", time_from="24h", no_value="0", text_mode="value_and_name",
                steps=thresholds(NEUTRAL, (1, "orange")), deps=deps)


def deadline_stats(w: int, h: int) -> list[dict]:
    """One stat per scheduled job: its successful executions within its missed-run deadline, the module's own
    condition (`missed run (<job>)`). None at all reads MISSED."""
    out = []
    for ds, job, deadline, deps in DEADLINES:
        window = deadline + METRIC_DELAY_MINUTES
        out.append(stat(job.removeprefix("tpa-jobs-"), ds,
                        executions(job, "succeeded", "+60s" if window <= 120 else "+3600s", by=(), name="runs"),
                        f"Successful executions of `{job}` in the last {window} minutes: its missed-run deadline "
                        f"({deadline} minutes, about one and a half cadences) plus three, because Cloud Run's job "
                        "metrics can arrive up to 180 s after the run. MISSED: none, so its `missed run` policy is "
                        "open or about to be.", w=w, h=h, time_from=f"{window}m", no_value="MISSED",
                        steps=thresholds("red", (1, "green")), deps=deps))
    return out


# ---- The home: what is wrong now, one project at a time ------------------------------------------------------------
# A cloud panel reads one project (rule 8), so the home's headline and "What's wrong now" are one per project, in
# the order TPA (portal and sign-in, then member records), call centre, CRM. Each reads counts where more than 0 is
# a problem, named with a ✕ (5xx answers, uptime and inside checks failing, journeys failed or broken, crashes,
# out-of-memory kills, failed job runs, minutes a database was down), plus one "reporting" count that is above 0
# whenever the project's metrics arrive at all. That one turns negative, so it stays apart: it is drawn teal and
# never counts as a problem, and with nothing at all (no metric arrived, or the query failed) the panel reads
# "? Can't tell", never green.
NOW = "+60s"   # one point a minute: every query of a home panel lines up for the join
# A count above 0 is red; the negative "reporting" count teal; no value at all (blind) amber, never teal.
def home_steps() -> dict:
    return thresholds(AMBER, (-1e15, TEAL), (0.5, RED))   # a new one each time: quieten() edits it in place
REPORTING = {"type": "range", "options": {"from": -1e15, "to": -0.5, "result": {"text": "reporting", "index": 0}}}


def area_queries(ds: str, services: str, jobs: str | None, db: str, *, checks: bool = False) -> list[dict]:
    """The problem counts of one project, and its "reporting" count (named `seeing`) last."""
    out = [q(RUN_REQUESTS, REV, period=NOW, by=("service_name",), name=alias("service_name", prefix="✕ 5xx · "),
             service_name=Re(services), response_code_class="5xx")]
    if checks:
        out += [q(UPTIME, URL, align="ALIGN_COUNT_FALSE", period=NOW, by=("host",),
                  name=alias("host", prefix="✕ uptime check failing · ")),
                q(UPTIME, PRIVATE, align="ALIGN_COUNT_FALSE", period=NOW, by=("service_name",),
                  name=alias("service_name", prefix="✕ inside check failing · ")),
                q(log("synthetic_results"), JOB, period=NOW, by=("job",), name=alias("job", prefix="✕ ") + " failed",
                  outcome="fail"),
                q(log("synthetic_results"), JOB, period=NOW, by=("job",), name=alias("job", prefix="✕ ") + " broke",
                  outcome="error")]
    out += [q(log("run_crash_exits"), REV, period=NOW, by=("service_name",),
              name=alias("service_name", prefix="✕ crashed · "), service_name=Re(services)),
            q(log("run_oom_kills"), REV, period=NOW, by=("service_name",),
              name=alias("service_name", prefix="✕ out of memory · "), service_name=Re(services))]
    if jobs:
        out += [q(log("run_oom_kills"), JOB, period=NOW, by=("job_name",),
                  name=alias("job_name", prefix="✕ out of memory · "), job_name=Re(jobs)),
                q(RUN_JOBS, JOB, period=NOW, by=("job_name",), name=alias("job_name", prefix="✕ run failed · "),
                  job_name=Re(jobs), result="failed")]
    out += [q(SQL_UP, SQL, align="ALIGN_MIN", period=NOW, reduce="REDUCE_MIN", by=("database_id",),
              name=f"{db} up", database_id=f"*:{db}")]
    if checks:
        # Every uptime check result, passed or not: they arrive every minute from three regions.
        out.append(q(UPTIME, URL, align="ALIGN_COUNT", period=NOW, reduce="REDUCE_SUM", name="seeing"))
    else:
        # Every point the project's database reports, up or down.
        out.append(q(SQL_UP, SQL, align="ALIGN_COUNT", period=NOW, reduce="REDUCE_SUM", name="seeing",
                     database_id=f"*:{db}"))
    return out


def area_transformations(db: str, reporting: str) -> list[dict]:
    """Join the minute points, turn the database's up into its down minutes and the reporting count negative, sum
    each series over the panel's 15 minutes, keep what is not 0, worst first."""
    def calc(alias_, left, op, right):
        side = lambda v: {"fixed": str(v)} if isinstance(v, (int, float)) else {"matcher": {"id": "byName", "options": v}}
        return {"id": "calculateField", "options": {"mode": "binary", "alias": alias_, "replaceFields": False,
                                                    "binary": {"left": side(left), "operator": op,
                                                               "right": side(right)}}}
    return [
        {"id": "joinByField", "options": {"byField": "Time", "mode": "outer"}},
        calc(f"✕ {db} down (minutes)", 1, "-", f"{db} up"),
        calc(reporting, "seeing", "*", -1),
        {"id": "organize", "options": {"excludeByName": {f"{db} up": True, "seeing": True}}},
        {"id": "reduce", "options": {"mode": "seriesToRows", "reducers": ["sum"], "labelsToFields": False,
                                     "includeTimeField": False}},
        {"id": "filterByValue", "options": {"type": "include", "match": "any", "filters": [
            {"fieldName": "Total", "config": {"id": "greater", "options": {"value": 0}}},
            {"fieldName": "Total", "config": {"id": "lower", "options": {"value": 0}}}]}},
        {"id": "sortBy", "options": {"sort": [{"field": "Total", "desc": True}]}},
    ]


AREAS = [
    # (key, headline title, datasource, services, jobs, database, the reporting row's words, has the checks)
    ("app", "TPA · portal and sign-in", APP, f"{WEB_API}|{AUTH_SERVICES}|tpa-jobs-drains", f"{TPA_JOBS}|{AUTH_JOBS}",
     "auth-db", "✓ portal and sign-in", True),
    ("phi", "TPA · member records", PHI, PHI_SERVICES, PHI_JOBS, "tpa-db", "✓ member records", False),
    ("cc", "Call centre", CC, CC_SERVICES, "migrate-cc", "cc-db", "✓ call centre", False),
    ("crm", "CRM", CRM, CRM_SERVICES, CRM_JOBS, "crm-db", "✓ CRM", False),
]
AREA_WORDS = ("5xx answers, uptime and inside checks failing (beta's checks pass on IAP's sign-in page), synthetic "
              "journeys failed or broken, crashes, out-of-memory kills, failed job runs, minutes the database was "
              "down")


def headline(key, title, ds, services, jobs, db, reporting, checks, w=6) -> dict:
    p = stat(title, ds, area_queries(ds, services, jobs, db, checks=checks),
             f"The last 15 minutes in this project, one tile per problem, named: "
             f"{AREA_WORDS if checks else 'its 5xx answers, crashes, out-of-memory kills, failed job runs and the minutes ' + db + ' was down'}. "
             f"'{reporting} · reporting' (teal) says this project's metrics are arriving (for the portal, the "
             "uptime checks' results; elsewhere, the database's own points); alone, it is the all-clear. "
             "'? Can't tell': nothing arrived, or the query failed. Open incidents are in PagerDuty.",
             w=w, h=5, calc="lastNotNull", text_mode="value_and_name", time_from="15m", no_value="? Can't tell",
             steps=home_steps(), deps=(db,), mappings=[REPORTING], decimals=0,
             transformations=area_transformations(db, reporting))
    # One tile per row: the problem's name, and its count. value_and_name, not name: with nothing to show, the
    # "? Can't tell" text is the value, and "name" would leave a blank tile (seen in a TestData render).
    p["options"].update({"reduceOptions": {"values": True, "calcs": ["lastNotNull"], "fields": "/^Total$/"},
                         # A block of colour, but no colour at all while its database is stopped on purpose.
                         "colorMode": when_quiet((db,), "background", "none"), "orientation": "horizontal",
                         "text": {"titleSize": 18, "valueSize": 18}})
    return p


def whats_wrong(key, title, ds, services, jobs, db, reporting, checks, w=6) -> dict:
    p = panel("table", f"What's wrong now · {title}", ds, area_queries(ds, services, jobs, db, checks=checks),
              "Each problem of the last 15 minutes with its count (answers, failures, runs or minutes), worst "
              "first; the teal row says the project's metrics are arriving. Empty reads '? Can't tell'.",
              w=w, h=6, time_from="15m", no_value=when_quiet((db,), "? Can't tell"),
              custom={"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False, "filterable": False},
              transformations=area_transformations(db, reporting) + [
                  {"id": "organize", "options": {"renameByName": {"Field": "Problem", "Total": "15 min"}}}])
    p["options"] = {"showHeader": False, "cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"],
                                                                         "fields": ""}}
    # Only the count is coloured, by its own value: red above 0, teal for the reporting row.
    p["fieldConfig"]["overrides"] = [{"matcher": {"id": "byName", "options": "15 min"}, "properties": [
        {"id": "custom.width", "value": 90}, {"id": "custom.cellOptions", "value": {"type": "color-text"}},
        {"id": "color", "value": {"mode": "thresholds"}}, {"id": "thresholds", "value": home_steps()},
        {"id": "mappings", "value": [REPORTING]}, {"id": "decimals", "value": 0}]}]
    p["description"] += f" Reads \"database stopped\" while `{db}` is stopped on purpose (TPA_STOPPED_DATABASES)."
    return p


def service_tile(title, ds, services, deps=()) -> dict:
    return stat(title, ds, [q(RUN_REQUESTS, REV, period="+900s", by=(), name="5xx (15 m)",
                              service_name=Re(services), response_code_class="5xx"),
                            q(RUN_INSTANCES, REV, align="ALIGN_MAX", period="+60s", by=(), name="instances",
                              service_name=Re(services))],
                f"{title}: 5xx answers in the last 15 minutes (red from 1) and Cloud Run instances now. No 5xx "
                "series means none was answered; no instance series, none is running (a scale-to-zero service "
                "idles at none). The link by the title opens the service's own page: its CPU, memory, instances, "
                "concurrency and start-up.", w=3, h=4, calc="lastNotNull", text_mode="value_and_name",
                time_from="15m", no_value="no data", deps=deps, links=service_links(*services.split("|")),
                overrides=[by_ref("A", thresholds=thresholds(NEUTRAL, (1, RED)), decimals=0),
                           by_ref("B", decimals=0)])


def db_tile(instance, ds, *, w=3, h=4) -> dict:
    return stat(instance, ds, db_up(instance, "+60s"),
                f"Cloud SQL's `database/up` for {instance}, now. " + STOPPED_DB, w=w, h=h, calc="lastNotNull",
                time_from="15m", no_value=when_quiet((instance,), "not reporting"), unit="none",
                mappings=[{"type": "value", "options": {"0": {"text": "✕ DOWN", "color": RED, "index": 0},
                                                         "1": {"text": "✓ up", "color": TEAL, "index": 1}}}],
                steps=thresholds(RED, (1, TEAL)))


# ---- What tpa-platform's Terraform sets, per environment, and what its monitoring module pages on -----------------
# Each environment root's limits (tpa-platform infra/envs/beta and infra/envs/production-full, read at the catalogue's
# pinned commit by tests/cloud/test_resources.py): each Cloud Run service's max_instances (Cloud Run's default, 100,
# where a root sets none) and concurrency (80 where none is set), the services the module writes a
# `ceiling-<service>` policy for (instance_ceilings: name -> max_instances), and each Cloud SQL instance's
# max_connections (the root's flag, else Cloud SQL's own for the tier its terraform.tfvars.example gives). A service or
# instance a root does not build is absent: no limit is drawn for it there. Each line is settled per TPA_ENVIRONMENT
# at start (per_env_number), so production never shows a line beta's Terraform drew.
DEFAULT_MAX_INSTANCES, DEFAULT_CONCURRENCY = 100, 80
LIMITS = {
    "beta": {
        "max_instances": {"web": 100, "tpa-api": 100, "model-gateway": 100, "tpa-jobs-drains": 1, "auth": 20,
                          "auth-outbox-publisher": 3, "watchtower": 1, "records": 20, "connectors": 4, "svc-voice": 1,
                          "svc-ops": 1, "svc-twilio-rest": 1, "crm-web": 2, "engine": 1},
        "concurrency": {"svc-voice": 20},   # one call each
        "ceilings": {"auth": 20, "auth-outbox-publisher": 3, "records": 20, "connectors": 4},
        "max_connections": {"auth-db": 100, "tpa-db": 400, "crm-db": 200, "cc-db": 100},
    },
    "production": {   # production-full: records keeps Cloud Run's default; no call centre, CRM services or watchtower
        "max_instances": {"web": 100, "tpa-api": 100, "model-gateway": 100, "tpa-jobs-drains": 1, "auth": 20,
                          "auth-outbox-publisher": 3, "records": 100, "connectors": 4},
        "concurrency": {},
        "ceilings": {"auth": 20, "auth-outbox-publisher": 3, "connectors": 4},
        "max_connections": {"auth-db": 500, "tpa-db": 400, "crm-db": 200},
    },
}


def limit(kind: str, name: str) -> dict:
    """Each environment's value of a limit (None where that environment does not build `name`)."""
    out = {}
    for env in ENVIRONMENTS:
        built = LIMITS[env]["max_instances"] if kind == "concurrency" else LIMITS[env][kind]
        if kind == "concurrency":
            out[env] = LIMITS[env]["concurrency"].get(name, DEFAULT_CONCURRENCY) if name in built else None
        else:
            out[env] = built.get(name)
    return out


# The monitoring module's own per-resource policies (tpa-platform infra/modules/monitoring/main.tf: local.sql_thresholds
# for each Cloud SQL instance, local.ceiling_policies for each instance ceiling), each as its condition reads: its
# line (a value, or a share of max_connections or of max_instances), and its window, aligner and reducer.
SQL_POLICIES = {
    "cpu-high": {"metric": SQL_CPU, "value": 0.8, "period": "300s", "aligner": "ALIGN_MEAN", "reducer": "REDUCE_MAX"},
    "cpu-saturated": {"metric": SQL_CPU, "value": 0.95, "period": "300s", "aligner": "ALIGN_MEAN",
                      "reducer": "REDUCE_MAX"},
    "memory-high": {"metric": SQL_MEMORY, "value": 0.9, "period": "300s", "aligner": "ALIGN_MEAN",
                    "reducer": "REDUCE_MAX"},
    "connections-high": {"metric": SQL_BACKENDS, "share": 0.8, "period": "60s", "aligner": "ALIGN_MEAN",
                         "reducer": "REDUCE_SUM"},
    "connections-saturated": {"metric": SQL_BACKENDS, "share": 0.95, "period": "60s", "aligner": "ALIGN_MEAN",
                              "reducer": "REDUCE_SUM"},
}
# `ceiling-<service>`: the service's instances, summed (active and idle), above ceil(share * max_instances) - 0.5.
CEILING_POLICY = {"metric": RUN_INSTANCES, "share": 0.8, "period": "60s", "aligner": "ALIGN_MAX",
                  "reducer": "REDUCE_SUM"}


def connections_lines(cap: int | None) -> list[tuple[float, str]]:
    """The connection policies' lines for a max_connections (none where it is not known)."""
    return [] if cap is None else [(math.floor(SQL_POLICIES[n]["share"] * cap), "red")
                                   for n in ("connections-high", "connections-saturated")]


def ceiling_line(cap: int) -> float:
    return math.ceil(CEILING_POLICY["share"] * cap) - 0.5


def sql_query(policy: str, instance: str, name: str) -> dict:
    """A Cloud SQL instance's metric read as the module's policy reads it."""
    m = SQL_POLICIES[policy]
    return db_resource(m["metric"], instance, name, "+" + m["period"], align=m["aligner"], reduce=m["reducer"])


def db_resources(instance, ds, w=6) -> dict:
    caps = limit("max_connections", instance)
    lines = {env: connections_lines(cap) for env, cap in caps.items()}
    cpu = [SQL_POLICIES[n]["value"] for n in ("cpu-high", "cpu-saturated")]
    return stat(instance, ds,
                [db_up(instance, "+60s"), db_resource(SQL_CPU, instance, "CPU", "+60s"),
                 db_resource(SQL_MEMORY, instance, "memory", "+60s"), db_disk(instance, "+300s"),
                 db_resource(SQL_BACKENDS, instance, "connections", "+60s", reduce="REDUCE_SUM")],
                f"Cloud SQL's own signals for {instance}, now: up; CPU (the module pages at {pct(cpu[0])} and "
                f"{pct(cpu[1])}); memory ({pct(SQL_POLICIES['memory-high']['value'])}); disk used (`{instance}-disk` "
                "at 85%); connections (num_backends; the module opens at 80% and 95% of max_connections, " +
                per_environment(*(f"{caps[env]} here" if caps[env] else "not known here" for env in ENVIRONMENTS)) +
                "). " + STOPPED_DB,
                w=w, h=5, calc="lastNotNull", text_mode="value_and_name", time_from="15m", value_size=26,
                no_value=when_quiet((instance,), "not reporting"),
                overrides=[by_ref("A", name="up", mappings=[{"type": "value", "options": {
                               "0": {"text": "✕ DOWN", "color": RED, "index": 0},
                               "1": {"text": "✓ up", "color": TEAL, "index": 1}}}], unit="none",
                                  thresholds=thresholds(RED, (1, TEAL))),
                           by_ref("B", name="CPU", unit="percentunit", decimals=0,
                                  thresholds=thresholds(NEUTRAL, (cpu[0], AMBER), (cpu[1], RED))),
                           by_ref("C", name="memory", unit="percentunit", decimals=0,
                                  thresholds=thresholds(NEUTRAL, (SQL_POLICIES["memory-high"]["value"], RED))),
                           by_ref("D", name="disk", unit="percentunit", decimals=0,
                                  thresholds=thresholds(NEUTRAL, (0.75, AMBER), (0.85, RED))),
                           by_ref("E", name="connections", decimals=0,
                                  thresholds=env_thresholds(NEUTRAL, {env: [(v, c) for (v, _), c in zip(
                                      lines[env], (AMBER, RED))] for env in ENVIRONMENTS}))])


def journeys_stat() -> dict:
    p = stat("Synthetic journeys (1 h)", APP,
             q(log("synthetic_results"), JOB, period="+3600s", by=("job", "outcome"),
               name=alias("job", "outcome")),
             "Each journey's runs in the last hour, by outcome (`synthetic_results`, one result line per run): "
             + "; ".join(f"`{job}` ({name}): {what}" for job, name, what in JOURNEYS) + ". pass is teal; fail "
             "is red (`synthetic-failing` pages on two fails and no pass in eleven minutes; J1 and J2 urgent); "
             "error is amber (the runner itself broke: `synthetic-broken`); skipped, grey. No runs at all: the "
             "journeys are off or paused (`synthetic-blind` when one goes quiet 15 minutes).",
             w=8, h=7, calc="sum", text_mode="value_and_name", time_from="1h",
             no_value="no runs (off or paused)", decimals=0,
             overrides=[{"matcher": {"id": "byRegexp", "options": f".* {word}$"},
                         "properties": [{"id": "thresholds", "value": thresholds(NEUTRAL, (1, colour))}]}
                        for word, colour in (("pass", TEAL), ("fail", RED), ("error", AMBER))])
    return p


# ---- Resources: every Cloud Run service's primitives ---------------------------------------------------------------
# The owner (2026-10-13): "Where are all the primitives for each service?" Each Cloud Run service's CPU, memory,
# instances, concurrency and start-up, the signals its saturation policies page on, drawn with the line each policy
# compares: a Resources row per service on its area's page, and a page of its own (the Services menu on every page,
# and the link by each service's title on the overview). There is no `$service` page: a cloud page takes no viewer
# input (dashboard_lint's rules 7 and 9), so each service's page is written out here, one per service.
#
# Each service: its datasource, and the page whose Resources rows hold it.
SERVICES = {
    "web": (APP, "portal-api"), "tpa-api": (APP, "portal-api"), "model-gateway": (APP, "portal-api"),
    "tpa-jobs-drains": (APP, "portal-api"), "watchtower": (APP, "portal-api"),
    "auth": (APP, "sign-in"), "auth-outbox-publisher": (APP, "sign-in"),
    "records": (PHI, "records"), "connectors": (PHI, "records"),
    "svc-voice": (CC, "callcentre"), "svc-ops": (CC, "callcentre"), "svc-twilio-rest": (CC, "callcentre"),
    "crm-web": (CRM, "crm"), "engine": (CRM, "crm"),
}
AREA_TITLES = {"portal-api": "Portal & API", "sign-in": "Sign-in", "records": "Member records",
               "callcentre": "Call centre", "crm": "CRM"}
WHAT = {"watchtower": "this monitoring site"}   # a service whose name does not say what it is
# The services whose Cloud Run latency beta's `canary-latency` leaves out: they hold a stream or a call open.
LATENCY_LEFT_OUT = ("web", "tpa-api", "svc-voice", "svc-ops")
# The pager's lines, read from the vendored catalogue. Each panel aggregates as the policy's condition does (its
# aligner, window and reducer), so its red line is the very threshold that condition compares.
CPU_POLICY, MEMORY_POLICY, CONCURRENCY_POLICY, QUOTA_POLICY = (
    CATALOGUE.threshold(name) for name in ("run-cpu-high", "run-memory-high", "run-concurrency-high",
                                           "run-instances-near-quota"))
REGIONAL_QUOTA = int(re.search(r"\((\d+)\)", CATALOGUE.policy("run-instances-near-quota")["display_name"]).group(1))
NAT_FAILED_POLICY, NAT_DROPPED_POLICY = (CATALOGUE.threshold("nat-port-exhaustion", condition=n) for n in (0, 1))
NAT_OUT_OF_PORTS = "OUT_OF_RESOURCES"   # the dropped-packets condition's reason (its filter, a block the reader skips)
# Each Cloud SQL instance's role, whose project holds it and its `<instance>-disk` policy.
DB_ROLE = {"auth-db": "app", "tpa-db": "phi", "crm-db": "crm", "cc-db": "cc"}
GREY = "#8c8c8c"   # a limit the service is set to; red is a line a policy pages at
NO_DISK = ("**Cloud Run services have no disk.** A file a container writes is held in its memory, so a service's "
           "\"disk space\" is its **Memory** chart: files that grow show as memory climbing to the red line, then as a "
           "container killed for memory. Real disk is on the databases (each one's disk space is on its area's page "
           "and on Databases) and in the buckets. A **red line** is the line the pager uses (tpa-platform's alert "
           "policies); a **grey line** is a limit the service is set to.")


def window(policy: dict) -> str:
    """A policy's alignment period as a fixed panel period (Grafana's `+300s`)."""
    return "+" + policy["alignment_period"]


def minutes(policy: dict, key: str = "alignment_period") -> int:
    return int(policy[key].removesuffix("s")) // 60


def pct(value: float) -> str:
    return f"{value * 100:g}%"


def service_uid(service: str) -> str:
    return f"tw-cloud-service-{service}"


def service_links(*services: str) -> list[dict]:
    """Panel links to services' own pages, keeping the time range."""
    return [{"title": f"{s}: CPU, memory, instances, concurrency, start-up",
             "url": f"/d/{service_uid(s)}?${{__url_time_range}}", "targetBlank": False} for s in services]


def percentiles(metric: str, resource: str, policy: dict, **where) -> list[dict]:
    """The 99th, 95th and 50th percentile of a distribution over the policy's window, reduced as the policy reduces:
    the p99 is the series the policy compares with its threshold."""
    assert policy["per_series_aligner"] == "ALIGN_PERCENTILE_99", policy
    return [q(metric, resource, align=f"ALIGN_PERCENTILE_{n}", period=window(policy),
              reduce=policy["cross_series_reducer"], name=f"p{n}", **where) for n in (99, 95, 50)]


def instance_limits(service: str) -> tuple[dict, dict]:
    """Each environment's lines on a service's instance count, and their words: a red line where the module writes a
    `ceiling-<service>` policy, a grey one at max_instances where it is below Cloud Run's default."""
    lines, words = {}, {}
    for env in ENVIRONMENTS:
        cap, ceiling = LIMITS[env]["max_instances"].get(service), LIMITS[env]["ceilings"].get(service)
        if cap is None:
            lines[env], words[env] = [], "This environment's Terraform does not build it, so no limit is drawn."
        elif ceiling is not None:
            red = ceiling_line(ceiling)
            lines[env] = [(red, "red")] + ([(cap, GREY)] if cap > red else [])
            words[env] = (f"The red line is `ceiling-{service}`'s: the total above {red:g} (80% of max_instances, "
                          f"rounded up, less a half) for ten minutes pages; the grey line is max_instances, {cap}: at "
                          "it new requests wait or fail with 429.")
        elif cap < DEFAULT_MAX_INSTANCES:
            lines[env], words[env] = [(cap, GREY)], (f"The grey line is max_instances, {cap} (too few for a "
                                                     "`ceiling-` policy): at it new requests wait or fail with 429.")
        else:
            lines[env], words[env] = [], (f"max_instances is Cloud Run's default, {cap}, so the project's regional "
                                          f"quota of {REGIONAL_QUOTA} binds first (`run-instances-near-quota`: the "
                                          "project's instances, on its area's page).")
    return lines, words


def concurrency_limits(service: str) -> tuple[dict, dict]:
    """Each environment's lines on a service's busiest instance: `run-concurrency-high`'s (every project has it) where
    it is below the concurrency setting, and the setting itself, grey, where the environment builds the service."""
    busy = CONCURRENCY_POLICY["threshold_value"]
    lines, words = {}, {}
    for env, slots in limit("concurrency", service).items():
        red = [] if slots is not None and busy >= slots else [(busy, "red")]
        lines[env] = red + ([(slots, GREY)] if slots is not None else [])
        words[env] = (
            (f"The red line is `run-concurrency-high`'s: the p99 above {busy:g} for "
             f"{minutes(CONCURRENCY_POLICY, 'duration')} minutes pages. " if red else
             f"`run-concurrency-high` opens above {busy:g}, beyond this service's setting, so it never opens for it. ")
            + (f"The grey line is the concurrency setting, {slots}: past it a request waits for a slot or a new "
               "instance." if slots is not None else "This environment's Terraform does not build it."))
    return lines, words


def resources(service: str, *, own_page: bool = False) -> list[dict]:
    """One Cloud Run service's Resources row: CPU, memory, instances, concurrency, start-up, instances billed, and
    containers killed for memory, crashed or failing to start. The same row on its area's page (shut) and on its own
    page (open). The lines drawn from Terraform's limits are each environment's (render-dashboards.sh settles them)."""
    ds, _page = SERVICES[service]
    me = {"service_name": service}
    cpu, memory = (p["threshold_value"] for p in (CPU_POLICY, MEMORY_POLICY))
    instance_lines, instance_words = instance_limits(service)
    busy_lines, busy_words = concurrency_limits(service)
    top = {env: max((v for v, _c in lines), default=None) for env, lines in instance_lines.items()}
    slots = {env: max((v for v, _c in lines), default=None) for env, lines in busy_lines.items()}
    ceiling = CEILING_POLICY
    if own_page:
        link = [{"title": f"{AREA_TITLES[_page]}: the page {service} is on", "url": f"/d/tw-cloud-{_page}"
                 "?${__url_time_range}", "targetBlank": False}]
    else:
        link = service_links(service)
    what = f" ({WHAT[service]})" if service in WHAT else ""
    return [
        row(f"Resources · {service}: CPU, memory, instances, concurrency, start-up{what}"),
        series("CPU (p99, p95, p50)", ds, percentiles(RUN_CPU, REV, CPU_POLICY, **me),
               f"{service}'s container CPU, the share of its CPU limit in use (`container/cpu/utilizations`): the "
               f"99th, 95th and 50th percentile across its instances in each {minutes(CPU_POLICY)}-minute window. The "
               f"red line is `run-cpu-high`'s: the p99 above {pct(cpu)} for {minutes(CPU_POLICY, 'duration')} "
               "minutes pages (instances saturated: requests queue and slow).", w=6, h=7, unit="percentunit",
               line=cpu, soft_max=1, links=link),
        series("Memory (p99, p95, p50)", ds, percentiles(RUN_MEMORY, REV, MEMORY_POLICY, **me),
               f"{service}'s container memory, the share of its memory limit in use (`container/memory/utilizations`), "
               f"percentiles across its instances in each {minutes(MEMORY_POLICY)}-minute window. Cloud Run has no "
               "disk: files the container writes are held in memory and count here. The red line is "
               f"`run-memory-high`'s: the p99 above {pct(memory)} for {minutes(MEMORY_POLICY, 'duration')} minutes "
               "pages; at the limit the container is killed (`run-oom`, the last panel of this row).", w=6, h=7,
               unit="percentunit", line=memory, soft_max=1),
        series("Instances (total, active, idle)", ds,
               [q(ceiling["metric"], REV, align=ceiling["aligner"], period="+" + ceiling["period"],
                  reduce=ceiling["reducer"], by=("service_name",), name="total", **me),
                q(RUN_INSTANCES, REV, align="ALIGN_MAX", by=("state",), **me)],
               f"{service}'s Cloud Run instances: the total, the most in each minute summed over active and idle, as "
               "the `ceiling-` policies read it, and active (serving or starting) and idle (kept warm, or waiting to "
               "be shut down) apart. " + per_environment(*(instance_words[env] for env in ENVIRONMENTS)), w=6, h=7,
               decimals=0, lines=instance_lines, soft_max=top),
        series("Concurrent requests, busiest instance (p99, p50)", ds,
               [q(RUN_CONCURRENCY, REV, align=f"ALIGN_PERCENTILE_{n}", period=window(CONCURRENCY_POLICY),
                  reduce=CONCURRENCY_POLICY["cross_series_reducer"], name=f"p{n}", **me) for n in (99, 50)],
               "The most requests one instance served at once (`container/max_request_concurrencies`), its 99th and "
               f"50th percentile in each {minutes(CONCURRENCY_POLICY)}-minute window. " +
               per_environment(*(busy_words[env] for env in ENVIRONMENTS)), w=6, h=7, lines=busy_lines,
               soft_max=slots),
        series("Start-up time (p99, p50)", ds,
               [q(RUN_STARTUP, REV, align=f"ALIGN_PERCENTILE_{n}", reduce="REDUCE_MAX", name=f"p{n}", **me)
                for n in (99, 50)],
               "How long a new instance took to start, until it was ready to serve (`container/startup_latencies`): a "
               "dot for each interval in which one started. Nothing drawn: no instance started. No policy reads it; a "
               "start-up that failed is the last panel.", w=8, h=7, unit="ms", points=True),
        series("Instances billed", ds, q(RUN_BILLABLE, REV, align="ALIGN_RATE", name="billed", **me),
               "Billable instance time per second (`container/billable_instance_time`): how many instances were billed "
               "on average. An instance kept warm with CPU always on bills all the time; one that scales to zero, "
               "only while it serves.", w=8, h=7, decimals=1),
        series("Killed for memory, crashed, failed to start", ds,
               [q(log("run_oom_kills"), REV, name="killed for memory", **me),
                q(log("run_crash_exits"), REV, name="crashed", **me),
                q(log("run_system_errors"), REV, name="failed probe or exit", **me)],
               "From Cloud Run's own system log: a container killed for exceeding its memory limit (`run_oom_kills`; "
               "`run-oom` pages on one), a container that exited with an error or a signal (`run_crash_exits`; "
               "`run-crash-loop` at three in fifteen minutes), and a failed start-up or liveness probe "
               "(`run_system_errors`; `canary-startup`).", w=8, h=7, bars=True),
    ]


def area_resources(page: str) -> list[dict]:
    """An area page's Resources: the note, then a shut row for each service SERVICES puts on the page (opened, its
    queries run; its own page has it open)."""
    return [row("Resources: each Cloud Run service's CPU, memory, instances, concurrency and start-up (open a row)"),
            text("No disk on a Cloud Run service", NO_DISK, w=24, h=3),
            *[p for service, (_ds, on) in SERVICES.items() if on == page for p in collapsed(resources(service))]]


def project_section(ds: str, where: str, gateway: str | None = None, through: str = "",
                    note: str = "") -> list[dict]:
    """A project's Cloud Run instances against its regional quota, and, where the project has one, its egress
    through Cloud NAT (`gateway`, the vpc module's `<network>-nat`; `through` names what leaves by it)."""
    quota = QUOTA_POLICY["threshold_value"]
    items = [row(f"The {where}: instances against the regional quota" +
                 (f", and egress through Cloud NAT ({gateway})" if gateway else "")),
             series("Cloud Run instances, every service", ds,
                    q(RUN_INSTANCES, REV, align=QUOTA_POLICY["per_series_aligner"], period=window(QUOTA_POLICY),
                      reduce=QUOTA_POLICY["cross_series_reducer"], name="every service"),
                    f"Every Cloud Run instance in the {where}, summed. The red line is `run-instances-near-quota`'s: "
                    f"above {quota:g} for {minutes(QUOTA_POLICY, 'duration')} minutes pages. The grey line is the "
                    f"regional quota, {REGIONAL_QUOTA}: at it no service can start another instance, whatever its "
                    "own ceiling." + note, w=4 if gateway else 24, h=7, decimals=0,
                    lines=[(quota, "red"), (REGIONAL_QUOTA, GREY)], soft_max=REGIONAL_QUOTA)]
    if not gateway:
        return items
    dropped, failed = NAT_DROPPED_POLICY, NAT_FAILED_POLICY
    by = ("gateway_name",)
    return items + [
        series("NAT ports: allocated, and the most in use", ds,
               [q(NAT_PORTS, NAT, align="ALIGN_MAX", by=by, name=alias("gateway_name", prefix="allocated · ")),
                q(NAT_PORTS_USED, NAT, align="ALIGN_MAX", reduce="REDUCE_MAX", by=by,
                  name=alias("gateway_name", prefix="most in use · "))],
               f"Cloud NAT's ports for {through}: the ports allocated to every instance behind the gateway "
               "(`nat/allocated_ports`), and the most connections one instance held to one destination "
               "(`nat/port_usage`). In use close to an instance's share of the allocated ports, new connections wait "
               "or drop. A cold gateway allocates ports as instances arrive, so the first calls after a quiet spell can "
               "wait.", w=5, h=7, decimals=0),
        series("NAT new connections", ds, q(NAT_CONNECTIONS, NAT, by=by, name=alias("gateway_name")),
               f"New connections Cloud NAT opened for {through} (`nat/new_connections_count`), per interval.", w=5,
               h=7, bars=True),
        series("NAT dropped packets", ds,
               [q(NAT_DROPPED_SENT, NAT, align=dropped["per_series_aligner"], period=window(dropped),
                  reduce=dropped["cross_series_reducer"], by=by, reason=NAT_OUT_OF_PORTS,
                  name=alias("gateway_name", prefix="sent, out of ports · ")),
                q(NAT_DROPPED_SENT, NAT, align=dropped["per_series_aligner"], period=window(dropped),
                  reduce=dropped["cross_series_reducer"], by=by, reason="ENDPOINT_INDEPENDENCE_CONFLICT",
                  name=alias("gateway_name", prefix="sent, endpoint conflict · ")),
                q(NAT_DROPPED_RECEIVED, NAT, align=dropped["per_series_aligner"], period=window(dropped),
                  reduce=dropped["cross_series_reducer"], by=by, name=alias("gateway_name", prefix="received · "))],
               f"Packets Cloud NAT dropped in each {minutes(dropped)} minutes. Sent, out of ports: an outgoing packet "
               f"with no port to leave by; the red line is `nat-port-exhaustion`'s, above {dropped['threshold_value']:g} "
               f"for {minutes(dropped, 'duration')} minutes. Sent, endpoint conflict: two instances reaching one "
               "destination from the same port. Received: replies with no open mapping (a connection already closed); "
               "a few are normal.", w=5, h=7, line=dropped["threshold_value"]),
        series("NAT could not allocate", ds,
               q(NAT_FAILED, NAT, align=failed["per_series_aligner"], period=window(failed),
                 reduce=failed["cross_series_reducer"], by=by, name=alias("gateway_name")),
               f"Minutes in each {minutes(failed)} in which Cloud NAT could not allocate an address or ports "
               f"(`nat/nat_allocation_failed`). The red line is `nat-port-exhaustion`'s: above "
               f"{failed['threshold_value']:g} pages.", w=5, h=7, decimals=0, line=failed["threshold_value"],
               soft_max=minutes(failed)),
    ]


def storage(ds: str, where: str) -> list[dict]:
    """A project's buckets: their size and how many objects they hold, never what the objects are."""
    return [
        row(f"Storage: the {where}'s buckets (size and object count)"),
        series("Bucket size", ds, q(GCS_BYTES, BUCKET, align="ALIGN_MEAN", period="+3600s", by=("bucket_name",)),
               f"Bytes stored in each of the {where}'s buckets, every storage class together "
               "(`storage/total_bytes`, measured every few minutes and reported up to twelve minutes late). Real disk, "
               "unlike a Cloud Run service's. No series: no bucket here holds anything yet.", w=12, h=7, unit="bytes"),
        series("Objects in each bucket", ds,
               q(GCS_OBJECTS, BUCKET, align="ALIGN_MEAN", period="+3600s", by=("bucket_name",)),
               "How many objects each bucket holds (`storage/object_count`). The bucket's name is the only label read: "
               "never an object's name.", w=12, h=7, decimals=0),
    ]


def database_rows(name: str, ds: str, who: str, *, now: bool = True) -> list[dict]:
    """One Cloud SQL instance's primitives: disk space (in use, and used against its size, with the `<name>-disk`
    line), up, CPU, memory, connections, disk operations and throughput, restarts and failed backups. On the Databases
    page (with the "Now" tile) and on the page of the area that owns it."""
    disk = CATALOGUE.threshold(f"{name}-disk", DB_ROLE[name])
    full = disk["threshold_value"]
    caps = limit("max_connections", name)
    connection_lines = {env: connections_lines(cap) + ([(cap, GREY)] if cap else []) for env, cap in caps.items()}
    cpu, saturated, memory = (SQL_POLICIES[n]["value"] for n in ("cpu-high", "cpu-saturated", "memory-high"))
    alert = f"alert line ({pct(full)} of size)"
    where = {"database_id": f"*:{name}"}
    wide = 10 if now else 12
    return [
        row(f"{name} ({who}): disk space, CPU, memory, connections, disk I/O"),
        *([db_stat("Now", ds, name, w=4, h=6)] if now else []),
        series("Disk space used (%)", ds,
               q(SQL_DISK, SQL, align=disk["per_series_aligner"], period=window(disk),
                 reduce=disk["cross_series_reducer"], by=("database_id",), name=f"{name} disk", **where),
               f"How full {name}'s disk is (`database/disk/utilization`), the mean of each {minutes(disk)} minutes. "
               f"The red line is `{name}-disk`'s: above {pct(full)} for {minutes(disk, 'duration')} minutes pages. "
               "Automatic storage increase grows the disk before it fills, up to the instance's "
               "disk_autoresize_limit; at that limit a full disk stops the database taking writes. " + STOPPED_DB,
               w=wide, h=6, unit="percentunit", line=full, soft_max=1),
        series("Disk space: used and size (bytes)", ds,
               [db_resource(SQL_DISK_BYTES, name, "used", align="ALIGN_MAX"),
                db_resource(SQL_DISK_SIZE, name, "size", align="ALIGN_MAX")],
               f"{name}'s disk in bytes: used (`database/disk/bytes_used`) and its size (`database/disk/quota`). When "
               "the size steps up, Cloud SQL's automatic storage increase grew the disk; it grows only up to "
               f"disk_autoresize_limit. The dashed red line is {pct(full)} of the size, where `{name}-disk` opens.",
               w=wide, h=6, unit="bytes",
               transformations=[{"id": "joinByField", "options": {"byField": "Time", "mode": "outer"}},
                                {"id": "calculateField", "options": {
                                    "mode": "binary", "alias": alert, "replaceFields": False,
                                    "binary": {"left": {"matcher": {"id": "byName", "options": f"{name} size"}},
                                               "operator": "*", "right": {"fixed": f"{full:g}"}}}}],
               overrides=[{"matcher": {"id": "byName", "options": alert}, "properties": [
                   {"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}},
                   {"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
                   {"id": "custom.fillOpacity", "value": 0}]}]),
        timeline("Up", ds, db_up(name), f"Cloud SQL's `database/up` for {name}, the lowest in each interval. "
                 f"`{name}-down` (urgent) pages below 1 for five minutes. " + STOPPED_DB, w=8, h=6,
                 mappings=UP_MAPPING, steps=thresholds("red", (1, "green"))),
        series("CPU", ds, sql_query("cpu-high", name, "CPU"),
               f"Cloud SQL's CPU utilisation for {name} (`database/cpu/utilization`), the mean of each five minutes, "
               f"as the monitoring module's policies read it. Their red lines: above {pct(cpu)} for thirty minutes, "
               f"and above {pct(saturated)} for fifteen (urgent).", w=8, h=6, unit="percentunit",
               lines=[(cpu, "red"), (saturated, "red")], soft_max=1),
        series("Memory", ds, sql_query("memory-high", name, "memory"),
               f"Cloud SQL's memory utilisation for {name} (`database/memory/utilization`), the mean of each five "
               f"minutes. The red line is the monitoring module's: above {pct(memory)} for fifteen minutes; past it "
               "PostgreSQL's out-of-memory killer restarts the server.", w=8, h=6, unit="percentunit", line=memory,
               soft_max=1),
        series("Connections", ds, sql_query("connections-high", name, "connections"),
               "Backends connected (num_backends, summed over the instance's databases), the mean of each minute, as "
               "the monitoring module's connection policies read it. " + per_environment(*(
                   f"Their red lines: above {connection_lines[env][0][0]:g} (80% of max_connections) for ten minutes, "
                   f"and above {connection_lines[env][1][0]:g} (95%) for five (urgent); max_connections is "
                   f"{caps[env]}, the grey line, where new connections are refused." if caps[env] else
                   "This environment does not build it, so no limit is drawn." for env in ENVIRONMENTS)),
               w=6, h=6, decimals=0, lines=connection_lines,
               soft_max={env: caps[env] for env in ENVIRONMENTS}),
        series("Disk operations per second", ds,
               [q(SQL_READ_OPS, SQL, align="ALIGN_RATE", by=(), name="read", **where),
                q(SQL_WRITE_OPS, SQL, align="ALIGN_RATE", by=(), name="write", **where)],
               f"{name}'s disk reads and writes per second (`database/disk/read_ops_count`, `write_ops_count`). Reads "
               "near none are normal: the working set is in memory.", w=6, h=6),
        series("Disk throughput", ds,
               [q(SQL_READ_BYTES, SQL, align="ALIGN_RATE", by=(), name="read", **where),
                q(SQL_WRITE_BYTES, SQL, align="ALIGN_RATE", by=(), name="write", **where)],
               f"Bytes {name} read from and wrote to its disk per second (`database/disk/read_bytes_count`, "
               "`write_bytes_count`).", w=6, h=6, unit="Bps"),
        series("Restarts and failed backups", ds,
               [q(log("sql_restarts"), SQL, by=(), name="restarts", **where),
                q(log("sql_backup_failures"), SQL, by=(), name="backup failed", **where)],
               "Postgres starting (`sql_restarts`: a crash, a maintenance or a resize restart) and an automated "
               "backup whose run ended in error (`sql_backup_failures`), counted from Cloud SQL's own logs.",
               w=6, h=6, bars=True),
    ]


def job_resources(ds: str, where: str, jobs: str | None = None) -> list[dict]:
    """A project's Cloud Run jobs (or those `jobs` matches): task attempts, how long each run's task ran, CPU,
    memory, and tasks killed for memory or failing to start."""
    mine = {"job_name": Re(jobs)} if jobs else {}
    return [
        row(f"Job resources: {where} (attempts, run length, CPU, memory)"),
        series("Task attempts, by job and result", ds, q(RUN_TASKS, JOB, by=("job_name", "result"), **mine),
               "Each task attempt that finished (`job/completed_task_attempt_count`), by job and result. A job here "
               "runs one task and no retry, so an attempt is a run.", w=8, h=7, bars=True),
        series("Tasks running, by job (each run's length)", ds,
               q(RUN_TASKS_RUNNING, JOB, align="ALIGN_MAX", by=("job_name",), **mine),
               "Task attempts running (`job/running_task_attempts`), the most in each interval: a run's bar lasts as "
               "long as its task ran. The module's `job-timeout-<job>` opens at 80% of a job's timeout.", w=8, h=7,
               bars=True, decimals=0),
        series("Killed for memory, or failed to start, by job", ds,
               [q(log("run_oom_kills"), JOB, by=("job_name",), name=alias("job_name", prefix="killed for memory · "),
                  **mine),
                q(log("run_system_errors"), JOB, by=("job_name",),
                  name=alias("job_name", prefix="failed probe or exit · "), **mine)],
               "A job's container killed for exceeding its memory limit (`run_oom_kills`; `run-oom` pages on one), or "
               "Cloud Run's system log at ERROR for it (`run_system_errors`; `canary-startup`).", w=8, h=7, bars=True),
        series("CPU, by job (p99)", ds,
               q(RUN_CPU, JOB, align="ALIGN_PERCENTILE_99", reduce="REDUCE_MAX", by=("job_name",), **mine),
               "Each job's container CPU, the share of its limit in use (`container/cpu/utilizations`), the 99th "
               "percentile in each interval while it runs. No policy reads a job's CPU: a slow job shows as a long "
               "bar above.", w=12, h=7, unit="percentunit", soft_max=1),
        series("Memory, by job (p99)", ds,
               q(RUN_MEMORY, JOB, align="ALIGN_PERCENTILE_99", reduce="REDUCE_MAX", by=("job_name",), **mine),
               "Each job's container memory, the share of its limit in use (`container/memory/utilizations`), the 99th "
               "percentile in each interval while it runs. At the limit the task is killed (`run-oom`).", w=12, h=7,
               unit="percentunit", soft_max=1),
    ]


def service_page(service: str) -> dict:
    """A service's own page: its requests, then its Resources row."""
    ds, page = SERVICES[service]
    left_out = service in LATENCY_LEFT_OUT
    items = [
        row(f"{service}: requests"),
        series("Requests, by status class", ds, requests(service, by=("response_code_class",)),
               f"Requests Cloud Run answered for {service} per interval. None: it serves no requests (a worker) or "
               "none came.", w=8, h=7, bars=True),
        series("5xx", ds, five_xx(service), f"{service}'s 5xx answers per interval. `canary-5xx` opens above 0.1% of "
               "its requests over five minutes (and five).", w=8, h=7, bars=True),
        series("p95 latency (Cloud Run)", ds, p95(service),
               f"{service}'s p95 request latency from Cloud Run. " +
               ("Beta's `canary-latency` leaves it out: it holds streams or calls open by design, so its p95 climbs "
                "while one is open." if left_out else "`canary-latency` opens above 2 s for ten minutes."),
               w=8, h=7, unit="ms", **({} if left_out else {"line": 2000})),
        text("No disk on a Cloud Run service", NO_DISK, w=24, h=3),
        *resources(service, own_page=True),
    ]
    return dashboard(service_uid(service), f"{service} (cloud service)",
                     f"{service}, on the {AREA_TITLES[page]} page, on its own: its requests, then its CPU, memory, "
                     "instances, concurrency and start-up, with the lines the pager uses. " + NOTHING_BUT_METRICS,
                     [page], items, kind=SERVICE_TAG,
                     links=({"title": AREA_TITLES[page], "type": "link", "url": f"/d/tw-cloud-{page}", "icon": "dashboard",
                             "keepTime": True, "includeVars": False, "targetBlank": False, "tags": [],
                             "asDropdown": False, "tooltip": f"The page {service} is on"},))


# ---- The pages -----------------------------------------------------------------------------------------------------
UPTIME_WORDING = per_environment(
    "Each check reads `/health` on a public host (the portal, auth and api hosts) from three US regions: a pass is the service answering through the load balancer and Cloud Armor. An outage pages when more than one region fails.",
    "Beta's hosts are behind IAP, so a check passes only on Google's sign-in page: it proves the address, the certificate, Cloud Armor and IAP, never the service behind them (that is the 5xx and instance panels). An outage pages when more than one region fails.")


def overview(cc: bool = True) -> dict:
    def area(name, ds, services, deps, p95_query, p95_desc, groups, fifth, jobs):
        return [
            row(name),
            stat("Requests (1 h)", ds, requests(services, "+300s"),
                 f"Requests Cloud Run answered in the last hour ({services.replace('|', ', ')}).", time_from="1h",
                 no_value="0"),
            stat("5xx (1 h)", ds, five_xx(services, "+300s"), "5xx answers in the last hour. `canary-5xx` opens "
                 "above 0.1% (and five); the urgent liveness policies when every answer for ten minutes was a 5xx.",
                 time_from="1h", no_value="0", steps=thresholds(NEUTRAL, (1, "orange"), (5, "red")), deps=deps),
            stat("p95 (1 h)", ds, p95_query, p95_desc, unit="ms", calc="max", time_from="1h",
                 no_value="no requests", steps=thresholds(NEUTRAL, (1000, "orange"), (2000, "red"))),
            groups, fifth, jobs]

    incidents = (
        "**Open incidents are in PagerDuty**, not here: [PagerDuty incidents](" + PAGERDUTY + "). "
        "Every Cloud Monitoring alert policy in a TPA project pages through it (urgent ones as high urgency). "
        "Google's own list, per project: "
        "[app](https://console.cloud.google.com/monitoring/alerting/incidents?project=__TPA_APP_PROJECT_ID__) · "
        "[member records](https://console.cloud.google.com/monitoring/alerting/incidents?project=__TPA_PHI_PROJECT_ID__)"
        + (" · [call centre](https://console.cloud.google.com/monitoring/alerting/incidents?project=__TPA_CC_PROJECT_ID__)"
           if cc else "") +
        " · [CRM](https://console.cloud.google.com/monitoring/alerting/incidents?project=__TPA_CRM_PROJECT_ID__).\n\n"
        "This site reads metrics only: Grafana's Cloud Monitoring datasource cannot list incidents. "
        + NOTHING_BUT_METRICS)
    areas = [a for a in AREAS if cc or a[0] != "cc"]
    span = 24 // len(areas)
    dbs = [(db, ds) for _k, _t, ds, _s, _j, db, _r, _c in areas]
    items = [
        row("Now: what is wrong, by project (TPA first)"),
        *[headline(*a, w=span) for a in areas],
        *[whats_wrong(*a, w=span) for a in areas],
        text("Open incidents", incidents, w=8, h=7),
        stat("Uptime checks passing (24 h)", APP,
             q(UPTIME, URL, align="ALIGN_FRACTION_TRUE", period="+3600s", reduce="REDUCE_MEAN", by=("host",)),
             "Share of uptime checks that passed in the last 24 h, by host. " + UPTIME_WORDING, w=8, h=7,
             calc="mean", value_size=32, time_from="24h", unit="percentunit", decimals=2,
             no_value="no uptime checks", text_mode="value_and_name",
             steps=thresholds(RED, (0.95, AMBER), (0.999, TEAL))),
        journeys_stat(),
        row("Beta, left to right: the way in → web → tpa-api → auth and records → their databases"),
        stat("portal · ops (15 m)", APP,
             q(UPTIME, URL, align="ALIGN_FRACTION_TRUE", period="+900s", reduce="REDUCE_MEAN", by=("host",)),
             "The way in: the share of uptime checks that passed in the last 15 minutes, by host. " + UPTIME_WORDING,
             w=4, h=4, calc="lastNotNull", time_from="15m", unit="percentunit", decimals=0,
             no_value="no uptime checks", text_mode="value_and_name",
             steps=thresholds(RED, (0.999, TEAL))),
        stat("inside (15 m)", APP,
             q(UPTIME, PRIVATE, align="ALIGN_FRACTION_TRUE", period="+900s", reduce="REDUCE_MEAN",
               by=("service_name",)),
             "Private uptime checks (D-149): Google's VPC checkers read auth's and tpa-api's /ready at their internal "
             "load balancers; tpa-api's /ready asks records, so records is covered from inside too. The share that "
             "passed in the last 15 minutes, by service. auth's leaves while auth-db is stopped on purpose. None: the "
             "inside checks are off (private_uptime_checks_enabled).", w=3, h=4, calc="lastNotNull",
             time_from="15m", unit="percentunit", decimals=0, no_value="off", text_mode="value_and_name",
             steps=thresholds(RED, (0.999, TEAL))),
        service_tile("web", APP, "web", SWEEP_DBS),
        service_tile("tpa-api", APP, "tpa-api", SWEEP_DBS),
        service_tile("auth", APP, AUTH_SERVICES, ("auth-db",)),
        service_tile("records", PHI, "records", ("tpa-db",)),
        service_tile("connectors", PHI, "connectors", ("tpa-db",)),
        row(("Call centre (svc-voice, svc-ops, relay, cc-db), " if cc else "") +
            "CRM (crm-web, engine, crm-db), and this site (watchtower)"),
        *([service_tile("svc-voice", CC, "svc-voice", ("cc-db",)), service_tile("svc-ops", CC, "svc-ops", ("cc-db",)),
           service_tile("relay", CC, "svc-twilio-rest", ("cc-db",)), db_tile("cc-db", CC)] if cc else []),
        service_tile("crm-web", CRM, "crm-web", ("crm-db",)), service_tile("engine", CRM, "engine", ("crm-db",)),
        db_tile("crm-db", CRM),
        service_tile("watchtower", APP, "watchtower"),
        row("Databases now: up, CPU, memory, disk, connections"),
        *[db_resources(db, ds, w=span) for db, ds in dbs],
        row("Scheduled runs: a successful run within each job's deadline"),
        *deadline_stats(w=4, h=4),
        *area("Portal & API (web, tpa-api, model-gateway; tpa-jobs)", APP, WEB_API, SWEEP_DBS, tpa_api_p95("+3600s"),
              "tpa-api's own p95 time to answer (its request line, without the streams, the file transfers and the "
              "model-backed rows): `tpa-api-latency` opens above 2 s for ten minutes. Cloud Run's own p95 for web "
              "and tpa-api counts the desk's 40-second streams, so it is on the Portal & API page only.",
              groups_stat("Error groups (24 h)", APP,
                          error_counts("errors", ("service", "class", "operation", "code"), "+86400s", groups=True),
                          "errors", SWEEP_DBS),
              stat("Instances now", APP, instances(APP_SERVICES, "+60s"), "Cloud Run instances per service. Zero "
                   "is how a scale-to-zero service idles; a service kept warm with none is the urgent `no instance` "
                   "policy. The link by the title opens each service's own page.", calc="lastNotNull",
                   time_from="15m", no_value="0", links=service_links(*APP_SERVICES.split("|"))),
              jobs_stat("tpa-jobs (24 h)", APP, TPA_JOBS, TPA_SCHEDULES, SWEEP_DBS)),
        *area("Sign-in (auth, its messenger and jobs)", APP, AUTH_SERVICES, ("auth-db",), p95("auth", "+3600s"),
              "auth's p95 request latency from Cloud Run. `canary-latency` opens above 2 s for ten minutes.",
              groups_stat("Error groups (24 h)", APP,
                          error_counts("auth_errors", ("class", "operation", "code"), "+86400s", groups=True),
                          "auth_errors", ("auth-db",)),
              db_stat("auth-db", APP, "auth-db"),
              jobs_stat("auth jobs (24 h)", APP, AUTH_JOBS, AUTH_SCHEDULES, ("auth-db",))),
        *area("Member records (records, connectors)", PHI, PHI_SERVICES, ("tpa-db",), p95("records", "+3600s"),
              "records' p95 request latency from Cloud Run. `canary-latency` opens above 2 s for ten minutes.",
              groups_stat("Error groups (24 h)", PHI,
                          error_counts("errors", ("service", "class", "operation", "code", "sqlstate"), "+86400s",
                                       groups=True), "errors", ("tpa-db",)),
              db_stat("tpa-db", PHI, "tpa-db"),
              jobs_stat("Jobs (24 h)", PHI, PHI_JOBS, PHI_SCHEDULES, ("tpa-db",))),
        *(area("Call centre (svc-voice, svc-ops, relay)", CC, CC_SERVICES, ("cc-db",), p95("svc-twilio-rest", "+3600s"),
              "The relay's p95 request latency. svc-voice holds a call's socket for up to an hour and svc-ops the "
              "desk's streams, so their latency is left out, as `canary-latency` leaves them out.",
              groups_stat("Error groups (24 h)", CC, error_counts("errors", ("class",), "+86400s", groups=True),
                          "errors", ("cc-db",)),
              db_stat("cc-db", CC, "cc-db"),
              jobs_stat("migrate-cc (24 h)", CC, "migrate-cc", None, ("cc-db",))) if cc else []),
        *area("CRM (crm-web, engine)", CRM, CRM_SERVICES, ("crm-db",), p95(CRM_SERVICES, "+3600s"),
              "The CRM's p95 request latency from Cloud Run. `canary-latency` opens above 2 s for ten minutes.",
              groups_stat("Error groups (24 h)", CRM, crm_errors("+86400s", groups=True),
                          "crm_errors (beta) or errors", ("crm-db",)),
              db_stat("crm-db", CRM, "crm-db"),
              jobs_stat("CRM jobs (24 h)", CRM, CRM_JOBS, None, ("crm-db",))),
    ]
    return dashboard("tw-cloud-overview", "TPA overview (cloud)",
                     "Home: what is wrong now in each project (TPA first), the way through beta, the databases, the "
                     "synthetic journeys and the scheduled runs, read from Cloud Monitoring. " + NOTHING_BUT_METRICS,
                     ["overview"], items)


def portal_api() -> dict:
    items = [
        row("Way in"),
        series("Uptime checks passing, by host", APP,
               q(UPTIME, URL, align="ALIGN_FRACTION_TRUE", reduce="REDUCE_MEAN", by=("host",)),
               "Share of checker regions passing, by host. " + UPTIME_WORDING, unit="percentunit"),
        series("IAP assertions refused, and stale pinned keys", APP,
               [q(log("iap_unknown_key"), REV, by=("service_name",), name=alias("service_name", prefix="refused: ")),
                q(log("iap_pinned_keys_stale"), REV, by=("service_name",),
                  name=alias("service_name", prefix="keys stale: "))],
               "auth's or tpa-api's refusals of an IAP assertion under a key the image does not pin (urgent "
               "`iap-unknown-key`: most likely Google rotated IAP's keys), and the image's own warning that its keys "
               "are stale. Silent while beta runs with the header check off (R302).", bars=True),
        row("Requests"),
        series("Requests, by service and status class", APP,
               requests(WEB_API, by=("service_name", "response_code_class")),
               "Requests Cloud Run answered per interval.", bars=True),
        series("5xx, by service", APP, five_xx(WEB_API),
               "5xx answers per interval. `canary-5xx` opens above 0.1% of a service's requests over five minutes "
               "(and five); `backend-down` (urgent) when everything web, auth or tpa-api answered for ten minutes was "
               "a 5xx.", bars=True),
        series("p95 latency, by service (Cloud Run)", APP, p95(WEB_API),
               "Cloud Run's p95 request latency. web and tpa-api relay the desk's event streams, held open about "
               "40 s by design, so theirs climbs whenever a desk page is open; beta's `canary-latency` leaves both "
               "out. tpa-api's real latency is the next panel.", unit="ms", line=2000),
        series("tpa-api p50 and p95 (its own request line)", APP,
               [q(log("tpa_api_latency"), REV, align="ALIGN_PERCENTILE_95", reduce="REDUCE_MAX", name="p95"),
                q(log("tpa_api_latency"), REV, align="ALIGN_PERCENTILE_50", reduce="REDUCE_MAX", name="p50")],
               "Time to the first byte from tpa-api's request line, without the live lane, the Ask lanes, uploads, "
               "downloads and the model-backed document rows (`tpa_api_latency`). `tpa-api-latency` opens above 2 s "
               "for ten minutes.", unit="ms", line=2000),
        table("tpa-api calls, by operation and outcome", APP,
              q(log("tpa_api_requests"), REV, by=("operation", "outcome", "status_class")),
              "tpa-api's request lines in the time range, by the operation the route called, its outcome and "
              "status class (`tpa_api_requests`). Never the filled path, the tenant or the session.",
              columns={"operation": "Operation", "outcome": "Outcome", "status_class": "Status class"}),
        series("tpa-api outcomes", APP, q(log("tpa_api_requests"), REV, by=("outcome",)),
               "tpa-api's request lines per interval, by outcome.", bars=True),
        series("Model gateway: vendor answers that failed, by kind", APP,
               q(log("model_gateway_calls"), REV, by=("code",)),
               "model-gateway's calls to the model vendor that came back as an error, busy, unavailable or rejected "
               "(`model_gateway_calls`; `model-vendor-errors`). Silent while model-gateway is not built.", bars=True),
        *area_resources("portal-api"),
        *project_section(APP, "app project", "app-net-nat",
                         "auth's messenger, the model gateway and the synthetic journeys"),
        row("Instances and start-up"),
        series("Instances, by service", APP, instances(APP_SERVICES),
               "Cloud Run instances per service (the most in each interval). A warm service with none pages as "
               "`no instance` (urgent)."),
        series("Start-up or runtime failures, and database proxy refusals", APP,
               [q(log("run_system_errors"), REV, by=("service_name",), service_name=Re(APP_SERVICES),
                  name=alias("service_name", prefix="system: ")),
                q(log("sql_proxy_errors"), REV, by=("service_name",), service_name=Re(APP_SERVICES),
                  name=alias("service_name", prefix="sql proxy: "))],
               "Cloud Run's system log at ERROR (a failed probe, an exit, a memory limit: `canary-startup`) and the "
               "Cloud SQL Auth Proxy's refusals (`canary-sql`), for these services.", bars=True),
        row("Background work (tpa-jobs)"),
        series("Run summaries, by job", APP, q(log("tpa_jobs_runs"), by=("job",)),
               "One per scheduled run and per drain tick (`tpa_jobs_runs`). A drain that stops writing them has "
               "stopped.", bars=True),
        table("Alerts raised by runs", APP, q(log("tpa_jobs_alerts"), by=("job", "code")),
              "Alert records the runs raised in the time range, by job and the registry's alert name "
              "(`jobs-alerts`; `anomaly_freeze`, `crm_signature_failure` and `member_access_mass_end` page as "
              "urgent). The record's tenant and detail are never read.", columns={"job": "Job", "code": "Alert"}),
        series("Drain ticks that raised", APP, q(log("tpa_jobs_drain_raised"), REV, by=("job", "class")),
               "A tick of tpa-jobs-drains that raised instead of finishing (`drain-raised`), by drain and exception "
               "class. The loop keeps ticking and delivers nothing until it is fixed.", bars=True),
    ]
    return dashboard("tw-cloud-portal-api", "Portal & API (cloud)",
                     "web, tpa-api and model-gateway in the app project, the way in, and tpa-jobs' background work.",
                     ["portal-api"], items)


def sign_in() -> dict:
    items = [
        row("Sign-in"),
        series("Requests, by service and status class", APP,
               requests(AUTH_SERVICES, by=("service_name", "response_code_class")),
               "Requests Cloud Run answered per interval for auth and its messenger.", bars=True),
        series("p95 latency (Cloud Run)", APP, p95(AUTH_SERVICES),
               "auth's p95 request latency. `canary-latency` opens above 2 s for ten minutes.", unit="ms", line=2000),
        series("Refused sign-ins and lockouts", APP,
               [q(log("auth_login_failures"), REV, name="401 refused"), q(log("auth_lockouts"), REV, name="423 locked")],
               "Password sign-ins refused with 401 (`auth_login_failures`) and answers of `423 locked` "
               "(`auth_lockouts`; `auth-lockouts` opens above 20 in five minutes: credential stuffing, most often).",
               bars=True),
        series("Not ready, by the check that failed", APP, q(log("auth_not_ready"), REV, by=("code",)),
               "auth's `/ready` refusing, by its first failed check. `database` pages as `auth-database` (urgent: "
               "nobody can sign in).", bars=True),
        series("Answered 500 (unhandled), by class", APP,
               q(log("auth_errors"), REV, by=("class",), operation="unhandled"),
               "An exception that reached auth's catch-all handler (`auth-unhandled`), by exception class.",
               bars=True),
        db_stat("auth-db", APP, "auth-db", w=4, h=8),
        series("5xx, by service", APP, five_xx(AUTH_SERVICES),
               "5xx answers per interval. `backend-down` (urgent) opens when everything auth answered for ten "
               "minutes was a 5xx.", bars=True, w=8),
        *area_resources("sign-in"),
        *database_rows("auth-db", APP, "auth and its jobs; app project", now=False),
        row("Sign-in messages"),
        series("Oldest unsent message (p99, seconds)", APP,
               q(log("auth_messages_outbox_lag"), REV, align="ALIGN_PERCENTILE_99", reduce="REDUCE_MAX", name="p99"),
               "How long the oldest unsent sign-in text or email has waited, as the messenger reads it every five "
               "seconds while one waits (`auth-messages-lag` opens above 30 s for two minutes). It counts emails "
               "too, so one email on its retry ladder opens it. Empty until auth-notary's messenger writes JSON "
               "(docs/infra/monitoring.md §6).", unit="s", line=30),
        series("Message vendor refusals, by lane and reason", APP,
               q(log("auth_message_vendor_failures"), REV, by=("lane", "code")),
               "Sign-in texts or emails the vendor would not take, by channel and the messenger's reason "
               "(`auth_message_vendor_failures`; `sign-in-message-vendor`).", bars=True),
        series("Messenger instances", APP, instances("auth-outbox-publisher"),
               "auth-outbox-publisher's instances. With none, no sign-in message is sent: `auth-messages-lag` opens "
               "on that too."),
        row("Audit and credentials"),
        series("Credential or workload tags that failed at use", APP,
               q(log("auth_credential_tag_invalid"), by=("code", "gate"),
                 name=alias("code") + " at " + alias("gate")),
               "A stored factor, workload, key or bearer row whose tag failed when a door used it, by kind and door "
               "(`audit-credential-tag`, urgent: forgery or tampering until shown otherwise).", bars=True),
        series("Membership reconcile: runs, and runs not clean", APP,
               [q(log("auth_audit_reconciled"), JOB, name="runs"),
                q(log("auth_audit_reconcile_outcomes"), JOB, by=("code",), name=alias("code", prefix="not clean: "))],
               "The auth-sweeper job's heartbeat, one per run (`audit-reconcile` pages when it is absent 90 "
               "minutes), and the runs that were not clean, by result.", bars=True),
        series("Reconcile findings and new chain breaks", APP,
               [q(log("auth_audit_reconcile_findings"), JOB, by=("code",), name=alias("code", prefix="finding: ")),
                q(log("auth_audit_chain_breaks_new"), JOB, by=("code",), name=alias("code", prefix="new break: "))],
               "What the membership reconcile found (by kind) and audit-chain breaks it had not paged before (by "
               "check). Both page as `audit-reconcile` (urgent).", bars=True),
        series("audit verify printed BREAK", APP, q(log("auth_audit_break"), JOB, by=("job_name",)),
               "`auth audit verify` printing a break (`audit-chain`, urgent). Only the line's prefix is matched.",
               bars=True),
        row("auth's jobs"),
        series("Executions, by job and result", APP, executions(AUTH_JOBS),
               "Completed executions of auth's jobs per interval. A failed one opens `jobs-failed`, or the urgent "
               "`audit-chain` for the audit jobs.", bars=True),
        series("Schedules that could not start their job", APP, schedule_failures(AUTH_SCHEDULES),
               "Cloud Scheduler attempts for auth's schedules that finished in error, by schedule and status.",
               bars=True),
    ]
    return dashboard("tw-cloud-sign-in", "Sign-in (cloud)",
                     "auth, its messenger and its jobs in the app project: sign-in health, messages, audit.",
                     ["sign-in"], items)


def records() -> dict:
    items = [
        row("The Records Gateway"),
        series("Requests, by status class", PHI, requests("records", by=("response_code_class",)),
               "Requests Cloud Run answered per interval. A refusal is a 4xx.", bars=True),
        series("p95 latency (Cloud Run)", PHI, p95("records"),
               "records' p95 request latency. `canary-latency` opens above 2 s for ten minutes.", unit="ms",
               line=2000),
        series("Refusals, by gate and code", PHI,
               q(log("records_refusals"), REV, by=("gate", "code"), name="gate " + alias("gate", "code")),
               "Every refusal the gateway answered, by gate and CONTRACT §7 code (`records_refusals`).", bars=True),
        table("Refusals, by gate, code and operation", PHI,
              q(log("records_refusals"), REV, by=("gate", "code", "operation")),
              "Refusals in the time range, by gate, code and catalogue operation.",
              columns={"gate": "Gate", "code": "Code", "operation": "Operation"}),
        series("Audit flush failed, or database unreachable", PHI, q(log("records_critical"), by=("code",)),
               "The two lines that mean the gateway is failing its promise (`records-critical`, urgent): a "
               "refusal's audit rows did not land, or tpa-db did not answer. From the service or a job.", bars=True),
        series("Rate limited, by operation", PHI, q(log("records_rate_limited"), REV, by=("operation",)),
               "Gate 8's rate limiter refusing a call (`records_rate_limited`).", bars=True),
        series("Mirror warnings and errors, by gate", PHI,
               q(log("records_mirror_problems"), REV, by=("gate",), name="gate " + alias("gate")),
               "The mirror's warnings and errors: gate 2 is the JWKS fetch, gate 3 the event and revocation feeds "
               "(`records_mirror_problems`).", bars=True),
        series("Database connection errors", PHI,
               [q(log("errors"), REV, by=("sqlstate",), sqlstate=Re("08.*"),
                  name=alias("sqlstate", prefix="SQLSTATE ")),
                q(log("sql_proxy_errors"), name="sql proxy refusals")],
               "records lines with a class-08 SQLSTATE (`records-sql-errors`) and the Cloud SQL Auth Proxy's own "
               "refusals in this project, services and jobs (`canary-sql`).", bars=True),
        series("Instances, and start-up or runtime failures", PHI,
               [instances(PHI_SERVICES), q(log("run_system_errors"), name="system log errors")],
               "Cloud Run instances of records and connectors, and Cloud Run's system log at ERROR in this project "
               "(`canary-startup`)."),
        db_stat("tpa-db", PHI, "tpa-db", w=4, h=8),
        series("5xx", PHI, five_xx("records"),
               "records' 5xx answers per interval. `records-down` (urgent) opens when everything it answered for ten "
               "minutes was a 5xx.", bars=True, w=8),
        *area_resources("records"),
        *database_rows("tpa-db", PHI, "records and its jobs; PHI project", now=False),
        *project_section(PHI, "PHI project", "phi-net-nat", "connectors' messages"),
        *storage(PHI, "PHI project"),
        row("Audit chain"),
        series("records-chain-head: executions and schedule", PHI,
               [executions("records-chain-head", by=("result",)),
                schedule_failures("records-chain-head", by=("code",),
                                  name=alias("code", prefix="schedule failed: "))],
               "Each closed day's chain head written to the vault. A failed execution or schedule pages as "
               "`audit-chain` (urgent).", bars=True),
        series("A chain head was already in the vault", PHI,
               q(log("records_chain_head_exists"), JOB, name="already there"),
               "The chain-head job found the latest day's head already written on its first attempt "
               "(`chain-head-exists`, normal): written before it (O137), a person's rerun, or the autumn clock "
               "change.", bars=True),
        row("Connectors"),
        series("Delivery passes (the loop's heartbeat)", PHI, q(log("connectors_passes"), REV, name="passes"),
               "One per pass of the delivery loop, its line matched whole. None for five minutes pages as "
               "`connectors-stalled`.", bars=True),
        series("Deliveries, by lane and outcome", PHI, q(log("connectors_deliveries"), REV, by=("lane", "outcome")),
               "One per send attempt (`connectors_deliveries`). The destination is not a label.", bars=True),
        series("Dead letters, refused destinations, unsigned envelopes", PHI,
               [q(log("connectors_dead_letters"), REV, by=("code",), name=alias("code", prefix="dead: ")),
                q(log("connectors_deliveries"), REV, by=("lane", "code"),
                  code=Re("destination_refused|envelope_unsigned"), name=alias("code", "lane"))],
               "A row settled dead (`connectors-dead-letters`), a destination outside the allowlist "
               "(`connectors-destination-refused`) and a claimed row with no signature "
               "(`connectors-envelope-unsigned`).", bars=True),
        row("Perimeter and alert changes"),
        series("Perimeter violations", PHI,
               q(log("perimeter_violations"), AUDITED, by=("code", "service", "outcome"),
                 name=alias("code", "service") + " dry run " + alias("outcome")),
               "VPC Service Controls violations logged in this project, by reason, service and whether it was a dry "
               "run (`perimeter-violations`).", bars=True),
        series("Alert, snooze and log-counter changes", PHI,
               [q(log("monitoring_changes"), by=("operation",)), q(log("log_metric_changes"), by=("operation",))],
               "Changes to this project's alert policies, notification channels or snoozes (`monitoring-changed`, "
               "D-137) and to its log-based counters (`log-counters-changed`, D-141), from the Admin Activity log, "
               "by method. The entry says who and what. No resource type is named: the catalogue has not yet "
               "confirmed which resource Google writes these on.", bars=True),
        row("Protected jobs"),
        series("Executions, by job and result", PHI, executions(PHI_JOBS),
               "The migration, the nightly export, the chain head, beta's seed and the quarterly restore drill.",
               bars=True),
        series("Schedules that could not start their job", PHI, schedule_failures(PHI_SCHEDULES),
               "Cloud Scheduler is outside the perimeter's restricted services: a refusal here may be the perimeter.",
               bars=True),
    ]
    return dashboard("tw-cloud-records", "Member records (cloud)",
                     "records, connectors and their jobs in the PHI project, read with `cloud-phi` alone. Health "
                     "numbers only: no member data reaches a metric. " + NOTHING_BUT_METRICS, ["records"], items)


def call_centre() -> dict:
    items = [
        row("Services"),
        series("Requests, by service and status class", CC,
               requests(CC_SERVICES, by=("service_name", "response_code_class")),
               "Requests Cloud Run answered per interval. A refused webhook signature is a 4xx.", bars=True),
        series("5xx, by service", CC, five_xx(CC_SERVICES),
               "5xx answers per interval. `voice-down` (urgent) opens when everything svc-voice answered for ten "
               "minutes was a 5xx.", bars=True),
        series("Relay p95 latency", CC, p95("svc-twilio-rest"),
               "svc-twilio-rest's p95. svc-voice (a call's socket, up to an hour) and svc-ops (the desk's streams) "
               "are left out, as `canary-latency` leaves them out.", unit="ms", line=2000),
        series("Instances, by service", CC, instances(CC_SERVICES),
               "Cloud Run instances. svc-voice is kept warm: none for five minutes pages as `no instance`."),
        series("Errors, by class", CC, error_counts("errors", ("class",)),
               "call-center's lines at ERROR, by the class a whole last line of the redacted traceback opens with "
               "(`errors`; new-group and spike policies).", bars=True),
        series("Start-up or runtime failures, and database proxy refusals", CC,
               [q(log("run_system_errors"), name="system log errors"),
                q(log("sql_proxy_errors"), name="sql proxy refusals")],
               "`canary-startup` and `canary-sql` in the call-centre project.", bars=True),
        *area_resources("callcentre"),
        *database_rows("cc-db", CC, "the staffed desk and svc-voice's hand-off ledger", now=False),
        *project_section(CC, "call-centre project", "cc-net-nat",
                         "the relay's calls to the telephony vendor and svc-voice's to the model"),
        row("Database and migration"),
        db_stat("cc-db", CC, "cc-db", w=6, h=7),
        series("migrate-cc executions", CC, executions("migrate-cc"),
               "cc-db's schema migration, run by a person (staffed desk only). A failure opens `jobs-failed`.",
               bars=True, w=18, h=7),
    ]
    return dashboard("tw-cloud-callcentre", "Call centre (cloud)",
                     "Beta's call-centre project: svc-voice, svc-ops, the relay, cc-db. production-full has no "
                     "call-centre project, so this page is empty there.", ["callcentre"], items)


def crm() -> dict:
    items = [
        row("Services"),
        series("Uptime check passing", CRM,
               q(UPTIME, URL, align="ALIGN_FRACTION_TRUE", reduce="REDUCE_MEAN", by=("host",), host="crm.*"),
               "The CRM host's check (beta, once its certificate is active and `crm_uptime_check_enabled` is on). "
               "Behind IAP it passes on Google's sign-in page.", unit="percentunit"),
        series("Requests, by service and status class", CRM,
               requests(CRM_SERVICES, by=("service_name", "response_code_class")),
               "Requests Cloud Run answered per interval.", bars=True),
        series("5xx, by service", CRM, five_xx(CRM_SERVICES), "5xx answers per interval.", bars=True),
        series("p95 latency, by service", CRM, p95(CRM_SERVICES),
               "Cloud Run's p95 request latency. `canary-latency` opens above 2 s for ten minutes.", unit="ms",
               line=2000),
        series("Instances, by service", CRM, instances(CRM_SERVICES), "Cloud Run instances."),
        series("Errors, by class" if CRM_CLASS else "Errors, by service", CRM, crm_errors(),
               "The CRM's lines at ERROR. Beta counts them as `crm_errors` (the CRM shares the app project); a CRM "
               "project of its own as `errors`." + CRM_CLASS_NOTE, bars=True),
        series("Start-up or runtime failures, and database proxy refusals", CRM,
               [q(log("run_system_errors"), REV, by=("service_name",), service_name=Re(CRM_SERVICES),
                  name=alias("service_name", prefix="system: ")),
                q(log("run_system_errors"), JOB, by=("job_name",), job_name=Re(CRM_JOBS),
                  name=alias("job_name", prefix="system: ")),
                q(log("sql_proxy_errors"), REV, by=("service_name",), service_name=Re(CRM_SERVICES),
                  name=alias("service_name", prefix="sql proxy: ")),
                q(log("sql_proxy_errors"), JOB, by=("job_name",), job_name=Re(CRM_JOBS),
                  name=alias("job_name", prefix="sql proxy: "))],
               "`canary-startup` and `canary-sql` for the CRM's services and jobs (beta's are in the app project).",
               bars=True),
        *area_resources("crm"),
        *database_rows("crm-db", CRM, "the CRM; the app project in beta", now=False),
        *project_section(CRM, "CRM's project", note=" In beta the CRM runs in the app project, so every app service "
                         "counts here too."),
        row("Database and jobs"),
        db_stat("crm-db", CRM, "crm-db", w=6, h=7),
        series("CRM job executions", CRM, executions(CRM_JOBS),
               "The CRM's migration and made-up data seed, each run by a person. A failure opens `jobs-failed` "
               "(`crm-jobs-failed` in beta).", bars=True, w=18, h=7),
    ]
    return dashboard("tw-cloud-crm", "CRM (cloud)",
                     "crm-web, engine and crm-db. In beta the CRM runs in the app project (R282), which `cloud-crm` "
                     "then reads.", ["crm"], items)


def errors(cc: bool = True) -> dict:
    run = {"service_name": "Cloud Run service", "job_name": "Cloud Run job"}

    def section(name, ds, metric, labels, columns):
        return [row(name),
                table(f"Error groups in the time range ({metric})", ds, error_counts(metric, labels),
                      f"Every error group of `{metric}` in the time range: the Cloud Run service or job, then the "
                      "counter's labels, and its ERROR lines. A line carries an exception's class and never its "
                      "message or a stack trace. A group new in the last hour (absent the 23 before) opens the "
                      "`new error group` policy.", columns={**run, **columns}, w=16, h=9),
                series("ERROR lines, by service or job", ds,
                       [q(log(metric), REV, by=("service_name",)), q(log(metric), JOB, by=("job_name",))],
                       f"`{metric}` per interval. A group's hour above 5 times its 23-hour mean (and 10) opens the "
                       "`error spike` policy.", bars=True, w=8, h=9)]

    items = [
        *section("App tier: tpa-api, tpa-jobs, drains, model-gateway (app project)", APP, "errors",
                 ("service", "class", "operation", "code"),
                 {"service": "Service", "class": "Class", "operation": "Operation", "code": "Code"}),
        *section("Sign-in: auth, its messenger and jobs (app project)", APP, "auth_errors",
                 ("class", "operation", "code"), {"class": "Class", "operation": "Event", "code": "Code"}),
        *section("Member records: records, its jobs, connectors (PHI project)", PHI, "errors",
                 ("service", "class", "operation", "code", "sqlstate"),
                 {"service": "Service", "class": "Class", "operation": "Operation", "code": "Code",
                  "sqlstate": "SQLSTATE"}),
        *(section("Call centre (call-centre project)", CC, "errors", ("class",), {"class": "Class"}) if cc else []),
        row("CRM"),
        table("Error groups in the time range (crm_errors or errors)", CRM, crm_errors(),
              "The CRM's error groups: the service" + (" and the exception class" if CRM_CLASS else "") +
              ". Beta counts them as `crm_errors`." + CRM_CLASS_NOTE,
              columns={"service_name": "Cloud Run service", **({"class": "Class"} if CRM_CLASS else {})}, w=16, h=9),
        series("ERROR lines, by service", CRM, crm_errors(by=("service_name",)),
               "The CRM's ERROR lines per interval.", bars=True, w=8, h=9),
        row("Crashes, out-of-memory kills, and secret or key versions taken away"),
        *[series(f"{where}", ds,
                 [q(log("run_crash_exits"), REV, by=("service_name",), name=alias("service_name", prefix="crashed: ")),
                  q(log("run_oom_kills"), REV, by=("service_name",), name=alias("service_name", prefix="OOM: ")),
                  q(log("run_oom_kills"), JOB, by=("job_name",), name=alias("job_name", prefix="OOM: ")),
                  q(log("secret_version_changes"), None, by=("operation",), name=alias("operation", prefix="secret: ")),
                  q(log("kms_version_changes"), None, by=("operation",), name=alias("operation", prefix="key: "))],
                 "Cloud Run containers that exited non-zero or by a signal other than SIGTERM and SIGKILL "
                 "(`run_crash_exits`; `run-crash-loop`), killed for memory (`run_oom_kills`; `run-oom`), and a Secret "
                 "Manager or KMS key version disabled or destroyed (Admin Activity audit log; `secret-version-disabled`, "
                 "`kms-version-disabled` urgent): each breaks what reads it at its next deploy or restart. By the "
                 "method alone; who and which stay in the entry.", bars=True, w=24 // (4 if cc else 3), h=7)
          for where, ds in (("App project", APP), ("PHI project", PHI), *((("Call-centre project", CC),) if cc else ()),
                            ("CRM", CRM))],
    ]
    return dashboard("tw-cloud-errors", "Errors (cloud)",
                     "Error groups from the log-based error counters, by the labels the catalogue allows: the "
                     "service, the exception class, the operation or event, the code and the SQLSTATE. Nothing "
                     "else.", ["errors"], items, time="now-24h")


def databases(cc: bool = True) -> dict:
    items = []
    for name, ds, who in (("auth-db", APP, "auth and its jobs; app project"),
                          ("tpa-db", PHI, "records and its jobs; PHI project"),
                          ("crm-db", CRM, "the CRM; the app project in beta"),
                          *((("cc-db", CC, "the call centre's staffed desk and svc-voice's hand-off ledger"),)
                            if cc else ())):
        items += database_rows(name, ds, who)
    return dashboard("tw-cloud-databases", "Databases (cloud)",
                     f"The {'four' if cc else 'three'} Cloud SQL instances: disk space (used, and used against the "
                     "disk's size), up, CPU, memory, connections, disk operations and throughput, restarts and failed "
                     "backups. " + STOPPED_DB, ["databases"], items, time="now-24h")


def jobs(cc: bool = True) -> dict:
    items = [
        row("Scheduled runs: a successful run within each job's deadline"),
        *deadline_stats(w=4, h=4),
        row("App project jobs (tpa-jobs, auth)"),
        series("Successful executions, by job", APP, executions(result="succeeded", by=("job_name",)),
               "A gap where a job's cadence says a run should be is a missed run.", bars=True),
        series("Failed executions, by job", APP, executions(result="failed", by=("job_name",)),
               "Executions that failed after their retries (`jobs-failed`; `audit-chain` for the audit jobs, "
               "urgent). For tpa-jobs a failed run is any tenant not `ok`.", bars=True),
        series("Schedules that could not start their job", APP, schedule_failures(),
               "Cloud Scheduler attempts that finished in error, by schedule and status (`scheduler-failed`). "
               "PERMISSION_DENIED means an invoker binding is not what the gate thinks.", bars=True),
        series("Run summaries, by job", APP, q(log("tpa_jobs_runs"), JOB, by=("job",)),
               "One per tpa-jobs scheduled run (`tpa_jobs_runs`); the drains' ticks are on the Portal & API page.",
               bars=True),
        table("Alerts raised, by job", APP, q(log("tpa_jobs_alerts"), JOB, by=("job", "code")),
              "Alert records the scheduled runs raised in the time range (`jobs-alerts`; the paging ones urgent; "
              "two `tenants_partial` in a day `jobs-partial-recurring`).", columns={"job": "Job", "code": "Alert"}),
        series("Reconciliations left open per tenant", APP,
               [q(log("tpa_jobs_accumulator_backlog"), JOB, align="ALIGN_MEAN", reduce="REDUCE_MAX", by=("job",),
                  name=alias("job", prefix="mean: ")),
                q(log("tpa_jobs_accumulator_backlog"), JOB, align="ALIGN_PERCENTILE_99", reduce="REDUCE_MAX",
                  by=("job",), name=alias("job", prefix="largest (p99): "))],
               "The outstanding reconciliations accumulator_reconcile left open, one point per tenant per run. "
               "`accumulator-backlog-growing` opens when tonight's total is above last night's."),
        row("PHI project jobs"),
        series("Executions, by job and result", PHI, executions(PHI_JOBS),
               "migrate-tpa, seed-tpa, tpa-db-export, records-chain-head and the restore drill.", bars=True),
        series("Schedules that could not start their job", PHI, schedule_failures(PHI_SCHEDULES),
               "`scheduler-failed` in the PHI project; `audit-chain` for the chain head.", bars=True),
        row("Call centre and CRM jobs" if cc else "CRM jobs"),
        *([series("migrate-cc", CC, executions("migrate-cc"), "cc-db's migration, run by a person.", bars=True)]
          if cc else []),
        series("migrate-crm and seed-crm", CRM, executions(CRM_JOBS), "The CRM's jobs, each run by a person.",
               bars=True),
        *job_resources(APP, "app project (tpa-jobs, auth's jobs, the synthetic journeys; the CRM's in beta)"),
        *job_resources(PHI, "PHI project"),
        *(job_resources(CC, "call-centre project") if cc else []),
        *job_resources(CRM, "the CRM's jobs", jobs=CRM_JOBS),
    ]
    return dashboard("tw-cloud-jobs", "Jobs (cloud)",
                     "Every scheduled and person-run Cloud Run job: executions, failures, schedules and missed runs, "
                     "then each project's task attempts, run lengths, CPU and memory.", ["jobs"], items,
                     time="now-24h")


PAGES = {"overview": overview, "portal-api": portal_api, "sign-in": sign_in, "records": records,
         "callcentre": call_centre, "crm": crm, "errors": errors, "databases": databases, "jobs": jobs,
         **{f"service-{service}": (lambda service=service: service_page(service)) for service in SERVICES}}


# production-full has no call-centre project: these pages are written again without their call-centre part, into
# no-cc/, and render-dashboards.sh uses them (and leaves out callcentre.json) when TPA_CC_PROJECT_ID is empty.
NO_CC = {"overview": overview, "errors": errors, "databases": databases, "jobs": jobs}
# The pages that read the call-centre project alone: render-dashboards.sh leaves them out with no call-centre project
# (its CC_ONLY_PAGES; tests/cloud hold the two lists together).
CC_ONLY = ["callcentre", *[f"service-{service}" for service, (ds, _page) in SERVICES.items() if ds == CC]]


def render() -> dict[str, str]:
    """Relative path -> JSON, every dashboard and every no-cc variant."""
    out = {f"{name}.json": build() for name, build in PAGES.items()}
    out.update({f"no-cc/{name}.json": build(cc=False) for name, build in NO_CC.items()})
    return {path: json.dumps(d, indent=2, ensure_ascii=False) + "\n" for path, d in out.items()}


def main(argv: list[str]) -> int:
    pages = render()
    if argv == ["--check"]:
        stale = [name for name, body in pages.items()
                 if not (OUT / name).exists() or (OUT / name).read_text() != body]
        extra = sorted(str(p.relative_to(OUT)) for p in [*OUT.glob("*.json"), *OUT.glob("no-cc/*.json")]
                       if str(p.relative_to(OUT)) not in pages)
        for name in stale:
            print(f"cloud_dashboards: cloud/dashboards/{name} differs from scripts/cloud_dashboards.py; run it")
        for name in extra:
            print(f"cloud_dashboards: cloud/dashboards/{name} is not written by scripts/cloud_dashboards.py")
        return 1 if stale or extra else 0
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    (OUT / "no-cc").mkdir(parents=True, exist_ok=True)
    for name, body in pages.items():
        (OUT / name).write_text(body)
    print(f"cloud_dashboards: wrote {len(pages)} dashboards to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
