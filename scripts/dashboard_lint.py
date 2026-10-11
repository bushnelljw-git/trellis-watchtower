#!/usr/bin/env python3
"""Lint the trellis-watchtower dashboards. Standard library only.

Every dashboard fails when:
  1. it names an identifier or a raw URL field (`requestUrl`, `uri`, `tid`, `tenant`, `tenant_id`, `request_id`,
     `principal_id`, `sid`) in a query, a legend, a transformation, a template variable or a field override.
     Monitoring labels come from a closed allowlist (docs/SPEC.md, "Rules the implementation must keep"), so a
     panel that groups or filters on one of these is charting an id;
  2. it uses a datasource uid outside its set: a local dashboard (grafana/dashboards) `prometheus`, `loki` or `fly`;
     a cloud dashboard (cloud/dashboards, and its no-cc/ variants) exactly the uids declared under
     cloud/provisioning/datasources/;
  3. it has no uid, or a uid another dashboard already uses (a no-cc/ variant has its page's uid, and nothing else);
  4. it is not valid JSON.

A cloud dashboard (the production image, read by grp-platform through IAP) also fails when:
  5. a query is not Cloud Monitoring's filter form (`timeSeriesList`) on the `stackdriver` datasource, or names a
     project other than its datasource's placeholder (`__TPA_PHI_PROJECT_ID__` on `cloud-phi`; render-dashboards.sh
     fills it in at start). Not PromQL: Grafana 12.4 turns a failed PromQL request into an empty answer, so a broken
     panel would read as zero. Nothing here reads logs: the datasource has no log query, and a log-based metric is a
     metric;
  6. a filter, a group-by or a legend (`{{...}}`, `${__field.labels.X}`) names a label outside the allowlist below,
     or a legend names `__field.labels` without one allowed key; a resource label is used without the query's
     `resource.type`; the metric is not a Google Cloud one; a filter is not `=` or `=~`; a cross-series reducer, primary
     or secondary, is missing or REDUCE_NONE (which would return every label of every series); or any Grafana
     variable appears in a query, so no dashboard query takes the viewer's input;
  7. a panel mixes datasources (so a PHI-project panel is `cloud-phi` and nothing else), or uses a panel type
     outside the allowlist;
  8. it declares any template variable (so no panel offers a viewer a filter or a project to change).

These rules bound what the dashboards ask, not what a viewer can ask. Any signed-in viewer can post a query of their
own to /api/ds/query (any filter, any reducer, another project), and Grafana 12.4 has no setting that limits a
datasource to its saved panels. What a viewer can read is whatever sa-watchtower can read: cloud/README.md, "What a
viewer can read".

Usage:
  scripts/dashboard_lint.py                       lint grafana/dashboards/ (local) and cloud/dashboards/ (cloud)
  scripts/dashboard_lint.py PATH ... [--cloud PATH ...]
                                                  lint these instead; paths after --cloud are linted as cloud

Exit 0 when clean, 1 when anything fails (each failure printed as `file: panel "title": message`).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL_DIR = ROOT / "grafana" / "dashboards"
CLOUD_DIR = ROOT / "cloud" / "dashboards"
CLOUD_DATASOURCES = ROOT / "cloud" / "provisioning" / "datasources"

LOCAL_UIDS = {"prometheus", "loki", "fly"}
# Grafana's own pseudo-datasources: the built-in annotation query and mixed/dashboard panels.
BUILTIN_UIDS = {"-- Grafana --", "grafana", "-- Mixed --", "-- Dashboard --"}

FORBIDDEN = ["requestUrl", "uri", "tid", "tenant", "tenant_id", "request_id", "principal_id", "sid"]
# Whole identifiers only: `tenants_total` and `sidebar` are fine, `tenant` and `sid` are not.
FORBIDDEN_RE = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(sorted(FORBIDDEN, key=len, reverse=True)) + r")(?![A-Za-z0-9_])")

# ---- Cloud: what a query may name ------------------------------------------------------------------------------------
# The catalogue's closed label list (tpa-platform docs/infra/monitoring.md §2) and Google's own metric labels the
# dashboards read (the status class, a job execution's result, an instance's state), as `metric.label.X`; the
# resource labels that come with every series and name our own services, jobs, instances, schedules and hosts, as
# `resource.label.X`.
CATALOGUE_LABELS = {"service", "operation", "gate", "code", "outcome", "status_class", "job", "lane", "class", "sqlstate"}
GOOGLE_METRIC_LABELS = {"response_code_class", "result", "state"}
METRIC_LABELS = CATALOGUE_LABELS | GOOGLE_METRIC_LABELS
RESOURCE_LABELS = {"service_name", "job_name", "database_id", "job_id", "host"}
ALLOWED_LABELS = {f"metric.label.{x}" for x in METRIC_LABELS} | {f"resource.label.{x}" for x in RESOURCE_LABELS}

MONITORED_RESOURCES = {"cloud_run_revision", "cloud_run_job", "cloudsql_database", "uptime_url", "cloud_scheduler_job",
                       "audited_resource"}
METRIC_TYPE_RE = re.compile(r"^(logging|run|cloudsql|monitoring)\.googleapis\.com/[a-z0-9_/]+$")
FILTER_OPERATORS = {"=", "=~"}
CLOUD_PANEL_TYPES = {"row", "stat", "timeseries", "table", "state-timeline", "text", "bargauge"}
ALIAS_RE = re.compile(r"\{\{\s*([^}\s]+)\s*\}\}")
# Every mention of a field's labels in a legend or display name, with the key it names (None for the bare map).
FIELD_LABELS_RE = re.compile(r"__field\.labels(?:\.([A-Za-z0-9_.]+))?")
PROJECT_VAR_RE = re.compile(r"^\s*defaultProject:\s*\$\{([A-Z0-9_]+)\}\s*(#.*)?$")


def cloud_datasources(directory: Path = CLOUD_DATASOURCES) -> dict[str, str]:
    """uid -> the environment variable its project comes from, as declared in the cloud image's datasource
    provisioning (no YAML parser needed: each datasource's `uid:` line precedes its `defaultProject: ${VAR}`)."""
    found: dict[str, str] = {}
    if directory.is_dir():
        for path in sorted(directory.glob("*.y*ml")):
            uid = None
            for line in path.read_text().splitlines():
                m = re.match(r"^\s*uid:\s*['\"]?([A-Za-z0-9_.-]+)['\"]?\s*(#.*)?$", line)
                if m:
                    uid = m.group(1)
                    found[uid] = ""
                    continue
                m = PROJECT_VAR_RE.match(line)
                if m and uid is not None:
                    found[uid] = m.group(1)
    return found


def project_placeholder(variable: str) -> str:
    """The token a cloud query names as its project, filled in at start by cloud/render-dashboards.sh."""
    return f"__{variable}__"


# ---- The filter form, as far as the lint needs it -------------------------------------------------------------------
class QueryError(ValueError):
    pass


def query_facts(tsl: dict) -> dict:
    """What a filter-form query (`timeSeriesList`) names: its metric type, its resource type, its filters as
    (key, operator, value), and every label it filters, groups or aggregates on. Raises QueryError when the filter
    list is not Grafana's [key, operator, value, AND, ...] shape."""
    filters = tsl.get("filters") or []
    if len(filters) % 4 != 3:
        raise QueryError("filters are not [key, operator, value] joined by AND")
    triples = []
    for i in range(0, len(filters), 4):
        key, op, value = filters[i:i + 3]
        if i + 3 < len(filters) and filters[i + 3] != "AND":
            raise QueryError(f"filters are joined by `{filters[i + 3]}`, not AND")
        triples.append((key, op, value))
    metric = [v for k, op, v in triples if k == "metric.type" and op == "="]
    resource = [v for k, op, v in triples if k == "resource.type" and op == "="]
    labels = {k for k, _op, _v in triples if k not in ("metric.type", "resource.type")}
    labels |= set(tsl.get("groupBys") or []) | set(tsl.get("secondaryGroupBys") or [])
    return {"metric": metric[0] if len(metric) == 1 else None, "resource": resource[0] if len(resource) == 1 else None,
            "filters": triples, "labels": labels}


# ---- Walking a dashboard -------------------------------------------------------------------------------------------
def strings(node):
    """Every string inside a JSON value, recursively, dict keys included (organize's renameByName and
    excludeByName name fields by key)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)


def panels(dashboard: dict):
    """Every panel, including those nested inside collapsed rows."""
    for panel in dashboard.get("panels", []) or []:
        yield panel
        for inner in panel.get("panels", []) or []:
            yield inner


def datasource_uids(node):
    """Every datasource reference below `node`, as a uid string (a legacy string reference is taken as-is)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "datasource":
                if isinstance(value, dict):
                    if value.get("uid") is not None:
                        yield str(value["uid"])
                elif isinstance(value, str):
                    yield value
            else:
                yield from datasource_uids(value)
    elif isinstance(node, list):
        for value in node:
            yield from datasource_uids(value)


def lint_dashboard(path: Path, dashboard: dict, allowed_uids: set[str]) -> list[str]:
    errors: list[str] = []

    def fail(where: str, message: str) -> None:
        errors.append(f"{path}: {where}: {message}")

    # 1. Forbidden identifiers in queries, legends, transformations, variables and overrides.
    places = []
    for panel in panels(dashboard):
        where = f'panel "{panel.get("title", "?")}"'
        places.append((where, panel.get("targets", [])))
        places.append((where, panel.get("transformations", [])))
        places.append((where, (panel.get("fieldConfig") or {}).get("overrides", [])))
        places.append((where, ((panel.get("fieldConfig") or {}).get("defaults") or {}).get("displayName", "")))
    for var in (dashboard.get("templating") or {}).get("list", []) or []:
        places.append((f'variable "{var.get("name", "?")}"',
                       [var.get("query", ""), var.get("definition", ""), var.get("regex", "")]))
    found: set[tuple[str, str]] = set()
    for where, node in places:
        for text in strings(node):
            for match in FORBIDDEN_RE.finditer(text):
                if (where, match.group(1)) not in found:
                    found.add((where, match.group(1)))
                    fail(where, f"references the forbidden field `{match.group(1)}`")

    # 2. Datasource uids.
    for uid in sorted(set(datasource_uids(dashboard))):
        if uid.startswith("$"):
            fail("datasource", f"uses a datasource variable `{uid}`; name a known uid instead")
        elif uid not in allowed_uids and uid not in BUILTIN_UIDS:
            fail("datasource", f"uses unknown datasource uid `{uid}` (allowed: {', '.join(sorted(allowed_uids))})")
    return errors


def lint_cloud(path: Path, dashboard: dict, datasources: dict[str, str]) -> list[str]:
    """Rules 5 to 8, for a dashboard baked into the production image."""
    errors: list[str] = []

    def fail(where: str, message: str) -> None:
        errors.append(f"{path}: {where}: {message}")

    # 8. No template variables at all.
    for var in (dashboard.get("templating") or {}).get("list", []) or []:
        fail(f'variable "{var.get("name", "?")}"', "a cloud dashboard declares no template variables")

    for panel in panels(dashboard):
        where = f'panel "{panel.get("title", "?")}"'
        kind = panel.get("type")
        if kind not in CLOUD_PANEL_TYPES:
            fail(where, f"panel type `{kind}` is not one a cloud dashboard uses ({', '.join(sorted(CLOUD_PANEL_TYPES))})")

        # 6. Legends and display names name one allowed label each, never the bare label map.
        for text in strings([panel.get("fieldConfig") or {}, panel.get("options") or {},
                             panel.get("transformations") or []]):
            for m in FIELD_LABELS_RE.finditer(text):
                if m.group(1) is None:
                    fail(where, "a legend names `__field.labels` without a key; name one allowed label")
                elif m.group(1) not in ALLOWED_LABELS:
                    fail(where, f"a legend names the label `{m.group(1)}`, which is not on the allowlist")

        targets = panel.get("targets") or []
        if kind in ("row", "text"):
            if targets:
                fail(where, f"a {kind} panel runs no query")
            continue

        # 7. One datasource per panel, the panel's own.
        panel_uid = (panel.get("datasource") or {}).get("uid") if isinstance(panel.get("datasource"), dict) else None
        uids = {(t.get("datasource") or {}).get("uid") for t in targets}
        if not targets:
            fail(where, "has no query")
        if panel_uid not in datasources:
            fail(where, f"the panel's datasource must be one cloud datasource, not `{panel_uid}`")
        if len(uids) > 1 or (uids and uids != {panel_uid}):
            fail(where, f"mixes datasources ({', '.join(sorted(str(u) for u in uids | {panel_uid}))}); one per panel")

        # 5 and 6. The filter form on stackdriver, naming its datasource's project and allowed labels only.
        for target in targets:
            ref = target.get("refId", "?")
            ds = target.get("datasource") or {}
            uid = ds.get("uid")
            if ds.get("type") != "stackdriver" or uid not in datasources:
                fail(where, f"query {ref}: not on a cloud (stackdriver) datasource")
                continue
            if target.get("queryType") != "timeSeriesList":
                fail(where, f"query {ref}: queryType must be `timeSeriesList` (the filter form), "
                            f"not `{target.get('queryType')}`")
            for other in ("promQLQuery", "timeSeriesQuery", "sloQuery", "metricQuery"):
                if other in target:
                    fail(where, f"query {ref}: carries a `{other}` block; the filter form only")
            tsl = target.get("timeSeriesList") or {}
            want = project_placeholder(datasources[uid]) if datasources[uid] else None
            if not want or tsl.get("projectName") != want:
                fail(where, f"query {ref}: projectName must be `{want}` on `{uid}`, not `{tsl.get('projectName')}`")
            if tsl.get("view", "FULL") != "FULL":
                fail(where, f"query {ref}: view must be FULL (HEADERS returns no points)")
            if any("$" in text for text in strings([tsl, target.get("aliasBy", "")])):
                fail(where, f"query {ref}: names a Grafana variable; a cloud query is fixed")
            try:
                facts = query_facts(tsl)
            except QueryError as exc:
                fail(where, f"query {ref}: {exc}")
                continue
            if not facts["metric"] or not METRIC_TYPE_RE.match(facts["metric"]):
                fail(where, f"query {ref}: metric.type `{facts['metric']}` is not one Google Cloud metric type")
            if facts["resource"] is not None and facts["resource"] not in MONITORED_RESOURCES:
                fail(where, f"query {ref}: resource.type `{facts['resource']}` is not one the dashboards read "
                            f"({', '.join(sorted(MONITORED_RESOURCES))})")
            for key, op, _value in facts["filters"]:
                if op not in FILTER_OPERATORS:
                    fail(where, f"query {ref}: filter `{key} {op}` uses an operator outside {sorted(FILTER_OPERATORS)}")
            labels = facts["labels"] | set(ALIAS_RE.findall(target.get("aliasBy") or ""))
            for label in sorted(labels - ALLOWED_LABELS):
                fail(where, f"query {ref}: names the label `{label}`, which is not on the allowlist")
            if facts["resource"] is None and any(label.startswith("resource.label.") for label in labels):
                fail(where, f"query {ref}: uses a resource label without filtering on resource.type")
            for key in ("perSeriesAligner", "secondaryPerSeriesAligner"):
                if key in tsl and not str(tsl[key]).startswith("ALIGN_"):
                    fail(where, f"query {ref}: {key} `{tsl[key]}` is not an aligner")
            secondary = any(k.startswith("secondary") for k in tsl)
            for key in ("crossSeriesReducer", *(("secondaryCrossSeriesReducer",) if secondary else ())):
                reducer = tsl.get(key)
                if not reducer:
                    fail(where, f"query {ref}: has no {key}; reduce across series to the labels it groups by")
                elif reducer == "REDUCE_NONE" or not str(reducer).startswith("REDUCE_"):
                    fail(where, f"query {ref}: {key} `{reducer}` is not a reducer that groups (REDUCE_NONE returns "
                                "every label of every series)")
    return errors


def collect(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.exists():
            files.append(path)
    return files


def main(argv: list[str]) -> int:
    local_targets: list[Path] = []
    cloud_targets: list[Path] = []
    into = local_targets
    for arg in argv:
        if arg == "--cloud":
            into = cloud_targets
        else:
            into.append(Path(arg))
    if not argv:
        local_targets, cloud_targets = [LOCAL_DIR], [CLOUD_DIR, CLOUD_DIR / "no-cc"]
    missing = [str(t) for t in local_targets + cloud_targets if argv and not t.exists()]
    if missing:
        print("dashboard_lint: no such path: " + ", ".join(missing), file=sys.stderr)
        return 1
    datasources = cloud_datasources()
    errors: list[str] = []
    seen_uids: dict[str, Path] = {}
    count = 0
    for files, cloud in ((collect(local_targets), False), (collect(cloud_targets), True)):
        for path in files:
            count += 1
            try:
                dashboard = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"{path}: not valid JSON ({exc})")
                continue
            if not isinstance(dashboard, dict):
                errors.append(f"{path}: not a dashboard object")
                continue
            # 3. uid present and unique; a no-cc/ variant has its page's uid.
            uid = dashboard.get("uid")
            if not isinstance(uid, str) or not uid.strip():
                errors.append(f"{path}: dashboard has no uid")
            elif cloud and path.parent.name == "no-cc":
                page = path.parent.parent / path.name
                page_uid = json.loads(page.read_text()).get("uid") if page.exists() else None
                if uid != page_uid:
                    errors.append(f"{path}: a no-cc variant needs the uid of {page} (`{page_uid}`), not `{uid}`")
            elif uid in seen_uids:
                errors.append(f"{path}: uid `{uid}` is already used by {seen_uids[uid]}")
            else:
                seen_uids[uid] = path
            errors.extend(lint_dashboard(path, dashboard, set(datasources) if cloud else LOCAL_UIDS))
            if cloud:
                errors.extend(lint_cloud(path, dashboard, datasources))
    for line in errors:
        print(line)
    print(f"dashboard_lint: {count} dashboard(s), {len(errors)} problem(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
