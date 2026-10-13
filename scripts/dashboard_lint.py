#!/usr/bin/env python3
"""Lint the trellis-watchtower dashboards. Standard library only.

Every dashboard fails when:
  1. it names an identifier or a raw URL field (`requestUrl`, `uri`, `tid`, `tenant`, `tenant_id`, `request_id`,
     `principal_id`, `sid`) anywhere in a panel (queries, legends, transformations, field config and overrides,
     links, `noValue`, options such as a Canvas element's field) or a template variable. Only prose is not read: a
     panel's title and description, and a text panel's `options.content`. Monitoring labels come from a closed allowlist (docs/SPEC.md, "Rules the
     implementation must keep"), so a panel that groups, filters or links on one of these is charting an id;
  2. it uses a datasource uid outside its set: a local dashboard (grafana/dashboards) `prometheus` or `loki`;
     a cloud dashboard (cloud/dashboards, and its no-cc/ variants) exactly the uids declared under
     cloud/provisioning/datasources/;
  3. it has no uid, or a uid another dashboard already uses (a no-cc/ variant has its page's uid, and nothing else);
  4. it is not valid JSON;
  4b. a panel is a library panel (`libraryPanel`): its queries live in Grafana's database, not in this file, so no
     rule here could read them.

A local dashboard (grafana/dashboards) also fails when (a query's datasource is resolved by uid, from the target or
else the panel, and `#` comments are stripped first, so a comment cannot hide a query):
  5. a panel reads raw log lines: a `logs` panel, or a Loki query that is a log query (it starts with a stream
     selector `{...}`) rather than a metric query. The lines are scrubbed, but a dashboard shows counts, ages and
     groups; reading a line is Explore's job, for one person at a time;
  5b. a query can return a label outside LOCAL_LABELS: a selector that is not inside an aggregation (`sum`, `max`,
     `count`, ..., or a LogQL range aggregation with its own `by`), a `by`/`on`/`ignoring`/`group_left` list, a
     `label_replace`/`count_values` target or a legend (`{{x}}`, `__field.labels.x`) naming another label, any
     `without` (it keeps every label it does not name), a bare `| json`, `| logfmt` or `| unpack` (they turn every
     field of the line into a label), or the word `instance` (a target's address) at all;
  5c. a query can copy a value into a listed label, or chart a value it should not: `| line_format` or `| pattern` at
     all; a `| regexp` that is not one of VETTED_REGEXPS (any other, digits only or not, could lift an identifier
     out of a line); a `| label_format` assignment that is not one of VETTED_LABEL_FORMATS (a rename such as
     `where=tid`, or a template such as `{{ index . "tid" }}`, would copy any field), or one whose helper fields are
     not each set once, by the pinned extraction, in the same pipeline; a `| json` or `| logfmt` extraction into a
     listed label from another field (outside VETTED_EXTRACTIONS); an `| unwrap` of anything but a number from
     VETTED_UNWRAPS, set once in the same pipeline (an unwrapped member number or date of birth is an identifier
     drawn as a line); a `label_replace`/`label_join` reading a source label that is not listed;
  5d. a server-side expression is anything but math, reduce, resample or threshold (an SQL expression can select
     anything the hidden queries returned).

The annotations are queries too: rules 5 to 5c read them as they read a panel's targets, and their title and text
templates and tag keys (`titleFormat`, `textFormat`, `tagKeys`) may name only listed labels.

Loki's recording rules (loki/rules/, a `.yml` path given on the command line) are queries too: whatever they record
lands in Prometheus, where any dashboard can read it. Each `expr` must be one double-quoted line (scripts/gen_home.py
writes them so) and passes rules 5 to 5c, and a rule's `labels` may name only listed labels.

A cloud dashboard (the production image, read by grp-platform through IAP) also fails when:
  6. a query is not Cloud Monitoring's filter form (`timeSeriesList`) on the `stackdriver` datasource, or names a
     project other than its datasource's placeholder (`__TPA_PHI_PROJECT_ID__` on `cloud-phi`; render-dashboards.sh
     fills it in at start). Not PromQL: Grafana 12.4 turns a failed PromQL request into an empty answer, so a broken
     panel would read as zero. Nothing here reads logs: the datasource has no log query, and a log-based metric is a
     metric;
  7. a filter, a group-by or a legend (`{{...}}`, `${__field.labels.X}`) names a label outside the allowlist below,
     or a legend names `__field.labels` without one allowed key; a resource label is used without the query's
     `resource.type`; the metric is not a Google Cloud one; a filter is not `=` or `=~`; a cross-series reducer, primary
     or secondary, is missing or REDUCE_NONE (which would return every label of every series); or any Grafana
     variable appears in a query, so no dashboard query takes the viewer's input;
  8. a panel mixes datasources (so a PHI-project panel is `cloud-phi` and nothing else), or uses a panel type
     outside the allowlist;
  9. it declares any template variable (so no panel offers a viewer a filter or a project to change).

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
LOKI_RULES_DIR = ROOT / "loki" / "rules"
CLOUD_DIR = ROOT / "cloud" / "dashboards"
CLOUD_DATASOURCES = ROOT / "cloud" / "provisioning" / "datasources"

LOCAL_UIDS = {"prometheus", "loki"}
# Grafana's own pseudo-datasources: the built-in annotation query and mixed/dashboard panels.
BUILTIN_UIDS = {"-- Grafana --", "grafana", "-- Mixed --", "-- Dashboard --", "__expr__"}
# Targets that run no query of their own: a server-side expression (math over other targets) and the dashboard
# datasource (another panel's results).
NO_QUERY_UIDS = {"__expr__", "-- Dashboard --"}
LOCAL_TYPES = {"prometheus": "prometheus", "loki": "loki"}

FORBIDDEN = ["requestUrl", "uri", "tid", "tenant", "tenant_id", "request_id", "principal_id", "sid"]
# Whole identifiers only: `tenants_total` and `sidebar` are fine, `tenant` and `sid` are not.
FORBIDDEN_RE = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(sorted(FORBIDDEN, key=len, reverse=True)) + r")(?![A-Za-z0-9_])")

# ---- Cloud: what a query may name ------------------------------------------------------------------------------------
# The catalogue's closed label list (tpa-platform docs/infra/monitoring.md §2) and Google's own metric labels the
# dashboards read (the status class, a job execution's or task attempt's result, an instance's state, the reason
# Cloud NAT dropped a packet: each a fixed word of Google's), as `metric.label.X`; the resource labels that come with
# every series and name our own services, jobs, instances, schedules, hosts, NAT gateways and buckets, as
# `resource.label.X`.
CATALOGUE_LABELS = {"service", "operation", "gate", "code", "outcome", "status_class", "job", "lane", "class", "sqlstate"}
GOOGLE_METRIC_LABELS = {"response_code_class", "result", "state", "reason"}
METRIC_LABELS = CATALOGUE_LABELS | GOOGLE_METRIC_LABELS
RESOURCE_LABELS = {"service_name", "job_name", "database_id", "job_id", "host", "gateway_name", "bucket_name"}
ALLOWED_LABELS = {f"metric.label.{x}" for x in METRIC_LABELS} | {f"resource.label.{x}" for x in RESOURCE_LABELS}

# servicedirectory_service: a private uptime check's resource (Google's VPC checkers reading auth's and tpa-api's
# /ready at their internal balancers; tpa-platform D-149). Its one label read here is service_name. nat_gateway: a
# project's Cloud NAT (its ports, connections and drops), read by gateway_name. gcs_bucket: a bucket's size and
# object count, read by bucket_name, never an object's name.
MONITORED_RESOURCES = {"cloud_run_revision", "cloud_run_job", "cloudsql_database", "uptime_url", "cloud_scheduler_job",
                       "audited_resource", "servicedirectory_service", "nat_gateway", "gcs_bucket"}
METRIC_TYPE_RE = re.compile(r"^(logging|run|cloudsql|monitoring|router|storage)\.googleapis\.com/[a-z0-9_/]+$")
FILTER_OPERATORS = {"=", "=~"}
CLOUD_PANEL_TYPES = {"row", "stat", "timeseries", "table", "state-timeline", "text", "bargauge"}
ALIAS_RE = re.compile(r"\{\{\s*([^}\s]+)\s*\}\}")
# Every mention of a field's labels in a legend or display name, with the key it names (None for the bare map).
FIELD_LABELS_RE = re.compile(r"__field\.labels(?:\.([A-Za-z0-9_.]+))?")
# A LogQL log query starts with its stream selector; a metric query starts with a function, a number or `(`.
LOG_QUERY_RE = re.compile(r"^\s*\{")

# ---- Local: the labels a panel may show (docs/SPEC.md "Naming rules"; docs/SIGNALS.md) -----------------------------
# Prometheus: the probe contract, the postgres db, an alert's name, a value turned into a label by count_values
# (`code`, `state`). Loki: the stream labels, Alloy's structured metadata, and the labels the dashboards derive
# from them: `where` (operation or route), `area`, `status_class`, `msg_name`/`reason_code` (a message's or reason's
# constant name; anything else is replaced by "other" before it is grouped), records' `gate`/`decision`, auth's
# `release`, `dash` (the dashboard a row links to), `check` (service and probe joined) and `rank` (a problem's
# severity, a constant 0, 1 or 9), and the headline's roll-up name: `lead` (a stack's name), `others` (a count of
# stacks, from count_values) and `scope` (the two joined, "TPA + 1 stack").
LOCAL_LABELS = {"stack", "service", "probe", "db", "job", "code", "state", "alertname", "level", "exc_class", "sqlstate",
                "operation", "route", "outcome", "status", "status_class", "lane", "gate", "decision", "where", "area",
                "msg_name", "reason_code", "release", "dash", "check", "rank", "lead", "others", "scope"}
# Recording rules whose own labels are all on the list, so they may be read without an aggregation.
LOCAL_BARE_SERIES = {"stack:probe_success:max_over_time1h"}
AGGREGATIONS = {"sum", "min", "max", "avg", "group", "stddev", "stdvar", "count", "count_values", "bottomk", "topk",
                "quantile", "limitk", "limit_ratio", "absent", "absent_over_time", "sort", "sort_desc"}
RANGE_AGGREGATIONS = {"quantile_over_time", "min_over_time", "max_over_time", "avg_over_time", "sum_over_time",
                      "stddev_over_time", "stdvar_over_time", "first_over_time", "last_over_time", "rate_counter",
                      "count_over_time", "rate", "bytes_over_time", "bytes_rate"}
GROUPING = {"by", "without", "on", "ignoring", "group_left", "group_right"}
KEYWORDS = GROUPING | {"bool", "and", "or", "unless", "offset", "inf", "nan", "atan2", "start", "end"}
TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|`[^`]*`|\d+(?:\.\d+)?(?:ms|[smhdwy])?(?:\d+(?:ms|[smhdwy]))*|'
                      r'[A-Za-z_:][A-Za-z0-9_:]*|\$\{?[A-Za-z_]\w*\}?|\|[=~]|!=|!~|=~|==|>=|<=|[(){}\[\],|=<>!+\-*/%^@:]|\S')
LEGEND_LABEL_RE = re.compile(r"\{\{\s*([^}\s]+)\s*\}\}")
EXPRESSION_TYPES = {"math", "reduce", "resample", "threshold"}
# The label_format assignments the dashboards may use, each read as (label, template) with runs of spaces folded:
# numbers for `unwrap` (an age, a time), and labels derived only from listed labels or from a constant's name.
VETTED_LABEL_FORMATS = {
    ("age_s", "{{ sub (unixEpoch now) (unixEpoch __timestamp__) }}"),
    ("ts", "{{ unixEpochMillis __timestamp__ }}"),
    ("seen_ms", "{{ unixEpochMillis __timestamp__ }}"),
    ("n", "{{ add .f .p .k }}"),
    ("where", "{{ or .operation .route }}"),
    ("status_class", "{{ substr 0 1 .status }}xx"),
    # A message's or reason's name only when it is a lower-case constant; anything else (an address, a count, a
    # sentence with digits) becomes "other".
    ("msg_name", '{{ $m := or .m1 .m2 }}{{ if eq (regexReplaceAll "^[a-z][a-z0-9_ ]{0,59}$" $m "") "" }}{{ $m }}'
                 "{{ else }}other{{ end }}"),
    ("reason_code", '{{ if eq (regexReplaceAll "^[A-Za-z][A-Za-z_]{0,39}$" .rc "") "" }}{{ .rc }}{{ else }}other'
                    "{{ end }}"),
}
# The fields each vetted template reads, pinned: the template is safe only fed from these.
VETTED_SOURCES = {
    "msg_name": {"m1": "msg", "m2": "message"},
    "reason_code": {"rc": "reason"},
    "n": {"f": "tenants_failed", "p": "tenants_partial", "k": "tenants_skipped"},
}
# `| json label="field"` into a listed label from a field of another name.
VETTED_EXTRACTIONS = {("release", "revision")}
# The only regexps: connectors' delivery counters, read from its pass line's message (`name=digits`), each capturing
# the count as `n` for `| unwrap n`.
VETTED_REGEXPS = {f"connectors_{c}_total=(?P<n>[0-9]+)" for c in (
    "delivered", "retried", "dead", "duplicate", "paused_skipped", "destination_refused", "envelope_unsigned")}
# What `| unwrap` may read: a number made by a vetted label_format (an age, a time, a sum of tenant counts), a
# duration or a tenant count extracted by name, or a connectors counter from a vetted regexp. Each is (label, how it
# is set in the same pipeline): ("label_format", label) or (parser, source field) or ("regexp", "n").
VETTED_UNWRAPS = {
    "age_s": {("label_format", "age_s")},
    "ts": {("label_format", "ts")},
    "seen_ms": {("label_format", "seen_ms")},
    "n": {("label_format", "n"), ("json", "tenants_failed"), ("json", "tenants_partial"), ("json", "tenants_skipped"),
          ("regexp", "n")},
    "d": {("json", "duration_ms")},
    "duration_ms": {("json", "duration_ms")},
    "duration": {("json", "duration")},
}
UNWRAP_RE = re.compile(r"\|\s*unwrap\s+(?:[a-z_]+\(\s*)?([A-Za-z_][A-Za-z0-9_]*)")
STAGE_RE = re.compile(r"\|\s*(json|logfmt|label_format|regexp|line_format|pattern)\b")
BARE_PARSER_RE = re.compile(r"\|\s*(json|logfmt|unpack)\b(?!\s*[A-Za-z_])")
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


def panel_without_prose(panel: dict) -> dict:
    """The whole panel as the lint reads it: everything but its prose (title, description, a text panel's content)
    and a row's nested panels (they are read on their own)."""
    out = {k: v for k, v in panel.items()
           if k not in ("title", "description") and not (k == "panels" and panel.get("type") == "row")}
    if panel.get("type") == "text" and isinstance(out.get("options"), dict):
        out["options"] = {k: v for k, v in out["options"].items() if k != "content"}
    return out


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
        places.append((where, panel_without_prose(panel)))
    for var in (dashboard.get("templating") or {}).get("list", []) or []:
        places.append((f'variable "{var.get("name", "?")}"',
                       [var.get("query", ""), var.get("definition", ""), var.get("regex", "")]))
    for ann in (dashboard.get("annotations") or {}).get("list", []) or []:
        places.append((f'annotation "{ann.get("name", "?")}"', {k: v for k, v in ann.items() if k != "name"}))
    found: set[tuple[str, str]] = set()
    for where, node in places:
        for text in strings(node):
            for match in FORBIDDEN_RE.finditer(text):
                if (where, match.group(1)) not in found:
                    found.add((where, match.group(1)))
                    fail(where, f"references the forbidden field `{match.group(1)}`")

    # 4b. No library panels: their queries live in Grafana's database, where this lint cannot read them.
    for panel in panels(dashboard):
        if "libraryPanel" in panel:
            fail(f'panel "{panel.get("title", "?")}"', "is a library panel (`libraryPanel`); its queries live outside "
                 "this file, so the lint cannot read them. Put the panel itself in the dashboard")

    # 2. Datasource uids.
    for uid in sorted(set(datasource_uids(dashboard))):
        if uid.startswith("$"):
            fail("datasource", f"uses a datasource variable `{uid}`; name a known uid instead")
        elif uid not in allowed_uids and uid not in BUILTIN_UIDS:
            fail("datasource", f"uses unknown datasource uid `{uid}` (allowed: {', '.join(sorted(allowed_uids))})")
    return errors


def strip_comments(expr: str) -> str:
    """A query without its `#` comments (to the end of the line), leaving `#` inside quotes and backticks."""
    out, quote = [], None
    i = 0
    while i < len(expr):
        c = expr[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(expr):
                out.append(expr[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"`":
            quote = c
            out.append(c)
        elif c == "#":
            while i < len(expr) and expr[i] != "\n":
                i += 1
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def ds_type(ref, fallback=None):
    """A datasource reference's type, by uid first (a target may name the uid only)."""
    if isinstance(ref, str):
        return LOCAL_TYPES.get(ref, ref)
    if isinstance(ref, dict):
        uid = ref.get("uid")
        if uid in LOCAL_TYPES:
            return LOCAL_TYPES[uid]
        if uid in NO_QUERY_UIDS:
            return uid
        if ref.get("type") and uid not in BUILTIN_UIDS:
            return ref["type"]
    return fallback


def _fold(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _read_value(expr: str, i: int) -> tuple[str | None, int]:
    """A quoted, backticked or bare value starting at i: (its text, the index after it)."""
    while i < len(expr) and expr[i] == " ":
        i += 1
    if i >= len(expr):
        return None, i
    if expr[i] == "`":
        end = expr.find("`", i + 1)
        return (expr[i + 1:end], end + 1) if end > 0 else (None, len(expr))
    if expr[i] == '"':
        j = i + 1
        while j < len(expr) and expr[j] != '"':
            j += 2 if expr[j] == "\\" else 1
        return expr[i + 1:j], j + 1
    m = re.match(r"[A-Za-z_][A-Za-z0-9_.]*", expr[i:])
    return (m.group(0), i + m.end()) if m else (None, i)


def _assignments(expr: str, i: int) -> list[tuple[str, str | None, bool]]:
    """The `name[=value]` list a LogQL stage takes, from i: (name, value or None, value was quoted)."""
    out = []
    while True:
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*", expr[i:])
        if not m:
            return out
        name, i = m.group(1), i + m.end()
        value, quoted = None, False
        if i < len(expr) and expr[i] == "=":
            quoted = i + 1 < len(expr) and expr[i + 1:].lstrip()[:1] in ("`", '"')
            value, i = _read_value(expr, i + 1)
        out.append((name, value, quoted))
        m = re.match(r"\s*,", expr[i:])
        if not m:
            return out
        i += m.end()


def pipelines(expr: str) -> list[str]:
    """Each LogQL log pipeline in a query: from a stream selector `{` to its range `[`, or to the `)` that closes the
    call it sits in (quotes and backticks skipped), so a stage is judged with the stages of its own pipeline only."""
    out = []
    i = 0
    while i < len(expr):
        c = expr[i]
        if c in "\"`":
            j = expr.find(c, i + 1) if c == "`" else _end_of_quoted(expr, i)
            i = (j + 1) if j > 0 else len(expr)
            continue
        if c == "{":
            j, depth = i, 0
            while j < len(expr):
                d = expr[j]
                if d in "\"`":
                    k = expr.find(d, j + 1) if d == "`" else _end_of_quoted(expr, j)
                    j = (k + 1) if k > 0 else len(expr)
                    continue
                if d == "(":
                    depth += 1
                elif d == ")":
                    if depth == 0:
                        break
                    depth -= 1
                elif d == "[" and depth == 0:
                    break
                j += 1
            out.append(expr[i:j])
            i = j
            continue
        i += 1
    return out


def _end_of_quoted(expr: str, i: int) -> int:
    j = i + 1
    while j < len(expr) and expr[j] != '"':
        j += 2 if expr[j] == "\\" else 1
    return j if j < len(expr) else -1


def _sets(pipe: str) -> dict[str, list[tuple[str, str]]]:
    """Every label a pipeline's stages set, with how: name -> [(stage, source)], in order. json and logfmt name their
    source field (the name itself when bare-named), label_format its own name, regexp each capture as "n"-style."""
    sets: dict[str, list[tuple[str, str]]] = {}
    for m in STAGE_RE.finditer(pipe):
        stage, rest = m.group(1), m.end()
        if stage in ("json", "logfmt"):
            for name, value, _quoted in _assignments(pipe, rest):
                sets.setdefault(name, []).append((stage, value if value is not None else name))
        elif stage == "label_format":
            for name, _value, _quoted in _assignments(pipe, rest):
                sets.setdefault(name, []).append(("label_format", name))
        elif stage == "regexp":
            pattern, _ = _read_value(pipe, rest)
            # Go's syntax accepts both (?P<name>...) and (?<name>...).
            for name in re.findall(r"\(\?P?<(\w+)>", pattern or ""):
                sets.setdefault(name, []).append(("regexp", name))
    return sets


def pipeline_problems(expr: str) -> list[str]:
    """Rule 5c for one LogQL query: no stage copies a value into a listed label, and nothing but a vetted number is
    unwrapped. Each pipeline is judged alone: the extractions a vetted template or an unwrap reads must be in the same
    pipeline, and set there exactly once (Loki keeps the first value a label gets, so a field set twice is read from
    whichever stage came first)."""
    problems = []
    vetted = {(n, _fold(t)) for n, t in VETTED_LABEL_FORMATS}
    for pipe in pipelines(expr):
        sets = _sets(pipe)
        for m in STAGE_RE.finditer(pipe):
            stage, rest = m.group(1), m.end()
            if stage in ("line_format", "pattern"):
                problems.append(f"uses `| {stage}`, which can rewrite or copy any part of a line")
            elif stage == "regexp":
                pattern, _ = _read_value(pipe, rest)
                if pattern not in VETTED_REGEXPS:
                    problems.append("uses a `| regexp` that is not one of VETTED_REGEXPS; it could lift any part of "
                                    "a line (an identifier's digits included) into a label or a number")
            elif stage == "label_format":
                for name, value, quoted in _assignments(pipe, rest):
                    if not quoted or (name, _fold(value or "")) not in vetted:
                        problems.append(f"`| label_format {name}=...` is not one of VETTED_LABEL_FORMATS; it could "
                                        "copy any field into the label")
                        continue
                    for helper, source in VETTED_SOURCES.get(name, {}).items():
                        if sets.get(helper) != [("json", source)]:
                            problems.append(f"`| label_format {name}=...` reads `{helper}`, which must be set once, "
                                            f"by `| json {helper}=\"{source}\"`, in the same pipeline")
            else:  # json, logfmt with parameters
                for name, value, _quoted in _assignments(pipe, rest):
                    source = value if value is not None else name
                    if name in LOCAL_LABELS and source != name and (name, source) not in VETTED_EXTRACTIONS:
                        problems.append(f"`| {stage} {name}=\"{source}\"` copies another field into the listed "
                                        f"label `{name}`")
        for m in UNWRAP_RE.finditer(pipe):
            name = m.group(1)
            how = sets.get(name, [])
            if len(how) != 1 or how[0] not in VETTED_UNWRAPS.get(name, set()):
                problems.append(f"`| unwrap {name}` reads a number that is not one of VETTED_UNWRAPS set once in the "
                                "same pipeline; an unwrapped field could be an identifier (a member number, a date "
                                "of birth)")
    return problems


def query_label_problems(expr: str, kind: str) -> list[str]:
    """Rules 5b and 5c for one query: every label it can return is on LOCAL_LABELS, and none holds a copied value."""
    problems: list[str] = []
    if kind == "loki":
        problems += pipeline_problems(expr)
    if re.search(r"(?<![A-Za-z0-9_])instance(?![A-Za-z0-9_])", expr):
        problems.append("names the `instance` label (a target's address); group by stack, service and probe")
    if kind == "loki":
        for m in BARE_PARSER_RE.finditer(expr):
            problems.append(f"a bare `| {m.group(1)}` turns every field of a line into a label; name the fields")
    tokens = TOKEN_RE.findall(expr)
    # Walk the tokens: a stack of open brackets, each with what opened it.
    stack: list[dict] = []
    calls: list[dict] = []          # every function call: name, and later whether a trailing `by` follows it
    selectors: list[tuple[str, list[dict]]] = []
    i = 0
    prev = None
    while i < len(tokens):
        tok = tokens[i]
        in_braces = any(b["kind"] == "brace" for b in stack)
        in_group = stack and stack[-1]["kind"] == "group"
        if tok == "(":
            if prev in GROUPING:
                entry = {"kind": "group", "word": prev}
            elif prev is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", prev) and prev not in KEYWORDS:
                entry = {"kind": "call", "name": prev, "agg": prev in AGGREGATIONS}
                calls.append(entry)
            elif prev == ")" and stack == [] and False:
                entry = {"kind": "paren"}
            else:
                # `sum by (x) (` : the call's argument list opens after its grouping list.
                entry = {"kind": "paren"}
                if pending_agg := (stack_pending.pop() if (stack_pending := [c for c in calls if c.get("await")]) else None):
                    pending_agg["await"] = False
                    entry = {"kind": "call", "name": pending_agg["name"], "agg": True}
            stack.append(entry)
        elif tok == ")":
            closed = stack.pop() if stack else {"kind": "paren"}
            if closed["kind"] == "call":
                # A LogQL range aggregation is an aggregation when its own `by` follows it.
                nxt = tokens[i + 1] if i + 1 < len(tokens) else None
                if nxt in ("by", "without") and closed["name"] in RANGE_AGGREGATIONS:
                    closed["agg"] = True
        elif tok == "{":
            if not in_braces:
                selectors.append(("{", list(stack)))
            stack.append({"kind": "brace"})
        elif tok == "}":
            if stack and stack[-1]["kind"] == "brace":
                stack.pop()
        elif tok == "[":
            stack.append({"kind": "range"})
        elif tok == "]":
            if stack and stack[-1]["kind"] == "range":
                stack.pop()
        elif in_group:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok) and tok not in LOCAL_LABELS:
                problems.append(f"`{stack[-1]['word']} (...)` names the label `{tok}`, which is not on LOCAL_LABELS")
        elif tok in ("without",):
            problems.append("uses `without`, which keeps every label it does not name; use `by` with listed labels")
        elif tok in AGGREGATIONS and i + 1 < len(tokens) and tokens[i + 1] in ("by", "without"):
            # `sum by (x) (...)`: remember that the next plain paren after the grouping list is this call's.
            calls.append({"kind": "call", "name": tok, "agg": True, "await": True})
        elif (kind == "prometheus" and not in_braces and re.fullmatch(r"[A-Za-z_:][A-Za-z0-9_:]*", tok)
              and tok not in KEYWORDS and tok not in AGGREGATIONS
              and not (i + 1 < len(tokens) and tokens[i + 1] == "(")
              and prev not in ("offset",)
              and not (stack and stack[-1]["kind"] == "range")):
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if nxt != "{":
                selectors.append((tok, list(stack)))
        if tok.startswith('"') and stack and stack[-1]["kind"] == "call":
            call = stack[-1]
            # The label a call creates: label_replace's and label_join's second argument, count_values' first.
            args_before = call.setdefault("args", 0)
            if (call["name"] in ("label_replace", "label_join") and args_before == 1) or \
               (call["name"] == "count_values" and args_before == 0):
                label = tok[1:-1]
                if label not in LOCAL_LABELS:
                    problems.append(f"`{call['name']}` creates the label `{label}`, which is not on LOCAL_LABELS")
            # The labels it reads: label_replace's fourth argument, label_join's from the fourth on.
            if (call["name"] == "label_replace" and args_before == 3) or \
               (call["name"] == "label_join" and args_before >= 3):
                label = tok[1:-1]
                if label and label not in LOCAL_LABELS:
                    problems.append(f"`{call['name']}` reads the label `{label}`, which is not on LOCAL_LABELS, "
                                    "into a listed one")
        if tok == "," and stack and stack[-1]["kind"] == "call":
            stack[-1]["args"] = stack[-1].get("args", 0) + 1
        prev = tok
        i += 1
    for sel, enclosing in selectors:
        if sel != "{" and sel in LOCAL_BARE_SERIES:
            continue
        if not any(e.get("kind") == "call" and e.get("agg") for e in enclosing):
            name = "a selector" if sel == "{" else f"`{sel}`"
            problems.append(f"{name} is not inside an aggregation, so the panel would get every label of every "
                            "series; aggregate it (`sum`, `max by (...)`, ...)")
    return sorted(set(problems))


def query_problems(expr: str, kind: str) -> list[str]:
    expr = strip_comments(expr)
    if kind == "loki" and LOG_QUERY_RE.match(expr):
        return ["is a log query (it returns raw lines); use a metric query (count_over_time, sum by, ...)"]
    return query_label_problems(expr, kind)


def lint_local(path: Path, dashboard: dict) -> list[str]:
    """Rules 5 to 5d, for a dashboard in grafana/dashboards."""
    errors: list[str] = []
    for ann in (dashboard.get("annotations") or {}).get("list", []) or []:
        # An annotation keeps its query at the top level (older form) or under `target` (Grafana 11 and later).
        target = ann.get("target") if isinstance(ann.get("target"), dict) else {}
        for source, holder in (("expr", ann), ("target.expr", target)):
            kind = ds_type(holder.get("datasource"), ds_type(ann.get("datasource")))
            if kind in ("prometheus", "loki") and holder.get("expr"):
                for problem in query_problems(str(holder["expr"]), kind):
                    errors.append(f'{path}: annotation "{ann.get("name", "?")}" ({source}): {problem}')
        # What an annotation prints: its title and text templates and its tag keys name labels of the series.
        where = f'{path}: annotation "{ann.get("name", "?")}"'
        for holder in (ann, target):
            for key in ("titleFormat", "textFormat"):
                for label in LEGEND_LABEL_RE.findall(str(holder.get(key) or "")):
                    if label not in LOCAL_LABELS:
                        errors.append(f"{where}: `{key}` names the label `{label}`, which is not on LOCAL_LABELS")
            for label in re.split(r"\s*,\s*", str(holder.get("tagKeys") or "").strip()):
                if label and label not in LOCAL_LABELS:
                    errors.append(f"{where}: `tagKeys` names the label `{label}`, which is not on LOCAL_LABELS")
        for text in strings({k: v for k, v in ann.items() if k != "name"}):
            if re.search(r"(?<![A-Za-z0-9_])instance(?![A-Za-z0-9_])", text):
                errors.append(f"{where}: names the `instance` label (a target's address)")
            for m in FIELD_LABELS_RE.finditer(text):
                if m.group(1) is None or m.group(1) not in LOCAL_LABELS:
                    errors.append(f"{where}: names `__field.labels` without one listed label")
    for panel in panels(dashboard):
        where = f'panel "{panel.get("title", "?")}"'
        if panel.get("type") == "logs":
            errors.append(f"{path}: {where}: a `logs` panel shows raw log lines; chart a metric query instead")
        panel_kind = ds_type(panel.get("datasource"))
        for target in panel.get("targets") or []:
            ref = target.get("refId", "?")
            kind = ds_type(target.get("datasource"), panel_kind)
            if kind == "__expr__" and target.get("type") not in EXPRESSION_TYPES:
                errors.append(f"{path}: {where}: query {ref}: a `{target.get('type')}` expression; only "
                              f"{', '.join(sorted(EXPRESSION_TYPES))} (an SQL expression can select any column)")
            if kind in NO_QUERY_UIDS or kind not in ("prometheus", "loki"):
                continue
            for problem in query_problems(str(target.get("expr", "")), kind):
                errors.append(f"{path}: {where}: query {ref}: {problem}")
            for label in LEGEND_LABEL_RE.findall(str(target.get("legendFormat") or "")):
                if label not in LOCAL_LABELS and label != "__auto":
                    errors.append(f"{path}: {where}: query {ref}: the legend names the label `{label}`, which is "
                                  "not on LOCAL_LABELS")
        for text in strings(panel_without_prose(panel)):
            for m in FIELD_LABELS_RE.finditer(text):
                if m.group(1) is None:
                    errors.append(f"{path}: {where}: names `__field.labels` without a key; name one listed label")
                elif m.group(1) not in LOCAL_LABELS:
                    errors.append(f"{path}: {where}: names the label `{m.group(1)}`, which is not on LOCAL_LABELS")
    return sorted(set(errors), key=errors.index)


def lint_cloud(path: Path, dashboard: dict, datasources: dict[str, str]) -> list[str]:
    """Rules 6 to 9, for a dashboard baked into the production image."""
    errors: list[str] = []

    def fail(where: str, message: str) -> None:
        errors.append(f"{path}: {where}: {message}")

    # 9. No template variables at all.
    for var in (dashboard.get("templating") or {}).get("list", []) or []:
        fail(f'variable "{var.get("name", "?")}"', "a cloud dashboard declares no template variables")

    for panel in panels(dashboard):
        where = f'panel "{panel.get("title", "?")}"'
        kind = panel.get("type")
        if kind not in CLOUD_PANEL_TYPES:
            fail(where, f"panel type `{kind}` is not one a cloud dashboard uses ({', '.join(sorted(CLOUD_PANEL_TYPES))})")

        # 7. Legends and display names name one allowed label each, never the bare label map.
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

        # 8. One datasource per panel, the panel's own.
        panel_uid = (panel.get("datasource") or {}).get("uid") if isinstance(panel.get("datasource"), dict) else None
        uids = {(t.get("datasource") or {}).get("uid") for t in targets}
        if not targets:
            fail(where, "has no query")
        if panel_uid not in datasources:
            fail(where, f"the panel's datasource must be one cloud datasource, not `{panel_uid}`")
        if len(uids) > 1 or (uids and uids != {panel_uid}):
            fail(where, f"mixes datasources ({', '.join(sorted(str(u) for u in uids | {panel_uid}))}); one per panel")

        # 6 and 7. The filter form on stackdriver, naming its datasource's project and allowed labels only.
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


def collect(paths: list[Path], pattern: str = "*.json") -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob(pattern)))
        elif path.exists() and path.match(pattern):
            files.append(path)
    return files


RULE_EXPR_RE = re.compile(r"^\s*(?:-\s*)?expr:\s*(.*?)\s*$")
RULE_KEY_RE = re.compile(r"^(\s*)(?:-\s*)?([A-Za-z_][A-Za-z0-9_]*):\s*(.*?)\s*$")


def lint_loki_rules(path: Path) -> list[str]:
    """Loki recording rules: each expr a metric query that passes rules 5 to 5c; each rule label a listed one."""
    errors: list[str] = []
    labels_indent = None
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key = RULE_KEY_RE.match(line)
        indent = len(key.group(1)) if key else len(line) - len(line.lstrip())
        if labels_indent is not None and indent <= labels_indent:
            labels_indent = None
        if labels_indent is not None and key:
            if key.group(2) not in LOCAL_LABELS:
                errors.append(f"{path}:{number}: a rule label `{key.group(2)}` is not on LOCAL_LABELS")
            continue
        if key and key.group(2) == "labels" and not key.group(3):
            labels_indent = indent
            continue
        m = RULE_EXPR_RE.match(line)
        if not m:
            continue
        try:
            expr = json.loads(m.group(1)) if m.group(1).startswith('"') else None
        except json.JSONDecodeError:
            expr = None
        if not isinstance(expr, str):
            errors.append(f"{path}:{number}: an expr must be one double-quoted line, so the lint can read it")
            continue
        for problem in query_problems(expr, "loki"):
            errors.append(f"{path}:{number}: {problem}")
    return errors


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
        local_targets, cloud_targets = [LOCAL_DIR, *sorted(LOKI_RULES_DIR.glob("*"))], [CLOUD_DIR, CLOUD_DIR / "no-cc"]
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
            else:
                errors.extend(lint_local(path, dashboard))
    rule_files = collect(local_targets, "*.yml")
    for path in rule_files:
        errors.extend(lint_loki_rules(path))
    for line in errors:
        print(line)
    print(f"dashboard_lint: {count} dashboard(s), {len(rule_files)} Loki rule file(s), {len(errors)} problem(s)",
          file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
