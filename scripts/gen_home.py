#!/usr/bin/env python3
"""Generate the home dashboard, grafana/dashboards/home.json (uid tw-home). Standard library only.

The home page answers "is anything wrong, and where" in a few seconds, and never says "normal" when it cannot see:

  - a headline (server-side expressions) that names each problem (up to three; above that, one roll-up line), says
    the running systems are normal, or reads "? Can't tell";
  - "What's wrong now", every problem as a row, worst first;
  - the watchtower itself: Prometheus and Loki each in its own tile, so neither hides the other;
  - a live map of every stack (Canvas), each card coloured by its checks' state (the `probe:state` recording rule);
  - tpa-api traffic, ERROR lines and new error groups;
  - every check (state, HTTP code, latency and its trend, uptime) and its history;
  - background work, error groups and drill-down links in collapsed rows.

The log-derived numbers (worker ages, ERROR and restart counts, auth's not-ready lines, the drains, records' velocity
lines) are not read from Loki on every refresh: Loki's ruler records them every 30 s and writes them to Prometheus
(loki/rules/fake/home.yml), and the page reads those few series. The alerts for them sit beside the probe alerts
(prometheus/rules/home.yml): among them "a staff account was frozen" (red) and "held" (amber), which the Security page
(scripts/gen_security.py) explains. This script writes all three files, so a worker's limits and the velocity
contract live in one place.

Usage:
  scripts/gen_home.py                     write home.json, loki/rules/fake/home.yml and prometheus/rules/home.yml
  scripts/gen_home.py --check             exit 1 when any of them is not what this script writes
  scripts/gen_home.py --candidate UID OUT write a copy under another uid (a review candidate)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "grafana" / "dashboards" / "home.json"
LOKI_RULES = ROOT / "loki" / "rules" / "fake" / "home.yml"
PROM_RULES = ROOT / "prometheus" / "rules" / "home.yml"
TARGETS = ROOT / "prometheus" / "targets"

# ---------------------------------------------------------------------------------------------------------------------
# Tokens. A state always has an icon and a word as well as a colour. "Up" is teal, not green: green and red sit 4.1
# apart for a deuteranope, teal and red 13+ (the dataviz palette validator, dark surface).
# ---------------------------------------------------------------------------------------------------------------------
UP = "#14b8a6"
UP_DIM = "#0f3d38"        # up in a history: quiet
UP_FILL = "#0f766e"       # a filled teal block, with white ink
WARN = "#fab219"
DOWN = "#d03b3b"          # a red fill (white ink on it)
RED_TEXT = "#f26b6b"      # red as text on the dark surface (5.8:1)
OFF = "#8b8e96"           # "not running" text
INK = "#e3e4ea"
INK_2 = "#a7a9b3"
INK_DARK = "#0b0b0b"
WHITE = "#ffffff"
CARD = "#1f2228"
LINE = "#2c3038"          # dividers and quiet card borders
NEUTRAL = "#5b5f6a"       # edges, neutral bars and sparklines
TINT_WARN = "#33290f"
TINT_DOWN = "#3b1a1d"
CLEAR = "transparent"

PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}
EXPR = {"type": "__expr__", "uid": "__expr__", "name": "Expression"}
MIXED = {"type": "datasource", "uid": "-- Mixed --"}
DASHBOARD_DS = {"type": "datasource", "uid": "-- Dashboard --"}

HERO_ID = 1
NEW_GROUPS_ID = 14

# ---------------------------------------------------------------------------------------------------------------------
# What is watched. Every service in prometheus/targets/*.yml has a card (tests/dashboards/test_home.py).
# ---------------------------------------------------------------------------------------------------------------------
WATCHTOWER_JOBS = "blackbox|loki|alloy|prometheus"
DASH_BY_SERVICE = [
    ("tw-tpa-edge-api", "web-tls|trellis|web|tpa-api"),
    ("tw-auth", "auth|auth-publisher|auth-sweeper|auth-outbox-publisher"),
    ("tw-records", "records"),
    ("tw-jobs-connectors", "connectors|tpa-jobs-drains|crm_transitions|outbox_dispatch"),
    ("tw-crm-network", "network-engine|network-tpa"),
    ("tw-forge", "forge-engine"),
    ("tw-enroll", "enroll-engine"),
    ("tw-feed-ingest", "feed-ingest"),
    # An alert's row is named after the alert: the security ones open the Security page.
    ("tw-security", "StaffAccountFrozen|StaffAccountHeld"),
]
# Services with a card of their own. Any other probed service (the TPA_NET overlay's web, connectors and
# tpa-jobs-drains, or a target added later) lands on the "other checks" card.
CARD_SERVICES = ["web-tls", "trellis", "tpa-api", "records", "auth", "network-engine", "network-tpa", "forge-engine",
                 "enroll-engine", "feed-ingest"]
CHECK_ORDER = [("web-tls", "tls"), ("trellis", "release"), ("tpa-api", "health"), ("tpa-api", "ready"),
               ("auth", "ready"), ("records", "ready"), ("records", "db"), ("network-engine", "db"), ("network-tpa", "db"),
               ("forge-engine", "db"), ("enroll-engine", "db"), ("feed-ingest", "health")]


def configured_checks() -> int:
    """How many probes prometheus/targets/*.yml configures, so the home can say when one is not loaded."""
    count = 0
    for path in sorted(TARGETS.glob("*.yml")):
        for group in re.findall(r"targets:\s*\[([^\]]*)\]", path.read_text()):
            count += len([t for t in group.split(",") if t.strip()])
    return count


# (key, card title, the INFO tick or summary line that means "reported", the ERROR lines, amber s, red s)
DRAINS = '{stack="tpa", service="tpa-jobs-drains"} |= `"tenants_total"`'
WORKERS = [
    ("connectors", "connectors",
     '{stack="tpa", service="connectors"} | level="INFO" | outcome="pass"',
     '{stack="tpa", service="connectors"} | level="ERROR"', 60, 120),
    ("crm_transitions", "crm_transitions",
     f'{DRAINS} | job="crm_transitions"',
     '{stack="tpa", service="tpa-jobs-drains"} | level="ERROR" | operation="crm_transitions" or job="crm_transitions"',
     90, 180),
    ("outbox_dispatch", "outbox_dispatch",
     f'{DRAINS} | job="outbox_dispatch"',
     '{stack="tpa", service="tpa-jobs-drains"} | level="ERROR" | operation="outbox_dispatch" or job="outbox_dispatch"',
     90, 180),
    ("auth-publisher", "auth-publisher",
     '{stack="tpa", service="auth-publisher"} |= "publisher: "',
     '{stack="tpa", service="auth-publisher"} | level="ERROR"', 75, 150),
    ("auth-sweeper", "auth-sweeper",
     '{stack="tpa", service="auth-sweeper"} | level="INFO" | outcome="ok"',
     '{stack="tpa", service="auth-sweeper"} | level="ERROR"', 450, 900),
]

# ---------------------------------------------------------------------------------------------------------------------
# PromQL. probe:state (prometheus/rules/local.yml) is computed once: 3 up, 2 degraded (a db probe's 2xx body says the
# database is down), 1 down (no answer, a 503 or any other status), 0 not running.
# ---------------------------------------------------------------------------------------------------------------------
PS = 'probe_success{job="blackbox"}'
CODE = 'probe_http_status_code{job="blackbox"}'
SCRAPES = f'up{{job=~"{WATCHTOWER_JOBS}"}}'
SINCE_UP = (f"(max by (stack, service, probe) (max_over_time(timestamp({PS} == 1)[24h:30s]))"
            f" or min by (stack, service, probe) (min_over_time(timestamp({PS})[24h:30s]))) * 1000")
CODES = (f'label_replace(count_values by (stack, service, probe) ("code", {CODE}), "code", "no answer", "code", "0")'
         f' or label_replace(count by (stack, service, probe) (probe_success{{job="blackbox", probe="tls"}}),'
         f' "code", "TLS", "", "")')
FAILING = "(max by (stack, service, probe) (probe:state) > 0 < 3)"
TPADB_STATE = 'max(probe:state{service="records", probe="db"})'
TPADB_SAYS_DOWN = ('(max(max_over_time(probe_success{job="blackbox-reason", service="records", probe="db-down"}[90s]))'
                   " or vector(0))")
# Alerts the headline already shows as problems of their own: the failing checks, auth not ready, a stale worker.
SHOWN_ALERTS = "ProbeDown|DatabaseReportedDown|AuthNotReady|WorkerStale"
def live(series: str) -> str:
    """An ALERTS series only while its rule still writes it (every 30 s). After a restart Prometheus keeps the last
    sample a cleared alert wrote before it stopped, and a query reads it for five minutes as if it still fired."""
    return f"({series} and (time() - timestamp({series}) < 75))"


ALERTS_OWN = live(f'ALERTS{{alertstate="firing", alertname!~"{SHOWN_ALERTS}"}}')
# The alerts of our own that are amber on the headline and in "What's wrong now" (a held staff account: records
# refuses some reads, and it clears itself); every other is red.
OWN_AMBER_ALERTS = "StaffAccountHeld"
ALERTS_OWN_RED = live(f'ALERTS{{alertstate="firing", alertname!~"{SHOWN_ALERTS}|{OWN_AMBER_ALERTS}"}}')
ALERTS_OWN_AMBER = live(f'ALERTS{{alertstate="firing", alertname=~"{OWN_AMBER_ALERTS}"}}')
# A firing alert is red unless it is about a degraded check (a 2xx whose body says the database is down) or a held
# staff account: amber.
AMBER_ALERTS = f"DatabaseReportedDown|{OWN_AMBER_ALERTS}"


def with_dash(expr: str) -> str:
    """Add `dash`, the dashboard a row or card opens, from the service label (the home's own for anything else)."""
    for uid, services in DASH_BY_SERVICE:
        expr = f'label_replace({expr}, "dash", "{uid}", "service", "{services}")'
    return f'label_replace({expr}, "dash", "tw-overview", "dash", "")'


def labelled(expr: str, **labels: str) -> str:
    for key, value in labels.items():
        expr = f'label_replace({expr}, "{key}", "{value}", "", "")'
    return expr


def check_of(expr: str) -> str:
    """`check`: "service · probe" for a probe, else the service, so one column names every problem."""
    return (f'label_replace(label_join({expr}, "check", " · ", "service", "probe"), "check", "$1", "check", '
            f'"(.*) · ")')


def problem_checks(state: int, word: str, rank: str) -> str:
    return with_dash(check_of(labelled(
        f"(({SINCE_UP}) * on (stack, service, probe) group_left (code) ({CODES})"
        f" and on (stack, service, probe) (max by (stack, service, probe) (probe:state) == {state}))",
        state=word, rank=rank)))


# ---------------------------------------------------------------------------------------------------------------------
# LogQL.
# ---------------------------------------------------------------------------------------------------------------------
AGE_FMT = "label_format age_s=`{{ sub (unixEpoch now) (unixEpoch __timestamp__) }}` | unwrap age_s"
TS_FMT = "label_format ts=`{{ unixEpochMillis __timestamp__ }}` | unwrap ts"
ALL_LINES = '{stack=~".+", stack!="fixture"}'
ERRORS = f'{ALL_LINES} | level="ERROR"'
WHERE = "label_format where=`{{ or .operation .route }}`"
# A constant's name only (scripts/dashboard_lint.py VETTED_LABEL_FORMATS): a message in lower case, digits,
# underscores and spaces; a reason in letters and underscores. Anything else becomes "other" before it is grouped.
REASON = ('label_format reason_code=`{{ if eq (regexReplaceAll "^[A-Za-z][A-Za-z_]{0,39}$" .rc "") "" }}{{ .rc }}'
          '{{ else }}other{{ end }}`')
NAMES = ('json m1="msg", m2="message", rc="reason" | label_format '
         'msg_name=`{{ $m := or .m1 .m2 }}{{ if eq (regexReplaceAll "^[a-z][a-z0-9_ ]{0,59}$" $m "") "" }}{{ $m }}'
         '{{ else }}other{{ end }}`, '
         'reason_code=`{{ if eq (regexReplaceAll "^[A-Za-z][A-Za-z_]{0,39}$" .rc "") "" }}{{ .rc }}{{ else }}other'
         '{{ end }}`')
GROUP_KEY = "service, exc_class, where, sqlstate, msg_name, reason_code"
GROUPS_24H = f"sum by ({GROUP_KEY}) (count_over_time({ERRORS} | {WHERE} | {NAMES} [24h]))"
GROUPS_PRIOR = f"sum by ({GROUP_KEY}) (count_over_time({ERRORS} | {WHERE} | {NAMES} [6d] offset 1d))"
TPA_API = '{stack="tpa", service="tpa-api"}'
API = f'{TPA_API} | route!="" | route!~"/health|/ready"'
RAISED = '{stack="tpa", service="tpa-jobs-drains"} |= `a drain tick raised`'
TENANTS_NOT_OK = (f'{DRAINS} | json f="tenants_failed", p="tenants_partial", k="tenants_skipped" | __error__="" '
                  '| label_format n=`{{ add .f .p .k }}`')
# auth's /ready refusal names its reason in the log line only (auth/api/health.py): database, signer, clock, ...
NOT_READY = '{stack="tpa", service="auth"} |~ `"msg": ?"not_ready"` | json rc="reason"'
STARTUPS = [("auth", '{stack="tpa", service="auth"} |= "Application startup complete"'),
            ("tpa-api", '{stack="tpa", service="tpa-api"} |= "Application startup complete"'),
            ("records", '{stack="tpa", service="records"} | operation="records.startup" |= "permissions_mode_set"')]

# records' velocity lines, the limit on how many members one staff person reads (bodyfirst tasks/security-watch
# SPEC §7): message "velocity", `code` one of velocity_flag|velocity_hold|velocity_freeze, `decision` enforce or
# report, `reason` the measure it crossed, `role` one internal role name. A settings change is message "velocity
# settings changed", `code` velocity_settings_changed, `reason` the field; the people's acts are velocity_lift,
# velocity_clear_signed (`reason` admin or compliance) and velocity_cleared. Alloy rebuilds every such line from that
# allowlist (alloy/config.alloy, 4b), so its values are closed words. The Security page (scripts/gen_security.py)
# reads the same constants.
RECORDS = '{stack="tpa", service="records"}'
VELOCITY = f'{RECORDS} |= `"message":"velocity"` | json code, decision'
VELOCITY_STATES = f'{VELOCITY} | code=~"velocity_(flag|hold|freeze)"'
VELOCITY_SETTINGS = f'{RECORDS} |= `velocity_settings_changed` | json code, role | code="velocity_settings_changed"'
# Every word a velocity line's `reason` may hold (SPEC §2.2, §6.5, §7.5): the six measures (members opened or
# listed, reveals, each in the hour or the day), the six tenant settings a change can name, and the half of a clear.
# The Alloy rebuild, the lint's `measure` template and the Security page all use this list.
VELOCITY_MEASURES = ("opened_1h", "opened_1d", "listed_1h", "listed_1d", "reveals_1h", "reveals_1d")
VELOCITY_REASONS = VELOCITY_MEASURES + ("hold_multiplier", "freeze_multiplier", "lift_minutes", "lifts_per_day",
                                        "mode", "unbound_multiplier", "admin", "compliance")
# The people's acts (SPEC §7.5) and the meter's own failures (§7.3, §7.4).
VELOCITY_ACTS = f'{RECORDS} |= `"code":"velocity_` | json code | code=~"velocity_(lift|clear_signed|cleared)"'
VELOCITY_FAILED = f'{RECORDS} |= `"code":"velocity_` | json code | code=~"velocity_(meter_failed|freeze_unwritten)"'
# How long a freeze, or a hold, stays on the headline after its line. A freeze stays until two people clear it, and
# the clear's line does not say whose freeze it ended, so it holds for a day rather than go quiet on the wrong one; a
# hold clears itself as its window slides.
FREEZE_SHOWN, HOLD_SHOWN = "24h", "1h"


# ---------------------------------------------------------------------------------------------------------------------
# Recorded by Loki's ruler every 30 s (loki/rules/fake/home.yml) and written to Prometheus. A count looks at the 30 s
# that ended 15 s ago, so a line Alloy ships a few seconds late still lands in a window; a time (the newest or oldest
# line) looks at the last minute, so consecutive windows overlap and none is missed. A worker's last report looks back
# over its whole red limit, so the first evaluation after the ruler starts already knows it (a shorter window would
# read every quiet worker as stale until its next tick).
# ---------------------------------------------------------------------------------------------------------------------
def _count(sel: str) -> str:
    return f"sum(count_over_time({sel} [30s] offset 15s)) or vector(0)"


def loki_rules() -> list[tuple[str, str, dict]]:
    """(record, LogQL, labels) for every series the home page reads instead of reading lines."""
    rules = [
        # Written on every evaluation (0 when nothing logged): its absence means the ruler is not writing.
        ("tw:loki_rules:heartbeat", _count(ALL_LINES), {}),
        ("tw:loki_lines:sum30s", f"sum by (stack, service) (count_over_time({ALL_LINES} [30s] offset 15s))", {}),
        ("tw:error_lines:sum30s", _count(ERRORS), {}),
    ]
    for key, _t, ok, err, _a, red in WORKERS:
        rules += [("tw:worker_ok_ms:max", f"max(max_over_time({ok} | {TS_FMT} [{red}s]))", {"service": key}),
                  ("tw:worker_errors:sum30s", _count(err), {"service": key}),
                  ("tw:worker_error_ms:min", f"min(min_over_time({err} | {TS_FMT} [1m]))", {"service": key})]
    rules += [
        ("tw:drain_raised:sum30s", _count(RAISED), {}),
        ("tw:drain_raised_ms:min", f"min(min_over_time({RAISED} | {TS_FMT} [1m]))", {}),
        ("tw:drain_tenants_not_ok:sum30s",
         f"sum(sum_over_time({TENANTS_NOT_OK} | unwrap n [30s] offset 15s)) or vector(0)", {}),
        ("tw:drain_tenants_not_ok_ms:min", f"min(min_over_time({TENANTS_NOT_OK} | n > 0 | {TS_FMT} [1m]))", {}),
        ("tw:auth_not_ready:sum30s",
         f"sum by (reason_code) (count_over_time({NOT_READY} | {REASON} [30s] offset 15s))", {}),
        ("tw:auth_not_ready_ms:min", f"min by (reason_code) (min_over_time({NOT_READY} | {REASON} | {TS_FMT} [1m]))",
         {}),
        # records' velocity lines in the last 10 minutes, by state and mode. Each line is seen by some twenty
        # evaluations, so one freeze line is never missed, even shipped minutes late (a count would double it; the
        # alerts only ask whether there was one).
        ("tw:velocity_lines:count10m", f"sum by (code, decision) (count_over_time({VELOCITY_STATES} [10m]))", {}),
    ]
    return rules


# PromQL over the recorded series. FRESH holds while lines are reaching Loki: the ruler counted at least one line
# from any stack in the last minute. Every log-derived answer is gated on it, so when the ruler stops writing, or Loki
# stops taking lines (on 2026-10-12 its WAL refused writes for six minutes when the Docker disk passed 90%), the page
# reads "? Can't tell", never "stale" for workers that are only unheard.
FRESH = "(sum(sum_over_time(tw:loki_rules:heartbeat[1m])) > 0)"
RULES_ABSENT = "absent_over_time(tw:loki_rules:heartbeat[2m])"
NO_LINES = "(sum(sum_over_time(tw:loki_rules:heartbeat[1m])) == 0)"
TPA_LINES_5M = '(sum(sum_over_time(tw:loki_lines:sum30s{stack="tpa"}[5m])) or vector(0))'
ERROR_LINES_10M = "sum(sum_over_time(tw:error_lines:sum30s[10m]))"


def ok_ms(key: str) -> str:
    return f'max(max_over_time(tw:worker_ok_ms:max{{service="{key}"}}[1h]))'


def age(key: str) -> str:
    """Seconds since the worker's last INFO tick or summary line; 3600 when there has been none for an hour."""
    return f"(time() - {ok_ms(key)} / 1000 or vector(3600))"


def errors_15m(key: str) -> str:
    return f'(sum(sum_over_time(tw:worker_errors:sum30s{{service="{key}"}}[15m])) or vector(0))'


def first_error_ms(key: str) -> str:
    return f'min(min_over_time(tw:worker_error_ms:min{{service="{key}"}}[24h]))'


def worker_state(key: str, amber: int, red: int) -> str:
    """3 on time, 2.5 late, 2 erroring (ERROR lines in 15 min), 1 stale (no report within the red limit); 5 when the
    ruler is not writing (can't tell)."""
    a, e = age(key), errors_15m(key)
    return (f"((3 - 2 * ({a} > bool {red}) - ({a} <= bool {red}) * "
            f"(({e} > bool 0) + 0.5 * ({a} > bool {amber}) * ({e} == bool 0))) and on () {FRESH}) or vector(5)")


def startups_24h(sel: str) -> str:
    """Starts in 24 h, read from Loki itself: a count the ruler recorded would read 0 for the first day after it
    started (it cannot look back), and with both sides 24 h Loki caches the past hours (about 1.6 MB a refresh each).
    0 only when the service logged at all in those 24 h."""
    stream = sel.split("}")[0] + "}"
    return f"sum(count_over_time({sel} [24h])) or 0 * sum(count_over_time({stream} [24h]))"


# ---------------------------------------------------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------------------------------------------------
def prom(ref, expr, legend="__auto", instant=True, fmt=None, hide=False):
    t = {"refId": ref, "datasource": PROM, "editorMode": "code", "expr": expr, "legendFormat": legend,
         "range": not instant, "instant": instant}
    if fmt:
        t["format"] = fmt
    if hide:
        t["hide"] = True
    return t


def loki(ref, expr, legend="", instant=True, hide=False):
    t = {"refId": ref, "datasource": LOKI, "editorMode": "code", "expr": expr, "legendFormat": legend,
         "queryType": "instant" if instant else "range"}
    if hide:
        t["hide"] = True
    return t


def math(ref, expression):
    return {"refId": ref, "datasource": EXPR, "type": "math", "expression": expression}


def vmap(mapping: dict) -> dict:
    return {"type": "value", "options": {str(k): {"text": t, "color": c, "index": i}
                                         for i, (k, (t, c)) in enumerate(mapping.items())}}


def rmap(frm, to, text, color=None, index=0):
    result = {"text": text, "index": index}
    if color:
        result["color"] = color
    return {"type": "range", "options": {"from": frm, "to": to, "result": result}}


def regex_map(pattern, color, index):
    return {"type": "regex", "options": {"pattern": pattern, "result": {"color": color, "index": index}}}


def steps(*pairs):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in pairs]}


def link(title, uid):
    return {"title": title, "url": f"/d/{uid}?${{__url_time_range}}", "targetBlank": False}


def by_name(name, *props):
    return {"matcher": {"id": "byName", "options": name}, "properties": [{"id": k, "value": v} for k, v in props]}


def by_regex(pattern, *props):
    return {"matcher": {"id": "byRegexp", "options": pattern}, "properties": [{"id": k, "value": v} for k, v in props]}


# Layout, in grid rows. The top band (headline, the Prometheus and Loki tiles) is TOP tall, the KPI strip under it
# KPI_H, and the map starts below both. "What's wrong now" runs down the middle to one row above the map, the "+N
# more" line in that last row. At small row height it holds ROWS_SHOWN rows in full (checked on screen at 1600 and
# 2560: a Grafana grid row is 30 px at any width), and it is limited to them, so no row is ever cut off.
TOP = 6
KPI_H = 3
KPI_VALUE = 40
MAP_Y = TOP + KPI_H
ROWS_SHOWN = 6


def panel(pid, kind, title, x, y, w, h, **kw):
    p = {"id": pid, "type": kind, "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h}}
    p.update(kw)
    return p


def stat_options(text=None, color_mode="background_solid", graph="none", text_mode="value", orientation="auto",
                 calcs=("lastNotNull",), fields=""):
    o = {"reduceOptions": {"calcs": list(calcs), "fields": fields, "values": False}, "colorMode": color_mode,
         "graphMode": graph, "justifyMode": "center", "orientation": orientation, "textMode": text_mode,
         "wideLayout": True, "showPercentChange": False}
    if text:
        o["text"] = text
    return o


def shown_if(ref, expression, condition):
    """Server-side: `expression` where `condition` holds, and no series at all where it does not. Dividing by a false
    condition gives NaN or Inf, and a reduce that drops non-numbers then drops the series."""
    return [{**math(f"{ref}_", f"({expression}) / ({condition})"), "hide": True},
            {"refId": ref, "datasource": EXPR, "type": "reduce", "expression": f"${ref}_", "reducer": "last",
             "settings": {"mode": "dropNN"}}]


# State words, glyphs and colours. Up is quiet (grey word, teal ✓, a 2 px border in the line colour); degraded and down
# are loud (a filled pill, a tinted card, an amber or red border); not running is grey.
STATE_WORD = vmap({0: ("not running", OFF), 1: ("down", WHITE), 2: ("degraded", INK_DARK), 3: ("up", INK_2)})
STATE_GLYPH = vmap({0: ("○", OFF), 1: ("✕", WHITE), 2: ("▲", INK_DARK), 3: ("✓", UP)})
STATE_PILL = vmap({0: ("", CLEAR), 1: ("", DOWN), 2: ("", WARN), 3: ("", CLEAR)})
STATE_RING = vmap({0: ("", LINE), 1: ("", DOWN), 2: ("", WARN), 3: ("", LINE)})
STATE_FILL = vmap({0: ("", CARD), 1: ("", TINT_DOWN), 2: ("", TINT_WARN), 3: ("", CARD)})
STATE_INK = vmap({0: ("", OFF), 1: ("", INK), 2: ("", INK), 3: ("", INK)})
STATE_EDGE = vmap({0: ("", LINE), 1: ("", DOWN), 2: ("", WARN), 3: ("", NEUTRAL)})
STACK_WORD = vmap({0: ("not running", OFF), 1: ("down", WHITE), 2: ("degraded", INK_DARK), 3: ("running", INK_2)})
# A database card follows the service whose health covers it: inferred, never a login of ours. A db probe whose 2xx
# body says the database is down is the application reporting it: red. A service that is down says nothing about its
# database: unknown.
INFER_WORD = vmap({0: ("not running", OFF), 1: ("unknown", INK_2), 2: ("reported down", WHITE),
                   3: ("inferred up", INK_2)})
INFER_GLYPH = vmap({0: ("○", OFF), 1: ("?", INK_2), 2: ("✕", WHITE), 3: ("✓", INK_2)})
INFER_PILL = vmap({0: ("", CLEAR), 1: ("", CLEAR), 2: ("", DOWN), 3: ("", CLEAR)})
INFER_RING = vmap({0: ("", LINE), 1: ("", LINE), 2: ("", DOWN), 3: ("", LINE)})
INFER_FILL = vmap({0: ("", CARD), 1: ("", CARD), 2: ("", TINT_DOWN), 3: ("", CARD)})
# auth-db: auth's state, plus 10 when auth logged "not_ready" with the reason "database" in the last 2 minutes.
AUTHDB_RED = {n: ("reported down", WHITE) for n in (10, 11, 12, 13)}
AUTHDB_WORD = vmap({0: ("not running", OFF), 1: ("unknown", INK_2), 2: ("unknown", INK_2), 3: ("inferred up", INK_2),
                    **AUTHDB_RED})
AUTHDB_GLYPH = vmap({0: ("○", OFF), 1: ("?", INK_2), 2: ("?", INK_2), 3: ("✓", INK_2),
                     **{n: ("✕", WHITE) for n in (10, 11, 12, 13)}})
AUTHDB_PILL = vmap({**{n: ("", CLEAR) for n in (0, 1, 2, 3)}, **{n: ("", DOWN) for n in (10, 11, 12, 13)}})
AUTHDB_RING = vmap({**{n: ("", LINE) for n in (0, 1, 2, 3)}, **{n: ("", DOWN) for n in (10, 11, 12, 13)}})
AUTHDB_FILL = vmap({**{n: ("", CARD) for n in (0, 1, 2, 3)}, **{n: ("", TINT_DOWN) for n in (10, 11, 12, 13)}})
# tpa-db: records' /ready asked only about the database (the "db" probe): it says up (3); it answered 503 saying
# "database": false (1, red); or anything else while the check fails (5: unknown, amber, since the check is failing
# but nothing says the database is down).
TPADB_WORD = vmap({1: ("reported down", WHITE), 3: ("reported up", INK_2), 5: ("unknown", INK_DARK)})
TPADB_GLYPH = vmap({1: ("✕", WHITE), 3: ("✓", INK_2), 5: ("?", INK_DARK)})
TPADB_PILL = vmap({1: ("", DOWN), 3: ("", CLEAR), 5: ("", WARN)})
TPADB_RING = vmap({1: ("", DOWN), 3: ("", LINE), 5: ("", WARN)})
TPADB_FILL = vmap({1: ("", TINT_DOWN), 3: ("", CARD), 5: ("", TINT_WARN)})
UNMAPPED_WORD = vmap({0: ("not running", OFF), 1: ("down", WHITE), 2: ("degraded", INK_DARK), 3: ("up", INK_2),
                      4: ("none", INK_2)})
UNMAPPED_GLYPH = vmap({0: ("○", OFF), 1: ("✕", WHITE), 2: ("▲", INK_DARK), 3: ("✓", UP), 4: (" ", INK_2)})
# 5: Loki's rules are not arriving, so the page cannot tell.
JOB_WORD = vmap({1: ("stale", WHITE), 2: ("erroring", INK_DARK), 2.5: ("late", INK_DARK), 3: ("on time", INK_2),
                 5: ("can't tell", INK_2)})
JOB_GLYPH = vmap({1: ("✕", WHITE), 2: ("▲", INK_DARK), 2.5: ("▲", INK_DARK), 3: ("✓", UP), 5: ("?", INK_2)})
JOB_PILL = vmap({1: ("", DOWN), 2: ("", WARN), 2.5: ("", WARN), 3: ("", CLEAR), 5: ("", CLEAR)})
JOB_RING = vmap({1: ("", DOWN), 2: ("", WARN), 2.5: ("", WARN), 3: ("", LINE), 5: ("", LINE)})
JOB_FILL = vmap({1: ("", TINT_DOWN), 2: ("", TINT_WARN), 2.5: ("", TINT_WARN), 3: ("", CARD), 5: ("", CARD)})
# History: up is dim, "not running" is empty, so colour means a problem.
HISTORY = vmap({0: ("not running", CLEAR), 1: ("down", DOWN), 2: ("degraded", WARN), 3: ("up", UP_DIM)})


# ---------------------------------------------------------------------------------------------------------------------
# Problems: the headline and "What's wrong now" read the same list.
# ---------------------------------------------------------------------------------------------------------------------
# Each side counts its own problems, so one source going blind never hides the other's (the headline gates each
# side's lines on its own count): the checks (Prometheus' probes and alerts) and the logs (what Loki's ruler records).
# The watchtower's own blindness is counted apart and always shown.
STALE_BOOL = [f"({age(key)} > bool {red})" for key, _t, _o, _e, _a, red in WORKERS]
ERRORING_BOOL = [f"({errors_15m(key)} > bool 0)" for key, *_ in WORKERS]
DRAINS_BOOL = ["((sum(sum_over_time(tw:drain_raised:sum30s[1h])) or vector(0)) > bool 0)",
               "((sum(sum_over_time(tw:drain_tenants_not_ok:sum30s[1h])) or vector(0)) > bool 0)"]
NOT_READY_BOOL = "((sum(sum_over_time(tw:auth_not_ready:sum30s[2m])) or vector(0)) > bool 0)"
# Logs: workers stale or erroring, drains, auth not ready, only while the ruler is writing. Red: all but erroring.
# Each total is parenthesised whole: `and` binds looser than `+` and `>`, so a bare one would swallow what follows.
LOKI_PROBLEMS = f"(({' + '.join(STALE_BOOL + ERRORING_BOOL + DRAINS_BOOL + [NOT_READY_BOOL])}) and on () {FRESH})"
LOKI_RED = f"(({' + '.join(STALE_BOOL + DRAINS_BOOL + [NOT_READY_BOOL])}) and on () {FRESH})"
# Blind: the ruler stopped writing; it writes but no line from any stack arrived in a minute; or lines arrive but none
# from tpa in 5 minutes.
LOKI_BLIND = (f"(((({TPA_LINES_5M} == bool 0) and on () {FRESH}) or vector(0))"
              f" + ({RULES_ABSENT} or vector(0)) + (({NO_LINES} * 0 + 1) or vector(0)))")
# Prometheus: failing checks and firing alerts other than ProbeDown and DatabaseReportedDown (those are the failing
# checks). Red: all but degraded checks.
PROM_PROBLEMS = f"(count({FAILING}) or 0 * count(probe:state)) + (count({ALERTS_OWN}) or vector(0))"
PROM_RED = (f"(count(max by (stack, service, probe) (probe:state) == 1) or 0 * count(probe:state))"
            f" + (count({ALERTS_OWN_RED}) or vector(0))")
PROM_BLIND = f'(count({SCRAPES} == 0) or 0 * count({SCRAPES})) + (absent(up{{job="blackbox"}}) or vector(0))'
LOKI_PROBLEMS_TOTAL = f"{LOKI_PROBLEMS} + {LOKI_BLIND}"
PROM_PROBLEMS_TOTAL = f"{PROM_PROBLEMS} + {PROM_BLIND}"
# (refId, legend, colour, side) for the per-problem lines, red first, then amber.
PROBLEM_KINDS = [
    ("PD", "✕ ${__field.labels.check} down · ${__field.labels.code}", DOWN, "P"),
    ("NR", "✕ auth not ready · ${__field.labels.code}", DOWN, "L"),
    ("AL", "✕ alert ${__field.labels.alertname}", DOWN, "P"),
    ("WS", "✕ ${__field.labels.check} stale", DOWN, "L"),
    ("DR", "✕ drains: ${__field.labels.state}", DOWN, "L"),
    ("PG", "▲ ${__field.labels.check} degraded · ${__field.labels.code}", WARN, "P"),
    ("WE", "▲ ${__field.labels.check} erroring", WARN, "L"),
    ("AW", "▲ alert ${__field.labels.alertname}", WARN, "P"),
]
# The watchtower's own blindness: never rolled up, always named.
BLIND_KINDS = [
    ("BL", "? Watchtower blind: ${__field.labels.job} not scraped"),
    ("BA", "? Watchtower blind: no checks loaded"),
    ("BK", "? Watchtower blind: no tpa lines in 5 min"),
    ("BR", "? Watchtower blind: Loki's rules stopped"),
    ("BN", "? Watchtower blind: no lines into Loki"),
]


def problems(table=False, hide=False):
    """Every problem as a series labelled check, state, rank (0 red, 1 amber) and dash (and code for a check),
    valued with when it began (epoch ms; 1 when that is not known)."""
    fmt = "table" if table else None
    stale = " or ".join(
        labelled(f"({ok_ms(key)} or vector(1)) and ({age(key)} > {red})",
                 service=key, check=key, state="stale", rank="0")
        for key, _t, _o, _e, _a, red in WORKERS)
    # Since: the first ERROR line in the last 24 h.
    erroring = " or ".join(
        labelled(f"({first_error_ms(key)} or vector(1)) and ({errors_15m(key)} > 0)",
                 service=key, check=key, state="erroring", rank="1")
        for key, *_ in WORKERS)
    drains = (labelled("(min(min_over_time(tw:drain_raised_ms:min[1h])) or vector(1))"
                       " and (sum(sum_over_time(tw:drain_raised:sum30s[1h])) > 0)",
                       service="tpa-jobs-drains", check="tpa-jobs-drains", state="tick raised", rank="0")
              + " or " + labelled("(min(min_over_time(tw:drain_tenants_not_ok_ms:min[1h])) or vector(1))"
                                  " and (sum(sum_over_time(tw:drain_tenants_not_ok:sum30s[1h])) > 0)",
                                  service="tpa-jobs-drains", check="tpa-jobs-drains", state="tenants not ok",
                                  rank="0"))
    not_ready = labelled(
        'label_replace(min by (reason_code) (min_over_time(tw:auth_not_ready_ms:min[15m]))'
        " and on (reason_code) (sum by (reason_code) (sum_over_time(tw:auth_not_ready:sum30s[2m])) > 0),"
        ' "code", "$1", "reason_code", "(.*)")', service="auth", check="auth", state="not ready", rank="0")

    def logs(expr: str) -> str:
        return f"({expr}) and on () {FRESH}"

    return [
        prom("PD", problem_checks(1, "down", "0"), "✕ {{check}} down · {{code}}", fmt=fmt, hide=hide),
        prom("PG", problem_checks(2, "degraded", "1"), "▲ {{check}} degraded · {{code}}", fmt=fmt, hide=hide),
        prom("AL", with_dash(check_of(labelled(
            f'label_replace(max by (alertname) (ALERTS_FOR_STATE{{alertname!~"ProbeDown|DatabaseReportedDown"}}) * 1000'
            f' and on (alertname) count by (alertname) ({ALERTS_OWN_RED}), "service", "$1", "alertname", "(.*)")',
            state="firing", rank="0"))), "✕ alert {{alertname}}", fmt=fmt, hide=hide),
        prom("AW", with_dash(check_of(labelled(
            f'label_replace(max by (alertname) (ALERTS_FOR_STATE{{alertname=~"{OWN_AMBER_ALERTS}"}}) * 1000'
            f' and on (alertname) count by (alertname) ({ALERTS_OWN_AMBER}), "service", "$1", "alertname", "(.*)")',
            state="warning", rank="1"))), "▲ alert {{alertname}}", fmt=fmt, hide=hide),
        prom("BL", with_dash(check_of(labelled(
            f'label_replace(max by (job) (max_over_time(timestamp({SCRAPES} == 1)[24h:1m])) * 1000'
            f' and on (job) (max by (job) ({SCRAPES}) == 0), "service", "$1", "job", "(.*)")', state="not scraped",
            rank="0"))), "? Watchtower blind: {{job}} not scraped", fmt=fmt, hide=hide),
        prom("BA", with_dash(check_of(labelled('absent(up{job="blackbox"})', service="blackbox", state="no checks",
                                               rank="0"))), "? Watchtower blind: no checks loaded", fmt=fmt, hide=hide),
        prom("WS", with_dash(logs(stale)), "✕ {{check}} stale", fmt=fmt, hide=hide),
        prom("WE", with_dash(logs(erroring)), "▲ {{check}} erroring", fmt=fmt, hide=hide),
        prom("DR", with_dash(logs(drains)), "✕ drains: {{state}}", fmt=fmt, hide=hide),
        prom("BK", with_dash(logs(labelled(f"vector(1) unless ({TPA_LINES_5M} > 0)", service="logs", check="tpa logs",
                                           state="no lines", rank="0"))),
             "? Watchtower blind: no tpa lines in 5 min", fmt=fmt, hide=hide),
        prom("BR", with_dash(labelled(RULES_ABSENT, service="loki rules", check="Loki's rules", state="not arriving",
                                      rank="0")), "? Watchtower blind: Loki's rules stopped", fmt=fmt, hide=hide),
        prom("BN", with_dash(labelled(f"{NO_LINES} * 0 + 1", service="loki", check="log lines", state="none arriving",
                                      rank="0")), "? Watchtower blind: no lines into Loki", fmt=fmt, hide=hide),
        prom("NR", with_dash(logs(not_ready)), "✕ auth not ready · {{code}}", fmt=fmt, hide=hide),
    ]


# ---------------------------------------------------------------------------------------------------------------------
# Row A: the headline, what's wrong now, the watchtower itself
# ---------------------------------------------------------------------------------------------------------------------
def hero():
    """Computed on the server, each side on its own: the checks' lines are gated on their count (T1), the logs' lines
    on theirs (T2), so the logs going blind never hides a check that is down, and the other way round. Up to three problems
    on a side show one line each; above three, that side shows one roll-up line, red when any of them is red and amber
    when all are amber. The watchtower's blindness is always its own line. "All running systems normal" only when
    both sides answer and every count is 0."""
    shown = [t for ref, _l, _c, side in PROBLEM_KINDS
             for t in shown_if(f"{ref}x", f"${ref}", "$T1 <= 3" if side == "P" else "$T2 <= 3")]
    # The roll-up's name: TPA first whenever it has a failing check ("TPA + 1 stack"), else the stack with the most.
    failing_stacks = f"count by (stack) ({FAILING})"
    lead = (f'topk(1, {failing_stacks} + on (stack) group_left () (label_replace(vector(1000), "stack", "tpa", "", "")'
            f" or 0 * {failing_stacks}))"
            f' * on () group_left (others) count_values("others", count({failing_stacks}) - 1)')
    scope = (f'label_replace(label_replace(label_replace(label_join(label_replace(label_replace({lead}, "lead", "$1",'
             f' "stack", "(.*)"), "lead", "TPA", "stack", "tpa"), "scope", "~", "lead", "others"), "scope", "$1",'
             f' "scope", "(.*)~0"), "scope", "$1 + 1 stack", "scope", "(.*)~1"), "scope", "$1 + $2 stacks", "scope",'
             f' "(.*)~([0-9]+)")'
             f' or (label_replace(vector(0), "scope", "TPA", "", "") unless on () count({failing_stacks}))')
    since_ms = "floor(${0} / 60000) * 60000 + ((${1} > 59) * 59 + (${1} <= 59) * ${1}) * 1000"
    targets = problems(hide=True) + [
        prom("T1", PROM_PROBLEMS, hide=True), prom("R1", PROM_RED, hide=True), prom("W1", PROM_BLIND, hide=True),
        prom("T2", LOKI_PROBLEMS, hide=True), prom("R2", LOKI_RED, hide=True), prom("W2", LOKI_BLIND, hide=True),
        prom("OFF", "count(min by (stack) (probe:state) == 0) or 0 * count(probe:state)", hide=True),
        prom("SC", scope, hide=True),
        # The earliest start on each side.
        prom("SP", f"min({SINCE_UP} and on (stack, service, probe) {FAILING}) or vector(9000000000000000)", hide=True),
        prom("SL", "min(" + " or ".join(
            [labelled(f"{ok_ms(key)} and ({age(key)} > {red})", service=key)
             for key, _t, _o, _e, _a, red in WORKERS]
            + [labelled(f"{first_error_ms(key)} and ({errors_15m(key)} > 0)", service=f"{key} errors")
               for key, *_ in WORKERS]
            + [labelled("min(min_over_time(tw:auth_not_ready_ms:min[15m]))"
                        " and (sum(sum_over_time(tw:auth_not_ready:sum30s[2m])) > 0)", service="auth"),
               labelled("min(min_over_time(tw:drain_raised_ms:min[1h]))", service="drains raised"),
               labelled("min(min_over_time(tw:drain_tenants_not_ok_ms:min[1h]))", service="drains tenants")])
            + ") or vector(9000000000000000)", hide=True),
        *shown,
        # A side's roll-up: since (to the minute) + its count as seconds, one time format: "since Mon 03:12 · 6".
        *shown_if("RPR", f"($SC * 0 + 1) * ({since_ms.format('SP', 'T1')})", "($T1 > 3) * ($R1 > 0)"),
        *shown_if("RPA", f"($SC * 0 + 1) * ({since_ms.format('SP', 'T1')})", "($T1 > 3) * ($R1 == 0)"),
        *shown_if("RLR", since_ms.format("SL", "T2"), "($T2 > 3) * ($R2 > 0)"),
        *shown_if("RLA", since_ms.format("SL", "T2"), "($T2 > 3) * ($R2 == 0)"),
        *shown_if("OK", "$OFF", "($T1 + $W1 + $T2 + $W2) == 0"),
    ]
    # The watchtower's blindness lines are shown as they come.
    for t in targets:
        if t["refId"] in [ref for ref, _l in BLIND_KINDS]:
            t.pop("hide", None)
    off_words = {0: "every stack running", 1: "1 stack off"}
    off_words.update({n: f"{n} stacks off" for n in range(2, 16)})
    roll_unit = "time:[since ]ddd HH:mm[ · ]s[ problems]"
    overrides = []
    for ref, legend, colour, _side in PROBLEM_KINDS:
        props = [("displayName", legend), ("color", {"mode": "fixed", "fixedColor": colour})]
        if ref == "WS":
            props.append(("mappings", [vmap({1: ("none in an hour", DOWN)})]))
        overrides.append(by_name(f"{ref}x", *props))
    for ref, legend in BLIND_KINDS:
        props = [("displayName", legend), ("color", {"mode": "fixed", "fixedColor": WARN})]
        if ref == "BA":
            props.append(("mappings", [vmap({1: ("now", WARN)})]))
        if ref == "BK":
            props.append(("mappings", [vmap({1: ("for 5+ min", WARN)})]))
        if ref == "BR":
            props.append(("mappings", [vmap({1: ("for 2+ min", WARN)})]))
        if ref == "BN":
            props.append(("mappings", [vmap({1: ("for 1+ min", WARN)})]))
        overrides.append({"matcher": {"id": "byFrameRefID", "options": ref},
                          "properties": [{"id": k, "value": v} for k, v in props]})
    overrides += [
        by_name("RPR", ("displayName", "✕ ${__field.labels.scope} failing"),
                ("color", {"mode": "fixed", "fixedColor": DOWN}), ("unit", roll_unit)),
        by_name("RPA", ("displayName", "▲ ${__field.labels.scope} degraded"),
                ("color", {"mode": "fixed", "fixedColor": WARN}), ("unit", roll_unit)),
        by_name("RLR", ("displayName", "✕ TPA background work failing"),
                ("color", {"mode": "fixed", "fixedColor": DOWN}), ("unit", roll_unit)),
        by_name("RLA", ("displayName", "▲ TPA background work erroring"),
                ("color", {"mode": "fixed", "fixedColor": WARN}), ("unit", roll_unit)),
        by_name("OK", ("displayName", "✓ All running systems normal"),
                ("color", {"mode": "fixed", "fixedColor": UP_FILL}),
                ("mappings", [vmap({n: (t, UP_FILL) for n, t in off_words.items()})]), ("unit", "none")),
    ]
    return panel(
        HERO_ID, "stat", "", 0, 0, 9, TOP, datasource=MIXED, targets=targets,
        description="Computed on the server. A problem is a check down (three failed probes in a row: no answer, a "
                    "503 or another error) or degraded (a 2xx whose body says the database is down), a firing "
                    "alert (amber for a held staff account, red for a frozen one and every other), auth not ready, a "
                    "worker stale or erroring, a drain tick that raised or a tenant not ok. "
                    "Each side (Prometheus: checks and alerts; Loki: logs) is gated on its own count, so one going "
                    "blind never hides the other's problems. Up to three on a side show a line each; above three, "
                    "one roll-up line for that side with the earliest start and the count, red when any is red and "
                    "amber when all are amber, naming TPA first whenever it has a failing check. The watchtower's own "
                    "blindness (a scrape target down, no checks loaded, no tpa log lines in 5 minutes, Loki's rules "
                    "stopped, no lines reaching Loki in a minute) is always its "
                    "own '? Watchtower blind' line. 'All running systems normal' appears only when both sides answer "
                    "and every count is zero; otherwise, with no line to show, this reads '? Can't tell'.",
        fieldConfig={"defaults": {"color": {"mode": "fixed", "fixedColor": WARN}, "noValue": "? Can't tell",
                                  "unit": "time:[since ]ddd HH:mm", "mappings": []}, "overrides": overrides},
        # The service and its state large; "since" smaller beside it.
        # 30 px keeps the longest line ("? Watchtower blind: no tpa lines in 5 min") on one line at 1600 px.
        options=stat_options(text={"titleSize": 30, "valueSize": 20}, text_mode="value_and_name",
                             orientation="horizontal"))


def whats_wrong():
    refs = [t["refId"] for t in problems()]
    ok_rows = [
        prom("OKP", labelled(
            f"(count(probe:state) > 0) * 0 unless on () (count({FAILING}) > 0"
            f" or count({ALERTS_OWN}) > 0 or count({SCRAPES} == 0) > 0)",
            service="every running check", check="every running check", state="passing", rank="9",
            dash="tw-overview"), fmt="table"),
        prom("OKL", labelled(f"(vector(0) unless ({LOKI_PROBLEMS_TOTAL} > 0)) and on () {FRESH}",
                             service="workers and drains",
                             check="workers and drains", state="on time", rank="9",
                             dash="tw-jobs-connectors"), fmt="table"),
    ]
    values = [f"Value #{r}" for r in refs + ["OKP", "OKL"]]
    state_colours = vmap({"down": ("✕ down", RED_TEXT), "stale": ("✕ stale", RED_TEXT),
                          "firing": ("✕ firing", RED_TEXT), "tick raised": ("✕ tick raised", RED_TEXT),
                          "tenants not ok": ("✕ tenants not ok", RED_TEXT), "not ready": ("✕ not ready", RED_TEXT),
                          "degraded": ("▲ degraded", WARN), "erroring": ("▲ erroring", WARN),
                          "warning": ("▲ firing", WARN),
                          "not scraped": ("? not scraped", WARN), "no checks": ("? no checks", WARN),
                          "no lines": ("? no log lines", WARN), "not arriving": ("? not arriving", WARN),
                          "none arriving": ("? none arriving", WARN),
                          "passing": ("✓ passing", UP),
                          "on time": ("✓ on time", UP)})
    return panel(
        2, "table", "What's wrong now", 9, 0, 8, MAP_Y - 1, datasource=MIXED, targets=problems(table=True) + ok_rows,
        description=f"Every problem as a row, red before amber, and the most recent first within each, with when it "
                    "began: when the check last passed, when the worker last reported, the first ERROR line in the "
                    "last 24 h, the first raised tick or not-ready line, or when the alert became active. Detail: the "
                    "HTTP status of a check, or the reason auth gives for not being ready. The green rows are "
                    "positive answers (all running checks pass; every worker and drain on time, none erroring, auth "
                    "ready), so an empty table means '? Can't tell', never 'fine'. The first {ROWS_SHOWN} rows show; "
                    "the line below counts the rest. Click a row to open its dashboard.",
        transformations=[
            {"id": "merge", "options": {}},
            # Each query's value lands in its own column; one row has one of them. Gather them into "Since".
            {"id": "calculateField", "options": {"mode": "reduceRow", "reduce": {"reducer": "max", "include": values},
                                                  "alias": "Since", "replaceFields": False}},
            # Worst first, then the most recent: key = rank * 1e14 - since.
            {"id": "convertFieldType", "options": {"conversions": [{"targetField": "rank",
                                                                    "destinationType": "number"}]}},
            {"id": "calculateField", "options": {"mode": "binary", "binary": {
                "left": {"matcher": {"id": "byName", "options": "rank"}}, "operator": "*",
                "right": {"fixed": "100000000000000"}}, "alias": "rank_ms", "replaceFields": False}},
            {"id": "calculateField", "options": {"mode": "binary", "binary": {
                "left": {"matcher": {"id": "byName", "options": "rank_ms"}}, "operator": "-",
                "right": {"matcher": {"id": "byName", "options": "Since"}}}, "alias": "order",
                "replaceFields": False}},
            {"id": "sortBy", "options": {"sort": [{"field": "order", "desc": False}]}},
            # Only the rows that fit in full: a row is never cut off at the bottom; "+N more" counts the rest.
            {"id": "limit", "options": {"limitField": ROWS_SHOWN}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, "stack": True, "alertname": True, "job": True, "service": True,
                                  "probe": True, "rank": True, "rank_ms": True, "order": True, "reason_code": True,
                                  **{v: True for v in values}},
                "renameByName": {"check": "Check", "state": "State", "code": "Detail"},
                "indexByName": {"check": 0, "state": 1, "code": 2, "Since": 3, "dash": 4}}},
        ],
        fieldConfig={"defaults": {"custom": {"align": "left", "cellOptions": {"type": "auto"}, "inspect": False,
                                             "filterable": False},
                                  "noValue": "? Can't tell"},
                     "overrides": [
                         by_name("Check", ("links", [{"title": "Open its dashboard",
                                                        "url": "/d/${__data.fields.dash}?${__url_time_range}"}])),
                         by_name("State", ("mappings", [state_colours]),
                                 ("custom.cellOptions", {"type": "color-text"}), ("custom.width", 130)),
                         by_name("Detail", ("custom.width", 90), ("noValue", "—")),
                         # Small values are not times: the positive rows and a fallback carry 0 or 1.
                         by_name("Since", ("unit", "time:[since ]ddd HH:mm"), ("custom.width", 125),
                                 ("mappings", [rmap(-1, 100000, "—", INK_2)])),
                         by_name("dash", ("custom.hidden", True)),
                     ]},
        # No header row: at this height it would cost a problem row, and each cell reads on its own.
        options={"showHeader": False, "cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                 "sortBy": []})


def more_rows():
    """Under "What's wrong now" (ROWS_SHOWN rows tall): "+N more" when it holds more rows than it shows. It counts the
    table's own rows (its results, through the dashboard datasource: no query of its own)."""
    more = {n: (f"+{n - ROWS_SHOWN} more below", WARN) for n in range(ROWS_SHOWN + 1, 41)}
    more.update({n: (" ", INK_2) for n in range(0, ROWS_SHOWN + 1)})
    return panel(
        17, "stat", "", 9, MAP_Y - 1, 8, 1, datasource=DASHBOARD_DS, transparent=True,
        targets=[{"refId": "A", "datasource": DASHBOARD_DS, "panelId": 2, "withTransforms": False}],
        transformations=[{"id": "merge", "options": {}}],
        fieldConfig={"defaults": {"mappings": [vmap(more)], "color": {"mode": "fixed", "fixedColor": WARN},
                                  "noValue": " "}, "overrides": []},
        options=stat_options(text={"valueSize": 15}, color_mode="value", calcs=("count",), fields="/^check$/"))


def watchtower():
    """Prometheus and Loki each in its own tile: a stat whose every query fails shows its noValue, so when one is
    down it is named."""
    expected = configured_checks()
    tidy = {**stat_options(text={"titleSize": 13, "valueSize": 18}, color_mode="value", text_mode="value_and_name",
                           orientation="horizontal"), "justifyMode": "auto"}
    prom_tile = panel(
        3, "stat", "Prometheus", 17, 0, 4, TOP, datasource=PROM,
        description="Is Prometheus seeing? Checks loaded: the probes it has against the "
                    f"{expected} prometheus/targets configures (a check dropped from the config shows here). Targets "
                    "down: Prometheus, the probe exporter, Loki or Alloy not scraped. History since: the oldest sample "
                    "it holds (every '24 h' figure covers only that). Checks loaded is amber whenever it differs from "
                    "the configured count, above it as well as below. Alerts: Prometheus' own rules (ProbeDown, "
                    "DatabaseReportedDown, PostgresDown, AuthNotReady, WorkerStale, StaffAccountFrozen, "
                    "StaffAccountHeld). A rule that matches is 'pending' "
                    "first and 'firing' after its hold (2 minutes for a probe, 1 for auth and the workers, none for "
                    "a staff account); the "
                    "headline names a problem as soon as it is seen, before its alert fires. 'Alerts firing' is red "
                    "when any of them is about an outage or a frozen staff account, and amber when all are about a "
                    "degraded check (a database a 2xx reports down) or a held one, matching the headline's colour "
                    "for the same problems. There is no "
                    "Alertmanager locally: alerts are shown here only and sent nowhere, so 0 firing means no rule has "
                    "held, not that someone was told.",
        targets=[
            prom("A", f"count({PS})", "Checks loaded"),
            prom("B", f"count({SCRAPES} == 0) or 0 * count({SCRAPES})", "Targets down"),
            prom("C", "min(prometheus_tsdb_lowest_timestamp_seconds) * 1000", "History since"),
            # The count, plus 0.5 when any firing alert is red-class: one number, coloured by its own worst.
            prom("D", f'(count({live('ALERTS{alertstate="firing"}')}) or vector(0)) + 0.5 * ((count('
                      f'{live(f'ALERTS{{alertstate="firing", alertname!~"{AMBER_ALERTS}"}}')}) or vector(0))'
                      " > bool 0)", "Alerts firing"),
            prom("E", f'count({live('ALERTS{alertstate="pending"}')}) or vector(0)', "Alerts pending"),
        ],
        fieldConfig={"defaults": {"color": {"mode": "thresholds"}, "thresholds": steps((None, INK)),
                                  "noValue": "? Prometheus not answering"},
                     "overrides": [
                         by_name("Checks loaded", ("unit", f"suffix: / {expected}"),
                                 ("thresholds", steps((None, WARN), (expected, INK), (expected + 1, WARN)))),
                         by_name("Targets down", ("thresholds", steps((None, INK), (1, WARN))), ("unit", "none")),
                         by_name("History since", ("unit", "time:MMM D HH:mm")),
                         by_name("Alerts firing", ("unit", "none"), ("decimals", 0), ("mappings", [vmap(
                             {0: ("0", INK), **{n: (str(n), WARN) for n in range(1, 61)},
                              **{n + 0.5: (str(n), RED_TEXT) for n in range(1, 61)}})])),
                         by_name("Alerts pending", ("thresholds", steps((None, INK), (1, WARN))), ("unit", "none")),
                     ]},
        options=tidy)
    loki_tile = panel(
        15, "stat", "Loki · edge", 21, 0, 3, TOP, datasource=MIXED,
        description="Last log line: the age of the newest line Loki holds from any stack (over 60 s amber, over 5 "
                    "minutes red). Last deploy: when the portal bundle's release.json last changed (its release id is "
                    "in the body, which a probe cannot export). TLS: days left on the :4310 certificate. The last two "
                    "are Prometheus' (the release and TLS probes).",
        targets=[
            loki("A", f"min(min_over_time({ALL_LINES} | {AGE_FMT} [5m])) or vector(300)", "Last log line"),
            prom("E", 'max(probe_http_last_modified_timestamp_seconds{job="blackbox", service="trellis"}) * 1000',
                 "Last deploy"),
            prom("F", 'min((probe_ssl_earliest_cert_expiry{job="blackbox", service="web-tls"} - time()) / 86400)',
                 "TLS cert"),
        ],
        transformations=[{"id": "organize", "options": {"renameByName": {"Value #A": "Last log line"}}}],
        fieldConfig={"defaults": {"color": {"mode": "thresholds"}, "thresholds": steps((None, INK)),
                                  "noValue": "? not answering"},
                     "overrides": [
                         by_name("Last log line", ("unit", "s"), ("decimals", 0),
                                 ("thresholds", steps((None, INK), (60, WARN), (300, RED_TEXT))),
                                 ("mappings", [rmap(300, 10 ** 9, "none in 5 min", RED_TEXT)])),
                         by_name("Last deploy", ("unit", "dateTimeFromNow")),
                         by_name("TLS cert", ("unit", "suffix: days"), ("decimals", 0),
                                 ("thresholds", steps((None, RED_TEXT), (14, WARN), (30, INK)))),
                     ]},
        options=tidy)
    return [prom_tile, loki_tile]


# ---------------------------------------------------------------------------------------------------------------------
# Row B: the live system map (Canvas). Positions in percent of the canvas (scale constraints); inside a card, text is
# placed in pixels from the card's left edge so it lines up at any width.
# ---------------------------------------------------------------------------------------------------------------------
def pct(left, top, width, height):
    return ({"horizontal": "scale", "vertical": "scale"},
            {"left": round(left, 2), "right": round(100 - left - width, 2), "top": round(top, 2),
             "bottom": round(100 - top - height, 2), "rotation": 0})


def element(kind, name, constraint, placement, config=None, bg=None, border=None, links=None, connections=None,
            elements=None):
    e = {"type": kind, "name": name, "constraint": constraint, "placement": placement, "config": config or {},
         "background": bg or {"color": {"fixed": CLEAR}},
         "border": border or {"color": {"fixed": CLEAR}, "width": 0}}
    if links:
        e["links"] = links
    if connections:
        e["connections"] = connections
    if elements is not None:
        e["elements"] = elements
    return e


def text_cfg(value=None, field=None, size=14, color=INK, color_field=None, align="left", valign="middle"):
    t = {"mode": "field", "field": field, "fixed": ""} if field else {"mode": "fixed", "fixed": value}
    c = {"fixed": color, **({"field": color_field} if color_field else {})}
    return {"text": t, "color": c, "size": size, "align": align, "valign": valign}


def inner(left_px, top, height, right_px=6, width_px=None):
    """Inside a card: px from the card's left edge, percent of its height."""
    if width_px is not None:
        return ({"horizontal": "left", "vertical": "scale"},
                {"left": left_px, "width": width_px, "top": top, "bottom": round(100 - top - height, 2), "rotation": 0})
    return ({"horizontal": "leftright", "vertical": "scale"},
            {"left": left_px, "right": right_px, "top": top, "bottom": round(100 - top - height, 2), "rotation": 0})


def conn(target, sx, sy, tx, ty, field):
    """An arrow from one card's edge midpoint to another's."""
    return {"source": {"x": sx, "y": sy}, "target": {"x": tx, "y": ty}, "targetName": target, "path": "straight",
            "color": {"fixed": NEUTRAL, "field": field}, "size": {"fixed": 2, "min": 1, "max": 10},
            "direction": {"fixed": "forward"}, "lineStyle": {"style": "solid", "animate": False}}


def card(name, title, left, top, width, height, *, word=None, glyph=None, pill=None, ring=None, fill=None, ink=None,
         sub=None, sub_field=None, code_field=None, lat_field=None, dash=None, connections=None, fixed_word=None,
         fixed_glyph=None, name_size=22):
    """A card is one frame: its fill and its 2 px border both follow the state (a line-coloured border when up, amber
    or red when not). Inside: the name, a status line (glyph and word, on a filled pill only when degraded or down),
    and a detail line."""
    c, p = pct(left, top, width, height)
    kids = [element("text", f"{name} name", *inner(12, 6, 32), config=text_cfg(title, size=name_size, color=INK,
                                                                             color_field=ink))]
    # The pill spans the card less 6 px each side, so a long word never pushes it past the border.
    kids.append(element("rectangle", f"{name} pill", *inner(6, 41, 27, right_px=6),
                        bg={"color": {"fixed": CLEAR, **({"field": pill} if pill else {})}},
                        border={"color": {"fixed": CLEAR}, "width": 0, "radius": 14}))
    kids.append(element("text", f"{name} glyph", *inner(14, 41, 27, width_px=22),
                        config=(text_cfg(field=glyph, size=16, color=INK_2, color_field=glyph) if glyph
                                else text_cfg(fixed_glyph, size=16, color=OFF))))
    kids.append(element("text", f"{name} word", *inner(36, 41, 27),
                        config=(text_cfg(field=word, size=16, color=INK_2, color_field=word) if word
                                else text_cfg(fixed_word, size=16, color=OFF))))
    if code_field:
        kids.append(element("metric-value", f"{name} code", *inner(12, 72, 22, width_px=86),
                            config=text_cfg(field=code_field, size=14, color=INK_2)))
        kids.append(element("metric-value", f"{name} latency", *inner(98, 72, 22),
                            config=text_cfg(field=lat_field, size=14, color=INK_2)))
    elif sub_field:
        kids.append(element("metric-value", f"{name} detail", *inner(12, 72, 22),
                            config=text_cfg(field=sub_field, size=14, color=INK_2)))
    elif sub:
        kids.append(element("text", f"{name} detail", *inner(12, 72, 22), config=text_cfg(sub, size=14, color=INK_2)))
    bg = {"color": {"fixed": CARD, **({"field": fill} if fill else {})}}
    border = {"color": {"fixed": LINE, **({"field": ring} if ring else {})}, "width": 2, "radius": 8}
    return element("frame", name, c, p, bg=bg, border=border,
                   links=[{**link(f"Open {dash[0]}", dash[1]), "oneClick": True}] if dash else None,
                   connections=connections, elements=kids)


def service_card(name, title, svc, left, top, width, height, dash, connections=None):
    return card(name, title, left, top, width, height, word=svc, glyph=f"glyph {svc}", pill=f"pill {svc}",
                ring=f"ring {svc}", fill=f"fill {svc}", ink=f"ink {svc}", code_field=f"code {svc}",
                lat_field=f"lat {svc}", dash=dash, connections=connections)


def db_card(name, svc, left, top, width, height, sub, dash, sub_field=None, prefix="infer"):
    """A database: plain text, no outline; "inferred up" until a database signal of its own exists."""
    return card(name, name, left, top, width, height, word=f"{prefix} {svc}", glyph=f"{prefix}g {svc}",
                pill=f"{prefix}p {svc}", ring=f"{prefix}r {svc}", fill=f"{prefix}f {svc}", ink=f"ink {svc}", sub=sub,
                sub_field=sub_field, dash=dash)


def divider(name, x1, y1, x2, y2):
    """A 1 px line: a connection between two invisible anchors (a Canvas element is at least 10 px, so a thin
    rectangle cannot be a line)."""
    a = element("rectangle", f"{name} a", *pct(x1 - 0.2, y1 - 0.8, 0.4, 1.6),
                connections=[{"source": {"x": 0, "y": 0}, "target": {"x": 0, "y": 0}, "targetName": f"{name} b",
                              "path": "straight", "color": {"fixed": LINE}, "size": {"fixed": 1, "min": 1, "max": 1},
                              "direction": {"fixed": "none"}, "lineStyle": {"style": "solid", "animate": False}}])
    b = element("rectangle", f"{name} b", *pct(x2 - 0.2, y2 - 0.8, 0.4, 1.6))
    return [a, b]


def stack_title(stack, title, left, top, title_w, size=22):
    c, p = pct(left, top, title_w, 6)
    out = [element("text", f"{stack} title", c, p, config=text_cfg(title, size=size, color=INK))]
    c, p = pct(left + title_w, top + 0.4, 9.5, 5.2)
    out.append(element("frame", f"{stack} stack pill", c, p,
                       bg={"color": {"fixed": CLEAR, "field": f"stackp {stack}"}},
                       border={"color": {"fixed": CLEAR}, "width": 0, "radius": 14},
                       elements=[
                           element("text", f"{stack} stack glyph", *inner(10, 0, 100, width_px=22),
                                   config=text_cfg(field=f"stackg {stack}", size=16, color=INK_2,
                                                   color_field=f"stackg {stack}")),
                           element("text", f"{stack} stack word", *inner(32, 0, 100, right_px=4),
                                   config=text_cfg(field=f"stack {stack}", size=16, color=INK_2,
                                                   color_field=f"stack {stack}"))]))
    return out


def system_map():
    E = []
    # ---- TPA (left 64 %) --------------------------------------------------------------------------------------------
    E += stack_title("tpa", "TPA stack · :4310", 1, 2, 13.5)
    W, H, r1, r2 = 10.6, 22, 12, 42
    col = [1 + i * (W + 2.25) for i in range(5)]
    edge_api = ("TPA edge and API", "tw-tpa-edge-api")
    E.append(service_card("web-tls", "web-tls", "web-tls", col[0], r1, W, H, edge_api,
                          [conn("web", 1, 0, -1, 0, "edge trellis")]))
    E.append(service_card("web", "web · trellis", "trellis", col[1], r1, W, H, edge_api,
                          [conn("tpa-api", 1, 0, -1, 0, "edge tpa-api"),
                           conn("auth", 0, -1, -1, 0, "edge auth")]))
    E.append(service_card("tpa-api", "tpa-api", "tpa-api", col[2], r1, W, H, edge_api,
                          [conn("records", 1, 0, -1, 0, "edge records"),
                           conn("auth", 0, -1, 0, 1, "edge auth")]))
    E.append(service_card("records", "records", "records", col[3], r1, W, H, ("records-service", "tw-records"),
                          [conn("tpa-db", 1, 0, -1, 0, "edge records"),
                           conn("auth", 0, -1, 1, 0, "edge auth")]))
    E.append(db_card("tpa-db", "records", col[4], r1, W, H, "via records /ready", ("records-service", "tw-records"),
                     prefix="tdb"))
    E.append(service_card("auth", "auth", "auth", col[2], r2, W, H, ("auth-notary", "tw-auth"),
                          [conn("auth-db", 1, 0, -1, 0, "edge auth")]))
    E.append(db_card("auth-db", "auth", col[4], r2, W, H, "via auth /ready", ("auth-notary", "tw-auth"),
                     prefix="adb"))
    # The sign-in journey runs in the cloud only (synthetics/README.md); not locally, see its card.
    E.append(card("sign-in journey", "sign-in", col[0], r2, W, H, fixed_glyph="○", fixed_word="cloud only",
                  sub="synthetic journey", dash=("Every check", "tw-overview")))

    E += divider("tpa divider", 1, 69.5, 63.5, 69.5)
    c, p = pct(1, 71, 40, 5)
    E.append(element("text", "bg title", c, p,
                     config=text_cfg("Background work  ·  since its last INFO tick or summary line", size=14,
                                     color=INK_2)))
    ww, wg = 12, 0.6
    for i, (key, title, _ok, _err, _a, _r) in enumerate(WORKERS):
        dash = ("auth-notary", "tw-auth") if key.startswith("auth") else ("Jobs and connectors", "tw-jobs-connectors")
        E.append(card(f"w {key}", title, 1 + i * (ww + wg), 77.5, ww, 20.5, word=f"job {key}", glyph=f"jobg {key}",
                      pill=f"jobp {key}", ring=f"jobr {key}", fill=f"jobf {key}", sub_field=f"age {key}", dash=dash,
                      name_size=20))

    # ---- divider between the TPA and the other stacks --------------------------------------------------------------
    E += divider("zone divider", 64.6, 2, 64.6, 98)

    # ---- other stacks (right 34 %), cards as wide as the TPA's -------------------------------------------------------
    blocks = [
        ("network", "network", ("CRM · network", "tw-crm-network")),
        ("forge", "forge", ("health-forge", "tw-forge")),
        ("enroll", "enroll", ("enroll", "tw-enroll")),
        ("feed-ingest", "feed-ingest", ("feed-ingest", "tw-feed-ingest")),
    ]
    zl, bh, cg = 65.6, 24.5, 0.6
    cx = [zl + i * (W + cg) for i in range(3)]
    for i, (stack, title, dash) in enumerate(blocks):
        top = 1 + i * bh
        if i:
            E += divider(f"{stack} divider", zl, top - 0.5, 99.4, top - 0.5)
        E += stack_title(stack, title, zl, top + 0.6, 9.2 if stack == "feed-ingest" else 7.4, size=20)
        ct, ch = top + 7.6, 15.6
        if stack == "network":
            E.append(service_card("network-engine", "engine", "network-engine", cx[0], ct, W, ch, dash,
                                  [conn("network-tpa", 1, 0, -1, 0, "edge network-tpa")]))
            E.append(service_card("network-tpa", "lattice", "network-tpa", cx[1], ct, W, ch, dash,
                                  [conn("network-db", 1, 0, -1, 0, "edge network-tpa")]))
            E.append(db_card("network-db", "network-engine", cx[2], ct, W, ch, None, dash,
                             sub_field="exporter network"))
        elif stack in ("forge", "enroll"):
            svc = f"{stack}-engine"
            E.append(service_card(svc, "engine", svc, cx[0], ct, W, ch, dash,
                                  [conn(f"{stack}-db", 1, 0, -1, 0, f"edge {svc}")]))
            E.append(db_card(f"{stack}-db", svc, cx[1], ct, W, ch, None if stack == "forge" else "via engine health",
                             dash, sub_field="exporter forge" if stack == "forge" else None))
        else:
            E.append(service_card("feed-ingest", "console", "feed-ingest", cx[0], ct, W, ch, dash))
            E.append(card("other checks", "other checks", cx[1], ct, W, ch, word="unmapped", glyph="unmappedg",
                          pill="unmappedp", ring="unmappedr", fill="unmappedf", sub="checks with no card",
                          dash=("Every check", "tw-overview")))

    root = {"type": "frame", "name": "root", "elements": E, "background": {"color": {"fixed": CLEAR}},
            "border": {"color": {"fixed": CLEAR}}, "constraint": {"horizontal": "left", "vertical": "top"},
            "placement": {}, "config": {}}

    known = "|".join(CARD_SERVICES)
    targets = [
        prom("A", "min by (service) (probe:state)", "{{service}}"),
        prom("B", "min by (stack) (probe:state)", "stack {{stack}}"),
        prom("C", f"max by (service) ({CODE} != 200) or max by (service) ({CODE})"
                  f' or (-2 + 0 * max by (service) (probe_success{{job="blackbox", probe="tls"}}))', "code {{service}}"),
        prom("D", f"max by (service) (probe_duration_seconds{{job=\"blackbox\"}} and on (stack, service, probe) ({PS} == 1))"
                  f" or (-1 + 0 * max by (service) ({PS}))", "lat {{service}}"),
        prom("E", 'max by (db) (up{job="postgres"})', "exporter {{db}}"),
        prom("F", f'min(probe:state{{service!~"{known}"}}) or (4 + 0 * count(probe:state))', "unmapped"),
        prom("Y", '(sum(sum_over_time(tw:auth_not_ready:sum30s{reason_code="database"}[2m])) > bool 0) or vector(0)',
             "authdb down"),
        # tpa-db: records' /ready asked only about the database (probe "db"). 3 it says up; 1 it answered 503 saying
        # "database": false (the blackbox-reason job's probe, which passes only then); 5 anything else (no answer,
        # another status, a body without the field): unknown.
        prom("Z", f"3 * ({TPADB_STATE} == bool 3) + ({TPADB_STATE} != bool 3) * (5 - 4 * {TPADB_SAYS_DOWN})",
             "tdb records"),
    ]
    refs = iter("GHIJKLMNOPQRSTUVWX")
    for key, _t, _o, _e, amber, red in WORKERS:
        r1_, r2_ = next(refs), next(refs)
        targets.append(prom(r1_, worker_state(key, amber, red), f"job {key}"))
        # -1 while the page cannot tell (no lines reaching Loki): a dash, not "Field not found".
        targets.append(prom(r2_, f"({age(key)} and on () {FRESH}) or vector(-1)", f"age {key}"))

    # One query per state; the colours and words each card needs are copies of it, made here rather than queried.
    def calc(left, op, right, alias):
        r = {"fixed": str(right)} if isinstance(right, (int, float)) else {"matcher": {"id": "byName", "options": right}}
        return {"id": "calculateField", "options": {
            "mode": "binary", "binary": {"left": {"matcher": {"id": "byName", "options": left}}, "operator": op,
                                         "right": r}, "alias": alias, "replaceFields": False}}

    def copy(src, alias):
        return calc(src, "+", 0, alias)

    transformations = [{"id": "joinByField", "options": {"byField": "Time", "mode": "outer"}}]
    for svc in CARD_SERVICES:
        for role in ("glyph", "pill", "ring", "fill", "ink", "edge", "infer", "inferg", "inferp", "inferr", "inferf"):
            transformations.append(copy(svc, f"{role} {svc}"))
    for role in ("tdbg", "tdbp", "tdbr", "tdbf"):
        transformations.append(copy("tdb records", f"{role} records"))
    # auth-db: auth's state + 10 when auth's /ready refusal names the database.
    transformations += [calc("authdb down", "*", 10, "authdb ten"), calc("auth", "+", "authdb ten", "adb auth")]
    for role in ("adbg", "adbp", "adbr", "adbf"):
        transformations.append(copy("adb auth", f"{role} auth"))
    for stack in ("tpa", "network", "forge", "enroll", "feed-ingest"):
        for role in ("stackg", "stackp"):
            transformations.append(copy(f"stack {stack}", f"{role} {stack}"))
    for role in ("unmappedg", "unmappedp", "unmappedr", "unmappedf"):
        transformations.append(copy("unmapped", role))
    for key, *_ in WORKERS:
        for role in ("jobg", "jobp", "jobr", "jobf"):
            transformations.append(copy(f"job {key}", f"{role} {key}"))

    def fam(pattern, mapping, *extra):
        return by_regex(pattern, ("mappings", [mapping]), *extra)

    overrides = [
        # Value mappings in an override merge with the defaults' mappings, so the defaults carry none.
        fam("^[a-z][a-z0-9-]*$", STATE_WORD),
        fam("^glyph .*", STATE_GLYPH), fam("^pill .*", STATE_PILL), fam("^ring .*", STATE_RING),
        fam("^fill .*", STATE_FILL), fam("^ink .*", STATE_INK), fam("^edge .*", STATE_EDGE),
        fam("^infer .*", INFER_WORD), fam("^inferg .*", INFER_GLYPH), fam("^inferp .*", INFER_PILL),
        fam("^inferr .*", INFER_RING), fam("^inferf .*", INFER_FILL),
        by_name("adb auth", ("mappings", [AUTHDB_WORD])), by_name("adbg auth", ("mappings", [AUTHDB_GLYPH])),
        by_name("adbp auth", ("mappings", [AUTHDB_PILL])), by_name("adbr auth", ("mappings", [AUTHDB_RING])),
        by_name("adbf auth", ("mappings", [AUTHDB_FILL])),
        by_name("tdb records", ("mappings", [TPADB_WORD])), by_name("tdbg records", ("mappings", [TPADB_GLYPH])),
        by_name("tdbp records", ("mappings", [TPADB_PILL])), by_name("tdbr records", ("mappings", [TPADB_RING])),
        by_name("tdbf records", ("mappings", [TPADB_FILL])),
        fam("^stack .*", STACK_WORD), fam("^stackg .*", STATE_GLYPH), fam("^stackp .*", STATE_PILL),
        by_name("unmapped", ("mappings", [UNMAPPED_WORD])), by_name("unmappedg", ("mappings", [UNMAPPED_GLYPH])),
        by_name("unmappedp", ("mappings", [vmap({0: ("", CLEAR), 1: ("", DOWN), 2: ("", WARN), 3: ("", CLEAR),
                                                 4: ("", CLEAR)})])),
        by_name("unmappedr", ("mappings", [vmap({0: ("", LINE), 1: ("", DOWN), 2: ("", WARN), 3: ("", LINE),
                                                 4: ("", LINE)})])),
        by_name("unmappedf", ("mappings", [vmap({0: ("", CARD), 1: ("", TINT_DOWN), 2: ("", TINT_WARN),
                                                 3: ("", CARD), 4: ("", CARD)})])),
        fam("^job .*", JOB_WORD), fam("^jobg .*", JOB_GLYPH), fam("^jobp .*", JOB_PILL), fam("^jobr .*", JOB_RING),
        fam("^jobf .*", JOB_FILL),
        by_regex("^code .*", ("unit", "prefix:HTTP "), ("decimals", 0),
                 ("mappings", [vmap({0: ("no answer", INK_2), -2: ("TLS", INK_2)})])),
        # A latency with no passing check is left blank.
        by_regex("^lat .*", ("unit", "s"), ("decimals", 0), ("mappings", [rmap(-10, -0.5, " ", INK_2)])),
        by_regex("^age .*", ("unit", "suffix: s ago"), ("decimals", 0),
                 ("mappings", [rmap(3600, 10 ** 9, "none in 1 h", INK_2), rmap(-5, -0.5, "—", INK_2, 1)])),
        by_regex("^exporter .*", ("mappings", [vmap({0: ("no exporter", INK_2), 1: ("exporter up", INK_2)})])),
    ]
    return panel(
        4, "canvas", "", 0, MAP_Y, 24, 15, datasource=MIXED, pluginVersion="12.4.11", targets=targets,
        transformations=transformations,
        description="Each card follows its checks (probe:state: three failed probes in a row). Up is quiet: a grey "
                    "word with a teal ✓. Down (✕, red: no answer, a 503 or another error) and degraded (▲, amber: a "
                    "2xx whose body says the database is down) fill the pill, tint the card, colour its border and "
                    "the arrows into it. ○ not running (grey) is a stack other than tpa with no passing check in the "
                    "last hour. Database cards read 'inferred': monitoring has no login to tpa-db or auth-db, so they "
                    "follow the health check that covers them; auth-db turns red when auth's /ready refusal names "
                    "the database, and reads '? unknown' when its service is down for another reason. The sign-in "
                    "journey runs in the cloud only. Background work: on time, ▲ late, ▲ erroring (ERROR lines in 15 "
                    "min), ✕ stale. Click a card to open its dashboard.",
        fieldConfig={"defaults": {"mappings": [], "color": {"mode": "thresholds"}, "thresholds": steps((None, OFF))},
                     "overrides": overrides},
        options={"inlineEditing": False, "showAdvancedTypes": True, "panZoom": False, "infinitePan": False,
                 "tooltip": {"mode": "none", "disableForOneClick": True}, "root": root})


# ---------------------------------------------------------------------------------------------------------------------
# Row C: tpa-api, errors, saturation
# ---------------------------------------------------------------------------------------------------------------------
def kpis(y):
    """A short strip under the headline and the watchtower: tpa-api, restarts, ERROR lines, new error groups."""
    inline = {**stat_options(text={"titleSize": 13, "valueSize": KPI_VALUE}, color_mode="value",
                             text_mode="value_and_name", orientation="vertical"), "justifyMode": "auto"}
    api = panel(
        5, "stat", "tpa-api", 0, y, 5, KPI_H, datasource=LOKI,
        description="tpa-api's own request lines that name a route (its /health and /ready probes left out): req/m, "
                    "requests per minute; 5xx, the share of 5xx in the last 5 minutes (0.0% when there was traffic and "
                    "no 5xx, 'idle' when there was none); p95, the 95th percentile of its duration_ms.",
        targets=[
            # -20 ("?") when tpa-api logged in the last 5 minutes but no line of the last minute reached Loki.
            loki("A", f"sum(count_over_time({API} [1m])) or 0 * sum(count_over_time({TPA_API} [1m]))"
                      f" or -20 + 0 * sum(count_over_time({TPA_API} [5m]))"),
            # -1 ("idle") while tpa-api logs but nothing named a route; nothing at all when it does not log.
            loki("B", f'((sum(count_over_time({API} | status=~"5.." [5m])) or 0 * sum(count_over_time({API} [5m])))'
                      f" / sum(count_over_time({API} [5m]))) or -1 + 0 * sum(count_over_time({TPA_API} [5m]))"),
            loki("C", f'max(quantile_over_time(0.95, {API} | json d="duration_ms" | __error__="" | unwrap d [5m])'
                      f" by (service)) or -1 + 0 * sum(count_over_time({TPA_API} [5m]))"),
        ],
        transformations=[{"id": "organize", "options": {"renameByName": {
            "Value #A": "req/m", "Value #B": "5xx", "Value #C": "p95"}}}],
        fieldConfig={"defaults": {"color": {"mode": "thresholds"}, "thresholds": steps((None, INK)),
                                  "noValue": "? no lines", "mappings": [rmap(-25, -15, "?", INK_2, 0),
                                                                        rmap(-10, -0.5, "idle", INK_2, 1)]},
                     "overrides": [
                         by_name("req/m", ("unit", "none"), ("decimals", 0)),
                         by_name("5xx", ("unit", "percentunit"), ("decimals", 1),
                                 ("thresholds", steps((None, INK), (0.01, WARN), (0.05, RED_TEXT)))),
                         by_name("p95", ("unit", "ms"), ("decimals", 0),
                                 ("thresholds", steps((None, INK), (1000, WARN), (2000, RED_TEXT)))),
                     ]},
        options=inline, links=[link("TPA edge and API", "tw-tpa-edge-api")])
    restarts = panel(
        18, "stat", "Restarts · 24 h", 5, y, 4, KPI_H, datasource=LOKI,
        description="Starts in the last 24 hours, counted from the startup line each service logs: auth and tpa-api "
                    "('Application startup complete'), records (its records.startup permissions line). Covered: these "
                    "three only. connectors, tpa-jobs-drains and auth's workers log no startup line, so their "
                    "restarts are not counted. Amber from 3 (a restart loop). CPU, memory and OOM kills are cloud "
                    "only: locally they would need a new exporter on the Docker socket's network, which only Alloy "
                    "may reach (container inspect shows every container's environment), or cAdvisor with host "
                    "privileges; the hosted dashboard reads them from Cloud Run. '?': Loki is not "
                    "answering. 0 needs a line from that service in 24 h.",
        targets=[loki(ref, startups_24h(sel)) for ref, (_svc, sel) in zip("ABC", STARTUPS)],
        transformations=[{"id": "organize", "options": {"renameByName": {
            f"Value #{ref}": svc for ref, (svc, _sel) in zip("ABC", STARTUPS)}}}],
        fieldConfig={"defaults": {"unit": "none", "decimals": 0, "color": {"mode": "thresholds"},
                                  "noValue": "?", "thresholds": steps((None, INK), (3, WARN))},
                     "overrides": []},
        options=inline)
    errors_tile = panel(
        8, "stat", "ERROR lines", 17, y, 3, KPI_H, datasource=PROM,
        description="ERROR lines from every stack that ships logs in the last 10 minutes (Loki's ruler counts them "
                    "every 30 s). Neutral below 50, amber above. '?' while no lines reach Loki or its ruler is not writing.",
        targets=[prom("A", f"{ERROR_LINES_10M} and on () {FRESH}")],
        fieldConfig={"defaults": {"unit": "none", "decimals": 0, "color": {"mode": "thresholds"},
                                  "noValue": "?", "thresholds": steps((None, INK), (50, WARN))},
                     "overrides": []},
        options=stat_options(text={"titleSize": 13, "valueSize": KPI_VALUE}, color_mode="value"))
    new_groups = panel(
        NEW_GROUPS_ID, "stat", "New error groups", 20, y, 4, KPI_H, datasource=LOKI,
        description="Error groups (service, exception class, operation or route, SQLSTATE, message name, reason "
                    "code) seen in the last 24 h and not in the 6 days before. Loki keeps 7 days, and a service whose "
                    "logs start later reads every group as new until it has 7 days. Amber means look, not an outage. "
                    "This is the one query that reads 7 days (Loki caches the past hours); the Errors row reuses its "
                    "result.",
        # Loki returns one table, a row per group: the tile counts the rows.
        targets=[loki("A", f"{GROUPS_24H} unless {GROUPS_PRIOR}")],
        fieldConfig={"defaults": {"unit": "none", "noValue": "0", "color": {"mode": "thresholds"},
                                  "thresholds": steps((None, INK), (1, WARN))}, "overrides": []},
        options=stat_options(text={"titleSize": 13, "valueSize": KPI_VALUE}, color_mode="value", calcs=("count",),
                             fields="/^Value/"))
    return [api, restarts, errors_tile, new_groups]


# ---------------------------------------------------------------------------------------------------------------------
# Row D: every check, and its history
# ---------------------------------------------------------------------------------------------------------------------
def check_label(expr):
    return f'label_join({expr}, "check", " · ", "service", "probe")'


# A latency is shown only for a probe that passed: a failed one's duration is its timeout.
PASSING_LATENCY = ('max by (stack, service, probe) (probe_duration_seconds{job="blackbox"}'
                   f' and on (stack, service, probe) ({PS} == 1))')
# The sign-in journey's row: it runs in the cloud only (see its card); -5 reads "cloud only".
JOURNEY = 'label_replace(label_replace(vector(-5), "service", "sign-in journey", "", ""), "probe", "staff-sign-in", "", "")'


def checks(y):
    order = " or ".join(
        f'label_replace(label_replace(vector({i}), "service", "{s}", "", ""), "probe", "{p}", "", "")'
        for i, (s, p) in enumerate(CHECK_ORDER))
    # Failing first: down 0, degraded 1, up 2, not running 3 ((state + 3) mod 4), then the request path's order.
    rank = (f"((max by (stack, service, probe) (probe:state) + 3) % 4) * 100"
            f" + on (service, probe) group_left () ({order})"
            f" or ((max by (stack, service, probe) (probe:state) + 3) % 4) * 100 + 50")
    uptime = (f'max by (stack, service, probe) (avg_over_time((probe_success{{job="blackbox", stack="tpa"}}'
              f' or (probe_success{{job="blackbox", stack!="tpa"}} and on (stack) '
              f'(stack:probe_success:max_over_time1h == 1)))[24h:1m]))'
              f" or (-1 + 0 * max by (stack, service, probe) ({PS}))")
    window = (f"max by (stack, service, probe) (0 * {PS})"
              " + scalar(clamp_max(time() - min(prometheus_tsdb_lowest_timestamp_seconds), 86400))")
    table = panel(
        11, "table", "Every check", 0, y, 12, 14, datasource=PROM,
        description="Each blackbox check now, failing ones first: its state (three failed probes in a row fail it), "
                    "the HTTP status (TLS for the handshake; 'no answer' when nothing answered), its latency and its "
                    "trend over the time range (one scale for every row, 0 to 25 ms), and its uptime: the share of "
                    "raw probes that passed over 24 hours or since Prometheus' history begins, whichever is shorter "
                    "('Over'). tpa counts all the time; the other stacks only while they were running.",
        targets=[
            prom("S", check_label("max by (stack, service, probe) (probe:state)"), fmt="table"),
            prom("H", check_label(f"max by (stack, service, probe) ({CODE})"), fmt="table"),
            prom("L", check_label(PASSING_LATENCY), fmt="table"),
            prom("U", check_label(uptime), fmt="table"),
            prom("W", check_label(window), fmt="table"),
            prom("O", check_label(rank), fmt="table"),
            prom("T", check_label(PASSING_LATENCY), "{{check}}", instant=False),
        ],
        transformations=[
            {"id": "timeSeriesTable", "options": {}},
            {"id": "merge", "options": {}},
            {"id": "sortBy", "options": {"sort": [{"field": "Value #O", "desc": False}]}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, "stack": True, "service": True, "probe": True, "Value #O": True},
                "renameByName": {"check": "Check", "Value #S": "Now", "Value #H": "HTTP", "Value #L": "Latency",
                                 "Trend #T": "Trend", "Value #U": "Uptime", "Value #W": "Over"},
                "indexByName": {"check": 0, "Value #S": 1, "Value #H": 2, "Value #L": 3, "Trend #T": 4, "Value #U": 5,
                                "Value #W": 6}}},
        ],
        fieldConfig={"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False,
                                             "filterable": False}, "color": {"mode": "fixed", "fixedColor": INK}},
                     "overrides": [
                         by_name("Check", ("custom.width", 165)),
                         by_name("Now", ("mappings", [vmap({0: ("○ not running", OFF), 1: ("✕ down", RED_TEXT),
                                                           2: ("▲ degraded", WARN), 3: ("✓ up", UP)})]),
                                 ("custom.cellOptions", {"type": "color-text"}), ("custom.width", 115)),
                         by_name("HTTP", ("noValue", "TLS"), ("custom.width", 85),
                                 ("mappings", [vmap({0: ("no answer", INK_2)})])),
                         by_name("Latency", ("unit", "s"), ("decimals", 0), ("custom.width", 70), ("noValue", "—")),
                         by_name("Trend", ("custom.cellOptions", {"type": "sparkline", "lineWidth": 1,
                                                                  "fillOpacity": 0, "hideValue": True}),
                                 ("color", {"mode": "fixed", "fixedColor": NEUTRAL}), ("unit", "s"), ("min", 0),
                                 ("max", 0.025), ("noValue", " ")),
                         by_name("Uptime", ("unit", "percentunit"), ("decimals", 1), ("custom.width", 90),
                                 ("color", {"mode": "thresholds"}),
                                 ("thresholds", steps((None, RED_TEXT), (0.99, WARN), (0.999, INK))),
                                 ("custom.cellOptions", {"type": "color-text"}), ("noValue", "—"),
                                 ("mappings", [rmap(-10, -0.5, "not running", OFF)])),
                         by_name("Over", ("unit", "s"), ("decimals", 1), ("custom.width", 75), ("noValue", "—")),
                     ]},
        options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                 "sortBy": []},
        links=[link("Every check (stack overview)", "tw-overview")])
    history = panel(
        12, "state-timeline", "Every check · history", 12, y, 12, 14, datasource=PROM,
        description="probe:state over the time range, one row per check by name (it began when the recording rule "
                    "was added; earlier time is blank, and so is any gap, such as a check that was removed). Up is dim "
                    "and 'not running' is empty on purpose: colour means a problem. Deploys of the trellis bundle are "
                    "marked.",
        targets=[prom("A", check_label("max by (stack, service, probe) (probe:state)"), "{{check}}", instant=False),
                 # The sign-in journey's place: it runs in the cloud only (its card on the map says why).
                 prom("J", check_label(JOURNEY), "{{check}}", instant=False)],
        # One frame per check, in Prometheus' order (by name), and no inserted nulls: a joined frame or an inserted
        # null makes the state timeline carry the last state across a gap, so a check that was removed, or a gap in
        # the data, would read "down" until now (seen 2026-10-12 with the stub checks). A gap is blank.
        fieldConfig={"defaults": {"mappings": [HISTORY], "color": {"mode": "fixed", "fixedColor": CLEAR},
                                  "custom": {"fillOpacity": 90, "lineWidth": 0,
                                             "hideFrom": {"legend": False, "tooltip": False, "viz": False}}},
                     "overrides": [by_name("sign-in journey · staff-sign-in",
                                           ("displayName", "sign-in journey · cloud only"),
                                           ("mappings", [vmap({-5: ("cloud only", "#24272e")})]))]},
        options={"mergeValues": True, "showValue": "never", "alignValue": "left", "rowHeight": 0.8,
                 "legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"},
                 "tooltip": {"mode": "single", "sort": "none"}},
        links=[link("Every check (stack overview)", "tw-overview")])
    return [table, history]


# ---------------------------------------------------------------------------------------------------------------------
# Collapsed rows: background work, errors, drill down
# ---------------------------------------------------------------------------------------------------------------------
def background(y):
    targets = []
    for i, (key, title, ok, err, _a, red) in enumerate(WORKERS):
        reported = f"((sum(count_over_time({ok} [{red}s])) or vector(0)) > bool 0)"
        expr = f"{reported} * (3 - ({errors_15m(err)} > bool 0)) + (1 - {reported})"
        targets.append(loki("ABCDE"[i], expr, title, instant=False))
    history = panel(
        20, "state-timeline", "Background work · history", 0, y + 1, 16, 6, datasource=LOKI, interval="1m",
        description="For each worker and drain job, at each moment: on time (an INFO tick or summary line within its "
                    "stale limit: connectors' pass 120 s, each drain job's summary 180 s, auth-publisher's counts "
                    "line 150 s, auth-sweeper's tick 900 s), ▲ erroring (ERROR lines in the 15 minutes before), or "
                    "✕ stale (no report within the limit).",
        targets=targets,
        fieldConfig={"defaults": {"mappings": [vmap({1: ("stale", DOWN), 2: ("erroring", WARN), 3: ("on time", UP_DIM)})],
                                  "color": {"mode": "fixed", "fixedColor": CLEAR},
                                  "custom": {"fillOpacity": 90, "lineWidth": 0,
                                             "hideFrom": {"legend": False, "tooltip": False, "viz": False}}},
                     "overrides": []},
        options={"mergeValues": True, "showValue": "never", "alignValue": "left", "rowHeight": 0.75,
                 "legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"},
                 "tooltip": {"mode": "single", "sort": "none"}},
        links=[link("Jobs and connectors", "tw-jobs-connectors"), link("auth-notary", "tw-auth")])
    tile = stat_options(text={"valueSize": 40}, color_mode="value")
    raised = panel(
        21, "stat", "Drain ticks that raised · 1 h", 16, y + 1, 8, 3, datasource=LOKI,
        description="A whole drain tick failed (usually configuration). The next tick retries.",
        targets=[loki("A", f"sum(count_over_time({RAISED} [1h])) or vector(0)")],
        transformations=[{"id": "organize", "options": {"renameByName": {"Value #A": "raised"}}}],
        fieldConfig={"defaults": {"unit": "none", "color": {"mode": "thresholds"},
                                  "thresholds": steps((None, INK), (1, RED_TEXT))}, "overrides": []},
        options=tile, links=[link("Jobs and connectors", "tw-jobs-connectors")])
    tenants = panel(
        22, "stat", "Drain tenants not ok · 1 h", 16, y + 4, 8, 3, datasource=LOKI,
        description="Failed, partial or skipped tenants in the drains' run summaries in the last hour.",
        targets=[loki("A", f"sum(sum_over_time({TENANTS_NOT_OK} | unwrap n [1h])) or vector(0)")],
        transformations=[{"id": "organize", "options": {"renameByName": {"Value #A": "not ok"}}}],
        fieldConfig={"defaults": {"unit": "none", "color": {"mode": "thresholds"},
                                  "thresholds": steps((None, INK), (1, RED_TEXT))}, "overrides": []},
        options=tile, links=[link("Jobs and connectors", "tw-jobs-connectors")])
    return {"id": 19, "type": "row", "title": "Background work", "collapsed": True,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": [history, raised, tenants]}


def errors(y):
    groups = panel(
        31, "table", "New error groups · 24 h", 0, y + 1, 14, 8, datasource=DASHBOARD_DS,
        targets=[{"refId": "A", "datasource": DASHBOARD_DS, "panelId": NEW_GROUPS_ID, "withTransforms": False}],
        description="The groups behind 'New error groups · 24 h' (its result, not a second 7-day query): service, "
                    "the message's and reason's constant names ('other' when a message carries an address or "
                    "punctuation), exception class, operation or route, SQLSTATE, and the ERROR lines in 24 h.",
        transformations=[
            {"id": "organize", "options": {
                "excludeByName": {"Time": True},
                "renameByName": {"service": "Service", "exc_class": "Class", "where": "Operation or route",
                                 "sqlstate": "SQLSTATE", "msg_name": "Message", "reason_code": "Reason",
                                 "Value #A": "Lines"},
                "indexByName": {"service": 0, "msg_name": 1, "reason_code": 2, "exc_class": 3, "where": 4,
                                "sqlstate": 5, "Value #A": 6}}}],
        fieldConfig={"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False,
                                             "filterable": False}, "noValue": "No new error groups in 24 h"},
                     "overrides": [by_name("Lines", ("custom.width", 70))]},
        options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                 "sortBy": [{"displayName": "Lines", "desc": True}]},
        links=[link("Errors", "tw-errors")])
    trend = panel(
        32, "timeseries", "ERROR lines · per 10 min", 14, y + 1, 10, 8, datasource=LOKI, interval="10m",
        description="ERROR lines from every stack per 10 minutes: neutral, amber above 50.",
        targets=[loki("A", f"sum(count_over_time({ERRORS} [$__auto])) or vector(0)", "ERROR lines", instant=False)],
        fieldConfig={"defaults": {"unit": "none", "min": 0, "color": {"mode": "thresholds"},
                                  "thresholds": steps((None, NEUTRAL), (50, WARN)),
                                  "custom": {"drawStyle": "bars", "lineWidth": 0, "fillOpacity": 85,
                                             "barWidthFactor": 0.6, "gradientMode": "scheme", "showPoints": "never",
                                             "axisBorderShow": False, "thresholdsStyle": {"mode": "off"}}},
                     "overrides": []},
        options={"legend": {"displayMode": "list", "placement": "bottom", "showLegend": False, "calcs": []},
                 "tooltip": {"mode": "single", "sort": "none"}},
        links=[link("Errors", "tw-errors")])
    return {"id": 30, "type": "row", "title": "Errors", "collapsed": True,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": [groups, trend]}


def drill(y):
    items = [("TPA edge and API", "tw-tpa-edge-api"), ("auth-notary", "tw-auth"), ("records-service", "tw-records"),
             ("Jobs and connectors", "tw-jobs-connectors"), ("Security", "tw-security"), ("Errors", "tw-errors"),
             ("Every check", "tw-overview"), ("CRM · network", "tw-crm-network"), ("health-forge", "tw-forge"),
             ("enroll", "tw-enroll"), ("feed-ingest", "tw-feed-ingest")]
    chips = "".join(
        f'<a href="/d/{uid}" style="display:inline-block;margin:4px 6px 4px 0;padding:6px 12px;border:1px solid {LINE};'
        f'border-radius:16px;color:{INK};text-decoration:none;font-size:14px">{t} &rarr;</a>' for t, uid in items)
    text = panel(41, "text", "", 0, y + 1, 24, 2,
                 options={"mode": "html", "content": f"<div>{chips}</div>",
                          "code": {"language": "plaintext", "showLineNumbers": False, "showMiniMap": False}})
    return {"id": 40, "type": "row", "title": "Drill down", "collapsed": True,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": [text]}


def dashboard(uid="tw-home", title="Home"):
    panels = [hero(), whats_wrong(), more_rows(), *watchtower(), *kpis(TOP), system_map()]
    panels += checks(MAP_Y + 15)
    panels += [background(MAP_Y + 29), errors(MAP_Y + 30), drill(MAP_Y + 31)]
    return {
        "uid": uid, "title": title,
        "description": "Home: is anything wrong, and where. Generated by scripts/gen_home.py; edit that, not this file.",
        "tags": ["trellis-watchtower", "overview"], "editable": False, "graphTooltip": 1, "refresh": "30s",
        "schemaVersion": 41, "version": 1, "timezone": "browser", "fiscalYearStartMonth": 0, "liveNow": False,
        "weekStart": "", "time": {"from": "now-1h", "to": "now"},
        "timepicker": {"refresh_intervals": ["30s", "1m", "5m", "15m"]},
        "annotations": {"list": [
            {"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True,
             "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"},
            {"datasource": PROM, "enable": True, "hide": False, "iconColor": INK_2, "name": "Deploys (trellis bundle)",
             "expr": 'max(changes(probe_http_last_modified_timestamp_seconds{job="blackbox", service="trellis"}[2m])) > 0',
             "step": "1m", "titleFormat": "trellis bundle deployed", "textFormat": "release.json changed",
             "useValueForTime": False}]},
        "links": [{"title": "Dashboards", "type": "dashboards", "tags": ["trellis-watchtower"], "asDropdown": True,
                   "keepTime": True, "includeVars": False, "targetBlank": False, "icon": "external link", "url": "",
                   "tooltip": ""}],
        "templating": {"list": []},
        "panels": panels,
    }


def render(uid="tw-home", title="Home") -> str:
    return json.dumps(dashboard(uid, title), indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------------------------------------------------
# The rule files. YAML written by hand (standard library only): every query is one double-quoted line (JSON string
# syntax, which YAML reads the same way), so scripts/dashboard_lint.py can read the Loki ones back without a parser.
# ---------------------------------------------------------------------------------------------------------------------
def _q(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def _rule_lines(rule: dict) -> list[str]:
    head, value = next(iter(rule.items()))
    lines = [f"      - {head}: {value}", f"        expr: {_q(rule['expr'])}"]
    if rule.get("for"):
        lines.append(f"        for: {rule['for']}")
    for block in ("labels", "annotations"):
        if rule.get(block):
            lines.append(f"        {block}:")
            lines += [f"          {k}: {_q(v)}" for k, v in rule[block].items()]
    return lines


def render_loki_rules() -> str:
    lines = ["# Generated by scripts/gen_home.py: edit that, not this file.",
             "# Loki's ruler evaluates these every 30 s and writes the results to Prometheus (loki/loki-config.yml,",
             "# ruler.remote_write), where the home page and prometheus/rules/home.yml read them. Linted like the",
             "# dashboards' queries (scripts/dashboard_lint.py): metric queries only, listed labels only.",
             "groups:", "  - name: home", "    interval: 30s", "    rules:"]
    for record, expr, labels in loki_rules():
        lines += _rule_lines({"record": record, "expr": expr, "labels": labels})
    return "\n".join(lines) + "\n"


def prom_alerts() -> list[dict]:
    stale = " or ".join(f'label_replace({age(key)} > {red}, "service", "{key}", "", "")'
                        for key, _t, _o, _e, _a, red in WORKERS)
    return [
        {"alert": "AuthNotReady",
         "expr": "sum by (reason_code) (sum_over_time(tw:auth_not_ready:sum30s[2m])) > 0", "for": "1m",
         "labels": {"severity": "page"},
         "annotations": {"summary": "auth is not ready ({{ $labels.reason_code }})",
                         "description": "auth's /ready refused with this reason in the last 2 minutes, for 1 minute "
                                        "(from its not_ready log lines, counted by Loki's ruler)."}},
        {"alert": "WorkerStale", "expr": f"({stale}) and on () {FRESH}", "for": "1m",
         "labels": {"severity": "page"},
         "annotations": {"summary": "{{ $labels.service }} has not reported for {{ $value | humanizeDuration }}",
                         "description": "No INFO tick or summary line from this worker within its limit (the home "
                                        "page's red), for 1 minute. Quiet while Loki's rules are not arriving: the "
                                        "page says it cannot tell instead."}},
        # records' velocity lines (VELOCITY above). Shown, never sent: no Alertmanager, and nothing on this laptop
        # pages anyone (the cloud pages through Google's own PagerDuty channel). A missing `decision` counts as
        # enforced, so a freeze line never goes quiet for want of one.
        {"alert": "StaffAccountFrozen",
         "expr": f'max(max_over_time(tw:velocity_lines:count10m{{code="velocity_freeze", decision!="report"}}'
                 f"[{FREEZE_SHOWN}])) > 0",
         "labels": {"severity": "page"},
         "annotations": {"summary": "a staff account was frozen",
                         "description": "records froze a staff account in the last 24 hours: it refuses every call "
                                        "that person makes in that tenant. Who and why: the ops portal, Compliance, "
                                        "Access limits. A freeze stays until a TPA admin and a compliance officer "
                                        "clear it; the clear's line does not say whose freeze it ended, so this "
                                        "alert holds for 24 hours rather than go quiet on the wrong one. "
                                        "Counted from records' velocity lines by Loki's ruler; nothing is paged from "
                                        "this laptop."}},
        {"alert": "StaffAccountHeld",
         "expr": f'max by (code, decision) (max_over_time(tw:velocity_lines:count10m{{code="velocity_hold"}}'
                 f"[{HOLD_SHOWN}]) or max_over_time(tw:velocity_lines:count10m{{code=\"velocity_freeze\", "
                 f'decision="report"}}[{HOLD_SHOWN}])) > 0',
         "labels": {"severity": "warning"},
         "annotations": {"summary": '{{ if eq $labels.code "velocity_freeze" }}a staff account would have been frozen'
                                    '{{ else }}a staff account was held{{ end }}'
                                    '{{ if eq $labels.decision "report" }} (report only){{ end }}',
                         "description": "records held a staff account in the last hour (new members show without "
                                        "details; lists, searches, downloads and reveals are refused until the "
                                        "window slides or a supervisor lifts it), or, in report-only mode, would "
                                        "have held or frozen one. Who and why: the ops portal, Compliance, Access "
                                        "limits. Counted from records' velocity lines by Loki's ruler; nothing is "
                                        "paged from this laptop."}},
    ]


def render_prom_rules() -> str:
    lines = ["# Generated by scripts/gen_home.py: edit that, not this file.",
             "# Alerts on what Loki's ruler records (loki/rules/fake/home.yml), beside the probe alerts in local.yml.",
             "# Visual only: no Alertmanager locally. Tested by tests/prometheus/rules_test.yml.",
             "groups:", "  - name: home-logs", "    rules:"]
    for rule in prom_alerts():
        lines += _rule_lines(rule)
    return "\n".join(lines) + "\n"


OUTPUTS = [(OUT, render), (LOKI_RULES, render_loki_rules), (PROM_RULES, render_prom_rules)]


def main(argv: list[str]) -> int:
    if argv[:1] == ["--check"]:
        stale = [path for path, make in OUTPUTS if not path.exists() or path.read_text() != make()]
        for path in stale:
            print(f"{path} is not what scripts/gen_home.py writes; run it", file=sys.stderr)
        return 1 if stale else 0
    if argv[:1] == ["--candidate"] and len(argv) == 3:
        Path(argv[2]).write_text(render(argv[1], f"Home · candidate {argv[1].removeprefix('tw-home-')}"))
        return 0
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    for path, make in OUTPUTS:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(make())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
