#!/usr/bin/env python3
"""Generate the Security page, grafana/dashboards/security.json (uid tw-security). Standard library only.

The page answers "is anyone reading too much, or trying to get in" from counts alone. Its panels are the local column
of bodyfirst tasks/security-watch PLAN §5, keyed to records' log lines in SPEC §7:

  - records' limits (the velocity lines: flags, holds and freezes, enforced or report only, by role and measure; the
    calls a hold or freeze refused; holds lifted and freezes cleared; settings changes; the meter failing) and the two
    alerts gen_home.py writes for them;
  - sign-in (auth's request lines: password sign-in refused, lockouts, step-up refused, admins ending sessions and
    suspending logins);
  - records' gate (refusals by gate and code, rate limits, reveals served, staff member reads over the day);
  - compliance findings, and what is not on this page yet (later slices, and the cloud-only signals).

No panel shows a person, member, tenant or address: Alloy strips them before Loki stores a line and rebuilds records'
velocity lines from an allowlist (alloy/config.alloy, 4b), and scripts/dashboard_lint.py holds every query to listed
labels. Who is held or frozen, and why, is on the ops portal's Access limits screen, behind records' own rules.

The velocity panels read "none yet" until records writes those lines (its slice R1); that is expected. A tile reads
"? no records lines" (or auth's) when that service logged nothing in the range, so a blind page never reads "none".

Usage:
  scripts/gen_security.py           write grafana/dashboards/security.json
  scripts/gen_security.py --check   exit 1 when it is not what this script writes
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from gen_home import (DOWN, FREEZE_SHOWN, HOLD_SHOWN, INK, INK_2, LOKI, PROM, RECORDS, RED_TEXT, REASON, VELOCITY,
                      VELOCITY_ACTS, VELOCITY_FAILED, VELOCITY_REASONS, VELOCITY_SETTINGS, VELOCITY_STATES, WARN,
                      by_name, by_regex, link, live, loki, panel, prom, stat_options, steps, vmap)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "grafana" / "dashboards" / "security.json"

AUTH = '{stack="tpa", service="auth"}'
# A velocity line's reason only when it is one of the contract's words (scripts/dashboard_lint.py
# VETTED_LABEL_FORMATS), else "other".
MEASURE = ('label_format measure=`{{ if eq (regexReplaceAll "^(' + "|".join(VELOCITY_REASONS) + ')$" .rc "") "" }}'
           '{{ .rc }}{{ else }}other{{ end }}`')
REASON_WORDS = {"opened_1h": "members opened · hour", "opened_1d": "members opened · day",
                "listed_1h": "members listed · hour", "listed_1d": "members listed · day",
                "reveals_1h": "reveals · hour", "reveals_1d": "reveals · day",
                "hold_multiplier": "hold at (× limit)", "freeze_multiplier": "freeze at (× limit)",
                "lift_minutes": "a lift's minutes", "lifts_per_day": "lifts a day", "mode": "mode",
                "unbound_multiplier": "unbound sessions (× limit)", "admin": "the TPA admin's half",
                "compliance": "the compliance officer's half", "other": "other"}
ACT_WORDS = {"velocity_lift": ("hold lifted", WARN), "velocity_clear_signed": ("freeze clear: half signed", INK),
             "velocity_cleared": ("freeze cleared", INK)}
STATE_WORDS = {"velocity_freeze": ("freeze", RED_TEXT), "velocity_hold": ("hold", WARN),
               "velocity_flag": ("flag", INK), "other": ("other", INK_2)}
MODE_WORDS = {"enforce": ("enforced", INK), "report": ("report only", INK_2), "other": ("other", INK_2)}
ROLE_WORDS = {"other": "other (not a staff role)"}
# records' calls a person reads members with on a staff door (the look watch's: records/ops/compliance/looks.py).
MEMBER_READS = "eligibility[.](list_members|search_members|get_member|member_id_card)|claims[.]list_claims"
STAFF_DOORS = "door_(internal|finance|agent)"
REVEALS = "eligibility[.]reveal|network[.]reveal_field"
SERVED = f'{RECORDS} |= `"message":"operation served"`'
REFUSED = f'{RECORDS} |= `"message":"refused"`'
ANOMALY = f'{RECORDS} |= `"message":"a compliance anomaly was recorded"`'
# The alerts gen_home.py writes for records' limits, each only while its rule still writes it.
FROZEN = live('ALERTS{alertstate="firing", alertname="StaffAccountFrozen"}')
HELD = live('ALERTS{alertstate="firing", alertname="StaffAccountHeld"}')

NONE_YET = "none yet"
TILE = {**stat_options(text={"titleSize": 13, "valueSize": 34}, color_mode="value"), "justifyMode": "center"}


def _count(sel: str, guard: str, window: str = "$__range") -> str:
    """Lines in the range, 0 when the service logged something else, nothing when it logged nothing (a '?')."""
    return f"sum(count_over_time({sel} [{window}])) or 0 * sum(count_over_time({guard} [{window}]))"


def tile(pid, title, x, y, w, expr, *, colour, description, zero=NONE_YET, guard=RECORDS, blind="? no records lines",
         h=4):
    """A count in the time range: `zero` when there were none, `blind` when the service wrote no line at all."""
    return panel(
        pid, "stat", title, x, y, w, h, datasource=LOKI, description=description,
        targets=[loki("A", _count(expr, guard))],
        fieldConfig={"defaults": {"unit": "none", "decimals": 0, "noValue": blind, "color": {"mode": "thresholds"},
                                  "thresholds": steps((None, INK_2), (1, colour)),
                                  "mappings": [vmap({0: (zero, INK_2)})]}, "overrides": []},
        options=TILE)


def bars(pid, title, x, y, w, h, targets, *, description, no_value, overrides=(), interval=None, links=None):
    custom = {"drawStyle": "bars", "lineWidth": 0, "fillOpacity": 85, "barWidthFactor": 0.7, "showPoints": "never",
              "stacking": {"mode": "normal", "group": "A"}, "gradientMode": "none", "axisBorderShow": False,
              "thresholdsStyle": {"mode": "off"}}
    extra = {"interval": interval} if interval else {}
    if links:
        extra["links"] = links
    return panel(
        pid, "timeseries", title, x, y, w, h, datasource=LOKI, description=description, targets=targets,
        fieldConfig={"defaults": {"unit": "none", "decimals": 0, "min": 0, "noValue": no_value,
                                  "color": {"mode": "palette-classic"}, "custom": custom},
                     "overrides": list(overrides)},
        options={"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True, "calcs": ["sum"]},
                 "tooltip": {"mode": "multi", "sort": "desc"}},
        **extra)


def table(pid, title, x, y, w, h, expr, *, description, no_value, rename, order, overrides=(), sort="Lines"):
    return panel(
        pid, "table", title, x, y, w, h, datasource=LOKI, description=description,
        targets=[{**loki("A", expr), "format": "table"}],
        transformations=[{"id": "organize", "options": {
            "excludeByName": {"Time": True}, "renameByName": {**rename, "Value #A": sort},
            "indexByName": {**{k: i for i, k in enumerate(order)}, "Value #A": len(order)}}}],
        fieldConfig={"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False,
                                             "filterable": False}, "noValue": no_value},
                     "overrides": [by_name(sort, ("custom.width", 80)), *overrides]},
        options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                 "sortBy": [{"displayName": sort, "desc": True}]})


def words(name, mapping):
    """A column whose closed words read as plain ones, coloured where the colour means something."""
    m = {k: (v if isinstance(v, tuple) else (v, INK)) for k, v in mapping.items()}
    return by_name(name, ("mappings", [vmap(m)]), ("custom.cellOptions", {"type": "color-text"}),
                   ("color", {"mode": "fixed", "fixedColor": INK}))


def row(pid, title, y):
    return {"id": pid, "type": "row", "title": title, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
            "panels": []}


# ---------------------------------------------------------------------------------------------------------------------
# Records' limits (PLAN §5 panels 1, 2, 3, 5 and the settings changes)
# ---------------------------------------------------------------------------------------------------------------------
def limits(y):
    enforced = f'{VELOCITY_STATES} | decision!="report"'
    out = [row(100, "Records limits · how many members one person reads", y)]
    out += [
        tile(101, "Freezes", 0, y + 1, 4, f'{enforced} | code="velocity_freeze"', colour=RED_TEXT,
             description="records froze a staff account: every call that person makes in that tenant is refused "
                         "until a TPA admin and a compliance officer both clear it. This counts freezes made in the "
                         "range, not freezes still in force; who is frozen now is on the ops portal (Compliance, "
                         "Access limits). Ending the person's sessions at auth comes with records' slice S2 and is "
                         "not logged yet. 'none yet' until records writes its velocity lines (slice R1)."),
        tile(102, "Holds", 4, y + 1, 4, f'{enforced} | code="velocity_hold"', colour=WARN,
             description="records held a staff account past 1.5 times a budget: new members show without details, "
                         "and lists, searches, downloads and reveals are refused until the window slides or a "
                         "supervisor lifts it. 'none yet' until records writes its velocity lines."),
        tile(103, "Flags", 8, y + 1, 4, f'{enforced} | code="velocity_flag"', colour=INK,
             description="A staff account reached a budget (1.0 times): nothing is refused, compliance is told once. "
                         "'none yet' until records writes its velocity lines."),
        tile(104, "Report only", 12, y + 1, 4, f'{VELOCITY_STATES} | decision="report"', colour=WARN,
             description="Flags, holds and freezes records would have made in report-only mode (it refuses nothing). "
                         "Report-only is for production's first weeks; beta and this laptop enforce."),
        tile(105, "Meter failed", 16, y + 1, 4, VELOCITY_FAILED, colour=RED_TEXT, zero="none",
             description="records could not count a person's reads (velocity meter failed) or could not write a "
                         "freeze (velocity freeze unwritten). Either way the call was refused: the meter fails "
                         "closed, so staff cannot work while it fails. Urgent in the cloud. Its exception class is on "
                         "the Errors page."),
        panel(106, "stat", "Alerts", 20, y + 1, 4, 4, datasource=PROM,
              description="The two local alerts on records' limits (prometheus/rules/home.yml): StaffAccountFrozen "
                          f"(red, for {FREEZE_SHOWN} after a freeze) and StaffAccountHeld (amber, for {HOLD_SHOWN} "
                          "after a hold or a report-only freeze). They show here, on Home and in Grafana's alert "
                          "list; nothing on this laptop pages anyone (the cloud pages through PagerDuty).",
              # 2 for a freeze firing, plus 1 for a hold: one number, its words below.
              targets=[prom("A", f"((count({FROZEN}) or vector(0)) > bool 0) * 2"
                                 f" + ((count({HELD}) or vector(0)) > bool 0)")],
              fieldConfig={"defaults": {"unit": "none", "noValue": "? Prometheus not answering",
                                        "color": {"mode": "thresholds"}, "thresholds": steps((None, INK_2)),
                                        "mappings": [vmap({0: ("✓ quiet", INK_2), 1: ("▲ held", WARN),
                                                           2: ("✕ frozen", RED_TEXT),
                                                           3: ("✕ frozen · ▲ held", RED_TEXT)})]},
                           "overrides": []},
              options=TILE, links=[{"title": "Grafana's alert list", "url": "/alerting/list?search=StaffAccount",
                                    "targetBlank": False}]),
    ]
    state_names = {f"{c} · {d}": (f"{w}{' · report only' if d == 'report' else ''}", colour)
                   for c, (w, colour) in STATE_WORDS.items() if c != "other" for d in ("enforce", "report")}
    out.append(bars(
        107, "Flags, holds and freezes", 0, y + 5, 12, 8,
        [loki("A", f"sum by (code, decision) (count_over_time({VELOCITY_STATES} [$__auto]))", "{{code}} · {{decision}}",
              instant=False)],
        description="records' velocity lines over time: each is one state change (a flag, a hold or a freeze) of one "
                    "staff account, enforced or report only. 'none yet' until records writes them.",
        no_value=NONE_YET,
        overrides=[by_name(name, ("displayName", word), ("color", {"mode": "fixed", "fixedColor": colour}))
                   for name, (word, colour) in state_names.items()]))
    out.append(table(
        108, "By role and measure", 12, y + 5, 12, 8,
        f'sum by (role, code, measure, decision) (count_over_time({VELOCITY} | json role, rc="reason"'
        f' | code=~"velocity_(flag|hold|freeze)" | {MEASURE} [$__range]))',
        description="Which staff role crossed which measure (members opened or listed, reveals, in the hour or the "
                    "day), and what records did. A role reads 'other' when the line named something that is not a "
                    "staff role (the scrub keeps role names only). No person: who it was is on the ops portal "
                    "(Compliance, Access limits).",
        no_value=NONE_YET, rename={"role": "Role", "code": "State", "measure": "Measure", "decision": "Mode"},
        order=["role", "code", "measure", "decision"],
        overrides=[words("State", STATE_WORDS), words("Measure", REASON_WORDS), words("Mode", MODE_WORDS),
                   words("Role", ROLE_WORDS)]))
    out.append(table(
        109, "Calls refused while held or frozen", 0, y + 13, 8, 7,
        f'sum by (operation, reason_code) (count_over_time({REFUSED} | json rc="reason"'
        f' | rc=~"velocity_(hold|freeze)" | {REASON} [$__range]))',
        description="records' refused lines whose reason is velocity_hold or velocity_freeze (403 denied), by "
                    "operation. 'none yet' until records gives its velocity refusals that reason.",
        no_value=NONE_YET, rename={"operation": "Operation", "reason_code": "Because"},
        order=["operation", "reason_code"], sort="Refused",
        overrides=[words("Because", {"velocity_hold": ("held", WARN), "velocity_freeze": ("frozen", RED_TEXT)})]))
    out.append(table(
        111, "Holds lifted, freezes cleared", 8, y + 13, 8, 7,
        f"sum by (code, measure) (count_over_time({VELOCITY_ACTS} | json rc=\"reason\" | {MEASURE} [$__range]))",
        description="The people's acts on records' limits: a supervisor lifting a hold for an hour, each half of a "
                    "freeze's clear (a TPA admin's and a compliance officer's), and the clear itself. Who acted, and "
                    "for whom, is in records' audit, not here. 'none yet' until records writes these lines.",
        no_value=NONE_YET, rename={"code": "Act", "measure": "Half"}, order=["code", "measure"], sort="Acts",
        overrides=[words("Act", ACT_WORDS), words("Half", REASON_WORDS)]))
    out.append(table(
        110, "Limit changes", 16, y + 13, 8, 7,
        f"sum by (role, measure) (count_over_time({VELOCITY_SETTINGS} | json rc=\"reason\" | {MEASURE} [$__range]))",
        description="A TPA admin changed records' limits (velocity_settings_changed, one line per field): the role "
                    "whose figure moved (blank for a tenant setting) and the field. Never the value; who changed it "
                    "is in records' audit. The cloud pages on these at normal urgency. 'none yet' until records "
                    "writes these lines.",
        no_value=NONE_YET, rename={"role": "Role", "measure": "Setting"}, order=["role", "measure"], sort="Changes",
        overrides=[words("Setting", REASON_WORDS), words("Role", ROLE_WORDS)]))
    return out


# ---------------------------------------------------------------------------------------------------------------------
# Sign-in (PLAN §5 panels 6, 7, 8)
# ---------------------------------------------------------------------------------------------------------------------
LOGIN_REFUSED = f'{AUTH} | route="POST /auth/login" | status="401"'
LOCKED = f'{AUTH} | status="423"'
STEP_UP_REFUSED = f'{AUTH} | route="POST /auth/step-up" | status=~"401|403"'
ADMIN_ENDS = (f'{AUTH} | route="POST /auth/admin/principals/{{sub}}/revoke-all"'
              ' or route="POST /auth/admin/principals/{sub}/suspend" | status=~"2.."')


def sign_in(y):
    out = [row(200, "Sign-in · auth", y)]
    auth_tile = {"guard": AUTH, "blind": "? no auth lines", "zero": "0"}
    out += [
        tile(201, "Sign-in refused", 0, y + 1, 6, LOGIN_REFUSED, colour=WARN, **auth_tile,
             description="Password sign-ins auth refused (POST /auth/login answering 401) in the range: a wrong "
                         "password, an unknown account or a second factor not passed."),
        tile(202, "Lockouts", 6, y + 1, 6, LOCKED, colour=RED_TEXT, **auth_tile,
             description="Every answer of 423 locked from auth (the sign-in family answers 423, never 429)."),
        tile(203, "Step-up refused", 12, y + 1, 6, STEP_UP_REFUSED, colour=WARN, **auth_tile,
             description="A signed-in person asked to confirm it was them again (step-up) and auth refused (401 or "
                         "403)."),
        tile(204, "Sessions ended by admins", 18, y + 1, 6, ADMIN_ENDS, colour=WARN, **auth_tile,
             description="A TPA admin ended all of a person's sessions (revoke-all) or suspended their login, "
                         "answered 2xx. A freeze will end sessions too once records' slice S2 lands; those are not "
                         "counted here."),
    ]
    out.append(bars(
        205, "Sign-in failures and lockouts", 0, y + 5, 8, 8,
        [loki("A", f"sum(count_over_time({LOGIN_REFUSED} [$__auto]))", "sign-in refused (401)", instant=False),
         loki("B", f"sum(count_over_time({LOCKED} [$__auto]))", "locked (423)", instant=False)],
        description="auth's request lines: POST /auth/login answering 401, and any 423.",
        no_value="none in range",
        overrides=[by_name("sign-in refused (401)", ("color", {"mode": "fixed", "fixedColor": WARN})),
                   by_name("locked (423)", ("color", {"mode": "fixed", "fixedColor": DOWN}))],
        links=[link("auth-notary", "tw-auth")]))
    out.append(bars(
        206, "Step-up failures", 8, y + 5, 8, 8,
        [loki("A", f"sum by (status) (count_over_time({STEP_UP_REFUSED} [$__auto]))", "step-up refused ({{status}})",
              instant=False)],
        description="auth's request lines: POST /auth/step-up answering 401 or 403.", no_value="none in range",
        links=[link("auth-notary", "tw-auth")]))
    out.append(bars(
        207, "Sessions revoked and logins suspended", 16, y + 5, 8, 8,
        [loki("A", f"sum by (route) (count_over_time({ADMIN_ENDS} [$__auto]))", "{{route}}", instant=False)],
        description="auth's request lines: an admin's revoke-all and suspend, answered 2xx. The route is a template; "
                    "who was revoked is in auth's audit, not here.",
        no_value="none in range",
        overrides=[by_name("POST /auth/admin/principals/{sub}/revoke-all", ("displayName", "sessions revoked")),
                   by_name("POST /auth/admin/principals/{sub}/suspend", ("displayName", "login suspended"))],
        links=[link("auth-notary", "tw-auth")]))
    return out


# ---------------------------------------------------------------------------------------------------------------------
# Records' gate (PLAN §5 panels 9, 10, 4, 11)
# ---------------------------------------------------------------------------------------------------------------------
def gate(y):
    out = [row(300, "Records gate · refusals, rate limits, reveals, member reads", y)]
    out.append(table(
        301, "Refusals by gate and code", 0, y + 1, 8, 8,
        f'topk(15, sum by (gate, code) (count_over_time({REFUSED} | json gate, code | __error__="" [$__range])))',
        description="records' refused lines by gate and code (CONTRACT §7). For security read session_revoked, "
                    "feed_cold, token_invalid and rate_limited first; a hold or freeze refuses as denied at gate 6.",
        no_value="none in range", rename={"gate": "Gate", "code": "Code"}, order=["gate", "code"], sort="Refused"))
    out.append(bars(
        302, "Refusals by code", 8, y + 1, 16, 8,
        [loki("A", f'sum by (code) (count_over_time({REFUSED} | json code | __error__="" [$__auto]))', "{{code}}",
              instant=False)],
        description="The same refused lines over time, by code.", no_value="none in range",
        overrides=[by_regex("^(session_revoked|token_invalid)$", ("color", {"mode": "fixed", "fixedColor": DOWN})),
                   by_regex("^(feed_cold|rate_limited)$", ("color", {"mode": "fixed", "fixedColor": WARN}))],
        links=[link("records-service", "tw-records")]))
    out.append(bars(
        303, "Rate limited by operation", 0, y + 9, 8, 8,
        [loki("A", f'sum by (operation) (count_over_time({RECORDS} |= `"message":"rate limited"` [$__auto]))',
              "{{operation}}", instant=False)],
        description="records' rate limited lines (a caller hit its rate class), by operation. The counters are per "
                    "instance in records today (RS-10).",
        no_value="none in range", links=[link("records-service", "tw-records")]))
    out.append(bars(
        304, "Reveals served by operation", 8, y + 9, 8, 8,
        [loki("A", f'sum by (operation) (count_over_time({SERVED} | operation=~"{REVEALS}" [$__auto]))',
              "{{operation}}", instant=False)],
        description="records' operation served lines for its two reveal operations (a secret value shown in full). "
                    "Per person is on the ops portal.",
        no_value="none in range"))
    out.append(bars(
        305, "Staff member reads", 16, y + 9, 8, 8,
        [loki("A", f'sum by (operation) (count_over_time({SERVED} | operation=~"{MEMBER_READS}" | json door'
                   f' | door=~"{STAFF_DOORS}" [$__auto]))', "{{operation}}", instant=False)],
        description="Member reads served to staff, a bar per 15 minutes (longer over a range of days), so "
                    "reading at night shows as night bars: records' operation served lines for the reads its look "
                    "watch counts (list, search and open a member, the ID card, a member's claims) on a staff door. "
                    "Not hourly: Grafana would draw the hour now under way after the end of the chart. A true "
                    "after-hours flag comes with records' slice S6.",
        no_value="none in range", interval="15m"))
    return out


# ---------------------------------------------------------------------------------------------------------------------
# Compliance findings, and what is not here (PLAN §5 panels 15, 16; 12, 13, 14, 17 are the hosted page's)
# ---------------------------------------------------------------------------------------------------------------------
NOT_HERE = (
    "<div style=\"font-size:14px;line-height:1.5\">"
    "<b>Not on this page yet</b><ul style=\"margin:6px 0 0 18px;padding:0\">"
    "<li>Sessions ended for a freeze: records asks auth to end them in its slice S2. Until then a freeze refuses "
    "every call, and the ops portal's suspend ends the sessions.</li>"
    "<li>The anomaly sweep's health: the nightly sweep runs nowhere yet (RS-343); records' slice S3 gives it a line "
    "of its own.</li>"
    "<li>Cloud only, on the hosted Security page: IAP assertions refused, Cloud Armor denials, perimeter violations, "
    "and changes to alerts, counters, secrets and keys.</li></ul></div>")


def findings(y):
    out = [row(400, "Compliance findings", y)]
    out.append(tile(
        401, "Findings", 0, y + 1, 4, ANOMALY, colour=WARN, zero="none", h=6,
        description="records' 'a compliance anomaly was recorded' lines in the range (each is a finding written for "
                    "compliance to review). The findings are read on records' compliance screens."))
    out.append(table(
        402, "Anomaly findings by rule", 4, y + 1, 8, 6,
        f'sum by (code) (count_over_time({ANOMALY} | json code | code!="" [$__range]))',
        description="The same lines by rule. records does not name the rule on the line yet; its slice S3 adds it as "
                    "a closed code.",
        no_value="by rule: none yet", rename={"code": "Rule"}, order=["code"], sort="Findings"))
    out.append(panel(403, "text", "", 12, y + 1, 12, 6, transparent=True,
                     options={"mode": "html", "content": NOT_HERE,
                              "code": {"language": "plaintext", "showLineNumbers": False, "showMiniMap": False}}))
    return out


INTRO = ("<div style=\"font-size:14px;line-height:1.5;color:" + INK_2 + "\">Counts only: no person, member, tenant "
         "or address is on this page. Who is held or frozen, and why: the ops portal, Compliance, Access limits. "
         "Alerts show here and on Home; nothing on this laptop pages anyone.</div>")


def dashboard() -> dict:
    panels = [panel(1, "text", "", 0, 0, 24, 2, transparent=True,
                    options={"mode": "html", "content": INTRO,
                             "code": {"language": "plaintext", "showLineNumbers": False, "showMiniMap": False}})]
    panels += limits(2) + sign_in(22) + gate(35) + findings(52)
    return {
        "uid": "tw-security", "title": "Security",
        "description": "Security: records' limits on staff reading, sign-in, records' refusals and compliance findings, "
                       "as counts. Generated by scripts/gen_security.py; edit that, not this file.",
        "tags": ["trellis-watchtower", "tpa", "security"], "editable": False, "graphTooltip": 1, "refresh": "30s",
        "schemaVersion": 41, "version": 1, "timezone": "browser", "fiscalYearStartMonth": 0, "liveNow": False,
        "weekStart": "", "time": {"from": "now-24h", "to": "now"},
        "timepicker": {"refresh_intervals": ["30s", "1m", "5m", "15m"]},
        "annotations": {"list": [
            {"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True,
             "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"}]},
        "links": [{"title": "Home", "type": "link", "url": "/d/tw-home", "icon": "dashboard", "keepTime": True,
                   "includeVars": False, "targetBlank": False, "tags": [], "asDropdown": False, "tooltip": ""},
                  {"title": "Dashboards", "type": "dashboards", "tags": ["trellis-watchtower"], "asDropdown": True,
                   "keepTime": True, "includeVars": False, "targetBlank": False, "icon": "external link", "url": "",
                   "tooltip": ""}],
        "templating": {"list": []},
        "panels": panels,
    }


def render() -> str:
    return json.dumps(dashboard(), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    if argv[:1] == ["--check"]:
        if not OUT.exists() or OUT.read_text() != render():
            print(f"{OUT} is not what scripts/gen_security.py writes; run it", file=sys.stderr)
            return 1
        return 0
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    OUT.write_text(render())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
