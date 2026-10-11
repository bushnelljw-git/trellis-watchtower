#!/usr/bin/env python3
"""trellis-watchtower: make the TPA's PagerDuty account match docs/PAGERDUTY.md. Standard library only.

What it makes (each found by its exact name, created when absent and corrected when it differs):
  - team "TPA Platform", with both people as managers (PagerDuty's only team role for an owner or admin);
  - schedule "TPA primary on-call": one weekly layer, hand-off Monday 09:00 America/Chicago;
  - escalation policy "TPA Platform": the schedule, then the second person after 15 minutes; repeats twice;
  - one service per Google Cloud project ("TPA beta · Portal & API", "· Member records", "· Call centre"), each with
    urgency from severity, a 30-minute acknowledgement timeout, no auto-resolve, the Google Cloud Monitoring
    integration, an alert grouping setting (intelligent, or time-based where the account refuses it) and a service
    event orchestration that turns Monitoring's severity, in any letter case, into the alert's severity and the
    incident's priority;
  - business service "Trellis TPA (beta)", supported by the three services;
  - notification rules for a contact method that has none yet (never adding or changing a contact method).

It also reads (never makes) each service's Slack connection and prints "by hand" until a person has connected the
service to #tpa-beta-alerts with every urgency, every priority and the five incident events (docs/PAGERDUTY.md).

What it will not do: delete anything; touch "Default Service" or the "Default" escalation policy; put back a
notification rule a person removed (unless --add-rules); change a schedule that has more than one active layer; or
create a service when one carrying our integration and description already exists under another name. Those print
as "kept" or "refused". When a parent object (team, schedule, policy, service, business service) is refused by
PagerDuty, the run stops before anything that depends on it.

Usage:
  scripts/pagerduty/pd_setup.py                    dry run: print the plan, change nothing
  scripts/pagerduty/pd_setup.py --apply            make the changes
  ... --add-rules                                  also add a designed notification rule that is missing on a contact
                                                   method which has other rules (normally left as the person set it)
  ... --retry-intelligent-grouping                 try intelligent alert grouping again where a service has
                                                   time-based grouping (for when the account gains it)

The API key: PAGERDUTY_TOKEN, or else the macOS login keychain (service "tpa-pagerduty-api"). It is never printed.
Re-running changes nothing when PagerDuty already matches: a second run prints "0 to create, 0 to update".
Exit: 0 clean; 1 something was refused or does not match and was left alone; 2 stopped.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pdlib as d  # noqa: E402
from pdlib import ApiError, PagerDuty, Refused, out  # noqa: E402

INTELLIGENT = {"type": "intelligent", "config": {"time_window": 300}}
TIME_BASED = {"type": "time", "config": {"timeout": d.TIME_GROUPING_MINUTES}}


class Stop(Exception):
    """A parent object was refused: nothing that depends on it is attempted."""


class Plan:
    """Prints each object's state and, with --apply, runs the change."""

    WORDS = {"create": ("create", "created"), "update": ("update", "updated"), "ok": ("ok", "ok"),
             "kept": ("kept", "kept"), "refused": ("refused", "refused"), "person": ("by hand", "by hand")}

    def __init__(self, apply: bool):
        self.apply = apply
        self.counts = {k: 0 for k in self.WORDS}

    def _say(self, verb: str, what: str, detail: str = "") -> None:
        self.counts[verb] += 1
        word = self.WORDS[verb][1 if self.apply else 0]
        out(f"{word:<9} {what}" + (f"  [{detail}]" if detail else ""))

    def ok(self, what: str, detail: str = "") -> None:
        self._say("ok", what, detail)

    def kept(self, what: str, detail: str) -> None:
        self._say("kept", what, detail)

    def refuse(self, what: str, detail: str) -> None:
        """The account differs from the design in a way the script must not change by itself."""
        self._say("refused", what, detail)

    def person(self, what: str, detail: str) -> None:
        """A step only a person can take; reported, never counted as a change."""
        self._say("person", what, detail)

    def change(self, verb: str, what: str, detail: str = "", action=None, placeholder=None, parent=False):
        """Report a create or update; with --apply, run it. A refused parent stops the run."""
        if self.apply and action is not None:
            try:
                result = action()
            except ApiError as e:
                self._say("refused", what, f"PagerDuty said {e}")
                if parent:
                    raise Stop(what) from None
                return placeholder
            self._say(verb, what, detail)
            return result
        self._say(verb, what, detail)
        return placeholder


def ref(kind: str, oid: str) -> dict:
    return {"id": oid, "type": f"{kind}_reference"}


def same_instant(a: str | None, b: str) -> bool:
    try:
        return datetime.fromisoformat(a.replace("Z", "+00:00")) == datetime.fromisoformat(b)
    except (AttributeError, ValueError):
        return False


def changed(pairs: list[tuple[str, object, object]]) -> list[str]:
    return [label for label, have, want in pairs if have != want]


# ---- people ----------------------------------------------------------------------------------------------------------


def read_users(pd: PagerDuty) -> dict[str, dict]:
    users = pd.list("/users", "users")
    by_name: dict[str, list[dict]] = {}
    for u in users:
        by_name.setdefault(u.get("name"), []).append(u)
    wanted = set(d.TEAM_MEMBERS) | set(d.ROTATION) | {d.SECOND_LEVEL}
    found = {}
    for name in sorted(wanted):
        matches = by_name.get(name, [])
        if len(matches) != 1:
            raise Refused(f'{len(matches)} PagerDuty users named "{name}" (want exactly one): '
                          "fix pdlib.py or the account")
        found[name] = matches[0]
    return found


# ---- team, schedule, escalation policy -------------------------------------------------------------------------------


def ensure_team(pd: PagerDuty, plan: Plan, users: dict[str, dict]) -> str:
    what = f'team "{d.TEAM}"'
    body = {"team": {"type": "team", "name": d.TEAM, "description": d.TEAM_DESCRIPTION}}
    team = pd.find_by_name("/teams", "teams", d.TEAM)
    members: dict[str, str] = {}
    if team is None:
        team_id = plan.change("create", what, action=lambda: pd.write("POST", "/teams", body)["team"]["id"],
                              placeholder="<new team>", parent=True)
    else:
        team_id = team["id"]
        diffs = changed([("description", team.get("description") or "", d.TEAM_DESCRIPTION)])
        if diffs:
            plan.change("update", what, ", ".join(diffs), lambda: pd.write("PUT", f"/teams/{team_id}", body))
        else:
            plan.ok(what)
        members = {m["user"]["id"]: m.get("role") for m in pd.list(f"/teams/{team_id}/members", "members")}

    ours = set()
    for name, role in d.TEAM_MEMBERS.items():
        uid = users[name]["id"]
        ours.add(uid)
        have = members.get(uid)
        what = f"team member {name} ({role})"
        if have == role:
            plan.ok(what)
        else:
            plan.change("create" if have is None else "update", what, "" if have is None else f"role was {have}",
                        lambda uid=uid, role=role: pd.write("PUT", f"/teams/{team_id}/users/{uid}", {"role": role}))
    for uid, role in members.items():
        if uid not in ours:
            plan.kept(f"team member {uid} ({role})", "not in the design; left as a person set it")
    return team_id


def ensure_schedule(pd: PagerDuty, plan: Plan, users: dict[str, dict], team_id: str) -> str:
    what = f'schedule "{d.SCHEDULE}"'
    rotation = [users[n]["id"] for n in d.ROTATION]
    layer = {
        "name": d.LAYER_NAME,
        "start": d.LAYER_START,
        "rotation_virtual_start": d.ROTATION_VIRTUAL_START,
        "rotation_turn_length_seconds": d.WEEK_SECONDS,
        "users": [{"user": ref("user", uid)} for uid in rotation],
    }

    def body(layer_: dict) -> dict:
        return {"schedule": {"type": "schedule", "name": d.SCHEDULE, "description": d.SCHEDULE_DESCRIPTION,
                             "time_zone": d.TIME_ZONE, "schedule_layers": [layer_], "teams": [ref("team", team_id)]}}

    detail = f"{', '.join(d.ROTATION)}; weekly, Monday 09:00 {d.TIME_ZONE}"
    found = pd.find_by_name("/schedules", "schedules", d.SCHEDULE)
    if found is None:
        return plan.change("create", what, detail,
                           lambda: pd.write("POST", "/schedules", body(layer))["schedule"]["id"],
                           placeholder="<new schedule>", parent=True)
    sid = found["id"]
    s = pd.get(f"/schedules/{sid}")["schedule"]
    live = [x for x in s.get("schedule_layers") or [] if not x.get("end")]
    if len(live) != 1:
        plan.refuse(what, f"{len(live)} active layers: the script only changes a schedule with exactly one, so "
                          "nothing was changed; a person merges the layers in PagerDuty")
        return sid
    have = live[0]
    diffs = changed([
        ("time zone", s.get("time_zone"), d.TIME_ZONE),
        ("description", s.get("description") or "", d.SCHEDULE_DESCRIPTION),
        ("team", sorted(t["id"] for t in s.get("teams") or []), [team_id]),
        ("who is on call", [u["user"]["id"] for u in have.get("users") or []], rotation),
        ("turn length", have.get("rotation_turn_length_seconds"), d.WEEK_SECONDS),
        ("hand-off time", same_instant(have.get("rotation_virtual_start"), d.ROTATION_VIRTUAL_START), True),
        ("restrictions", bool(have.get("restrictions")), False),
    ])
    if diffs:
        new_layer = {**layer, "id": have["id"], "start": have.get("start") or d.LAYER_START}
        plan.change("update", what, ", ".join(diffs), lambda: pd.write("PUT", f"/schedules/{sid}", body(new_layer)))
    else:
        plan.ok(what, detail)
    return sid


def ensure_policy(pd: PagerDuty, plan: Plan, users: dict[str, dict], team_id: str, schedule_id: str) -> str:
    what = f'escalation policy "{d.POLICY}"'
    second = users[d.SECOND_LEVEL]["id"]
    rules = [
        {"escalation_delay_in_minutes": d.LEVEL_DELAY_MINUTES, "targets": [ref("schedule", schedule_id)]},
        {"escalation_delay_in_minutes": d.LEVEL_DELAY_MINUTES, "targets": [ref("user", second)]},
    ]
    body = {"escalation_policy": {
        "type": "escalation_policy", "name": d.POLICY, "description": d.POLICY_DESCRIPTION,
        "num_loops": d.POLICY_LOOPS, "on_call_handoff_notifications": "if_has_services",
        "escalation_rules": rules, "teams": [ref("team", team_id)],
    }}
    detail = f"1: {d.SCHEDULE}, 15 min; 2: {d.SECOND_LEVEL}, 15 min; repeats {d.POLICY_LOOPS}x"

    def shape(rs):
        return [(r.get("escalation_delay_in_minutes"),
                 sorted((t.get("type", "").removesuffix("_reference"), t.get("id")) for t in r.get("targets") or []))
                for r in rs]

    found = pd.find_by_name("/escalation_policies", "escalation_policies", d.POLICY)
    if found is None:
        return plan.change("create", what, detail,
                           lambda: pd.write("POST", "/escalation_policies", body)["escalation_policy"]["id"],
                           placeholder="<new escalation policy>", parent=True)
    pid = found["id"]
    diffs = changed([
        ("levels", shape(found.get("escalation_rules") or []), shape(rules)),
        ("repeats", found.get("num_loops"), d.POLICY_LOOPS),
        ("description", found.get("description") or "", d.POLICY_DESCRIPTION),
        ("hand-off notifications", found.get("on_call_handoff_notifications"), "if_has_services"),
        ("team", sorted(t["id"] for t in found.get("teams") or []), [team_id]),
    ])
    if diffs:
        plan.change("update", what, ", ".join(diffs), lambda: pd.write("PUT", f"/escalation_policies/{pid}", body))
    else:
        plan.ok(what, detail)
    return pid


# ---- services --------------------------------------------------------------------------------------------------------


def refuses_intelligent(e: ApiError) -> bool:
    """A refusal of intelligent grouping itself: a 4xx whose text names it. Any other error is not a fallback."""
    text = e.message.lower()
    return 400 <= e.status < 500 and e.status not in (401, 404, 429) and ("intelligent" in text or "grouping" in text)


class Grouping:
    """Alert grouping through /alert_grouping_settings (the service field alert_grouping_parameters is deprecated):
    intelligent where the account allows it, else time-based, 10 minutes. The fallback is learned once a run."""

    def __init__(self, pd: PagerDuty, plan: Plan, retry_intelligent: bool):
        self.pd, self.plan, self.retry_intelligent = pd, plan, retry_intelligent
        self.preferred = INTELLIGENT

    def acceptable(self, setting: dict) -> bool:
        kind = setting.get("type")
        if kind == "intelligent":
            return True
        timeout = (setting.get("config") or {}).get("timeout")
        return kind == "time" and timeout == d.TIME_GROUPING_MINUTES and not self.retry_intelligent

    def _send(self, send):
        if self.preferred is INTELLIGENT:
            try:
                return send(INTELLIGENT)
            except ApiError as e:
                if not refuses_intelligent(e):
                    raise
                out(f"          (PagerDuty refused intelligent alert grouping: {e.message[:160]}; using time-based "
                    f"grouping, {d.TIME_GROUPING_MINUTES} minutes)")
                self.preferred = TIME_BASED
        return send(TIME_BASED)

    def ensure(self, name: str, sid: str, new: bool) -> None:
        what = f'  alert grouping on "{name}"'
        if new and not self.plan.apply:
            self.plan.change("create", what, "intelligent (time-based, 10 min, if the account refuses it)")
            return
        settings = [s for s in self.pd.list_cursor("/alert_grouping_settings", "alert_grouping_settings")
                    if any(x.get("id") == sid for x in s.get("services") or [])]
        if len(settings) > 1:
            self.plan.refuse(what, f"{len(settings)} grouping settings hold this service; a person keeps one")
            return
        if not settings:
            def create(g):
                return self.pd.write("POST", "/alert_grouping_settings", {"alert_grouping_setting": {
                    "name": name, **g, "services": [{"id": sid}]}})
            self.plan.change("create", what, "intelligent (time-based, 10 min, if the account refuses it)",
                             lambda: self._send(create))
            return
        setting = settings[0]
        if self.acceptable(setting):
            self.plan.ok(what, setting.get("type"))
            return

        def update(g):
            return self.pd.write("PUT", f"/alert_grouping_settings/{setting['id']}", {"alert_grouping_setting": {
                "name": setting.get("name") or name, **g,
                "services": [{"id": x["id"]} for x in setting.get("services") or []]}})
        self.plan.change("update", what, f"was {setting.get('type')}", lambda: self._send(update))


def service_fields(cfg: dict, policy_id: str) -> dict:
    return {
        "type": "service",
        "name": cfg["name"],
        "description": cfg["description"],
        "escalation_policy": ref("escalation_policy", policy_id),
        "incident_urgency_rule": {"type": "constant", "urgency": "severity_based"},
        "acknowledgement_timeout": d.ACK_TIMEOUT_SECONDS,
        "auto_resolve_timeout": None,
        "alert_creation": "create_alerts_and_incidents",
    }


def desired_orchestration(service_id: str, priorities: dict[str, str]) -> dict:
    rules = [{
        "label": d.rule_label(r),
        "conditions": [{"expression": d.rule_expression(r["monitoring"])}],
        "actions": {"severity": r["severity"], "priority": priorities[r["priority"]]},
    } for r in d.SEVERITY_RULES]
    return {"type": "service", "parent": ref("service", service_id),
            "sets": [{"id": "start", "rules": rules}], "catch_all": {"actions": {}}}


def _set_actions(actions: dict | None) -> dict:
    return {k: v for k, v in (actions or {}).items() if v not in (None, False, "", [], {})}


def orchestration_shape(path: dict) -> tuple:
    sets = [(s.get("id"), [(r.get("label"), [c.get("expression") for c in r.get("conditions") or []],
                            _set_actions(r.get("actions")), bool(r.get("disabled"))) for r in s.get("rules") or []])
            for s in path.get("sets") or []]
    return sets, _set_actions((path.get("catch_all") or {}).get("actions"))


def ours(integration: dict) -> bool:
    return ((integration.get("vendor") or {}).get("id") == d.VENDOR_ID
            or (integration.get("name") == d.INTEGRATION_NAME and integration.get("type") == d.INTEGRATION_TYPE))


def ensure_services(pd: PagerDuty, plan: Plan, policy_id: str, priorities: dict[str, str],
                    grouping: Grouping) -> list[str | None]:
    """Each service's id, or None for one the script refused to make (its children are skipped)."""
    every = pd.list("/services", "services", {"include[]": "integrations"})
    ids: list[str | None] = []
    for cfg in d.SERVICES:
        name = cfg["name"]
        what = f'service "{name}"'
        fields = service_fields(cfg, policy_id)
        detail = "urgency from severity; ack timeout 30 min; no auto-resolve"
        same = [s for s in every if s.get("name") == name]
        if len(same) > 1:
            raise Refused(f'{len(same)} services named "{name}": remove the extra ones first')
        svc = same[0] if same else None
        if svc is None:
            renamed = [s for s in every if s.get("description") == cfg["description"]
                       and any(ours(i) for i in s.get("integrations") or [])]
            if renamed:
                plan.refuse(what, f'not created: "{renamed[0].get("name")}" carries its integration and description '
                                  f'(renamed?). Rename it back to "{name}", or remove it, then re-run')
                ids.append(None)
                continue
            sid = plan.change("create", what, detail,
                              lambda f=fields: pd.write("POST", "/services", {"service": f})["service"]["id"],
                              placeholder=f"<new service {cfg['role']}>", parent=True)
            integrations = []
        else:
            sid = svc["id"]
            integrations = svc.get("integrations") or []
            diffs = changed([
                ("description", svc.get("description") or "", cfg["description"]),
                ("escalation policy", (svc.get("escalation_policy") or {}).get("id"), policy_id),
                ("urgency", svc.get("incident_urgency_rule"), fields["incident_urgency_rule"]),
                ("acknowledgement timeout", svc.get("acknowledgement_timeout"), d.ACK_TIMEOUT_SECONDS),
                ("auto-resolve", svc.get("auto_resolve_timeout"), None),
                ("alert creation", svc.get("alert_creation", "create_alerts_and_incidents"),
                 "create_alerts_and_incidents"),
            ])
            if diffs:
                plan.change("update", what, ", ".join(diffs),
                            lambda f=fields, sid=sid: pd.write("PUT", f"/services/{sid}", {"service": f}))
            else:
                plan.ok(what, detail)
        ids.append(sid)
        new = svc is None

        iwhat = f'  integration "{d.INTEGRATION_NAME}" on "{name}"'
        if any(ours(i) for i in integrations):
            plan.ok(iwhat)
        else:
            body = {"integration": {"type": d.INTEGRATION_TYPE, "name": d.INTEGRATION_NAME,
                                    "service": ref("service", sid), "vendor": ref("vendor", d.VENDOR_ID)}}
            plan.change("create", iwhat, "the key Monitoring's pagerduty channel uses (gcp_channels.py)",
                        lambda sid=sid, body=body: pd.write("POST", f"/services/{sid}/integrations", body))

        grouping.ensure(name, sid, new)
        ensure_orchestration(pd, plan, name, sid, new, priorities)
    return ids


def ensure_orchestration(pd: PagerDuty, plan: Plan, name: str, sid: str, new: bool, priorities: dict[str, str]):
    what = f'  event orchestration on "{name}"'
    detail = "; ".join(f"{r['monitoring']} -> {r['severity']} {r['priority']}" for r in d.SEVERITY_RULES)
    detail += " (any letter case); anything else keeps the default (critical)"

    def put():
        return pd.write("PUT", f"/event_orchestrations/services/{sid}",
                        {"orchestration_path": desired_orchestration(sid, priorities)})

    def activate():
        return pd.write("PUT", f"/event_orchestrations/services/{sid}/active", {"active": True})

    if new:
        plan.change("create", what, detail, put)
        plan.change("create", f'  event orchestration active on "{name}"', "", activate)
        return
    path = pd.get(f"/event_orchestrations/services/{sid}")["orchestration_path"]
    if orchestration_shape(path) == orchestration_shape(desired_orchestration(sid, priorities)):
        plan.ok(what, detail)
    else:
        plan.change("update", what, detail, put)
    active = (pd.get(f"/event_orchestrations/services/{sid}/active") or {}).get("active")
    if active:
        plan.ok(f'  event orchestration active on "{name}"')
    else:
        plan.change("update", f'  event orchestration active on "{name}"', "was inactive", activate)


# ---- Slack (read only) -----------------------------------------------------------------------------------------------


def slack_gaps(config: dict, priority_ids: list[str]) -> list[str]:
    """What a service's Slack connection lacks against the design, in words."""
    gaps = []
    events = config.get("events") or []
    missing = [e.removeprefix("incident.") for e in d.SLACK_EVENTS if e not in events]
    if missing:
        gaps.append("events: add " + ", ".join(missing))
    if config.get("urgency") not in (None, ""):
        gaps.append(f"urgency: both high and low (it is {config['urgency']} only)")
    chosen = config.get("priorities") or []
    if "*" not in chosen and not (chosen and set(priority_ids) <= set(chosen)):
        gaps.append("priorities: all")
    return gaps


def report_slack(pd: PagerDuty, plan: Plan, service_ids: list[str | None], priority_ids: list[str]) -> None:
    try:
        connections = pd.slack_connections()
    except ApiError as e:
        plan.person("  Slack connections", f'cannot read them ({e}); check by hand: docs/PAGERDUTY.md "Slack"')
        return
    for cfg, sid in zip(d.SERVICES, service_ids):
        if sid is None:
            continue
        what = f'  Slack: "{cfg["name"]}"'
        mine = [c for c in connections if c.get("source_id") == sid]
        if not mine:
            plan.person(what, f'not connected: a person connects it to #{d.SLACK_CHANNEL} (docs/PAGERDUTY.md "Slack")')
        for c in mine:
            where = f"{what} connected to #{c.get('channel_name') or c.get('channel_id')}"
            gaps = slack_gaps(c.get("config") or {}, priority_ids)
            if gaps:
                plan.person(where, "in PagerDuty, set " + "; ".join(gaps))
            else:
                plan.ok(where)


# ---- business service ------------------------------------------------------------------------------------------------


def ensure_business_service(pd: PagerDuty, plan: Plan, team_id: str, service_ids: list[str | None]) -> None:
    what = f'business service "{d.BUSINESS_SERVICE}"'
    body = {"business_service": {"name": d.BUSINESS_SERVICE, "description": d.BUSINESS_DESCRIPTION,
                                 "point_of_contact": d.BUSINESS_POINT_OF_CONTACT, "team": ref("team", team_id)}}
    found = [b for b in pd.list("/business_services", "business_services") if b.get("name") == d.BUSINESS_SERVICE]
    if len(found) > 1:
        raise Refused(f'{len(found)} business services named "{d.BUSINESS_SERVICE}": remove the extra ones first')
    supporting: set[str] = set()
    if not found:
        bid = plan.change("create", what, "", lambda: pd.write("POST", "/business_services", body)
                          ["business_service"]["id"], placeholder="<new business service>", parent=True)
    else:
        b = found[0]
        bid = b["id"]
        diffs = changed([
            ("description", b.get("description") or "", d.BUSINESS_DESCRIPTION),
            ("point of contact", b.get("point_of_contact") or "", d.BUSINESS_POINT_OF_CONTACT),
            ("team", (b.get("team") or {}).get("id"), team_id),
        ])
        if diffs:
            plan.change("update", what, ", ".join(diffs), lambda: pd.write("PUT", f"/business_services/{bid}", body))
        else:
            plan.ok(what)
        rels = pd.get(f"/service_dependencies/business_services/{bid}").get("relationships") or []
        supporting = {r["supporting_service"]["id"] for r in rels if r.get("dependent_service", {}).get("id") == bid}

    for cfg, sid in zip(d.SERVICES, service_ids):
        if sid is None:
            continue
        dwhat = f'  "{d.BUSINESS_SERVICE}" supported by "{cfg["name"]}"'
        if sid in supporting:
            plan.ok(dwhat)
        else:
            rel = {"relationships": [{"supporting_service": {"id": sid, "type": "service"},
                                      "dependent_service": {"id": bid, "type": "business_service"}}]}
            plan.change("create", dwhat, "", lambda rel=rel: pd.write("POST", "/service_dependencies/associate", rel))


# ---- notification rules ----------------------------------------------------------------------------------------------


def ensure_notification_rules(pd: PagerDuty, plan: Plan, users: dict[str, dict], add_rules: bool) -> None:
    """Rules for a contact method that has none yet (first-time setup). A method that already has rules is the
    person's: a designed rule missing from it is reported, not added, unless --add-rules (settings must be honoured)."""
    for name in d.TEAM_MEMBERS:
        u = users[name]
        # Read from the user's own endpoints: /users?include[]=notification_rules leaves out Slack rules, and
        # /users/{id}/notification_rules returns high urgency only unless asked for low ("any" returns none).
        methods = [c for c in pd.get(f"/users/{u['id']}/contact_methods").get("contact_methods") or []
                   if c.get("type") in d.CONTACT_WORDS]
        have: dict[tuple, list[int]] = {}
        for urgency in ("high", "low"):
            got = pd.get(f"/users/{u['id']}/notification_rules", {"urgency": urgency}).get("notification_rules")
            for r in got or []:
                key = ((r.get("contact_method") or {}).get("id"), r.get("urgency"))
                have.setdefault(key, []).append(r.get("start_delay_in_minutes"))
        with_rules = {cm_id for cm_id, _ in have}
        wanted = set()
        for urgency in ("high", "low"):
            for cm in methods:
                delay = d.NOTIFY[urgency].get(cm["type"])
                if delay is None:
                    continue
                wanted.add((cm["id"], urgency))
                what = (f"notification rule {name}: {urgency} urgency -> {d.CONTACT_WORDS[cm['type']]} "
                        f'"{cm.get("label") or ""}" at {delay} min')
                delays = have.get((cm["id"], urgency))
                if delays is not None:
                    if delay in delays:
                        plan.ok(what)
                    else:
                        plan.kept(what, f"the person set it at {sorted(delays)} min")
                elif cm["id"] in with_rules and not add_rules:
                    plan.kept(what, "not added: this contact method has rules the person set and none at this "
                                    "urgency (--add-rules adds it)")
                else:
                    body = {"notification_rule": {"type": "assignment_notification_rule", "urgency": urgency,
                                                  "start_delay_in_minutes": delay,
                                                  "contact_method": {"id": cm["id"], "type": cm["type"]}}}
                    plan.change("create", what, "", lambda uid=u["id"], body=body:
                                pd.write("POST", f"/users/{uid}/notification_rules", body))
        for (cm_id, urgency), delays in sorted(have.items(), key=str):
            if (cm_id, urgency) not in wanted:
                plan.kept(f"notification rule {name}: {urgency} urgency -> contact method {cm_id} at {delays} min",
                          "not in the design; left as the person set it")
        missing = sorted({t for t in d.CONTACT_WORDS} - {c["type"] for c in methods})
        if missing:
            out(f"          ({name} has no {', '.join(d.CONTACT_WORDS[t] for t in missing)} yet: once added in "
                "PagerDuty, a re-run adds its rules)")


# ---- main ------------------------------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true", help="make the changes (default: dry run)")
    parser.add_argument("--add-rules", action="store_true",
                        help="also add designed notification rules missing on a contact method that has others")
    parser.add_argument("--retry-intelligent-grouping", action="store_true",
                        help="try intelligent alert grouping again where a service has time-based grouping")
    args = parser.parse_args()

    pd = PagerDuty(d.pagerduty_token(), writes=args.apply)
    plan = Plan(args.apply)
    out("pd_setup: " + ("APPLY: making the changes below." if args.apply else
                        "dry run: nothing is changed; --apply makes the creates and updates below."))

    vendor = pd.get(f"/vendors/{d.VENDOR_ID}")["vendor"]
    if vendor.get("name") != d.INTEGRATION_NAME:
        raise Refused(f"vendor {d.VENDOR_ID} is {vendor.get('name')!r}, not {d.INTEGRATION_NAME!r}")
    priorities = {p["name"]: p["id"] for p in pd.list("/priorities", "priorities")}
    missing = [r["priority"] for r in d.SEVERITY_RULES if r["priority"] not in priorities]
    if missing:
        raise Refused(f"the account has no priority {', '.join(missing)}: turn priorities on in PagerDuty first")
    users = read_users(pd)

    stopped = None
    try:
        team_id = ensure_team(pd, plan, users)
        schedule_id = ensure_schedule(pd, plan, users, team_id)
        policy_id = ensure_policy(pd, plan, users, team_id, schedule_id)
        service_ids = ensure_services(pd, plan, policy_id, priorities,
                                      Grouping(pd, plan, args.retry_intelligent_grouping))
        report_slack(pd, plan, service_ids, list(priorities.values()))
        ensure_business_service(pd, plan, team_id, service_ids)
        ensure_notification_rules(pd, plan, users, args.add_rules)
    except Stop as e:
        stopped = str(e)
        out(f"stopped: {stopped} was refused, so nothing that depends on it was attempted")

    c = plan.counts
    if args.apply:
        out(f"summary: created {c['create']}, updated {c['update']}, ok {c['ok']}, kept {c['kept']}, "
            f"refused {c['refused']}, by hand {c['person']}")
    else:
        out(f"summary: {c['create']} to create, {c['update']} to update, {c['ok']} ok, {c['kept']} kept, "
            f"{c['refused']} refused, {c['person']} by hand")
    if stopped:
        return 2
    return 1 if c["refused"] else 0


if __name__ == "__main__":
    d.run_main(main)
