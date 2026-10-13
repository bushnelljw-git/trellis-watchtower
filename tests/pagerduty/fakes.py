"""A fake PagerDuty (REST and Events API v1) for the scripts/pagerduty tests.

An automated gate only: one local HTTP server on 127.0.0.1 answering the calls the scripts make, holding its state in
memory and recording every request. It also models what the design relies on, so the tests can check it end to end:
a v1 event's `description` becomes the summary and its `details` become `custom_details`; a service orchestration
starts at its "start" set, where the first matching rule (no conditions: it always matches) applies its actions and
its `route_to` moves the event to the next set, later actions winning; a set with no match applies the catch-all and
ends. Conditions: `matches part` is a case-sensitive substring test, the cautious reading; `matches regex` is an
RE2-like search ((?i), the POSIX class [[:space:]], [[] for a "[", and $ only at the very end of the text); `exists`;
`and`; `not (…)`. A regex variable takes its capture group, else the whole match, and is unset when nothing matches;
a template names only variables of its own rule, and an unset one renders empty; a regex extraction joins its capture
groups and changes nothing when nothing matches. The rules set the alert's severity, the incident's priority and its
title (the final summary); an event no rule gives a severity keeps critical; a severity-based service pages critical
and error at high urgency, warning and info at low. A resolve finds its alert by the incident key alone. Error bodies
echo what they were sent, as a careless API might, so the tests can prove the scripts never print a secret that comes
back in one.

The live account is the real proof (docs/PAGERDUTY.md, "Verified"); this is the model the scripts are tested against.
"""

from __future__ import annotations

import copy
import itertools
import json
import re
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "pd-sentinel-token-7f3a9c41"
KEY_PREFIX = "keysentinel"

ACTION_DEFAULTS = {
    "route_to": None, "suppress": False, "suspend": None, "priority": None, "annotate": None, "severity": None,
    "event_action": None, "variables": [], "extractions": [], "incident_custom_field_updates": [],
    "escalation_policy": None, "automation_action": None, "pagerduty_automation_action": None,
}
FIELD = r"event\.custom_details\.([A-Za-z0-9_.]+)"
# One condition term: `<field> matches part|regex '<text>'` or `<field> exists`, optionally inside `not ( … )`.
TERM = re.compile(rf"(not \()?{FIELD} (?:matches (part|regex) '([^']*)'|(exists))(\))?")
EVENT_PATH = re.compile(r"^event\.(summary|custom_details(?:\.[A-Za-z0-9_]+)+)$")
TARGET = re.compile(r"^event\.(summary|custom_details\.[A-Za-z0-9_]+)$")
TEMPLATE_VARIABLE = re.compile(r"\{\{variables\.([A-Za-z0-9_]+)\}\}")


def re2(pattern: str) -> re.Pattern:
    """RE2's meaning in Python's re: the class [:space:] inside brackets is \\s ([[:space:]], [^[:space:]]), [[] is a
    literal "[", and $ (outside multi-line mode) matches only at the very end of the text. Python's own $ also matches
    before a final newline, which RE2's never does."""
    pat = pattern.replace("[:space:]", r"\s").replace("[[]", r"\[")
    if pat.endswith("$") and not pat.endswith(r"\$"):
        pat = pat[:-1] + r"\Z"
    return re.compile(pat)


def re2_search(pattern: str, text: str) -> bool:
    return re2(pattern).search(text) is not None


def parse_pcl(expression: str) -> list[tuple] | None:
    """[(negated, field, operator, text)] for `term and term …`, or None for a form this fake does not know."""
    terms, pos = [], 0
    while True:
        m = TERM.match(expression, pos)
        if not m or bool(m.group(1)) != bool(m.group(6)):
            return None
        terms.append((bool(m.group(1)), m.group(2), m.group(3) or "exists", m.group(4)))
        pos = m.end()
        if pos == len(expression):
            return terms
        if not expression.startswith(" and ", pos):
            return None
        pos += len(" and ")


def lookup(value, dotted: str):
    for part in dotted.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def regex_value(pattern: str, value, join_groups: bool):
    """A variable's (first capture group) or an extraction's (every group, joined) value; None when nothing matches."""
    m = re2(pattern).search(value) if isinstance(value, str) else None
    if m is None:
        return None
    if not m.groups():
        return m.group(0)
    return "".join(g or "" for g in m.groups()) if join_groups else m.group(1)


class Fail(Exception):
    def __init__(self, status: int, body: dict | None, location: str | None = None):
        super().__init__(status)
        self.status, self.body, self.location = status, body, location


def not_found():
    return Fail(404, {"error": {"message": "Not Found", "code": 2100}})


class FakeState:
    def __init__(self, refuse_intelligent=False, rich_contacts=False, refuse_team_create=False, grouping_error=None,
                 redirect_pd=False):
        self.lock = threading.Lock()
        self.seq = itertools.count(1)
        self.requests: list[dict] = []
        self.page = 2  # small pages, so every listing paginates
        self.refuse_intelligent = refuse_intelligent
        self.refuse_team_create = refuse_team_create
        self.grouping_error = grouping_error  # (status, text) for any grouping-setting write
        self.redirect_pd = redirect_pd
        self.grouping: dict[str, dict] = {}

        self.priorities = [{"id": f"PRI{i}", "name": f"P{i}", "description": ""} for i in range(1, 6)]
        jon_methods = [
            {"id": "CMJEMAIL", "type": "email_contact_method", "label": "Default", "address": "jon@example.test"},
            {"id": "CMJSLACK", "type": "slack_contact_method", "label": "slack", "address": "slack_T1_U1"},
        ]
        if rich_contacts:
            jon_methods += [
                {"id": "CMJPHONE", "type": "phone_contact_method", "label": "Mobile", "address": "5550100"},
                {"id": "CMJSMS", "type": "sms_contact_method", "label": "Mobile", "address": "5550100"},
                {"id": "CMJPUSH", "type": "push_notification_contact_method", "label": "iPhone", "address": "x"},
            ]
        self.users = {
            "PJON": {"id": "PJON", "name": "Jonathan Bushnell", "role": "owner", "contact_methods": jon_methods,
                     "notification_rules": []},
            "PRAF": {"id": "PRAF", "name": "Rafeale Hill", "role": "admin", "contact_methods": [
                {"id": "CMREMAIL", "type": "email_contact_method", "label": "Default", "address": "raf@example.test"}],
                "notification_rules": []},
            "POTHER": {"id": "POTHER", "name": "Someone Else", "role": "user", "contact_methods": [],
                       "notification_rules": []},
        }
        for uid, cm in (("PJON", "CMJEMAIL"), ("PRAF", "CMREMAIL")):
            for urgency in ("high", "low"):
                self.add_rule(uid, cm, urgency, 0)

        self.teams: dict[str, dict] = {}
        self.members: dict[str, dict[str, str]] = {}
        self.schedules: dict[str, dict] = {}
        self.policies = {"PDEFEP": {"id": "PDEFEP", "name": "Default", "num_loops": 0, "teams": [],
                                    "escalation_rules": [{"escalation_delay_in_minutes": 30,
                                                          "targets": [{"id": "PJON", "type": "user_reference"}]}]}}
        self.services = {"PDEFSVC": {"id": "PDEFSVC", "name": "Default Service", "description": "Your first service",
                                     "escalation_policy": {"id": "PDEFEP"}, "incident_urgency_rule":
                                         {"type": "constant", "urgency": "high"}, "acknowledgement_timeout": None,
                                     "auto_resolve_timeout": None, "alert_creation": "create_alerts_and_incidents",
                                     "alert_grouping_parameters": {"type": None, "config": None}}}
        self.integrations: dict[str, list[dict]] = {"PDEFSVC": []}
        self.orchestrations: dict[str, dict] = {}
        self.active: dict[str, bool] = {"PDEFSVC": True}
        self.business: dict[str, dict] = {}
        self.dependencies: list[tuple[str, str]] = []
        self.incidents: dict[str, dict] = {}
        self.alerts: dict[str, list[dict]] = {}
        self.slack_connections: list[dict] = []

    # ---- helpers ---------------------------------------------------------------------------------------------------
    def new_id(self, prefix: str) -> str:
        return f"{prefix}{next(self.seq):04d}"

    def delete_rule(self, uid, cm_id, urgency):
        rules = self.users[uid]["notification_rules"]
        rules[:] = [r for r in rules if not (r["contact_method"]["id"] == cm_id and r["urgency"] == urgency)]

    def add_rule(self, uid, cm_id, urgency, delay):
        user = self.users[uid]
        cm = next(c for c in user["contact_methods"] if c["id"] == cm_id)
        user["notification_rules"].append({"id": self.new_id("NR"), "type": "assignment_notification_rule",
                                           "urgency": urgency, "start_delay_in_minutes": delay, "contact_method": cm})

    def writes(self, prefix="/pd"):
        return [r for r in self.requests if r["method"] != "GET" and r["path"].startswith(prefix)]

    def page_of(self, items, key, query):
        if "query" in query:
            items = [i for i in items if query["query"][0].lower() in (i.get("name") or "").lower()]
        offset = int(query.get("offset", ["0"])[0])
        limit = min(int(query.get("limit", ["25"])[0]), self.page)
        chunk = items[offset:offset + limit]
        return {key: chunk, "offset": offset, "limit": limit, "more": offset + limit < len(items), "total": None}

    def service_view(self, sid, with_integrations):
        view = dict(self.services[sid])
        if with_integrations:
            view["integrations"] = [dict(i) for i in self.integrations.get(sid, [])]
        return view

    # ---- PagerDuty REST --------------------------------------------------------------------------------------------
    def pagerduty(self, method, parts, query, body):
        p = parts
        if method == "GET" and p[:1] == ["vendors"] and len(p) == 2:
            if p[1] != "PUCLE3C":
                raise not_found()
            return 200, {"vendor": {"id": "PUCLE3C", "name": "Google Cloud Monitoring", "generic_service_type": "api"}}
        if method == "GET" and p == ["integration-slack", "workspaces"]:
            return 200, {"workspaces": [{"slack_team_id": "T1", "slack_team_name": "Fake"}]}
        if method == "GET" and p == ["priorities"]:
            return 200, self.page_of(self.priorities, "priorities", query)
        if method == "GET" and p == ["users"]:
            # Like the live API: an included rule list leaves out Slack rules.
            views = [{**u, "notification_rules": [r for r in u["notification_rules"]
                                                  if r["contact_method"]["type"] != "slack_contact_method"]}
                     for u in self.users.values()]
            return 200, self.page_of(views, "users", query)
        if method == "GET" and p[:1] == ["users"] and len(p) == 3 and p[2] == "contact_methods":
            return 200, {"contact_methods": self.users[p[1]]["contact_methods"]}
        if method == "GET" and p[:1] == ["users"] and len(p) == 3 and p[2] == "notification_rules":
            # Like the live API: high urgency unless asked; "any" returns nothing.
            urgency = query.get("urgency", ["high"])[0]
            rules = [r for r in self.users[p[1]]["notification_rules"] if r["urgency"] == urgency]
            return 200, {"notification_rules": rules, "total": len(rules)}
        if p[:1] == ["users"] and len(p) == 3 and p[2] == "notification_rules" and method == "POST":
            rule = body["notification_rule"]
            user = self.users[p[1]]
            cm = next((c for c in user["contact_methods"] if c["id"] == rule["contact_method"]["id"]), None)
            if cm is None or cm["type"] != rule["contact_method"]["type"]:
                raise Fail(400, {"error": {"message": "Invalid Input Provided"}})
            if any(r["contact_method"]["id"] == cm["id"] and r["urgency"] == rule["urgency"]
                   and r["start_delay_in_minutes"] == rule["start_delay_in_minutes"]
                   for r in user["notification_rules"]):
                raise Fail(400, {"error": {"message": "Invalid Input Provided", "code": 2001, "errors": [
                    "Channel Start delay must be unique for a given contact method"]}})
            self.add_rule(p[1], cm["id"], rule["urgency"], rule["start_delay_in_minutes"])
            return 201, {"notification_rule": user["notification_rules"][-1]}

        if p == ["teams"]:
            if method == "GET":
                return 200, self.page_of(list(self.teams.values()), "teams", query)
            if self.refuse_team_create:
                raise Fail(400, {"error": {"message": "Invalid Input Provided", "errors": ["Name is reserved"]}})
            team = {"id": self.new_id("PT"), **{k: body["team"][k] for k in ("name", "description")}}
            self.teams[team["id"]] = team
            self.members[team["id"]] = {}
            return 201, {"team": team}
        if p[:1] == ["teams"] and len(p) == 2 and method == "PUT":
            self.teams[p[1]].update({k: body["team"][k] for k in ("name", "description")})
            return 200, {"team": self.teams[p[1]]}
        if p[:1] == ["teams"] and len(p) == 3 and p[2] == "members":
            ms = [{"user": {"id": uid, "type": "user_reference"}, "role": r} for uid, r in self.members[p[1]].items()]
            return 200, self.page_of(ms, "members", query)
        if p[:1] == ["teams"] and len(p) == 4 and p[2] == "users" and method == "PUT":
            if self.users[p[3]]["role"] in ("owner", "admin") and body["role"] != "manager":
                raise Fail(400, {"error": {"message": "Invalid Input Provided", "code": 2001,
                                           "errors": [f"{self.users[p[3]]['role']} cannot take team role "
                                                      f"{body['role']}"]}})
            self.members[p[1]][p[3]] = body["role"]
            return 204, None

        if p == ["schedules"]:
            if method == "GET":
                return 200, self.page_of([{"id": s["id"], "name": s["name"]} for s in self.schedules.values()],
                                         "schedules", query)
            s = self.store_schedule(self.new_id("PS"), body["schedule"])
            return 201, {"schedule": s}
        if p[:1] == ["schedules"] and len(p) == 2:
            if p[1] not in self.schedules:
                raise not_found()
            if method == "PUT":
                self.store_schedule(p[1], body["schedule"])
            return 200, {"schedule": self.schedules[p[1]]}

        if p == ["escalation_policies"]:
            if method == "GET":
                return 200, self.page_of(list(self.policies.values()), "escalation_policies", query)
            ep = {"id": self.new_id("PE"), **body["escalation_policy"]}
            self.policies[ep["id"]] = ep
            return 201, {"escalation_policy": ep}
        if p[:1] == ["escalation_policies"] and len(p) == 2 and method == "PUT":
            self.policies[p[1]] = {"id": p[1], **body["escalation_policy"]}
            return 200, {"escalation_policy": self.policies[p[1]]}

        if p == ["alert_grouping_settings"]:
            if method == "GET":
                items = list(self.grouping.values())
                start = int(query.get("after", ["0"])[0])
                chunk = items[start:start + self.page]
                after = str(start + self.page) if start + self.page < len(items) else None
                return 200, {"alert_grouping_settings": chunk, "after": after, "limit": self.page}
            g = self.check_grouping(body["alert_grouping_setting"])
            g["id"] = self.new_id("PG")
            self.grouping[g["id"]] = g
            return 201, {"alert_grouping_setting": g}
        if p[:1] == ["alert_grouping_settings"] and len(p) == 2 and method == "PUT":
            g = self.check_grouping(body["alert_grouping_setting"])
            self.grouping[p[1]] = {**g, "id": p[1]}
            return 200, {"alert_grouping_setting": self.grouping[p[1]]}

        if p == ["services"]:
            if method == "GET":
                incl = "integrations" in query.get("include[]", [])
                views = [self.service_view(s, incl) for s in self.services]
                return 200, self.page_of(views, "services", query)
            svc = self.check_service(body["service"])
            svc["id"] = self.new_id("PSV")
            self.services[svc["id"]] = svc
            self.integrations[svc["id"]] = []
            self.active[svc["id"]] = True
            return 201, {"service": svc}
        if p[:1] == ["services"] and len(p) == 2 and method == "PUT":
            svc = self.check_service(body["service"])
            self.services[p[1]] = {**self.services[p[1]], **svc}
            return 200, {"service": self.services[p[1]]}
        if p[:1] == ["services"] and len(p) == 3 and p[2] == "integrations" and method == "POST":
            i = body["integration"]
            integ = {"id": self.new_id("PI"), "type": i["type"], "name": i["name"], "vendor": i.get("vendor"),
                     "integration_key": f"{KEY_PREFIX}{next(self.seq):08d}abcdef0123456789"[:32]}
            self.integrations[p[1]].append(integ)
            return 201, {"integration": integ}
        if p[:1] == ["services"] and len(p) == 4 and p[2] == "integrations" and method == "GET":
            found = [i for i in self.integrations.get(p[1], []) if i["id"] == p[3]]
            if not found:
                raise not_found()
            return 200, {"integration": found[0]}

        if p[:2] == ["event_orchestrations", "services"] and len(p) == 3:
            sid = p[2]
            if method == "PUT":
                self.orchestrations[sid] = self.store_orchestration(body["orchestration_path"])
            path = self.orchestrations.get(sid) or {"type": "service", "parent": {"id": sid}, "sets": [
                {"id": "start", "rules": []}], "catch_all": {"actions": {}}}
            return 200, {"orchestration_path": path}
        if p[:2] == ["event_orchestrations", "services"] and len(p) == 4 and p[3] == "active":
            if method == "PUT":
                self.active[p[2]] = bool(body["active"])
            return 200, {"active": self.active.get(p[2], False)}

        if p == ["business_services"]:
            if method == "GET":
                return 200, self.page_of(list(self.business.values()), "business_services", query)
            b = {"id": self.new_id("PB"), **body["business_service"]}
            self.business[b["id"]] = b
            return 201, {"business_service": b}
        if p[:1] == ["business_services"] and len(p) == 2 and method == "PUT":
            self.business[p[1]].update(body["business_service"])
            return 200, {"business_service": self.business[p[1]]}
        if p[:2] == ["service_dependencies", "business_services"] and len(p) == 3:
            rels = [{"supporting_service": {"id": s, "type": "technical_service_reference"},
                     "dependent_service": {"id": b, "type": "business_service_reference"}}
                    for s, b in self.dependencies if b == p[2]]
            return 200, {"relationships": rels}
        if p == ["service_dependencies", "associate"] and method == "POST":
            for r in body["relationships"]:
                pair = (r["supporting_service"]["id"], r["dependent_service"]["id"])
                if pair not in self.dependencies:
                    self.dependencies.append(pair)
            return 200, {"relationships": body["relationships"]}

        if p == ["incidents"] and method == "GET":
            sids = query.get("service_ids[]", [])
            items = [i for i in self.incidents.values() if not sids or i["service"]["id"] in sids]
            return 200, self.page_of(items, "incidents", query)
        if p[:1] == ["incidents"] and len(p) == 2:
            return 200, {"incident": self.incidents[p[1]]}
        if p[:1] == ["incidents"] and len(p) == 3 and p[2] == "alerts":
            return 200, self.page_of(self.alerts[p[1]], "alerts", query)
        raise not_found()

    def check_service(self, svc):
        if "alert_grouping_parameters" in svc:
            raise Fail(400, {"error": {"message": "alert_grouping_parameters is deprecated in this fake"}})
        return dict(svc)

    def check_grouping(self, g):
        if self.grouping_error:
            status, text = self.grouping_error
            raise Fail(status, {"error": {"message": "Invalid Input Provided", "errors": [text]}})
        if g.get("type") == "intelligent" and self.refuse_intelligent:
            raise Fail(400, {"error": {"message": "Invalid Input Provided", "code": 2001,
                                       "errors": ["Intelligent alert grouping is not available on this account"]}})
        return dict(g)

    def store_schedule(self, sid, s):
        layers = []
        old = {x["id"]: x for x in (self.schedules.get(sid) or {}).get("schedule_layers", [])}
        for layer in s["schedule_layers"]:
            lid = layer.get("id") or self.new_id("PL")
            vstart = datetime.fromisoformat(layer["rotation_virtual_start"]).astimezone(timezone.utc)
            layers.append({**layer, "id": lid, "end": None, "restrictions": [],
                           "rotation_virtual_start": vstart.strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "start": (old.get(lid) or layer)["start"]})
        self.schedules[sid] = {"id": sid, "name": s["name"], "description": s.get("description"),
                               "time_zone": s["time_zone"], "teams": s.get("teams", []), "schedule_layers": layers}
        return self.schedules[sid]

    @staticmethod
    def invalid(text):
        return Fail(400, {"error": {"message": "Invalid payload", "errors": [text]}})

    def check_actions(self, actions, set_ids, catch_all=False):
        """Refuse what the design must never send. A backslash in any regex is refused, the cautious reading of the
        live parser's refusal of one inside a quoted condition string (2026-10-11)."""
        names = set()
        for v in actions.get("variables") or []:
            if v.get("type") != "regex" or not EVENT_PATH.match(v.get("path") or "") or "\\" in v.get("value", "\\"):
                raise self.invalid(f"bad variable {v}")
            re2(v["value"])
            names.add(v["name"])
        for x in actions.get("extractions") or []:
            by_template = x.get("template") is not None
            by_regex = x.get("regex") is not None and x.get("source") is not None
            if not TARGET.match(x.get("target") or "") or by_template == by_regex:
                raise self.invalid(f"bad extraction {x}")
            if by_regex:
                if not EVENT_PATH.match(x["source"]) or "\\" in x["regex"]:
                    raise self.invalid(f"bad extraction {x}")
                re2(x["regex"])
            elif not set(TEMPLATE_VARIABLE.findall(x["template"])) <= names:
                raise self.invalid(f"template names a variable its rule does not define: {x['template']}")
        route = actions.get("route_to")
        if route is not None and (catch_all or route not in set_ids):
            raise self.invalid(f"route_to {route!r} is not a set of this orchestration")

    def store_orchestration(self, path):
        set_ids = [s["id"] for s in path["sets"]]
        if set_ids[:1] != ["start"] or len(set(set_ids)) != len(set_ids):
            raise self.invalid(f"sets {set_ids}: the first must be start, and each id unique")
        for s in path["sets"]:
            for r in s.get("rules", []):
                for c in r.get("conditions", []):
                    if "\\" in c["expression"] or parse_pcl(c["expression"]) is None:
                        # Like the live parser (2026-10-11): no backslash inside a quoted string.
                        raise self.invalid(f"unexpected symbols in {c['expression']}")
                self.check_actions(r.get("actions", {}), set_ids)
        self.check_actions(path.get("catch_all", {}).get("actions", {}), set_ids, catch_all=True)
        sets = []
        for s in path["sets"]:
            rules = [{"id": self.new_id("r"), "label": r.get("label"), "conditions": r.get("conditions", []),
                      "actions": self.stored_actions(r.get("actions", {})), "disabled": False}
                     for r in s.get("rules", [])]
            sets.append({"id": s["id"], "rules": rules})
        return {"type": "service", "parent": path["parent"], "sets": sets,
                "catch_all": {"actions": self.stored_actions(path.get("catch_all", {}).get("actions", {}))}}

    @staticmethod
    def stored_actions(actions):
        """As the API returns them: every action field, and every extraction field, null or not."""
        stored = {**ACTION_DEFAULTS, **copy.deepcopy(actions)}
        stored["extractions"] = [{"regex": None, "source": None, "template": None, **x} for x in stored["extractions"]]
        return stored

    # ---- PagerDuty Events API v1 -----------------------------------------------------------------------------------
    def orchestrate(self, sid, body) -> tuple[dict, dict]:
        """The event ({summary, custom_details}) after the service's orchestration, and the severity and priority it
        set. From "start", each set's first matching rule applies its actions and its route_to moves the event on; a
        set where nothing matches applies the catch-all and ends."""
        event = {"summary": body.get("description"), "custom_details": copy.deepcopy(body.get("details") or {})}
        outcome: dict = {}
        path = self.orchestrations.get(sid)
        if not path or not self.active.get(sid):
            return event, outcome
        sets = {s["id"]: s["rules"] for s in path["sets"]}
        current, visited = "start", set()
        while current is not None and current not in visited:
            visited.add(current)
            rule = next((r for r in sets[current] if not r.get("disabled") and self.matches(r, event)), None)
            actions = rule["actions"] if rule else path["catch_all"]["actions"]
            self.apply_actions(actions, event, outcome)
            current = actions.get("route_to") if rule else None
        return event, outcome

    def matches(self, rule, event) -> bool:
        """Any one condition matches; a rule with none always does."""
        return not rule["conditions"] or any(self.pcl(c["expression"], event["custom_details"])
                                             for c in rule["conditions"])

    @staticmethod
    def apply_actions(actions, event, outcome):
        variables = {}
        for v in actions.get("variables") or []:
            value = regex_value(v["value"], lookup(event, v["path"].removeprefix("event.")), join_groups=False)
            if value is not None:
                variables[v["name"]] = value
        for x in actions.get("extractions") or []:
            if x.get("template") is not None:
                value = TEMPLATE_VARIABLE.sub(lambda m: variables.get(m.group(1), ""), x["template"])
            else:
                value = regex_value(x["regex"], lookup(event, x["source"].removeprefix("event.")), join_groups=True)
                if value is None:
                    continue
            field = x["target"].removeprefix("event.")
            if field == "summary":
                event["summary"] = value
            else:
                event["custom_details"][field.removeprefix("custom_details.")] = value
        for k in ("severity", "priority"):
            if actions.get(k):
                outcome[k] = actions[k]

    def event(self, body):
        found = [(sid, i) for sid, items in self.integrations.items() for i in items
                 if i["integration_key"] == body.get("service_key")]
        if not found:
            raise Fail(400, {"status": "invalid event", "message": "Event object is invalid"})
        sid, _ = found[0]
        key = body["incident_key"]
        if body["event_type"] == "resolve":
            for inc_id, alerts in self.alerts.items():
                if any(a["alert_key"] == key for a in alerts):
                    self.incidents[inc_id]["status"] = "resolved"
            return 200, {"status": "success", "message": "Event processed", "incident_key": key}
        event, outcome = self.orchestrate(sid, body)
        severity, priority = outcome.get("severity") or "critical", outcome.get("priority")
        svc = self.services[sid]
        if svc["incident_urgency_rule"].get("urgency") == "severity_based":
            urgency = "high" if severity in ("critical", "error") else "low"
        else:
            urgency = svc["incident_urgency_rule"].get("urgency", "high")
        inc_id = self.new_id("PINC")
        prio = next(({"id": p["id"], "summary": p["name"]} for p in self.priorities if p["id"] == priority), None)
        self.incidents[inc_id] = {"id": inc_id, "incident_number": len(self.incidents) + 1, "status": "triggered",
                                  "urgency": urgency, "priority": prio, "service": {"id": sid},
                                  "title": event["summary"]}
        self.alerts[inc_id] = [{"id": self.new_id("PA"), "alert_key": key, "severity": severity,
                                "status": "triggered", "summary": event["summary"],
                                "body": {"details": event["custom_details"]}}]
        return 200, {"status": "success", "message": "Event processed", "incident_key": key}

    @staticmethod
    def pcl(expression, custom_details):
        terms = parse_pcl(expression)
        if terms is None:
            raise Fail(400, {"error": f"unsupported condition {expression}"})
        return all(negated != FakeState.term(field, op, text, custom_details) for negated, field, op, text in terms)

    @staticmethod
    def term(field, op, text, custom_details) -> bool:
        value = lookup(custom_details, field)
        if op == "exists":
            return value is not None
        if not isinstance(value, str):
            return False
        if op == "part":
            return text in value
        return re2_search(text, value)


class Server:
    """Starts the fake on 127.0.0.1 with a free port; `url(prefix)` gives the base URL for one of the APIs."""

    def __init__(self, state: FakeState):
        self.state = state
        state_ref = state

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _handle(self):
                split = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(split.query)
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else None
                parts = [urllib.parse.unquote(x) for x in split.path.strip("/").split("/")]
                with state_ref.lock:
                    state_ref.requests.append({"method": self.command, "path": split.path, "query": split.query,
                                               "raw": raw.decode(errors="replace"),
                                               "authorization": self.headers.get("Authorization", "")})
                    location = None
                    try:
                        if parts[0] == "pd":
                            if state_ref.redirect_pd:
                                raise Fail(302, None, location="/capture" + split.path)
                            presented = self.headers.get("Authorization", "")
                            if presented != f"Token token={TOKEN}":
                                raise Fail(401, {"error": {"message": f"Unauthorized: {presented} is not valid",
                                                           "code": 2006}})
                            status, payload = state_ref.pagerduty(self.command, parts[1:], query, body)
                        elif parts[0] == "slack":
                            if self.headers.get("Authorization") != f"Token token={TOKEN}":
                                raise Fail(401, {"error": {"message": "Unauthorized"}})
                            if parts[1:] == ["workspaces", "T1", "connections"]:
                                status, payload = 200, {"slack_connections": state_ref.slack_connections,
                                                        "more": False}
                            else:
                                raise not_found()
                        elif parts[0] == "events":
                            status, payload = state_ref.event(body)
                        else:
                            raise not_found()
                    except Fail as f:
                        status, payload, location = f.status, f.body, f.location
                data = b"" if payload is None else json.dumps(payload).encode()
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def url(self, prefix: str) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}/{prefix}"
