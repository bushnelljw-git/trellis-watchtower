"""Shared pieces of the PagerDuty scripts: the design, the secrets and the HTTP client. Standard library only.

The design (docs/PAGERDUTY.md) is the constants below. pd_setup.py makes PagerDuty match it, tf_with_keys.py hands
the services' integration keys to the tpa-platform Terraform apply that makes each project's `pagerduty` notification
channel, and pd_test_event.py sends one Monitoring-shaped test event through a service's integration. Each service
has two integrations, and ROUTE below says which one's key those two scripts use.

Secrets. The PagerDuty REST API key comes from PAGERDUTY_TOKEN, or else from the macOS login keychain (generic password,
service "tpa-pagerduty-api"). It and every integration key the scripts handle are registered with `secret()`, and
everything the scripts print goes through `scrub()`, which replaces each of them. Nothing is written to a file, and no
secret is ever put on a command line.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ---- the design ------------------------------------------------------------------------------------------------------

TEAM = "TPA Platform"
TEAM_DESCRIPTION = (
    "Runs the TPA platform: the portal and its API, member records and the call centre. "
    "Managed as code by trellis-watchtower scripts/pagerduty/pd_setup.py (docs/PAGERDUTY.md)."
)
# Each person by their PagerDuty name, and their role on the team. PagerDuty gives an account owner or admin the team
# role "manager" only ("admin cannot take team role responder", 2026-10-11), and both are admins today.
TEAM_MEMBERS = {"Jonathan Bushnell": "manager", "Rafeale Hill": "manager"}

SCHEDULE = "TPA primary on-call"
SCHEDULE_DESCRIPTION = (
    "Who is paged first for the TPA platform. One weekly layer, handed off on Monday at 09:00 Chicago time. "
    "Managed by trellis-watchtower scripts/pagerduty/pd_setup.py: change ROTATION there to change who is on call."
)
TIME_ZONE = "America/Chicago"
LAYER_NAME = "Weekly"
# The layer's people, in turn order. One person is always on call; a second name here makes it a weekly rotation.
ROTATION = ["Jonathan Bushnell"]
WEEK_SECONDS = 7 * 24 * 3600
# A Monday at 09:00 in Chicago: every hand-off falls on a Monday at 09:00.
ROTATION_VIRTUAL_START = "2026-10-05T09:00:00-05:00"
LAYER_START = "2026-10-11T00:00:00-05:00"

POLICY = "TPA Platform"
POLICY_DESCRIPTION = (
    "Level 1: whoever is on call on the TPA primary on-call schedule. Level 2 after 15 minutes without an "
    "acknowledgement. The whole policy repeats twice. Managed by trellis-watchtower scripts/pagerduty/pd_setup.py."
)
LEVEL_DELAY_MINUTES = 15
SECOND_LEVEL = "Rafeale Hill"
POLICY_LOOPS = 2

ACK_TIMEOUT_SECONDS = 30 * 60

# PagerDuty's AIOps add-on. The owner, 2026-11-12, of the account made after PagerDuty deleted the first one: "We are
# not using AIops". Off, the design leaves out the two things only the add-on runs: the incident titles (a second rule
# set, variables and extractions: Advanced Event Orchestration) and alert grouping. pd_setup.py then makes each
# service's orchestration the severity rules alone and never reads or writes a grouping setting. The titles then come
# from the second integration instead ("The titled integration", below). The variable is for the tests, which keep
# the add-on's design covered.
AIOPS = os.environ.get("TW_PAGERDUTY_AIOPS", "").strip() == "1"
TIME_GROUPING_MINUTES = 10

VENDOR_ID = "PUCLE3C"  # PagerDuty's "Google Cloud Monitoring" vendor (generic_service_type "api": the Events API v1)
INTEGRATION_TYPE = "generic_events_api_inbound_integration"
INTEGRATION_NAME = "Google Cloud Monitoring"

# The titled integration (docs/PAGERDUTY.md, "Incident titles"). Each service has a second integration, PagerDuty's
# Custom Event Transformer: a small piece of JavaScript that PagerDuty runs on every request posted to the
# integration's own address. Its code is scripts/pagerduty/monitoring_transform.js, with WATCHTOWER_URL put in, and it
# gives each incident its short title ("The incident's title", below, rules 1 to 3), a few plainly named details and
# its links to the watchtower. It needs no add-on. pd_setup.py creates it, stores the code and corrects the stored
# code whenever it differs from the file. The integration above stays as it is: it is the way back.
TRANSFORMER_VENDOR_ID = "PCJ0EFQ"  # PagerDuty's "Custom Event Transformer" vendor
TRANSFORMER_TYPE = "event_transformer_api_inbound_integration"
TRANSFORMER_NAME = "Google Cloud Monitoring (titled)"
TRANSFORM_FILE = Path(__file__).resolve().with_name("monitoring_transform.js")
# The production watchtower (Grafana, behind Google sign-in). Every incident links to its best-matching page and to
# the overview, at <this>/d/<dashboard uid>; the pages and the matching are in monitoring_transform.js.
WATCHTOWER_URL = "https://watch.trellistpa.com"
WATCHTOWER_PLACEHOLDER = "__WATCHTOWER_URL__"

# Which integration's key Monitoring is given (tf_with_keys.py) and the test event goes through (pd_test_event.py):
#   "transformer"  the titled integration. The design without the AIOps add-on, which is how the account runs;
#   "monitoring"   the plain "Google Cloud Monitoring" integration: Monitoring's own long title. The way back, and
#                  the design with the add-on, whose orchestration writes the titles itself.
# TW_PAGERDUTY_ROUTE=monitoring|transformer overrides it for one run: the rollback, and the tests.
ROUTES = ("monitoring", "transformer")
ROUTE = "monitoring" if AIOPS else "transformer"
ROUTE_VARIABLE = "TW_PAGERDUTY_ROUTE"

# One service per Google Cloud project. `role` is that project's key in tpa-platform's `pagerduty_service_keys`.
SERVICES = [
    {
        "role": "app",
        "name": "TPA · Portal & API",
        "description": (
            "The beta app project: the web edge and portal, tpa-api, sign-in (auth) and tpa-jobs. Paged by Cloud "
            "Monitoring alert policies in that project (tpa-platform infra/modules/monitoring). Each alert carries "
            "its runbook; the signal catalogue is trellis-watchtower docs/SIGNALS.md. Alerts never carry PHI."
        ),
    },
    {
        "role": "phi",
        "name": "TPA · Member records",
        "description": (
            "The beta PHI project: records (the Records Gateway), connectors and tpa-db, inside the perimeter. Paged "
            "by Cloud Monitoring alert policies in that project. Alerts carry metric labels from a closed allowlist "
            "and never PHI. The signal catalogue is trellis-watchtower docs/SIGNALS.md."
        ),
    },
    {
        "role": "cc",
        "name": "TPA · Call centre",
        "description": (
            "The beta call-centre project: the phone line (svc-voice). Paged by Cloud Monitoring alert policies in "
            "that project. Alerts never carry PHI. The signal catalogue is trellis-watchtower docs/SIGNALS.md."
        ),
    },
]

# Slack is reached through PagerDuty: each service is connected to this channel (docs/PAGERDUTY.md, "Slack"), the one
# PagerDuty made in the workspace for the new account (2026-11-12; the first account's was #tpa-beta-alerts).
# pd_setup.py only reads the connections and reports them; it never makes one.
# The events are what a connection must carry to post an incident and close it in the channel: the shape PagerDuty's
# own Slack screen makes (kind "stakeholder", no priority filter). 2026-11-12: three connections made through the API
# as kind "responder" with every event were accepted, listed as healthy and posted nothing, so that kind is a gap.
SLACK_CHANNEL = "obatpa-incidents"
SLACK_EVENTS = ["incident.triggered", "incident.resolved"]
SLACK_SILENT_KINDS = ("responder",)

BUSINESS_SERVICE = "Trellis TPA"
BUSINESS_DESCRIPTION = (
    "The TPA as its users see it: the portal, member records and the call centre. Its status is the status "
    "of the three TPA services that support it."
)
BUSINESS_POINT_OF_CONTACT = "The TPA Platform team in PagerDuty"

# Monitoring's policy severity, as it arrives in the event (custom_details.incident.severity), becomes the alert's
# severity and the incident's priority. Anything else ("No severity", a hand-made policy) keeps PagerDuty's default
# severity, critical, on purpose: it still pages at high urgency.
#
# The match ignores case and surrounding spaces. Google's guide never states the casing (its payload example writes
# "no severity" in lower case), and a WARNING read as unmatched would page at high urgency. RE2's (?i) flag; the word
# is written capitalised so that a lower-case test event proves the flag works (docs/PAGERDUTY.md, "Verified").
# [[:space:]], not \s: PagerDuty's condition language refuses a backslash inside a quoted string (HTTP 400,
# 2026-10-11) and accepts the POSIX class. In RE2, $ is the end of the text (never before a final newline), so the
# class is what lets a trailing tab or newline still match.
SEVERITY_FIELD = "event.custom_details.incident.severity"
SEVERITY_RULES = [
    {"monitoring": "Critical", "severity": "critical", "priority": "P1"},
    {"monitoring": "Error", "severity": "error", "priority": "P2"},
    {"monitoring": "Warning", "severity": "warning", "priority": "P3"},
]


def rule_expression(monitoring_severity: str) -> str:
    return f"{SEVERITY_FIELD} matches regex '(?i)^[[:space:]]*{monitoring_severity}[[:space:]]*$'"


def rule_label(rule: dict) -> str:
    return f"Monitoring {rule['monitoring']}: severity {rule['severity']}, {rule['priority']}"


# Severity-based urgency (dynamic notifications): critical and error page at high urgency, warning and info at low.
EXPECTED_URGENCY = {"critical": "high", "error": "high", "warning": "low", "info": "low"}

# The incident's title (docs/PAGERDUTY.md, "Incident titles"). Without the AIOps add-on the titled integration's
# code writes it (monitoring_transform.js: rules 1 to 3 below, and its own details); what follows is how the
# orchestration writes the same title with the add-on. Monitoring titles each event with its generated summary
# ("tpa_jobs_alerts for trellistpa-beta-tpa-app Cloud Run Job labels {…} with metric labels {…} is above the threshold
# of 0.000 with a value of 2.000. | Violation started: … | Policy: … | View incident: <url>"), and PagerDuty and Slack
# show it as the incident's title.
#
# Each service orchestration's "start" set holds the severity rules above, each of which then goes on (route_to) to the
# "titles" set, and a last rule with no conditions that only goes on, so an event with no severity rule is titled too.
# In "titles" the first rule that matches wins:
#   1. the policy's own subject, documentation.subject, without Monitoring's tag. tpa-platform gives every policy a
#      short plain one, "<environment> · <what happened>", such as "beta · engine p95 above 2 s", and Monitoring sends
#      it with a tag in front: "[ALERT - Warning] beta · engine p95 above 2 s" (incidents #32 and #33, 2026-10-13).
#      The rule matches a subject that, after at most one leading "[…] " tag, starts with a word and " · ", and the
#      title is the subject without the tag. A policy without a subject gets Monitoring's own, "[ALERT - Warning]
#      <condition> on <resource>", which has no such shape and is not used;
#   2. else "<policy name> · <condition name>";
#   3. else (an event without them) the title as Monitoring wrote it.
# Every title rule also copies four fields of the same payload to the top of the alert's details, where the PagerDuty
# app and web show each on its own line. Nothing is fetched, and nothing outside the payload is added. No rule touches
# the dedup key, so a resolve event still finds its incident.
#
# Routing to a second set, variables and extractions are Advanced Event Orchestration, a paid add-on. Without it,
# PagerDuty still takes the update, answers with `warnings` and evaluates only "start". The severity rules live in
# "start" for that reason: such an account loses the titles, never the severity. pd_setup.py also reads the warnings,
# puts the previous orchestration back and refuses (exit 1).
#
# PagerDuty's condition language refuses a backslash inside a quoted string, so the tag's "[" is the class [[] and its
# "]" the class []] (a "]" first in a class is literal in RE2), and [^]] is anything but "]". No lookaround: RE2 has
# none. A field is present when it holds a character other than a space.
INCIDENT_FIELD = "event.custom_details.incident"
SUBJECT_FIELD = f"{INCIDENT_FIELD}.documentation.subject"
POLICY_FIELD = f"{INCIDENT_FIELD}.policy_name"
CONDITION_FIELD = f"{INCIDENT_FIELD}.condition_name"
MONITORING_TAG = "(?:[[][^]]*[]] )?"
# Our subject's shape after the tag, and the subject without it (the regex variable takes the capture group).
OUR_SUBJECT = f"^{MONITORING_TAG}[A-Za-z][A-Za-z-]* · "   # the word may be the estate's ("TPA · "), not only an environment's
SUBJECT_WITHOUT_TAG = f"^{MONITORING_TAG}(.+)"
TITLES_SET = "titles"
TITLE_SEPARATOR = " · "
# The first line that is not blank (RE2's . never matches a newline, unless PagerDuty were to compile with the s flag:
# then it takes the rest of the field, which is harmless), and the incident's own Google Cloud console link.
FIRST_LINE = "^[[:space:]]*(.+)"
CONSOLE_LINK = "^https://console[.]cloud[.]google[.]com/[^[:space:]]+"
# (key in the alert's details, the payload field it is copied from, the regex that picks it out)
TITLE_DETAILS = [
    ("what_to_check", f"{INCIDENT_FIELD}.documentation.content", FIRST_LINE),
    ("console", f"{INCIDENT_FIELD}.url", CONSOLE_LINK),
    ("observed", f"{INCIDENT_FIELD}.observed_value", FIRST_LINE),
    ("threshold", f"{INCIDENT_FIELD}.threshold_value", FIRST_LINE),
]


def present(field: str) -> str:
    return f"{field} matches regex '[^[:space:]]'"


SUBJECT_EXPRESSION = f"{SUBJECT_FIELD} matches regex '{OUR_SUBJECT}'"
NAMES_EXPRESSION = f"{present(POLICY_FIELD)} and {present(CONDITION_FIELD)}"

# Each person's notification rules, built only from contact methods they already have: minutes after an incident is
# assigned to them. Phone and SMS are for high urgency only. Rules are created only with --add-rules: a plain --apply
# never creates one, so a rule a person removed (even a method's only rule) stays removed.
NOTIFY = {
    "high": {
        "push_notification_contact_method": 0,
        "sms_contact_method": 0,
        "phone_contact_method": 3,
        "email_contact_method": 0,
        "slack_contact_method": 0,
    },
    "low": {
        "push_notification_contact_method": 0,
        "email_contact_method": 0,
        "slack_contact_method": 0,
    },
}
CONTACT_WORDS = {
    "push_notification_contact_method": "mobile app push",
    "sms_contact_method": "SMS",
    "phone_contact_method": "phone call",
    "email_contact_method": "email",
    "slack_contact_method": "Slack",
}

TITLE_LIMIT = 250
_TAG = re.compile(r"^\[[^\]]*\] ")
_OUR_SUBJECT = re.compile(r"^[A-Za-z][A-Za-z-]* · ")


_OPERATION = re.compile(r"google\.[A-Za-z0-9.]+\.([A-Z][A-Za-z]+)\b")


def transformer_title(incident: dict) -> str:
    """The title monitoring_transform.js gives Monitoring's incident object: the same rules, written again here so
    pd_test_event.py knows what to expect. tests/pagerduty/test_monitoring_transform.py holds the two to each other."""
    def text(value) -> str:
        return "" if value is None else str(value).strip()

    subject = _TAG.sub("", text((incident.get("documentation") or {}).get("subject")), count=1)
    policy, condition = text(incident.get("policy_name")), text(incident.get("condition_name"))
    if _OUR_SUBJECT.match(subject):
        # The environment word is dropped and a Google operation name becomes its last part in words (the .js file).
        title = _OPERATION.sub(lambda m: re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", m.group(1)).lower(),
                               _OUR_SUBJECT.sub("", subject, count=1))
        title = title[:1].upper() + title[1:]
    elif policy and condition:
        title = policy + TITLE_SEPARATOR + condition
    else:
        title = text(incident.get("summary")) or "Cloud Monitoring alert"
    return title if len(title) <= TITLE_LIMIT else title[:TITLE_LIMIT - 3] + "..."


def normalise_code(code: str | None) -> str:
    """Code as compared: line endings made the same, and no space at the end of a line or blank line at either end
    (PagerDuty may store either differently from what it was sent)."""
    lines = (code or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip()


def transformer_code() -> str:
    """The code the titled integration must hold: the file's text with the watchtower's address put in."""
    code = TRANSFORM_FILE.read_text(encoding="utf-8")
    if code.count(WATCHTOWER_PLACEHOLDER) != 1:
        raise Refused(f"{TRANSFORM_FILE.name} must hold {WATCHTOWER_PLACEHOLDER} exactly once")
    return normalise_code(code.replace(WATCHTOWER_PLACEHOLDER, WATCHTOWER_URL.rstrip("/")))


def stored_code(integration: dict) -> str:
    """The code PagerDuty holds for a transformer integration, as read from GET …/integrations/{id}."""
    value = (((integration.get("config") or {}).get("fields") or {}).get("code") or {}).get("value")
    return normalise_code(value if isinstance(value, str) else "")


def integration_name(integration: dict) -> str:
    """An integration's name, as a full object gives it (`name`) or a reference to one does (`summary`)."""
    return integration.get("name") or integration.get("summary") or ""


def is_transformer(integration: dict) -> bool:
    """The titled integration: found by its exact name, and of the transformer's type or vendor."""
    return (integration_name(integration) == TRANSFORMER_NAME
            and ((integration.get("type") or "").startswith(TRANSFORMER_TYPE)
                 or (integration.get("vendor") or {}).get("id") == TRANSFORMER_VENDOR_ID))


def route() -> str:
    """The route in force: TW_PAGERDUTY_ROUTE when set, else ROUTE."""
    chosen = os.environ.get(ROUTE_VARIABLE, "").strip() or ROUTE
    if chosen not in ROUTES:
        raise Refused(f"{ROUTE_VARIABLE} is {chosen!r}: it may only be {' or '.join(ROUTES)}")
    return chosen


def route_integration(chosen: str) -> str:
    """The name of the integration a route goes through."""
    return TRANSFORMER_NAME if chosen == "transformer" else INTEGRATION_NAME


# ---- printing, with every secret scrubbed ----------------------------------------------------------------------------

_SECRETS: set[str] = set()
SECRET_FIELDS = {"integration_key", "routing_key", "service_key", "token", "access_token"}


def secret(value: str) -> str:
    """Register a secret so that scrub() removes it from anything printed."""
    if value and len(value) >= 6:
        _SECRETS.add(value)
    return value


def scrub(text: str) -> str:
    for value in sorted(_SECRETS, key=len, reverse=True):
        text = text.replace(value, "<redacted>")
    return text


def out(*parts) -> None:
    print(scrub(" ".join(str(p) for p in parts)), flush=True)


def err(*parts) -> None:
    print(scrub(" ".join(str(p) for p in parts)), file=sys.stderr, flush=True)


class Refused(Exception):
    """A stop with a message for the person running the script (exit 2)."""


def register_secrets(value) -> None:
    """Walk a decoded API response and register every secret-shaped field's value."""
    if isinstance(value, dict):
        for k, v in value.items():
            if k in SECRET_FIELDS and isinstance(v, str):
                secret(v)
            else:
                register_secrets(v)
    elif isinstance(value, list):
        for v in value:
            register_secrets(v)


# ---- where requests may go -------------------------------------------------------------------------------------------


def base_url(env_name: str, default: str) -> str:
    """The API base URL: the real one, or (for the tests' fake servers) a loopback address only.

    An override can only point at this machine, so no environment variable can send a key to another host.
    """
    value = os.environ.get(env_name, "").strip().rstrip("/")
    if not value:
        return default
    parsed = urllib.parse.urlsplit(value)
    host = parsed.hostname or ""
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if value == default or (parsed.scheme in ("http", "https") and loopback):
        return value
    raise Refused(f"{env_name} may only be {default} or a loopback address (it is for tests)")


# ---- HTTP ------------------------------------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: urllib would send the Authorization header on to wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def child_env() -> dict:
    """The environment for a child process (security, terraform): never the PagerDuty key."""
    return {k: v for k, v in os.environ.items() if k != "PAGERDUTY_TOKEN"}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message


def http_json(method: str, url: str, headers: dict, body=None, timeout: float = 30):
    """One JSON request. Retries a 429 up to three times. Returns the decoded body (None when empty)."""
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(4):
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
            if e.code == 429 and attempt < 3:
                time.sleep(min(int(e.headers.get("Retry-After") or 2), 30))
                continue
            text = raw.decode(errors="replace")
            try:
                decoded = json.loads(text)
                register_secrets(decoded)
                text = json.dumps(decoded.get("error", decoded))
            except (ValueError, AttributeError):
                pass
            raise ApiError(e.code, scrub(text)[:600]) from None
        except urllib.error.URLError as e:
            raise ApiError(0, scrub(str(e.reason))) from None
        if not raw.strip():
            return None
        decoded = json.loads(raw)
        register_secrets(decoded)
        return decoded
    raise ApiError(429, "rate limited")


# ---- PagerDuty -------------------------------------------------------------------------------------------------------

KEYCHAIN_SERVICE = "tpa-pagerduty-api"
PAGERDUTY_API = "https://api.pagerduty.com"
PAGERDUTY_EVENTS = "https://events.pagerduty.com"
# The Slack integration's connections are read on app.pagerduty.com (the same path on api.pagerduty.com answers 401
# to an account key), while its workspace list answers on api.pagerduty.com only. Both checked live 2026-10-11.
PAGERDUTY_SLACK_API = "https://app.pagerduty.com/integration-slack"


def pagerduty_token() -> str:
    """PAGERDUTY_TOKEN, or else the login keychain's "tpa-pagerduty-api" item. Never printed."""
    token = os.environ.get("PAGERDUTY_TOKEN", "").strip()
    if not token:
        try:
            found = subprocess.run(
                ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
                capture_output=True, text=True, timeout=30, env=child_env(),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            found = None
        if found is None or found.returncode != 0 or not found.stdout.strip():
            raise Refused(
                "no PagerDuty API key: set PAGERDUTY_TOKEN, or add it to the login keychain as a generic password "
                f'with service "{KEYCHAIN_SERVICE}" '
                f"(security add-generic-password -s {KEYCHAIN_SERVICE} -a pagerduty -w)"
            )
        token = found.stdout.strip()
    return secret(token)


class PagerDuty:
    """The REST API. Writes raise unless the client was made with writes=True, so a dry run cannot change anything."""

    PAGE = 100

    def __init__(self, token: str, writes: bool = False):
        self.base = base_url("PAGERDUTY_API_URL", PAGERDUTY_API)
        self.slack_base = base_url("PAGERDUTY_SLACK_API_URL", PAGERDUTY_SLACK_API)
        self.writes = writes
        self.headers = {
            "Authorization": f"Token token={token}",
            "Accept": "application/vnd.pagerduty+json;version=2",
            "Content-Type": "application/json",
        }

    def _url(self, path: str, params=None) -> str:
        if "<" in path or ">" in path:
            raise RuntimeError(f"refusing a URL built from a placeholder: {path}")
        url = self.base + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        return url

    def get(self, path: str, params=None):
        return http_json("GET", self._url(path, params), self.headers)

    def list(self, path: str, key: str, params=None) -> list:
        items, offset = [], 0
        while True:
            page = self.get(path, {**(params or {}), "limit": self.PAGE, "offset": offset})
            got = page.get(key) or []
            items.extend(got)
            if not page.get("more") or not got:
                return items
            offset += len(got)

    def list_cursor(self, path: str, key: str) -> list:
        """A listing paged by cursor (`after`), such as /alert_grouping_settings."""
        items, after = [], None
        while True:
            page = self.get(path, {"limit": self.PAGE, **({"after": after} if after else {})})
            items.extend(page.get(key) or [])
            after = page.get("after")
            if not after or not page.get(key):
                return items

    def slack_connections(self) -> list[dict]:
        """Every service-to-Slack-channel connection in every linked Slack workspace (read only)."""
        found = []
        for ws in self.get("/integration-slack/workspaces").get("workspaces") or []:
            offset = 0
            while True:
                url = f"{self.slack_base}/workspaces/{ws['slack_team_id']}/connections?limit=50&offset={offset}"
                page = http_json("GET", url, self.headers) or {}
                got = page.get("slack_connections") or []
                found.extend({**c, "workspace": ws.get("slack_team_name")} for c in got)
                if not page.get("more") or not got:
                    break
                offset += len(got)
        return found

    def write(self, method: str, path: str, body=None):
        if not self.writes:
            raise RuntimeError(f"dry run attempted {method} {path}")
        return http_json(method, self._url(path), self.headers, body)

    def find_by_name(self, path: str, key: str, name: str, params=None):
        """The one object called exactly `name`, or None. Two with the same name is a stop, never a guess."""
        found = [o for o in self.list(path, key, {**(params or {}), "query": name}) if o.get("name") == name]
        if len(found) > 1:
            raise Refused(f'{len(found)} objects named "{name}" at {path}: rename or remove the extra ones first')
        return found[0] if found else None


def service_integration_key(pd: PagerDuty, service_name: str, chosen: str | None = None) -> tuple[dict, str]:
    """The service and the key of the integration the route goes through (registered as a secret, never printed):
    the titled integration's by default, the plain Google Cloud Monitoring integration's under "monitoring". The
    titled integration's key is given out only while PagerDuty holds the file's code for it."""
    chosen = chosen or route()
    name = route_integration(chosen)
    service = pd.find_by_name("/services", "services", service_name, {"include[]": "integrations"})
    if service is None:
        raise Refused(f'no PagerDuty service "{service_name}": run scripts/pagerduty/pd_setup.py --apply first')
    integrations = service.get("integrations") or []
    if chosen == "transformer":
        ours = [i for i in integrations if is_transformer(i)]
    else:
        ours = [i for i in integrations if (i.get("vendor") or {}).get("id") == VENDOR_ID]
    if not ours:
        raise Refused(f'"{service_name}" has no {name} integration: run pd_setup.py --apply first')
    if chosen == "transformer" and len(ours) > 1:
        raise Refused(f'"{service_name}" has {len(ours)} integrations named "{name}": remove the extra ones first')
    full = pd.get(f"/services/{service['id']}/integrations/{ours[0]['id']}")["integration"]
    key = full.get("integration_key") or ""
    if not key:
        raise Refused(f'"{service_name}": PagerDuty returned no integration key')
    secret(key)
    if chosen == "transformer" and stored_code(full) != transformer_code():
        raise Refused(f'"{service_name}": the code PagerDuty holds for "{name}" is not {TRANSFORM_FILE.name}: run '
                      "pd_setup.py --apply first")
    return service, key


def run_main(main) -> None:
    """Run a script's main(), printing any failure scrubbed and without a traceback (which could hold a value)."""
    try:
        sys.exit(main())
    except Refused as e:
        err(f"refused: {e}")
        sys.exit(2)
    except ApiError as e:
        err(f"failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        err("interrupted")
        sys.exit(130)
    except Exception as e:  # noqa: BLE001 - last resort: a class and a scrubbed message, never a traceback
        err(f"failed: {type(e).__name__}: {e}")
        sys.exit(1)
