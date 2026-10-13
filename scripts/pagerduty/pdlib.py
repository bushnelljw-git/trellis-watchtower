"""Shared pieces of the PagerDuty scripts: the design, the secrets and the HTTP client. Standard library only.

The design (docs/PAGERDUTY.md) is the constants below. pd_setup.py makes PagerDuty match it, tf_with_keys.py hands
the services' integration keys to the tpa-platform Terraform apply that makes each project's `pagerduty` notification
channel, and pd_test_event.py sends one Monitoring-shaped test event through a service's integration.

Secrets. The PagerDuty REST API key comes from PAGERDUTY_TOKEN, or else from the macOS login keychain (generic password,
service "tpa-pagerduty-api"). It and every integration key the scripts handle are registered with `secret()`, and
everything the scripts print goes through `scrub()`, which replaces each of them. Nothing is written to a file, and no
secret is ever put on a command line.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

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
TIME_GROUPING_MINUTES = 10

VENDOR_ID = "PUCLE3C"  # PagerDuty's "Google Cloud Monitoring" vendor (generic_service_type "api": the Events API v1)
INTEGRATION_TYPE = "generic_events_api_inbound_integration"
INTEGRATION_NAME = "Google Cloud Monitoring"

# One service per Google Cloud project. `role` is that project's key in tpa-platform's `pagerduty_service_keys`.
SERVICES = [
    {
        "role": "app",
        "name": "TPA beta · Portal & API",
        "description": (
            "The beta app project: the web edge and portal, tpa-api, sign-in (auth) and tpa-jobs. Paged by Cloud "
            "Monitoring alert policies in that project (tpa-platform infra/modules/monitoring). Each alert carries "
            "its runbook; the signal catalogue is trellis-watchtower docs/SIGNALS.md. Alerts never carry PHI."
        ),
    },
    {
        "role": "phi",
        "name": "TPA beta · Member records",
        "description": (
            "The beta PHI project: records (the Records Gateway), connectors and tpa-db, inside the perimeter. Paged "
            "by Cloud Monitoring alert policies in that project. Alerts carry metric labels from a closed allowlist "
            "and never PHI. The signal catalogue is trellis-watchtower docs/SIGNALS.md."
        ),
    },
    {
        "role": "cc",
        "name": "TPA beta · Call centre",
        "description": (
            "The beta call-centre project: the phone line (svc-voice). Paged by Cloud Monitoring alert policies in "
            "that project. Alerts never carry PHI. The signal catalogue is trellis-watchtower docs/SIGNALS.md."
        ),
    },
]

# Slack is reached through PagerDuty: a person connects each service to this channel (docs/PAGERDUTY.md, "Slack").
# pd_setup.py only reads the connections and reports them; it never makes one.
SLACK_CHANNEL = "tpa-beta-alerts"
SLACK_EVENTS = ["incident.triggered", "incident.acknowledged", "incident.escalated", "incident.resolved",
                "incident.reassigned"]

BUSINESS_SERVICE = "Trellis TPA (beta)"
BUSINESS_DESCRIPTION = (
    "The TPA beta as its users see it: the portal, member records and the call centre. Its status is the status "
    "of the three TPA beta services that support it."
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

# The incident's title (docs/PAGERDUTY.md, "Incident titles"). Monitoring titles each event with its generated summary
# ("tpa_jobs_alerts for trellistpa-beta-tpa-app Cloud Run Job labels {…} with metric labels {…} is above the threshold
# of 0.000 with a value of 2.000. | Violation started: … | Policy: … | View incident: <url>"), and PagerDuty and Slack
# show it as the incident's title. Each service orchestration's "start" set retitles the event, then sends it on to the
# "severity" set (the rules above, unchanged). The first title rule that matches wins:
#   1. the policy's own subject, documentation.subject. tpa-platform gives every policy a short plain one, such as
#      "beta · engine p95 above 2 s". A policy without one gets Monitoring's, "[ALERT - Warning] <condition> on
#      <resource>", which is not used;
#   2. else "<policy name> · <condition name>";
#   3. else (an event without them) the title as Monitoring wrote it.
# Every title rule also copies four fields of the same payload to the top of the alert's details, where the PagerDuty
# app and web show them first. Nothing is fetched, and nothing outside the payload is added. No rule touches the dedup
# key, so a resolve event still finds its incident.
#
# PagerDuty's condition language refuses a backslash inside a quoted string, so the "[" of "[ALERT - " is the class
# [[]. A field is present when it holds a character other than a space.
INCIDENT_FIELD = "event.custom_details.incident"
SUBJECT_FIELD = f"{INCIDENT_FIELD}.documentation.subject"
POLICY_FIELD = f"{INCIDENT_FIELD}.policy_name"
CONDITION_FIELD = f"{INCIDENT_FIELD}.condition_name"
MONITORING_SUBJECT = "^[[]ALERT - "
SEVERITY_SET = "severity"
TITLE_SEPARATOR = " · "
# The first line that is not blank (RE2's . never matches a newline), and the incident's own Google Cloud console link.
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


SUBJECT_EXPRESSION = f"{present(SUBJECT_FIELD)} and not ({SUBJECT_FIELD} matches regex '{MONITORING_SUBJECT}')"
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


def service_integration_key(pd: PagerDuty, service_name: str) -> tuple[dict, str]:
    """The service and its Google Cloud Monitoring integration key (registered as a secret, never printed)."""
    service = pd.find_by_name("/services", "services", service_name, {"include[]": "integrations"})
    if service is None:
        raise Refused(f'no PagerDuty service "{service_name}": run scripts/pagerduty/pd_setup.py --apply first')
    ours = [i for i in service.get("integrations") or [] if (i.get("vendor") or {}).get("id") == VENDOR_ID]
    if not ours:
        raise Refused(f'"{service_name}" has no {INTEGRATION_NAME} integration: run pd_setup.py --apply first')
    full = pd.get(f"/services/{service['id']}/integrations/{ours[0]['id']}")["integration"]
    key = full.get("integration_key") or ""
    if not key:
        raise Refused(f'"{service_name}": PagerDuty returned no integration key')
    return service, secret(key)


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
