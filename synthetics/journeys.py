"""The sign-in journeys (design §3), each a fixed list of steps that stops at the first failure.

- **J1 `staff-sign-in`** (CRITICAL), on the ops host through IAP: `GET /ops/` and
  `/ops/release.json`; `POST /auth/login`; `POST /auth/mfa/verify` with one TOTP
  code; `GET /auth/me`; `GET /tpa/api/v1/desk/cases/version` (counts only,
  uncached, reaches tpa-db); `POST /auth/logout`. Then `GET /tpa/` on the
  portal host through IAP.
- **J2 `ops-desk`** (CRITICAL): sign in as the desk login; `GET
  /tpa/api/v1/live/queue` (a non-touching snapshot through svc-ops); `GET
  /tpa/api/v1/desk/cases/version?scope=employers`; sign out.
- **J3 `crm`** (WARNING), only with `SYNTHETICS_CRM_ENABLED`: the CRM's shell
  through IAP; its own sign-in (`/api/v1/auth/login`, `/api/v1/auth/mfa/verify`,
  a bearer token); `GET /api/v1/auth/me`, which names the one business the
  login belongs to; `GET /api/v1/tenants/current` in that business (the
  portal's boot read: membership, row security and crm-db, read-only);
  `POST /api/v1/auth/logout`. The login is the CRM's own (its
  `app/synthetic_login.py`: `synthetic-crm@synthetic.invalid`, a read-only
  member with no book); until the flag is on, J3 reports `skipped` /
  `not_configured` and never fails.

Each journey starts with the `egress` step, after `config` and before anything
is read or sent: the run's own network path, which Cloud NAT holds shut for a
new task's first 30 s or more, must answer two fresh TCP connections in a row
to every host and port the journey uses before the run's deadline starts
(`_egress`). If it never does, the run is `error` / `egress`, no verdict.

Every journey is read-only past the sign-in: one password and one code per run,
never retried (a TOTP step is accepted once, and a refused one is charged to the
lockout budget). **Every run that got a session signs out**, whatever ends it:
the moment auth's session cookie arrives (or the CRM's bearer is read) the
session counts as signed in, and from then on any exception, a check's failure
or a bug, sends the sign-out before it propagates. The sign-out has its own
budget, `min(step timeout, 10 s)`, outside the run's deadline, so a run that
spent its deadline on a hung step still ends its session. Nothing here reads
more of a response than its status, the cookies auth sets, and the few fields a
sign-in needs; nothing is printed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import ssl
import stat
import time
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from synthetics import client, iap, totp
from synthetics.client import Response, Session, StepFailure

TRUE = frozenset({"1", "true", "yes", "on"})
DEFAULT_STEP_TIMEOUT_S = 15.0
#: The job's task_timeout, 300 s (design §3, piece 5), holds the egress
#: warm-up's budget (at most MOST_EGRESS_WAIT_S), then the run's deadline (at
#: most MOST_DEADLINE_S), then the sign-out's own budget: 220 s with the
#: defaults, 290 s at most.
DEFAULT_DEADLINE_S = 90.0
MOST_DEADLINE_S = 100.0
#: The egress warm-up (`_egress`): its own budget, spent before the deadline
#: starts (0 skips it); each fresh connection's timeout; the pause between
#: rounds; and how many fresh connections in a row make a host and port ready.
DEFAULT_EGRESS_WAIT_S = 120.0
MOST_EGRESS_WAIT_S = 180.0
EGRESS_ATTEMPT_S = 3.0
EGRESS_PAUSE_S = 1.0
EGRESS_READY = 2
#: The sign-out's own budget: the smaller of this and the step timeout, never the deadline's.
SIGN_OUT_BUDGET_S = 10.0
MAX_CREDENTIALS_BYTES = 64 * 1024

SESSION_COOKIE = "__Host-tpa-session"
CSRF_COOKIE = client.CSRF_COOKIE

OPS_SHELL = "/ops/"
OPS_RELEASE = "/ops/release.json"
PORTAL_SHELL = "/tpa/"
AUTH_LOGIN = "/auth/login"
AUTH_VERIFY = "/auth/mfa/verify"
AUTH_ME = "/auth/me"
AUTH_LOGOUT = "/auth/logout"
DESK_VERSION = "/tpa/api/v1/desk/cases/version"
DESK_VERSION_EMPLOYERS = "/tpa/api/v1/desk/cases/version?scope=employers"
LIVE_QUEUE = "/tpa/api/v1/live/queue"
CRM_SHELL = "/"
CRM_LOGIN = "/api/v1/auth/login"
CRM_VERIFY = "/api/v1/auth/mfa/verify"
CRM_ME = "/api/v1/auth/me"
CRM_TENANT = "/api/v1/tenants/current"
CRM_LOGOUT = "/api/v1/auth/logout"
#: A CRM business's id, as `/api/v1/auth/me` names it: the only value J3 ever
#: copies from a response into a request (`X-Tenant-Id`), so it must be a UUID.
TENANT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class Skip(Exception):
    """The run is skipped: `paused` or `not_configured`."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, repr=False)
class Credentials:
    password: str
    totp_secret: str

    def __repr__(self) -> str:
        return "Credentials(<withheld>)"


@dataclass(frozen=True)
class Config:
    base_url: str
    portal_base_url: str
    email: str
    credentials_file: str
    iap_audience: str
    metadata_host: str
    step_timeout: float
    deadline: float
    egress_wait: float
    ca_file: str


@dataclass
class Run:
    """Where a run is, how long each step took, and the last HTTP status it saw."""

    job: str
    step: str = "none"
    last_status: int | None = None
    steps_ms: dict[str, int] = field(default_factory=dict)

    @contextmanager
    def timed(self, name: str) -> Iterator[None]:
        self.step = name
        started = time.monotonic()
        try:
            yield
        finally:
            self.steps_ms[name] = int((time.monotonic() - started) * 1000)

    def check(
        self,
        response: Response,
        ok: tuple[int, ...] = (200,),
        *,
        gate: bool = False,
        sign_in: bool = False,
    ) -> Response:
        """A response is the step's, or the step fails with a closed code.

        `gate`: the first request to a host through IAP, whose own answer is never
        a 401 or 403 (a static shell), so either one there is IAP's refusal.
        `sign_in`: a 401 from auth's sign-in is the credentials (`credentials`).
        """
        self.last_status = response.status
        status = response.status
        if response.iap_generated() or response.redirects_to_google_sign_in():
            raise StepFailure("iap", status)
        if gate and status in (401, 403):
            raise StepFailure("iap", status)
        if status in ok:
            return response
        if 300 <= status < 400:
            raise StepFailure("redirect", status)
        if sign_in and status == 401:
            raise StepFailure("credentials", status)
        if status == 423:
            raise StepFailure("locked", status)
        if status == 429:
            raise StepFailure("rate_limited", status)
        raise StepFailure("status", status)


# --- configuration -------------------------------------------------------------


def truthy(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in TRUE


def _seconds(env: Mapping[str, str], name: str, default: float, *, most: float, zero: bool = False) -> float:
    """Above 0 and at most `most`; or 0 itself when `zero` (the setting's "off")."""
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise StepFailure("config") from None
    if not (0 <= value <= most if zero else 0 < value <= most):
        raise StepFailure("config")
    return value


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise StepFailure("config")
    return value


def _origin(value: str) -> str:
    try:
        return client.origin_of(value)
    except ValueError:
        raise StepFailure("config") from None


def load_config(env: Mapping[str, str], *, job: str, use_iap: bool) -> Config:
    base_url = _origin(_required(env, "SYNTHETICS_BASE_URL"))
    portal = _origin(_required(env, "SYNTHETICS_PORTAL_BASE_URL")) if job == "staff-sign-in" else ""
    email = _required(env, "SYNTHETICS_EMAIL")
    if len(email) > 254 or "@" not in email or any(c.isspace() for c in email):
        raise StepFailure("config")
    credentials_file = _required(env, "SYNTHETICS_CREDENTIALS_FILE")
    audience = env.get("SYNTHETICS_IAP_AUDIENCE", "").strip()
    metadata_host = env.get("SYNTHETICS_METADATA_HOST", "").strip() or iap.METADATA_HOST
    if use_iap:
        if not audience or not metadata_host_allowed(metadata_host):
            raise StepFailure("config")
    elif not all(client.is_loopback(url) for url in (base_url, portal) if url):
        # The local mode (no IAP) reaches this machine's own stack and nothing else.
        raise StepFailure("config")
    ca_file = env.get("SYNTHETICS_CA_FILE", "").strip()
    if ca_file and not os.path.isfile(ca_file):
        raise StepFailure("config")
    return Config(
        base_url=base_url,
        portal_base_url=portal,
        email=email,
        credentials_file=credentials_file,
        iap_audience=audience,
        metadata_host=metadata_host,
        step_timeout=_seconds(env, "SYNTHETICS_STEP_TIMEOUT_S", DEFAULT_STEP_TIMEOUT_S, most=60),
        deadline=_seconds(env, "SYNTHETICS_DEADLINE_S", DEFAULT_DEADLINE_S, most=MOST_DEADLINE_S),
        egress_wait=_seconds(env, "SYNTHETICS_EGRESS_WAIT_S", DEFAULT_EGRESS_WAIT_S, most=MOST_EGRESS_WAIT_S,
                             zero=True),
        ca_file=ca_file,
    )


def metadata_host_allowed(value: str) -> bool:
    """Google's metadata server, or a loopback host (the tests' fake), and nothing else:
    the token is minted there, so it is never asked of another host."""
    if value == iap.METADATA_HOST:
        return True
    try:
        parts = urllib.parse.urlsplit("//" + value)
        _ = parts.port  # a malformed port raises
    except ValueError:
        return False
    return (parts.hostname in client.LOOPBACK and not parts.path and not parts.query and not parts.fragment
            and parts.username is None)


def read_credentials(path: str) -> Credentials:
    """`{"password": ..., "totp_secret": ...}`, the mounted secret's one version.

    A regular file only (checked on the open descriptor, so a FIFO or a device
    never blocks or streams). Every failure is `config` with no detail: no path,
    no value, no parse error.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise StepFailure("config") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise StepFailure("config")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_CREDENTIALS_BYTES + 1)
    except OSError:
        raise StepFailure("config") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_CREDENTIALS_BYTES:
        raise StepFailure("config")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):  # RecursionError: nesting too deep
        raise StepFailure("config") from None
    if not isinstance(value, dict):
        raise StepFailure("config")
    password = value.get("password")
    secret = value.get("totp_secret")
    if not isinstance(password, str) or not password or not isinstance(secret, str):
        raise StepFailure("config")
    try:
        totp.decode_base32(secret)
    except totp.SecretUnusable:
        raise StepFailure("config") from None
    return Credentials(password=password, totp_secret=secret)


def ssl_context(config: Config) -> ssl.SSLContext:
    """The system's trust store, or only the given CA file (the local stack's mkcert root)."""
    try:
        if config.ca_file:
            return ssl.create_default_context(cafile=config.ca_file)
        return ssl.create_default_context()
    except (OSError, ssl.SSLError):
        raise StepFailure("config") from None


# --- the shared steps ------------------------------------------------------------


@dataclass
class Tools:
    """What a journey needs from outside: the clock and a pause, for the TOTP code; a
    steady clock, the pause and a bare TCP connect, for the egress warm-up and the deadline."""

    now: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    connect: Callable[[int, Any, float], None] = client.knock


def _egress(run: Run, config: Config, tools: Tools) -> None:
    """Wait for the run's own network path to the edge, before anything is read or sent.

    Every run is a new Cloud Run task, whose Direct VPC egress goes out through
    Cloud NAT, and for its first 30 to 60 s or more the path drops replies
    (Google: "With Cloud NAT, you might experience cold start delays of 30s or
    more on instance startup", docs.cloud.google.com/run/docs/configuring/vpc-direct-vpc).
    So each host and port the journey uses (the base URL's, and J1's portal's),
    resolved once, gets a fresh TCP connection of at most EGRESS_ATTEMPT_S,
    closed at once with nothing sent, a round every EGRESS_PAUSE_S, until
    EGRESS_READY in a row have connected to every one. Many short connections,
    never one long one: Linux backs a connect's SYN retries off (0, 1, 3, 7, 15,
    31, 63 s), which can leave it waiting 32 s on a path that is already up.

    The budget is the setting's own (0 skips the step); spent, the run is
    `error` / `egress`, as the robot reached nothing and so has no verdict.
    """
    if not config.egress_wait:
        return
    targets = list(dict.fromkeys(
        client.host_port(url) for url in (config.base_url, config.portal_base_url) if url))
    addresses: dict[tuple[str, int], list[tuple[int, Any]]] = {}
    in_a_row = dict.fromkeys(targets, 0)
    with run.timed("egress"):
        end = tools.monotonic() + config.egress_wait
        while True:
            for target in targets:
                if in_a_row[target] < EGRESS_READY:
                    reached = _reach(target, addresses, end, tools)
                    in_a_row[target] = in_a_row[target] + 1 if reached else 0
            if all(count >= EGRESS_READY for count in in_a_row.values()):
                return
            left = end - tools.monotonic()
            if left <= 0:
                raise StepFailure("egress")
            tools.sleep(min(EGRESS_PAUSE_S, left))


def _reach(target: tuple[str, int], addresses: dict[tuple[str, int], list[tuple[int, Any]]], end: float,
           tools: Tools) -> bool:
    """One fresh connection to a host and port: its addresses in order, as the client tries
    them, each for at most EGRESS_ATTEMPT_S and never past `end`. A name that does not
    resolve is a failed attempt, resolved again next round; once resolved, never again."""
    if end - tools.monotonic() <= 0:
        return False
    if target not in addresses:
        try:
            addresses[target] = client.resolve(*target)
        except OSError:
            return False
    for family, address in addresses[target]:
        left = end - tools.monotonic()
        if left <= 0:
            break
        try:
            tools.connect(family, address, min(EGRESS_ATTEMPT_S, left))
        except OSError:
            continue
        return True
    return False


def _prepare(
    run: Run, env: Mapping[str, str], *, use_iap: bool, tools: Tools
) -> tuple[Config, Credentials, str | None, ssl.SSLContext, client.Deadline]:
    with run.timed("config"):
        config = load_config(env, job=run.job, use_iap=use_iap)
        context = ssl_context(config)
    _egress(run, config, tools)
    # The deadline starts once the path is up: the warm-up's time is its own budget's, never the journey's.
    deadline = client.Deadline(config.deadline, clock=tools.monotonic)
    with run.timed("secrets"):
        credentials = read_credentials(config.credentials_file)
    token = None
    if use_iap:
        with run.timed("iap_token"):
            token = iap.fetch_id_token(
                config.iap_audience,
                host=config.metadata_host,
                timeout=min(config.step_timeout, deadline.left()),
            )
    return config, credentials, token, context, deadline


def _session(base_url: str, config: Config, token: str | None, context: ssl.SSLContext,
             deadline: client.Deadline) -> Session:
    return Session(base_url, iap_token=token, ssl_context=context, step_timeout=config.step_timeout,
                   deadline=deadline)


def _shell(run: Run, session: Session, step: str, path: str, base_href: str) -> None:
    """A portal's index.html through IAP: 200, and its own `<base href>`."""
    with run.timed(step):
        response = run.check(session.get(path, accept="text/html"), gate=True)
        if f'<base href="{base_href}"'.encode() not in response.body:
            raise StepFailure("shape", response.status)


def _auth_sign_in(run: Run, session: Session, email: str, credentials: Credentials, tools: Tools) -> None:
    """auth's password step and one TOTP code: a session and its CSRF cookie, or a failure."""
    with run.timed("login"):
        answer = run.check(
            session.post(AUTH_LOGIN, payload={"email": email, "password": credentials.password}),
            sign_in=True,
        ).json_object()
        challenge = answer.get("challenge_id")
        methods = answer.get("methods")
        if (
            not isinstance(challenge, str)
            or not challenge
            or answer.get("enrolment_required")
            or not isinstance(methods, list)
            or "totp" not in methods
        ):
            raise StepFailure("shape", session.last_status)
    code = totp.mint(credentials.totp_secret, now=tools.now, sleep=tools.sleep)
    with run.timed("mfa_verify"):
        run.check(
            session.post(AUTH_VERIFY, payload={"challenge_id": challenge, "code": code}),
            sign_in=True,
        ).json_object()
        if not {SESSION_COOKIE, CSRF_COOKIE} <= session.cookies.names():
            raise StepFailure("shape", session.last_status)


def _sign_out_budget(config: Config) -> float:
    return min(config.step_timeout, SIGN_OUT_BUDGET_S)


def _auth_sign_out(run: Run, session: Session, budget: float) -> None:
    with run.timed("logout"):
        response = session.post(AUTH_LOGOUT, csrf=True, timeout=budget)
        if response.status == 403 and not response.iap_generated():
            run.last_status = response.status
            raise StepFailure("csrf", response.status)
        run.check(response, ok=(200, 204))


def _quiet_sign_out(session: Session, path: str, **kwargs: object) -> None:
    """After anything went wrong: end the session if possible, and change nothing about the result."""
    with contextlib.suppress(Exception):
        session.post(path, **kwargs)  # type: ignore[arg-type]


@contextmanager
def _signed_in_to_auth(run: Run, session: Session, config: Config, credentials: Credentials,
                       tools: Tools) -> Iterator[None]:
    """Signed in to auth for the body, then the `logout` step.

    Signed in means auth's session cookie is in the jar: it is taken there the
    moment `/auth/mfa/verify` answers, before anything reads the body. From then
    on, any exception (in the sign-in's own checks, in the body, or a bug) sends
    the sign-out quietly before it propagates. The `logout` step runs only after
    the body succeeded, and is never repeated.
    """
    budget = _sign_out_budget(config)
    try:
        _auth_sign_in(run, session, config.email, credentials, tools)
        yield
    except BaseException:
        if session.cookies.value(SESSION_COOKIE):
            _quiet_sign_out(session, AUTH_LOGOUT, csrf=True, timeout=budget)
        raise
    _auth_sign_out(run, session, budget)


def _json_read(run: Run, session: Session, step: str, path: str, *, bearer: str | None = None) -> None:
    with run.timed(step):
        run.check(session.get(path, bearer=bearer)).json_object()


# --- the journeys ----------------------------------------------------------------


def staff_sign_in(run: Run, env: Mapping[str, str], *, use_iap: bool, tools: Tools) -> None:
    config, credentials, token, context, deadline = _prepare(run, env, use_iap=use_iap, tools=tools)
    ops = _session(config.base_url, config, token, context, deadline)
    _shell(run, ops, "ops_shell", OPS_SHELL, "/ops/")
    with run.timed("ops_release"):
        run.check(ops.get(OPS_RELEASE)).json_object()
    with _signed_in_to_auth(run, ops, config, credentials, tools):
        _json_read(run, ops, "me", AUTH_ME)
        _json_read(run, ops, "desk_version", DESK_VERSION)
    portal = _session(config.portal_base_url, config, token, context, deadline)
    _shell(run, portal, "portal_shell", PORTAL_SHELL, "/tpa/")


def ops_desk(run: Run, env: Mapping[str, str], *, use_iap: bool, tools: Tools) -> None:
    config, credentials, token, context, deadline = _prepare(run, env, use_iap=use_iap, tools=tools)
    ops = _session(config.base_url, config, token, context, deadline)
    with _signed_in_to_auth(run, ops, config, credentials, tools):
        _json_read(run, ops, "live_queue", LIVE_QUEUE)
        _json_read(run, ops, "desk_version_employers", DESK_VERSION_EMPLOYERS)


def crm(run: Run, env: Mapping[str, str], *, use_iap: bool, tools: Tools) -> None:
    if not truthy(env, "SYNTHETICS_CRM_ENABLED"):
        raise Skip("not_configured")
    config, credentials, token, context, deadline = _prepare(run, env, use_iap=use_iap, tools=tools)
    crm_host = _session(config.base_url, config, token, context, deadline)
    _shell(run, crm_host, "crm_shell", CRM_SHELL, "/")
    with _signed_in_to_crm(run, crm_host, config, credentials, tools) as bearer:
        with run.timed("me"):
            me = run.check(crm_host.get(CRM_ME, bearer=bearer)).json_object()
            tenant = _crm_business(me, crm_host.last_status)
        with run.timed("crm_tenant"):
            run.check(crm_host.get(CRM_TENANT, bearer=bearer, tenant=tenant)).json_object()


def _crm_business(me: dict, status: int | None) -> str:
    """The one business `/api/v1/auth/me` lists, by id, as long as the login is
    still exactly what it was made to be.

    **A tripwire, not only a parser.** The CRM's synthetic login is one active
    `member` of one business with no partner row (its `app/synthetic_login.py`;
    the database refuses anything wider, migration 920261012T1058). Anything
    else - a second business, another role, a partner, a Lattice role - means
    what a leak of its secret could READ has grown, so the run fails (`shape`
    at `me`, WARNING) rather than passing over it. The id must also be a UUID:
    it is the one value J3 copies from a response into a request."""
    memberships = me.get("memberships")
    only = memberships[0] if isinstance(memberships, list) and len(memberships) == 1 else None
    if (
        not isinstance(only, dict)
        or only.get("role") != "member"
        or "partner_id" not in only
        or only.get("partner_id") is not None
        or only.get("roles") not in (None, [])
    ):
        raise StepFailure("shape", status)
    tenant = only.get("tenant_id")
    if not isinstance(tenant, str) or not TENANT_ID.fullmatch(tenant):
        raise StepFailure("shape", status)
    return tenant


@contextmanager
def _signed_in_to_crm(run: Run, session: Session, config: Config, credentials: Credentials,
                      tools: Tools) -> Iterator[str]:
    """Signed in to the CRM (its bearer read from `/api/v1/auth/mfa/verify`) for the body,
    then the `logout` step; any exception once the bearer is held signs out quietly first.

    A bearer handed back by `/api/v1/auth/login` itself (the login answered the password
    alone: it has lost its second factor) is held too, so that failure signs out as well.
    """
    budget = _sign_out_budget(config)
    bearer = ""
    try:
        with run.timed("login"):
            answer = run.check(
                session.post(CRM_LOGIN, payload={"email": config.email, "password": credentials.password}),
                sign_in=True,
            ).json_object()
            challenge = answer.get("challenge_id")
            handed = answer.get("token")
            if isinstance(handed, str) and handed:
                # The password alone minted a session: the login has lost its
                # second factor (an administrator's reset clears it). A fail, and
                # the session it was handed is ended rather than left for 30 days.
                bearer = handed
                raise StepFailure("shape", session.last_status)
            if (answer.get("mfa_required") is not True or answer.get("method") != "totp"
                    or not isinstance(challenge, str)):
                raise StepFailure("shape", session.last_status)
        code = totp.mint(credentials.totp_secret, now=tools.now, sleep=tools.sleep)
        with run.timed("mfa_verify"):
            verified = run.check(
                session.post(CRM_VERIFY, payload={"challenge_id": challenge, "code": code}),
                sign_in=True,
            ).json_object()
            token = verified.get("token")
            if not isinstance(token, str) or not token:
                raise StepFailure("shape", session.last_status)
            bearer = token
        yield bearer
    except BaseException:
        if bearer:
            _quiet_sign_out(session, CRM_LOGOUT, bearer=bearer, timeout=budget)
        raise
    with run.timed("logout"):
        run.check(session.post(CRM_LOGOUT, bearer=bearer, timeout=budget), ok=(200, 204))


JOURNEYS: dict[str, Callable[..., None]] = {
    "staff-sign-in": staff_sign_in,
    "ops-desk": ops_desk,
    "crm": crm,
}
