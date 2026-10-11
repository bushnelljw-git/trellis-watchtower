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
  a bearer token); `GET /api/v1/auth/me`; `POST /api/v1/auth/logout`. The CRM
  lane owns its synthetic user and its cheapest list read; until it switches
  the flag on, J3 reports `skipped` / `not_configured` and never fails.

Every journey is read-only past the sign-in: one password and one code per run,
never retried (a TOTP step is accepted once, and a refused one is charged to the
lockout budget); every run that got a session signs out, also when a later step
failed. Nothing here reads more of a response than its status, the cookies
auth sets, and the few fields a sign-in needs; nothing is printed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import ssl
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field

from synthetics import client, iap, totp
from synthetics.client import Response, Session, StepFailure

TRUE = frozenset({"1", "true", "yes", "on"})
DEFAULT_STEP_TIMEOUT_S = 15.0
#: The job's task_timeout is 120 s (design §3, piece 5); the run ends well inside it.
DEFAULT_DEADLINE_S = 100.0
MAX_CREDENTIALS_BYTES = 64 * 1024
METADATA_HOST = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$")

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
CRM_LOGOUT = "/api/v1/auth/logout"


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


def _seconds(env: Mapping[str, str], name: str, default: float, *, most: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise StepFailure("config") from None
    if not 0 < value <= most:
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
        if not audience or not METADATA_HOST.match(metadata_host):
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
        deadline=_seconds(env, "SYNTHETICS_DEADLINE_S", DEFAULT_DEADLINE_S, most=110),
        ca_file=ca_file,
    )


def read_credentials(path: str) -> Credentials:
    """`{"password": ..., "totp_secret": ...}`, the mounted secret's one version.

    Every failure is `config` with no detail: no path, no value, no parse error.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CREDENTIALS_BYTES + 1)
    except OSError:
        raise StepFailure("config") from None
    if len(raw) > MAX_CREDENTIALS_BYTES:
        raise StepFailure("config")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
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
    """What a journey needs from outside: the clock, for the TOTP code."""

    now: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep


def _prepare(
    run: Run, env: Mapping[str, str], *, use_iap: bool
) -> tuple[Config, Credentials, str | None, ssl.SSLContext, client.Deadline]:
    with run.timed("config"):
        config = load_config(env, job=run.job, use_iap=use_iap)
        context = ssl_context(config)
    deadline = client.Deadline(config.deadline)
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


def _auth_sign_out(run: Run, session: Session) -> None:
    with run.timed("logout"):
        response = session.post(AUTH_LOGOUT, csrf=True)
        if response.status == 403 and not response.iap_generated():
            run.last_status = response.status
            raise StepFailure("csrf", response.status)
        run.check(response, ok=(200, 204))


def _quiet_sign_out(session: Session, path: str, **kwargs: object) -> None:
    """After a failure: end the session if possible, and change nothing about the result."""
    with contextlib.suppress(StepFailure):
        session.post(path, **kwargs)  # type: ignore[arg-type]


def _json_read(run: Run, session: Session, step: str, path: str, *, bearer: str | None = None) -> None:
    with run.timed(step):
        run.check(session.get(path, bearer=bearer)).json_object()


# --- the journeys ----------------------------------------------------------------


def staff_sign_in(run: Run, env: Mapping[str, str], *, use_iap: bool, tools: Tools) -> None:
    config, credentials, token, context, deadline = _prepare(run, env, use_iap=use_iap)
    ops = _session(config.base_url, config, token, context, deadline)
    _shell(run, ops, "ops_shell", OPS_SHELL, "/ops/")
    with run.timed("ops_release"):
        run.check(ops.get(OPS_RELEASE)).json_object()
    _auth_sign_in(run, ops, config.email, credentials, tools)
    try:
        _json_read(run, ops, "me", AUTH_ME)
        _json_read(run, ops, "desk_version", DESK_VERSION)
    except StepFailure:
        _quiet_sign_out(ops, AUTH_LOGOUT, csrf=True)
        raise
    _auth_sign_out(run, ops)
    portal = _session(config.portal_base_url, config, token, context, deadline)
    _shell(run, portal, "portal_shell", PORTAL_SHELL, "/tpa/")


def ops_desk(run: Run, env: Mapping[str, str], *, use_iap: bool, tools: Tools) -> None:
    config, credentials, token, context, deadline = _prepare(run, env, use_iap=use_iap)
    ops = _session(config.base_url, config, token, context, deadline)
    _auth_sign_in(run, ops, config.email, credentials, tools)
    try:
        _json_read(run, ops, "live_queue", LIVE_QUEUE)
        _json_read(run, ops, "desk_version_employers", DESK_VERSION_EMPLOYERS)
    except StepFailure:
        _quiet_sign_out(ops, AUTH_LOGOUT, csrf=True)
        raise
    _auth_sign_out(run, ops)


def crm(run: Run, env: Mapping[str, str], *, use_iap: bool, tools: Tools) -> None:
    if not truthy(env, "SYNTHETICS_CRM_ENABLED"):
        raise Skip("not_configured")
    config, credentials, token, context, deadline = _prepare(run, env, use_iap=use_iap)
    crm_host = _session(config.base_url, config, token, context, deadline)
    _shell(run, crm_host, "crm_shell", CRM_SHELL, "/")
    with run.timed("login"):
        answer = run.check(
            crm_host.post(CRM_LOGIN, payload={"email": config.email, "password": credentials.password}),
            sign_in=True,
        ).json_object()
        challenge = answer.get("challenge_id")
        if answer.get("mfa_required") is not True or answer.get("method") != "totp" or not isinstance(challenge, str):
            raise StepFailure("shape", crm_host.last_status)
    code = totp.mint(credentials.totp_secret, now=tools.now, sleep=tools.sleep)
    with run.timed("mfa_verify"):
        verified = run.check(
            crm_host.post(CRM_VERIFY, payload={"challenge_id": challenge, "code": code}),
            sign_in=True,
        ).json_object()
        bearer = verified.get("token")
        if not isinstance(bearer, str) or not bearer:
            raise StepFailure("shape", crm_host.last_status)
    try:
        _json_read(run, crm_host, "me", CRM_ME, bearer=bearer)
    except StepFailure:
        _quiet_sign_out(crm_host, CRM_LOGOUT, bearer=bearer)
        raise
    with run.timed("logout"):
        run.check(crm_host.post(CRM_LOGOUT, bearer=bearer), ok=(200, 204))


JOURNEYS: dict[str, Callable[..., None]] = {
    "staff-sign-in": staff_sign_in,
    "ops-desk": ops_desk,
    "crm": crm,
}
