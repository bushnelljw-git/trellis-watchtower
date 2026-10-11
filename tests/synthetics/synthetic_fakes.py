"""A fake edge for the synthetics tests: Google's metadata server, IAP, auth, tpa-api and the CRM.

An automated gate only: one local HTTP server on 127.0.0.1 holding its state in
memory and recording every request. It models what the runner relies on:

- **The metadata server** answers the identity call with a JWT-shaped token only
  with `Metadata-Flavor: Google`, the expected audience and `format=full`.
- **IAP** (when on) refuses, with `X-Goog-IAP-Generated-Response: true` and a
  401, any request whose `Proxy-Authorization` is not that token's bearer.
- **auth**: `/auth/login` answers a challenge for the right email and password;
  `/auth/mfa/verify` takes the challenge and the TOTP code of the current (or the
  previous) step at the fake's clock, sets the three `__Host-` cookies and, as
  auth does, echoes the session and CSRF values in its body; `/auth/me` needs the
  session cookie; `/auth/logout` needs the session cookie, `X-CSRF-Token` equal to
  the CSRF value, and `Origin` equal to the origin it was sent to.
- **tpa-api**: the desk version and live queue reads need the session cookie.
- **The CRM**: its login answers `mfa_required`, its verify a bearer token, and
  its me and logout need that bearer in `Authorization`.

Every secret here is a sentinel the tests then look for in the runner's output.
`fail` maps a route name to a behaviour: an int status; "hang" (no answer for
`hang_s`); "slow_body" (headers, then nothing); "drop" (close the connection);
"redirect_google"; "redirect_other"; "iap_refuse"; "not_json"; "no_base_href";
"enrol"; "no_cookies".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import threading
import time
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IAP_TOKEN = "eyJzZW50aW5lbC1pYXAi.eyJhdWQiOiJzZW50aW5lbCJ9.c2VudGluZWwtc2ln"
AUDIENCE = "123456789-sentinel.apps.googleusercontent.com"
EMAIL = "synthetic-staff@sentinel-org.test"
PASSWORD = "sentinel-password-5c1e9a7d"
TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
SESSION = "sentinel-session-ref-91b2e0"
CSRF = "sentinel-csrf-4d7e33"
EPOCH = "7"
CHALLENGE = "chl_sentinel_77aa"
CRM_TOKEN = "sentinel-crm-bearer-0a8f12"
SENTINELS = (IAP_TOKEN, AUDIENCE, EMAIL, PASSWORD, TOTP_SECRET, SESSION, CSRF, CHALLENGE, CRM_TOKEN,
             "sentinel")

IDENTITY = "/computeMetadata/v1/instance/service-accounts/default/identity"

ROUTES = {
    ("GET", IDENTITY): "metadata",
    ("GET", "/ops/"): "ops_shell",
    ("GET", "/ops/release.json"): "ops_release",
    ("GET", "/tpa/"): "portal_shell",
    ("POST", "/auth/login"): "login",
    ("POST", "/auth/mfa/verify"): "mfa_verify",
    ("GET", "/auth/me"): "me",
    ("GET", "/tpa/api/v1/desk/cases/version"): "desk_version",
    ("GET", "/tpa/api/v1/live/queue"): "live_queue",
    ("POST", "/auth/logout"): "logout",
    ("GET", "/"): "crm_shell",
    ("POST", "/api/v1/auth/login"): "crm_login",
    ("POST", "/api/v1/auth/mfa/verify"): "crm_mfa_verify",
    ("GET", "/api/v1/auth/me"): "crm_me",
    ("POST", "/api/v1/auth/logout"): "crm_logout",
}


def totp_code(secret: str, step: int) -> str:
    """An independent RFC 6238 (SHA-1, six digits), so the runner's is not checked against itself."""
    import base64

    key = base64.b32decode(secret)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


class Fake:
    def __init__(self, *, iap: bool = True, fail: dict[str, object] | None = None,
                 clock: Callable[[], float] = time.time, hang_s: float = 2.0) -> None:
        self.iap = iap
        self.fail = dict(fail or {})
        self.clock = clock
        self.hang_s = hang_s
        self.requests: list[dict] = []
        self.codes_received: list[str] = []
        self.lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence the server
                return

            def do_GET(self):
                fake.handle(self, "GET")

            def do_POST(self):
                fake.handle(self, "POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        # A handler still sleeping ("hang") when its client has gone fails to write; socketserver
        # would print that to whatever sys.stderr is by then, which may be a later test's capture.
        self.server.handle_error = lambda request, client_address: None
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    # -- lifecycle --

    def __enter__(self) -> Fake:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def portal_base(self) -> str:
        return f"http://localhost:{self.port}"

    @property
    def metadata_host(self) -> str:
        return f"127.0.0.1:{self.port}"

    def routes(self) -> list[str]:
        return [r["route"] for r in self.requests]

    # -- answering --

    def reply(self, h: BaseHTTPRequestHandler, status: int, body: bytes = b"", *,
              content_type: str = "application/json", headers: dict | None = None,
              cookies: list[str] | None = None) -> None:
        h.send_response(status)
        h.send_header("Content-Type", content_type)
        h.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            h.send_header(name, value)
        for cookie in cookies or []:
            h.send_header("Set-Cookie", cookie)
        h.end_headers()
        if body:
            h.wfile.write(body)

    def json(self, h, status: int, value: object, **kwargs) -> None:
        self.reply(h, status, json.dumps(value).encode(), **kwargs)

    def cookies(self, h) -> dict[str, str]:
        jar = {}
        for part in (h.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                name, value = part.strip().split("=", 1)
                jar[name] = value
        return jar

    def handle(self, h: BaseHTTPRequestHandler, method: str) -> None:
        parts = urllib.parse.urlsplit(h.path)
        query = urllib.parse.parse_qs(parts.query)
        route = ROUTES.get((method, parts.path), "unknown")
        if route == "desk_version" and query.get("scope") == ["employers"]:
            route = "desk_version_employers"
        length = int(h.headers.get("Content-Length") or 0)
        body = h.rfile.read(length) if length else b""
        record = {
            "route": route,
            "method": method,
            "host": h.headers.get("Host"),
            "proxy_authorization": h.headers.get("Proxy-Authorization"),
            "authorization": h.headers.get("Authorization"),
            "origin": h.headers.get("Origin"),
            "sec_fetch_site": h.headers.get("Sec-Fetch-Site"),
            "csrf": h.headers.get("X-CSRF-Token"),
            "cookie": h.headers.get("Cookie"),
            "metadata_flavor": h.headers.get("Metadata-Flavor"),
            "query": query,
        }
        with self.lock:
            self.requests.append(record)

        behaviour = self.fail.get(route)
        if behaviour == "drop":
            h.close_connection = True
            h.connection.shutdown(2)
            return
        if behaviour == "hang":
            time.sleep(self.hang_s)
            self.json(h, 200, {})
            return
        if behaviour == "slow_body":
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", "100")
            h.end_headers()
            h.wfile.write(b"{")
            h.wfile.flush()
            time.sleep(self.hang_s)
            return

        if route == "metadata":
            ok = (
                record["metadata_flavor"] == "Google"
                and query.get("audience") == [AUDIENCE]
                and query.get("format") == ["full"]
            )
            if isinstance(behaviour, int):
                self.reply(h, behaviour, b"metadata refused", content_type="text/plain")
            elif not ok:
                self.reply(h, 403, b"bad metadata request", content_type="text/plain")
            else:
                self.reply(h, 200, IAP_TOKEN.encode(), content_type="application/text")
            return

        # IAP, in front of everything else.
        if self.iap and (record["proxy_authorization"] != f"Bearer {IAP_TOKEN}" or behaviour == "iap_refuse"):
            self.reply(h, 401, b"Invalid IAP credentials", content_type="text/html",
                       headers={"X-Goog-IAP-Generated-Response": "true"})
            return
        if behaviour == "redirect_google":
            self.reply(h, 302, headers={"Location": f"https://accounts.google.com/o/oauth2/v2/auth?client_id={AUDIENCE}"})
            return
        if behaviour == "redirect_other":
            self.reply(h, 302, headers={"Location": f"{self.base}/elsewhere?session={SESSION}"})
            return
        if isinstance(behaviour, int):
            self.json(h, behaviour, {"error": {"code": "sentinel_refusal", "echo": SESSION, "password": PASSWORD}})
            return

        getattr(self, f"_{route}", self._unknown)(h, record, body, behaviour)

    # -- the routes --

    def _unknown(self, h, record, body, behaviour) -> None:
        self.json(h, 404, {"error": {"code": "not_found"}})

    def _shell(self, h, base_href: str, behaviour) -> None:
        if behaviour == "no_base_href":
            page = b"<html><title>Sign in - Google Accounts</title></html>"
        else:
            page = f'<!doctype html><html><head><base href="{base_href}"></head><body>{SESSION}</body></html>'.encode()
        self.reply(h, 200, page, content_type="text/html")

    def _ops_shell(self, h, record, body, behaviour) -> None:
        self._shell(h, "/ops/", behaviour)

    def _portal_shell(self, h, record, body, behaviour) -> None:
        self._shell(h, "/tpa/", behaviour)

    def _crm_shell(self, h, record, body, behaviour) -> None:
        self._shell(h, "/", behaviour)

    def _ops_release(self, h, record, body, behaviour) -> None:
        if behaviour == "not_json":
            self.reply(h, 200, b"<html>not json</html>", content_type="text/html")
        else:
            self.json(h, 200, {"configuration": "production", "release": "sentinel-release"})

    def _credentials_ok(self, body: bytes) -> bool:
        try:
            sent = json.loads(body)
        except ValueError:
            return False
        return sent == {"email": EMAIL, "password": PASSWORD}

    def _login(self, h, record, body, behaviour) -> None:
        if not self._credentials_ok(body):
            self.json(h, 401, {"error": {"code": "invalid_credentials"}})
        elif behaviour == "enrol":
            self.json(h, 200, {"challenge_id": CHALLENGE, "methods": [], "enrolment_required": True,
                               "enrol_methods": ["totp"]})
        else:
            self.json(h, 200, {"challenge_id": CHALLENGE, "methods": ["totp"]})

    def _code_ok(self, body: bytes) -> bool:
        try:
            sent = json.loads(body)
        except ValueError:
            return False
        code = sent.get("code", "")
        self.codes_received.append(code)
        step = int(self.clock() // 30)
        return sent.get("challenge_id") == CHALLENGE and code in (
            totp_code(TOTP_SECRET, step), totp_code(TOTP_SECRET, step - 1))

    def _mfa_verify(self, h, record, body, behaviour) -> None:
        if not self._code_ok(body):
            self.json(h, 401, {"error": {"code": "token_invalid"}})
            return
        cookies = [] if behaviour == "no_cookies" else [
            f"__Host-tpa-session={SESSION}; Path=/; HttpOnly; Secure; SameSite=Lax",
            f"__Host-tpa-csrf={CSRF}; Path=/; Secure; SameSite=Lax",
            f"__Host-tpa-epoch={EPOCH}; Path=/; HttpOnly; Secure; SameSite=Lax",
        ]
        self.json(h, 200, {"session": SESSION, "csrf": CSRF, "tenants": [], "current_tid": "sentinel-tid"},
                  cookies=cookies)

    def _signed_in(self, h) -> bool:
        if self.cookies(h).get("__Host-tpa-session") != SESSION:
            self.json(h, 401, {"error": {"code": "token_invalid"}})
            return False
        return True

    def _me(self, h, record, body, behaviour) -> None:
        if self._signed_in(h):
            self.json(h, 200, {"sub": "prn_sentinel", "email": EMAIL})

    def _desk_version(self, h, record, body, behaviour) -> None:
        if self._signed_in(h):
            self.json(h, 200, {"version": "sentinel-v", "counts": {"open": 3}})

    _desk_version_employers = _desk_version

    def _live_queue(self, h, record, body, behaviour) -> None:
        if self._signed_in(h):
            self.json(h, 200, {"calls": [], "server_now": "sentinel"})

    def _logout(self, h, record, body, behaviour) -> None:
        if not self._signed_in(h):
            return
        expected_origin = f"http://{record['host']}"
        if record["csrf"] != CSRF or record["origin"] != expected_origin or record["sec_fetch_site"] == "cross-site":
            self.json(h, 403, {"error": {"code": "denied"}})
            return
        cleared = [f"{name}=; Path=/; Max-Age=0; Secure" for name in
                   ("__Host-tpa-session", "__Host-tpa-csrf", "__Host-tpa-epoch")]
        self.reply(h, 204, cookies=cleared)

    def _crm_login(self, h, record, body, behaviour) -> None:
        if not self._credentials_ok(body):
            self.json(h, 401, {"detail": "invalid_credentials"})
        else:
            self.json(h, 200, {"mfa_required": True, "challenge_id": CHALLENGE, "method": "totp"})

    def _crm_mfa_verify(self, h, record, body, behaviour) -> None:
        if not self._code_ok(body):
            self.json(h, 401, {"detail": "mfa_invalid"})
        else:
            self.json(h, 200, {"token": CRM_TOKEN, "user": {"email": EMAIL}})

    def _crm_bearer(self, h, record) -> bool:
        if record["authorization"] != f"Bearer {CRM_TOKEN}":
            self.json(h, 401, {"detail": "not_authenticated"})
            return False
        return True

    def _crm_me(self, h, record, body, behaviour) -> None:
        if self._crm_bearer(h, record):
            self.json(h, 200, {"user": {"email": EMAIL}})

    def _crm_logout(self, h, record, body, behaviour) -> None:
        if self._crm_bearer(h, record):
            self.reply(h, 204)
