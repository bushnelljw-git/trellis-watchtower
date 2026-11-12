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
  its me, tenant and logout need that bearer in `Authorization`; me names one
  business (`CRM_TENANT_ID`) and `/api/v1/tenants/current` needs it in
  `X-Tenant-Id`.
- **Connections**: each one the server accepts is recorded as `request`, or as
  `silent` when it closes before its first byte (the egress warm-up's), which
  never reaches a route.

Every secret here is a sentinel the tests then look for in the runner's output.
`fail` maps a route name to a behaviour: an int status; "hang" (no answer for
`hang_s`); "slow_body" (headers, then nothing); "trickle" (headers, then one
byte every 0.3 s for up to a minute); "deep_json" (the route's normal answer,
cookies included, with a body nested 100,000 deep); "drop" (close the connection);
"redirect_google"; "redirect_other"; "iap_refuse"; "not_json"; "no_base_href";
"enrol"; "no_cookies"; "password_only" (the CRM's login hands back a token with
no second factor); "no_memberships" and "bad_tenant" (the CRM's me names no
business, or one whose id is not a UUID); "two_businesses", "admin", "partner",
"lattice_role" and "no_partner_field" (the login has been widened, or me no
longer says whether it has a book).

**The sign-in robots** (the member and the broker, on the portal with no IAP):

- the portal's shell names its main script (`MAIN_SCRIPT`), `/tpa/release.json`
  names `RELEASE_ID`, and the script answers as JavaScript;
- `/auth/login` with an `audience` signs in one of the two robot accounts (each
  its own address and password) and answers the member a WebAuthn challenge on
  the fake's own relying party (its host) and the broker `totp`;
- `/auth/mfa/verify` checks the member's assertion as auth does, independently
  of the runner (`verify_assertion`: the client data's type, challenge, origin
  and crossOrigin; the rpId hash; UP, UV and the registration's BE; the counter
  rule; the signature against the public key in the registration fixture's
  attestation, read with this file's own CBOR reader), and the broker's code as
  auth does (one step either side, and never a step at or below the last it
  accepted for that account, `totp_last_step`); then sets a session of the
  robot's own and answers its `audience`;
- `/auth/me` for that session answers a hatted session's thirteen keys.

Their behaviours: "checks_off" and "checks_off_code" (auth's switch-off refusal,
as `decision.reason` or as the code), "audience_not_held" (403 at either),
"wrong_rp", "no_options", "bad_challenge", "check_email", "no_factor",
"no_audience" (verify's 200 without it); at me "two_tenants", "extra_role",
"other_role", "crm_tenant", "sso", "staff", "aal1", "must_replace",
"other_hat", "other_pin", "no_tenants"; at the portal "no_main_script",
"two_main_scripts", "bad_release", "no_release", "not_js", "empty".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import threading
import time
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

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
CRM_TENANT_ID = "00000000-0000-4000-8000-5e471e100001"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
#: The member robot's secret and its registration, as auth's job makes them (make the fixture: see the README).
MEMBER_CREDENTIALS = json.loads((FIXTURES / "member-credentials.json").read_text(encoding="utf-8"))
MEMBER_REGISTRATION = json.loads((FIXTURES / "member-registration.json").read_text(encoding="utf-8"))
MEMBER_EMAIL = MEMBER_CREDENTIALS["email"]
MEMBER_PASSWORD = MEMBER_CREDENTIALS["password"]
BROKER_EMAIL = "sr-0b7e5e471e1a4b0c9d8e7f6a5b4c3d2e@robots.sentinel.invalid"
BROKER_PASSWORD = "sentinel-broker-password-4f1d2c"
BROKER_TOTP_SECRET = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BAJZ2W24DTEBXXMZLSEB2GQZJA"
ROBOT_SESSIONS = {"member": "sentinel-session-member-7c1a", "broker": "sentinel-session-broker-2e9d"}
ROBOT_TID = "ten_sentinel_bootstrap"
RELEASE_ID = "5e471e1a0b7e"
MAIN_SCRIPT = "main-SENT1NEL.js"
SENTINELS = (IAP_TOKEN, AUDIENCE, EMAIL, PASSWORD, TOTP_SECRET, SESSION, CSRF, CHALLENGE, CRM_TOKEN,
             MEMBER_EMAIL, MEMBER_PASSWORD, BROKER_EMAIL, BROKER_PASSWORD, BROKER_TOTP_SECRET, RELEASE_ID,
             MAIN_SCRIPT, ROBOT_TID, *ROBOT_SESSIONS.values(),
             *(MEMBER_CREDENTIALS["passkey"]["private_jwk"][part] for part in ("x", "y", "d")),
             MEMBER_CREDENTIALS["passkey"]["credential_id"],
             MEMBER_CREDENTIALS["passkey"]["user_handle"], "sentinel")

IDENTITY = "/computeMetadata/v1/instance/service-accounts/default/identity"

ROUTES = {
    ("GET", IDENTITY): "metadata",
    ("GET", "/ops/"): "ops_shell",
    ("GET", "/ops/release.json"): "ops_release",
    ("GET", "/tpa/"): "portal_shell",
    ("GET", "/tpa/release.json"): "portal_release",
    ("GET", f"/tpa/{MAIN_SCRIPT}"): "portal_bundle",
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
    ("GET", "/api/v1/tenants/current"): "crm_tenant",
    ("POST", "/api/v1/auth/logout"): "crm_logout",
}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def cbor_decode(raw: bytes) -> object:
    """RFC 8949, the few types an attestation object holds (unsigned and negative integers, byte and text
    strings, arrays, maps), definite lengths only: an independent reader, so the fixture is not read by the
    code that made it."""
    def item(at: int) -> tuple[object, int]:
        major, info = raw[at] >> 5, raw[at] & 0x1F
        at += 1
        if info < 24:
            n = info
        else:
            width = {24: 1, 25: 2, 26: 4, 27: 8}[info]
            n = int.from_bytes(raw[at:at + width], "big")
            at += width
        if major == 0:
            return n, at
        if major == 1:
            return -1 - n, at
        if major in (2, 3):
            chunk = raw[at:at + n]
            return (chunk if major == 2 else chunk.decode("utf-8")), at + n
        if major == 4:
            values = []
            for _ in range(n):
                value, at = item(at)
                values.append(value)
            return values, at
        if major == 5:
            mapping = {}
            for _ in range(n):
                key, at = item(at)
                mapping[key], at = item(at)
            return mapping, at
        raise ValueError(f"CBOR major type {major}")

    value, end = item(0)
    if end != len(raw):
        raise ValueError("trailing bytes")
    return value


def registered(registration: dict) -> dict:
    """What auth stores of a registration (its verify_registration, as far as the robot's assertion needs):
    the rpId hash and flags of the registration's authenticator data, its counter, the credential id, and the
    public key from its COSE key."""
    attestation = cbor_decode(unb64url(registration["response"]["attestationObject"]))
    data = attestation["authData"]
    flags = data[32]
    length = int.from_bytes(data[53:55], "big")
    credential_id = data[55:55 + length]
    cose = cbor_decode(data[55 + length:])
    assert attestation["fmt"] == "none" and cose[1] == 2 and cose[3] == -7 and cose[-1] == 1
    public = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"),
                                           ec.SECP256R1()).public_key()
    return {"rp_id_hash": data[:32], "flags": flags, "sign_count": int.from_bytes(data[33:37], "big"),
            "credential_id": credential_id, "public_key": public}


def verify_assertion(assertion: object, *, challenge: bytes, origin: str, rp_id: str, stored: dict,
                     user_handle: bytes) -> str:
    """auth-notary's checks of a passkey assertion (py_webauthn's verify_authentication_response with
    require_user_verification, then flags_agree and counter_is_fresh), written apart from the runner:
    "" when it verifies, else the reason."""
    try:
        if set(assertion) != {"id", "rawId", "type", "response", "authenticatorAttachment",
                              "clientExtensionResults"}:
            return "fields"
        response = assertion["response"]
        if set(response) != {"clientDataJSON", "authenticatorData", "signature", "userHandle"}:
            return "response fields"
        if assertion["type"] != "public-key" or assertion["id"] != assertion["rawId"]:
            return "type or id"
        if unb64url(assertion["rawId"]) != stored["credential_id"]:
            return "credential"
        if unb64url(response["userHandle"]) != user_handle:
            return "user handle"
        client_json = unb64url(response["clientDataJSON"])
        client = json.loads(client_json)
        if client.get("type") != "webauthn.get" or unb64url(client.get("challenge", "")) != challenge:
            return "client data"
        if client.get("origin") != origin or client.get("crossOrigin") not in (None, False):
            return "origin"
        data = unb64url(response["authenticatorData"])
        if len(data) < 37 or data[:32] != hashlib.sha256(rp_id.encode()).digest():
            return "rp"
        flags = data[32]
        if not flags & 0x01 or not flags & 0x04:
            return "user verification"
        if bool(flags & 0x08) is not bool(stored["flags"] & 0x08) or (flags & 0x10 and not flags & 0x08):
            return "backup flags"
        count = int.from_bytes(data[33:37], "big")
        if not (count == 0 and stored["sign_count"] == 0) and count <= stored["sign_count"]:
            return "counter"
        stored["public_key"].verify(unb64url(response["signature"]),
                                    data + hashlib.sha256(client_json).digest(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return "malformed or unsigned"
    return ""


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
        self.connections: list[str] = []
        self.current = ""
        self.codes_received: list[str] = []
        self.assertions_received: list[dict] = []
        self.refusals: list[str] = []
        #: auth's `totp_last_step` per robot account, and the challenge each robot login opened.
        self.last_step: dict[str, int] = {}
        self.robot_challenges: dict[str, dict] = {}
        self.member_key = registered(MEMBER_REGISTRATION["registration"])
        self.lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence the server
                return

            def handle(self):
                try:
                    spoke = bool(self.rfile.peek(1))
                except OSError:
                    spoke = False
                with fake.lock:
                    fake.connections.append("request" if spoke else "silent")
                if spoke:
                    super().handle()

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
        body = json.dumps(value).encode()
        if self.fail.get(self.current) == "deep_json" and status == 200:
            body = b"[" * 100_000 + b"]" * 100_000
        self.reply(h, status, body, **kwargs)

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
            "tenant": h.headers.get("X-Tenant-Id"),
            "cookie": h.headers.get("Cookie"),
            "metadata_flavor": h.headers.get("Metadata-Flavor"),
            "release": h.headers.get("X-Client-Release"),
            "content_type": h.headers.get("Content-Type"),
            "query": query,
            "payload": _json_or_none(body),
        }
        with self.lock:
            self.requests.append(record)
        self.current = route

        behaviour = self.fail.get(route)
        if behaviour == "drop":
            h.close_connection = True
            h.connection.shutdown(2)
            return
        if behaviour == "hang":
            time.sleep(self.hang_s)
            self.json(h, 200, {})
            return
        if behaviour == "trickle":
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", "200")
            h.end_headers()
            try:
                for _ in range(200):
                    h.wfile.write(b" ")
                    h.wfile.flush()
                    time.sleep(0.3)
            except OSError:
                pass  # the client gave up, as it must
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
        scripts = {
            "no_main_script": '<script src="polyfills-SENT1NEL.js" type="module"></script>',
            "two_main_scripts": f'<script src="{MAIN_SCRIPT}" type="module"></script>'
                                '<script src="main-OTHER123.js" type="module"></script>',
        }.get(behaviour, f'<script src="polyfills-SENT1NEL.js" type="module"></script>'
                         f'<script src="{MAIN_SCRIPT}" type="module"></script>')
        if behaviour == "no_base_href":
            page = b"<html><title>Sign in - Google Accounts</title></html>"
        else:
            page = (f'<!doctype html><html><head><base href="/tpa/"><link rel="modulepreload" href="chunk-SENT.js">'
                    f'</head><body><app-root></app-root>{scripts}</body></html>').encode()
        self.reply(h, 200, page, content_type="text/html")

    def _portal_release(self, h, record, body, behaviour) -> None:
        release = {"bad_release": "sentinel\r\nX-Injected: 1", "no_release": None}.get(behaviour, RELEASE_ID)
        if behaviour == "not_json":
            self.reply(h, 200, b"<html>not json</html>", content_type="text/html")
        else:
            self.json(h, 200, {"release": release, "configuration": "production"})

    def _portal_bundle(self, h, record, body, behaviour) -> None:
        if behaviour == "not_js":
            self.reply(h, 200, b"<html>the shell again</html>", content_type="text/html")
        elif behaviour == "empty":
            self.reply(h, 200, b"", content_type="text/javascript; charset=utf-8")
        else:
            self.reply(h, 200, b"import{a as b}from'./chunk-SENT.js';b();",
                       content_type="text/javascript; charset=utf-8")

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

    def _robot_of(self, payload: object) -> str | None:
        """The robot account a sign-in names, by its address and password, or None."""
        if not isinstance(payload, dict) or set(payload) != {"email", "password", "audience"}:
            return None
        accounts = {"member": (MEMBER_EMAIL, MEMBER_PASSWORD), "broker": (BROKER_EMAIL, BROKER_PASSWORD)}
        for hat, (email, password) in accounts.items():
            if (payload["email"], payload["password"]) == (email, password):
                return hat
        return None

    def _refuse(self, h, reason: str, *, as_code: bool = False) -> None:
        self.refusals.append(reason)
        error = ({"code": reason, "detail": "sentinel"} if as_code else
                 {"code": "denied", "detail": "sentinel", "decision": {"outcome": "deny", "reason": reason}})
        self.json(h, 403, {"error": error})

    def _robot_login(self, h, record, behaviour) -> None:
        payload = record["payload"]
        account = self._robot_of(payload)
        if account is None:
            self.json(h, 401, {"error": {"code": "invalid_credentials"}})
            return
        if behaviour == "checks_off":
            self._refuse(h, "sign_in_checks_off")
            return
        if behaviour == "checks_off_code":
            self._refuse(h, "sign_in_checks_off", as_code=True)
            return
        if behaviour == "audience_not_held":
            self._refuse(h, "audience_not_held")
            return
        if behaviour == "check_email":
            self.json(h, 200, {"check_email": True})
            return
        challenge_id = f"chl_sentinel_{account}"
        ceremony = hashlib.sha256(f"sentinel-ceremony-{len(self.robot_challenges)}".encode()).digest()
        self.robot_challenges[challenge_id] = {"account": account, "audience": payload["audience"],
                                               "ceremony": ceremony}
        if account == "broker":
            methods = ["recovery"] if behaviour == "no_factor" else ["totp"]
            self.json(h, 200, {"challenge_id": challenge_id, "methods": methods})
            return
        options = {"challenge": b64url(ceremony), "rpId": self.rp_id(record), "allowCredentials": [],
                   "userVerification": "required", "timeout": 300000}
        if behaviour == "wrong_rp":
            options["rpId"] = "portal.elsewhere.invalid"
        elif behaviour == "bad_challenge":
            options["challenge"] = "not base64url!"
        methods = ["sms"] if behaviour == "no_factor" else ["webauthn"]
        answer = {"challenge_id": challenge_id, "methods": methods, "webauthn": options}
        if behaviour == "no_options":
            del answer["webauthn"]
        self.json(h, 200, answer)

    def rp_id(self, record) -> str:
        return urllib.parse.urlsplit(f"http://{record['host']}").hostname

    def _login(self, h, record, body, behaviour) -> None:
        if isinstance(record["payload"], dict) and "audience" in record["payload"]:
            self._robot_login(h, record, behaviour)
            return
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

    def _robot_verify(self, h, record, behaviour) -> None:
        payload = record["payload"] if isinstance(record["payload"], dict) else {}
        opened = self.robot_challenges.pop(payload.get("challenge_id"), None)
        if opened is None:
            self.json(h, 410, {"error": {"code": "challenge_expired"}})
            return
        account = opened["account"]
        if account == "member":
            if set(payload) != {"challenge_id", "assertion"}:
                self.json(h, 400, {"error": {"code": "invalid_args"}})
                return
            self.assertions_received.append(payload["assertion"])
            why = verify_assertion(payload["assertion"], challenge=opened["ceremony"],
                                   origin=f"http://{record['host']}", rp_id=self.rp_id(record),
                                   stored=self.member_key, user_handle=unb64url(MEMBER_REGISTRATION["user_handle"]))
        else:
            code = payload.get("code", "") if set(payload) == {"challenge_id", "code"} else ""
            self.codes_received.append(code)
            current = int(self.clock() // 30)
            matched = [step for step in (current - 1, current, current + 1)
                       if totp_code(BROKER_TOTP_SECRET, step) == code]
            why = "code" if not matched else ""
            if matched and max(matched) <= self.last_step.get(account, -1):
                why = "replayed"
            if not why:
                self.last_step[account] = max(matched)
        if why:
            self.refusals.append(why)
            self.json(h, 401, {"error": {"code": "invalid_code"}})
            return
        if behaviour in ("checks_off", "audience_not_held"):
            self._refuse(h, "sign_in_checks_off" if behaviour == "checks_off" else behaviour)
            return
        cookies = [] if behaviour == "no_cookies" else [
            f"__Host-tpa-session={ROBOT_SESSIONS[account]}; Path=/; HttpOnly; Secure; SameSite=Lax",
            f"__Host-tpa-csrf={CSRF}; Path=/; Secure; SameSite=Lax",
            f"__Host-tpa-epoch={EPOCH}; Path=/; HttpOnly; Secure; SameSite=Lax",
        ]
        answer = {"csrf": CSRF, "tenants": [{"tid": ROBOT_TID, "tkind": "tpa", "name": "sentinel",
                                             "roles": [account]}],
                  "current_tid": ROBOT_TID, "audience": opened["audience"]}
        if behaviour == "no_audience":
            del answer["audience"]
        self.json(h, 200, answer, cookies=cookies)

    def _mfa_verify(self, h, record, body, behaviour) -> None:
        if isinstance(record["payload"], dict) and record["payload"].get("challenge_id") in self.robot_challenges:
            self._robot_verify(h, record, behaviour)
            return
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
        if self.cookies(h).get("__Host-tpa-session") not in (SESSION, *ROBOT_SESSIONS.values()):
            self.json(h, 401, {"error": {"code": "token_invalid"}})
            return False
        return True

    def _me(self, h, record, body, behaviour) -> None:
        if not self._signed_in(h):
            return
        session = self.cookies(h).get("__Host-tpa-session")
        robot = next((hat for hat, value in ROBOT_SESSIONS.items() if value == session), None)
        if robot is None:
            self.json(h, 200, {"sub": "prn_sentinel", "email": EMAIL})
            return
        tenant = {"tid": ROBOT_TID, "tkind": "tpa", "name": "sentinel", "roles": [robot],
                  "role_labels": {"member": "Member", "broker": "Broker"}}
        me = {"sub": "prn_sentinel", "email": MEMBER_EMAIL if robot == "member" else BROKER_EMAIL,
              "display_name": "Sign-in check", "tenants": [tenant], "current_tid": ROBOT_TID,
              "amr": ["pwd", "webauthn" if robot == "member" else "totp"], "acr": "aal2", "rat": 1, "idle_seconds": 900,
              "absolute_seconds": 120, "epoch": 7, "must_replace": False, "audience": robot}
        if behaviour == "two_tenants":
            me["tenants"] = [tenant, dict(tenant, tid="ten_sentinel_other")]
            me["current_tid"] = None
        elif behaviour == "extra_role":
            tenant["roles"] = [robot, "employer_admin"]
        elif behaviour == "other_role":
            tenant["roles"] = ["employer_admin"]
        elif behaviour == "crm_tenant":
            tenant["tkind"] = "crm"
        elif behaviour == "sso":
            me["sso"] = ["crm"]
        elif behaviour == "staff":
            me["staff"] = {"restriction": "frozen"}
        elif behaviour == "aal1":
            me["acr"] = "aal1"
        elif behaviour == "must_replace":
            me["must_replace"] = True
        elif behaviour == "other_hat":
            me["audience"] = "employer"
        elif behaviour == "other_pin":
            me["current_tid"] = "ten_sentinel_other"
        elif behaviour == "no_tenants":
            me["tenants"] = []
        self.json(h, 200, me)

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
        elif behaviour == "password_only":
            self.json(h, 200, {"mfa_required": False, "challenge_id": None, "method": None,
                               "token": CRM_TOKEN, "user": {"email": EMAIL}})
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
        if not self._crm_bearer(h, record):
            return
        memberships = [{"tenant_id": CRM_TENANT_ID, "tenant_name": "sentinel", "role": "member",
                        "partner_id": None}]
        if behaviour == "no_memberships":
            memberships = []
        elif behaviour == "bad_tenant":
            memberships[0]["tenant_id"] = "sentinel\r\nX-Injected: 1"
        elif behaviour == "two_businesses":
            memberships.append({"tenant_id": "00000000-0000-4000-8000-5e471e100002",
                                "tenant_name": "sentinel", "role": "member", "partner_id": None})
        elif behaviour == "admin":
            memberships[0]["role"] = "admin"
        elif behaviour == "partner":
            memberships[0]["partner_id"] = "00000000-0000-4000-8000-5e471e100003"
        elif behaviour == "lattice_role":
            memberships[0]["roles"] = ["broker"]
        elif behaviour == "no_partner_field":
            del memberships[0]["partner_id"]
        self.json(h, 200, {"user": {"email": EMAIL}, "memberships": memberships})

    def _crm_tenant(self, h, record, body, behaviour) -> None:
        if not self._crm_bearer(h, record):
            return
        if record["tenant"] != CRM_TENANT_ID:
            self.json(h, 400, {"detail": "tenant_required"})
            return
        self.json(h, 200, {"tenant": {"id": CRM_TENANT_ID, "name": "sentinel"}, "role": "member",
                           "partner": None})

    def _crm_logout(self, h, record, body, behaviour) -> None:
        if self._crm_bearer(h, record):
            self.reply(h, 204)


def _json_or_none(body: bytes) -> object:
    try:
        return json.loads(body) if body else None
    except ValueError:
        return None
