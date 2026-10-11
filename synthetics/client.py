"""The journeys' HTTP client: urllib, one origin, a small cookie jar, no redirects.

- **One origin per `Session`.** Every request goes to the base URL the session
  was made with; paths only, never a URL from a response.
- **No redirect is followed.** A 3xx comes back as a response, and the journey
  decides what it means (IAP's sign-in page, or a wrong route).
- **IAP.** With a token, every request carries `Proxy-Authorization: Bearer`,
  and `Authorization` is left empty, so nothing behind IAP can read Google's
  token as its own bearer (design §3; Google's programmatic-access page: a valid
  ID token in `Proxy-Authorization` authorises the request, and IAP passes
  `Authorization` on to the application unread). The CRM's own bearer, when a
  journey has one, rides in `Authorization`.
- **Browser-shaped writes.** Every request carries `Sec-Fetch-Site: same-origin`;
  every write carries `Origin` and, when the session has one, auth's CSRF value
  (`__Host-tpa-csrf` into `X-CSRF-Token`, auth's double submit).
- **Timeouts.** Each request has the smaller of its step timeout and what is
  left of the run's deadline: the socket timeout bounds the connect and each
  read, and the body is read against the same step deadline.
- **No proxy from the environment**, ever: `HTTP(S)_PROXY` is ignored.

Nothing here logs. A transport failure becomes a `StepFailure` carrying a code
from result.CODES and nothing else: no URL, no exception text.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Any

USER_AGENT = "trellis-synthetics/1"
#: Enough for a portal's index.html or a JSON answer; the rest is never read.
MAX_BODY = 512 * 1024
CHUNK = 16 * 1024
LOOPBACK = ("localhost", "127.0.0.1", "::1")
#: Google's own responses (IAP's refusals among them) carry this header.
IAP_GENERATED = "x-goog-iap-generated-response"
GOOGLE_SIGN_IN_HOST = "accounts.google.com"
CSRF_COOKIE = "__Host-tpa-csrf"


class StepFailure(Exception):
    """A step failed. Holds a code from result.CODES and the HTTP status, if any."""

    def __init__(self, code: str, status: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Response:
    status: int
    headers: Message
    body: bytes

    def header(self, name: str) -> str:
        return self.headers.get(name, "") or ""

    def json_object(self) -> dict[str, Any]:
        """The body as a JSON object, or a `shape` failure."""
        try:
            value = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise StepFailure("shape", self.status) from None
        if not isinstance(value, dict):
            raise StepFailure("shape", self.status)
        return value

    def iap_generated(self) -> bool:
        return self.header(IAP_GENERATED).strip().lower() == "true"

    def redirects_to_google_sign_in(self) -> bool:
        if not 300 <= self.status < 400:
            return False
        host = urllib.parse.urlsplit(self.header("Location")).hostname or ""
        return host == GOOGLE_SIGN_IN_HOST or host.endswith("." + GOOGLE_SIGN_IN_HOST)


def origin_of(base_url: str) -> str:
    """`scheme://host[:port]` of a base URL that must be an origin and nothing more.

    https always; plain http only to a loopback host (the local stack's tests).
    Raises ValueError, whose message names no part of the URL.
    """
    parts = urllib.parse.urlsplit(base_url)
    host = parts.hostname or ""
    if not host or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("a base URL is an origin: scheme, host and port only")
    if parts.path not in ("", "/"):
        raise ValueError("a base URL has no path")
    if parts.scheme == "https" or (parts.scheme == "http" and host in LOOPBACK):
        return f"{parts.scheme}://{parts.netloc}"
    raise ValueError("a base URL is https (plain http only to a loopback host)")


def is_loopback(base_url: str) -> bool:
    return (urllib.parse.urlsplit(base_url).hostname or "") in LOOPBACK


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None


def opener(ssl_context: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    return urllib.request.build_opener(*handlers)


class Deadline:
    """The run's whole budget; each request takes the smaller of this and its step's."""

    def __init__(self, seconds: float, clock: Any = time.monotonic) -> None:
        self._clock = clock
        self._end = clock() + seconds

    def left(self) -> float:
        return self._end - self._clock()


def _read_body(response: Any, step_end: float) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size < MAX_BODY:
        if time.monotonic() > step_end:
            raise StepFailure("timeout", getattr(response, "status", None))
        chunk = response.read(min(CHUNK, MAX_BODY - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def send(
    open_: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    *,
    timeout: float,
) -> Response:
    """One request; every transport failure mapped to a closed code."""
    if timeout <= 0:
        raise StepFailure("timeout")
    step_end = time.monotonic() + timeout
    try:
        try:
            raw = open_.open(request, timeout=timeout)
        except urllib.error.HTTPError as answered:  # a 3xx, 4xx or 5xx is still an answer
            raw = answered
        with raw:
            status = int(getattr(raw, "status", None) or raw.code)
            body = _read_body(raw, step_end) if getattr(raw, "fp", True) is not None else b""
            return Response(status=status, headers=raw.headers, body=body)
    except StepFailure:
        raise
    except TimeoutError:
        raise StepFailure("timeout") from None
    except ssl.SSLError:
        raise StepFailure("tls") from None
    except urllib.error.URLError as failed:
        reason = failed.reason
        if isinstance(reason, TimeoutError):
            raise StepFailure("timeout") from None
        if isinstance(reason, (ssl.SSLError, ssl.CertificateError)):
            raise StepFailure("tls") from None
        raise StepFailure("connect") from None
    except (http.client.HTTPException, ConnectionError, OSError):
        raise StepFailure("connect") from None


def _default_path(request_path: str) -> str:
    """RFC 6265 §5.1.4: the cookie's path when Set-Cookie names none."""
    if not request_path.startswith("/") or request_path.count("/") == 1:
        return "/"
    return request_path[: request_path.rfind("/")]


class CookieJar:
    """The cookies one origin set, by name and path. Values never leave this object
    except in a `Cookie` header to that same origin (or the CSRF header)."""

    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str], str] = {}

    def take(self, headers: Message, request_path: str) -> None:
        for raw in headers.get_all("Set-Cookie") or []:
            self._take_one(raw, request_path)

    def _take_one(self, raw: str, request_path: str) -> None:
        first, *attributes = raw.split(";")
        if "=" not in first:
            return
        name, value = (part.strip() for part in first.split("=", 1))
        if not name:
            return
        path = _default_path(request_path)
        expired = False
        for attribute in attributes:
            key, _, setting = attribute.strip().partition("=")
            key = key.strip().lower()
            setting = setting.strip()
            if key == "path" and setting.startswith("/"):
                path = setting
            elif key == "max-age":
                with contextlib.suppress(ValueError):
                    expired = int(setting) <= 0
            elif key == "expires" and setting:
                with contextlib.suppress(TypeError, ValueError, IndexError):
                    expired = parsedate_to_datetime(setting).timestamp() <= time.time()
        if expired:
            self._cookies.pop((name, path), None)
        else:
            self._cookies[(name, path)] = value

    def header_for(self, path: str) -> str:
        matched = [
            (name, value)
            for (name, cookie_path), value in self._cookies.items()
            if path == cookie_path
            or path.startswith(cookie_path if cookie_path.endswith("/") else cookie_path + "/")
        ]
        return "; ".join(f"{name}={value}" for name, value in matched)

    def value(self, name: str) -> str:
        for (cookie_name, _path), value in self._cookies.items():
            if cookie_name == name:
                return value
        return ""

    def names(self) -> set[str]:
        return {name for name, _path in self._cookies}


class Session:
    """Requests to one origin, through IAP when there is a token."""

    def __init__(
        self,
        base_url: str,
        *,
        iap_token: str | None,
        ssl_context: ssl.SSLContext | None,
        step_timeout: float,
        deadline: Deadline,
    ) -> None:
        self.origin = origin_of(base_url)
        self._iap_token = iap_token
        self._open = opener(ssl_context)
        self._step_timeout = step_timeout
        self._deadline = deadline
        self.cookies = CookieJar()
        self.last_status: int | None = None

    def _timeout(self) -> float:
        return min(self._step_timeout, self._deadline.left())

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        accept: str = "application/json",
        bearer: str | None = None,
        csrf: bool = False,
    ) -> Response:
        if not path.startswith("/") or path.startswith("//"):
            raise StepFailure("runner")
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": accept,
            "Sec-Fetch-Site": "same-origin",
        }
        if self._iap_token:
            headers["Proxy-Authorization"] = f"Bearer {self._iap_token}"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        cookie_path = urllib.parse.urlsplit(path).path
        cookie = self.cookies.header_for(cookie_path)
        if cookie:
            headers["Cookie"] = cookie
        data = None
        if method != "GET":
            headers["Origin"] = self.origin
            if payload is not None:
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                headers["Content-Type"] = "application/json"
            else:
                data = b""
        if csrf:
            token = self.cookies.value(CSRF_COOKIE)
            if not token:
                raise StepFailure("csrf")
            headers["X-CSRF-Token"] = token
        request = urllib.request.Request(self.origin + path, data=data, headers=headers, method=method)
        response = send(self._open, request, timeout=self._timeout())
        self.last_status = response.status
        self.cookies.take(response.headers, cookie_path)
        return response

    def get(self, path: str, **kwargs: Any) -> Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Response:
        return self.request("POST", path, **kwargs)
