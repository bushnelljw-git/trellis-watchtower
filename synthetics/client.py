"""The journeys' HTTP client: http.client, one origin, one connection, a small cookie jar, no redirects.

- **One origin per `Session`, and one connection.** Every request goes to the
  base URL the session was made with; paths only, never a URL from a response.
  The session dials its origin once (TCP, then TLS) and every later request of
  the run rides that connection (HTTP/1.1 keep-alive), as a browser's would: a
  run makes one new connection through Cloud NAT where it made one per request
  (`Session._connection`). A connection carries one origin's requests and
  nothing else; J1's second host is a second session.
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
  (`__Host-tpa-csrf` into `X-CSRF-Token`, auth's double submit). Once a journey
  has read the portal's release (the sign-in robots), every request names it in
  `X-Client-Release`, as the portal's own requests do.
- **Timeouts: the dial has its own budget, the answer the step's.** A request
  that needs a new connection dials it for at most CONNECT_BUDGET_S (`dial`,
  below); the step timeout then starts, and bounds TLS's handshake, the write,
  the wait for the headers and the body. The run's deadline bounds the two
  together: a step's dial and answer never pass it. A request with a budget
  of its own (the sign-out's: see journeys.py) spends it on both, outside the
  deadline. `at_most` (a TOTP code's accepted life) caps either, so a code is
  never written after auth would refuse it. The body is read with `read1`,
  one socket read at a time, the socket's timeout shrunk before each to what
  the step has left, so neither a stall nor a server trickling a byte at a
  time can outlast the step.
- **Dialling keeps trying; a request is written once.** Cloud NAT drops some
  new connections' first packets after the egress warm-up (production,
  2026-11-13 to 11-18: about one new connection in seven needed a second
  attempt, and four in a row failing inside a 15 s step paged "Members cannot
  sign in" twice, #161 and #176, while the load balancer saw none of those
  requests). A member on the internet never meets our NAT, so a connect that
  fails is ours, and a late or wrong answer is the site's. The TCP connection
  is tried with a fresh socket, at most CONNECT_ATTEMPT_S each (the name
  resolved, then its addresses in turn, all inside it), CONNECT_PAUSE_S apart,
  until one connects or the dial's budget is spent. Only then is anything
  written. A request is written once, on one connection, whatever happens
  after its first byte: `Session._exchange` calls http.client's `request()`
  once and has no loop around it, http.client never sends a request again,
  and its connection (`_Wire`) cannot open a socket of its own, so nothing
  is dialled in the middle of a request. No sign-in, code or sign-out is
  sent twice. An open connection is used again only while it is known to be
  usable before the request's first byte (`_idle`): the last answer was read
  to its end and did not close it (`Connection: close`, HTTP/1.0, a body that
  ends at the close), and nothing is waiting on it (an EOF, TLS's
  close_notify, bytes nobody asked for). Otherwise the next request dials a
  new one first. Any failure closes the connection, so the request after it
  (the sign-out) starts on a new one. TLS is not retried: its handshake runs
  once on each connected socket.
- **No proxy from the environment**, ever: http.client reads none.
- **The warm-up's connect** (`knock`, journeys.py's `egress` step): a bare TCP
  connection to one resolved address, closed at once. No byte is sent: no
  TLS, no HTTP, no header, no token.
- **The metadata server** (iap.py) is asked through `send` and `opener`,
  urllib with no proxy and no redirect: one request on a fresh connection
  dialled inside its step's time. It is not behind Cloud NAT.

Nothing here logs. A transport failure becomes a `StepFailure` carrying a code
from result.CODES and nothing else: no URL, no exception text.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
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
#: Opening a TCP connection (`dial`): each attempt's longest wait, and the pause before the next.
CONNECT_ATTEMPT_S = 3.0
CONNECT_PAUSE_S = 0.5
#: A session's dial, apart from its step's time: nine attempts (eight that time out, 3.5 s each with the pause, and
#: 2 s for the ninth), where a 15 s step held four and 1 s of a fifth. Inside the run's deadline (80 s in
#: production), which after a dial of up to about 29.5 s and the portal's three reads still holds the broker's
#: 50.2 s. The sign-out's dial shares the sign-out's own 10 s instead.
CONNECT_BUDGET_S = 30.0
#: The most of an answer read past MAX_BODY and thrown away, so its connection can carry the next request.
MAX_DRAIN = 4 * 1024 * 1024
#: The content type urllib gave a write with no JSON body (the sign-outs), kept so nothing a request carries
#: changes with the connection.
EMPTY_BODY_TYPE = "application/x-www-form-urlencoded"


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
        except (UnicodeDecodeError, ValueError, RecursionError):  # RecursionError: nesting too deep
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


def host_port(origin: str) -> tuple[str, int]:
    """The host and port an origin's connections go to."""
    parts = urllib.parse.urlsplit(origin)
    return parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80)


def resolve(host: str, port: int) -> list[tuple[int, Any]]:
    """Each (family, address) a connection to host:port may use, in getaddrinfo's order,
    IPv4 and IPv6 alike, as http.client's own connect tries them. Raises OSError."""
    return [(family, address) for family, _type, _proto, _name, address
            in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)]


def knock(family: int, address: Any, timeout: float) -> None:
    """One fresh TCP connection to one address, closed at once with nothing sent.
    Raises OSError (TimeoutError among them) when it does not connect in `timeout`."""
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(address)


def _open(family: int, address: Any, timeout: float) -> socket.socket:
    """A fresh socket connected to one address inside `timeout`, or OSError (the socket closed)."""
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(address)
    except BaseException:
        sock.close()
        raise
    return sock


def _connect_once(address: tuple[str, int], timeout: float) -> socket.socket:
    """One attempt: the name resolved (getaddrinfo, which no timeout bounds), then its
    addresses in turn as socket.create_connection tries them, but all of them inside
    `timeout` together rather than each with the whole of it. OSError: the last
    address's, or TimeoutError once the attempt's time is spent."""
    end = time.monotonic() + timeout
    failed: OSError = OSError("the name has no address")
    for family, resolved in resolve(*address):
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError
        try:
            return _open(family, resolved, left)
        except OSError as error:
            failed = error
    raise failed


def dial(address: tuple[str, int], timeout: float) -> socket.socket:
    """A TCP connection to host:port inside `timeout` (a session's dial budget, or
    what the metadata call's step has left).

    A fresh socket each attempt, for at most CONNECT_ATTEMPT_S and never past
    `timeout`, CONNECT_PAUSE_S apart, until one connects. When the time is spent the
    last attempt's error stands, so the step fails as it did before: `timeout`
    after attempts that timed out, `connect` after refusals. The socket comes back
    with what is left of `timeout` as its timeout. Nothing is written here.
    """
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError
        try:
            sock = _connect_once(address, min(CONNECT_ATTEMPT_S, left))
        except OSError:
            if end - time.monotonic() <= CONNECT_PAUSE_S:
                raise
            time.sleep(CONNECT_PAUSE_S)
            continue
        left = end - time.monotonic()
        if left <= 0:
            sock.close()
            raise TimeoutError
        sock.settimeout(left)
        return sock


class _Connection(http.client.HTTPConnection):
    """http.client's connection for `opener` (the metadata call), its TCP connection
    dialled. http.client calls `connect()` before it writes a byte of the request,
    and only then."""

    def connect(self) -> None:
        self.sock = dial((self.host, self.port), self.timeout)
        with contextlib.suppress(OSError):  # as http.client does, where the system has it
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


class _TlsConnection(http.client.HTTPSConnection, _Connection):
    """HTTPS: its `connect()` calls `_Connection.connect()` (next in the MRO), then the TLS handshake."""


class _Http(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_Connection, req)


class _Https(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(context=context)
        self._tls = context

    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_TlsConnection, req, context=self._tls)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None


def opener(ssl_context: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    """The metadata call's (iap.py): no proxy, no redirect, and every connection dialled (`dial`)."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), _Http(),
                                       _Https(ssl_context or ssl.create_default_context()))


class Deadline:
    """The run's whole budget; each request takes the smaller of this and its step's."""

    def __init__(self, seconds: float, clock: Any = time.monotonic) -> None:
        self._clock = clock
        self._end = clock() + seconds

    def left(self) -> float:
        return self._end - self._clock()


def _socket_of(response: Any) -> socket.socket | None:
    """The connection's socket under an http.client response, or None.

    Best effort, through the buffered reader's raw `SocketIO` (CPython's layout
    since 3.0). Without it, a stall is still bounded by the timeout the socket
    was opened with (the step's), and a trickle by the check before each read.
    """
    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    return sock if isinstance(sock, socket.socket) else None


def _read_body(raw: Any, step_end: float) -> bytes:
    """At most MAX_BODY bytes, one socket read at a time, never past the step's end."""
    # urllib hands back the http.client response itself, or an HTTPError wrapping it in `fp`.
    reader = raw.fp if isinstance(raw, urllib.error.HTTPError) else raw
    if reader is None:
        return b""
    sock = _socket_of(reader)
    chunks: list[bytes] = []
    size = 0
    while size < MAX_BODY:
        left = step_end - time.monotonic()
        if left <= 0:
            raise StepFailure("timeout")
        if sock is not None:
            # A response read to its end has closed its socket already (EBADF): nothing to bound.
            with contextlib.suppress(OSError):
                sock.settimeout(left)
        chunk = reader.read1(min(CHUNK, MAX_BODY - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def _drain(raw: http.client.HTTPResponse, step_end: float) -> None:
    """The rest of an answer longer than MAX_BODY, read and thrown away (at most MAX_DRAIN, never past the
    step), so its connection can carry the next request. Whatever stops it leaves the answer unfinished, and
    the session closes the connection instead: the step is never failed for bytes it does not read."""
    sock = _socket_of(raw)
    drained = 0
    with contextlib.suppress(OSError, http.client.HTTPException, ValueError):
        while drained < MAX_DRAIN and not raw.isclosed():
            left = step_end - time.monotonic()
            if left <= 0:
                return
            if sock is not None:
                sock.settimeout(left)
            chunk = raw.read1(CHUNK)
            if not chunk:
                return
            drained += len(chunk)


def _bound(sock: socket.socket | None, end: float) -> None:
    """The socket's timeout cut to what is left before `end`, or TimeoutError when nothing is (and so
    nothing is written)."""
    left = end - time.monotonic()
    if left <= 0:
        raise TimeoutError
    if sock is not None:
        sock.settimeout(left)


def _idle(sock: socket.socket) -> bool:
    """True when an open connection has nothing waiting on it, so the next request may be written on it.

    Anything waiting means it cannot carry one: an EOF (the server closed it), TLS's close_notify, a reset,
    or bytes nobody asked for. A TLS record that holds no data (a TLS 1.3 session ticket) is taken in here
    and leaves it idle. Looked at without waiting; nothing is written.
    """
    if sock.fileno() < 0:
        return False
    timeout = sock.gettimeout()
    try:
        sock.setblocking(False)
        sock.recv(1)
    except (BlockingIOError, ssl.SSLWantReadError):
        return True
    except OSError:
        return False
    finally:
        with contextlib.suppress(OSError):
            sock.settimeout(timeout)
    return False  # b"" (the end) or a byte nobody asked for


@contextlib.contextmanager
def _transport_failures() -> Iterator[None]:
    """Every transport failure as a closed code, with no exception text: `timeout`, `tls` or `connect`."""
    try:
        yield
    except StepFailure:
        raise
    except TimeoutError:
        raise StepFailure("timeout") from None
    except ssl.SSLError:  # ssl.CertificateError among them
        raise StepFailure("tls") from None
    except (http.client.HTTPException, OSError):
        raise StepFailure("connect") from None


class _Wire(http.client.HTTPConnection):
    """http.client's HTTP/1.1 over the socket a session dialled and handed it (`Session._connection`).

    It never opens a connection of its own: with no socket, http.client raises NotConnected before
    writing a byte, rather than dialling in the middle of a request. http.client never sends a request
    again by itself, and reads each answer to its end before the next can be read."""

    auto_open = 0

    def connect(self) -> None:
        raise http.client.NotConnected


def send(
    open_: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    *,
    timeout: float,
) -> Response:
    """One request through `opener` (the metadata call); every transport failure mapped to a closed code."""
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
            body = _read_body(raw, step_end)
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
    """Requests to one origin, through IAP when there is a token, on one connection kept open between them.

    A context manager: leaving it closes the connection."""

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
        parts = urllib.parse.urlsplit(self.origin)
        self._address = host_port(self.origin)
        #: The `Host` header, the origin's own host and port as written (what urllib sent).
        self._host = parts.netloc
        self._tls = (ssl_context or ssl.create_default_context()) if parts.scheme == "https" else None
        self._wire: _Wire | None = None
        self._iap_token = iap_token
        self._step_timeout = step_timeout
        self._deadline = deadline
        self.cookies = CookieJar()
        self.last_status: int | None = None
        #: The portal release every later request names in `X-Client-Release`, as the portal's own interceptor
        #: stamps it (the sign-in robots set it from `/tpa/release.json`, already checked to be a plain token).
        self.release: str | None = None
        #: How many connections this session has opened: one for a run, unless one could not carry on.
        self.opened = 0

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the connection, if one is open. The next request, if any, dials a new one."""
        wire, self._wire = self._wire, None
        if wire is not None:
            wire.close()

    def _connection(self, end: float, connect: float, answer: float) -> tuple[_Wire, float]:
        """The connection the next request is written on, and when its answer must be in by.

        The open one while it is known to be usable before anything is written: the last answer was
        read to its end and did not close it (http.client drops the socket of an answer that ends with
        the connection: `Connection: close`, HTTP/1.0, a body read to the close), and nothing is waiting
        on it (`_idle`). Otherwise, and the first time, a new one: dialled for at most `connect` (never
        past `end`), then TLS's handshake, once, inside the answer's time, which starts once it is
        connected. A socket connected with no time left is closed with nothing written.
        """
        wire = self._wire
        if wire is not None and (wire.sock is None or not _idle(wire.sock)):
            self.close()
            wire = None
        if wire is not None:
            return wire, min(time.monotonic() + answer, end)
        sock = dial(self._address, min(connect, end - time.monotonic()))
        try:
            answer_end = min(time.monotonic() + answer, end)
            _bound(sock, answer_end)
            if self._tls is not None:
                sock = self._tls.wrap_socket(sock, server_hostname=self._address[0])
        except BaseException:
            sock.close()
            raise
        wire = _Wire(*self._address)
        wire.sock = sock
        self._wire = wire
        self.opened += 1
        return wire, answer_end

    def _exchange(self, method: str, path: str, body: bytes | None, headers: dict[str, str], *,
                  limit: float, connect: float, answer: float) -> Response:
        """One request, written once: a connection (`_connection`), the request, its answer.

        `limit` bounds it all; `connect` the dial, if one is needed; `answer` the rest, from the moment
        it is connected. http.client's `request()` is the one write, called once and never again for
        this request: whatever fails after it (a broken write, no answer, a dropped connection, a
        trickle) closes the connection and fails the step, and nothing is sent again.
        """
        if limit <= 0:
            raise StepFailure("timeout")
        end = time.monotonic() + limit
        with _transport_failures():
            try:
                wire, answer_end = self._connection(end, connect, answer)
                _bound(wire.sock, answer_end)
                wire.request(method, path, body=body, headers=headers)
                _bound(wire.sock, answer_end)
                raw = wire.getresponse()
                try:
                    status = raw.status
                    content = _read_body(raw, answer_end)
                    if not raw.isclosed():
                        _drain(raw, answer_end)
                    finished = raw.isclosed()
                finally:
                    raw.close()
            except BaseException:
                self.close()
                raise
            if not finished:
                # Its end did not come inside the step: the connection cannot carry another request.
                self.close()
            return Response(status=status, headers=raw.msg, body=content)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        accept: str = "application/json",
        bearer: str | None = None,
        tenant: str | None = None,
        csrf: bool = False,
        timeout: float | None = None,
        at_most: float | None = None,
    ) -> Response:
        """One request to this origin. A step's has CONNECT_BUDGET_S for a dial, if it
        needs one, then the step timeout for its answer, and the run's deadline bounds
        both. `timeout` replaces all three with a budget of its own, the dial's and the
        answer's together, outside the deadline (the sign-out's); `at_most` caps
        whichever applies (a TOTP code's accepted life, for its `mfa_verify`). `tenant`
        is the CRM's `X-Tenant-Id`, which the caller has already checked is a UUID."""
        if not path.startswith("/") or path.startswith("//"):
            raise StepFailure("runner")
        headers = {
            "Host": self._host,
            "User-Agent": USER_AGENT,
            "Accept": accept,
            "Sec-Fetch-Site": "same-origin",
        }
        if self._iap_token:
            headers["Proxy-Authorization"] = f"Bearer {self._iap_token}"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if tenant:
            headers["X-Tenant-Id"] = tenant
        if self.release:
            headers["X-Client-Release"] = self.release
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
                headers["Content-Type"] = EMPTY_BODY_TYPE
        if csrf:
            token = self.cookies.value(CSRF_COOKIE)
            if not token:
                raise StepFailure("csrf")
            headers["X-CSRF-Token"] = token
        if timeout is None:
            limit, connect, answer = self._deadline.left(), CONNECT_BUDGET_S, self._step_timeout
        else:
            limit = connect = answer = timeout
        if at_most is not None:
            limit = min(limit, at_most)
        response = self._exchange(method, path, data, headers, limit=limit, connect=connect, answer=answer)
        self.last_status = response.status
        self.cookies.take(response.headers, cookie_path)
        return response

    def get(self, path: str, **kwargs: Any) -> Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Response:
        return self.request("POST", path, **kwargs)
