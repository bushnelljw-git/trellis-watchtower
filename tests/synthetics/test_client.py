"""The client's one connection per session, against local servers: every request of a session rides one
connection; a new one is dialled only when the open one is known to be unusable before anything is written
(`Connection: close`, a close the server never announced, an answer not read to its end); a request is never
sent again once a byte of it is written; the dial keeps trying inside its own budget, apart from the step's,
which still bounds the answer; and the run's deadline, the sign-out's own budget and a code's life bound both.

Run: python3 -m unittest discover -s tests/synthetics -v   (make synthetics-test)
"""

from __future__ import annotations

import contextlib
import datetime
import ipaddress
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import synthetic_fakes as fakes  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from synthetics import client  # noqa: E402
from synthetics.client import Deadline, Session, StepFailure  # noqa: E402


@contextlib.contextmanager
def constants(**values: float):
    """client's dial constants (CONNECT_ATTEMPT_S, CONNECT_PAUSE_S, CONNECT_BUDGET_S, MAX_DRAIN) for the block."""
    real = {name: getattr(client, name) for name in values}
    for name, value in values.items():
        setattr(client, name, value)
    try:
        yield
    finally:
        for name, value in real.items():
            setattr(client, name, value)


@contextlib.contextmanager
def attempts(attempt: Callable):
    """client._connect_once replaced by `attempt(address, timeout, real)`; yields each attempt's timeout."""
    real = client._connect_once
    seen: list[float] = []

    def recorded(address, timeout):
        seen.append(timeout)
        return attempt(address, timeout, real)

    client._connect_once = recorded
    try:
        yield seen
    finally:
        client._connect_once = real


def blackholed(first: int | None = None):
    """The first `first` attempts (all, if None) are never answered: each spends its whole timeout, as a SYN
    Cloud NAT dropped does. The rest connect for real."""
    count = [0]

    def attempt(address, timeout, real):
        count[0] += 1
        if first is None or count[0] <= first:
            time.sleep(timeout)
            raise TimeoutError
        return real(address, timeout)
    return attempt


def refused(address, timeout, real):
    raise ConnectionRefusedError


def session(origin: str, *, step: float = 5.0, deadline: float = 60.0,
            context: ssl.SSLContext | None = None) -> Session:
    return Session(origin, iap_token=None, ssl_context=context, step_timeout=step, deadline=Deadline(deadline))


# --- a raw server: every byte each connection received, and a script for how each is answered -------------


def read_request(conn: socket.socket) -> bytes:
    """One HTTP/1.1 request, headers and Content-Length body, or b"" at the end."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return b""
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def answer(conn: socket.socket, body: bytes = b"{}", *, extra: str = "") -> None:
    conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n{extra}\r\n"
                 .encode() + body)


def reset(conn: socket.socket) -> None:
    """Close with a reset (SO_LINGER 0), as a connection dropped mid-request."""
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()


class RawServer:
    """127.0.0.1, one thread per connection running `serve(conn, server)`; `received[i]` is every byte the
    i-th connection received (`serve` appends what it reads)."""

    def __init__(self, serve: Callable[[socket.socket, RawServer], None]) -> None:
        self.serve = serve
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.received: list[list[bytes]] = []
        self.lock = threading.Lock()
        self.done = threading.Event()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> RawServer:
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.done.set()
        self.listener.close()

    def _accept(self) -> None:
        while not self.done.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with self.lock:
                self.received.append([])
                index = len(self.received) - 1
            threading.Thread(target=self._run, args=(conn, index), daemon=True).start()

    def _run(self, conn: socket.socket, index: int) -> None:
        with contextlib.suppress(OSError):
            self.serve(_Recording(conn, self.received[index]), self)
        with contextlib.suppress(OSError):
            conn.close()

    def requests(self) -> list[bytes]:
        return [request for connection in self.received for request in connection]


class _Recording:
    """A connection whose `recv` appends to its connection's record, request by request (read_request)."""

    def __init__(self, conn: socket.socket, record: list[bytes]) -> None:
        self._conn = conn
        self._record = record

    def recv(self, size: int) -> bytes:
        return self._conn.recv(size)

    def __getattr__(self, name: str):
        return getattr(self._conn, name)

    def next_request(self) -> bytes:
        request = read_request(self._conn)
        if request:
            self._record.append(request)
        return request


def keep_alive(conn: _Recording, _server: RawServer) -> None:
    while conn.next_request():
        answer(conn)


def self_signed(directory: str) -> tuple[str, str]:
    """A certificate for 127.0.0.1 that is its own issuer, and its key: the TLS tests' one trust anchor."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetics-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    public = key.public_key()
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                       critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=False,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return cert_path, key_path


# --- the tests -----------------------------------------------------------------------------------------------


class OneConnection(unittest.TestCase):
    def test_every_request_of_a_session_rides_one_connection(self):
        with fakes.Fake(iap=False) as fake:
            with session(fake.base) as s:
                for path in ("/tpa/", "/tpa/release.json", f"/tpa/{fakes.MAIN_SCRIPT}", "/tpa/release.json"):
                    self.assertEqual(s.get(path).status, 200)
                self.assertEqual(s.post("/auth/login", payload={"email": "x", "password": "y"}).status, 401)
                self.assertEqual(s.get("/auth/me").status, 401)
                self.assertEqual(s.opened, 1)
        self.assertEqual(fake.routes(), ["portal_shell", "portal_release", "portal_bundle", "portal_release",
                                         "login", "me"])
        self.assertEqual(fake.connections, ["request"], "six requests, one connection")

    def test_a_reused_connection_dials_nothing(self):
        with fakes.Fake(iap=False) as fake, session(fake.base) as s:
            s.get("/tpa/")

            def never(address, timeout, real):
                raise AssertionError("dialled again")

            with attempts(never) as seen:
                s.get("/tpa/release.json")
            self.assertEqual(seen, [])

    def test_the_request_on_the_wire_changes_only_its_connection(self):
        # urllib's request, header for header, but for `Connection: close`: Host is the origin's own
        # host and port, a write with no JSON carries urllib's content type and a zero length.
        with RawServer(keep_alive) as server, session(server.origin) as s:
            s.get("/tpa/release.json")
            s.post("/auth/logout")
            s.post("/auth/login", payload={"a": 1})
        get, logout, login = server.requests()
        self.assertEqual(len(server.received), 1)
        heads = [request.split(b"\r\n\r\n")[0].decode().split("\r\n") for request in (get, logout, login)]
        self.assertEqual(heads[0][0], "GET /tpa/release.json HTTP/1.1")
        for head in heads:
            fields = {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip() for line in head[1:]}
            self.assertEqual(fields["host"], f"127.0.0.1:{server.port}")
            self.assertEqual(fields["user-agent"], client.USER_AGENT)
            self.assertEqual(fields["sec-fetch-site"], "same-origin")
            self.assertEqual(fields["accept-encoding"], "identity")
            self.assertNotIn("connection", fields, "HTTP/1.1 keeps it open; nothing asks otherwise")
            self.assertNotIn("proxy-authorization", fields)
            if head is not heads[0]:
                self.assertEqual(fields["origin"], server.origin)
        logout_fields = {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip() for line in heads[1][1:]}
        self.assertEqual((logout_fields["content-type"], logout_fields["content-length"]),
                         (client.EMPTY_BODY_TYPE, "0"))
        self.assertTrue(login.endswith(b'\r\n\r\n{"a":1}'))

    def test_connection_close_is_followed_by_a_new_connection(self):
        with fakes.Fake(iap=False, fail={"portal_release": "close"}) as fake, session(fake.base) as s:
            for path in ("/tpa/", "/tpa/release.json", f"/tpa/{fakes.MAIN_SCRIPT}", "/auth/me"):
                s.get(path)
            self.assertEqual(s.opened, 2)
        self.assertEqual(fake.routes(), ["portal_shell", "portal_release", "portal_bundle", "me"])
        self.assertEqual(fake.connections, ["request", "request"])

    def test_a_close_the_server_never_announced_is_seen_before_writing(self):
        with fakes.Fake(iap=False, fail={"portal_release": "hangup"}) as fake, session(fake.base) as s:
            s.get("/tpa/release.json")
            fake.wait_closed(1)
            time.sleep(0.05)  # the server's close reaches this end of the loopback
            self.assertEqual(s.get("/tpa/").status, 200, "seen at its end before a byte was written")
            self.assertEqual(s.opened, 2)
        self.assertEqual(fake.routes(), ["portal_release", "portal_shell"])

    def test_bytes_nobody_asked_for_mean_a_new_connection(self):
        read, sent = threading.Event(), threading.Event()

        def chatty(conn, _server):
            conn.next_request()
            answer(conn)
            # An answer to nothing, sent once the answer has been read (bytes that came with it are thrown away
            # with its reader, and could not mislead the next): the connection cannot carry another request.
            read.wait(5)
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            sent.set()
            while conn.next_request():
                answer(conn)

        with RawServer(chatty) as server, session(server.origin) as s:
            s.get("/one")
            read.set()
            self.assertTrue(sent.wait(5))
            time.sleep(0.05)  # the unasked bytes reach this end of the loopback
            self.assertEqual(s.get("/two").status, 200)
            self.assertEqual(s.opened, 2)
        self.assertEqual([len(requests) for requests in server.received], [1, 1])

    def test_an_answer_longer_than_what_is_read_is_drained_and_the_connection_kept(self):
        big = b" " * (client.MAX_BODY + 100_000)

        def long_answer(conn, _server):
            conn.next_request()
            answer(conn, big)
            while conn.next_request():
                answer(conn)

        with RawServer(long_answer) as server, session(server.origin) as s:
            self.assertEqual(len(s.get("/big").body), client.MAX_BODY)
            s.get("/next")
            self.assertEqual(s.opened, 1)
        self.assertEqual(len(server.received), 1)

    def test_an_answer_too_long_to_drain_closes_its_connection_and_passes(self):
        def long_answer(conn, _server):
            conn.next_request()
            with contextlib.suppress(OSError):
                answer(conn, b" " * (client.MAX_BODY + 300_000))
            while conn.next_request():
                answer(conn)

        with constants(MAX_DRAIN=64 * 1024), RawServer(long_answer) as server, session(server.origin) as s:
            self.assertEqual(s.get("/big").status, 200)
            self.assertEqual(s.get("/next").status, 200)
            self.assertEqual(s.opened, 2)
        self.assertEqual([len(requests) for requests in server.received], [1, 1])


class WrittenOnce(unittest.TestCase):
    def assert_never_again(self, server: RawServer, requests: int) -> None:
        time.sleep(0.3)  # time for a second connection, were one dialled
        self.assertEqual(len(server.received), 1, "no new connection")
        self.assertEqual(len(server.requests()), requests, "and nothing sent again")

    def test_a_connection_reset_after_the_request_is_never_sent_again(self):
        def reads_then_resets(conn, _server):
            conn.next_request()
            reset(conn)

        with RawServer(reads_then_resets) as server, session(server.origin) as s:
            with self.assertRaises(StepFailure) as failed:
                s.post("/auth/login", payload={"email": "x", "password": "y"})
            self.assertEqual(failed.exception.code, "connect")
            self.assert_never_again(server, 1)

    def test_a_reset_in_the_middle_of_the_write_is_never_sent_again(self):
        # Eight megabytes: the server reads the start of the request and resets while it is still being written.
        def resets_mid_request(conn, server):
            conn._record.append(conn.recv(65536))
            reset(conn)

        with RawServer(resets_mid_request) as server, session(server.origin) as s:
            with self.assertRaises(StepFailure) as failed:
                s.post("/auth/login", payload={"blob": "x" * (8 * 1024 * 1024)})
            self.assertEqual(failed.exception.code, "connect")
            self.assert_never_again(server, 1)

    def test_on_a_reused_connection_a_dropped_request_is_never_sent_again_on_a_new_one(self):
        def second_dropped(conn, _server):
            conn.next_request()
            answer(conn)
            conn.next_request()
            reset(conn)

        with RawServer(second_dropped) as server, session(server.origin) as s:
            s.get("/tpa/")
            with self.assertRaises(StepFailure) as failed:
                s.post("/auth/mfa/verify", payload={"code": "000000"})
            self.assertEqual(failed.exception.code, "connect")
            self.assert_never_again(server, 2)
            self.assertIsNone(s._wire, "the failed connection is closed")

    def test_after_a_failure_the_next_request_goes_on_a_new_connection_once(self):
        with fakes.Fake(iap=False, fail={"login": "drop"}) as fake, session(fake.base) as s:
            s.get("/tpa/")
            with self.assertRaises(StepFailure) as failed:
                s.post("/auth/login", payload={"email": "x", "password": "y"})
            self.assertEqual(failed.exception.code, "connect")
            s.post("/auth/logout")
            self.assertEqual(s.opened, 2)
        self.assertEqual(fake.routes(), ["portal_shell", "login", "logout"])
        self.assertEqual(fake.connections, ["request", "request"])


class TheDialsBudget(unittest.TestCase):
    """CONNECT_BUDGET_S, scaled down (attempts of 0.2 s, 0.05 s apart): the dial's own, apart from the step's."""

    SCALED = {"CONNECT_ATTEMPT_S": 0.2, "CONNECT_PAUSE_S": 0.05}

    def test_attempts_dropped_for_longer_than_the_step_then_accepted_land_once(self):
        # Six attempts never answered (1.5 s), three times the step's half second, inside the dial's 3 s.
        with fakes.Fake(iap=False) as fake, constants(CONNECT_BUDGET_S=3.0, **self.SCALED), \
                attempts(blackholed(first=6)) as seen, session(fake.base, step=0.5) as s:
            started = time.monotonic()
            self.assertEqual(s.get("/tpa/").status, 200)
            took = time.monotonic() - started
        self.assertEqual(len(seen), 7)
        self.assertGreaterEqual(took, 1.45)
        self.assertEqual(fake.routes(), ["portal_shell"])

    def test_attempts_refused_for_a_while_then_accepted_land_once(self):
        tries = []

        def refused_then_real(address, timeout, real):
            tries.append(timeout)
            if len(tries) <= 5:
                raise ConnectionRefusedError
            return real(address, timeout)

        with fakes.Fake(iap=False) as fake, constants(CONNECT_BUDGET_S=3.0, **self.SCALED), \
                attempts(refused_then_real), session(fake.base, step=0.1) as s:
            self.assertEqual(s.get("/tpa/").status, 200)
        self.assertEqual(len(tries), 6)
        self.assertEqual(fake.routes(), ["portal_shell"])

    def test_dropped_past_the_budget_is_a_timeout_with_nothing_sent(self):
        with fakes.Fake(iap=False) as fake, constants(CONNECT_BUDGET_S=1.0, **self.SCALED), \
                attempts(blackholed()), session(fake.base, step=5.0) as s:
            started = time.monotonic()
            with self.assertRaises(StepFailure) as failed:
                s.post("/auth/login", payload={"email": "x", "password": "y"})
            took = time.monotonic() - started
        self.assertEqual(failed.exception.code, "timeout")
        self.assertGreaterEqual(took, 0.95)
        self.assertLess(took, 2.0, "the dial's budget, not the step's 5 s")
        self.assertEqual((fake.requests, fake.connections), ([], []))

    def test_refused_past_the_budget_is_connect(self):
        with fakes.Fake(iap=False) as fake, constants(CONNECT_BUDGET_S=0.6, **self.SCALED), \
                attempts(refused) as seen, session(fake.base) as s:
            started = time.monotonic()
            with self.assertRaises(StepFailure) as failed:
                s.get("/tpa/")
            took = time.monotonic() - started
        self.assertEqual(failed.exception.code, "connect")
        self.assertGreater(len(seen), 5)
        self.assertLess(took, 1.0)

    def test_the_step_still_bounds_a_slow_answer_after_a_slow_dial(self):
        # The dial takes about 1 s of its 3; the answer then has the step's whole half second, and no more.
        with fakes.Fake(iap=False, fail={"portal_shell": "hang"}, hang_s=3.0) as fake, \
                constants(CONNECT_BUDGET_S=3.0, **self.SCALED), attempts(blackholed(first=4)), \
                session(fake.base, step=0.5) as s:
            started = time.monotonic()
            with self.assertRaises(StepFailure) as failed:
                s.get("/tpa/")
            took = time.monotonic() - started
        self.assertEqual(failed.exception.code, "timeout")
        self.assertGreaterEqual(took, 1.45)
        self.assertLess(took, 2.0)
        self.assertEqual(fake.routes(), ["portal_shell"])

    def test_the_step_bounds_a_slow_answer_on_a_reused_connection(self):
        with fakes.Fake(iap=False, fail={"me": "hang"}, hang_s=3.0) as fake, session(fake.base, step=0.5) as s:
            s.get("/tpa/")
            started = time.monotonic()
            with self.assertRaises(StepFailure) as failed:
                s.get("/auth/me")
            took = time.monotonic() - started
        self.assertEqual(failed.exception.code, "timeout")
        self.assertLess(took, 0.9)

    def test_the_runs_deadline_bounds_the_dial(self):
        with fakes.Fake(iap=False) as fake, constants(CONNECT_BUDGET_S=30.0, **self.SCALED), \
                attempts(blackholed()), session(fake.base, step=15.0, deadline=0.8) as s:
            started = time.monotonic()
            with self.assertRaises(StepFailure) as failed:
                s.get("/tpa/")
            took = time.monotonic() - started
        self.assertEqual(failed.exception.code, "timeout")
        self.assertLess(took, 1.2)
        self.assertEqual(fake.connections, [])

    def test_the_sign_outs_own_budget_bounds_its_dial_and_answer_together(self):
        # The task's timeout counts the sign-out at 10 s at most: its dial never gets CONNECT_BUDGET_S on top.
        with fakes.Fake(iap=False) as fake, constants(CONNECT_BUDGET_S=30.0, **self.SCALED), \
                attempts(blackholed()), session(fake.base) as s:
            started = time.monotonic()
            with self.assertRaises(StepFailure) as failed:
                s.post("/auth/logout", timeout=0.6)
            took = time.monotonic() - started
        self.assertEqual(failed.exception.code, "timeout")
        self.assertLess(took, 1.0)
        self.assertEqual(fake.requests, [])

    def test_a_codes_life_bounds_the_dial_and_the_code_is_never_written(self):
        with fakes.Fake(iap=False) as fake, constants(CONNECT_BUDGET_S=30.0, **self.SCALED), \
                attempts(blackholed()), session(fake.base, step=60.0) as s:
            started = time.monotonic()
            with self.assertRaises(StepFailure) as failed:
                s.post("/auth/mfa/verify", payload={"code": "000000"}, at_most=0.6)
            took = time.monotonic() - started
        self.assertEqual(failed.exception.code, "timeout")
        self.assertLess(took, 1.0)
        self.assertEqual(fake.requests, [])

    def test_a_spent_budget_sends_nothing_and_dials_nothing(self):
        with fakes.Fake(iap=False) as fake, attempts(refused) as seen, session(fake.base, deadline=0.0) as s:
            with self.assertRaises(StepFailure) as failed:
                s.get("/tpa/")
        self.assertEqual((failed.exception.code, seen, fake.connections), ("timeout", [], []))


class OverTls(unittest.TestCase):
    """The same over TLS, as production's portal speaks it: one handshake, then every request on that
    connection (a TLS 1.3 session ticket is not a reason to dial again); a close is still seen."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cert, key = self_signed(self.tmp.name)
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(cert, key)
        self.client_context = ssl.create_default_context(cafile=cert)

    def tls_fake(self, **kwargs) -> fakes.Fake:
        fake = fakes.Fake(iap=False, **kwargs)
        fake.server.socket = self.server_context.wrap_socket(fake.server.socket, server_side=True)
        return fake

    def test_one_handshake_carries_every_request(self):
        with self.tls_fake() as fake:
            origin = f"https://127.0.0.1:{fake.port}"
            with session(origin, context=self.client_context) as s:
                for path in ("/tpa/", "/tpa/release.json", f"/tpa/{fakes.MAIN_SCRIPT}", "/auth/me", "/tpa/"):
                    s.get(path)
                    time.sleep(0.02)  # room for anything the server sends after an answer to arrive
                self.assertEqual(s.opened, 1)
        self.assertEqual(fake.connections, ["request"])
        self.assertEqual(len(fake.requests), 5)

    def test_a_tls_connection_the_server_closed_is_dialled_again_before_writing(self):
        with self.tls_fake(fail={"portal_release": "hangup"}) as fake:
            with session(f"https://127.0.0.1:{fake.port}", context=self.client_context) as s:
                s.get("/tpa/release.json")
                fake.wait_closed(1)
                time.sleep(0.05)
                self.assertEqual(s.get("/tpa/").status, 200)
                self.assertEqual(s.opened, 2)
        self.assertEqual(fake.routes(), ["portal_release", "portal_shell"])

    def test_a_redialled_connection_still_verifies_its_certificate(self):
        # The first connection presents the trusted certificate, answers, and is closed by the server; the
        # re-dial meets a certificate nobody trusts: `tls`, and nothing of the request reaches the server.
        untrusted_dir = os.path.join(self.tmp.name, "untrusted")
        os.mkdir(untrusted_dir)
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        untrusted.load_cert_chain(*self_signed(untrusted_dir))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(5)
        self.addCleanup(listener.close)
        seen: list[tuple[int, bytes]] = []
        closed = threading.Event()

        def serve() -> None:
            for index, context in enumerate((self.server_context, untrusted)):
                with contextlib.suppress(OSError):
                    raw, _ = listener.accept()
                    try:
                        conn = context.wrap_socket(raw, server_side=True)
                    except OSError:
                        seen.append((index, b"handshake refused"))
                        raw.close()
                        continue
                    seen.append((index, read_request(conn).split(b"\r\n")[0]))
                    answer(conn)
                    conn.close()
                    closed.set()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        with session(f"https://127.0.0.1:{listener.getsockname()[1]}", context=self.client_context) as s:
            s.get("/one")
            self.assertTrue(closed.wait(5))
            time.sleep(0.05)  # the server's close reaches this end of the loopback
            with self.assertRaises(StepFailure) as failed:
                s.get("/two")
            self.assertEqual(s.opened, 1)
        server.join(5)
        self.assertEqual(failed.exception.code, "tls")
        self.assertEqual(seen, [(0, b"GET /one HTTP/1.1"), (1, b"handshake refused")])

    def test_a_certificate_refused_is_tls_and_never_dialled_again(self):
        with self.tls_fake() as fake, attempts(lambda address, timeout, real: real(address, timeout)) as seen:
            with session(f"https://127.0.0.1:{fake.port}") as s, self.assertRaises(StepFailure) as failed:
                s.get("/tpa/")
        self.assertEqual((failed.exception.code, len(seen)), ("tls", 1))


if __name__ == "__main__":
    unittest.main()
