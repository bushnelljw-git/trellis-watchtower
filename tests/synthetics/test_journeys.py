"""The journeys against a local fake (synthetic_fakes.py): pass, each step failing, timeouts,
transport failures, configuration, pausing, the egress warm-up, connections dialled and requests
written once, and no secret on stdout or stderr on any path.

Run: python3 -m unittest discover -s tests/synthetics -v   (make synthetics-test)
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import synthetic_fakes as fakes  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from synthetics import __main__ as cli  # noqa: E402
from synthetics import client, journeys, result, totp  # noqa: E402
from synthetics.journeys import Tools  # noqa: E402

#: The start of a TOTP step, so a code minted at it never waits.
FIXED_NOW = 1_800_000_000.0 - (1_800_000_000.0 % 30) + 1
KEYS = ["severity", "level", "message", "job", "outcome", "code", "step", "status_class", "elapsed_ms", "steps_ms"]

J1_STEPS = ["config", "egress", "secrets", "iap_token", "ops_shell", "ops_release", "login", "mfa_verify", "me",
            "desk_version", "logout", "portal_shell"]
J1_ROUTES = ["metadata", "ops_shell", "ops_release", "login", "mfa_verify", "me", "desk_version", "logout",
             "portal_shell"]
J2_ROUTES = ["metadata", "login", "mfa_verify", "live_queue", "desk_version_employers", "logout"]
J3_ROUTES = ["metadata", "crm_shell", "crm_login", "crm_mfa_verify", "crm_me", "crm_tenant", "crm_logout"]
J3_STEPS = ["config", "egress", "secrets", "iap_token", "crm_shell", "login", "mfa_verify", "me", "crm_tenant",
            "logout"]


def credentials_file(directory: str, value: object | None = None, raw: bytes | None = None) -> str:
    path = os.path.join(directory, "credentials.json")
    if raw is None:
        raw = json.dumps(value if value is not None else
                         {"password": fakes.PASSWORD, "totp_secret": fakes.TOTP_SECRET}).encode()
    with open(path, "wb") as handle:
        handle.write(raw)
    return path


class Network:
    """The warm-up's steady clock, pause and connect, scripted: no time passes and no socket opens.

    `script[port]` is that port's answers in order: True connects (0.05 s); False is never
    answered, so it spends the attempt's whole timeout. Past the script's end, `then`.
    """

    START = 1000.0

    def __init__(self, script: dict[int, list[bool]] | None = None, *, then: bool = True) -> None:
        self.clock = self.START
        self.script = {port: list(answers) for port, answers in (script or {}).items()}
        self.then = then
        self.connects: list[tuple[int, float]] = []
        self.pauses: list[float] = []

    def monotonic(self) -> float:
        return self.clock

    def sleep(self, seconds: float) -> None:
        self.pauses.append(seconds)
        self.clock += seconds

    def connect(self, _family: int, address: tuple, timeout: float) -> None:
        self.connects.append((address[1], timeout))
        answers = self.script.get(address[1], [])
        if not (answers.pop(0) if answers else self.then):
            self.clock += timeout
            raise TimeoutError
        self.clock += 0.05

    def tools(self) -> Tools:
        return Tools(now=lambda: FIXED_NOW, sleep=self.sleep, monotonic=self.monotonic, connect=self.connect)

    def spent(self) -> float:
        return self.clock - self.START


@contextlib.contextmanager
def dialling(attempt):
    """client._connect_once replaced by `attempt(address, timeout, real)` for the block; yields each
    attempt's timeout, in order."""
    real = client._connect_once
    timeouts: list[float] = []

    def recorded(address, timeout):
        timeouts.append(timeout)
        return attempt(address, timeout, real)

    client._connect_once = recorded
    try:
        yield timeouts
    finally:
        client._connect_once = real


def failing_first(errors: list):
    """Each attempt takes the next of `errors`: an exception is raised at once; None connects."""
    def attempt(address, timeout, real):
        error = errors.pop(0) if errors else None
        if error is not None:
            raise error
        return real(address, timeout)
    return attempt


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.creds = credentials_file(self.tmp.name)

    def env(self, fake: fakes.Fake, **extra: str) -> dict[str, str]:
        env = {
            "SYNTHETICS_BASE_URL": fake.base,
            "SYNTHETICS_PORTAL_BASE_URL": fake.portal_base,
            "SYNTHETICS_EMAIL": fakes.EMAIL,
            "SYNTHETICS_CREDENTIALS_FILE": self.creds,
            "SYNTHETICS_IAP_AUDIENCE": fakes.AUDIENCE,
            "SYNTHETICS_METADATA_HOST": fake.metadata_host,
        }
        env.update(extra)
        return {k: v for k, v in env.items() if v is not None}

    def run_journey(self, name: str, env: dict[str, str], *, use_iap: bool = True,
                    tools: Tools | None = None) -> tuple[dict, int]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.run(name, env, use_iap=use_iap,
                           tools=tools or Tools(now=lambda: FIXED_NOW, sleep=lambda _s: None))
        return self.parse_clean(out.getvalue(), err.getvalue()), code

    def assert_silent(self, fake: fakes.Fake, expected: int) -> None:
        """The connections that closed with nothing sent (the warm-up's), once the server has read them."""
        settle = time.monotonic() + 2
        while fake.connections.count("silent") < expected and time.monotonic() < settle:
            time.sleep(0.01)
        self.assertEqual(fake.connections.count("silent"), expected)
        self.assertEqual(fake.connections.count("request"), len(fake.requests))

    def parse_clean(self, stdout: str, stderr: str) -> dict:
        """Exactly one line on stdout, nothing on stderr, no sentinel anywhere, closed values only."""
        self.assertEqual(stderr, "", "the runner wrote to stderr")
        for sentinel in fakes.SENTINELS:
            self.assertNotIn(sentinel, stdout)
        self.assertNotIn("127.0.0.1", stdout)
        self.assertNotIn("localhost", stdout)
        lines = stdout.split("\n")
        self.assertEqual(len(lines), 2, "exactly one line, newline-terminated")
        self.assertEqual(lines[1], "")
        line = json.loads(lines[0])
        self.assertEqual(list(line), KEYS)
        self.assertEqual(line["message"], "synthetic_result")
        self.assertIn(line["job"], result.JOBS)
        self.assertIn(line["outcome"], result.OUTCOMES)
        self.assertIn(line["code"], result.CODES)
        self.assertIn(line["step"], result.STEPS)
        self.assertIn(line["status_class"], result.STATUS_CLASSES)
        for name, ms in line["steps_ms"].items():
            self.assertIn(name, result.STEPS)
            self.assertIsInstance(ms, int)
        return line

    def assert_failed(self, line: dict, exit_code: int, *, step: str, code: str, status_class: str) -> None:
        """A verdict: the site failed a check. The line drives the alert; the job itself succeeds."""
        self.assertEqual((line["outcome"], line["step"], line["code"], line["status_class"]),
                         ("fail", step, code, status_class))
        self.assertEqual(line["severity"], "ERROR")
        self.assertEqual(exit_code, 0, "a journey that ran to a verdict exits 0, fail included")

    def assert_error(self, line: dict, exit_code: int, *, step: str, code: str, status_class: str = "none") -> None:
        """The runner itself broke: an error line, and a non-zero exit for jobs-failed."""
        self.assertEqual((line["outcome"], line["step"], line["code"], line["status_class"]),
                         ("error", step, code, status_class))
        self.assertEqual(line["severity"], "ERROR")
        self.assertEqual(exit_code, 1)

    def assert_no_received_code_printed(self, fake: fakes.Fake, line: dict) -> None:
        # Every string in the line is from a closed list and every number a duration, so a
        # six-digit code could only appear as a string.
        text = json.dumps(line)
        self.assertTrue(fake.codes_received)
        for code in fake.codes_received:
            self.assertNotIn(f'"{code}"', text)


class StaffSignIn(Case):
    def test_pass_through_iap(self):
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assertEqual(code, 0)
        self.assertEqual((line["outcome"], line["code"], line["step"], line["status_class"]),
                         ("pass", "ok", "none", "2xx"))
        self.assertEqual(line["severity"], "INFO")
        self.assertEqual(list(line["steps_ms"]), J1_STEPS)
        self.assertEqual(fake.routes(), J1_ROUTES)
        edge = [r for r in fake.requests if r["route"] != "metadata"]
        for request in edge:
            self.assertEqual(request["proxy_authorization"], f"Bearer {fakes.IAP_TOKEN}")
            self.assertIsNone(request["authorization"], "Authorization stays empty (AN-01)")
            self.assertEqual(request["sec_fetch_site"], "same-origin")
        metadata = fake.requests[0]
        self.assertEqual(metadata["metadata_flavor"], "Google")
        self.assertEqual(metadata["query"], {"audience": [fakes.AUDIENCE], "format": ["full"]})
        self.assertIsNone(metadata["proxy_authorization"])
        portal = fake.requests[-1]
        self.assertEqual(portal["host"], f"localhost:{fake.port}")
        self.assertIsNone(portal["cookie"], "the portal host gets no cookie from the ops host")
        self.assertTrue(all(r["host"] == f"127.0.0.1:{fake.port}" for r in edge[:-1]))
        logout = edge[-2]
        self.assertEqual((logout["csrf"], logout["origin"]), (fakes.CSRF, fake.base))
        self.assertEqual(len(fake.codes_received), 1)
        self.assert_no_received_code_printed(fake, line)
        # The warm-up: two connections in a row to each host (127.0.0.1 and localhost), not a byte sent.
        self.assert_silent(fake, 4)

    def test_each_step_failing(self):
        for route, step in [("ops_shell", "ops_shell"), ("ops_release", "ops_release"), ("login", "login"),
                            ("mfa_verify", "mfa_verify"), ("me", "me"), ("desk_version", "desk_version"),
                            ("logout", "logout"), ("portal_shell", "portal_shell")]:
            with self.subTest(step=step):
                with fakes.Fake(fail={route: 503}, clock=lambda: FIXED_NOW) as fake:
                    line, code = self.run_journey("staff-sign-in", self.env(fake))
                self.assert_failed(line, code, step=step, code="status", status_class="5xx")
                routes = fake.routes()
                self.assertEqual(routes[: routes.index(route) + 1], J1_ROUTES[: J1_ROUTES.index(route) + 1])
                self.assertEqual(routes.count("login"), 1 if J1_ROUTES.index(route) >= 3 else 0)
                self.assertLessEqual(routes.count("mfa_verify"), 1)
                if step in ("me", "desk_version"):
                    # Signed in, then failed: the session is still ended.
                    self.assertEqual(routes[-1], "logout")
                    self.assertEqual(fake.requests[-1]["csrf"], fakes.CSRF)
                self.assertIn(step, line["steps_ms"])

    def test_metadata_server_refuses(self):
        with fakes.Fake(fail={"metadata": 500}) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        # The job's own environment, not the site: the runner's error, for jobs-failed.
        self.assert_error(line, code, step="iap_token", code="iap_token", status_class="5xx")
        self.assertEqual(fake.routes(), ["metadata"], "nothing reaches the edge without a token")

    def test_wrong_audience_is_refused_by_the_metadata_server(self):
        with fakes.Fake() as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_IAP_AUDIENCE="other"))
        self.assert_error(line, code, step="iap_token", code="iap_token", status_class="4xx")

    def test_iap_refuses(self):
        with fakes.Fake(fail={"ops_shell": "iap_refuse"}) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="ops_shell", code="iap", status_class="4xx")

    def test_iap_refuses_later_steps_too(self):
        with fakes.Fake(fail={"desk_version": "iap_refuse"}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="desk_version", code="iap", status_class="4xx")

    def test_google_sign_in_redirect_is_iap(self):
        with fakes.Fake(fail={"ops_shell": "redirect_google"}) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="ops_shell", code="iap", status_class="3xx")

    def test_other_redirect_is_never_followed(self):
        with fakes.Fake(fail={"me": "redirect_other"}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="me", code="redirect", status_class="3xx")
        self.assertNotIn("unknown", fake.routes(), "the redirect's target was never asked")
        self.assertEqual(fake.routes()[-1], "logout")

    def test_iap_sign_in_page_instead_of_the_shell(self):
        with fakes.Fake(fail={"ops_shell": "no_base_href"}) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="ops_shell", code="shape", status_class="2xx")

    def test_release_not_json(self):
        with fakes.Fake(fail={"ops_release": "not_json"}) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="ops_release", code="shape", status_class="2xx")

    def test_sign_in_refusals(self):
        for route, status, expected in [("login", 401, "credentials"), ("login", 423, "locked"),
                                        ("login", 429, "rate_limited"), ("mfa_verify", 401, "credentials"),
                                        ("mfa_verify", 423, "locked"), ("login", 400, "status")]:
            with self.subTest(route=route, status=status):
                with fakes.Fake(fail={route: status}, clock=lambda: FIXED_NOW) as fake:
                    line, code = self.run_journey("staff-sign-in", self.env(fake))
                self.assert_failed(line, code, step=route, code=expected, status_class="4xx")
                self.assertEqual(fake.routes().count("login"), 1, "one password per run, never retried")
                self.assertLessEqual(fake.routes().count("mfa_verify"), 1, "one code per run, never retried")
                self.assertNotIn("logout", fake.routes())

    def test_wrong_password_is_credentials(self):
        path = credentials_file(self.tmp.name, {"password": "not-it", "totp_secret": fakes.TOTP_SECRET})
        with fakes.Fake() as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_CREDENTIALS_FILE=path))
        self.assert_failed(line, code, step="login", code="credentials", status_class="4xx")
        self.assertNotIn("not-it", json.dumps(line))

    def test_wrong_totp_secret_is_credentials(self):
        path = credentials_file(self.tmp.name, {"password": fakes.PASSWORD, "totp_secret": "JBSWY3DPEHPK3PXP"})
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_CREDENTIALS_FILE=path))
        self.assert_failed(line, code, step="mfa_verify", code="credentials", status_class="4xx")
        self.assertEqual(len(fake.codes_received), 1)
        self.assert_no_received_code_printed(fake, line)

    def test_enrolment_required_is_shape(self):
        with fakes.Fake(fail={"login": "enrol"}) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="login", code="shape", status_class="2xx")
        self.assertNotIn("mfa_verify", fake.routes())

    def test_no_session_cookies_is_shape(self):
        with fakes.Fake(fail={"mfa_verify": "no_cookies"}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="mfa_verify", code="shape", status_class="2xx")

    def test_logout_refused_is_csrf(self):
        with fakes.Fake(fail={"logout": 403}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="logout", code="csrf", status_class="4xx")

    def test_timeout_waiting_for_an_answer(self):
        with fakes.Fake(fail={"desk_version": "hang"}, clock=lambda: FIXED_NOW, hang_s=2.0) as fake:
            started = time.monotonic()
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="0.4"))
            took = time.monotonic() - started
        self.assert_failed(line, code, step="desk_version", code="timeout", status_class="none")
        self.assertLess(took, 1.9)
        self.assertLess(line["steps_ms"]["desk_version"], 1500)

    def test_timeout_reading_a_body(self):
        with fakes.Fake(fail={"me": "slow_body"}, clock=lambda: FIXED_NOW, hang_s=2.0) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="0.4"))
        self.assert_failed(line, code, step="me", code="timeout", status_class="none")

    def test_a_trickling_body_cannot_outlast_its_step(self):
        # One byte every 0.3 s: each read returns something, so only the step's own clock can stop it.
        with fakes.Fake(fail={"me": "trickle"}, clock=lambda: FIXED_NOW) as fake:
            started = time.monotonic()
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="1"))
            took = time.monotonic() - started
        self.assert_failed(line, code, step="me", code="timeout", status_class="none")
        self.assertLess(line["steps_ms"]["me"], 1500, "the step's budget is 1 s")
        self.assertLess(took, 3)
        self.assertEqual(fake.routes()[-1], "logout", "and the session is still ended")

    def test_too_deep_json_is_shape_and_still_signs_out(self):
        for route in ("me", "mfa_verify"):
            with self.subTest(route=route), fakes.Fake(fail={route: "deep_json"}, clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_journey("staff-sign-in", self.env(fake))
                self.assert_failed(line, code, step=route, code="shape", status_class="2xx")
                self.assertEqual(fake.routes()[-1], "logout")
                self.assertEqual(fake.requests[-1]["csrf"], fakes.CSRF)

    def test_any_exception_after_sign_in_still_signs_out(self):
        original = journeys._json_read

        def broken(run, session, step, path, **kwargs):
            if step == "desk_version":
                with run.timed(step):
                    raise RuntimeError(f"a bug holding {fakes.SESSION}")
            return original(run, session, step, path, **kwargs)

        journeys._json_read = broken
        try:
            with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_journey("staff-sign-in", self.env(fake))
        finally:
            journeys._json_read = original
        self.assert_error(line, code, step="desk_version", code="runner")
        self.assertEqual(fake.routes()[-2:], ["me", "logout"])
        self.assertEqual(fake.requests[-1]["csrf"], fakes.CSRF)
        self.assertEqual(fake.routes().count("logout"), 1)

    def test_sign_out_has_its_own_budget_after_the_deadline_is_spent(self):
        with fakes.Fake(fail={"desk_version": "hang"}, clock=lambda: FIXED_NOW, hang_s=1.5) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_STEP_TIMEOUT_S="30", SYNTHETICS_DEADLINE_S="0.6"))
            routes = fake.routes()
        self.assert_failed(line, code, step="desk_version", code="timeout", status_class="none")
        self.assertEqual(routes[-1], "logout", "the deadline was spent, and the sign-out still went")

    def test_logout_step_failing_is_not_repeated(self):
        with fakes.Fake(fail={"logout": 503}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="logout", code="status", status_class="5xx")
        self.assertEqual(fake.routes().count("logout"), 1)

    def test_timeout_at_the_metadata_server(self):
        with fakes.Fake(fail={"metadata": "hang"}, hang_s=2.0) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="0.4"))
        self.assert_error(line, code, step="iap_token", code="iap_token")

    def test_run_deadline_bounds_every_step(self):
        with fakes.Fake(fail={"ops_shell": "hang"}, hang_s=2.0) as fake:
            started = time.monotonic()
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_STEP_TIMEOUT_S="30", SYNTHETICS_DEADLINE_S="0.5"))
            took = time.monotonic() - started
        self.assert_failed(line, code, step="ops_shell", code="timeout", status_class="none")
        self.assertLess(took, 1.9)

    def test_connection_dropped(self):
        with fakes.Fake(fail={"ops_release": "drop"}) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake))
        self.assert_failed(line, code, step="ops_release", code="connect", status_class="none")

    def test_nothing_listening(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        with fakes.Fake() as fake:
            # Without the warm-up, which would wait out its budget here (Egress has that case). Refusals are
            # dialled again until the step's second is spent; the last one stands.
            started = time.monotonic()
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_BASE_URL=f"http://127.0.0.1:{closed}", SYNTHETICS_EGRESS_WAIT_S="0",
                SYNTHETICS_STEP_TIMEOUT_S="1"))
            took = time.monotonic() - started
        self.assert_failed(line, code, step="ops_shell", code="connect", status_class="none")
        self.assertLess(took, 2.5)

    def test_https_to_a_plain_server_is_tls(self):
        with fakes.Fake() as fake:
            started = time.monotonic()
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_BASE_URL=f"https://127.0.0.1:{fake.port}"))
            took = time.monotonic() - started
        self.assert_failed(line, code, step="ops_shell", code="tls", status_class="none")
        self.assertLess(took, 3, "a TLS failure is never dialled again")


class Configuration(Case):
    def test_each_required_setting(self):
        for name in ("SYNTHETICS_BASE_URL", "SYNTHETICS_PORTAL_BASE_URL", "SYNTHETICS_EMAIL",
                     "SYNTHETICS_CREDENTIALS_FILE", "SYNTHETICS_IAP_AUDIENCE"):
            with self.subTest(missing=name), fakes.Fake() as fake:
                env = self.env(fake)
                del env[name]
                line, code = self.run_journey("staff-sign-in", env)
                self.assert_error(line, code, step="config", code="config")
                self.assertEqual(fake.requests, [], "nothing is sent on a configuration failure")

    def test_bad_values(self):
        for name, value in [("SYNTHETICS_BASE_URL", "http://ops.example.com"),
                            ("SYNTHETICS_BASE_URL", "https://ops.example.com/ops/"),
                            ("SYNTHETICS_BASE_URL", "https://user:pw@ops.example.com"),
                            ("SYNTHETICS_BASE_URL", "ftp://ops.example.com"),
                            ("SYNTHETICS_EMAIL", "no-at-sign"),
                            ("SYNTHETICS_STEP_TIMEOUT_S", "0"),
                            ("SYNTHETICS_STEP_TIMEOUT_S", "abc"),
                            ("SYNTHETICS_DEADLINE_S", "500"),
                            ("SYNTHETICS_METADATA_HOST", "evil.example/path?x="),
                            ("SYNTHETICS_METADATA_HOST", "evil.example"),
                            ("SYNTHETICS_METADATA_HOST", "metadata.evil.example:80"),
                            ("SYNTHETICS_METADATA_HOST", "127.0.0.1:80/path"),
                            ("SYNTHETICS_METADATA_HOST", "user@127.0.0.1:80"),
                            ("SYNTHETICS_METADATA_HOST", "127.0.0.1:notaport"),
                            ("SYNTHETICS_DEADLINE_S", "101"),
                            ("SYNTHETICS_EGRESS_WAIT_S", "-1"),
                            ("SYNTHETICS_EGRESS_WAIT_S", "171"),
                            ("SYNTHETICS_EGRESS_WAIT_S", "abc"),
                            ("SYNTHETICS_EGRESS_WAIT_S", "nan"),
                            ("SYNTHETICS_CA_FILE", "/nonexistent/ca.pem")]:
            with self.subTest(name=name, value=value), fakes.Fake() as fake:
                line, code = self.run_journey("staff-sign-in", self.env(fake, **{name: value}))
                self.assert_error(line, code, step="config", code="config")
                self.assertEqual(fake.requests, [])
                self.assertEqual(fake.connections, [], "and no warm-up")

    def test_bad_credentials_file(self):
        for raw in [b"", b"not json", b"[]", b'{"password": "x"}', b'{"password": "", "totp_secret": "JBSWY3DP"}',
                    b'{"password": "x", "totp_secret": "not base32 !!"}', b"\xff\xfe", b"{" * 70000]:
            with self.subTest(raw=raw[:20]), fakes.Fake() as fake:
                path = credentials_file(self.tmp.name, raw=raw)
                line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_CREDENTIALS_FILE=path))
                self.assert_error(line, code, step="secrets", code="config")
                self.assertEqual(fake.requests, [])

    def test_credentials_must_be_a_regular_file(self):
        fifo = os.path.join(self.tmp.name, "fifo")
        os.mkfifo(fifo)
        for path in (self.tmp.name, fifo, "/dev/zero"):
            with self.subTest(path=os.path.basename(path)), fakes.Fake() as fake:
                started = time.monotonic()
                line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_CREDENTIALS_FILE=path))
                self.assert_error(line, code, step="secrets", code="config")
                self.assertLess(time.monotonic() - started, 2, "a FIFO or a device never blocks the read")
                self.assertEqual(fake.requests, [])

    def test_credentials_nested_too_deep(self):
        path = credentials_file(self.tmp.name, raw=b"[" * 30000 + b"]" * 30000)
        with fakes.Fake() as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_CREDENTIALS_FILE=path))
        self.assert_error(line, code, step="secrets", code="config")

    def test_missing_credentials_file(self):
        with fakes.Fake() as fake:
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_CREDENTIALS_FILE=os.path.join(self.tmp.name, "absent")))
        self.assert_error(line, code, step="secrets", code="config")

    def test_local_mode_is_loopback_only(self):
        with fakes.Fake(iap=False) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_BASE_URL="https://ops.example.com"), use_iap=False)
        self.assert_error(line, code, step="config", code="config")

    def test_local_mode_sends_no_iap_token(self):
        with fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
            env = self.env(fake)
            del env["SYNTHETICS_IAP_AUDIENCE"]
            line, code = self.run_journey("staff-sign-in", env, use_iap=False)
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertNotIn("iap_token", line["steps_ms"])
        self.assertNotIn("metadata", fake.routes())
        self.assertTrue(all(r["proxy_authorization"] is None for r in fake.requests))

    def test_paused_sends_nothing(self):
        for value in ("1", "true", "TRUE", "yes"):
            with self.subTest(value=value), fakes.Fake() as fake:
                line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_PAUSED=value))
                self.assertEqual((line["outcome"], line["code"], line["step"], line["status_class"], code),
                                 ("skipped", "paused", "none", "none", 0))
                self.assertEqual(line["steps_ms"], {})
                self.assertEqual(fake.requests, [])
                self.assertEqual(fake.connections, [], "not even the warm-up's")

    def test_paused_false_runs(self):
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_PAUSED="false"))
        self.assertEqual((line["outcome"], code), ("pass", 0))

    def test_a_runner_crash_is_an_error_line_says_nothing_and_exits_non_zero(self):
        def boom(run, env, **kwargs):
            run.step = "me"
            raise RuntimeError(f"{fakes.PASSWORD} {fakes.SESSION}")

        original = journeys.JOURNEYS["staff-sign-in"]
        journeys.JOURNEYS["staff-sign-in"] = boom
        try:
            with fakes.Fake() as fake:
                line, code = self.run_journey("staff-sign-in", self.env(fake))
        finally:
            journeys.JOURNEYS["staff-sign-in"] = original
        self.assert_error(line, code, step="me", code="runner")

    def test_a_line_that_cannot_be_written_exits_non_zero(self):
        class Broken(io.StringIO):
            def write(self, _text):
                raise BrokenPipeError

        for fail in ({}, {"login": 401}):
            with self.subTest(fail=fail), fakes.Fake(fail=fail, clock=lambda: FIXED_NOW) as fake:
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    code = cli.run("staff-sign-in", self.env(fake), use_iap=True, stream=Broken(),
                                   tools=Tools(now=lambda: FIXED_NOW, sleep=lambda _s: None))
                self.assertEqual((code, err.getvalue()), (1, ""))


class OpsDesk(Case):
    def test_pass(self):
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("ops-desk", self.env(fake, SYNTHETICS_PORTAL_BASE_URL=""))
        self.assertEqual((line["job"], line["outcome"], line["code"], code), ("ops-desk", "pass", "ok", 0))
        self.assertEqual(fake.routes(), J2_ROUTES)
        self.assertEqual(fake.requests[-2]["query"], {"scope": ["employers"]})

    def test_each_step_failing(self):
        for route in ("login", "mfa_verify", "live_queue", "desk_version_employers", "logout"):
            with self.subTest(step=route), fakes.Fake(fail={route: 500}, clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_journey("ops-desk", self.env(fake))
                self.assert_failed(line, code, step=route, code="status", status_class="5xx")
                if route in ("live_queue", "desk_version_employers"):
                    self.assertEqual(fake.routes()[-1], "logout")


class Crm(Case):
    def test_off_by_default_never_fails(self):
        for value in (None, "", "0", "false"):
            with self.subTest(value=value), fakes.Fake() as fake:
                env = self.env(fake, SYNTHETICS_CRM_ENABLED=value)
                del env["SYNTHETICS_BASE_URL"]  # not even configuration is read
                line, code = self.run_journey("crm", env)
                self.assertEqual((line["outcome"], line["code"], line["step"], code),
                                 ("skipped", "not_configured", "none", 0))
                self.assertEqual(fake.requests, [])

    def test_pass_when_switched_on(self):
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("crm", self.env(fake, SYNTHETICS_CRM_ENABLED="1"))
        self.assertEqual((line["job"], line["outcome"], code), ("crm", "pass", 0))
        self.assertEqual(list(line["steps_ms"]), J3_STEPS)
        self.assertEqual(fake.routes(), J3_ROUTES)
        by_route = {r["route"]: r for r in fake.requests}
        self.assertIsNone(by_route["crm_shell"]["authorization"])
        self.assertEqual(by_route["crm_me"]["authorization"], f"Bearer {fakes.CRM_TOKEN}")
        self.assertEqual(by_route["crm_me"]["proxy_authorization"], f"Bearer {fakes.IAP_TOKEN}")
        self.assertIsNone(by_route["crm_me"]["tenant"])
        # The portal's boot read, in the one business me named, with the CRM's bearer
        # beside IAP's token.
        self.assertEqual(by_route["crm_tenant"]["tenant"], fakes.CRM_TENANT_ID)
        self.assertEqual(by_route["crm_tenant"]["authorization"], f"Bearer {fakes.CRM_TOKEN}")
        self.assertEqual(by_route["crm_tenant"]["proxy_authorization"], f"Bearer {fakes.IAP_TOKEN}")
        self.assertEqual(by_route["crm_tenant"]["method"], "GET")

    def test_the_tenant_read_failing_still_signs_out(self):
        for behaviour, expected, status_class in [(500, "status", "5xx"), ("deep_json", "shape", "2xx"),
                                                  ("hang", "timeout", "none")]:
            with self.subTest(behaviour=behaviour), fakes.Fake(fail={"crm_tenant": behaviour},
                                                               clock=lambda: FIXED_NOW) as fake:
                env = self.env(fake, SYNTHETICS_CRM_ENABLED="1", SYNTHETICS_STEP_TIMEOUT_S="0.5")
                line, code = self.run_journey("crm", env)
                self.assert_failed(line, code, step="crm_tenant", code=expected, status_class=status_class)
                self.assertEqual(fake.routes()[-1], "crm_logout")
                self.assertEqual(fake.requests[-1]["authorization"], f"Bearer {fakes.CRM_TOKEN}")

    def test_a_me_that_names_no_usable_business_fails_and_signs_out(self):
        for behaviour in ("no_memberships", "bad_tenant"):
            with self.subTest(behaviour=behaviour), fakes.Fake(fail={"crm_me": behaviour},
                                                               clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_journey("crm", self.env(fake, SYNTHETICS_CRM_ENABLED="1"))
                self.assert_failed(line, code, step="me", code="shape", status_class="2xx")
                self.assertNotIn("crm_tenant", fake.routes(), "nothing from a bad id is ever sent")
                self.assertEqual(fake.routes()[-1], "crm_logout")

    def test_a_widened_login_trips_the_wire_and_still_signs_out(self):
        """Exactly one business, as a plain member with no book, or the run fails: a
        widened robot is one whose leaked secret reads more than it did."""
        for behaviour in ("two_businesses", "admin", "partner", "lattice_role", "no_partner_field"):
            with self.subTest(behaviour=behaviour), fakes.Fake(fail={"crm_me": behaviour},
                                                               clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_journey("crm", self.env(fake, SYNTHETICS_CRM_ENABLED="1"))
                self.assert_failed(line, code, step="me", code="shape", status_class="2xx")
                self.assertNotIn("crm_tenant", fake.routes())
                self.assertEqual(fake.routes()[-1], "crm_logout")
                self.assertEqual(fake.requests[-1]["authorization"], f"Bearer {fakes.CRM_TOKEN}")

    def test_a_login_that_lost_its_second_factor_fails_and_ends_the_session_it_was_handed(self):
        with fakes.Fake(fail={"crm_login": "password_only"}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("crm", self.env(fake, SYNTHETICS_CRM_ENABLED="1"))
        self.assert_failed(line, code, step="login", code="shape", status_class="2xx")
        self.assertEqual(fake.routes(), ["metadata", "crm_shell", "crm_login", "crm_logout"])
        self.assertEqual(fake.requests[-1]["authorization"], f"Bearer {fakes.CRM_TOKEN}")
        self.assertEqual(fake.codes_received, [], "no code is spent on it")

    def test_any_exception_after_sign_in_still_signs_out(self):
        with fakes.Fake(fail={"crm_me": "deep_json"}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("crm", self.env(fake, SYNTHETICS_CRM_ENABLED="1"))
        self.assert_failed(line, code, step="me", code="shape", status_class="2xx")
        self.assertEqual(fake.routes()[-1], "crm_logout")
        self.assertEqual(fake.requests[-1]["authorization"], f"Bearer {fakes.CRM_TOKEN}")

    def test_me_failing_still_signs_out(self):
        with fakes.Fake(fail={"crm_me": 502}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("crm", self.env(fake, SYNTHETICS_CRM_ENABLED="1"))
        self.assert_failed(line, code, step="me", code="status", status_class="5xx")
        self.assertEqual(fake.routes()[-1], "crm_logout")


class Egress(Case):
    """The warm-up: two fresh TCP connections in a row to every host and port, before anything is
    read or sent, inside its own budget, which the run's deadline never pays for."""

    def test_ready_after_failures_then_two_in_a_row(self):
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            net = Network({fake.port: [False, False, False, True, True]})
            line, code = self.run_journey("ops-desk", self.env(fake), tools=net.tools())
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertEqual(list(line["steps_ms"])[:3], ["config", "egress", "secrets"])
        self.assertEqual(net.connects, [(fake.port, 3.0)] * 5, "a fresh 3 s connection each time")
        self.assertEqual(net.pauses, [1.0] * 4, "a pause between rounds, none after the last")
        self.assertEqual(fake.routes(), J2_ROUTES)

    def test_a_success_then_a_failure_starts_over(self):
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            net = Network({fake.port: [True, False, True, False, True, True]})
            line, code = self.run_journey("ops-desk", self.env(fake), tools=net.tools())
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertEqual(len(net.connects), 6, "ready at the first two in a row, and no sooner")

    def test_never_two_in_a_row_is_never_ready(self):
        with fakes.Fake() as fake:
            net = Network({fake.port: [True, False] * 50})
            line, code = self.run_journey("ops-desk", self.env(fake, SYNTHETICS_EGRESS_WAIT_S="30"),
                                          tools=net.tools())
        self.assert_error(line, code, step="egress", code="egress")
        self.assertGreater(net.connects.count((fake.port, 3.0)), 6)

    def test_every_host_and_port_needs_two_in_a_row(self):
        # J1 with its portal on another port: the ops host is ready at once, the portal only later.
        with fakes.Fake(clock=lambda: FIXED_NOW) as ops, fakes.Fake() as portal:
            net = Network({ops.port: [True, True], portal.port: [False, True, False, False, True, True]})
            line, code = self.run_journey("staff-sign-in", self.env(ops, SYNTHETICS_PORTAL_BASE_URL=portal.base),
                                          tools=net.tools())
        self.assertEqual((line["outcome"], code), ("pass", 0))
        ports = [port for port, _timeout in net.connects]
        self.assertEqual(ports.count(ops.port), 2, "a ready host is not asked again")
        self.assertEqual(ports.count(portal.port), 6)
        self.assertEqual(portal.routes(), ["portal_shell"])

    def test_one_origin_is_one_host_and_port(self):
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            net = Network()
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_PORTAL_BASE_URL=fake.base),
                                          tools=net.tools())
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertEqual(len(net.connects), 2)

    def test_out_of_budget_is_an_error_that_sends_and_reads_nothing(self):
        # A credentials file that is not there: had it been read, the run would be error / config at secrets.
        absent = os.path.join(self.tmp.name, "absent")
        with fakes.Fake() as fake:
            net = Network(then=False)
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_CREDENTIALS_FILE=absent),
                                          tools=net.tools())
        self.assert_error(line, code, step="egress", code="egress")
        self.assertEqual(list(line["steps_ms"]), ["config", "egress"])
        self.assertEqual(fake.requests, [], "no metadata call, no request")
        self.assertTrue(all(timeout <= 3.0 for _port, timeout in net.connects))

    def test_the_budget(self):
        # 3.5: one attempt (3 s), then a pause cut to the half second left.
        for value, budget in [(None, 120.0), ("170", 170.0), ("2.5", 2.5), ("3.5", 3.5)]:
            with self.subTest(value=value), fakes.Fake() as fake:
                net = Network(then=False)
                line, code = self.run_journey("ops-desk", self.env(fake, SYNTHETICS_EGRESS_WAIT_S=value),
                                              tools=net.tools())
                self.assert_error(line, code, step="egress", code="egress")
                self.assertAlmostEqual(net.spent(), budget, msg="the whole budget, and not a moment past it")

    def test_nothing_listening_is_an_error_once_the_budget_is_spent(self):
        # Real sockets, a real clock and real pauses.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        with fakes.Fake() as fake:
            started = time.monotonic()
            line, code = self.run_journey("ops-desk", self.env(
                fake, SYNTHETICS_BASE_URL=f"http://127.0.0.1:{closed}", SYNTHETICS_EGRESS_WAIT_S="1.5"),
                tools=Tools(now=lambda: FIXED_NOW))
            took = time.monotonic() - started
        self.assert_error(line, code, step="egress", code="egress")
        self.assertGreaterEqual(line["steps_ms"]["egress"], 1400)
        self.assertLess(took, 3)
        self.assertEqual(fake.requests, [])

    def test_zero_skips_it(self):
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            net = Network()
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_EGRESS_WAIT_S="0"),
                                          tools=net.tools())
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertEqual(list(line["steps_ms"]), [step for step in J1_STEPS if step != "egress"])
        self.assertEqual((net.connects, net.pauses), ([], []))

    def test_a_paused_run_writes_its_line_before_any_warm_up(self):
        # tpa-platform's runbook relies on it: paused, the run answers at once, however long the path would take.
        with fakes.Fake() as fake:
            net = Network(then=False)
            line, code = self.run_journey("staff-sign-in", self.env(fake, SYNTHETICS_PAUSED="true"), tools=net.tools())
        self.assertEqual((line["outcome"], line["code"], line["step"], line["steps_ms"], code),
                         ("skipped", "paused", "none", {}, 0))
        self.assertEqual((net.connects, net.pauses, net.spent()), ([], [], 0))
        self.assertEqual((fake.requests, fake.connections), ([], []))

    def test_none_when_switched_off_or_misconfigured(self):
        for job, extra in [("crm", {}), ("staff-sign-in", {"SYNTHETICS_EMAIL": "no-at-sign"})]:
            with self.subTest(job=job, extra=extra), fakes.Fake() as fake:
                net = Network()
                line, _code = self.run_journey(job, self.env(fake, **extra), tools=net.tools())
                self.assertIn(line["code"], ("not_configured", "config"))
                self.assertNotIn("egress", line["steps_ms"])
                self.assertEqual((net.connects, net.pauses), ([], []))
                self.assertEqual(fake.requests, [])

    def test_the_deadline_starts_after_it(self):
        # 100 s of the warm-up's 120 spent before the path answers; the journey still has its whole 5 s.
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            net = Network({fake.port: [False] * 25})
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_PORTAL_BASE_URL=fake.base, SYNTHETICS_DEADLINE_S="5"), tools=net.tools())
        self.assertGreater(net.spent(), 100)
        self.assertEqual((line["outcome"], line["code"], code), ("pass", "ok", 0))

    def test_the_deadline_starts_after_it_on_the_real_clock(self):
        # Real time and pauses: a path that answers only after 2 s, then a 1.5 s deadline the warm-up never touches.
        with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
            started = time.monotonic()

            def connect(_family, _address, _timeout):
                if time.monotonic() - started < 2:
                    time.sleep(0.3)
                    raise TimeoutError

            line, code = self.run_journey("ops-desk", self.env(fake, SYNTHETICS_DEADLINE_S="1.5"),
                                          tools=Tools(now=lambda: FIXED_NOW, connect=connect))
        self.assertEqual((line["outcome"], line["code"], code), ("pass", "ok", 0))
        self.assertGreaterEqual(line["steps_ms"]["egress"], 2000)
        self.assertEqual(fake.routes(), J2_ROUTES)

    def test_no_name_is_looked_up_once_the_budget_is_spent(self):
        # J1 on two ports: the ops host's attempt spends the whole budget, so the portal's name is never resolved.
        original = journeys.client.resolve
        asked = []

        def counted(host, port):
            asked.append(port)
            return original(host, port)

        journeys.client.resolve = counted
        try:
            with fakes.Fake() as ops, fakes.Fake() as portal:
                net = Network(then=False)
                line, code = self.run_journey("staff-sign-in", self.env(
                    ops, SYNTHETICS_PORTAL_BASE_URL=portal.base, SYNTHETICS_EGRESS_WAIT_S="2.5"), tools=net.tools())
        finally:
            journeys.client.resolve = original
        self.assert_error(line, code, step="egress", code="egress")
        self.assertEqual(asked, [ops.port])
        self.assertEqual(net.connects, [(ops.port, 2.5)])

    def test_a_name_that_does_not_resolve_is_resolved_again_then_kept(self):
        original = journeys.client.resolve
        asked = []

        def flaky(host, port):
            asked.append((host, port))
            if len(asked) <= 2:
                raise socket.gaierror(socket.EAI_AGAIN, "sentinel")
            return original(host, port)

        journeys.client.resolve = flaky
        try:
            with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
                net = Network()
                line, code = self.run_journey("ops-desk", self.env(fake), tools=net.tools())
        finally:
            journeys.client.resolve = original
        self.assertEqual((line["outcome"], code), ("pass", 0))
        # The warm-up's three (two failed, then kept for good), then one per connection the client dials.
        self.assertEqual(asked, [("127.0.0.1", fake.port)] * (3 + len(J2_ROUTES)))
        self.assertEqual(len(net.connects), 2)


class Connect(Case):
    """Every connection dialled with a fresh socket until it connects or the step's time is spent; every
    request written once, whatever happens after (beta, 2026-10-12: a connection opened after the warm-up
    could still be dropped)."""

    def test_a_request_lands_once_after_connects_that_failed(self):
        # J2's connections in order: the metadata server's, login's, mfa_verify's, ...
        for name, errors, extra in [("login, timed out twice", [None, TimeoutError, TimeoutError], 2),
                                    ("mfa_verify, refused three times",
                                     [None, None, ConnectionRefusedError, ConnectionRefusedError,
                                      ConnectionRefusedError], 3)]:
            with self.subTest(name), fakes.Fake(clock=lambda: FIXED_NOW) as fake:
                with dialling(failing_first(errors)) as timeouts:
                    line, code = self.run_journey("ops-desk", self.env(fake))
                self.assertEqual((line["outcome"], code), ("pass", 0))
                self.assertEqual(fake.routes(), J2_ROUTES, "each request sent once")
                self.assertEqual(len(timeouts), len(J2_ROUTES) + extra)
                self.assertEqual(len(fake.codes_received), 1)

    def test_a_request_is_never_written_twice(self):
        # The sign-in, the code and the sign-out, each answered by nothing or a dropped connection.
        for route, behaviour, expected in [("login", "hang", "timeout"), ("login", "drop", "connect"),
                                           ("mfa_verify", "hang", "timeout"), ("mfa_verify", "drop", "connect"),
                                           ("logout", "hang", "timeout"), ("logout", "drop", "connect")]:
            with self.subTest(route=route, behaviour=behaviour), fakes.Fake(
                    fail={route: behaviour}, clock=lambda: FIXED_NOW, hang_s=1.5) as fake:
                line, code = self.run_journey("ops-desk", self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="0.5"))
                self.assert_failed(line, code, step=route, code=expected, status_class="none")
                self.assertEqual(fake.routes().count(route), 1)
                self.assertLessEqual(len(fake.codes_received), 1)

    def test_the_step_bounds_every_attempt(self):
        # Local mode (no metadata call): login's every attempt is never answered and spends its whole timeout.
        def stalled(address, timeout, real):
            time.sleep(timeout)
            raise TimeoutError

        with fakes.Fake(iap=False) as fake:
            started = time.monotonic()
            with dialling(stalled) as timeouts:
                line, code = self.run_journey("ops-desk", self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="3.6"),
                                              use_iap=False)
            took = time.monotonic() - started
        self.assert_failed(line, code, step="login", code="timeout", status_class="none")
        self.assertEqual(len(timeouts), 2)
        self.assertEqual(timeouts[0], 3.0, "an attempt waits 3 s at most")
        self.assertLess(timeouts[1], 0.2, "then only what the step has left, after a half-second pause")
        self.assertLess(took, 4.5)
        self.assertEqual(fake.requests, [])

    def test_an_answer_has_the_rest_of_the_step_not_an_attempts_3_s(self):
        # The connected socket's timeout is what the step has left: a 3.5 s answer inside a 5 s step is a pass.
        with fakes.Fake(fail={"live_queue": "hang"}, hang_s=3.5, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_journey("ops-desk", self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="5"))
        self.assertEqual((line["outcome"], line["code"], code), ("pass", "ok", 0))
        self.assertGreaterEqual(line["steps_ms"]["live_queue"], 3500)

    def test_a_connection_made_too_late_is_closed(self):
        # Connected only after the step's half second: closed, never written to, and the step times out.
        made = []

        def late(address, timeout, real):
            sock = real(address, timeout)
            made.append(sock)
            time.sleep(0.6)
            return sock

        with fakes.Fake(iap=False) as fake:
            with dialling(late):
                line, code = self.run_journey("ops-desk", self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="0.5"),
                                              use_iap=False)
        self.assert_failed(line, code, step="login", code="timeout", status_class="none")
        self.assertEqual(len(made), 1)
        self.assertEqual(made[0].fileno(), -1, "closed, not left open")
        self.assertEqual(fake.requests, [])

    def test_a_hosts_addresses_are_tried_in_turn(self):
        # The name resolves to a refused address first: the next one connects, and each request goes once.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        real = client.resolve
        client.resolve = lambda host, port: [(socket.AF_INET, ("127.0.0.1", closed))] + real(host, port)
        try:
            with fakes.Fake(clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_journey("ops-desk", self.env(fake))
        finally:
            client.resolve = real
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertEqual(fake.routes(), J2_ROUTES)

    def test_one_attempt_shares_its_time_across_the_addresses(self):
        # Two addresses: the first refuses after 1 s, the second is never answered. The second has the
        # attempt's 2 s left, not 3 s of its own, and the step's 3.6 s is never overrun.
        opened = []

        def opening(family, address, timeout):
            opened.append((address[1], timeout))
            if address[1] == 1:
                time.sleep(min(1.0, timeout))
                raise ConnectionRefusedError if timeout > 1.0 else TimeoutError
            time.sleep(timeout)
            raise TimeoutError

        real_resolve, real_open = client.resolve, client._open
        client.resolve = lambda host, port: [(socket.AF_INET, ("127.0.0.1", 1)), (socket.AF_INET, ("127.0.0.1", 2))]
        client._open = opening
        try:
            with fakes.Fake(iap=False) as fake:
                started = time.monotonic()
                line, code = self.run_journey("ops-desk", self.env(
                    fake, SYNTHETICS_STEP_TIMEOUT_S="3.6", SYNTHETICS_EGRESS_WAIT_S="0"), use_iap=False)
                took = time.monotonic() - started
        finally:
            client.resolve, client._open = real_resolve, real_open
        self.assert_failed(line, code, step="login", code="timeout", status_class="none")
        self.assertEqual([port for port, _timeout in opened], [1, 2, 1])
        self.assertAlmostEqual(opened[0][1], 3.0, delta=0.01)
        self.assertAlmostEqual(opened[1][1], 2.0, delta=0.1)
        self.assertLess(opened[2][1], 0.2)
        self.assertLess(took, 4.5)
        self.assertEqual(fake.requests, [])

    def test_a_code_is_never_sent_after_auth_would_refuse_it(self):
        # A 60 s step, but the code has 1 s of accepted life left: its connection, never answered, fails
        # `timeout` inside that second, and the code is never sent (a stale one costs a lockout strike).
        for job, nth, extra in [("ops-desk", 2, {}), ("crm", 3, {"SYNTHETICS_CRM_ENABLED": "1"})]:
            calls = []

            def attempt(address, timeout, real):
                calls.append(timeout)
                if len(calls) == nth:  # local mode: J2's login then mfa_verify; J3's shell, login, mfa_verify
                    time.sleep(timeout)
                    raise TimeoutError
                return real(address, timeout)

            real_accepted_for = journeys.totp.accepted_for
            journeys.totp.accepted_for = lambda _now: 1.0
            try:
                with self.subTest(job=job), fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
                    started = time.monotonic()
                    with dialling(attempt):
                        line, code = self.run_journey(job, self.env(fake, SYNTHETICS_STEP_TIMEOUT_S="60", **extra),
                                                      use_iap=False)
                    took = time.monotonic() - started
                    self.assert_failed(line, code, step="mfa_verify", code="timeout", status_class="none")
                    self.assertEqual(fake.codes_received, [])
                    self.assertLessEqual(calls[nth - 1], 1.0)
                    self.assertLess(took, 3)
            finally:
                journeys.totp.accepted_for = real_accepted_for


class EntryPoint(Case):
    """The real entry point, as the job runs it: a child process with a real clock."""

    def spawn(self, fake: fakes.Fake, *args: str, **extra: str) -> tuple[dict, int]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("SYNTHETICS_")}
        env.update(self.env(fake, **extra))
        env["PYTHONPATH"] = str(ROOT)
        done = subprocess.run([sys.executable, "-m", "synthetics", "journey", *args], env=env,
                              capture_output=True, text=True, timeout=60, cwd=self.tmp.name)
        return self.parse_clean(done.stdout, done.stderr), done.returncode

    def test_pass(self):
        with fakes.Fake() as fake:
            line, code = self.spawn(fake, "staff-sign-in")
            self.assert_silent(fake, 4)
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertEqual(list(line["steps_ms"]), J1_STEPS)
        self.assert_no_received_code_printed(fake, line)

    def test_a_failing_journey_exits_zero_with_outcome_fail(self):
        for fail, step, expected, status_class in [({"login": 401}, "login", "credentials", "4xx"),
                                                   ({"desk_version": 503}, "desk_version", "status", "5xx")]:
            with self.subTest(step=step), fakes.Fake(fail=fail) as fake:
                line, code = self.spawn(fake, "staff-sign-in")
                self.assert_failed(line, code, step=step, code=expected, status_class=status_class)

    def test_bad_credentials_file_is_an_error_and_exits_non_zero(self):
        path = credentials_file(self.tmp.name, raw=f'{{"password": "{fakes.PASSWORD}"}}'.encode())
        with fakes.Fake() as fake:
            line, code = self.spawn(fake, "ops-desk", SYNTHETICS_CREDENTIALS_FILE=path)
        self.assert_error(line, code, step="secrets", code="config")

    def test_a_runner_crash_exits_non_zero_with_an_error_line(self):
        # The real exit path (main, then sys.exit), with a journey that raises.
        crash = (
            "import sys; from synthetics import journeys, __main__ as cli\n"
            "def boom(run, env, **kwargs):\n"
            "    run.step = 'login'\n"
            f"    raise KeyError('{fakes.PASSWORD}')\n"
            "journeys.JOURNEYS['staff-sign-in'] = boom\n"
            "sys.exit(cli.main(['journey', 'staff-sign-in']))\n"
        )
        with fakes.Fake() as fake:
            env = {k: v for k, v in os.environ.items() if not k.startswith("SYNTHETICS_")}
            env.update(self.env(fake), PYTHONPATH=str(ROOT))
            done = subprocess.run([sys.executable, "-c", crash], env=env, capture_output=True, text=True,
                                  timeout=30, cwd=self.tmp.name)
        line = self.parse_clean(done.stdout, done.stderr)
        self.assert_error(line, done.returncode, step="login", code="runner")
        self.assertEqual(fake.requests, [])

    def test_skips_exit_zero(self):
        with fakes.Fake() as fake:
            line, code = self.spawn(fake, "crm")
            self.assertEqual((line["outcome"], line["code"], code), ("skipped", "not_configured", 0))
            line, code = self.spawn(fake, "staff-sign-in", SYNTHETICS_PAUSED="1")
            self.assertEqual((line["outcome"], line["code"], code), ("skipped", "paused", 0))

    def test_a_paused_run_answers_at_once_before_any_warm_up(self):
        # The real process and clock, a path that never comes up and the warm-up's 120 s: the line comes first.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        with fakes.Fake() as fake:
            started = time.monotonic()
            line, code = self.spawn(fake, "ops-desk", SYNTHETICS_PAUSED="true", SYNTHETICS_EGRESS_WAIT_S="120",
                                    SYNTHETICS_BASE_URL=f"http://127.0.0.1:{closed}")
            took = time.monotonic() - started
        self.assertEqual((line["outcome"], line["code"], line["steps_ms"], code), ("skipped", "paused", {}, 0))
        self.assertLess(took, 10)

    def test_bad_command_line_exits_two_and_prints_no_result(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        done = subprocess.run([sys.executable, "-m", "synthetics", "journey", "nope"], env=env,
                              capture_output=True, text=True, timeout=30, cwd=self.tmp.name)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")

    def test_isolated_mode_imports_nothing_from_the_working_directory(self):
        # The image runs `python -I -m synthetics`; the package must import cleanly and do nothing.
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        done = subprocess.run([sys.executable, "-c", "import synthetics, synthetics.journeys, synthetics.__main__"],
                              env=env, capture_output=True, text=True, timeout=30, cwd=self.tmp.name)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))



# --- the sign-in robots -------------------------------------------------------------

ROBOT_STEPS = ["config", "egress", "secrets", "portal_shell", "portal_release", "portal_bundle", "login",
               "mfa_verify", "me", "logout"]
ROBOT_ROUTES = ["portal_shell", "portal_release", "portal_bundle", "login", "mfa_verify", "me", "logout"]


class WallClock:
    """The wall clock and the steady clock a pause moves on, shared by the runner's Tools (its deadline too)
    and the fake auth (a broker's code)."""

    def __init__(self, at: float) -> None:
        self.at = at
        self.steady = 0.0
        self.slept: list[float] = []

    def now(self) -> float:
        return self.at

    def monotonic(self) -> float:
        return self.steady

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.at += seconds
        self.steady += seconds

    def tools(self) -> Tools:
        return Tools(now=self.now, sleep=self.sleep, monotonic=self.monotonic)


def member_credentials(directory: str, origin: str, **changes: object) -> str:
    """The fixture's member secret, on this fake's origin (its rp the fake's host), with `changes` over it."""
    value = json.loads(json.dumps(fakes.MEMBER_CREDENTIALS))
    value["passkey"]["origin"] = origin
    value["passkey"]["rp_id"] = "127.0.0.1"
    for name, changed in changes.items():
        if name.startswith("passkey_"):
            value["passkey"][name[len("passkey_"):]] = changed
        elif changed is None:
            del value[name]
        else:
            value[name] = changed
    path = os.path.join(directory, "member.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle)
    return path


def broker_credentials(directory: str, **changes: object) -> str:
    value = {"email": fakes.BROKER_EMAIL, "password": fakes.BROKER_PASSWORD, "totp_secret": fakes.BROKER_TOTP_SECRET}
    for name, changed in changes.items():
        if changed is None:
            del value[name]
        else:
            value[name] = changed
    path = os.path.join(directory, "broker.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle)
    return path


class RobotCase(Case):
    def robot_env(self, fake: fakes.Fake, job: str, **extra: str) -> dict[str, str]:
        env = {"SYNTHETICS_PORTAL_ORIGIN": fake.base}
        if "SYNTHETICS_CREDENTIALS_FILE" not in extra:
            env["SYNTHETICS_CREDENTIALS_FILE"] = (member_credentials(self.tmp.name, fake.base)
                                                  if job == "member-sign-in" else broker_credentials(self.tmp.name))
        env.update(extra)
        return {k: v for k, v in env.items() if v is not None}

    def run_robot(self, job: str, env: dict[str, str], *, tools: Tools | None = None) -> tuple[dict, int]:
        # Local mode (--no-iap): the fakes are loopback, and the cloud mode takes production's portal alone.
        return self.run_journey(job, env, use_iap=False, tools=tools)

    def assert_skipped(self, line: dict, exit_code: int, code: str) -> None:
        self.assertEqual((line["outcome"], line["code"], line["step"], line["status_class"], line["severity"]),
                         ("skipped", code, "none", "none", "INFO"))
        self.assertEqual(exit_code, 0)

    def assert_signed_out(self, fake: fakes.Fake, session: str) -> None:
        logout = fake.requests[-1]
        self.assertEqual(logout["route"], "logout")
        self.assertEqual(fake.routes().count("logout"), 1)
        self.assertIn(f"__Host-tpa-session={session}", logout["cookie"])
        self.assertEqual((logout["csrf"], logout["origin"]), (fakes.CSRF, fake.base))


class MemberSignIn(RobotCase):
    JOB = "member-sign-in"

    def run_member(self, fake: fakes.Fake, **extra: str) -> tuple[dict, int]:
        return self.run_robot(self.JOB, self.robot_env(fake, self.JOB, **extra))

    def test_pass(self):
        with fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_member(fake)
            self.assert_silent(fake, 2)
        self.assertEqual((line["job"], line["outcome"], line["code"], line["step"], line["status_class"], code),
                         (self.JOB, "pass", "ok", "none", "2xx", 0))
        self.assertEqual(list(line["steps_ms"]), ROBOT_STEPS)
        self.assertEqual(fake.routes(), ROBOT_ROUTES)
        self.assertEqual(fake.refusals, [])
        for request in fake.requests:
            self.assertIsNone(request["proxy_authorization"], "no IAP, ever")
            self.assertIsNone(request["authorization"])
            self.assertEqual(request["sec_fetch_site"], "same-origin")
            self.assertEqual(request["host"], f"127.0.0.1:{fake.port}")
        # X-Client-Release from release.json on every request after it, as the portal's interceptor stamps it.
        self.assertEqual([r["release"] for r in fake.requests],
                         [None, None] + [fakes.RELEASE_ID] * (len(ROBOT_ROUTES) - 2))
        login, verify = fake.requests[3], fake.requests[4]
        self.assertEqual(login["payload"], {"email": fakes.MEMBER_EMAIL, "password": fakes.MEMBER_PASSWORD,
                                            "audience": "member"})
        self.assertEqual((login["origin"], login["content_type"]), (fake.base, "application/json"))
        self.assertEqual(set(verify["payload"]), {"challenge_id", "assertion"})
        self.assertEqual(verify["payload"]["challenge_id"], "chl_sentinel_member")
        self.assertEqual(len(fake.assertions_received), 1)
        self.assertEqual(fake.codes_received, [])
        self.assert_signed_out(fake, fakes.ROBOT_SESSIONS["member"])

    def test_each_step_failing(self):
        for route in ROBOT_ROUTES:
            with self.subTest(step=route), fakes.Fake(iap=False, fail={route: 503}, clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_failed(line, code, step=route, code="status", status_class="5xx")
                routes = fake.routes()
                self.assertEqual(routes[: routes.index(route) + 1], ROBOT_ROUTES[: ROBOT_ROUTES.index(route) + 1])
                self.assertLessEqual(routes.count("login"), 1)
                self.assertLessEqual(routes.count("mfa_verify"), 1)
                if route == "me":
                    self.assert_signed_out(fake, fakes.ROBOT_SESSIONS["member"])
                elif route != "logout":
                    self.assertNotIn("logout", routes)

    def test_switched_off_is_disabled_never_a_failure(self):
        for route, behaviour in [("login", "checks_off"), ("login", "checks_off_code"), ("mfa_verify", "checks_off")]:
            with self.subTest(route=route, behaviour=behaviour), fakes.Fake(
                    iap=False, fail={route: behaviour}, clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_skipped(line, code, "disabled")
                self.assertEqual(fake.refusals, ["sign_in_checks_off"])
                self.assertEqual(fake.routes()[-1], route, "it stops there")
                self.assertNotIn("logout", fake.routes(), "no session was born")
                self.assertIn(route, line["steps_ms"])

    def test_any_other_refusal_is_denied(self):
        for route in ("login", "mfa_verify"):
            with self.subTest(route=route), fakes.Fake(iap=False, fail={route: "audience_not_held"},
                                                       clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_failed(line, code, step=route, code="denied", status_class="4xx")
                self.assertNotIn("logout", fake.routes())
        with fakes.Fake(iap=False, fail={"login": 403}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_member(fake)
        self.assert_failed(line, code, step="login", code="denied", status_class="4xx")

    def test_a_widened_robot_trips_the_wire_stops_and_signs_out(self):
        for behaviour in ("two_tenants", "extra_role", "other_role", "crm_tenant", "sso", "long_session"):
            with self.subTest(behaviour=behaviour), fakes.Fake(iap=False, fail={"me": behaviour},
                                                               clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_failed(line, code, step="me", code="widened", status_class="2xx")
                self.assertEqual(fake.routes(), ROBOT_ROUTES)
                self.assert_signed_out(fake, fakes.ROBOT_SESSIONS["member"])

    def test_a_me_that_is_not_the_robots_session_is_shape(self):
        for behaviour in ("aal1", "other_amr", "must_replace", "other_hat", "other_pin", "no_tenants", "no_absolute",
                          "staff", "deep_json"):
            with self.subTest(behaviour=behaviour), fakes.Fake(iap=False, fail={"me": behaviour},
                                                               clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_failed(line, code, step="me", code="shape", status_class="2xx")
                self.assert_signed_out(fake, fakes.ROBOT_SESSIONS["member"])

    def test_a_login_the_passkey_cannot_answer_is_shape(self):
        for behaviour in ("wrong_rp", "no_options", "bad_challenge", "check_email", "no_factor", "deep_json"):
            with self.subTest(behaviour=behaviour), fakes.Fake(iap=False, fail={"login": behaviour},
                                                               clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_failed(line, code, step="login", code="shape", status_class="2xx")
                self.assertNotIn("mfa_verify", fake.routes())
                self.assertEqual(fake.assertions_received, [])

    def test_a_verify_answer_that_is_not_the_hats_session(self):
        with fakes.Fake(iap=False, fail={"mfa_verify": "no_cookies"}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_member(fake)
        self.assert_failed(line, code, step="mfa_verify", code="shape", status_class="2xx")
        self.assertNotIn("logout", fake.routes())
        for behaviour in ("no_audience", "deep_json"):
            with self.subTest(behaviour=behaviour), fakes.Fake(iap=False, fail={"mfa_verify": behaviour},
                                                               clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_failed(line, code, step="mfa_verify", code="shape", status_class="2xx")
                self.assert_signed_out(fake, fakes.ROBOT_SESSIONS["member"])

    def test_the_portal_steps(self):
        for route, behaviour in [("portal_shell", "no_main_script"), ("portal_shell", "two_main_scripts"),
                                 ("portal_shell", "no_base_href"), ("portal_release", "bad_release"),
                                 ("portal_release", "no_release"), ("portal_release", "not_json"),
                                 ("portal_bundle", "not_js"), ("portal_bundle", "empty")]:
            with self.subTest(route=route, behaviour=behaviour), fakes.Fake(
                    iap=False, fail={route: behaviour}, clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_failed(line, code, step=route, code="shape", status_class="2xx")
                self.assertNotIn("login", fake.routes(), "no password is sent past a broken portal")
                self.assertNotIn("X-Injected", json.dumps(fake.requests))

    def test_sign_in_refusals(self):
        for route, status, expected in [("login", 401, "credentials"), ("login", 423, "locked"),
                                        ("login", 429, "rate_limited"), ("mfa_verify", 401, "credentials"),
                                        ("mfa_verify", 410, "status")]:
            with self.subTest(route=route, status=status), fakes.Fake(iap=False, fail={route: status},
                                                                      clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
                self.assert_failed(line, code, step=route, code=expected, status_class="4xx")
                self.assertEqual(fake.routes().count("login"), 1, "one password per run, never retried")
                self.assertLessEqual(fake.routes().count("mfa_verify"), 1)
                self.assertNotIn("logout", fake.routes())

    def test_a_key_auth_does_not_hold_is_credentials(self):
        other = ec.generate_private_key(ec.SECP256R1()).private_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "x": fakes.b64url(other.public_numbers.x.to_bytes(32, "big")),
               "y": fakes.b64url(other.public_numbers.y.to_bytes(32, "big")),
               "d": fakes.b64url(other.private_value.to_bytes(32, "big"))}
        with fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
            env = self.robot_env(fake, self.JOB)
            env["SYNTHETICS_CREDENTIALS_FILE"] = member_credentials(self.tmp.name, fake.base, passkey_private_jwk=jwk)
            line, code = self.run_robot(self.JOB, env)
        self.assert_failed(line, code, step="mfa_verify", code="credentials", status_class="4xx")
        self.assertEqual(fake.refusals, ["malformed or unsigned"])

    def test_the_wrong_password_is_credentials(self):
        with fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
            env = self.robot_env(fake, self.JOB)
            env["SYNTHETICS_CREDENTIALS_FILE"] = member_credentials(self.tmp.name, fake.base, password="not-it")
            line, code = self.run_robot(self.JOB, env)
        self.assert_failed(line, code, step="login", code="credentials", status_class="4xx")

    def test_a_signature_that_cannot_be_made_is_the_runners_error(self):
        original = journeys.passkey.assertion

        def unsigned(*_args):
            raise journeys.passkey.Unsigned("sentinel")

        journeys.passkey.assertion = unsigned
        try:
            with fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake)
        finally:
            journeys.passkey.assertion = original
        self.assert_error(line, code, step="mfa_verify", code="passkey")
        self.assertNotIn("mfa_verify", fake.routes())

    def test_two_runs_back_to_back_with_the_counter_at_zero(self):
        # auth admits zero against zero for ever; the fake stores each verified count, as auth does.
        with fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
            first, _ = self.run_member(fake)
            second, _ = self.run_member(fake)
        self.assertEqual((first["outcome"], second["outcome"]), ("pass", "pass"))
        self.assertEqual((len(fake.assertions_received), fake.member_key["sign_count"]), (2, 0))

    def test_a_counter_that_never_rose_is_refused_the_second_time(self):
        # Why the count is zero and never anything else: a robot cannot remember a count between runs, and auth
        # reads a repeated non-zero count as a cloned key (it revokes the credential; the fake refuses it).
        original = journeys.passkey.SIGN_COUNT
        journeys.passkey.SIGN_COUNT = 1
        try:
            with fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
                first, _ = self.run_member(fake)
                second, code = self.run_member(fake)
        finally:
            journeys.passkey.SIGN_COUNT = original
        self.assertEqual(first["outcome"], "pass")
        self.assert_failed(second, code, step="mfa_verify", code="credentials", status_class="4xx")
        self.assertEqual(fake.refusals, ["counter"])

    def test_logout_refused_is_csrf(self):
        with fakes.Fake(iap=False, fail={"logout": 403}, clock=lambda: FIXED_NOW) as fake:
            line, code = self.run_member(fake)
        self.assert_failed(line, code, step="logout", code="csrf", status_class="4xx")
        self.assertEqual(fake.routes().count("logout"), 1)

    def test_iap_never_asked(self):
        def no_token(*_args, **_kwargs):
            raise AssertionError("the robots never ask the metadata server")

        original = journeys.iap.fetch_id_token
        journeys.iap.fetch_id_token = no_token
        try:
            with fakes.Fake(iap=False, clock=lambda: FIXED_NOW) as fake:
                line, code = self.run_member(fake, SYNTHETICS_IAP_AUDIENCE=fakes.AUDIENCE,
                                             SYNTHETICS_METADATA_HOST=fake.metadata_host)
        finally:
            journeys.iap.fetch_id_token = original
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertNotIn("metadata", fake.routes())


class BrokerSignIn(RobotCase):
    JOB = "broker-sign-in"
    #: Just after a step began: a run that minted at once would have most of the step left.
    START = FIXED_NOW

    def run_broker(self, fake: fakes.Fake, clock: WallClock, **extra: str) -> tuple[dict, int]:
        return self.run_robot(self.JOB, self.robot_env(fake, self.JOB, **extra), tools=clock.tools())

    def test_pass_with_the_next_steps_code(self):
        clock = WallClock(self.START)
        with fakes.Fake(iap=False, clock=clock.now) as fake:
            line, code = self.run_broker(fake, clock)
        self.assertEqual((line["job"], line["outcome"], line["code"], code), (self.JOB, "pass", "ok", 0))
        self.assertEqual(list(line["steps_ms"]), ROBOT_STEPS)
        self.assertEqual(fake.routes(), ROBOT_ROUTES)
        self.assertEqual(fake.requests[3]["payload"], {"email": fakes.BROKER_EMAIL, "password": fakes.BROKER_PASSWORD,
                                                       "audience": "broker"})
        self.assertEqual(set(fake.requests[4]["payload"]), {"challenge_id", "code"})
        started = int(self.START // 30)
        # It waited for the step after the one it asked in, and sent that step's code.
        self.assertEqual(fake.codes_received, [fakes.totp_code(fakes.BROKER_TOTP_SECRET, started + 1)])
        self.assertEqual(fake.last_step, {"broker": started + 1})
        # The last pause is that wait (the warm-up's pauses before it moved the clock too).
        self.assertAlmostEqual(clock.slept[-1], totp.wait_for_fresh(self.START + sum(clock.slept[:-1])), places=6)
        self.assertGreater(clock.slept[-1], 25)
        self.assert_no_received_code_printed(fake, line)
        self.assert_signed_out(fake, fakes.ROBOT_SESSIONS["broker"])

    def test_two_runs_back_to_back_never_send_one_code_twice(self):
        # The second starts the moment the first ends (a hand-started run after the schedule's, say): auth
        # refuses a step at or below the last it accepted, and the second never sends one.
        clock = WallClock(self.START)
        with fakes.Fake(iap=False, clock=clock.now) as fake:
            first, _ = self.run_broker(fake, clock)
            second, _ = self.run_broker(fake, clock)
        self.assertEqual((first["outcome"], second["outcome"]), ("pass", "pass"))
        self.assertEqual(len(set(fake.codes_received)), 2)
        self.assertEqual(fake.refusals, [])

    def test_the_wait_is_what_keeps_a_code_from_being_sent_twice(self):
        # The fake refuses a replayed step as auth does: minting at once, the second run would fail.
        original = journeys.totp.fresh

        def at_once(secret, *, now, sleep, budget):
            return totp.code_at(totp.decode_base32(secret), totp.step_at(now()))

        journeys.totp.fresh = at_once
        try:
            clock = WallClock(self.START)
            with fakes.Fake(iap=False, clock=clock.now) as fake:
                first, _ = self.run_broker(fake, clock)
                second, code = self.run_broker(fake, clock)
        finally:
            journeys.totp.fresh = original
        self.assertEqual(first["outcome"], "pass")
        self.assert_failed(second, code, step="mfa_verify", code="credentials", status_class="4xx")
        self.assertEqual(fake.refusals, ["replayed"])

    def test_the_wait_comes_out_of_the_deadline(self):
        clock = WallClock(self.START)
        with fakes.Fake(iap=False, clock=clock.now) as fake:
            line, code = self.run_broker(fake, clock, SYNTHETICS_DEADLINE_S="60")
        self.assertEqual((line["outcome"], code), ("pass", 0))
        self.assertGreater(clock.steady, 25, "the wait was the deadline's time")

    def test_no_room_for_the_wait_sends_no_password(self):
        # 40 s left before login: less than the longest wait and a send either side (30.2 + 2 x 10), so not even
        # the password goes, and nothing is waited for.
        clock = WallClock(self.START)
        with fakes.Fake(iap=False, clock=clock.now) as fake:
            line, code = self.run_broker(fake, clock, SYNTHETICS_DEADLINE_S="40")
        self.assert_failed(line, code, step="login", code="timeout", status_class="none")
        self.assertNotIn("login", fake.routes())
        self.assertEqual(fake.codes_received, [])
        self.assertTrue(all(pause <= 1.0 for pause in clock.slept), "only the warm-up's pauses")
        # 50.2 s is room enough.
        clock = WallClock(self.START)
        with fakes.Fake(iap=False, clock=clock.now) as fake:
            line, code = self.run_broker(fake, clock, SYNTHETICS_DEADLINE_S="50.3")
        self.assertEqual((line["outcome"], code), ("pass", 0))

    def test_no_room_after_login_sends_no_code(self):
        # The wait must leave a send's time after it: a code sent with no time to read its answer spends the
        # step and may open a session the runner never holds a cookie for.
        original = journeys.totp.wait_for_fresh
        journeys.totp.wait_for_fresh = lambda _at: 55.0  # with a 60 s deadline, 50 s is the most it may wait
        try:
            clock = WallClock(self.START)
            with fakes.Fake(iap=False, clock=clock.now) as fake:
                line, code = self.run_broker(fake, clock, SYNTHETICS_DEADLINE_S="60")
        finally:
            journeys.totp.wait_for_fresh = original
        self.assert_failed(line, code, step="mfa_verify", code="timeout", status_class="none")
        self.assertEqual(fake.routes().count("login"), 1)
        self.assertNotIn("mfa_verify", fake.routes())
        self.assertEqual(fake.codes_received, [])
        self.assertNotIn(55.0, clock.slept)

    def test_more_than_one_task_at_once_refuses_to_run(self):
        for value, outcome in [("2", "error"), ("10", "error"), ("1", "pass"), (None, "pass")]:
            clock = WallClock(self.START)
            with self.subTest(count=value), fakes.Fake(iap=False, clock=clock.now) as fake:
                line, code = self.run_broker(fake, clock, CLOUD_RUN_TASK_COUNT=value)
                self.assertEqual(line["outcome"], outcome)
                if outcome == "error":
                    self.assert_error(line, code, step="config", code="config")
                    self.assertEqual((fake.requests, fake.connections), ([], []))

    def test_a_login_that_offers_no_authenticator_code_is_shape(self):
        clock = WallClock(self.START)
        with fakes.Fake(iap=False, fail={"login": "no_factor"}, clock=clock.now) as fake:
            line, code = self.run_broker(fake, clock)
        self.assert_failed(line, code, step="login", code="shape", status_class="2xx")
        self.assertEqual(fake.codes_received, [])

    def test_switched_off_is_disabled(self):
        for route in ("login", "mfa_verify"):
            clock = WallClock(self.START)
            with self.subTest(route=route), fakes.Fake(iap=False, fail={route: "checks_off"}, clock=clock.now) as fake:
                line, code = self.run_broker(fake, clock)
                self.assert_skipped(line, code, "disabled")
                self.assertNotIn("logout", fake.routes())

    def test_a_wrong_seed_is_credentials(self):
        clock = WallClock(self.START)
        with fakes.Fake(iap=False, clock=clock.now) as fake:
            env = self.robot_env(fake, self.JOB)
            env["SYNTHETICS_CREDENTIALS_FILE"] = broker_credentials(self.tmp.name, totp_secret="JBSWY3DPEHPK3PXP")
            line, code = self.run_robot(self.JOB, env, tools=clock.tools())
        self.assert_failed(line, code, step="mfa_verify", code="credentials", status_class="4xx")
        self.assertEqual(fake.refusals, ["code"])

    def test_widened_and_signed_out(self):
        clock = WallClock(self.START)
        with fakes.Fake(iap=False, fail={"me": "extra_role"}, clock=clock.now) as fake:
            line, code = self.run_broker(fake, clock)
        self.assert_failed(line, code, step="me", code="widened", status_class="2xx")
        self.assert_signed_out(fake, fakes.ROBOT_SESSIONS["broker"])


class RobotConfiguration(RobotCase):
    """The portal origin is production's alone in the cloud and a loopback one locally (SR-11), the address is
    the secret's alone (SR-01), and each robot reads exactly its own kind of secret."""

    def test_the_cloud_takes_productions_portal_and_nothing_else(self):
        robot = journeys.ROBOTS["member-sign-in"]
        base = {"SYNTHETICS_CREDENTIALS_FILE": "/secrets/credentials.json"}
        config = journeys.load_portal_config(
            dict(base, SYNTHETICS_PORTAL_ORIGIN="https://portal.trellistpa.com"), robot=robot, local=False)
        self.assertEqual(config.origin, journeys.PRODUCTION_PORTAL_ORIGIN)
        self.assertEqual(journeys.load_portal_config(
            dict(base, SYNTHETICS_PORTAL_ORIGIN="https://portal.trellistpa.com/"), robot=robot, local=False).origin,
            "https://portal.trellistpa.com")
        for origin in ("https://portal.trellistpa.com.evil.example", "https://evil.example",
                       "https://ops.trellistpa.com", "http://portal.trellistpa.com",
                       "https://portal.trellistpa.com:8443", "https://PORTAL.trellistpa.com",
                       "https://portal.trellistpa.com/tpa/", "https://user@portal.trellistpa.com",
                       "https://localhost:4310", "http://127.0.0.1:8080", ""):
            with self.subTest(origin=origin), self.assertRaises(journeys.StepFailure) as refused:
                journeys.load_portal_config(dict(base, SYNTHETICS_PORTAL_ORIGIN=origin), robot=robot, local=False)
            self.assertEqual(refused.exception.code, "config")

    def test_the_cloud_trusts_the_images_store_alone(self):
        robot = journeys.ROBOTS["member-sign-in"]
        base = {"SYNTHETICS_CREDENTIALS_FILE": "/secrets/credentials.json",
                "SYNTHETICS_PORTAL_ORIGIN": journeys.PRODUCTION_PORTAL_ORIGIN}
        ca = os.path.join(self.tmp.name, "ca.pem")
        with open(ca, "w", encoding="utf-8") as handle:
            handle.write("not a CA")
        for name, value in [("SYNTHETICS_CA_FILE", ca), ("SSL_CERT_FILE", ca), ("SSL_CERT_DIR", self.tmp.name)]:
            with self.subTest(name=name), self.assertRaises(journeys.StepFailure) as refused:
                journeys.load_portal_config(dict(base, **{name: value}), robot=robot, local=False)
            self.assertEqual(refused.exception.code, "config")
        local = dict(base, SYNTHETICS_PORTAL_ORIGIN="https://localhost:4310", SYNTHETICS_CA_FILE=ca,
                     SSL_CERT_FILE=ca)
        self.assertEqual(journeys.load_portal_config(local, robot=robot, local=True).ca_file, ca)

    def test_the_local_mode_takes_a_loopback_origin_alone(self):
        robot = journeys.ROBOTS["broker-sign-in"]
        base = {"SYNTHETICS_CREDENTIALS_FILE": "/secrets/credentials.json"}
        for origin in ("https://localhost:4310", "http://127.0.0.1:8080", "https://[::1]:4310"):
            with self.subTest(origin=origin):
                journeys.load_portal_config(dict(base, SYNTHETICS_PORTAL_ORIGIN=origin), robot=robot, local=True)
        for origin in ("https://portal.trellistpa.com", "https://localhost.evil.example"):
            with self.subTest(origin=origin), self.assertRaises(journeys.StepFailure):
                journeys.load_portal_config(dict(base, SYNTHETICS_PORTAL_ORIGIN=origin), robot=robot, local=True)

    def test_a_loopback_origin_in_the_cloud_mode_sends_nothing(self):
        for job in journeys.ROBOTS:
            with self.subTest(job=job), fakes.Fake(iap=False) as fake:
                line, code = self.run_journey(job, self.robot_env(fake, job), use_iap=True)
                self.assert_error(line, code, step="config", code="config")
                self.assertEqual((fake.requests, fake.connections), ([], []))

    def test_settings(self):
        for job in journeys.ROBOTS:
            for name, value in [("SYNTHETICS_PORTAL_ORIGIN", None), ("SYNTHETICS_CREDENTIALS_FILE", None),
                                ("SYNTHETICS_EMAIL", fakes.MEMBER_EMAIL), ("SYNTHETICS_STEP_TIMEOUT_S", "0"),
                                ("SYNTHETICS_DEADLINE_S", "101"), ("SYNTHETICS_EGRESS_WAIT_S", "171"),
                                ("SYNTHETICS_CA_FILE", "/nonexistent/ca.pem")]:
                with self.subTest(job=job, name=name), fakes.Fake(iap=False) as fake:
                    env = self.robot_env(fake, job)
                    env.pop(name, None)
                    if value is not None:
                        env[name] = value
                    line, code = self.run_robot(job, env)
                    self.assert_error(line, code, step="config", code="config")
                    self.assertEqual((fake.requests, fake.connections), ([], []))

    def test_each_robot_reads_exactly_its_own_secret(self):
        with fakes.Fake(iap=False) as fake:
            member, broker = member_credentials(self.tmp.name, fake.base), broker_credentials(self.tmp.name)
            staff = credentials_file(self.tmp.name)
            for job, path in [("member-sign-in", broker), ("member-sign-in", staff), ("broker-sign-in", member),
                              ("broker-sign-in", staff)]:
                with self.subTest(job=job, path=os.path.basename(path)):
                    env = self.robot_env(fake, job, SYNTHETICS_CREDENTIALS_FILE=path)
                    line, code = self.run_robot(job, env)
                    self.assert_error(line, code, step="secrets", code="config")
            self.assertEqual(fake.requests, [], "nothing is sent on a secret that is not the robot's")

    def test_bad_member_secrets(self):
        with fakes.Fake(iap=False) as fake:
            for changes in [{"email": None}, {"password": None}, {"passkey": None}, {"password": ""},
                            {"email": "no-at-sign"}, {"email": "two@@robots.invalid"}, {"email": "a b@robots.invalid"},
                            {"email": "@robots.invalid"}, {"email": 7}, {"totp_secret": fakes.BROKER_TOTP_SECRET},
                            {"passkey_origin": "https://portal.trellistpa.com"}, {"passkey_rp_id": "localhost"},
                            {"passkey_private_jwk": {"kty": "EC"}}, {"passkey_credential_id": "!"},
                            {"passkey_sign_count": 0}]:
                with self.subTest(changes=changes):
                    path = member_credentials(self.tmp.name, fake.base, **changes)
                    line, code = self.run_robot("member-sign-in", self.robot_env(
                        fake, "member-sign-in", SYNTHETICS_CREDENTIALS_FILE=path))
                    self.assert_error(line, code, step="secrets", code="config")
            self.assertEqual(fake.requests, [])

    def test_bad_broker_secrets(self):
        with fakes.Fake(iap=False) as fake:
            for changes in [{"email": None}, {"password": None}, {"totp_secret": None}, {"totp_secret": "not b32 !"},
                            {"totp_secret": 7}, {"password": ""}, {"email": "no-at-sign"}, {"extra": "x"}]:
                with self.subTest(changes=changes):
                    path = broker_credentials(self.tmp.name, **changes)
                    line, code = self.run_robot("broker-sign-in", self.robot_env(
                        fake, "broker-sign-in", SYNTHETICS_CREDENTIALS_FILE=path))
                    self.assert_error(line, code, step="secrets", code="config")
            self.assertEqual(fake.requests, [])

    def test_paused_sends_nothing(self):
        for job in journeys.ROBOTS:
            with self.subTest(job=job), fakes.Fake(iap=False) as fake:
                line, code = self.run_robot(job, self.robot_env(fake, job, SYNTHETICS_PAUSED="true"))
                self.assert_skipped(line, code, "paused")
                self.assertEqual(line["steps_ms"], {})
                self.assertEqual((fake.requests, fake.connections), ([], []))

    def test_the_credentials_never_reach_the_line(self):
        for job in journeys.ROBOTS:
            clock = WallClock(FIXED_NOW)
            with self.subTest(job=job), fakes.Fake(iap=False, fail={"me": 500}, clock=clock.now) as fake:
                line, _code = self.run_robot(job, self.robot_env(fake, job), tools=clock.tools())
                text = json.dumps(line)
                for secret in fakes.SENTINELS:
                    self.assertNotIn(secret, text)
                self.assertEqual(line["code"], "status")


class RobotEntryPoint(RobotCase):
    """The member robot as the job runs it: a child process with a real clock (the broker's real wait, up to 30 s,
    is the in-process tests' to pin)."""

    def spawn(self, env: dict[str, str], *args: str) -> tuple[dict, int]:
        child = {k: v for k, v in os.environ.items() if not k.startswith(("SYNTHETICS_", "CLOUD_RUN_"))}
        child.update(env, PYTHONPATH=str(ROOT))
        done = subprocess.run([sys.executable, "-m", "synthetics", "journey", *args], env=child,
                              capture_output=True, text=True, timeout=60, cwd=self.tmp.name)
        return self.parse_clean(done.stdout, done.stderr), done.returncode

    def test_pass(self):
        with fakes.Fake(iap=False) as fake:
            line, code = self.spawn(self.robot_env(fake, "member-sign-in"), "member-sign-in", "--no-iap")
        self.assertEqual((line["job"], line["outcome"], code), ("member-sign-in", "pass", 0))
        self.assertEqual(list(line["steps_ms"]), ROBOT_STEPS)
        self.assertEqual(fake.routes(), ROBOT_ROUTES)

    def test_disabled_exits_zero_and_a_bad_secret_one(self):
        with fakes.Fake(iap=False, fail={"login": "checks_off"}) as fake:
            line, code = self.spawn(self.robot_env(fake, "member-sign-in"), "member-sign-in", "--no-iap")
        self.assert_skipped(line, code, "disabled")
        with fakes.Fake(iap=False) as fake:
            env = self.robot_env(fake, "broker-sign-in", SYNTHETICS_CREDENTIALS_FILE=credentials_file(self.tmp.name))
            line, code = self.spawn(env, "broker-sign-in", "--no-iap")
        self.assert_error(line, code, step="secrets", code="config")

    def test_the_cloud_mode_refuses_a_loopback_portal(self):
        with fakes.Fake(iap=False) as fake:
            line, code = self.spawn(self.robot_env(fake, "member-sign-in"), "member-sign-in")
        self.assert_error(line, code, step="config", code="config")
        self.assertEqual(fake.requests, [])


if __name__ == "__main__":
    unittest.main()
