"""The journeys against a local fake (synthetic_fakes.py): pass, each step failing, timeouts,
transport failures, configuration, pausing, and no secret on stdout or stderr on any path.

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

from synthetics import __main__ as cli  # noqa: E402
from synthetics import journeys, result  # noqa: E402
from synthetics.journeys import Tools  # noqa: E402

#: The start of a TOTP step, so a code minted at it never waits.
FIXED_NOW = 1_800_000_000.0 - (1_800_000_000.0 % 30) + 1
KEYS = ["severity", "level", "message", "job", "outcome", "code", "step", "status_class", "elapsed_ms", "steps_ms"]

J1_STEPS = ["config", "secrets", "iap_token", "ops_shell", "ops_release", "login", "mfa_verify", "me",
            "desk_version", "logout", "portal_shell"]
J1_ROUTES = ["metadata", "ops_shell", "ops_release", "login", "mfa_verify", "me", "desk_version", "logout",
             "portal_shell"]
J2_ROUTES = ["metadata", "login", "mfa_verify", "live_queue", "desk_version_employers", "logout"]
J3_ROUTES = ["metadata", "crm_shell", "crm_login", "crm_mfa_verify", "crm_me", "crm_tenant", "crm_logout"]
J3_STEPS = ["config", "secrets", "iap_token", "crm_shell", "login", "mfa_verify", "me", "crm_tenant", "logout"]


def credentials_file(directory: str, value: object | None = None, raw: bytes | None = None) -> str:
    path = os.path.join(directory, "credentials.json")
    if raw is None:
        raw = json.dumps(value if value is not None else
                         {"password": fakes.PASSWORD, "totp_secret": fakes.TOTP_SECRET}).encode()
    with open(path, "wb") as handle:
        handle.write(raw)
    return path


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

    def run_journey(self, name: str, env: dict[str, str], *, use_iap: bool = True) -> tuple[dict, int]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.run(name, env, use_iap=use_iap,
                           tools=Tools(now=lambda: FIXED_NOW, sleep=lambda _s: None))
        return self.parse_clean(out.getvalue(), err.getvalue()), code

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
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_BASE_URL=f"http://127.0.0.1:{closed}"))
        self.assert_failed(line, code, step="ops_shell", code="connect", status_class="none")

    def test_https_to_a_plain_server_is_tls(self):
        with fakes.Fake() as fake:
            line, code = self.run_journey("staff-sign-in", self.env(
                fake, SYNTHETICS_BASE_URL=f"https://127.0.0.1:{fake.port}"))
        self.assert_failed(line, code, step="ops_shell", code="tls", status_class="none")


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
                            ("SYNTHETICS_CA_FILE", "/nonexistent/ca.pem")]:
            with self.subTest(name=name, value=value), fakes.Fake() as fake:
                line, code = self.run_journey("staff-sign-in", self.env(fake, **{name: value}))
                self.assert_error(line, code, step="config", code="config")
                self.assertEqual(fake.requests, [])

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
        self.assertEqual((line["outcome"], code), ("pass", 0))
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


if __name__ == "__main__":
    unittest.main()
