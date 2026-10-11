"""scripts/pagerduty/tf_with_keys.py against the fake PagerDuty (fakes.py) and a fake terraform: an automated gate only.

The fake terraform is a small program on PATH that records its argv and its whole environment to a file in a
temporary directory, so each test can see exactly what reached the child.

Run: python3 -m unittest discover -s tests/pagerduty -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import fakes
from test_pd_setup import SCRIPTS, Base

VARIABLE = "TF_VAR_pagerduty_service_keys"
APP_CHANNEL = "-replace=module.monitoring_app.google_monitoring_notification_channel.pagerduty[0]"
FOUND_ALL = "tf_with_keys: PagerDuty keys (beta): app present, phi present, cc present"
ROLE_SERVICE = {"app": "TPA beta · Portal & API", "phi": "TPA beta · Member records", "cc": "TPA beta · Call centre"}


class WithTerraform(Base):
    def setUp(self):
        super().setUp()
        self.apply()
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.record = tmp / "child.json"
        fake = self.bin / "terraform"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            f"open({str(self.record)!r}, 'w').write(json.dumps({{'argv': sys.argv[1:], 'env': dict(os.environ)}}))\n"
            "print('fake terraform ran')\n"
        )
        fake.chmod(0o755)
        self.roots = {}
        for name in ("beta", "production", "production-full"):
            self.roots[name] = tmp / "infra" / "envs" / name
            self.roots[name].mkdir(parents=True)
        self.requests_before = len(self.state.requests)

    def tearDown(self):
        self.tmp.cleanup()
        super().tearDown()

    def tf(self, *command, opts=(), token=fakes.TOKEN, extra=None, path=None, separator=True):
        """Run the script with a clean, known environment; returns (result, the environment it was given)."""
        env = {k: v for k, v in os.environ.items() if k != "PAGERDUTY_TOKEN" and not k.startswith("TF_")}
        env.update({"PAGERDUTY_API_URL": self.server.url("pd"),
                    "PATH": path if path is not None else f"{self.bin}{os.pathsep}{env.get('PATH', '')}"})
        if token is not None:
            env["PAGERDUTY_TOKEN"] = token
        env.update(extra or {})
        argv = [sys.executable, str(SCRIPTS / "tf_with_keys.py"), *opts, *(["--"] if separator else []), *command]
        result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=120)
        self.outputs += [result.stdout, result.stderr]
        return result, env

    def beta(self, *args):
        return ["terraform", f"-chdir={self.roots['beta']}", *args]

    def keys(self):
        by_name = {self.state.services[sid]["name"]: items[0]["integration_key"]
                   for sid, items in self.state.integrations.items() if items}
        return {role: by_name[name] for role, name in ROLE_SERVICE.items()}

    def child(self):
        return json.loads(self.record.read_text())

    def assert_not_run(self, result):
        self.assertFalse(self.record.exists(), "terraform must not run: " + result.stderr)
        self.assertNotIn("fake terraform ran", result.stdout)

    def assert_reads_only(self):
        made = self.state.requests[self.requests_before:]
        self.assertTrue(made, "the script should have read PagerDuty")
        self.assertEqual([r for r in made if r["method"] != "GET"], [], "the script must only read PagerDuty")


class KeysReachTheChildOnly(WithTerraform):
    def test_the_variable_reaches_the_child_and_nothing_else_changes(self):
        result, env = self.tf(*self.beta("apply", APP_CHANNEL, "-auto-approve"))
        self.assertEqual(result.returncode, 0, result.stderr)
        child = self.child()
        self.assertEqual(json.loads(child["env"][VARIABLE]), self.keys())
        expected = {k: v for k, v in env.items() if k != "PAGERDUTY_TOKEN"}
        expected[VARIABLE] = child["env"][VARIABLE]
        # The interpreter running the fake may add these; nothing else may differ.
        added = {k for k in child["env"].keys() - expected.keys() if k.startswith("__CF") or k == "__PYVENV_LAUNCHER__"}
        self.assertEqual({k: v for k, v in child["env"].items() if k not in added}, expected)
        self.assertEqual(child["argv"], [f"-chdir={self.roots['beta']}", "apply", APP_CHANNEL, "-auto-approve"])
        self.assertEqual(result.stderr.strip().splitlines(), [FOUND_ALL])
        self.assertEqual(result.stdout, "fake terraform ran\n")
        self.assert_reads_only()

    def test_the_key_is_in_no_argument_and_never_printed(self):
        result, _ = self.tf(*self.beta("plan"))
        self.assertEqual(result.returncode, 0, result.stderr)
        for key in self.keys().values():
            self.assertNotIn(key, " ".join(self.child()["argv"]))
            self.assertNotIn(key, result.stdout + result.stderr)

    def test_the_token_is_never_inherited(self):
        result, _ = self.tf(*self.beta("plan"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("PAGERDUTY_TOKEN", self.child()["env"])
        self.assertNotIn(fakes.TOKEN, json.dumps(self.child()))

    def test_the_token_read_from_the_keychain_is_not_inherited_either(self):
        log = Path(self.tmp.name) / "security.log"
        security = self.bin / "security"
        security.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\necho "{fakes.TOKEN}"\n')
        security.chmod(0o755)
        result, _ = self.tf(*self.beta("apply"), token=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text().strip(), "find-generic-password -s tpa-pagerduty-api -w")
        self.assertNotIn(fakes.TOKEN, json.dumps(self.child()))
        self.assertEqual(json.loads(self.child()["env"][VARIABLE]), self.keys())

    def test_an_inherited_variable_is_replaced_not_kept(self):
        result, _ = self.tf(*self.beta("plan"), extra={VARIABLE: '{"app":"stale"}'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.child()["env"][VARIABLE]), self.keys())


class Refusals(WithTerraform):
    def assert_refused(self, result, words):
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("refused:", result.stderr)
        self.assertIn(words, result.stderr)
        self.assert_not_run(result)

    def assert_pagerduty_untouched(self):
        self.assertEqual(len(self.state.requests), self.requests_before, "a refused command must not read the keys")

    def test_only_plan_and_apply_run(self):
        root = f"-chdir={self.roots['beta']}"
        for command, words in [
            (["terraform", root, "destroy"], "only `terraform plan` and `terraform apply`"),
            (["terraform", root, "state", "pull"], "only `terraform plan` and `terraform apply`"),
            (["terraform", root, "output", "-json"], "only `terraform plan` and `terraform apply`"),
            (["terraform", root, "console"], "only `terraform plan` and `terraform apply`"),
            (["terraform", "-version"], "only `terraform plan` and `terraform apply`"),
            (["terraform"], "only `terraform plan` and `terraform apply`"),
            (["sh", "-c", "env"], "only terraform runs here"),
            (["env"], "only terraform runs here"),
            ([str(self.bin / "terraform-other"), "apply"], "only terraform runs here"),
            ([], "only terraform runs here"),
            (["terraform", root, "apply", "saved.tfplan"], "is not a flag"),
            (["terraform", root, "apply", "-replace", "module.x.y[0]"], "is not a flag"),
            (["terraform", root, "apply", "--", "-x"], "is not a flag"),
            (["terraform", root, "plan", "-out=keys.tfplan"], "-out writes a plan file"),
        ]:
            with self.subTest(command=command):
                result, _ = self.tf(*command)
                self.assert_refused(result, words)
        self.assert_pagerduty_untouched()

    def test_a_command_without_the_separator_is_refused(self):
        result, _ = self.tf(*self.beta("apply"), separator=False)
        self.assert_refused(result, "no `--` before the command")
        self.assert_pagerduty_untouched()

    def test_a_terraform_debug_log_is_refused(self):
        for name in ("TF_LOG", "TF_LOG_PROVIDER"):
            with self.subTest(name=name):
                result, _ = self.tf(*self.beta("apply"), extra={name: "DEBUG"})
                self.assert_refused(result, f"{name} is set")
        self.assert_pagerduty_untouched()

    def test_another_environments_root_is_refused(self):
        prod_full = ["terraform", f"-chdir={self.roots['production-full']}", "apply"]
        result, _ = self.tf(*prod_full)
        self.assert_refused(result, "which is not a beta root")
        result, _ = self.tf(*self.beta("apply"), opts=("--env", "production"))
        self.assert_refused(result, "which is not a production root")
        result, _ = self.tf(*self.beta("apply"), opts=("--env", "Beta;rm"))
        self.assert_refused(result, "is not an environment name")
        self.assert_pagerduty_untouched()

    def test_production_reads_the_production_services(self):
        result, _ = self.tf("terraform", f"-chdir={self.roots['production-full']}", "apply",
                            opts=("--env", "production"))
        self.assert_refused(result, 'no PagerDuty service "TPA production · Portal & API"')
        self.assertIn("tf_with_keys: PagerDuty keys (production): app missing, phi missing, cc missing",
                      result.stderr)
        self.assert_reads_only()


class MissingAndErrors(WithTerraform):
    def service_id(self, role):
        return next(s for s, v in self.state.services.items() if v["name"] == ROLE_SERVICE[role])

    def test_a_missing_service_stops_it_before_terraform(self):
        self.state.services[self.service_id("phi")]["name"] = "Member records (renamed)"
        result, _ = self.tf(*self.beta("apply"))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("tf_with_keys: PagerDuty keys (beta): app present, phi missing, cc present", result.stderr)
        self.assertIn('no PagerDuty service "TPA beta · Member records"', result.stderr)
        self.assert_not_run(result)

    def test_a_missing_integration_stops_it_before_terraform(self):
        self.state.integrations[self.service_id("cc")] = []
        result, _ = self.tf(*self.beta("apply"))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("app present, phi present, cc missing", result.stderr)
        self.assertIn("has no Google Cloud Monitoring integration", result.stderr)
        self.assert_not_run(result)

    def test_a_malformed_key_stops_it_and_is_not_printed(self):
        # tearDown checks every output for fakes.KEY_PREFIX, which this value carries.
        self.state.integrations[self.service_id("app")][0]["integration_key"] = f"{fakes.KEY_PREFIX}-not-a-key"
        result, _ = self.tf(*self.beta("apply"))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("app missing, phi present, cc present", result.stderr)
        self.assertIn("is not 32 letters and digits (not shown)", result.stderr)
        self.assert_not_run(result)

    def test_a_401_that_echoes_the_token_prints_no_secret(self):
        self.extra_secrets = ["wrong-token-0000"]
        result, _ = self.tf(*self.beta("apply"), token="wrong-token-0000")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("HTTP 401", result.stderr)
        self.assertIn("<redacted>", result.stderr)
        self.assert_not_run(result)

    def test_terraform_not_found_prints_no_key(self):
        empty = Path(self.tmp.name) / "empty"
        empty.mkdir()
        result, _ = self.tf(*self.beta("apply"), path=str(empty))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr.splitlines()[0], FOUND_ALL)
        self.assertIn("failed: FileNotFoundError", result.stderr)
        self.assert_not_run(result)


if __name__ == "__main__":
    import unittest

    unittest.main()
