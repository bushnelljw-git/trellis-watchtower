"""No panel reads Grafana's "No data" when the truth is zero, idle or not running (the owner, 2026-11-12, of the
engine page's tiles: "investigate why some of these i dont see data"), and no page says "beta" to a reader (the owner,
the same day: "We are NOT in beta").

A read-only sweep that day ran every query of the 23 pages as production renders them against Google's API: 181
panels came back empty, and none of them was broken but one (the Jobs page's backlog chart, a distribution read with
ALIGN_MEAN, which Google refuses). The rest were empty because nothing happened. So every panel that queries says in
words what its empty answer means, by what it counts (scripts/cloud_dashboards.py, "What an empty panel says";
cloud/README.md, the same heading):

- a count of bad events: "None in this range" (a stat tile "0", in the neutral colour, never green);
- requests and their latency: "No requests in this range"; runs of a job: "No runs in this range";
- a service's instances and what they measure: per environment, "scales to zero when idle" or "kept warm, so it is
  down or not reporting";
- a signal that should always have points (a heartbeat, an uptime check, a database's own metrics): missing, in words,
  never zero; a database stopped on purpose "database stopped";
- a job paused on purpose: its charts "paused", as its deadline tile reads.

The pages are checked as each environment renders them (cloud/render-dashboards.sh), and as production's estate runs
on 2026-11-12 (three jobs paused).

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE))

import cloud_dashboards as gen  # noqa: E402
import dashboard_lint as lint  # noqa: E402
from test_resources import DASHBOARDS, ENVIRONMENTS, RENDER, RENDERED, sections  # noqa: E402

LOG = "logging.googleapis.com/user/"
# The estate as it ran on 2026-11-12 (its service's environment, read only): three jobs paused, nothing stopped.
ESTATE = {**ENVIRONMENTS["beta"], "TPA_PAUSED_JOBS": "accumulator-reconcile,feed-ingest-everon-sync,nightly-anomalies",
          "TPA_NOT_DEPLOYED_JOBS": "", "TPA_STOPPED_DATABASES": ""}
# Counters of bad events: a panel reading these alone says "None in this range" with nothing arrived.
BAD = {LOG + m for m in (
    "run_crash_exits", "run_oom_kills", "run_system_errors", "sql_proxy_errors", "errors", "auth_errors", "crm_errors",
    "scheduler_failures", "sql_restarts", "sql_backup_failures", "iap_unknown_key", "iap_pinned_keys_stale",
    "auth_login_failures", "auth_lockouts", "auth_not_ready", "auth_stepup_failures", "auth_admin_revocations",
    "auth_credential_tag_invalid", "auth_audit_reconcile_findings", "auth_audit_chain_breaks_new", "auth_audit_break",
    "auth_message_vendor_failures", "records_refusals", "records_critical", "records_rate_limited",
    "records_mirror_problems", "records_chain_head_exists", "connectors_dead_letters", "perimeter_violations",
    "monitoring_changes", "log_metric_changes", "tpa_jobs_drain_raised", "model_gateway_calls", "voice_loop_lag",
    "voice_loop_lag_ms", "voice_loop_lag_over_1s", "voice_loop_lag_over_5s", "voice_stack_dumps",
    "voice_keep_warm_failures", "secret_version_changes", "kms_version_changes", "source_sync_alerts",
    "records_velocity", "records_velocity_settings_changes", "records_reveals", "records_staff_member_reads",
    # The catalogue at 1e15b0e8: the Admin Activity security changes and Cloud Armor's three (every project's), auth's
    # guards, IAP's not-ok assertions, the CRM's sign-in refusals and the importer's runs that did not end whole.
    "iam_policy_changes", "audit_config_changes", "org_policy_changes", "network_control_changes",
    "logging_config_changes", "service_account_key_changes", "run_public_invokers", "iap_setting_changes",
    "security_changes_by_robot", "sql_exports_by_hand", "armor_waf_refused", "armor_waf_previewed",
    "armor_adaptive_alerts", "auth_sign_in_protection", "auth_breach_corpus_unavailable",
    "auth_sms_codes_estate_ceiling", "auth_sms_codes_registration_ceiling", "iap_not_ok", "crm_login_failures",
    "crm_sign_in_throttled", "crm_sign_in_protection", "everon_runs_not_whole",
    # The sign-in row's sections (SR-OR-1, D-335): a robot's secret read by anyone else, texts never handed over,
    # the delivery read's own faults, emails that could not be delivered, mail kept from a synthetic login.
    "signin_robot_secret_read", "auth_texts_not_sent", "auth_text_delivery_faults", "auth_email_undeliverable",
    "auth_message_to_synthetic_login")}
# Heartbeats: written every pass or run, so nothing at all is the signal missing, said as missing.
HEARTBEATS = {LOG + "connectors_passes", LOG + "auth_audit_reconciled", LOG + "auth_events_publisher_alive",
              LOG + "auth_events_outbox_lag"}
REQUESTS = {"run.googleapis.com/request_count", "run.googleapis.com/request_latencies", LOG + "tpa_api_requests",
            LOG + "tpa_api_latency", LOG + "engine_latency"}
# The words a reader sees: titles, descriptions, a text panel's content, the no-value words, display names, value
# mappings, legends and link titles (never a query, a url or a project id).
READER_KEYS = {"title", "description", "content", "noValue", "displayName", "text", "tooltip", "aliasBy"}


def render(env: dict) -> dict[str, dict]:
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "src", Path(tmp) / "dst"
        shutil.copytree(DASHBOARDS, src, ignore=shutil.ignore_patterns("*.md"))
        base = {k: v for k, v in os.environ.items() if not k.startswith("TPA_")}
        done = subprocess.run(["sh", str(RENDER), "--render-only", str(src), str(dst)], env={**base, **env},
                              capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        return {p.stem: json.loads(p.read_text()) for p in dst.glob("*.json")}


PAGES = {**{env: pages for env, pages in RENDERED.items()}, "estate": render(ESTATE)}


def queried(dashboard: dict):
    for panel in lint.panels(dashboard):
        if panel.get("targets"):
            yield panel


def metrics(panel: dict) -> set[str]:
    return {lint.query_facts(t["timeSeriesList"])["metric"] for t in panel["targets"]}


def filters(panel: dict) -> list[tuple[str, str, str]]:
    return [f for t in panel["targets"] for f in lint.query_facts(t["timeSeriesList"])["filters"]]


def no_value(panel: dict) -> str | None:
    return panel["fieldConfig"]["defaults"].get("noValue")


def reader_words(node, key=""):
    if isinstance(node, dict):
        for k, v in node.items():
            if k not in ("targets", "url", "projectName", "datasource"):
                yield from reader_words(v, k)
    elif isinstance(node, list):
        for v in node:
            yield from reader_words(v, key)
    elif isinstance(node, str) and key in READER_KEYS:
        yield node


class EmptyPanelTest(unittest.TestCase):
    def test_no_panel_reads_no_data(self):
        for env, pages in PAGES.items():
            blank = [f"{name}: {p['title']}" for name, page in pages.items() for p in queried(page) if not no_value(p)]
            self.assertEqual(blank, [], f"{env}: these read Grafana's \"No data\" with nothing arrived")

    def test_a_count_of_bad_events_reads_none(self):
        for env, pages in PAGES.items():
            for name, page in pages.items():
                for p in queried(page):
                    if p["type"] == "stat" or not metrics(p) <= BAD:
                        continue
                    # A paused job's charts say "paused" instead (test_a_paused_jobs_charts_say_paused).
                    quiet = env == "estate" and no_value(p) == "paused"
                    self.assertEqual(gen.NONE if quiet else no_value(p), gen.NONE, f"{env} {name}: {p['title']}")

    def test_a_stat_that_counts_reads_zero_in_no_colour(self):
        for env, pages in PAGES.items():
            for name, page in pages.items():
                for p in queried(page):
                    if p["type"] == "stat" and no_value(p) == "0":
                        base = p["fieldConfig"]["defaults"]["thresholds"]["steps"][0]["color"]
                        self.assertEqual(base, gen.NEUTRAL, f"{env} {name}: {p['title']}")

    def test_requests_read_no_requests(self):
        for env, pages in PAGES.items():
            for name, page in pages.items():
                for p in queried(page):
                    if p["type"] == "stat" or not metrics(p) <= REQUESTS:
                        continue
                    five_xx = ("metric.label.response_code_class", "=", "5xx") in filters(p)
                    self.assertEqual(no_value(p), gen.NONE if five_xx else gen.NO_REQUESTS,
                                     f"{env} {name}: {p['title']}")

    def test_a_missing_heartbeat_says_missing(self):
        for env, pages in PAGES.items():
            for name, page in pages.items():
                for p in queried(page):
                    if metrics(p) & HEARTBEATS:
                        self.assertTrue(no_value(p).startswith("Missing"), f"{env} {name}: {p['title']}")

    def test_an_instance_chart_says_whether_the_service_rests_or_is_down(self):
        for env, pages in RENDERED.items():
            for service in gen.SERVICES:
                page = pages.get(f"service-{service}")
                if page is None:
                    continue
                cpu = next(p for title, ps in sections(page).items() if title.startswith("Resources")
                           for p in ps if p["title"].startswith("CPU"))
                want = ("kept warm" if service in gen.KEPT_WARM[env] else "scales to zero" if service in gen.RUNS[env]
                        else "does not run here")
                self.assertIn(want, no_value(cpu), (env, service))
        # The engine, the owner's page: it scales to zero.
        engine = PAGES["estate"]["service-engine"]
        self.assertEqual({no_value(p) for p in queried(engine)} - {gen.NONE, gen.NO_REQUESTS,
                                                                    "No instance started in this range"},
                         {"No instance in this range: engine scales to zero when idle"})

    def test_a_paused_jobs_charts_say_paused(self):
        jobs = PAGES["estate"]["jobs"]
        row = sections(jobs)[f"The administrator-feed importer ({gen.IMPORTER})"]
        self.assertEqual([no_value(p) for p in row], ["paused"] * 6)
        backlog = next(p for p in lint.panels(jobs) if p["title"] == "Reconciliations left open per tenant")
        self.assertEqual(no_value(backlog), "paused")
        # Running, each says its own words.
        built = next(p for p in lint.panels(RENDERED["beta"]["jobs"]) if p["title"] == backlog["title"])
        self.assertEqual(no_value(built), "None left open in this range")

    def test_a_stopped_database_reads_database_stopped_on_its_charts(self):
        pages = render({**ENVIRONMENTS["beta"], "TPA_STOPPED_DATABASES": "crm-db"})
        crm = {p["title"]: no_value(p) for title, ps in sections(pages["databases"]).items()
               if title.startswith("crm-db (") for p in ps}
        self.assertEqual(crm["CPU"], "database stopped")
        self.assertEqual(crm["Restarts"], gen.NONE)
        auth = {p["title"]: no_value(p) for title, ps in sections(pages["databases"]).items()
                if title.startswith("auth-db (") for p in ps}
        self.assertEqual(auth["CPU"], "Not reporting: no reading from auth-db in this range")


class DistributionTest(unittest.TestCase):
    def test_no_distribution_is_read_with_align_mean(self):
        # Cloud Monitoring answers 400 ("The aligner cannot be applied to metrics with kind DELTA and value type
        # DISTRIBUTION"), and the panel shows only the error: the Jobs page's backlog chart until 2026-11-12.
        for env, pages in PAGES.items():
            for name, page in pages.items():
                for p in queried(page):
                    for t in p["targets"]:
                        tsl = t["timeSeriesList"]
                        if lint.query_facts(tsl)["metric"] == LOG + "tpa_jobs_accumulator_backlog":
                            self.assertNotEqual(tsl["perSeriesAligner"], "ALIGN_MEAN", f"{env} {name}")


class WordsTest(unittest.TestCase):
    def test_no_page_says_beta_to_a_reader(self):
        # The owner, 2026-11-12: "We are NOT in beta". The estate's Terraform root, its projects and TPA_ENVIRONMENT
        # keep the name (identifiers); nothing a person reads on a page does.
        for env, pages in PAGES.items():
            said = [f"{name}: {w[:120]}" for name, page in pages.items()
                    for w in reader_words({k: v for k, v in page.items() if k != "uid"})
                    if re.search(r"beta", re.sub(r"\bbeta-(tpa-app|tpa-phi|callcentre)\b", "", w), re.I)]
            self.assertEqual(said, [], env)


if __name__ == "__main__":
    unittest.main()
