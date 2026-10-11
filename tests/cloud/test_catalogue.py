"""The cloud dashboards against tpa-platform's metric catalogue, so a renamed metric, label, job or database fails
this repository's build.

The catalogue is vendored (cloud/catalogue/monitoring.yml, pinned by commit and blob sha in SOURCE, written by
scripts/vendor_catalogue.sh), not read from a tpa-platform checkout: the build is hermetic, and a rename on that
side fails here the moment the new catalogue is vendored.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import catalogue as cat  # noqa: E402
import cloud_dashboards as gen  # noqa: E402
import dashboard_lint as lint  # noqa: E402

# Every page, and the no-cc/ variants production-full renders (scripts/cloud_dashboards.py NO_CC).
PAGES = sorted((ROOT / "cloud" / "dashboards").glob("*.json"))
DASHBOARDS = PAGES + sorted((ROOT / "cloud" / "dashboards" / "no-cc").glob("*.json"))
ROLE = {"cloud-app": "app", "cloud-phi": "phi", "cloud-crm": "crm", "cloud-cc": "cc"}
LOG_PREFIX = "logging.googleapis.com/user/"

# Google's own metrics the dashboards read: the metric labels each one carries, and its kind.
BUILTIN = {
    "run.googleapis.com/request_count": ({"response_code_class"}, "counter"),
    "run.googleapis.com/request_latencies": (set(), "distribution"),
    "run.googleapis.com/container/instance_count": ({"state"}, "gauge"),
    "run.googleapis.com/job/completed_execution_count": ({"result"}, "counter"),
    "cloudsql.googleapis.com/database/up": (set(), "gauge"),
    "cloudsql.googleapis.com/database/disk/utilization": (set(), "gauge"),
    "monitoring.googleapis.com/uptime_check/check_passed": (set(), "bool"),
}
# Written by Google for objects tpa-platform's monitoring module makes, not named in the catalogue's YAML: the uptime
# checks (modules/monitoring/main.tf, google_monitoring_alert_policy.uptime reads it; docs/infra/monitoring.md §8).
BUILTIN_FROM_THE_MODULE = {"monitoring.googleapis.com/uptime_check/check_passed"}
RESOURCE_LABELS = {"cloud_run_revision": {"service_name"}, "cloud_run_job": {"job_name"},
                   "cloudsql_database": {"database_id"}, "uptime_url": {"host"}, "cloud_scheduler_job": {"job_id"},
                   "audited_resource": set()}
# A distribution (a latency, a lag, a backlog) is read through a percentile or its mean; a counter by its count.
DISTRIBUTION_ALIGNERS = {"ALIGN_PERCENTILE_99", "ALIGN_PERCENTILE_95", "ALIGN_PERCENTILE_50", "ALIGN_PERCENTILE_05",
                         "ALIGN_MEAN"}
COUNTER_ALIGNERS = {"ALIGN_DELTA", "ALIGN_RATE", "ALIGN_SUM", "ALIGN_COUNT"}
ALIGNERS = {"counter": COUNTER_ALIGNERS, "distribution": DISTRIBUTION_ALIGNERS,
            "gauge": {"ALIGN_MAX", "ALIGN_MIN", "ALIGN_MEAN"},
            "bool": {"ALIGN_FRACTION_TRUE", "ALIGN_COUNT_TRUE", "ALIGN_COUNT_FALSE"}}


def promql_name(metric_type: str) -> str:
    """How Cloud Monitoring's PromQL names a metric type (the catalogue writes some policies in PromQL)."""
    domain, path = metric_type.split("/", 1)
    return domain.replace(".", "_") + ":" + path.replace("/", "_")


# Each project's Cloud Run services, jobs, schedules and Cloud SQL instances, from tpa-platform's beta roots at the
# pinned commit (infra/envs/beta/main.tf, crm.tf, callcentre.tf). The jobs, schedules and instances are also held
# to the names the catalogue's own policies use (test_names_agree_with_the_catalogue).
NAMES = {
    "app": {
        "service_name": {"web", "auth", "auth-outbox-publisher", "tpa-api", "model-gateway", "tpa-jobs-drains"},
        "job_name": {"migrate-auth", "auth-publisher", "auth-sweeper", "auth-audit-head", "auth-audit-verify",
                     "auth-audit-verify-monthly", "auth-bootstrap", "auth-tag-credentials", "auth-retag-bearer-key",
                     "tpa-jobs-erisa-clocks", "tpa-jobs-nightly-anomalies", "tpa-jobs-stoploss-surveillance",
                     "tpa-jobs-accumulator-reconcile", "tpa-jobs-workload-audit", "tpa-jobs-member-access"},
        "job_id": {"erisa-clocks", "nightly-anomalies", "stoploss-surveillance", "accumulator-reconcile",
                   "workload-audit", "member-access", "auth-publish", "auth-sweep", "auth-audit-head",
                   "auth-audit-verify", "auth-audit-verify-monthly"},
        "database_id": {"auth-db"},
    },
    "phi": {
        "service_name": {"records", "connectors"},
        "job_name": {"migrate-tpa", "seed-tpa", "tpa-db-export", "restore-drill", "records-chain-head"},
        "job_id": {"tpa-db-export", "records-chain-head", "restore-drill"},
        "database_id": {"tpa-db"},
    },
    "crm": {"service_name": {"crm-web", "engine"}, "job_name": {"migrate-crm", "seed-crm"}, "job_id": set(),
            "database_id": {"crm-db"}},
    "cc": {"service_name": {"svc-voice", "svc-ops", "svc-twilio-rest"}, "job_name": {"migrate-cc"}, "job_id": set(),
           "database_id": {"cc-db"}},
}


def queries(paths=None):
    """(dashboard file, panel title, refId, datasource uid, (aligner, reducer), query facts) for every cloud query."""
    for path in DASHBOARDS if paths is None else paths:
        for panel in lint.panels(json.loads(path.read_text())):
            for target in panel.get("targets") or []:
                tsl = target.get("timeSeriesList") or {}
                yield (str(path.relative_to(ROOT / "cloud" / "dashboards")), panel.get("title"), target.get("refId"),
                       (target.get("datasource") or {}).get("uid"),
                       (tsl.get("perSeriesAligner"), tsl.get("crossSeriesReducer")), lint.query_facts(tsl))


class CatalogueTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = cat.Catalogue()
        # role -> {name in its project: catalogue name}, for every environment the role exists in.
        cls.valid: dict[str, dict[str, str]] = {role: {} for role in ROLE.values()}
        for layout in cat.LAYOUTS.values():
            for role, names in cat.project_names(cls.catalogue, layout).items():
                cls.valid[role].update(names)
        for names in cls.valid.values():
            names.update({name: name for name in cls.catalogue.shared})

    def test_the_vendored_catalogue_is_the_pinned_blob(self):
        pin = cat.source()
        self.assertEqual(pin.get("path"), "infra/monitoring.yml")
        self.assertRegex(pin.get("commit", ""), r"^[0-9a-f]{40}$")
        self.assertEqual(cat.git_blob_sha(self.catalogue.data), pin.get("blob"),
                         "cloud/catalogue/monitoring.yml is not the blob SOURCE pins; re-vendor it with "
                         "scripts/vendor_catalogue.sh, never edit it by hand")

    def test_the_reader_finds_the_catalogue(self):
        # Known facts of the catalogue, so a reader that silently reads nothing fails here.
        self.assertEqual(set(self.catalogue.roles), {"app", "phi", "crm", "cc"})
        self.assertEqual(set(self.catalogue.shared), {"run_system_errors", "sql_proxy_errors"})
        self.assertEqual(self.catalogue.roles["phi"]["errors"]["labels"],
                         {"service", "class", "operation", "code", "sqlstate"})
        self.assertTrue(self.catalogue.roles["app"]["tpa_api_latency"]["distribution"])
        self.assertFalse(self.catalogue.roles["app"]["tpa_api_requests"]["distribution"])
        self.assertIn("crm_errors", self.valid["crm"], "beta's app project renames the CRM's errors")

    def test_every_metric_a_dashboard_queries_is_in_the_catalogue(self):
        problems = []
        for name, title, ref, uid, (aligner, reducer), facts in queries():
            metric, where = facts["metric"], f"{name}: {title} ({ref}) on {uid}"
            # A distribution is also read whole: merged across series, then a percentile (canary-latency's way).
            merged = aligner == "ALIGN_DELTA" and str(reducer).startswith("REDUCE_PERCENTILE_")
            if metric.startswith(LOG_PREFIX):
                found = self._log_metric(ROLE[uid], metric[len(LOG_PREFIX):])
                if found is None:
                    problems.append(f"{where}: `{metric}` is not a log metric of the {ROLE[uid]} role (nor the "
                                    "shared list) in the catalogue")
                elif found["distribution"] and aligner not in DISTRIBUTION_ALIGNERS and not merged:
                    problems.append(f"{where}: `{metric}` is a distribution; read it with a percentile or its mean, "
                                    f"not {aligner}")
                elif not found["distribution"] and aligner not in COUNTER_ALIGNERS:
                    problems.append(f"{where}: `{metric}` is a counter; read it by its count, not {aligner}")
            elif metric in BUILTIN:
                if metric not in BUILTIN_FROM_THE_MODULE and f'metric.type = "{metric}"' not in self.catalogue.text \
                        and promql_name(metric) not in self.catalogue.text:
                    problems.append(f"{where}: `{metric}` is read by no catalogue policy")
                kind = BUILTIN[metric][1]
                if aligner not in ALIGNERS[kind] and not (kind == "distribution" and merged):
                    problems.append(f"{where}: `{metric}` is a {kind}; {aligner} does not read one")
            else:
                problems.append(f"{where}: `{metric}` is neither a log metric nor a known Google metric")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_every_label_a_query_names_belongs_to_its_metric(self):
        problems = []
        for name, title, ref, uid, _aligner, facts in queries():
            metric = facts["metric"]
            if metric.startswith(LOG_PREFIX):
                found = self._log_metric(ROLE[uid], metric[len(LOG_PREFIX):])
                # A label whose extractor is an unanchored regular expression may hold a word out of free text
                # (the CRM's class, 2026-10-11): never charted until the vendored catalogue anchors it.
                base = self.valid[ROLE[uid]].get(metric[len(LOG_PREFIX):])
                unsafe = self.catalogue.unanchored_labels(ROLE[uid], base) if base else set()
                metric_labels = (found["labels"] if found else set()) - unsafe
            else:
                metric_labels = BUILTIN.get(metric, (set(), None))[0]
            allowed = {f"metric.label.{x}" for x in metric_labels} | \
                      {f"resource.label.{x}" for x in RESOURCE_LABELS.get(facts["resource"], set())}
            extra = facts["labels"] - allowed
            if extra:
                problems.append(f"{name}: {title} ({ref}): {sorted(extra)} are not labels of `{metric}` on "
                                f"{facts['resource']}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_names_in_a_query_belong_to_its_project(self):
        problems = []
        for name, title, ref, uid, _aligner, facts in queries():
            role = ROLE[uid]
            for key, op, value in facts["filters"]:
                label = key.removeprefix("resource.label.")
                if label not in NAMES[role]:
                    continue
                # Grafana sends a value with `*` as starts_with/ends_with, and =~ as a full regular-expression match.
                pattern = re.compile(value if op == "=~" else ".*".join(map(re.escape, value.split("*"))))

                def matches(names, label=label, pattern=pattern):
                    return {n for n in names if pattern.fullmatch(f"a-project:{n}" if label == "database_id" else n)}
                mine = matches(NAMES[role][label])
                theirs = set().union(*(matches(NAMES[r][label]) for r in NAMES if r != role))
                if not mine or theirs:
                    problems.append(f"{name}: {title} ({ref}) on {uid}: {key} {op} \"{value}\" matches "
                                    f"{sorted(mine) or 'nothing'} here and {sorted(theirs) or 'nothing'} elsewhere")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_names_agree_with_the_catalogue(self):
        jobs = set().union(*(n["job_name"] for n in NAMES.values()))
        schedules = set().union(*(n["job_id"] for n in NAMES.values()))
        databases = set().union(*(n["database_id"] for n in NAMES.values()))
        self.assertEqual(jobs, self.catalogue.jobs_named())
        self.assertEqual(schedules, self.catalogue.schedules_named())
        self.assertEqual(databases, self.catalogue.databases_named())

    def test_every_catalogue_metric_is_charted(self):
        charted: dict[str, set[str]] = {role: set() for role in ROLE.values()}
        for _name, _title, _ref, uid, _aligner, facts in queries(PAGES):
            if facts["metric"].startswith(LOG_PREFIX):
                base = facts["metric"][len(LOG_PREFIX):]
                charted[ROLE[uid]].add(self.valid[ROLE[uid]].get(base, base))
        missing = [f"{role}: {name}" for role in ROLE.values()
                   for name in sorted(set(self.catalogue.roles[role]) | set(self.catalogue.shared))
                   if name not in charted[role]]
        self.assertEqual(missing, [], "catalogue metrics no cloud dashboard charts:\n" + "\n".join(missing))

    def test_phi_metrics_are_read_with_cloud_phi_alone(self):
        phi_only = set(self.catalogue.roles["phi"]) - set().union(
            *(self.catalogue.roles[r] for r in ("app", "crm", "cc"))) - set(self.catalogue.shared)
        problems = []
        for name, title, ref, uid, _aligner, facts in queries():
            base = facts["metric"].removeprefix(LOG_PREFIX)
            if base in phi_only and uid != "cloud-phi":
                problems.append(f"{name}: {title} ({ref}) reads the PHI project's `{base}` on {uid}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_an_unanchored_extractor_keeps_its_label_off_and_an_anchored_one_lets_it_back(self):
        # Today's catalogue (tpa-platform d60de911): the CRM's class is anchored, as the call centre's is, so the
        # CRM's error panels group by it again...
        self.assertEqual(self.catalogue.unanchored_labels("crm", "errors"), set())
        self.assertEqual(self.catalogue.unanchored_labels("cc", "errors"), set(), "the call centre's is anchored")
        crm_class = [(n, t) for n, t, _r, uid, _a, f in queries() if uid == "cloud-crm"
                     and "metric.label.class" in f["labels"]]
        self.assertNotEqual(crm_class, [])
        # ...and the moment a vendored catalogue un-anchors it, the rule takes the label off again.
        unanchored = self.catalogue.text.replace(
            'REGEXP_EXTRACT(jsonPayload.exc, "(?:^|\\\\n)([A-Za-z_]', 'REGEXP_EXTRACT(jsonPayload.exc, "([A-Za-z_]')
        self.assertNotEqual(unanchored, self.catalogue.text, "the CRM extractor's text moved; update this test")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "monitoring.yml"
            path.write_text(unanchored)
            self.assertEqual(cat.Catalogue(path).unanchored_labels("crm", "errors"), {"class"})

    def test_every_quiet_token_names_a_known_sweep_or_database(self):
        known = set(gen.SWEEPS) | set(gen.DATABASES)
        problems = []
        for path in DASHBOARDS:
            for token in re.findall(r"@@[RF](,[a-z0-9,-]*,)@@", path.read_text()):
                unknown = set(token.strip(",").split(",")) - known
                if unknown:
                    problems.append(f"{path.name}: {sorted(unknown)}")
        self.assertEqual(problems, [])

    def test_the_render_script_knows_exactly_the_generators_names(self):
        script = (ROOT / "cloud" / "render-dashboards.sh").read_text()
        sweeps = re.search(r'^KNOWN_SWEEPS="([^"]*)"', script, re.M).group(1).split()
        databases = re.search(r'^KNOWN_DATABASES="([^"]*)"', script, re.M).group(1).split()
        self.assertEqual(sweeps, list(gen.SWEEPS))
        self.assertEqual(databases, list(gen.DATABASES))

    def test_no_cc_variants_read_no_call_centre_project(self):
        variants = [p for p in DASHBOARDS if p.parent.name == "no-cc"]
        self.assertEqual(sorted(p.stem for p in variants), sorted(gen.NO_CC))
        for path in variants:
            text = path.read_text()
            self.assertNotIn("cloud-cc", text, path)
            self.assertNotIn("__TPA_CC_PROJECT_ID__", text, path)

    def _log_metric(self, role: str, name: str) -> dict | None:
        """The catalogue entry a dashboard's log metric name reads in this role's project."""
        if name in self.valid[role]:
            return self.catalogue.metric(role, self.valid[role][name])
        return None


class DatasourceContractTest(unittest.TestCase):
    def test_exactly_the_four_cloud_datasources(self):
        self.assertEqual(lint.cloud_datasources(), {
            "cloud-app": "TPA_APP_PROJECT_ID", "cloud-crm": "TPA_CRM_PROJECT_ID",
            "cloud-phi": "TPA_PHI_PROJECT_ID", "cloud-cc": "TPA_CC_PROJECT_ID"})

    def test_every_datasource_sets_both_project_fields(self):
        text = (ROOT / "cloud" / "provisioning" / "datasources" / "cloud-monitoring.yml").read_text()
        for var in lint.cloud_datasources().values():
            self.assertIn(f"defaultProject: ${{{var}}}", text)
            # Grafana's browser side reads this one under gce authentication.
            self.assertIn(f"gceDefaultProject: ${{{var}}}", text)
        self.assertEqual(text.count("authenticationType: gce"), 4)

    def test_the_render_script_fills_every_placeholder(self):
        script = (ROOT / "cloud" / "render-dashboards.sh").read_text()
        for var in lint.cloud_datasources().values():
            self.assertIn(f's/{lint.project_placeholder(var)}/', script)


if __name__ == "__main__":
    unittest.main()
