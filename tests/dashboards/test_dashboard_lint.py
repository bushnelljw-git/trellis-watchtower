"""scripts/dashboard_lint.py must fail the bad fixtures and pass the good one and the real dashboards.

Run: python3 -m unittest discover -s tests/dashboards -v
"""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LINT = ROOT / "scripts" / "dashboard_lint.py"


def lint(*paths):
    result = subprocess.run([sys.executable, str(LINT), *map(str, paths)], capture_output=True, text=True)
    return result.returncode, result.stdout


class DashboardLintTest(unittest.TestCase):
    def test_bad_fixtures_fail_for_each_reason(self):
        code, out = lint(HERE / "bad")
        self.assertEqual(code, 1, out)
        for expected in [
            "forbidden field `tenant_id`",
            "forbidden field `request_id`",
            "forbidden field `uri`",
            "forbidden field `sid`",
            "unknown datasource uid `mystery`",
            "dashboard has no uid",
            "uid `tw-bad` is already used",
            # A cloud datasource has no place in a local dashboard.
            "unknown datasource uid `cloud-app` (allowed: loki, prometheus)",
        ]:
            self.assertIn(expected, out)

    def test_near_misses_pass(self):
        code, out = lint(HERE / "good")
        self.assertEqual(code, 0, out)

    def test_bad_cloud_fixtures_fail_for_each_reason(self):
        code, out = lint("--cloud", HERE / "cloud-bad")
        self.assertEqual(code, 1, out)
        for expected in [
            'variable "who": a cloud dashboard declares no template variables',
            'panel "promql": query A: queryType must be `timeSeriesList` (the filter form), not `promQL`',
            'panel "promql": query A: carries a `promQLQuery` block; the filter form only',
            'panel "wrong project": query A: projectName must be `__TPA_PHI_PROJECT_ID__` on `cloud-phi`',
            'panel "revision label": query A: names the label `resource.label.revision_name`',
            'panel "no resource type": query A: uses a resource label without filtering on resource.type',
            'panel "not google": query A: metric.type `custom.googleapis.com/anything` is not one Google Cloud',
            'panel "mixed": mixes datasources (cloud-app, cloud-phi); one per panel',
            'panel "lines": panel type `logs` is not one a cloud dashboard uses',
            'panel "tenant": references the forbidden field `tenant`',
            'panel "tenant": query A: names the label `metric.label.tenant`',
            "uses unknown datasource uid `loki` (allowed: cloud-app, cloud-cc, cloud-crm, cloud-phi)",
            'panel "viewer steered": query A: names a Grafana variable; a cloud query is fixed',
            'panel "negated": query A: filter `resource.label.service_name !=~` uses an operator outside',
            'panel "headers only": query A: view must be FULL',
            'panel "broken filters": query A: filters are not [key, operator, value] joined by AND',
        ]:
            self.assertIn(expected, out)

    def test_good_cloud_fixture_passes(self):
        code, out = lint("--cloud", HERE / "cloud-good")
        self.assertEqual(code, 0, out)

    def test_repository_dashboards_pass(self):
        code, out = lint()
        self.assertEqual(code, 0, out)

    def test_cloud_dashboards_are_what_the_generator_writes(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "cloud_dashboards.py"), "--check"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class CloudMutationTest(unittest.TestCase):
    """Each mutation of a real cloud dashboard must fail the lint with its own message (the holes the review of
    cfbc3a7 found by mutation)."""

    @classmethod
    def setUpClass(cls):
        cls.overview = json.loads((ROOT / "cloud" / "dashboards" / "overview.json").read_text())

    def lint_mutated(self, mutate) -> tuple[int, str]:
        dashboard = copy.deepcopy(self.overview)
        mutate(dashboard)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "overview.json"
            path.write_text(json.dumps(dashboard))
            return lint("--cloud", path)

    def panel(self, dashboard, title, row=None):
        current = None
        for p in dashboard["panels"]:
            if p["type"] == "row":
                current = p["title"]
            elif p["title"] == title and (row is None or current.startswith(row)):
                return p
        raise KeyError(title)

    def first_query(self, dashboard, title, row=None):
        return self.panel(dashboard, title, row)["targets"][0]["timeSeriesList"]

    def assertCaught(self, mutate, message):
        code, out = self.lint_mutated(mutate)
        self.assertEqual(code, 1, out)
        self.assertIn(message, out)

    def test_the_unmutated_dashboard_passes(self):
        code, out = self.lint_mutated(lambda d: None)
        self.assertEqual(code, 0, out)

    def test_a_missing_reducer(self):
        self.assertCaught(lambda d: self.first_query(d, "5xx (1 h)", "Sign-in").pop("crossSeriesReducer"),
                          "has no crossSeriesReducer")

    def test_reduce_none(self):
        self.assertCaught(lambda d: self.first_query(d, "5xx (1 h)", "Sign-in").update(
            crossSeriesReducer="REDUCE_NONE"), "crossSeriesReducer `REDUCE_NONE` is not a reducer that groups")

    def test_secondary_reduce_none(self):
        self.assertCaught(lambda d: self.first_query(d, "Error groups (24 h)", "Sign-in").update(
            secondaryCrossSeriesReducer="REDUCE_NONE"),
            "secondaryCrossSeriesReducer `REDUCE_NONE` is not a reducer that groups")

    def test_a_secondary_aggregation_without_its_reducer(self):
        self.assertCaught(lambda d: self.first_query(d, "Error groups (24 h)", "Sign-in").pop(
            "secondaryCrossSeriesReducer"), "has no secondaryCrossSeriesReducer")

    def test_bare_field_labels_in_a_display_name(self):
        self.assertCaught(lambda d: self.panel(d, "Uptime checks passing (24 h)")["fieldConfig"]["defaults"].update(
            displayName="${__field.labels}"), "a legend names `__field.labels` without a key")

    def test_bare_field_labels_in_an_override(self):
        def mutate(d):
            self.panel(d, "Uptime checks passing (24 h)")["fieldConfig"]["overrides"].append(
                {"matcher": {"id": "byFrameRefID", "options": "A"},
                 "properties": [{"id": "displayName", "value": "host ${__field.labels}"}]})
        self.assertCaught(mutate, "a legend names `__field.labels` without a key")

    def test_a_field_label_off_the_allowlist(self):
        self.assertCaught(lambda d: self.panel(d, "Uptime checks passing (24 h)")["fieldConfig"]["defaults"].update(
            displayName="${__field.labels.revision_name}"), "a legend names the label `revision_name`")

    def test_a_field_label_on_the_allowlist_passes(self):
        code, out = self.lint_mutated(lambda d: self.panel(d, "Uptime checks passing (24 h)")[
            "fieldConfig"]["defaults"].update(displayName="${__field.labels.resource.label.host}"))
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
