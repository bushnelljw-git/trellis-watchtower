"""scripts/dashboard_lint.py must fail the bad fixtures and pass the good one and the real dashboards.

Run: python3 -m unittest discover -s tests/dashboards -v
"""

import subprocess
import sys
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
            "unknown datasource uid `cloud-app` (allowed: fly, loki, prometheus)",
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


if __name__ == "__main__":
    unittest.main()
