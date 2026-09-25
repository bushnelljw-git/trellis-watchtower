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
        ]:
            self.assertIn(expected, out)

    def test_near_misses_pass(self):
        code, out = lint(HERE / "good")
        self.assertEqual(code, 0, out)

    def test_repository_dashboards_pass(self):
        code, out = lint()
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
