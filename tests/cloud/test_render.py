"""cloud/render-dashboards.sh fills each query's project placeholder from the service's environment, and refuses
anything that is not a project id.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "cloud" / "render-dashboards.sh"
DASHBOARDS = ROOT / "cloud" / "dashboards"
IDS = {"TPA_APP_PROJECT_ID": "beta-tpa-app", "TPA_CRM_PROJECT_ID": "beta-tpa-app",
       "TPA_PHI_PROJECT_ID": "beta-tpa-phi", "TPA_CC_PROJECT_ID": "beta-callcentre"}


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src, self.dst = self.tmp / "src", self.tmp / "dst"
        shutil.copytree(DASHBOARDS, self.src, ignore=shutil.ignore_patterns("*.md"))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def render(self, **env):
        base = {k: v for k, v in os.environ.items() if not k.startswith("TPA_")}
        return subprocess.run(["sh", str(SCRIPT), "--render-only", str(self.src), str(self.dst)],
                              env={**base, **env}, capture_output=True, text=True)

    def projects(self) -> dict[str, set[str]]:
        found: dict[str, set[str]] = {}
        for path in self.dst.glob("*.json"):
            for panel in json.loads(path.read_text())["panels"]:
                for target in panel.get("targets") or []:
                    found.setdefault(target["datasource"]["uid"], set()).add(target["timeSeriesList"]["projectName"])
        return found

    def test_every_query_gets_its_datasource_project(self):
        result = self.render(**IDS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(list(self.dst.glob("*.json"))), len(list(self.src.glob("*.json"))))
        self.assertEqual(self.projects(), {"cloud-app": {"beta-tpa-app"}, "cloud-crm": {"beta-tpa-app"},
                                           "cloud-phi": {"beta-tpa-phi"}, "cloud-cc": {"beta-callcentre"}})
        overview = (self.dst / "overview.json").read_text()
        self.assertIn("incidents?project=beta-tpa-phi", overview)
        self.assertNotIn("__TPA_", "".join(p.read_text() for p in self.dst.glob("*.json")))

    def test_no_call_centre_project_leaves_its_queries_without_one(self):
        result = self.render(**{**IDS, "TPA_CC_PROJECT_ID": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.projects()["cloud-cc"], {""})

    def test_a_required_project_missing_is_refused(self):
        env = dict(IDS)
        del env["TPA_PHI_PROJECT_ID"]
        result = self.render(**env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TPA_PHI_PROJECT_ID must be a Google Cloud project id", result.stderr)

    def test_anything_but_a_project_id_is_refused(self):
        for bad in ['beta-tpa-app"}', "beta/tpa", "Beta-Tpa-App", "x", "beta-tpa-app-", "a" * 31]:
            result = self.render(**{**IDS, "TPA_APP_PROJECT_ID": bad})
            self.assertNotEqual(result.returncode, 0, bad)
            self.assertIn("TPA_APP_PROJECT_ID must be a Google Cloud project id", result.stderr)

    def test_a_placeholder_with_no_variable_is_refused(self):
        (self.src / "stray.json").write_text('{"x": "__TPA_VAULT_PROJECT_ID__"}')
        result = self.render(**IDS)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("a placeholder above has no variable here", result.stderr)


if __name__ == "__main__":
    unittest.main()
