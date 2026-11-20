"""The Errors page's security changes: every series named in the legend without scrolling it, and each name whole.

At four to a line (w=6, h=7) the app project's legend held seven names at 1280 px: the eighth, `who may pass IAP`
(D-447's `backend_iam_changes`), was out of sight, and Google's method names were cut to `goog...`. The charts are
now two to a line, 14 high, a legend of names alone (19 rows at 1470 and 1280 px, rendered 2026-11-20), and the
method names are shortened by two `renameByRegex` steps.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import cloud_dashboards as gen  # noqa: E402

ROW = "Security and configuration changes (Admin Activity audit log), by project"
# The names one chart's legend shows whole without scrolling, at 1470 and 1280 px (the render of 2026-11-20).
LEGEND_ROWS = 19

SHORTENED = {
    "IAP: google.cloud.iap.v1.IdentityAwareProxyAdminService.UpdateIapSettings": "IAP: UpdateIapSettings",
    "who may pass IAP: google.cloud.iap.v1.IdentityAwareProxyAdminService.SetIamPolicy":
        "who may pass IAP: SetIamPolicy",
    "who may pass IAP: v1.compute.backendServices.setIamPolicy": "who may pass IAP: backendServices.setIamPolicy",
    "IAP: beta.compute.backendServices.patch": "IAP: backendServices.patch",
    "firewall or Armor: v1.compute.securityPolicies.patchRule": "firewall or Armor: securityPolicies.patchRule",
    "logging: google.logging.v2.ConfigServiceV2.UpdateSink": "logging: UpdateSink",
    "log counters: google.logging.v2.MetricsServiceV2.UpdateLogMetric": "log counters: UpdateLogMetric",
    "alerts: google.monitoring.v3.AlertPolicyService.UpdateAlertPolicy": "alerts: UpdateAlertPolicy",
    "service account key: google.iam.admin.v1.CreateServiceAccountKey":
        "service account key: CreateServiceAccountKey",
    "IAM: google.iam.admin.v1.CreateRole": "IAM: CreateRole",
    "made public: google.cloud.run.v2.Services.SetIamPolicy": "made public: Services.SetIamPolicy",
    "made public: google.cloud.run.v2.Jobs.SetIamPolicy": "made public: Jobs.SetIamPolicy",
    "org policy: google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy": "org policy: OrgPolicy.UpdatePolicy",
    # Already short: left as they are.
    "IAM: SetIamPolicy": "IAM: SetIamPolicy",
    "SQL export by hand: cloudsql.instances.export": "SQL export by hand: cloudsql.instances.export",
    "IAM: storage.setIamPermissions": "IAM: storage.setIamPermissions",
}


def rename(name: str, steps) -> str:
    """Grafana's renameByRegex on a display name: a match is replaced with the pattern ($1 as \\1)."""
    for step in steps:
        assert step["id"] == "renameByRegex", step
        regex = re.compile(step["options"]["regex"])
        if regex.search(name):
            name = regex.sub(re.sub(r"\$(\d)", r"\\\1", step["options"]["renamePattern"]), name)
    return name


def security_panels(path: Path) -> list[dict]:
    panels, inside = [], False
    for p in json.loads(path.read_text())["panels"]:
        if p["type"] == "row":
            inside = p["title"] == ROW
            assert not p.get("collapsed"), p["title"]
        elif inside:
            panels.append(p)
    return panels


class SecurityLegend(unittest.TestCase):
    def test_method_names_shortened(self):
        for whole, short in SHORTENED.items():
            self.assertEqual(rename(whole, gen.SHORT_METHOD_NAMES), short, whole)

    def test_every_chart_holds_its_legend(self):
        for path, charts in ((ROOT / "cloud/dashboards/errors.json", 4),
                             (ROOT / "cloud/dashboards/no-cc/errors.json", 3)):
            panels = security_panels(path)
            self.assertEqual(len(panels), charts, path)
            self.assertEqual(sum(p["gridPos"]["w"] for p in panels), 24 * ((charts + 1) // 2), path)
            for p in panels:
                where = f"{path.parent.name}/{path.name}: {p['title']}"
                self.assertGreaterEqual(p["gridPos"]["w"], 12, where)
                self.assertGreaterEqual(p["gridPos"]["h"], 14, where)
                self.assertEqual(p["options"]["legend"], {"displayMode": "table", "placement": "right",
                                                          "showLegend": True, "calcs": []}, where)
                self.assertEqual(p["transformations"], list(gen.SHORT_METHOD_NAMES), where)
                # One counter, one method each, and room to spare: a second method or a new counter is still seen.
                self.assertLessEqual(len(p["targets"]) + 5, LEGEND_ROWS, where)
            self.assertIn("backend_iam_changes", json.dumps(panels[0]["targets"]), path)


if __name__ == "__main__":
    unittest.main()
