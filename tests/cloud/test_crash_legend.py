"""The Errors page's crash row: Google's method names shortened, every name whole and in sight.

At four to a line (w=6, h=7) the legend showed about 25 characters of a name at 1280 px (`crashed: auth-outbox-pu`)
and seven names, so the `secret:` and `key:` names, Google's whole method names
(`google.cloud.secretmanager.v1.SecretManagerService.DisableSecretVersion`), were cut or out of sight. The charts are
now two to a line, 12 high, a legend of names alone (14 rows at 1470 and 1280 px, rendered 2026-11-21), and the
method names are shortened by the security row's `SHORT_METHOD_NAMES`.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))

import cloud_dashboards as gen  # noqa: E402
from test_security_legend import rename  # noqa: E402

ROW = "Crashes, out-of-memory kills, and secret or key versions taken away"
# At 12 high a chart's legend shows 14 names whole without scrolling, at 1470 and 1280 px (the render of
# 2026-11-21): the five methods `secret_version_changes` and `kms_version_changes` count, and nine services and jobs.
HEIGHT = 12

SHORTENED = {
    "secret: google.cloud.secretmanager.v1.SecretManagerService.DisableSecretVersion": "secret: DisableSecretVersion",
    "secret: google.cloud.secretmanager.v1.SecretManagerService.DestroySecretVersion": "secret: DestroySecretVersion",
    "secret: google.cloud.secretmanager.v1.SecretManagerService.DeleteSecret": "secret: DeleteSecret",
    "key: google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion": "key: DestroyCryptoKeyVersion",
    "key: google.cloud.kms.v1.KeyManagementService.UpdateCryptoKeyVersion": "key: UpdateCryptoKeyVersion",
    # KMS may write the short name; services and jobs are never renamed.
    "key: DestroyCryptoKeyVersion": "key: DestroyCryptoKeyVersion",
    "crashed: auth-outbox-publisher": "crashed: auth-outbox-publisher",
    "OOM: records-chain-head": "OOM: records-chain-head",
}


def row_panels(path: Path) -> list[dict]:
    panels, inside = [], False
    for p in json.loads(path.read_text())["panels"]:
        if p["type"] == "row":
            inside = p["title"] == ROW
            assert not p.get("collapsed"), p["title"]
        elif inside:
            panels.append(p)
    return panels


class CrashLegend(unittest.TestCase):
    def test_method_names_shortened(self):
        for whole, short in SHORTENED.items():
            self.assertEqual(rename(whole, gen.SHORT_METHOD_NAMES), short, whole)

    def test_every_chart_holds_its_legend(self):
        for path, charts in ((ROOT / "cloud/dashboards/errors.json", 4),
                             (ROOT / "cloud/dashboards/no-cc/errors.json", 3)):
            panels = row_panels(path)
            self.assertEqual(len(panels), charts, path)
            self.assertEqual(sum(p["gridPos"]["w"] for p in panels), 24 * ((charts + 1) // 2), path)
            for p in panels:
                where = f"{path.parent.name}/{path.name}: {p['title']}"
                self.assertGreaterEqual(p["gridPos"]["w"], 12, where)
                self.assertGreaterEqual(p["gridPos"]["h"], HEIGHT, where)
                self.assertEqual(p["options"]["legend"], {"displayMode": "table", "placement": "right",
                                                          "showLegend": True, "calcs": []}, where)
                self.assertEqual(p["transformations"], list(gen.SHORT_METHOD_NAMES), where)
                self.assertEqual([t["aliasBy"].split("{{")[0] for t in p["targets"]],
                                 ["crashed: ", "OOM: ", "OOM: ", "secret: ", "key: "], where)


if __name__ == "__main__":
    unittest.main()
