"""The Errors page's Cloud Armor row: every legend name whole at four charts to a line.

At four to a line (w=6) a right-hand legend shows about 25 characters of a name at 1280 px: `attack rule in preview
would refuse` was cut to `attack rule in preview wo`, and the max and last columns were out of sight to its right.
The names are now at most 25 characters (`Adaptive Protection alert`, the longest, whole in the render of 2026-11-21)
and the legend is names alone.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import cloud_dashboards as gen  # noqa: E402

ROW = "Cloud Armor: attack rules and Adaptive Protection, by project"
# The characters a quarter-width chart's legend shows of a name at 1280 px (the render of 2026-11-21).
QUARTER_WIDTH_NAME = 25


def row_panels(path: Path, title: str) -> list[dict]:
    panels, inside = [], False
    for p in json.loads(path.read_text())["panels"]:
        if p["type"] == "row":
            inside = p["title"] == title
            assert not p.get("collapsed"), p["title"]
        elif inside:
            panels.append(p)
    return panels


class ArmorLegend(unittest.TestCase):
    def test_every_name_whole(self):
        for path, charts in ((ROOT / "cloud/dashboards/errors.json", 4),
                             (ROOT / "cloud/dashboards/no-cc/errors.json", 3)):
            panels = row_panels(path, ROW)
            self.assertEqual(len(panels), charts, path)
            for p in panels:
                where = f"{path.parent.name}/{path.name}: {p['title']}"
                self.assertEqual(p["gridPos"]["w"], 24 // charts, where)
                self.assertEqual(p["gridPos"]["h"], 7, where)
                self.assertEqual(p["options"]["legend"], {"displayMode": "table", "placement": "right",
                                                          "showLegend": True, "calcs": []}, where)
                names = [t["aliasBy"] for t in p["targets"]]
                self.assertEqual(names, [name for _counter, name in gen.ARMOR_NAMES], where)
                for name in names:
                    self.assertLessEqual(len(name), QUARTER_WIDTH_NAME, f"{where}: {name}")
                for counter, _name in gen.ARMOR_NAMES:
                    self.assertIn(f"logging.googleapis.com/user/{counter}", json.dumps(p["targets"]), where)


if __name__ == "__main__":
    unittest.main()
