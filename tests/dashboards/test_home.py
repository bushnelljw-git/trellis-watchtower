"""The home dashboard: it is what scripts/gen_home.py writes, and every probed service has a card on its map.

Run: python3 -m unittest discover -s tests/dashboards -v   (also run by `make lint` and `make check`)
"""

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HOME = ROOT / "grafana" / "dashboards" / "home.json"
TARGETS = ROOT / "prometheus" / "targets"


def probed_services() -> set[str]:
    """Every `service:` label in prometheus/targets/*.yml (the always-on probes)."""
    found = set()
    for path in sorted(TARGETS.glob("*.yml")):
        found |= set(re.findall(r"\bservice:\s*([A-Za-z0-9_.-]+)", path.read_text()))
    return found


def canvas_fields(node) -> set[str]:
    """Every field a Canvas element reads (text or colour), recursively through frames."""
    out = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "field" and isinstance(value, str) and value:
                out.add(value)
            else:
                out |= canvas_fields(value)
    elif isinstance(node, list):
        for value in node:
            out |= canvas_fields(value)
    return out


class HomeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = json.loads(HOME.read_text())
        cls.map = next(p for p in cls.home["panels"] if p.get("type") == "canvas")

    def test_home_is_what_the_generator_writes(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_home.py"), "--check"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_every_probed_service_has_a_card(self):
        services = probed_services()
        self.assertTrue(services, "no services found in prometheus/targets/*.yml")
        fields = canvas_fields(self.map["options"]["root"])
        missing = sorted(s for s in services if s not in fields)
        self.assertEqual(missing, [], "these probed services have no card on the home map (add one in "
                                      "scripts/gen_home.py: CARD_SERVICES and system_map)")

    def test_a_service_without_a_card_still_shows(self):
        # Anything probed without a card of its own lands on the "other checks" card.
        exprs = [t.get("expr", "") for t in self.map["targets"]]
        self.assertTrue(any('probe:state{service!~"' in e for e in exprs))
        self.assertIn("unmapped", canvas_fields(self.map["options"]["root"]))

    def test_the_headline_never_defaults_to_normal(self):
        hero = next(p for p in self.home["panels"] if p.get("id") == 1)
        self.assertEqual(hero["fieldConfig"]["defaults"]["noValue"], "? Can't tell")
        ok = next(t for t in hero["targets"] if t["refId"] == "OK")
        self.assertEqual(ok["datasource"]["uid"], "__expr__")
        # The problem series never fall back to a constant, so a blind query cannot read as "nothing wrong".
        for t in hero["targets"]:
            if t["refId"] in ("PD", "PG", "AL", "BL", "WE", "DR"):
                self.assertNotIn("or vector(0)\n", t.get("expr", "") + "\n", t["refId"])

    def test_log_answers_wait_for_lines_to_reach_loki(self):
        # A worker is "stale" only while other lines are arriving: every log-derived answer (the problems, the side's
        # totals, the map's worker cards and the stale alert) is gated on Loki's ruler counting lines.
        heartbeat = "sum(sum_over_time(tw:loki_rules:heartbeat[1m])) > 0"
        hero = next(p for p in self.home["panels"] if p.get("id") == 1)
        for t in hero["targets"]:
            if t["refId"] in ("WS", "WE", "DR", "NR", "T2", "R2"):
                self.assertIn(heartbeat, t["expr"], t["refId"])
        workers = [t for t in self.map["targets"] if t.get("legendFormat", "").startswith(("job ", "age "))]
        self.assertTrue(workers)
        for t in workers:
            self.assertIn(heartbeat, t["expr"], t["legendFormat"])
        alerts = (ROOT / "prometheus" / "rules" / "home.yml").read_text()
        stale = alerts[alerts.index("alert: WorkerStale"):]
        self.assertIn(heartbeat, stale.split("\n")[1].replace('\\"', '"'))


if __name__ == "__main__":
    unittest.main()
