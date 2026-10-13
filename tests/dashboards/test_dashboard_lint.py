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
            # No panel reads raw log lines; a Canvas card's field is checked like a query.
            'panel "lines panel": a `logs` panel shows raw log lines',
            'panel "lines in a table": query B: is a log query (it returns raw lines)',
            'panel "card reads an id": references the forbidden field `tenant_id`',
            # The nine holes round 1's evaluators found by mutating the home page.
            'mut-canvas-tid.json: panel "map": references the forbidden field `tid`',
            'mut-comment-rawlines.json: panel "comment": query A: is a log query',
            'mut-datalink-tid.json: panel "datalink": references the forbidden field `tid`',
            'mut-json-explode.json: panel "explode": query A: a bare `| json` turns every field',
            'mut-json-explode.json: panel "explode": query A: a selector is not inside an aggregation',
            'mut-legend-instance.json: panel "instance legend": query A: the legend names the label `instance`',
            'mut-loki-no-type.json: panel "no type": query A: is a log query',
            'mut-novalue-tenant.json: panel "novalue": references the forbidden field `tenant`',
            'mut-panellink-reqid.json: panel "panel link": references the forbidden field `request_id`',
            'mut-sum-without.json: panel "without": query A: uses `without`',
            'mut-sum-without.json: panel "without": query A: a bare `| logfmt`',
            # Round 2's evaluators' mutations, and the copy-into-a-label rules (5c, 5d).
            'mut3-annotation-raw.json: annotation "lines" (expr): is a log query',
            'mut3-hidden-raw.json: panel "hidden": query ZZ: is a log query',
            'mut3-paren-selector.json: panel "paren": query A: a selector is not inside an aggregation',
            'mut3-loki-string-ds.json: panel "string ds": query A: is a log query',
            'mut3-bare-field-labels.json: panel "bare labels": names `__field.labels` without a key',
            'mut3-label-replace-source.json: panel "address": query A: `label_replace` reads the label `__address__`',
            'mut3-line-format.json: panel "line_format": query A: uses `| line_format`',
            'mut3-regexp-capture.json: panel "regexp": query A: uses a `| regexp` that is not one of VETTED_REGEXPS',
            'mut3-pattern.json: panel "pattern": query A: uses `| pattern`',
            'mut3-template-index.json: panel "index": query A: `| label_format where=...` is not one of VETTED',
            'mut3-label-format-rename.json: panel "rename": query A: `| label_format where=...` is not one of VETTED',
            'mut3-json-copy.json: panel "json copy": query A: `| json where="email"` copies another field',
            'mut3-msg-name-loose.json: panel "loose": query A: `| label_format msg_name=...` is not one of VETTED',
            'mut3-sql-expression.json: panel "sql": query Q: a `sql` expression',
            # Round 3's evaluators' bypasses.
            'mut4-annotation-target-expr.json: annotation "x" (target.expr): is a log query',
            'mut4-annotation-uid-only.json: annotation "y" (expr): is a log query',
            'mut4-regexp-angle-group.json: panel "angle": query A: uses a `| regexp` that is not one of VETTED',
            'mut4-regexp-unwrap-elsewhere.json: panel "elsewhere": query A: uses a `| regexp` that is not one of VETTED',
            'mut4-regexp-unwrap-elsewhere.json: panel "elsewhere": query A: `| unwrap where` reads a number that is not',
            'mut4-regexp-second-group.json: panel "two groups": query A: uses a `| regexp` that is not one of VETTED',
            'mut4-vetted-msg-other-source.json: panel "msg source": query A: `| label_format msg_name=...` reads `m1`, which must be set once',
            'mut4-vetted-n-other-source.json: panel "n source": query A: `| label_format n=...` reads `f`',
            'mut4-logfmt-operation.json: panel "logfmt op": query A: `| logfmt operation="member"` copies',
            'mut4-json-unlisted-by.json: panel "who": query A: `by (...)` names the label `who`',
            # Round 4's evaluators' bypasses: an unwrapped identifier, a helper set twice, a library panel, an
            # annotation printing the instance.
            'mut5-library-panel.json: panel "library": is a library panel (`libraryPanel`)',
            'mut5-logfmt-then-json-pin.json: panel "pin twice": query A: `| label_format msg_name=...` reads `m1`, '
            'which must be set once',
            'mut5-annotation-titleformat.json: annotation "z": `titleFormat` names the label `instance`',
            'mut5-annotation-titleformat.json: annotation "z": `tagKeys` names the label `instance`',
            'mut5-unwrap-date-of-birth.json: panel "dob": query A: `| unwrap d` reads a number that is not one of '
            'VETTED_UNWRAPS',
            'mut5-unwrap-member-number.json: panel "member number": query A: `| unwrap x` reads a number that is not',
            'mut5-regexp-digits-identifier.json: panel "digits": query A: uses a `| regexp` that is not one of VETTED',
            # Loki's recording rules are queries too.
            'mut5-loki-rules.yml:7: is a log query',
            'mut5-loki-rules.yml:9: `by (...)` names the label `member`',
            'mut5-loki-rules.yml:13: a rule label `principal` is not on LOCAL_LABELS',
            'mut5-loki-rules.yml:15: an expr must be one double-quoted line',
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

    def test_cloud_nat_by_its_address_is_refused(self):
        # Cloud NAT's gateway and drop reason are on the list; the address a port belongs to is not.
        def mutate(d):
            tsl = self.first_query(d, "5xx (1 h)", "Sign-in")
            tsl["filters"] = ["metric.type", "=", "router.googleapis.com/nat/allocated_ports",
                              "AND", "resource.type", "=", "nat_gateway"]
            tsl["groupBys"] = ["resource.label.gateway_name", "metric.label.nat_ip"]
        self.assertCaught(mutate, "names the label `metric.label.nat_ip`, which is not on the allowlist")

    def test_a_drop_reason_off_the_nat_drop_counter_is_refused(self):
        # `reason` is Cloud NAT's word for a dropped packet; on any other metric it is refused.
        def mutate(d):
            tsl = self.first_query(d, "5xx (1 h)", "Sign-in")
            tsl["groupBys"] = ["resource.label.service_name", "metric.label.reason"]
        self.assertCaught(mutate, "names the label `metric.label.reason`, allowed only on "
                                  "router.googleapis.com/nat/dropped_sent_packets_count")

    def test_a_field_label_on_the_allowlist_passes(self):
        code, out = self.lint_mutated(lambda d: self.panel(d, "Uptime checks passing (24 h)")[
            "fieldConfig"]["defaults"].update(displayName="${__field.labels.resource.label.host}"))
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
