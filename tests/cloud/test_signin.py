"""The overview's first row, "Can people sign in?" (SR-OR-1; the owner, 2026-11-12, of the robots that sign in as a
member and a broker every five minutes and page when they cannot: "i want these alerts on the main watchtower
dashboard").

- The row is the first thing on every overview, open: the two robots, the texted codes and the emails going out, the
  outside checks on the portal host, and the sign-in alerts (production-full, which builds none of the robots, the
  texts' delivery reads or the outside checks, has the messenger's part alone).
- Every query of the robots' result lines names a robot's job, reads the catalogue's metric and labels, and is never
  sent while that robot is not deployed (its counter does not exist until tpa-platform builds it: a 404). The staff
  journeys J1 to J3 are read nowhere (off by ruling).
- Each window is its policy's own, read from the vendored catalogue; the robots' names, their people and the
  database they need are the beta root's; the outside checks are the root's.
- What each tile shows in each state is fed through tests/cloud/grafana_model.py: the frames Cloud Monitoring would
  return for a scenario (each window's latest point at the range's end, none for a quiet window), read as the tile's
  own transformations read them.
- Nothing empty reads "No data": not deployed, paused, auth-db stopped, and running with nothing, each in words.

Run: python3 -m unittest discover -s tests/cloud -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import catalogue as cat  # noqa: E402
import cloud_dashboards as gen  # noqa: E402
import dashboard_lint as lint  # noqa: E402
import grafana_model as model  # noqa: E402
from synthetics import result  # noqa: E402
from test_catalogue import promql_name  # noqa: E402
from test_resources import (CHECKOUT_PRESENT, DASHBOARDS, ENVIRONMENTS, INFRA, INFRA_SOURCE, RENDER,  # noqa: E402
                            RENDERED, sections)

CATALOGUE = cat.Catalogue()
BUILT = ",".join((gen.ROBOT_SECRETS, *gen.ROBOT_JOBS))   # stage 2: the secrets and both robots
BETA_TILES = ["Member robot", "Broker robot", "Texted codes (24 h)", "Emails (24 h)", "Outside checks",
              "Sign-in alerts"]
PRODUCTION_TILES = ["Emails (24 h)", "Sign-in alerts"]
END = 1_000_000_000_000   # the range's end, in ms (any fixed number: the frames are placed against it)


def render(**env) -> dict[str, dict]:
    """The pages as the image renders them for beta with these settings beside its project ids."""
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "src", Path(tmp) / "dst"
        shutil.copytree(DASHBOARDS, src, ignore=shutil.ignore_patterns("*.md"))
        base = {k: v for k, v in os.environ.items() if not k.startswith("TPA_")}
        done = subprocess.run(["sh", str(RENDER), "--render-only", str(src), str(dst)],
                              env={**base, **ENVIRONMENTS["beta"], **env}, capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        return {p.stem: json.loads(p.read_text()) for p in dst.glob("*.json")}


def refused(**env) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "src", Path(tmp) / "dst"
        shutil.copytree(DASHBOARDS, src, ignore=shutil.ignore_patterns("*.md"))
        base = {k: v for k, v in os.environ.items() if not k.startswith("TPA_")}
        done = subprocess.run(["sh", str(RENDER), "--render-only", str(src), str(dst)],
                              env={**base, **env}, capture_output=True, text=True)
        assert done.returncode != 0, "rendered, not refused"
        return done.stderr


def row_tiles(overview: dict) -> tuple[dict, list[dict]]:
    head, *rest = overview["panels"]
    tiles = []
    for p in rest:
        if p["type"] == "row":
            break
        tiles.append(p)
    return head, tiles


def tile(pages: dict, title: str) -> dict:
    return next(p for p in row_tiles(pages["overview"])[1] if p["title"] == title)


def facts(target: dict) -> dict:
    return lint.query_facts(target["timeSeriesList"])


def where(target: dict) -> dict[str, tuple[str, str]]:
    return {k.split(".")[-1]: (op, v) for k, op, v in facts(target)["filters"] if k not in ("metric.type",
                                                                                          "resource.type")}


def period_s(target: dict) -> int:
    return int(target["timeSeriesList"]["alignmentPeriod"].removeprefix("+").removesuffix("s"))


def all_targets(pages: dict):
    for name, page in pages.items():
        for p in lint.panels(page):
            for t in p.get("targets") or []:
                yield name, p, t


# ---- Scenarios: what Cloud Monitoring would return -----------------------------------------------------------------
def robot_frames(panel: dict, runs: list[tuple[float, str, str, str]]) -> list[dict]:
    """The frames of a panel's robot queries for these runs, each (minutes ago, robot job, outcome, code): every
    window's count at the range's end and each period back, a point only where a run fell (a counter writes nothing
    for a quiet period)."""
    span = int(panel["timeFrom"].removesuffix("h")) * 3600 if panel["timeFrom"].endswith("h") else \
        int(panel["timeFrom"].removesuffix("m")) * 60
    out = []
    for t in panel["targets"]:
        if facts(t)["metric"] != gen.SYNTHETIC or t.get("hide"):
            continue
        w, p = where(t), period_s(t)
        times, values = [], []
        for k in range(span // p + 1):
            hi, lo = k * p, (k + 1) * p   # seconds ago: (lo, hi]
            n = 0
            for ago, job, outcome, code in runs:
                s = ago * 60
                if not (hi <= s < lo) or job != w["job_name"][1]:
                    continue
                if "outcome" in w and outcome != w["outcome"][1]:
                    continue
                if "code" in w and not (re.fullmatch(w["code"][1], code) if w["code"][0] == "=~"
                                        else code == w["code"][1]):
                    continue
                n += 1
            if n:
                times.append(END - hi * 1000)
                values.append(n)
        if times:
            out.append(model.frame(t["refId"], t["aliasBy"], values[::-1], times[::-1]))
    return out


def latest(panel: dict, values: dict[str, float]) -> list[dict]:
    """Frames of a panel's other queries: each named by its alias, its latest window's value at the range's end."""
    return [model.frame(t["refId"], t["aliasBy"], [values[t["aliasBy"]]], [END]) for t in panel["targets"]
            if t["aliasBy"] in values and not t.get("hide")]


def shown(panel: dict, frames: list[dict]) -> dict[str, object]:
    """What a stat shows: each field's display name and its mapped word (or number); {} for nothing (no value). As
    Grafana picks a stat's fields: the numeric ones, and, with `reduceOptions.fields` set, those whose display name
    (after the overrides) matches it."""
    out = model.apply(frames, panel["transformations"])
    if not out or not out[0]["fields"] or not out[0]["fields"][0]["values"]:
        return {}
    words = {}
    for o in panel["fieldConfig"]["overrides"]:
        props = {x["id"]: x["value"] for x in o["properties"]}
        words[o["matcher"]["options"]] = props
    pick = panel["options"]["reduceOptions"].get("fields") or ""
    res = {}
    for x in out[0]["fields"]:
        props = words.get(x["name"], {})
        if x["time"] or (pick and not re.search(pick.strip("/"), props.get("displayName", x["name"]))):
            continue
        value = x["values"][-1]
        text = value
        for mapping in props.get("mappings", []):
            if mapping["type"] == "value" and value is not None and f"{value:g}" in mapping["options"]:
                text = mapping["options"][f"{value:g}"]["text"]
            elif mapping["type"] == "range" and value is not None and \
                    mapping["options"]["from"] <= value <= mapping["options"]["to"]:
                text = mapping["options"]["result"]["text"]
        res[props.get("displayName", x["name"])] = text
    return res


def rows(panel: dict, frames: list[dict]) -> list[tuple[str, float]]:
    """A table's rows: (its first column, its count)."""
    out = model.apply(frames, panel["transformations"])
    if not out:
        return []
    cols = {x["name"]: x["values"] for x in out[0]["fields"]}
    return list(zip(cols.get("Alert", []), cols.get("Pages", [])))


MEMBER, BROKER = gen.ROBOT_JOBS
# The two counters that watch the robots' logins (a secret read by anyone else, a login tried from anywhere but the
# runner): asked once the secrets exist, paused or not.
LOGIN_WATCH = (gen.log("signin_robot_secret_read"), gen.log(gen.FOREIGN))
SECRET_CHART, FOREIGN_CHART = "A robot's secret read by anyone else", "A robot's login tried from anywhere but its runner"
PASSWORD_ROW, GUESS_ROW = "✕ A robot's password used elsewhere", "⚠ A robot's login tried elsewhere"


def every_five(job: str, outcome: str = "pass", code: str = "ok", since: float = 0.5, until: float = 1440):
    """A run every five minutes from `since` to `until` minutes ago, each ending as said."""
    out, ago = [], since
    while ago < until:
        out.append((ago, job, outcome, code))
        ago += 5
    return out


class RowTest(unittest.TestCase):
    def test_the_row_is_first_and_open_on_every_overview(self):
        pages = {"beta": RENDERED["beta"]["overview"], "production": RENDERED["production"]["overview"],
                 "no-cc": json.loads((DASHBOARDS / "no-cc" / "overview.json").read_text())}
        for env, overview in pages.items():
            head, tiles = row_tiles(overview)
            self.assertEqual((head["type"], head["title"], head["collapsed"]), ("row", gen.SIGNIN_ROW, False), env)
            self.assertTrue(head["title"].startswith("Can people sign in?"), env)
            self.assertEqual([p["title"] for p in tiles], PRODUCTION_TILES if env == "production" else BETA_TILES, env)
            self.assertEqual(sum(p["gridPos"]["w"] for p in tiles), 24, env)
            self.assertEqual({p["gridPos"]["y"] for p in tiles}, {1}, env)

    def test_the_old_journey_tiles_are_gone_and_nothing_reads_the_staff_journeys(self):
        for env, pages in {**RENDERED, "built": render(TPA_SIGNIN_ROBOTS=BUILT)}.items():
            titles = [p["title"] for p in lint.panels(pages["overview"])]
            self.assertNotIn("Sign-in journeys (1 h)", titles, env)
            for name, p, t in all_targets(pages):
                if facts(t)["metric"] != gen.SYNTHETIC:
                    continue
                op, job = where(t).get("job_name", ("", ""))
                self.assertEqual((op, job in gen.ROBOT_JOBS), ("=", True), f"{env} {name}: {p['title']} {t['refId']}")
                self.assertNotEqual(env, "production", f"production-full builds no robot: {name} {p['title']}")
        for words in (json.dumps(RENDERED["beta"]), json.dumps(RENDERED["production"])):
            self.assertNotIn("J1", words)
            self.assertNotIn("synthetic journeys", words)

    def test_the_robots_are_the_roots_and_the_runners(self):
        self.assertTrue({k for k, *_r in gen.SIGNIN_ROBOTS} <= set(result.JOBS))
        self.assertEqual(gen.DISABLED, "disabled")
        self.assertEqual(result.OUTCOME_OF["disabled"], "skipped")
        # The lockout codes the policies read are the runner's own failure codes.
        self.assertTrue(all(result.OUTCOME_OF[c] == "fail" for c in gen.SIGNIN["lockout"].split("|")))
        if INFRA is None:
            if CHECKOUT_PRESENT:
                self.fail(INFRA_SOURCE)
            self.skipTest(f"SKIPPED LOUDLY: {INFRA_SOURCE}")
        tf = INFRA.show("infra/envs/beta/signinrobots.tf")
        robots = dict(re.findall(r'^\s+([a-z-]+) = \{ schedule = "[^"]+", login = "[a-z]+", secret = "[a-z-]+", '
                                 r'who = "([A-Za-z]+)", databases = \["auth_db"\] \}$', tf, re.M))
        self.assertEqual(robots, {k: who for k, who, *_r in gen.SIGNIN_ROBOTS})
        self.assertEqual(gen.ROBOT_DBS, ("auth-db",))
        self.assertIn('name                  = "synthetics-${each.key}"', tf)
        # A day switched off is a notice there (email and Slack, never PagerDuty), as the alerts tile weighs it.
        self.assertIn('"signin-checks-off-${k}" => "notice"', tf)
        for name in ("signin-failing", "signin-robot-locked-out", "signin-silent", "signin-robot-secret-read",
                     "signin-robot-foreign-password"):
            self.assertEqual(CATALOGUE.policy(name, section="signin_robots")["tier"], "p1", name)
        for name in ("signin-robot-broken", "signin-robot-foreign-guess"):
            self.assertEqual(CATALOGUE.policy(name, section="signin_robots")["tier"], "p2", name)

    def test_tpa_platform_writes_what_the_robots_read(self):
        # The three policies that watch the logins, and their two counters, are written once while the robots'
        # secrets exist (stage 1 on), paused or not and whatever auth-db is: so the alerts tile asks for them once
        # TPA_SIGNIN_ROBOTS names the secrets, and never weighs them 0. The website is told what is built and
        # what is paused in the apply that builds it (tpa-platform 10e20a62, the request in docs/REQUESTS.md).
        if INFRA is None:
            if CHECKOUT_PRESENT:
                self.fail(INFRA_SOURCE)
            self.skipTest(f"SKIPPED LOUDLY: {INFRA_SOURCE}")
        tf = " ".join(INFRA.show("infra/envs/beta/signinrobots.tf").split())
        self.assertIn('signin_robot_once_policies = [local.signin_robot_secret_policy, "signin-robot-foreign-password", '
                      '"signin-robot-foreign-guess"]', tf)
        self.assertIn('signin_robot_secret_policy = "signin-robot-secret-read"', tf)
        self.assertIn("for name in local.signin_robot_once_policies : name => "
                      "local.monitoring.signin_robots.alert_policies[name] if local.signin_robots_exist }", tf)
        self.assertIn("signin_robot_log_metrics = { for name, metric in local.monitoring.signin_robots.log_metrics : "
                      "name => metric if local.signin_robots_exist }", tf)
        # Merged into the app project with no database filter (so whatever auth-db is), and no tier of theirs is
        # overridden there (the tile weighs each by the catalogue's tier): the root's one robot override is a day
        # switched off.
        main = " ".join(INFRA.show("infra/envs/beta/main.tf").split())
        self.assertIn('{ for name, policy in local.signin_robot_policies : name => policy if p == "app" }', main)
        self.assertNotIn("signin-robot-foreign", main)
        self.assertIn('signin_robot_tier_overrides = { for k in keys(local.signin_robots_running) : '
                      '"signin-checks-off-${k}" => "notice" }', tf)
        self.assertIn("} : {}, local.signin_robot_tier_overrides)", main)
        watch = " ".join(INFRA.show("infra/envs/beta/watch.tf").split())
        self.assertIn('watch_signin_robot_jobs = [for k in keys(local.signin_robots_built) : "synthetics-${k}"]',
                      watch)
        self.assertIn(f'watch_signin_robots = concat(local.signin_robots_exist ? ["{gen.ROBOT_SECRETS}"] : [], '
                      "local.watch_signin_robot_jobs)", watch)
        self.assertIn('length(local.watch_signin_robots) > 0 ? { TPA_SIGNIN_ROBOTS = join(",", '
                      "local.watch_signin_robots) } : {}", watch)
        self.assertIn("var.signin_robots_paused ? local.watch_signin_robot_jobs : []", watch)

    def test_the_outside_checks_are_the_roots(self):
        # Google's ids for the portal host's checks, read 2026-11-12 (`gcloud monitoring uptime list-configs`).
        live = {"sign-in": "beta-sign-in-auth-me-LigyebjeN50", "portal-app": "beta-portal-app-tpa-r7sS-IFkTCs"}
        others = ["beta-portal-health-ZBteOZ0P5_4", "beta-inside-auth-ready-_PVgSS6Nvv0", "beta-ops-health-ivepzEiZ7Hc",
                  "beta-crm-api-v1-health-EHt8mz388xI", "beta-watch-health-bPby0Wsxtrk"]
        for key, path, *_r in gen.OUTSIDE_CHECKS:
            pattern = gen.check_id_pattern(key, path)
            self.assertRegex(live[key], f"^{pattern}$")
            for other in [*others, *(v for k, v in live.items() if k != key)]:
                self.assertNotRegex(other, f"^{pattern}$")
        if INFRA is None:
            if CHECKOUT_PRESENT:
                self.fail(INFRA_SOURCE)
            self.skipTest(f"SKIPPED LOUDLY: {INFRA_SOURCE}")
        main = " ".join(INFRA.show("infra/envs/beta/main.tf").split())
        for key, path, *_r in gen.OUTSIDE_CHECKS:
            self.assertIn(f"{key} = {{ host = local.portal_host path = \"{path}\"", main)
        module = INFRA.show("infra/modules/monitoring/main.tf")
        self.assertIn('display_name     = "${local.display_prefix}${each.key} ${each.value.path}"', module)
        self.assertIn('metric.labels.check_id = \\"${google_monitoring_uptime_check_config.this[each.key].uptime_check_id}',
                      module)


class QueriesTest(unittest.TestCase):
    def test_every_robot_query_reads_the_policies_metric_and_labels(self):
        labels = CATALOGUE.roles["app"]["synthetic_results"]["labels"]
        for name in ("signin-failing", "signin-robot-locked-out", "signin-silent", "signin-robot-broken",
                     "signin-checks-off"):
            text = CATALOGUE.promql(name, "signin_robots")
            self.assertIn(promql_name(gen.SYNTHETIC) + "{", text)
            self.assertIn('job_name="__JOB__"', text)
        for name, p, t in all_targets(RENDERED["beta"]):
            if facts(t)["metric"] != gen.SYNTHETIC:
                continue
            self.assertEqual(facts(t)["resource"], gen.JOB, p["title"])
            used = {k.split(".")[-1] for k in facts(t)["labels"] if k.startswith("metric.label.")}
            self.assertLessEqual(used, labels, p["title"])

    def test_each_window_is_its_policys(self):
        # Read from the catalogue's own text here, apart from the generator's reading.
        text = {n: CATALOGUE.promql(n, "signin_robots") for n in
                ("signin-failing", "signin-robot-locked-out", "signin-silent", "signin-robot-broken",
                 "signin-checks-off")}
        window = {n: re.findall(r"\[(\d+)([mh])\]", t) for n, t in text.items()}
        minutes = {n: {int(v) * (60 if u == "h" else 1) for v, u in w} for n, w in window.items()}
        hold = gen.seconds(CATALOGUE.policy("signin-silent", section="signin_robots")["conditions"]["-0"]["promql"]
                           ["duration"].strip('"')) // 60
        self.assertEqual(minutes["signin-failing"], {gen.SIGNIN["window"]})
        self.assertEqual(minutes["signin-robot-broken"], {gen.SIGNIN["broken"]})
        self.assertEqual(minutes["signin-checks-off"], {gen.SIGNIN["off_hours"] * 60})
        self.assertEqual(gen.SIGNIN["silent"], min(minutes["signin-silent"]) + hold)
        self.assertEqual(re.findall(r">= (\d+)", text["signin-failing"]), [str(gen.SIGNIN["fails"])])
        self.assertIn(f'code!~"{gen.SIGNIN["lockout"]}"', text["signin-failing"])
        self.assertIn(f'code=~"{gen.SIGNIN["lockout"]}"', text["signin-robot-locked-out"])
        alerts = tile(RENDERED["beta"], "Sign-in alerts")
        robot = [t for t in alerts["targets"] if facts(t)["metric"] == gen.SYNTHETIC]
        want = {(MEMBER, "fail", None, gen.SIGNIN["window"]), (MEMBER, "fail", gen.SIGNIN["lockout"], gen.SIGNIN["window"]),
                (MEMBER, "pass", None, gen.SIGNIN["window"]), (MEMBER, "error", None, gen.SIGNIN["broken"]),
                (MEMBER, None, None, gen.SIGNIN["silent"]), (MEMBER, None, "disabled", gen.SIGNIN["off_hours"] * 60),
                (MEMBER, "pass", None, gen.SIGNIN["off_hours"] * 60)}
        have = {(where(t)["job_name"][1], where(t).get("outcome", (0, None))[1], where(t).get("code", (0, None))[1],
                 period_s(t) // 60) for t in robot}
        self.assertEqual(have, want | {(BROKER, *w[1:]) for w in want})
        # The messenger's, from their policies: five on a lane in fifteen minutes, the lag over its hold.
        vendor = CATALOGUE.threshold("sign-in-message-vendor", "app")
        lanes = {where(t)["lane"][1]: period_s(t) for t in alerts["targets"]
                 if facts(t)["metric"] == gen.log("auth_message_vendor_failures")}
        self.assertEqual(lanes, {"sms": gen.seconds(vendor["alignment_period"]),
                                 "email": gen.seconds(vendor["alignment_period"])})
        self.assertEqual(vendor["threshold_value"], 4)
        stalled = CATALOGUE.threshold("auth-messages-stalled", "app")
        lag = next(t for t in alerts["targets"] if facts(t)["metric"] == gen.log("auth_messages_outbox_lag"))
        self.assertEqual((lag["timeSeriesList"]["perSeriesAligner"], lag["timeSeriesList"]["crossSeriesReducer"]),
                         (stalled["per_series_aligner"], stalled["cross_series_reducer"]))
        # A robot's login from elsewhere, read here from the catalogue apart from the generator's reading: each
        # policy's level, on auth's revisions, summed over both robots in the policy's own window (one incident per
        # robot, so the sum holds exactly when one of them pages).
        foreign = {where(t)["code"][1]: (period_s(t), t["timeSeriesList"]["perSeriesAligner"],
                                         t["timeSeriesList"]["crossSeriesReducer"], t["timeSeriesList"]["groupBys"],
                                         facts(t)["resource"], set(where(t)))
                   for t in alerts["targets"] if facts(t)["metric"] == gen.log(gen.FOREIGN)}
        want = {}
        for name in ("signin-robot-foreign-password", "signin-robot-foreign-guess"):
            rule = CATALOGUE.threshold(name, section="signin_robots")
            text = CATALOGUE.folded(name, "signin_robots", "filter")
            level = re.fullmatch(r'metric\.type = "logging\.googleapis\.com/user/signin_robot_foreign" AND '
                                 r'resource\.type = "cloud_run_revision" AND metric\.labels\.code = "([A-Z]+)"',
                                 text).group(1)
            self.assertEqual((rule["threshold_value"], rule["comparison"], rule["duration"]), (0, "COMPARISON_GT", "0s"))
            want[level] = (gen.seconds(rule["alignment_period"]), rule["per_series_aligner"],
                           rule["cross_series_reducer"], [], gen.REV, {"code"})
        self.assertEqual(foreign, want)
        self.assertEqual({k: v[0] for k, v in foreign.items()}, {"ERROR": 300, "WARNING": 900})

    def test_a_foreign_policy_that_moved_is_refused(self):
        """A moved filter, threshold, aligner, grouping, tier or a second condition is a change to the generator,
        never a row that quietly disagrees with its page; a moved window is read."""
        text = CATALOGUE.text

        def patched(policy: str, old: str, new: str) -> cat.Catalogue:
            at = text.index(f"    {policy}:\n")
            end = text.index(old, at)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "monitoring.yml"
                path.write_text(text[:end] + new + text[end + len(old):])
                return cat.Catalogue(path)

        password, guess = "signin-robot-foreign-password", "signin-robot-foreign-guess"
        self.assertEqual(gen.foreign_rules(cat.Catalogue()), gen.FOREIGN_RULES)
        error = 'metric.labels.code = "ERROR"'
        cases = {
            "level": (password, error, 'metric.labels.code = "WARNING"'),
            "resource": (password, 'resource.type = "cloud_run_revision"', 'resource.type = "global"'),
            "threshold": (guess, 'alignment_period: "900s"', 'alignment_period: "900s"\n            threshold_value: 2'),
            "held": (guess, 'alignment_period: "900s"', 'alignment_period: "900s"\n            duration: "300s"'),
            "aligner": (guess, 'alignment_period: "900s"',
                        'alignment_period: "900s"\n            per_series_aligner: "ALIGN_COUNT"'),
            "grouping": (password, 'group_by_fields: ["metric.label.class"]', 'group_by_fields: []'),
            "tier": (guess, "tier: p2", "tier: p3"),
            # The same condition again, after the first one's grouping: only the count of conditions differs.
            "second condition": (password, 'group_by_fields: ["metric.label.class"]\n',
                                 'group_by_fields: ["metric.label.class"]\n        - name: "again"\n'
                                 "          threshold:\n            filter: >-\n              " +
                                 CATALOGUE.folded(password, "signin_robots", "filter") +
                                 '\n            group_by_fields: ["metric.label.class"]\n'),
        }
        for case, (policy, old, new) in cases.items():
            moved = patched(policy, old, new)
            self.assertNotEqual(moved.text, text, case)
            with self.assertRaises(AssertionError, msg=case):
                gen.foreign_rules(moved)
        self.assertEqual(gen.foreign_rules(patched(guess, 'alignment_period: "900s"', 'alignment_period: "600s"'))
                         [guess]["alignment_period"], "600s")

    def test_a_robots_queries_are_never_sent_while_it_is_not_deployed(self):
        cases = {"not built": (render(), True), "built": (render(TPA_SIGNIN_ROBOTS=BUILT), False),
                 "built, paused": (render(TPA_SIGNIN_ROBOTS=BUILT, TPA_PAUSED_JOBS=",".join(gen.ROBOT_JOBS)), False)}
        for case, (pages, hidden) in cases.items():
            robot = [(n, p["title"], t) for n, p, t in all_targets(pages)
                     if facts(t)["metric"] in (gen.SYNTHETIC, *LOGIN_WATCH)]
            self.assertGreater(len(robot), 50, case)
            self.assertEqual({t.get("hide") for _n, _p, t in robot}, {hidden}, case)
            # Nothing else is ever held back.
            others = {t.get("hide") for _n, _p, t in all_targets(pages)} - {None}
            self.assertEqual(others, {hidden} if robot else set(), case)
        # Stage 1: the secrets alone, their reads and the logins tried from elsewhere asked (their policies exist), no
        # robot's.
        for case, built, robot_hidden in (("stage 1", gen.ROBOT_SECRETS, {MEMBER: True, BROKER: True}),
                                          ("one robot", f"{gen.ROBOT_SECRETS},{MEMBER}", {MEMBER: False, BROKER: True})):
            asked = {}
            for _n, p, t in all_targets(render(TPA_SIGNIN_ROBOTS=built)):
                if facts(t)["metric"] == gen.SYNTHETIC:
                    self.assertEqual(t["hide"], robot_hidden[where(t)["job_name"][1]], (case, p["title"]))
                if facts(t)["metric"] in LOGIN_WATCH:
                    self.assertFalse(t["hide"], (case, p["title"]))
                    asked.setdefault(facts(t)["metric"], set()).add(p["title"])
            self.assertEqual(asked, {gen.log("signin_robot_secret_read"): {"Sign-in alerts", SECRET_CHART},
                                     gen.log(gen.FOREIGN): {"Sign-in alerts", FOREIGN_CHART}}, case)

    def test_the_render_step_refuses_what_it_does_not_know(self):
        beta = ENVIRONMENTS["beta"]
        self.assertIn("TPA_SIGNIN_ROBOTS names 'synthetics-staff-sign-in'",
                      refused(**beta, TPA_SIGNIN_ROBOTS="synthetics-staff-sign-in"))
        self.assertIn("a robot that is not built has no schedule to pause",
                      refused(**beta, TPA_PAUSED_JOBS=MEMBER))
        self.assertIn("a robot is never built without its secrets", refused(**beta, TPA_SIGNIN_ROBOTS=MEMBER))
        self.assertIn("TPA_PAUSED_JOBS names 'signin-robot-secrets'",
                      refused(**beta, TPA_SIGNIN_ROBOTS=BUILT, TPA_PAUSED_JOBS=gen.ROBOT_SECRETS))
        self.assertIn("TPA_SIGNIN_ROBOTS must be empty with TPA_ENVIRONMENT=production",
                      refused(**ENVIRONMENTS["production"], TPA_SIGNIN_ROBOTS=MEMBER))


class WordsTest(unittest.TestCase):
    """Nothing empty reads "No data"; a quiet robot says why, in no colour."""

    def no_values(self, pages: dict) -> dict[str, str]:
        return {p["title"]: p["fieldConfig"]["defaults"].get("noValue") for p in row_tiles(pages["overview"])[1]}

    def test_each_state_says_itself(self):
        built = self.no_values(render(TPA_SIGNIN_ROBOTS=BUILT))
        self.assertEqual(built["Member robot"], "✕ Not reporting: no result in 24 h")
        self.assertEqual(built["Texted codes (24 h)"], "No texted code in 24 h")
        self.assertEqual(built["Emails (24 h)"], "None refused in 24 h")
        self.assertEqual(built["Outside checks"], gen.UPTIME_MISSING)
        self.assertEqual(built["Sign-in alerts"], "? Can't tell")
        paused = {"TPA_SIGNIN_ROBOTS": BUILT, "TPA_PAUSED_JOBS": ",".join(gen.ROBOT_JOBS)}
        for env, word in (({}, "not deployed"), (paused, "paused"),
                          ({"TPA_SIGNIN_ROBOTS": BUILT, "TPA_STOPPED_DATABASES": "auth-db"}, "database stopped")):
            pages = render(**env)
            words = self.no_values(pages)
            self.assertEqual((words["Member robot"], words["Broker robot"]), (word, word), env)
            for title in ("Member robot", "Broker robot"):
                p = tile(pages, title)
                colours = {s["color"] for s in p["fieldConfig"]["defaults"]["thresholds"]["steps"]} | {
                    s["color"] for o in p["fieldConfig"]["overrides"] for x in o["properties"]
                    if x["id"] == "thresholds" for s in x["value"]["steps"]}
                self.assertEqual(colours, {gen.NEUTRAL}, (env, title))
                now = next(x["value"][0]["options"] for o in p["fieldConfig"]["overrides"] for x in o["properties"]
                           if x["id"] == "mappings" and o["properties"][0]["value"] == "now")
                self.assertEqual({m["text"] for m in now.values()}, {word}, (env, title))
            robots_row = next(ps for t, ps in sections(pages["sign-in"]).items()
                              if t.startswith("Sign-in robots"))
            self.assertEqual([p["fieldConfig"]["defaults"]["noValue"] for p in robots_row],
                             [word, word, gen.NONE, gen.NONE], env)
        # The robots are never on production-full's pages.
        for page in RENDERED["production"].values():
            self.assertNotIn("synthetics-member-sign-in", json.dumps(page))
            self.assertNotIn(gen.FOREIGN, json.dumps(page))

    def test_the_sign_in_page_charts_a_robots_login_from_elsewhere(self):
        pages = render(TPA_SIGNIN_ROBOTS=gen.ROBOT_SECRETS)
        robots_row = next(ps for t, ps in sections(pages["sign-in"]).items() if t.startswith("Sign-in robots"))
        # Two by two: the robots' runs, then the two that watch their logins.
        self.assertEqual([(p["title"], p["gridPos"]["x"], p["gridPos"]["w"]) for p in robots_row][2:],
                         [(SECRET_CHART, 0, 12), (FOREIGN_CHART, 12, 12)])
        self.assertEqual([(p["gridPos"]["x"], p["gridPos"]["w"]) for p in robots_row[:2]], [(0, 12), (12, 12)])
        chart = robots_row[3]
        got = {where(t)["code"][1]: (t["aliasBy"], t["timeSeriesList"]["groupBys"], facts(t)["resource"], t["hide"])
               for t in chart["targets"]}
        by = ["metric.label.class", "metric.label.operation"]
        who = "{{metric.label.class}} at {{metric.label.operation}}"
        self.assertEqual(got, {"ERROR": (f"right password or challenge: {who}", by, gen.REV, False),
                               "WARNING": (f"wrong password: {who}", by, gen.REV, False)})
        self.assertEqual(chart["fieldConfig"]["defaults"]["noValue"], gen.NONE)
        for word in ("signin-robot-foreign-password", "signin-robot-foreign-guess", "urgent", "can wait"):
            self.assertIn(word, chart["description"])


class ScenarioTest(unittest.TestCase):
    """The robot tile and the alerts table read as their policies would, from the frames Cloud Monitoring returns."""

    @classmethod
    def setUpClass(cls):
        cls.pages = render(TPA_SIGNIN_ROBOTS=BUILT)
        cls.member = tile(cls.pages, "Member robot")
        cls.alerts = tile(cls.pages, "Sign-in alerts")
        cls.paused = render(TPA_SIGNIN_ROBOTS=BUILT, TPA_PAUSED_JOBS=",".join(gen.ROBOT_JOBS))
        cls.stopped = render(TPA_SIGNIN_ROBOTS=BUILT, TPA_STOPPED_DATABASES="auth-db")

    def setUp(self):
        model.NONE_IN_ARITHMETIC.clear()

    def tearDown(self):
        # Every count reaches the arithmetic through a sum that reads a missing one as 0 (Grafana's and this model's
        # null arithmetic differ: neither is relied on).
        self.assertEqual(model.NONE_IN_ARITHMETIC, [])

    def robot(self, runs) -> dict:
        return shown(self.member, robot_frames(self.member, runs))

    def firing(self, runs=(), **values) -> list[tuple[str, float]]:
        base = {"seeing": 4000, "sender instances": 1, "sign-in failing": 0, "portal-app failing": 0}
        base.update(values)
        return rows(self.alerts, robot_frames(self.alerts, list(runs)) + latest(self.alerts, base))

    def test_a_robot_signing_in(self):
        self.assertEqual(self.robot(every_five(MEMBER)), {"now": "✓ Signing in", "last pass": "≤ 6 min ago",
                                                          "24 h": 1.0})
        self.assertEqual(list(self.robot(every_five(MEMBER))), ["now", "last pass", "24 h"])

    def test_two_failed_checks_and_no_pass_are_failing(self):
        runs = every_five(MEMBER, since=12) + [(1, MEMBER, "fail", "status"), (6, MEMBER, "fail", "status")]
        self.assertEqual(self.robot(runs)["now"], "✕ Failing")
        self.assertIn(("✕ Members can't sign in", 2), self.firing(runs))
        # Two lockouts alone are the lockout's page, never "cannot sign in".
        locks = every_five(MEMBER, since=12) + [(1, MEMBER, "fail", "locked"), (6, MEMBER, "fail", "rate_limited")]
        self.assertEqual(self.robot(locks)["now"], "✕ Locked out")
        names = [n for n, _v in self.firing(locks)]
        self.assertIn("✕ Members' check locked out", names)
        self.assertNotIn("✕ Members can't sign in", names)
        # One failure is a look, not a page; a pass after it is signing in again.
        once = every_five(MEMBER, since=7) + [(2, MEMBER, "fail", "timeout")]
        self.assertEqual(self.robot(once)["now"], "⚠ Failed once")
        self.assertEqual(self.firing(once + every_five(BROKER)), [("✓ None firing", -1)])
        # A pass after it still shows the failure for the window: a look, never a page.
        again = every_five(MEMBER, since=1) + [(8, MEMBER, "fail", "timeout")]
        self.assertEqual(self.robot(again)["now"], "⚠ Failed once")
        self.assertEqual(self.robot(every_five(MEMBER, since=1) + [(13, MEMBER, "fail", "timeout")])["now"],
                         "✓ Signing in")

    def test_silence_is_red_while_it_runs(self):
        runs = every_five(MEMBER, since=120)
        got = self.robot(runs)
        self.assertEqual((got["now"], got["last pass"]), ("✕ Not reporting", "1 to 24 h ago"))
        self.assertIn(("✕ Members' check silent", 2), self.firing(runs + every_five(BROKER)))
        self.assertEqual(self.robot([]), {}, "nothing in the day: the tile's no-value words")

    def test_the_runners_own_fault_and_the_switch(self):
        broken = every_five(MEMBER, since=6) + [(1, MEMBER, "error", "egress")]
        self.assertEqual(self.robot(broken)["now"], "⚠ Robot broken")
        self.assertIn(("⚠ Members' check broken", 1), self.firing(broken + every_five(BROKER)))
        off = every_five(MEMBER, since=60) + every_five(MEMBER, "skipped", "disabled", since=0.5, until=60)
        self.assertEqual(self.robot(off)["now"], "Switched off")
        # Lines eight minutes apart (a slow run, then Logging's delay): still switched off, never "no verdict".
        gap = every_five(MEMBER, since=60) + [(8, MEMBER, "skipped", "disabled"), (16, MEMBER, "skipped", "disabled")]
        self.assertEqual(self.robot(gap)["now"], "Switched off")
        day = every_five(MEMBER, "skipped", "disabled")
        got = self.robot(day)
        self.assertEqual((got["now"], got["last pass"], got["24 h"]), ("⚠ Off over a day", "none in 24 h",
                                                                       "no runs counted"))
        self.assertIn(("⚠ Members' check off a day", 0.5), self.firing(day + every_five(BROKER)))

    def test_the_pass_rate_counts_verdicts(self):
        runs = every_five(MEMBER, until=60) + [(70, MEMBER, "fail", "status"), (75, MEMBER, "error", "egress")]
        self.assertAlmostEqual(self.robot(runs)["24 h"], 12 / 13)

    def test_the_messenger_and_the_outside_checks(self):
        both = every_five(MEMBER) + every_five(BROKER)
        self.assertEqual(self.firing(both), [("✓ None firing", -1)])
        self.assertEqual(self.firing(both, **{"vendor sms": 4}), [("✓ None firing", -1)])
        self.assertIn(("✕ Text vendor failing", 2), self.firing(both, **{"vendor sms": 5}))
        self.assertIn(("✕ Email vendor failing", 2), self.firing(both, **{"vendor email": 7}))
        self.assertEqual(self.firing(both, **{"oldest waiting": 120}), [("✓ None firing", -1)])
        self.assertIn(("✕ A sign-in message stuck", 2), self.firing(both, **{"oldest waiting": 278}))
        self.assertIn(("✕ Carriers blocking texts", 2), self.firing(both, **{"texts 1h": 9, "unverified 1h": 1}))
        self.assertIn(("✕ Carriers blocking texts", 2), self.firing(both, **{"texts 1h": 5, "filtered 1h": 3}))
        self.assertEqual(self.firing(both, **{"texts 1h": 6, "filtered 1h": 3}), [("✓ None firing", -1)],
                         "half is not more than half")
        self.assertIn(("✕ Sender has no instance", 2), self.firing(both, **{"sender instances": 0}))
        self.assertEqual(self.firing(both, **{"sign-in failing": 1}), [("✓ None firing", -1)], "one region alone")
        self.assertIn(("✕ Outside check: sign-in", 2), self.firing(both, **{"sign-in failing": 2}))
        self.assertIn(("✕ A robot's secret was read", 2), self.firing(both, **{"secret read": 1}))
        self.assertEqual(self.firing(both, seeing=0, **{"sender instances": 1}), [],
                         "nothing arrived: no row, so the table's no-value words")

    def test_nothing_of_a_paused_or_stopped_robot_reads_as_a_page(self):
        # Its policies are gone while it does not run (signinrobots.tf, local.signin_robots_running), and the
        # sender's no instance and the stalled messages while auth-db is stopped (beta's main.tf).
        failing = every_five(MEMBER, since=12) + [(1, MEMBER, "fail", "status"), (6, MEMBER, "fail", "status")] + \
            every_five(BROKER, "skipped", "disabled")
        for pages, word in ((self.paused, "paused"), (self.stopped, "database stopped")):
            member, alerts = tile(pages, "Member robot"), tile(pages, "Sign-in alerts")
            self.assertEqual(shown(member, robot_frames(member, failing))["now"], word)
            got = rows(alerts, robot_frames(alerts, failing) + latest(alerts, {"seeing": 4000, "sender instances": 1}))
            self.assertEqual(got, [("✓ None firing", -1)], word)
        alerts = tile(self.stopped, "Sign-in alerts")
        got = rows(alerts, latest(alerts, {"seeing": 4000, "sender instances": 0, "oldest waiting": 400}))
        self.assertEqual(got, [("✓ None firing", -1)], "auth-db stopped: no sender, no message, no page")
        alerts = tile(self.paused, "Sign-in alerts")
        got = rows(alerts, latest(alerts, {"seeing": 4000, "sender instances": 0}))
        self.assertEqual(got, [("✕ Sender has no instance", 2)], "a paused robot leaves the messenger's pages")

    def test_a_robots_login_tried_from_elsewhere(self):
        password, guess = "signin-robot-foreign-password", "signin-robot-foreign-guess"
        both = every_five(MEMBER) + every_five(BROKER)
        # Any one line in its window is its page: the right password urgent, a guess one that can wait.
        self.assertEqual(self.firing(both, **{password: 1}), [(PASSWORD_ROW, 2)])
        self.assertEqual(self.firing(both, **{guess: 1}), [(GUESS_ROW, 1)])
        self.assertEqual(self.firing(both, **{password: 2, guess: 7}), [(PASSWORD_ROW, 2), (GUESS_ROW, 1)])
        self.assertEqual(self.firing(both, **{password: 1, "secret read": 1}),
                         [("✕ A robot's secret was read", 2), (PASSWORD_ROW, 2)])
        # Its policies are written while the secrets exist, paused or not, whatever auth-db is (signinrobots.tf,
        # local.signin_robot_once_policies), so they read so here: with the robots paused, auth-db stopped, or the
        # secrets alone (stage 1, no robot built).
        stage1 = render(TPA_SIGNIN_ROBOTS=gen.ROBOT_SECRETS)
        for case, pages in (("paused", self.paused), ("auth-db stopped", self.stopped), ("stage 1", stage1)):
            alerts = tile(pages, "Sign-in alerts")
            seen = {"seeing": 4000, "sender instances": 1}
            self.assertEqual(rows(alerts, latest(alerts, {**seen, password: 1})), [(PASSWORD_ROW, 2)], case)
            self.assertEqual(rows(alerts, latest(alerts, {**seen, guess: 3})), [(GUESS_ROW, 1)], case)
            self.assertEqual(rows(alerts, latest(alerts, seen)), [("✓ None firing", -1)], case)
        # Nothing built: never asked (no such counter, a 404), so never a row.
        alerts = tile(render(), "Sign-in alerts")
        self.assertEqual(rows(alerts, latest(alerts, {"seeing": 4000, "sender instances": 1, password: 1, guess: 1})),
                         [("✓ None firing", -1)])
        for word in (password, guess, "any one in 5 minutes", "any one in 15 minutes", "paused or not"):
            self.assertIn(word, self.alerts["description"])

    def test_an_older_window_is_never_read_as_now(self):
        # Two failures 12 to 20 minutes ago sit in the eleven-minute window before this one: never "failing" now.
        runs = every_five(MEMBER, since=21) + [(12, MEMBER, "fail", "status"), (17, MEMBER, "fail", "status")] + \
            every_five(MEMBER, since=1, until=11)
        self.assertEqual(self.robot(runs)["now"], "✓ Signing in")

    def test_the_outside_checks_tile(self):
        p = tile(self.pages, "Outside checks")
        got = shown(p, latest(p, {"sign-in failing": 0, "sign-in reporting": 3, "portal-app failing": 2,
                                  "portal-app reporting": 3}))
        self.assertEqual(got, {"sign-in": "✓ passing", "portal": "✕ failing"})
        got = shown(p, latest(p, {"sign-in failing": 1, "sign-in reporting": 3}))
        self.assertEqual(got, {"sign-in": "⚠ 1 region", "portal": "missing"})

    def test_the_codes_going_out(self):
        texts = tile(self.pages, "Texted codes (24 h)")
        got = shown(texts, latest(texts, {"reported": 9, "delivered reported": 8, "vendor failed": 2}))
        self.assertEqual(got, {"delivered": 8, "not delivered": 1, "not sent": 2})
        emails = tile(self.pages, "Emails (24 h)")
        self.assertEqual(shown(emails, latest(emails, {"undeliverable count": 1})), {"refused": 0,
                                                                                     "undeliverable": 1})


if __name__ == "__main__":
    unittest.main()
