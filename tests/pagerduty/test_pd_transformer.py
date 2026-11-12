"""The titled integration (pdlib.py, "The titled integration"): pd_setup.py making and keeping it, and
pd_test_event.py going through it, against the fake PagerDuty (fakes.py), which runs the stored code under node the
way PagerDuty runs it. An automated gate only.

Run: python3 -m unittest discover -s tests/pagerduty -v
"""

from __future__ import annotations

import json
import sys
import unittest

import fakes
from test_monitoring_transform import NO_NODE
from test_pd_setup import SUMMARY_STEADY_DRY, Base, pdlib, run

SERVICES = ("TPA · Portal & API", "TPA · Member records", "TPA · Call centre")
NAME = "Google Cloud Monitoring (titled)"
TITLED = "event_transformer_api_inbound_integration"
PLAIN = "generic_events_api_inbound_integration"


def setUpModule():
    if fakes.NODE is None:
        print(f"\n{'!' * 100}\nWARNING: {NO_NODE}: the test events through it were NOT sent.\n{'!' * 100}",
              file=sys.stderr, flush=True)


class Live(Base):
    """The design as it runs live: no AIOps add-on, and an account that has neither of its features."""
    state_options = {"advanced_orchestration": False, "grouping_error": (403, "Access Denied")}

    def pd(self, *args, **kw):
        return super().pd(*args, **{"aiops": False, **kw})

    def integration(self, service, kind=TITLED):
        (found,) = [i for i in self.state.integrations[self.service_id(service)] if i["type"] == kind]
        return found

    def code(self, service):
        return self.integration(service)["config"]["fields"]["code"]["value"]

    def event(self, *args, **kw):
        result = run(self.server, "pd_test_event.py", *args, **{"aiops": False, **kw})
        self.outputs += [result.stdout, result.stderr]
        return result


class Setup(Live):
    def test_a_dry_run_plans_it_and_writes_nothing(self):
        result = self.pd()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.writes(), [])
        for service in SERVICES:
            self.assertIn(f'create      integration "{NAME}" on "{service}"  [the titles, details and watchtower '
                          "links: monitoring_transform.js]", result.stdout)
            self.assertIn(f'create      integration "Google Cloud Monitoring" on "{service}"', result.stdout)

    def test_created_with_the_files_code_in_a_second_request(self):
        result = self.apply()
        self.assertIn(", refused 0,", self.summary(result))
        want = pdlib.transformer_code()
        self.assertIn(f'var WATCHTOWER = "{pdlib.WATCHTOWER_URL}";', want)
        for service in SERVICES:
            self.assertIn(f'created     integration "{NAME}" on "{service}"', result.stdout)
            titled = self.integration(service)
            self.assertEqual((titled["name"], titled["vendor"]), (NAME, {"id": "PCJ0EFQ", "type": "vendor_reference"}))
            self.assertNotEqual(self.code(service), want, "the fake stores other line endings, as a store might")
            self.assertEqual(pdlib.normalise_code(self.code(service)), want)
            self.assertEqual(titled["config"]["fields"]["debug"]["value"], "false", "debug is left off")
            sid = self.service_id(service)
            creates = [json.loads(r["raw"])["integration"] for r in self.state.writes()
                       if r["method"] == "POST" and r["path"] == f"/pd/services/{sid}/integrations"]
            self.assertEqual([c["type"] for c in creates], [PLAIN, TITLED])
            self.assertNotIn("config", creates[1], "PagerDuty ignores a config on the create: none is sent")
            (put,) = [json.loads(r["raw"])["integration"] for r in self.state.writes()
                      if r["method"] == "PUT" and r["path"] == f"/pd/services/{sid}/integrations/{titled['id']}"]
            self.assertEqual(put, {"type": TITLED, "name": NAME,
                                   "config": {"fields": {"code": {"type": "code", "value": want}}}})

    def test_a_second_run_is_all_ok_and_writes_nothing(self):
        self.apply()
        before = len(self.state.writes())
        again = self.pd("--apply")
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertEqual(len(self.state.writes()), before, "a steady account gets no write")
        self.assertIn("summary: created 0, updated 0,", again.stdout)
        for service in SERVICES:
            self.assertIn(f'ok          integration "{NAME}" on "{service}"', again.stdout)
        self.assertRegex(self.summary(self.pd()), SUMMARY_STEADY_DRY)

    def test_code_that_differs_is_updated_then_steady(self):
        self.apply()
        want = pdlib.transformer_code()
        drifted = self.integration(SERVICES[1])
        drifted["config"]["fields"]["code"]["value"] = want.replace("TITLE_LIMIT = 250", "TITLE_LIMIT = 9")
        dry = self.pd()
        self.assertIn(f'update      integration "{NAME}" on "{SERVICES[1]}"  [its code differs from '
                      "monitoring_transform.js]", dry.stdout)
        self.assertIn("summary: 0 to create, 1 to update,", dry.stdout)
        self.assertNotEqual(pdlib.normalise_code(self.code(SERVICES[1])), want, "a dry run changes nothing")
        before = len(self.state.writes())
        fixed = self.pd("--apply")
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        self.assertIn("summary: created 0, updated 1,", fixed.stdout)
        self.assertEqual([(r["method"], r["path"]) for r in self.state.writes()[before:]],
                         [("PUT", f"/pd/services/{self.service_id(SERVICES[1])}/integrations/{drifted['id']}")])
        self.assertEqual(pdlib.normalise_code(self.code(SERVICES[1])), want)
        self.assertRegex(self.summary(self.pd()), SUMMARY_STEADY_DRY)

    def test_only_line_endings_and_trailing_space_differing_is_no_drift(self):
        self.apply()
        field = self.integration(SERVICES[0])["config"]["fields"]["code"]
        field["value"] = "\n" + pdlib.transformer_code().replace("\n", "  \r\n") + "\n\n"
        self.assertRegex(self.summary(self.pd()), SUMMARY_STEADY_DRY)

    def test_the_plain_integration_is_never_touched(self):
        """It is the way back: same integration, same key, and no request ever names it."""
        self.apply()
        plain = {s: dict(self.integration(s, PLAIN)) for s in SERVICES}
        self.integration(SERVICES[0])["config"]["fields"]["code"]["value"] = "PD.fail('drift');"
        self.pd("--apply")
        self.pd("--apply")
        for service in SERVICES:
            self.assertEqual(self.integration(service, PLAIN), plain[service])
            self.assertEqual(len(self.state.integrations[self.service_id(service)]), 2)
            touched = [r for r in self.state.writes() if r["path"].endswith(f"/integrations/{plain[service]['id']}")]
            self.assertEqual(touched, [])
        self.assertEqual([r for r in self.state.requests if r["method"] == "DELETE"], [])

    def test_a_service_made_before_the_titled_integration_gains_it(self):
        """The account as it is today: the three services with the plain integration alone."""
        self.apply()
        for service in SERVICES:
            sid = self.service_id(service)
            self.state.integrations[sid] = [self.integration(service, PLAIN)]
        dry = self.pd()
        self.assertIn("summary: 3 to create, 0 to update,", dry.stdout)
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("summary: created 3, updated 0,", result.stdout)
        for service in SERVICES:
            self.assertEqual(pdlib.normalise_code(self.code(service)), pdlib.transformer_code())

    def test_a_transformer_under_another_name_is_left_alone(self):
        """Such as a throwaway one made by hand: ours is found by its exact name."""
        self.apply()
        sid = self.service_id(SERVICES[0])
        probe = {"id": "PPROBE", "type": TITLED, "name": "cet probe", "vendor": {"id": "PCJ0EFQ"},
                 "integration_key": f"{fakes.KEY_PREFIX}probe0000000000000000"[:32],
                 "config": {"fields": {"code": {"type": "code", "value": fakes.SAMPLE_CODE}}}}
        self.state.integrations[sid].append(probe)
        before = len(self.state.writes())
        self.assertRegex(self.summary(self.pd("--apply")), r"created 0, updated 0,")
        self.assertEqual(len(self.state.writes()), before)
        self.assertEqual(probe["config"]["fields"]["code"]["value"], fakes.SAMPLE_CODE)

    def test_two_with_our_name_are_refused(self):
        self.apply()
        sid = self.service_id(SERVICES[2])
        self.state.integrations[sid].append({**self.integration(SERVICES[2]), "id": "PTWIN"})
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f'refused     integration "{NAME}" on "{SERVICES[2]}"  [2 integrations carry this name',
                      result.stdout)

    def test_another_kind_of_integration_with_our_name_is_refused(self):
        self.apply()
        self.integration(SERVICES[2]).update({"type": PLAIN, "vendor": None})
        result = self.pd("--apply")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("[1 integrations carry this name, 0 of the Custom Event Transformer type", result.stdout)

    def test_with_the_add_on_and_its_route_there_is_no_titled_integration(self):
        """The add-on's design titles through the orchestration and the plain integration, as before."""
        self.state.advanced_orchestration, self.state.grouping_error = True, None
        result = self.pd("--apply", "--add-rules", aiops=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(NAME, result.stdout)
        self.assertEqual({i["type"] for items in self.state.integrations.values() for i in items}, {PLAIN})

    def test_an_unknown_route_is_refused_before_anything_is_read(self):
        result = self.pd("--apply", route="titles")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("refused: TW_PAGERDUTY_ROUTE is 'titles': it may only be monitoring or transformer",
                      result.stderr)
        self.assertEqual(self.state.requests, [])

    def test_the_way_back_route_still_keeps_the_titled_integration(self):
        result = self.pd("--apply", "--add-rules", route="monitoring")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for service in SERVICES:
            self.assertEqual(pdlib.normalise_code(self.code(service)), pdlib.transformer_code())


class CodeNotStored(Live):
    state_options = {**Live.state_options, "ignore_transformer_code": True}

    def test_a_put_pagerduty_does_not_keep_is_refused_not_reported_as_done(self):
        result = self.pd("--apply", "--add-rules")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for service in SERVICES:
            self.assertIn(f'refused     integration "{NAME}" on "{service}"  [PagerDuty took the code and does not '
                          "hold it", result.stdout)
        event = run(self.server, "pd_test_event.py", "--role", "app", "--severity", "warning", "--send", aiops=False)
        self.outputs += [event.stdout, event.stderr]
        self.assertEqual(event.returncode, 2, event.stdout + event.stderr)
        self.assertIn(f'the code PagerDuty holds for "{NAME}" is not monitoring_transform.js', event.stderr)
        self.assertEqual([r for r in self.state.requests if r["path"].startswith("/events")], [])


class DryTestEvent(Live):
    def test_the_dry_run_shows_monitorings_notification_and_sends_nothing(self):
        self.apply()
        result = self.event("--role", "phi", "--severity", "Warning")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r for r in self.state.requests if r["path"].startswith("/events")], [])
        self.assertIn(f'route transformer (the "{NAME}" integration)', result.stdout)
        self.assertIn('title "PagerDuty setup check, please ignore (Warning, TPA · Member records)"',
                      result.stdout)
        shown = json.loads(result.stdout[result.stdout.index("{"):])
        self.assertEqual(sorted(shown), ["incident", "version"])
        self.assertEqual(shown["incident"]["severity"], "Warning")


@unittest.skipIf(fakes.NODE is None, NO_NODE)
class TestEvents(Live):
    """pd_test_event.py through the titled integration: the fake runs the stored code on what is posted."""

    def setUp(self):
        super().setUp()
        self.apply()

    def posts(self):
        return [r for r in self.state.requests if r["path"].startswith("/events")]

    def test_the_title_is_the_subject_and_the_severity_rules_still_apply(self):
        for role, severity, service, outcome in [
            ("cc", "warning", SERVICES[2], "urgency low, alert severity warning, priority P3"),
            ("app", "CRITICAL", SERVICES[0], "urgency high, alert severity critical, priority P1"),
            ("phi", "Error", SERVICES[1], "urgency high, alert severity error, priority P2"),
            ("app", "No severity", SERVICES[0], "urgency high, alert severity critical, priority none"),
        ]:
            with self.subTest(severity=severity):
                result = self.event("--role", role, "--severity", severity, "--send", "--wait", "5")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(outcome, result.stdout)
                self.assertIn(f'title "PagerDuty setup check, please ignore ({severity}, {service})"',
                              result.stdout)
                self.assertIn("\nas designed\n", result.stdout)
                self.assertIn("status resolved", result.stdout, "closed by a notification with state closed")
        self.assertEqual(self.state.transformer_failures, [])

    def test_it_is_posted_to_the_titled_integrations_own_address_as_monitoring_posts(self):
        result = self.event("--role", "app", "--severity", "warning", "--send", "--wait", "5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        key = [i for i in self.state.integrations[self.service_id(SERVICES[0])] if i["type"] == TITLED][0][
            "integration_key"]
        trigger, resolve = self.posts()
        for post in (trigger, resolve):
            self.assertEqual(post["path"], f"/events/integration/{key}/enqueue")
            self.assertEqual(post["authorization"], "", "an event carries no API key")
            self.assertEqual(sorted(json.loads(post["raw"])), ["incident", "version"])
        self.assertEqual(json.loads(trigger["raw"])["incident"]["state"], "open")
        self.assertEqual(json.loads(resolve["raw"])["incident"]["state"], "closed")
        self.assertEqual(json.loads(trigger["raw"])["incident"]["incident_id"],
                         json.loads(resolve["raw"])["incident"]["incident_id"])

    def test_the_alert_carries_the_details_and_the_watchtower_links(self):
        self.event("--role", "phi", "--severity", "error", "--send", "--wait", "5", "--keep")
        ((alert,),) = self.state.alerts.values()
        details = alert["body"]["details"]
        base = pdlib.WATCHTOWER_URL
        self.assertEqual(list(details)[:4], ["what_happened", "what_to_check", "dashboard", "overview"])
        self.assertEqual(details["what_happened"], alert["summary"])
        self.assertEqual(details["incident"]["severity"], "error")
        self.assertEqual(details["overview"], f"{base}/d/tw-cloud-overview")
        self.assertEqual(alert["body"]["contexts"],
                         [{"type": "link", "href": f"{base}/d/tw-cloud-overview", "text": "Watchtower: overview"}])
        self.assertEqual(alert["body"]["cef_details"], {"client": "Watchtower: overview",
                                                        "client_url": f"{base}/d/tw-cloud-overview"})

    def test_monitorings_own_subject_titles_policy_and_condition(self):
        result = self.event("--role", "app", "--severity", "Critical", "--monitoring-subject", "--send", "--wait", "5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('title "TEST — PagerDuty setup check, please ignore · test condition"', result.stdout)
        self.assertIn("as designed", result.stdout)

    def test_the_way_back_goes_through_the_plain_integration_with_monitorings_summary(self):
        result = self.event("--role", "app", "--severity", "warning", "--send", "--wait", "5", route="monitoring")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('route monitoring (the "Google Cloud Monitoring" integration)', result.stdout)
        self.assertIn('title "TEST — PagerDuty setup check, please ignore: Monitoring\'s own summary', result.stdout)
        self.assertIn("\nas designed\n", result.stdout)
        self.assertEqual({r["path"] for r in self.posts()}, {"/events/generic/2010-04-15/create_event.json"})

    def test_other_code_in_pagerduty_is_refused_before_anything_is_sent(self):
        sid = self.service_id(SERVICES[0])
        titled = [i for i in self.state.integrations[sid] if i["type"] == TITLED][0]
        titled["config"]["fields"]["code"]["value"] = fakes.SAMPLE_CODE
        result = self.event("--role", "app", "--severity", "warning", "--send", "--wait", "5")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("run pd_setup.py --apply first", result.stderr)
        self.assertEqual(self.posts(), [])

    def test_the_fake_refuses_a_titled_key_on_the_plain_address(self):
        """Not yet seen live either way (docs/PAGERDUTY.md): the fake takes the cautious reading."""
        key = [i for i in self.state.integrations[self.service_id(SERVICES[0])] if i["type"] == TITLED][0][
            "integration_key"]
        with self.assertRaises(fakes.Fail):
            self.state.event({"service_key": key, "event_type": "trigger", "incident_key": "x", "description": "d"})


if __name__ == "__main__":
    unittest.main()
