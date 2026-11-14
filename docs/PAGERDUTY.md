# PagerDuty for the TPA

The owner, 2026-10-11: *"This is my API key for pagerduty, i want everything set up very well with it."*

The TPA's production alerts are Cloud Monitoring alert policies in each Google Cloud project (tpa-platform's
`infra/modules/monitoring`). Each project sends its alerts to one PagerDuty service. PagerDuty decides how urgent the
alert is from the policy's severity, pages whoever is on call, escalates urgent ones if nobody acknowledges, and posts
to Slack.

```
alert policy (severity CRITICAL or WARNING)
  -> the project's `pagerduty` notification channel          (tpa-platform's Terraform; tf_with_keys.py gives it the key)
  -> PagerDuty service "TPA · …"                        (pd_setup.py makes it)
       integration "Google Cloud Monitoring (titled)": the title (the policy's subject, else
                            "policy · condition"), the details and the watchtower links
       event orchestration: severity (any letter case) -> alert severity + priority
       urgency from severity: critical/error = high, warning/info = low
  -> escalation policy "TPA Platform"                        (high urgency only; low urgency never escalates)
       level 1: on call on "TPA primary on-call" (15 min)
       level 2: Rafeale Hill (15 min); then the policy repeats, twice
  -> each person's notification rules (phone, SMS, app, email, Slack)
```

## The new account (2026-11-12)

PagerDuty deleted the TPA's first account. The owner made a new one and the same day `pd_setup.py --apply
--add-rules` rebuilt everything below in it under the same names. What differs from the first account:

- **No AIOps add-on** (the owner: *"We are not using AIops"*). `pdlib.AIOPS` is off, so the design leaves out the two
  things only the add-on runs: the orchestration's title rules and the alert grouping settings. Each service's
  orchestration is the three severity rules alone, and `pd_setup.py` neither reads nor writes a grouping setting.
  Severity, urgency and priority are unchanged. The account refuses the title rules outright (`forbidden_feature`
  for template strings, variables and extractions, proven again on 2026-11-12 in a single flat set).
- **The titles come from a second integration instead.** The owner, the same day, of the incidents channel: *"the messages to
  that channel suck, not easy to read whats going on, long form text not well formatted, it should be very well
  structured, easy to read"*, and *"I want ALL message and alerts to be well structured and formatted and links to
  the production watchtower platform"*. Each service now has a "Google Cloud Monitoring (titled)" integration, a
  small piece of code PagerDuty runs on every notification, which needs no add-on ("Incident titles" below). The
  plain "Google Cloud Monitoring" integration and its key stay: they are the way back.
- **Slack thread reply with watchtower links (2026-11-12).** PagerDuty's own channel post shows only the title, status
  and priority, and none of an event's links. So an incident workflow, "TPA: Slack thread with watchtower links",
  replies in each incident's thread with the incident link and the watchtower pages (action
  `pagerduty.com:slack:reply-in-incident-thread:1`; made through `POST /incident_workflows`, by hand, not yet by
  `pd_setup.py`). Started by hand through the API it posts as designed. Its **trigger** could not be made through the
  API (`POST /incident_workflows/triggers` answered 500 "Reduce of empty array with no initial value" for every
  shape tried with the account key), so a person adds it in PagerDuty: the workflow → Triggers → "Conditional
  trigger", the three "TPA beta ·" services, condition "incident status is triggered".
- **No "beta" in what people read (the owner, 2026-11-12: "We are NOT in beta").** The Terraform root is named
  `beta` but it is the production estate. The services are "TPA · Portal & API", "TPA · Member records" and
  "TPA · Call centre", the business service "Trellis TPA", and the titled integration drops the subject's
  environment word and writes a Google operation name as its last part in words ("Alert policy or channel changed:
  delete notification channel"). `tf_with_keys.py` reads those names for the `beta` root and "TPA <env> · …" for any
  other. Policy names inside Google Cloud still begin "beta:" (tpa-platform's naming, not changed here).
- **Slack channel: #obatpa-incidents** (the owner's name for it, 2026-11-12; made as #pd-incidents, same channel id
  C0CH19SCVDL, so the connections did not change), the channel PagerDuty made in the workspace (the first account's
  #tpa-beta-alerts is gone). The three connections were made through PagerDuty's Slack integration API
  (`POST app.pagerduty.com/integration-slack/workspaces/<team>/connections`). Made as `notification_type: responder`
  with every event and priorities `["*"]`, they were accepted, listed as healthy and **posted nothing**: the owner
  saw PagerDuty's direct message and an empty channel. Remade the same day (`PUT` on each) in the shape PagerDuty's
  own Slack screen writes, which does post: `notification_type: stakeholder`, events `incident.triggered`,
  `incident.resolved`, `incident.status_update_published`, `priorities: null`, `urgency: null`. `pd_setup.py` now
  reports a "responder" connection as a gap. Which of the three differences was the fault is not known.
- **New integration keys.** Each project's `pagerduty` channel in Google Cloud needs the "Rotation" apply below
  (`-replace`, through `tf_with_keys.py`) before any alert reaches the new account.
- Rafeale Hill was invited again (admin) and is level 2. Neither person has a phone or the app on the account yet.
- Live checks: test events on all three services gave warning = low urgency, P3 and critical = high urgency, P1; a
  dry run prints "0 to create, 0 to update, 30 ok, 0 kept, 0 refused, 0 by hand".

The scripts here are run by a person. The repo holds no key, no Terraform and no
deploy identity. The PagerDuty key stays in the owner's login keychain.

## What exists in PagerDuty

All of it was made by `scripts/pagerduty/pd_setup.py` on 2026-10-11 and is checked by every re-run.

| Object | Name | Settings |
|---|---|---|
| Team | TPA Platform | Jonathan Bushnell and Rafeale Hill, both **manager**. PagerDuty gives an account owner or admin the manager role only. |
| Schedule | TPA primary on-call | America/Chicago. One weekly layer, handed off Monday at 09:00. Jonathan alone today. To make it a rotation, add a name to `ROTATION` in `pdlib.py` and re-run. The script only changes a schedule that has exactly one active layer. |
| Escalation policy | TPA Platform | Owned by the team. Level 1: the schedule, 15 min. Level 2: Rafeale Hill, 15 min. Repeats twice. |
| Services | TPA · Portal & API (app project), TPA · Member records (PHI project), TPA · Call centre (call-centre project) | The escalation policy above. Urgency from severity (dynamic notifications). Acknowledgement timeout 30 min. No auto-resolve, because Monitoring resolves. Two integrations each: "Google Cloud Monitoring (titled)", which Monitoring's channel is given and which writes the title, the details and the watchtower links ("Incident titles"), and the plain "Google Cloud Monitoring", kept as the way back. A service event orchestration: the severity (next section). |
| Alert grouping settings | one per service, named after it | Intelligent grouping (PagerDuty set a 5-minute window). The script falls back to time-based grouping (10 minutes) only if PagerDuty's refusal says "intelligent". It uses `/alert_grouping_settings`, because the service field `alert_grouping_parameters` is deprecated. |
| Business service | Trellis TPA | Supported by the three services. It is what PagerDuty's status dashboard shows. |
| Notification rules | Jonathan Bushnell, Rafeale Hill | Built from the contact methods each person already has, and created only with `--add-rules` (next sections). |

"Default Service" and the "Default" escalation policy are left as they were. The names start "TPA beta ·" so a
production set ("TPA production · …") can sit beside them later. If one of the three is missing while a service
carrying the Google Cloud Monitoring integration exists under a name the design doesn't use, the script refuses to
create it and names that service: it may be ours, renamed, whether or not its description changed too.

**What PagerDuty could not take.** PagerDuty can't tag services: tags attach only to users, teams and escalation
policies. So the services carry no "tpa" or "beta" tags, and "beta" is in each name instead.

**Integration choice.** Google's guide (docs.cloud.google.com/monitoring/support/notification-options) says to add an
"Events API v1" integration. PagerDuty's own Google Cloud Monitoring page links to that same guide. PagerDuty's vendor
"Google Cloud Monitoring" (id `PUCLE3C`) is that same Events API v1 integration (`generic_service_type: api`), with
Google's name and logo on each alert. We use the vendor integration. Both are the same thing to the `pagerduty`
channel. The live tests below sent Monitoring-shaped events to the v1 endpoint with the vendor integration's key, and
the severity field matched where Google's guide says it would.

## How severity becomes urgency

tpa-platform sets a severity on every alert policy: urgent ones are CRITICAL, everything else is WARNING. Monitoring
puts that severity in the event at `event.custom_details.incident.severity`. **Google never says in what letter case.**
Its guide's payload example writes "no severity" in lower case. So each rule ignores case and surrounding spaces. If a
WARNING went unmatched, it would page at high urgency. Each service's event orchestration maps the severity like this:

| Monitoring sends (any case) | Rule (exact, as stored in PagerDuty) | Alert severity | Priority | Urgency | What happens |
|---|---|---|---|---|---|
| critical | `event.custom_details.incident.severity matches regex '(?i)^[[:space:]]*Critical[[:space:]]*$'` | critical | P1 | **high** | The on-call person gets every contact method at once (a phone call after 3 min). Level 2 at 15 min if nobody acknowledges. |
| error | `… matches regex '(?i)^[[:space:]]*Error[[:space:]]*$'` | error | P2 | **high** | as above |
| warning | `… matches regex '(?i)^[[:space:]]*Warning[[:space:]]*$'` | warning | P3 | low | The on-call person gets app push, email and Slack only. Never a call or text. **Never escalates.** |
| anything else ("no severity", a policy made by hand) | no rule matches | critical (PagerDuty's default) | none | **high** | as critical. This is on purpose: a policy someone forgot to grade still pages. |

`(?i)` is RE2's ignore-case flag. `[[:space:]]` is RE2's class for spaces, tabs and newlines. The pattern can't use
`\s`, because PagerDuty's condition language refuses a backslash inside a quoted string. In RE2, `$` matches only at
the very end of the text, so the class is what lets a trailing tab or newline still match. The live checks below sent
lower-case severities against these capitalised patterns, which proves the flag works.

**Only high urgency escalates.** PagerDuty never moves a low-urgency incident to the next level, and nobody can
escalate one by hand without first raising it to high urgency. A WARNING therefore reaches only whoever is on call.

**Acknowledge, don't resolve, while the problem is still there.** If you resolve an incident in PagerDuty while its
alert is still open in Monitoring, Monitoring reopens it. Acknowledge it, fix the problem, and let Monitoring close
the alert, which resolves the incident. An acknowledged incident that is still open after 30 minutes pages again.

## Incident titles

The owner, 2026-10-13, showing a PagerDuty message in Slack: *"Arent all of these messages supposed to be formatted
better?"* Monitoring titles every event with its own generated summary, and PagerDuty uses it as the incident's title
in the app, by email and in Slack. Incident #31's title was:

> tpa_jobs_alerts for trellistpa-beta-tpa-app Cloud Run Job labels {project_id=trellistpa-beta-tpa-app} with metric
> labels {code=workload_orphan, job=workload_audit} is above the threshold of 0.000 with a value of 2.000. | Violation
> started: … | Policy: beta: a job raised an alert | Condition: from a scheduled run | View incident: https://…

The title, either way, is the same three rules, the first that fits:

| Rule | Fits when | Title |
|---|---|---|
| The policy's own subject | `documentation.subject`, after at most one leading `[…] ` tag, starts with a word and ` · ` (tpa-platform's "<environment> · <what happened>") | the subject without the tag, e.g. "beta · tpa-jobs cutoff_freeze behind: cutoff_freeze_behind" |
| policy · condition | `policy_name` and `condition_name` both have one | "beta: a job raised an alert · from a scheduled run" |
| As Monitoring wrote it | otherwise | Monitoring's summary (or "Cloud Monitoring alert" when there is none) |

### The titled integration (how the account runs, 2026-11-12)

Each service has a second integration, **"Google Cloud Monitoring (titled)"**. It is PagerDuty's Custom Event
Transformer (vendor `PCJ0EFQ`, type `event_transformer_api_inbound_integration`): PagerDuty runs a small piece of
JavaScript on every request posted to the integration's own address, and the code says what event to make. It is part
of the plan the account has, with no add-on.

- **The code is `scripts/pagerduty/monitoring_transform.js`.** `pd_setup.py` creates the integration, stores the
  file's text in it (with the watchtower's address, `pdlib.WATCHTOWER_URL`, put in), reads it back, and on every
  later run compares what PagerDuty holds with the file and updates PagerDuty when they differ (line endings and
  space at a line's end aside). Change the file and re-run; never edit the code in PagerDuty's screen. PagerDuty's
  runtime is ES5, and the tests refuse anything newer in the file.
- **What it makes of a notification.** Monitoring posts `{"incident": {…}, "version": "1.2"}`. The code emits one
  event: a trigger, or a resolve when `incident.state` is `closed`, keyed by `incident.incident_id` so the resolve
  finds its incident. The title is the table above, cut at 250 characters. A body with no `incident` object makes no
  event at all (`PD.fail`), so it pages nobody.
- **One problem, one page (2026-11-14, deploy-safety).** The account's plan has no alert grouping: its `/abilities`
  name no time-based, content-based or intelligent grouping, `/alert_grouping_settings` is empty and there is no
  global event orchestration (read 2026-11-14). So the code groups with the Events API's own rule: an event whose
  `incident_key` names an incident that is still open is added to that alert's log (a "trigger" entry, not a new
  alert) and pages nobody again. Two groups,
  each keyed with the project and Monitoring's severity, so a Critical event never joins a Warning incident and
  nothing is downgraded:
  - **Control-plane changes**: one change counter (`iam_policy_changes`, `network_control_changes`,
    `monitoring_changes` or `log_metric_changes`) within one two-hour UTC slot (from `started_at`) is one incident,
    titled "Changes, 02:00 to 04:00 UTC: <the first change>". The counter is in the key (the review), so a change of
    another kind during an apply still pages on its own. An approved apply made 4 to 8 change incidents per project,
    one per method (105 incidents from 11-07 to 11-14, most of them changes); now it is at most one per kind per
    project per slot. These policies send no close (#202), so a person resolves the incident after reading the
    project's Admin Activity log for the slot; PHI's Critical IAM change sends one, and its close resolves its group.
    `started_at` is when Google opened its incident, a few minutes after the change: read the slot against the deploy
    NOTICE's START and DONE with that slack.
  - **One Cloud Run service failing**: `run_system_errors`, `run_crash_exits`, `run_oom_kills` and
    `sql_proxy_errors` for one service (or job) within one half-hour UTC slot are one incident, titled "<service>
    failing, from 02:00 to 02:30 UTC: <the first alert>". A Google close of one of them is dropped (no event): one
    counter going quiet must not resolve an incident whose other counters still fire, so a person resolves it, after
    checking each one's Cloud Monitoring incident (PagerDuty is not told when a counter goes quiet). tpa-platform's
    catalogue keeps these four policies on its waiting list (D-402).
  - A group that crosses a slot's end is two incidents, never none. An event with no `started_at`, or a failing
    counter with no service or job label, keeps its own incident. Everything else is keyed by Monitoring's
    `incident_id`, as before. The alert's details say which group it is in (`grouped`). A run that emits no event
    (a dropped close) is answered 202 like any other; that is not yet seen live.
  - **Not built: a "during deploy" label** (the coordinator's ask (a), 2026-11-14). The code runs on Monitoring's
    payload alone and fetches nothing, and nothing in that payload says a deploy window is open; the only markers a
    deploy could set where it would show (a policy's labels) are themselves the changes the alerts watch, and a
    maintenance window suppresses incidents, which is ruled out. The change group's title names its slot, which
    reads against the deploy NOTICE's START and DONE. PagerDuty's Change Events (a deploy's start and end posted to
    each service, shown under "Recent changes" on its incidents) would do it if the plan carries them; unverified.
- **The details**, in reading order, each left out when it has nothing to say:

  | Detail | From |
  |---|---|
  | `what_happened` | the title |
  | `what_to_check` | `documentation.content`: the policy's own words on what happened and what to read |
  | `dashboard` | the watchtower page that best fits the alert (below) |
  | `overview` | the watchtower's overview page |
  | `project` | `resource.labels.project_id` |
  | `severity` | `severity`, as Monitoring wrote it |
  | `measured` | `observed_value` and `threshold_value`: "1.000 (threshold 0)" |
  | `where` | `resource_type_display_name`, e.g. "Cloud Run Revision" |
  | `metric` | `metric.type` and its labels: "…/tpa_jobs_alerts {code=cutoff_freeze_behind, job=cutoff_freeze}" |
  | `policy`, `condition` | `policy_name`, `condition_name` |
  | `started`, `ended` | `started_at`, `ended_at`, as "2026-11-12T11:28:39Z" |
  | `console` | `url`: the incident in the Google Cloud console |
  | `monitoring_summary` | `summary`: Monitoring's own long sentence, which used to be the title |
  | `incident` | Monitoring's whole object, unchanged |

  `incident` stays where it was, so the severity rules of the section above still read
  `event.custom_details.incident.severity`: urgency and priority are exactly as before.
- **The links.** Every incident carries links to the production watchtower (the hosted Grafana, `cloud/`): the
  `dashboard` and `overview` details above, and the event's link list, "Watchtower: <page>", "Watchtower: overview"
  and "Cloud Monitoring incident" (the console). The event's own link (`client_url`, the "view in" link PagerDuty
  shows) is the watchtower page; the console is one of the links beside it. **The watchtower links open only for
  people who can sign in to the watchtower** (Google sign-in, `grp-platform`); anyone else gets Google's refusal.
  The page is picked from the alert alone, the first that fits:

  | The alert | Page |
  |---|---|
  | names jobs: `tpa_jobs` or `tpa-jobs` in the metric type, the policy or condition name or the subject, or a `cloud_run_job` or `cloud_scheduler_job` resource | Jobs |
  | names `cloudsql` | Databases |
  | names an `auth_` counter or "sign-in" | Sign-in |
  | is on a Cloud Run service that has a page of its own (`resource.labels.service_name`) | that service's page |
  | is in a project ending `-tpa-app`, `-tpa-phi`, `-cc` | Portal & API, Member records, Call centre |
  | anything else | the overview |

  The pages are named in the file by their dashboard ids, and a test holds each id, and the list of service pages,
  to the files in `cloud/dashboards`: renaming a dashboard fails `make pagerduty-test`.
- **Which integration is used: the route.** `pdlib.ROUTE` is `transformer`. `tf_with_keys.py` hands Monitoring's
  channels the titled integration's keys, and `pd_test_event.py` posts through it. Both refuse a titled integration
  whose stored code is not the file's. `TW_PAGERDUTY_ROUTE=monitoring` on one command makes it use the plain
  integration instead: that, and the "Rotation" apply below, is the whole way back.
- **Seen live: Monitoring's own channel posting to it** (read back 2026-11-14). The integration was proven on
  2026-11-12 by posting Monitoring's notification to its address by hand (trigger and resolve, title exactly the
  subject). Production's incidents since then carry this code's titles, which only it writes: #94 to #96 read
  "Alert policy or channel changed: update alert policy" (the subject without its environment word, the Google
  operation name in words), and #103 to #105 the same shape. The way back is still one apply to the plain
  integration's keys. The code also reads an Events API v1 event that carries the incident in its details.

**Applying it.**
1. `make pagerduty-plan`: three creates, the titled integration on each service.
2. `python3 scripts/pagerduty/pd_setup.py --apply`, then `make pagerduty-plan` again: "0 to create, 0 to update".
3. `python3 scripts/pagerduty/pd_test_event.py --role app --severity Warning --send`, then `phi` and `cc`. Each must
   print "as designed" with the title "test · PagerDuty setup check, please ignore (…)". It pages whoever is on call
   at low urgency, and resolves itself.
4. The "Rotation" apply below, for all three channels, then the test page.

### With the AIOps add-on (not how the account runs)

The first account had the add-on, and wrote the same titles in each service's event orchestration. The scripts keep
that design behind `pdlib.AIOPS` (off) and the tests keep it covered. It then needs no titled integration, and the
route is `monitoring`.

Each service's event orchestration then has two sets. The `start` set holds the three severity rules of the
section above. Each of them, and a fourth rule with no conditions for any other event, then sends the event on
(`route_to`) to the `titles` set, which picks the title. In each set, the first rule that matches wins:

| Rule in `titles` | Matches when | Title |
|---|---|---|
| Title: the policy's own subject | `documentation.subject`, after at most one leading `[…] ` tag, starts with a word and ` · ` (tpa-platform's "<environment> · <what happened>") | the subject without the tag, e.g. "beta · PagerDuty test (turn alert_pagerduty_test_enabled off)" |
| Title: policy · condition | `policy_name` and `condition_name` both have one | "beta: a job raised an alert · from a scheduled run" |
| Title: as Monitoring wrote it | always (no conditions) | unchanged |

- **The subject is tpa-platform's.** Each alert policy's `documentation.subject` is a short, plain line,
  "<environment> · <what happened>". GCP fills in variables, then sends the subject with its own tag in front:
  incident #33's was `[ALERT - Warning] beta · PagerDuty test (turn alert_pagerduty_test_enabled off)`, and #32's
  `[ALERT - Warning] beta · alert policy or channel changed: google.monitoring.v3.AlertPolicyService.UpdateAlertPolicy`
  (2026-10-13; both still titled with Monitoring's summary, before the apply). The first rule drops one leading tag
  of any kind (`[ALERT - Warning] `, `[RESOLVED] `). A policy without a subject gets Monitoring's default,
  `[ALERT - Warning] <condition> on <resource>` (incident #31). After its tag that isn't "word · ", so the title
  becomes "policy · condition". So does any other subject not in tpa-platform's shape.
- **The conditions.** `event.custom_details.incident.documentation.subject matches regex
  '^(?:[[][^]]*[]] )?[a-z][a-z-]* · '`. The condition language refuses a backslash inside a quoted string, so `[[]`
  is a literal `[`, `[]]` a literal `]` (a `]` first in a class is literal in RE2), and `[^]]` anything but `]`. There
  is no lookaround, because RE2 has none. The matching ignores letter case unless written `exactly`, so "Beta · " also
  matches.
- **How the title is made.** Each rule reads its fields into `variables` and writes the title with a template
  `extraction` into `event.summary` (`{{variables.subject}}`, or `{{variables.policy}} · {{variables.condition}}`).
  The subject's regex is `^(?:[[][^]]*[]] )?(.+)`: the subject without its tag. The names' regex is
  `^[[:space:]]*(.+)`: the first line that isn't blank. A variable takes its capture group. RE2's `.` never matches a newline
  unless the `s` flag is on. If PagerDuty compiled with it, "the first line" would take the rest of the field, which
  is harmless.
- **Details.** Every rule in `titles` also copies four fields of the same event to the top level of the alert's
  details, where the PagerDuty app and web show each on its own line beside the nested payload. A field that is
  missing, or that its regex doesn't match, is left out (the fake's reading; "PagerDuty API behaviour" below):

  | Detail | From | |
  |---|---|---|
  | `what_to_check` | `documentation.content` | its first line that isn't blank (tpa-platform writes a policy's documentation as one paragraph: what happened, then what to read) |
  | `console` | `url` | the incident's Google Cloud console link, only when it starts `https://console.cloud.google.com/` |
  | `observed` | `observed_value` | e.g. `2.000` |
  | `threshold` | `threshold_value` | e.g. `0` |

  Nothing is fetched and nothing outside the event is added, so what reaches PagerDuty is what reached it before
  ("What reaches PagerDuty").
- **Resolves still match.** No rule touches the dedup key (Monitoring's `incident_key`) or the event action. A
  resolve event finds its incident exactly as before.
- **Severity is untouched.** The three severity rules keep their labels, conditions, severities and priorities, and
  stay in `start`. They only gain `route_to: titles`. An event that none of them matches reaches the fourth rule, which
  sets nothing, so it keeps PagerDuty's default severity, critical, as before.

**The titles need Advanced Event Orchestration.** Routing to a second set, variables and extractions are part of
PagerDuty's Advanced Event Orchestration (the AIOps add-on; support.pagerduty.com/main/docs/pricing-tiers). On an
account without it, PagerDuty still takes the update. It answers with `warnings` ("only rules in the 'start' set will
be evaluated") and then runs `start` alone. That is why the severity rules are in `start`: such an account loses only
the titles, never the severity.
- `pd_setup.py --apply` reads each orchestration update's `warnings`. If there are any, it puts back the orchestration
  it read before the update (a new service gets the severity rules alone), refuses with "this PagerDuty plan lacks
  Advanced Event Orchestration; titles unchanged, the previous orchestration restored", and exits 1.
- If putting it back fails, the line says so. The severity rules still run, because they are in `start`.
- No API shows the add-on before an update. `/abilities` names no such ability, and a service's `aiops`
  enablement is only an on/off switch for each service. So the dry run prints a note that `--apply` checks the warnings.

`pd_setup.py`'s dry run lists an orchestration update rule by rule: `+` added, `~` moved or changed (naming each
action that changed, such as "route_to added"), `-` removed. `pd_test_event.py` gives its event a subject in
tpa-platform's shape with Monitoring's tag in front (`[ALERT - warning] test · PagerDuty setup check, please ignore
(…)`) and checks the title: the subject without the tag, or, with `--monitoring-subject` (Monitoring's own default
subject), "policy · condition". It does the same through the titled integration.

**Applying it (with the add-on only).**
1. `make pagerduty-plan`, and read the three updates.
2. `python3 scripts/pagerduty/pd_setup.py --apply`. If it refuses with "lacks Advanced Event Orchestration", the
   account has no add-on. Nothing else changed, and the severity rules are as they were.
3. `make pagerduty-plan` again. It must print "0 to create, 0 to update". If an orchestration still shows as an
   update, PagerDuty stores a field the comparison doesn't expect: read the `~` line before re-applying.
4. The two live test events (`pd_test_event.py`, "Verified live" below).

## Notification rules

`pd_setup.py` builds each person's rules from the contact methods they **already have**. It never adds or changes a
contact method, because phone numbers are personal. The minutes are counted from when the incident is assigned to
the person.

| Contact method | High urgency | Low urgency |
|---|---|---|
| PagerDuty app (push) | 0 min | 0 min |
| SMS | 0 min | never |
| Phone call | 3 min | never |
| Email | 0 min | 0 min |
| Slack (direct message from PagerDuty) | 0 min | 0 min |

Today Jonathan has email and Slack, and Rafeale has email only.

**Settings are honoured. Rules are created only with `--apply --add-rules`.** A plain `--apply` never creates a
notification rule, even for a contact method that has none.
- A designed rule that is missing is reported as "kept … missing, not added". That includes a rule a person deleted,
  even a method's only rule. For example, someone who removed their phone's only rule to stop calls doesn't get calls
  back.
- A rule set to a different delay is reported as "kept" and left alone.
- Run `--add-rules` when someone adds a phone or installs the app and wants the designed rules. It also puts back any
  rule a person removed, so check the dry run (`pd_setup.py --add-rules`) first.

## The owner's phone (Jonathan)

1. Install the PagerDuty app (iOS or Android), sign in to the TPA's PagerDuty account and allow notifications.
2. In PagerDuty, go to **My Profile → Contact Information**. Add your mobile number for **SMS** and for **phone**, and
   confirm both when PagerDuty sends a code.
3. On this Mac: `python3 scripts/pagerduty/pd_setup.py --add-rules`. It should list "create" lines for app push, SMS
   and phone call. Then run `python3 scripts/pagerduty/pd_setup.py --apply --add-rules`.
4. Send yourself a test page and leave it open:
   `python3 scripts/pagerduty/pd_test_event.py --role app --severity critical --send --keep`. Your phone should get a
   push and a text straight away, and a call after 3 minutes. Then resolve the incident in the app. Resolve it within
   15 minutes, or level 2 (Rafeale) is paged.
5. Once that page reaches your phone, **drop Google's own text message channel**: step 5 of the Google Cloud half
   below (`alert_sms_number = null` in beta's untracked `terraform.tfvars`, then an apply). From then on, urgent texts
   come from PagerDuty only.

Rafeale must accept his PagerDuty invitation. His email contact method shows as not enabled, so until he accepts,
level 2 reaches nobody. He should then do steps 1 to 3 for himself.

## Slack

PagerDuty is already linked to the Sentient Forge Slack workspace, and Jonathan's PagerDuty user is linked to his
Slack user. Steps for a person:

1. The channel is **#obatpa-incidents** (2026-11-12). A different channel needs **@PagerDuty** invited to it and
   `SLACK_CHANNEL` in `pdlib.py` changed.
2. Connect each of the three "TPA beta ·" services to that channel. Either run `/pd connect` in the channel, or go
   to PagerDuty → Integrations → Slack. Choose:
   - urgency: **all** (high and low);
   - priorities: **all** (no filter). An empty priority filter is reported as a gap;
   - events: at least **triggered** and **resolved**.
   Made through the API, a connection takes the screen's shape (`notification_type: stakeholder`, `priorities: null`):
   a "responder" one posts nothing ("The new account", above).
3. Re-run `python3 scripts/pagerduty/pd_setup.py`. Each service's "Slack:" line turns from "by hand … not
   connected" to "ok … connected to #obatpa-incidents". If a setting is missing, the line names it.

Slack is reached **through PagerDuty**, not through Google's own Slack channel. You get one message per incident, with
Acknowledge and Resolve buttons and every update in its thread. tpa-platform's `alert_slack_channel_ids` stays empty,
so alerts aren't posted twice. `pd_setup.py` only reads the connections, through PagerDuty's Slack integration API on
`app.pagerduty.com` (the same path on `api.pagerduty.com` answers 401 to an account key). It never makes one.

## Silencing

- **Planned work on a service:** in PagerDuty, open the service, choose **New Maintenance Window**, and set the start
  and end. Alerts that arrive during the window make no incident and page nobody.
- **One noisy alert in Google Cloud:** in Monitoring → Alerting, **snooze** the policy (or its incident) for a set
  time. Monitoring then sends nothing to PagerDuty.
- **Don't** disable a service or change the escalation policy to silence it: `pd_setup.py` reports either as drift,
  and a disabled service drops real alerts too.

## Running the scripts

All three use the Python standard library only. They read the PagerDuty REST API key from `PAGERDUTY_TOKEN`, or else
from the macOS login keychain (generic password, service `tpa-pagerduty-api`). They never print it, nor an integration
key. They never follow an HTTP redirect, so the key can't be carried to another host. They never pass
`PAGERDUTY_TOKEN` to `security` or `terraform`.

On a machine without the keychain item, give the key to one command only. Don't `export` it to the whole shell:

```bash
read -rs PD_KEY                                     # paste the key; nothing is echoed
PAGERDUTY_TOKEN="$PD_KEY" python3 scripts/pagerduty/pd_setup.py
unset PD_KEY
```

| Script | Does | Default | To change things |
|---|---|---|---|
| `scripts/pagerduty/pd_setup.py` | Makes PagerDuty match this page, found by exact name. Never deletes. Never touches what it did not make, except the two people's notification rules, and those only with `--add-rules`. Stops when a parent object is refused. | dry run: prints create / update / ok / kept / refused / by hand | `--apply`; `--add-rules` (create missing designed notification rules: the only way any rule is created); `--retry-intelligent-grouping` |
| `scripts/pagerduty/tf_with_keys.py -- terraform -chdir=DIR plan\|apply [-flag=value …]` | Reads the three services' integration keys (the titled integration's, or the plain one's with `TW_PAGERDUTY_ROUTE=monitoring`) and runs that one Terraform command with `TF_VAR_pagerduty_service_keys` in its environment only. Prints one line saying which route's keys it found. Stops before Terraform if one is missing, or if a titled integration does not hold the file's code. Refuses any other command. | none: it runs the plan or apply it is given (`plan` is the dry run) | `--env production` (the "TPA production ·" services); `TW_PAGERDUTY_ROUTE=monitoring` (the way back) |
| `scripts/pagerduty/pd_test_event.py --role app\|phi\|cc --severity <text>` | Posts one test notification, shaped as Monitoring posts it, to the service's titled integration (or, with `TW_PAGERDUTY_ROUTE=monitoring`, an Events API v1 event through the plain one). The severity can be in any case, for example `critical`, `WARNING` or `"no severity"`. Prints the urgency, severity, priority and title PagerDuty gave it, checks them against the tables above, and resolves it. | dry run: shows the notification (key hidden) | `--send`; `--keep` (leave it open); `--monitoring-subject` (Monitoring's own subject, so the title must be "policy · condition") |

`make pagerduty-plan` is the `pd_setup.py` dry run. `make pagerduty-test` runs the scripts' tests against a local fake
PagerDuty and a fake `terraform` (part of `make check`). The tests of the titled integration's code run it under
`node`; without `node` they are skipped with a loud warning, never passed. The fakes are an automated gate only; the live account is the real proof.

## The Google Cloud half: Terraform makes the channels

The owner, 2026-10-11 (tpa-platform D-142): *"Remember all changes must be done to terraform if needed so we never
modify the project directly."* So nobody makes a PagerDuty channel by hand or by API. tpa-platform's Terraform
(`infra/modules/monitoring`) makes one `pagerduty` notification channel in each of the app, PHI and call-centre
projects, and routes every alert policy there to it. Budget alerts stay on email.

The owner's Ruling K (D-143, *"Store it hidden now (Recommended)"*): each channel's integration key is kept in
Terraform's state, marked sensitive. The pinned google provider (6.x) has no write-only form for it. The key can only
send alerts into PagerDuty; it reads nothing.

tpa-platform's inputs. Its `infra/README.md`, "PagerDuty's keys at the apply", is the authority:

- `alert_pagerduty_enabled` (bool, in beta's untracked `terraform.tfvars`) decides whether the channels exist. The key
  decides nothing about that.
- `pagerduty_service_keys` (`map(string)` keyed `app`, `phi` and `cc`, `sensitive`) holds the keys. It is never in a
  tfvars file or a repo. It is set only as `TF_VAR_pagerduty_service_keys`, in Terraform's environment, for the apply
  that creates or rotates the channels, and `tf_with_keys.py` sets it. Every later apply runs without it and changes
  no channel. A create or a replace without it fails at plan, naming this script.
- `alert_pagerduty_test_enabled` (bool, beta) is the test page.

**`tf_with_keys.py`.** Run it from tpa-platform's checkout, as whoever runs beta's applies:

```bash
python3 ~/Documents/code/trellis-watchtower/scripts/pagerduty/tf_with_keys.py -- terraform -chdir=infra/envs/beta plan
```

- It reads the three services' integration keys from PagerDuty: "TPA · Portal & API" is `app`, "TPA beta ·
  Member records" is `phi`, and "TPA · Call centre" is `cc`. Each service has two integrations, and the route
  picks one: the "Google Cloud Monitoring (titled)" integration's keys by default, the plain "Google Cloud
  Monitoring" integration's with `TW_PAGERDUTY_ROUTE=monitoring` in front of the command.
- It prints one line, for example `tf_with_keys: PagerDuty keys (beta; route transformer, the "Google Cloud
  Monitoring (titled)" integration): app present, phi present, cc present`, and never a key.
- If a service or its integration is missing, or PagerDuty does not hold `monitoring_transform.js` for a titled
  integration, it stops there and Terraform never runs.
- Otherwise it runs the command with `TF_VAR_pagerduty_service_keys` added to that command's environment, and nowhere
  else: never on a command line, in a file or in the output. The command gets this shell's environment without
  `PAGERDUTY_TOKEN`.
- It runs `terraform [-chdir=DIR] plan|apply` with flags only (`-replace=ADDR`, `-auto-approve` and so on). It refuses
  any other program or subcommand, an argument that isn't a flag (a saved plan file, or `-replace ADDR` without the
  `=`), `-out` (a saved plan holds the keys), and any `TF_LOG*` setting (Terraform's debug log writes the API
  requests, keys included).
- The directory Terraform runs in must be named for `--env` (default `beta`: `beta` or `beta-…`), so one
  environment's keys never reach another's channels. A future production set is `--env production`, which reads the
  "TPA production · …" services.

Steps:

1. **The first apply.** In beta's `terraform.tfvars`, set `alert_pagerduty_enabled = true`. Plan through the helper
   and read the plan. It should show three channel creates (app, PHI, call centre), each policy's channel list gaining
   one, and nothing destroyed or replaced. Then apply through the helper:

   ```bash
   W=~/Documents/code/trellis-watchtower/scripts/pagerduty/tf_with_keys.py
   python3 "$W" -- terraform -chdir=infra/envs/beta plan
   python3 "$W" -- terraform -chdir=infra/envs/beta apply
   ```

   The PHI channel is made by the same apply, so nobody calls the PHI project by hand.
2. **Later applies need no key.** Run a plain `terraform apply`. The channels keep the stored key, and the plan shows
   no change to them.
3. **Rotation.** When a service's integration key changes in PagerDuty, replace that project's channel with the new
   key, through the helper:

   ```bash
   python3 "$W" -- terraform -chdir=infra/envs/beta apply \
     '-replace=module.monitoring_app.google_monitoring_notification_channel.pagerduty[0]'
   ```

   The channel addresses, as tpa-platform's `beta-alert-gaps` work writes them. Check them against its
   `infra/README.md`:
   - app: `module.monitoring_app.google_monitoring_notification_channel.pagerduty[0]`
   - PHI: `module.monitoring_own["phi"].google_monitoring_notification_channel.pagerduty[0]`
   - call centre: `module.monitoring_cc.google_monitoring_notification_channel.pagerduty[0]`

   Quote the whole `-replace=…` argument in single quotes, because the brackets and the PHI address's `"phi"` mean
   something to the shell. The module makes the new channel first, moves every policy to it, and then deletes the old
   one.

   **Moving the channels to the titled integration, and back.** A channel keeps the key it was made with, so the
   move is this same rotation: after `pd_setup.py --apply` and the three test events ("Incident titles"), one apply
   with all three `-replace=…` arguments gives each channel its service's titled key. Then run the test page (step
   4): its incident's title must be the policy's subject, "beta · PagerDuty test (…)", not Monitoring's long
   sentence. That is the first proof that Google's channel reaches a titled integration. If no incident appears, or
   the title is wrong, go back with the same apply and the plain integration's keys:

   ```bash
   TW_PAGERDUTY_ROUTE=monitoring python3 "$W" -- terraform -chdir=infra/envs/beta apply \
     '-replace=module.monitoring_app.google_monitoring_notification_channel.pagerduty[0]' \
     '-replace=module.monitoring_own["phi"].google_monitoring_notification_channel.pagerduty[0]' \
     '-replace=module.monitoring_cc.google_monitoring_notification_channel.pagerduty[0]'
   ```

   The script's one line on stderr says which route's keys went in. Nothing in PagerDuty changes for the way back:
   the plain integrations were never touched.
4. **The test page.** Set `alert_pagerduty_test_enabled = true` (it needs `alert_pagerduty_enabled = true`) and apply.
   It writes one WARNING policy, `pagerduty-test`, in the app and call-centre projects only. Its condition is always
   true, so it opens within a few minutes, and it carries no log field. Each of those two services should show an
   incident at **low urgency, severity warning, P3**. Open the alert's details and write down the exact text of
   `incident.severity` here, in docs/PAGERDUTY.md. Then set the switch back to `false` and apply. Monitoring closes
   the alert, which resolves the incident.

   **Never in the PHI project.** tpa-platform's `must_not_exist` rows (D-137) ban creating policies or channels there
   by hand, and the switch writes no test policy there. A log-match policy would carry log fields out to its channel,
   and here that channel is a vendor with no BAA. The PHI channel uses the same notification path (a `pagerduty`
   channel, the same payload, a service with the same rules), so the app project's result also settles the letter
   case for PHI.
5. **Drop Google's own text message.** Once a PagerDuty page has reached the owner's phone (step 4 of "The owner's
   phone", or the test page above), set `alert_sms_number = null` in beta's `terraform.tfvars` and apply. From then
   on, urgent texts come from PagerDuty only. The live check on 2026-10-11 found both of Google's SMS channels
   unverified, so Google's text isn't a working path today either.

## What reaches PagerDuty

PagerDuty is an outside vendor and holds no BAA, so **no PHI may reach it**. That holds by construction. A Monitoring
event carries the policy and condition names, the policy's documentation, the metric type and its labels, and the
resource labels (project, service, job). tpa-platform's monitoring module refuses any metric label outside the closed
allowlist (`service`, `operation`, `gate`, `code`, `outcome`, `status_class`, `job`, `lane`, `class`, `sqlstate`), and
any extractor that reads a tenant, member, request, row or URL field (SPEC.md, "No PHI anywhere in monitoring").
The titled integration adds one thing that is not in the event: the watchtower's address, in the links. It rearranges
the rest and fetches nothing. A new alert policy's documentation must keep to the same rule. Each service's description says so too. Beta's
administrator-feed importer (2026-10-25) keeps it: `feed-ingest-failed` (the app project, "TPA · Portal & API")
names the job alone, and records' `records-source-sync-alert` (the PHI project, "· Member records") counts a
value-free line, never its run, tenant or counts.

## Verified live (2026-10-11)

- **First build.** `pd_setup.py`'s first dry run planned 23 creates, and the first `--apply` made 22 of them.
  PagerDuty refused one: "responder" for an admin (now "manager"). The second `--apply` hit a PagerDuty listing quirk
  on the Slack rules (now fixed by reading each person's rules by urgency). After that, a dry run and an `--apply`
  both printed "0 to create, 0 to update".
- **Read back through the API, everything matched.**
  - The team and its two managers.
  - The schedule: Jonathan on call now, layer virtual start 2026-10-05 09:00 −05:00, turn 604800 s.
  - The policy: schedule then Rafeale, 15 min each, 2 loops, team-owned.
  - The three services: `severity_based` urgency, ack 1800 s, no auto-resolve, the vendor integration, orchestration
    active with an empty catch-all.
  - One intelligent grouping setting per service.
  - The business service with all three supporting it, and the notification rules.
  - "Default Service" and "Default" unchanged (`updated_at` still 07:35 −05:00).
- **First test events** (capitalised severities, rules then `matches part`, each resolved through the same
  integration within 11 s, none escalated):

  | Service | Severity sent | Urgency | Alert severity | Priority |
  |---|---|---|---|---|
  | TPA · Portal & API | Warning | low | warning | P3 |
  | TPA · Member records | Warning | low | warning | P3 |
  | TPA · Call centre | Warning | low | warning | P3 |
  | TPA · Portal & API | Critical | high | critical | P1 |

- **Case-insensitive rules.** The review found that the first test sent the same casing the rules matched, so it
  proved nothing about lower case. The rules became `matches regex '(?i)^ *Word *$'`.
  - PagerDuty refused the first form, which used `\s` ("unexpected symbols '^\\'"). The space form was accepted on all
    three services.
  - A dry run and an `--apply` then printed "0 to create, 0 to update" (30 ok, 3 by hand).
  - Two lower-case test events to Portal & API, each resolved within 7 s, none escalated:

  | Service | Severity sent | Urgency | Alert severity | Priority |
  |---|---|---|---|---|
  | TPA · Portal & API | `warning` | low | warning | P3 |
  | TPA · Portal & API | `critical` | high | critical | P1 |

  Both lower-case words matched patterns written capitalised, so the ignore-case flag works in PagerDuty. P1 on the
  critical event shows its rule matched: an unmatched event gets no priority.
- **The space class.** The re-review asked for `[[:space:]]` in place of a literal space, so a trailing tab or
  newline also matches (RE2's `$` is the very end of the text).
  - PagerDuty accepted `'(?i)^[[:space:]]*Word[[:space:]]*$'` on Portal & API, and the script then updated the other
    two.
  - A dry run and a second `--apply` printed "0 to create, 0 to update".
  - One more lower-case test on Portal & API: `warning` → **low urgency, severity warning, P3**, resolved through
    the integration after 9 s, not escalated (incident #7).
- PagerDuty's log shows it notified Jonathan by email and Slack for the first Warning, the Critical and the
  lower-case events. Two of the first Warnings were resolved within 11 s, before PagerDuty logged any notification.
- `gcp_channels.py` dry run: three keys read (not shown); Google answered 403 for all three projects. That script
  was removed the same day: under D-142 Terraform makes the channels, and `tf_with_keys.py` gives it the keys.
- Not yet seen live:
  - **The exact casing Monitoring itself sends.** The test page (step 4 of the Google Cloud half) settles it, in
    the app and call-centre projects (never PHI), and the PHI path is the same.
  - **The "no severity → critical" row.** It comes from Google's guide and the fake's model. Confirm it with
    `pd_test_event.py --role app --severity "no severity" --send`, which pages at high urgency.
- **The titles (2026-10-13), planned, not yet applied.** `make pagerduty-plan` against the account (read only):
  "0 to create, 3 to update, 27 ok, 4 kept, 0 refused, 3 by hand". The three updates are the event orchestrations.
  Each lists the three severity rules "route_to added", the fourth `start` rule added, and the three `titles` rules
  added. After the apply, `make pagerduty-plan` must print "0 to create, 0 to update". Then check it live with one
  test event per path, each resolved by the test:
  `pd_test_event.py --role app --severity warning --send` (the title is the event's subject without its tag) and
  `pd_test_event.py --role app --severity warning --monitoring-subject --send` (the title is "policy · condition").
  Before the apply, both say "NOT as designed" because of the title only.

## PagerDuty API behaviour the scripts rely on (seen 2026-10-11)

- An account owner or admin can only be a team **manager** ("admin cannot take team role responder").
- `GET /users?include[]=notification_rules` leaves out Slack rules. `GET /users/{id}/notification_rules` returns
  high urgency only unless `urgency=low` is given, and `urgency=any` returns none. So the script reads each urgency.
- The condition language refuses a backslash inside a quoted string. `matches regex` takes RE2 with `(?i)` and the
  POSIX class `[[:space:]]`.
- A service's `alert_grouping_parameters` is deprecated. Grouping lives in `/alert_grouping_settings`, paged by an
  `after` cursor, one setting per service here.
- The Slack integration API: the workspace list answers on `api.pagerduty.com`, and the connections only on
  `app.pagerduty.com`.
- A Slack connection that the API accepts and lists is not proof that it posts (2026-11-12, kind "responder"), and
  an incident's log records only the direct message to a person, never the channel post. Prove a connection with a
  labelled incident and a person's look at the channel.
- The Custom Event Transformer (seen 2026-11-12). `POST /services/{id}/integrations` with type
  `event_transformer_api_inbound_integration` and vendor `PCJ0EFQ` creates one and returns its `integration_key`. A
  `config` sent on that create is **ignored**: PagerDuty stores its own sample code. A following `PUT
  /services/{id}/integrations/{iid}` with `config.fields.code` (`{"type": "code", "value": "<the code>"}`) stores the
  code, and `GET` on the one integration returns it at `config.fields.code.value`, beside a `debug` field the script
  never sends (debug stays off). So the script creates, then stores, then reads back, and refuses when what it reads
  is not the file. The code is ES5. It reads `PD.inputRequest.body` (the parsed JSON) and calls
  `PD.emitGenericEvents([{event_type, description, incident_key, details, client, client_url}])` with `PD.Trigger` or
  `PD.Resolve`, or `PD.fail(message)`. `PD.emitCEFEvents` lost the summary (the title came out "(Incident triggered
  via the API)"), so it is never used. Requests go to `https://events.pagerduty.com/integration/<key>/enqueue` as
  JSON, and a 202 means taken.
- Not yet seen live about the transformer: Google's `pagerduty` channel posting to a titled integration's key ("Not
  yet proven", in "Incident titles"); whether a `contexts` link list passed to `PD.emitGenericEvents` is shown on
  the incident (the links are in the details too, so nothing is lost if it is not); and whether a service's listing
  with `include[]=integrations` carries the integration's name and type as the single `GET` does (the script finds
  the titled integration in that listing by its `name`, or a reference's `summary`; if neither shows,
  `pd_setup.py` would plan a create on every run, and the dry run after the first apply shows it).
- Not yet seen live, from PagerDuty's documentation (the Terraform provider's `pagerduty_event_orchestration_service`
  and the PCL reference): an orchestration update answers `{"orchestration_path": …, "warnings": [{"feature",
  "feature_type", "message", "rule_id", "warning_type"}]}`, with `warning_type` `forbidden_feature` for a feature
  the account lacks. A rule's actions carry on into the set its `route_to` names, and later rules win. A rule
  with no conditions always matches. The catch-all applies when an event reaches the end of any set without a match.
  A regex variable takes its capture group, or else the whole match. A template names variables as
  `{{variables.name}}`. A regex extraction joins its capture groups. `matches`, `matches part` and `matches regex`
  ignore case unless written `exactly`. The fake models the narrower reading wherever the documentation leaves room:
  case-sensitive matching, and a regex extraction that matches nothing changes nothing.
