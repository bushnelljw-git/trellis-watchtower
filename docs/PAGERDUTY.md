# PagerDuty for the TPA

The owner, 2026-10-11: *"This is my API key for pagerduty, i want everything set up very well with it."*

The TPA's production alerts are Cloud Monitoring alert policies in each Google Cloud project (tpa-platform's
`infra/modules/monitoring`). Each project sends its alerts to one PagerDuty service. PagerDuty decides how urgent the
alert is from the policy's severity, pages whoever is on call, escalates if nobody acknowledges, and posts to Slack.

```
alert policy (severity CRITICAL or WARNING)
  -> the project's `pagerduty` notification channel          (gcp_channels.py makes it; Terraform takes its id)
  -> PagerDuty service "TPA beta · …"                        (pd_setup.py makes it)
       event orchestration: severity -> alert severity + priority
       urgency from severity: critical/error = high, warning/info = low
  -> escalation policy "TPA Platform"
       level 1: on call on "TPA primary on-call" (15 min)
       level 2: Rafeale Hill (15 min); then the policy repeats, twice
  -> each person's notification rules (phone, SMS, app, email, Slack)
```

Like `scripts/fly-uptime-checks.sh`, the scripts here are run by a person. The repo holds no key, no Terraform and no
deploy identity. The PagerDuty key stays in the owner's login keychain.

## What exists in PagerDuty

All of it was made by `scripts/pagerduty/pd_setup.py` on 2026-10-11 and is checked by every re-run.

| Object | Name | Settings |
|---|---|---|
| Team | TPA Platform | Jonathan Bushnell and Rafeale Hill, both **manager**. PagerDuty gives an account owner or admin the manager role only. |
| Schedule | TPA primary on-call | America/Chicago. One weekly layer, handed off Monday at 09:00. Jonathan alone today. Add a name to `ROTATION` in `pdlib.py` and re-run to make it a rotation. |
| Escalation policy | TPA Platform | Owned by the team. Level 1: the schedule, 15 min. Level 2: Rafeale Hill, 15 min. Repeats twice. |
| Services | TPA beta · Portal & API (app project), TPA beta · Member records (PHI project), TPA beta · Call centre (call-centre project) | The escalation policy above. Urgency from severity (dynamic notifications). Intelligent alert grouping (PagerDuty set a 5-minute window). Acknowledgement timeout 30 min. No auto-resolve, because Monitoring resolves. One "Google Cloud Monitoring" integration each. A service event orchestration (next section). |
| Business service | Trellis TPA (beta) | Supported by the three services. It is what PagerDuty's status dashboard shows. |
| Notification rules | Jonathan Bushnell, Rafeale Hill | Built from the contact methods each person already has (next sections). |

"Default Service" and the "Default" escalation policy are left as they were. The names start "TPA beta ·" so a
production set ("TPA production · …") can sit beside them later.

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
puts that severity in the event at `event.custom_details.incident.severity`. Each service's event orchestration maps
it like this:

| Monitoring sends | Rule (exact) | Alert severity | Priority | Urgency | What the on-call person gets |
|---|---|---|---|---|---|
| `Critical` | `event.custom_details.incident.severity matches part 'Critical'` | critical | P1 | **high** | Every contact method at once (phone call after 3 min), then level 2 at 15 min |
| `Error` | `… matches part 'Error'` | error | P2 | **high** | as above |
| `Warning` | `… matches part 'Warning'` | warning | P3 | low | App push, email and Slack only. Never a call or text. |
| anything else (`No severity`, a policy made by hand) | no rule matches | critical (PagerDuty's default) | none | **high** | as Critical. This is on purpose: a policy someone forgot to grade still pages. |

An incident nobody acknowledges within 15 minutes goes to level 2. Each person is notified by their own rules for
that urgency (below).

**Acknowledge, don't resolve, while the problem is still there.** If you resolve an incident in PagerDuty while its
alert is still open in Monitoring, Monitoring reopens it. Acknowledge it, fix the problem, and let Monitoring close
the alert, which resolves the incident. An acknowledged incident that is still open after 30 minutes pages again.

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

Today Jonathan has email and Slack, and Rafeale has email only. When someone adds a phone or installs the app,
re-run `pd_setup.py` and it adds the matching rules. A rule a person set up themselves is left alone (the script
reports it as "kept").

## The owner's phone (Jonathan)

1. Install the PagerDuty app (iOS or Android), sign in to the TPA's PagerDuty account and allow notifications.
2. In PagerDuty, go to **My Profile → Contact Information**. Add your mobile number for **SMS** and for **phone**, and
   confirm both when PagerDuty sends a code.
3. On this Mac: `python3 scripts/pagerduty/pd_setup.py`. It should list "create" lines for app push, SMS and phone
   call. Then run `python3 scripts/pagerduty/pd_setup.py --apply`.
4. Send yourself a test page and leave it open:
   `python3 scripts/pagerduty/pd_test_event.py --role app --severity Critical --send --keep`. Your phone should get a
   push and a text straight away, and a call after 3 minutes. Then resolve the incident in the app. Resolve it within
   15 minutes, or level 2 (Rafeale) is paged.
5. Once that page reaches your phone, **drop Google's own text message channel**. tpa-platform's session sets
   `alert_sms_number = null` in beta's untracked `terraform.tfvars` and applies. From then on, urgent texts come from
   PagerDuty only. Until then, an urgent alert also texts you directly from Google, so you may get two texts.

Rafeale must accept his PagerDuty invitation. His email contact method shows as not enabled, so until he accepts,
level 2 reaches nobody. He should then do steps 1 to 3 for himself.

## Slack

PagerDuty is already linked to the Sentient Forge Slack workspace, and Jonathan's PagerDuty user is linked to his
Slack user. Steps for a person:

1. In Sentient Forge, create the channel **#tpa-beta-alerts** and invite **@PagerDuty** to it.
2. Connect each of the three "TPA beta ·" services to that channel. Either run `/pd connect` in the channel, or go
   to PagerDuty → Integrations → Slack. Choose:
   - urgency: **all** (high and low);
   - priorities: **all**;
   - events: **triggered, acknowledged, escalated, resolved, reassigned**.
3. Re-run `python3 scripts/pagerduty/pd_setup.py`. Each service's "Slack:" line turns from "by hand … not
   connected" to "ok … connected to #tpa-beta-alerts". If a setting is missing, the line names it.

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
key, nor a Google access token. On another machine, set the key without echoing it: `read -rs PAGERDUTY_TOKEN; export PAGERDUTY_TOKEN`.

| Script | Does | Default | To change things |
|---|---|---|---|
| `scripts/pagerduty/pd_setup.py` | Makes PagerDuty match this page, found by exact name. Never deletes. Never touches what it did not make, except the two people's notification rules. | dry run: prints create / update / ok / kept / by hand | `--apply`; `--retry-intelligent-grouping` (only if a service ever falls back to time-based grouping) |
| `scripts/pagerduty/gcp_channels.py --app P --phi P --cc P` | Makes or corrects each project's `pagerduty` notification channel "PagerDuty · <service name>", with that service's integration key. Prints `alert_pagerduty_channel_ids = { app = "…", phi = "…", cc = "…" }` on stdout. | dry run: reads both sides | `--apply`; `--rekey` (send the key again) |
| `scripts/pagerduty/pd_test_event.py --role app\|phi\|cc --severity Critical\|Error\|Warning\|"No severity"` | Sends one Monitoring-shaped test event through the service's own integration. Prints the urgency, severity and priority PagerDuty gave it, checks them against the table above, and resolves it. | dry run: shows the event (key hidden) | `--send`; `--keep` (leave it open) |

`make pagerduty-plan` is the `pd_setup.py` dry run. `make pagerduty-test` runs the scripts' tests against local fake
APIs (part of `make check`). The fakes are an automated gate only; the live account is the real proof.

## The Google Cloud half (for a person with access)

The owner's Google account can't see the TPA projects yet. The dry run on 2026-10-11 got HTTP 403 from all three.
A person who can:

1. **Needs rights.** They need `roles/monitoring.notificationChannelEditor` (or `monitoring.editor`) on each of
   `trellistpa-beta-tpa-app`, `trellistpa-beta-tpa-phi` and `trellistpa-beta-cc`. Today people hold `roles/viewer`.
   Who holds this is the owner's ruling (SPEC.md, "Who holds `monitoring.editor`"); granting it is tpa-platform's IAM.
   The PHI project is inside the VPC Service Controls perimeter, so its channel can only be made by a member of
   `grp-platform-admin` working from the break-glass access level (tpa-platform's `ing-monitoring` rule). Anywhere
   else, that one call is refused.
2. `gcloud auth login`, as that person.
3. Dry run:
   `python3 scripts/pagerduty/gcp_channels.py --app trellistpa-beta-tpa-app --phi trellistpa-beta-tpa-phi --cc trellistpa-beta-cc`.
   It should print three `create` lines and no 403.
4. Run it again with `--apply`. Paste the printed `alert_pagerduty_channel_ids = { … }` line into beta's untracked
   `terraform.tfvars` in tpa-platform. tpa-platform's session then plans and applies, which routes every policy in
   each project to that project's channel by id. The key never enters Terraform.
5. Run the dry run again. It should print three `ok` lines and the same ids.

If someone makes a channel by hand in the console (Monitoring → Alerting → Edit notification channels → PagerDuty →
Add new), they use the display name "PagerDuty · <service name>" and paste the key from PagerDuty → the service →
Integrations → Google Cloud Monitoring. A later `gcp_channels.py` run then finds and checks that channel.

## What reaches PagerDuty

PagerDuty is an outside vendor and holds no BAA, so **no PHI may reach it**. That holds by construction. A Monitoring
event carries the policy and condition names, the policy's documentation, the metric type and its labels, and the
resource labels (project, service, job). tpa-platform's monitoring module refuses any metric label outside the closed
allowlist (`service`, `operation`, `gate`, `code`, `outcome`, `status_class`, `job`, `lane`, `class`, `sqlstate`), and
any extractor that reads a tenant, member, request, row or URL field (SPEC.md, "No PHI anywhere in monitoring").
A new alert policy's documentation must keep to the same rule. Each service's description says so too.

## Verified live (2026-10-11)

- `pd_setup.py`: the first dry run planned 23 creates. The first `--apply` made 22 of them. PagerDuty refused one:
  "responder" for an admin (now "manager"). The second `--apply` hit a PagerDuty listing quirk on the Slack rules (now
  fixed by reading each person's rules by urgency). After that, a dry run and an `--apply` both printed "0 to create,
  0 to update" (27 ok, 3 by hand: the Slack connections).
- **Read back through the API, everything matched.** The team and its two managers. The schedule: Jonathan on call
  now, layer virtual start 2026-10-05 09:00 −05:00, turn 604800 s. The policy: schedule then Rafeale, 15 min each,
  2 loops, team-owned. The three services: `severity_based` urgency, ack 1800 s, no auto-resolve, intelligent
  grouping, the vendor integration, the three rules exactly as above with an empty catch-all, orchestration active.
  The business service with all three supporting it. The notification rules. "Default Service" and "Default" were
  unchanged (`updated_at` still 07:35 −05:00).
- **Test events** (`pd_test_event.py`, Monitoring's 1.2 payload on the Events API v1, each resolved through the same
  integration 5 to 11 seconds later, none escalated):

  | Service | Severity sent | Urgency | Alert severity | Priority |
  |---|---|---|---|---|
  | TPA beta · Portal & API | Warning | low | warning | P3 |
  | TPA beta · Member records | Warning | low | warning | P3 |
  | TPA beta · Call centre | Warning | low | warning | P3 |
  | TPA beta · Portal & API | Critical | high | critical | P1 |

  PagerDuty's log shows it notified Jonathan by email and Slack for the first Warning and for the Critical. The other
  two Warnings were resolved within 11 s, before PagerDuty logged any notification.
- `gcp_channels.py` dry run: three keys read (not shown); Google answered 403 for all three projects (expected); it
  printed `alert_pagerduty_channel_ids = { app = null, phi = null, cc = null }`.
- Not yet seen live: the "No severity → critical" row. It comes from Google's guide and is covered by the fake's
  model. One `pd_test_event.py --severity "No severity" --send` confirms it, and it pages at high urgency.

## PagerDuty API behaviour the scripts rely on (seen 2026-10-11)

- An account owner or admin can only be a team **manager** ("admin cannot take team role responder").
- `GET /users?include[]=notification_rules` leaves out Slack rules. `GET /users/{id}/notification_rules` returns
  high urgency only unless `urgency=low` is given, and `urgency=any` returns none. So the script reads each urgency.
- PagerDuty fills each service's intelligent grouping with a 5-minute window and also lists it under
  `/alert_grouping_settings`.
- The Slack integration API: the workspace list answers on `api.pagerduty.com`, and the connections only on
  `app.pagerduty.com`.
