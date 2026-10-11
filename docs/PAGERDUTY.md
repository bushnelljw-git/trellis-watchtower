# PagerDuty for the TPA

The owner, 2026-10-11: *"This is my API key for pagerduty, i want everything set up very well with it."*

The TPA's production alerts are Cloud Monitoring alert policies in each Google Cloud project (tpa-platform's
`infra/modules/monitoring`). Each project sends its alerts to one PagerDuty service. PagerDuty decides how urgent the
alert is from the policy's severity, pages whoever is on call, escalates urgent ones if nobody acknowledges, and posts
to Slack.

```
alert policy (severity CRITICAL or WARNING)
  -> the project's `pagerduty` notification channel          (gcp_channels.py makes it; Terraform takes its id)
  -> PagerDuty service "TPA beta · …"                        (pd_setup.py makes it)
       event orchestration: severity (any letter case) -> alert severity + priority
       urgency from severity: critical/error = high, warning/info = low
  -> escalation policy "TPA Platform"                        (high urgency only; low urgency never escalates)
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
| Schedule | TPA primary on-call | America/Chicago. One weekly layer, handed off Monday at 09:00. Jonathan alone today. To make it a rotation, add a name to `ROTATION` in `pdlib.py` and re-run. The script only changes a schedule that has exactly one active layer. |
| Escalation policy | TPA Platform | Owned by the team. Level 1: the schedule, 15 min. Level 2: Rafeale Hill, 15 min. Repeats twice. |
| Services | TPA beta · Portal & API (app project), TPA beta · Member records (PHI project), TPA beta · Call centre (call-centre project) | The escalation policy above. Urgency from severity (dynamic notifications). Acknowledgement timeout 30 min. No auto-resolve, because Monitoring resolves. One "Google Cloud Monitoring" integration each. A service event orchestration (next section). |
| Alert grouping settings | one per service, named after it | Intelligent grouping (PagerDuty set a 5-minute window). The script falls back to time-based grouping (10 minutes) only if PagerDuty's refusal says "intelligent". It uses `/alert_grouping_settings`, because the service field `alert_grouping_parameters` is deprecated. |
| Business service | Trellis TPA (beta) | Supported by the three services. It is what PagerDuty's status dashboard shows. |
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
   - priorities: **all**. An empty priority filter is reported as a gap;
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
key, nor a Google access token. They never follow an HTTP redirect, so the key can't be carried to another host. They
never pass `PAGERDUTY_TOKEN` to `security` or `gcloud`.

On a machine without the keychain item, give the key to one command only. Don't `export` it to the whole shell:

```bash
read -rs PD_KEY                                     # paste the key; nothing is echoed
PAGERDUTY_TOKEN="$PD_KEY" python3 scripts/pagerduty/pd_setup.py
unset PD_KEY
```

| Script | Does | Default | To change things |
|---|---|---|---|
| `scripts/pagerduty/pd_setup.py` | Makes PagerDuty match this page, found by exact name. Never deletes. Never touches what it did not make, except the two people's notification rules, and those only with `--add-rules`. Stops when a parent object is refused. | dry run: prints create / update / ok / kept / refused / by hand | `--apply`; `--add-rules` (create missing designed notification rules: the only way any rule is created); `--retry-intelligent-grouping` |
| `scripts/pagerduty/gcp_channels.py --app P --phi P --cc P` | Makes or corrects each project's `pagerduty` notification channel "PagerDuty · <service name>", with that service's integration key. Prints `alert_pagerduty_channel_ids = { app = "…", phi = "…", cc = "…" }` on stdout. A project Google refuses prints `null` and does not stop the others. | dry run: reads both sides | `--apply`; `--rekey` (send the key again: the only way an "unknown" key is re-sent) |
| `scripts/pagerduty/pd_test_event.py --role app\|phi\|cc --severity <text>` | Sends one Monitoring-shaped test event through the service's own integration. The severity can be in any case, for example `critical`, `WARNING` or `"no severity"`. Prints the urgency, severity and priority PagerDuty gave it, checks them against the table above, and resolves it. | dry run: shows the event (key hidden) | `--send`; `--keep` (leave it open) |

`make pagerduty-plan` is the `pd_setup.py` dry run. `make pagerduty-test` runs the scripts' tests against local fake
APIs (part of `make check`). The fakes are an automated gate only; the live account is the real proof.

**How `gcp_channels.py` compares keys.** Google returns a channel's key masked, so the script can rarely see all of
it. It treats a channel's key as:
- **the same** only when Google shows the whole key and it matches;
- **different** only when the visible part proves another key (the whole value differs, or the visible tail after the
  stars is not this key's). It re-sends the key;
- **unknown** otherwise: empty, missing, all stars, a matching tail (four characters prove nothing), or a shape it
  doesn't recognise. It says so and leaves it. `--apply --rekey` sends the key again.

## The Google Cloud half (for a person with access)

The owner's Google account can't see the TPA projects yet. The dry run on 2026-10-11 got HTTP 403 from all three.

**Who runs it: the projects' owner, during the setup runbook.** That is Rafeale's owner role, before it is removed at
the end of the runbook. Nobody else is set up to make these channels:
- The platform admins' role on the PHI project is deliberately unable to create notification channels. tpa-platform is
  building a narrow custom role that can only edit and silence existing alerts.
- `roles/viewer`, which people hold today, can't create channels either.

**The PHI project and its perimeter.** The PHI project sits inside the VPC Service Controls perimeter. While beta's
perimeter is still in dry-run mode (`perimeter_dry_run`), the owner's call goes through. Once it is enforced, a
Monitoring call into the PHI project from outside is admitted only by tpa-platform's `ing-monitoring` rule. That rule
needs both of these:
- the caller is in `grp-platform-admin@${domain}`;
- the caller meets the break-glass access level `al_beta_tpa_breakglass`
  (tpa-platform `docs/infra/network-and-perimeter.md` §5.4). That means a person named in `breakglass_members`
  (people, never the group), calling from the organisation's office or VPN ranges (`breakglass_ip_ranges`), on a
  corporate-owned device with a screen lock, in a session that re-authenticated within the last hour.

So do this whole half **in one sitting during the setup runbook**, before the PHI perimeter is enforced and while
the owner role still exists. Step 3 needs both for the PHI channel. Step 5 creates and deletes an alert policy in the
app and call-centre projects, which only the owner role can do, so it too works only before the runbook ends.

**The dependency.** `alert_pagerduty_channel_ids` exists only once tpa-platform's `beta-alert-gaps` work has landed.
Pasted earlier, Terraform warns about an undeclared variable and **routes nothing**.

Steps:

1. `gcloud auth login`, as the projects' owner.
2. Dry run:
   `python3 scripts/pagerduty/gcp_channels.py --app trellistpa-beta-tpa-app --phi trellistpa-beta-tpa-phi --cc trellistpa-beta-cc`.
   It should print three `create` lines and no 403.
3. Run it again with `--apply`. Once `beta-alert-gaps` has landed, paste the printed
   `alert_pagerduty_channel_ids = { … }` line into beta's untracked `terraform.tfvars` in tpa-platform. tpa-platform's
   session then plans and applies, which routes every policy in each project to that project's channel by id. The key
   never enters Terraform.
4. Run the dry run again. It should print three `ok` lines and the same ids. The key shows as "unknown" unless Google
   shows all of it; that is expected.
5. **Fire one real Monitoring test notification in the app and call-centre projects, and confirm the urgency.**
   **Never in the PHI project.** tpa-platform's `must_not_exist` rows (D-137) ban creating policies or channels there
   by hand. A log-match policy carries log fields out to its channel, and here that channel is a vendor with no BAA.
   The PHI channel uses the same notification path (a `pagerduty` channel, the same payload, a service with the same
   rules), so the app project's result also settles the letter case for PHI.

   Google has no "send test" button for a PagerDuty channel, so this uses a temporary log-match policy. The snippet
   creates the policy, writes one log line and waits for you. Create and delete are in the same snippet: the `trap`
   **always deletes the policy on the way out**, even if a step fails or you press Ctrl-C. It works in bash and zsh,
   and was checked against a stub `gcloud` on 2026-10-11, including the failure path. Run it once with the app project
   and once with the call-centre project, each with its own channel id from step 3:

   ```bash
   P=trellistpa-beta-tpa-app CH=<the app channel id>    # second run: P=trellistpa-beta-cc CH=<the cc channel id>
   (
     set -euo pipefail
     POLICY='{"displayName": "TEST — PagerDuty setup check, please ignore", "severity": "WARNING",
       "combiner": "OR", "conditions": [{"displayName": "setup check line", "conditionMatchedLog":
       {"filter": "logName=\"projects/'"$P"'/logs/pagerduty-setup-check\""}}],
       "alertStrategy": {"notificationRateLimit": {"period": "300s"}, "autoClose": "1800s"},
       "notificationChannels": ["projects/'"$P"'/notificationChannels/'"$CH"'"],
       "documentation": {"content": "One-off PagerDuty channel check; the snippet that made it deletes it.",
       "mimeType": "text/markdown"}}'
     NAME="$(gcloud alpha monitoring policies create --project="$P" --policy="$POLICY" --format='value(name)')"
     trap 'gcloud alpha monitoring policies delete "$NAME" --project="$P" --quiet' EXIT
     gcloud logging write pagerduty-setup-check "TEST — PagerDuty setup check, please ignore" --project="$P"
     printf 'When PagerDuty shows the incident, note incident.severity, then press Enter to delete the policy: '
     read -r _
   )
   ```

   Within a few minutes the project's PagerDuty service should show an incident at **low urgency, severity warning,
   P3**. Open the alert's details and write down the exact text of `incident.severity` here, in docs/PAGERDUTY.md.
   After the policy is deleted, resolve the PagerDuty incident if it is still open: with the policy gone, nothing can
   reopen it.

   **A PHI-project check, if one is still wanted, is tpa-platform's to build.** It would be a job made through
   Terraform: an alert policy with a metric-threshold condition (no log fields) on the PHI channel, made to fire once
   and then removed by the same reviewed change. These docs give no command for it.

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
  | TPA beta · Portal & API | Warning | low | warning | P3 |
  | TPA beta · Member records | Warning | low | warning | P3 |
  | TPA beta · Call centre | Warning | low | warning | P3 |
  | TPA beta · Portal & API | Critical | high | critical | P1 |

- **Case-insensitive rules.** The review found that the first test sent the same casing the rules matched, so it
  proved nothing about lower case. The rules became `matches regex '(?i)^ *Word *$'`.
  - PagerDuty refused the first form, which used `\s` ("unexpected symbols '^\\'"). The space form was accepted on all
    three services.
  - A dry run and an `--apply` then printed "0 to create, 0 to update" (30 ok, 3 by hand).
  - Two lower-case test events to Portal & API, each resolved within 7 s, none escalated:

  | Service | Severity sent | Urgency | Alert severity | Priority |
  |---|---|---|---|---|
  | TPA beta · Portal & API | `warning` | low | warning | P3 |
  | TPA beta · Portal & API | `critical` | high | critical | P1 |

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
- `gcp_channels.py` dry run: three keys read (not shown); Google answered 403 for all three projects (expected); it
  printed `alert_pagerduty_channel_ids = { app = null, phi = null, cc = null }`.
- Not yet seen live:
  - **The exact casing Monitoring itself sends.** Step 5 of the Google Cloud half settles it, in the app and
    call-centre projects (never PHI), and the PHI path is the same.
  - **The "no severity → critical" row.** It comes from Google's guide and the fake's model. Confirm it with
    `pd_test_event.py --role app --severity "no severity" --send`, which pages at high urgency.

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
