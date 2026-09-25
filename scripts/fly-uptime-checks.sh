#!/usr/bin/env bash
# trellis-watchtower: production paging for the BodyF1rst apps on Fly (docs/SPEC.md, phase F).
#
# Creates, in the existing `bodyf1rst-prod` project:
#   - two Cloud Monitoring uptime checks with a body match:
#       fly-network  https://bodyf1rst-network.fly.dev/api/v1/health   regex "database"\s*:\s*true
#                    (the endpoint answers 200 with the database down, so the status code alone reads green)
#       fly-portal   https://bodyf1rst-portal.fly.dev/                 contains "Partner Portal" (the page <title>)
#     Bodies read with one curl each on 2026-09-24:
#       {"status":"ok","database":true,"version":"2.0.0"}   and   <title>Partner Portal · BodyF1RST Network</title>
#   - an email and an SMS notification channel (the owner's, from the environment or flags);
#   - one alert policy per check, firing when the check fails from 2 of its 3 regions, to email + SMS + Slack.
#     An outage is urgent under the owner's 2026-09-24 decision: text plus Slack plus email.
#
# The Slack channel is created by a person in the console and passed in by its id. This script never creates a Slack
# channel and never handles a Slack token.
#
# Safety:
#   - Dry run by default: every gcloud call is printed and none is run (not even the read-only listing).
#   - --apply runs them. Running it needs the owner's OK (docs/SPEC.md, "Owner-gated").
#   - Idempotent: with --apply it first lists the uptime checks, channels and policies whose display name starts with
#     "trellis-watchtower:" and skips any that exist. It never updates or deletes anything, and never reads or touches
#     the old watchtower's checks (their display names do not carry the prefix).
#   - The project is fixed. BodyF1rst names never go into a TPA project.
#
# Usage:
#   scripts/fly-uptime-checks.sh [--apply] [--email ADDRESS] [--sms +E164] [--slack-channel ID]
# Environment (flags win): TW_ALERT_EMAIL, TW_ALERT_SMS, TW_SLACK_CHANNEL
#   --slack-channel takes the numeric id or projects/bodyf1rst-prod/notificationChannels/<id>.

set -euo pipefail

readonly PROJECT="bodyf1rst-prod"
readonly PREFIX="trellis-watchtower:"
readonly REGIONS="usa-oregon,usa-iowa,usa-virginia"

APPLY=0
EMAIL="${TW_ALERT_EMAIL:-}"
SMS="${TW_ALERT_SMS:-}"
SLACK="${TW_SLACK_CHANNEL:-}"

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

while (($#)); do
  case "$1" in
    --apply) APPLY=1 ;;
    --email) EMAIL="${2:?--email needs an address}"; shift ;;
    --sms) SMS="${2:?--sms needs a number}"; shift ;;
    --slack-channel) SLACK="${2:?--slack-channel needs an id}"; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

# ---- inputs ----------------------------------------------------------------------------------------------------------
fail() { echo "fly-uptime-checks: $*" >&2; exit 2; }

if [[ -n "$SLACK" && "$SLACK" != projects/* ]]; then SLACK="projects/${PROJECT}/notificationChannels/${SLACK}"; fi
[[ -z "$EMAIL" || "$EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || fail "--email is not an address"
[[ -z "$SMS" || "$SMS" =~ ^\+[1-9][0-9]{7,14}$ ]] || fail "--sms must be E.164, e.g. +15551234567"
[[ -z "$SLACK" || "$SLACK" =~ ^projects/${PROJECT}/notificationChannels/[0-9]+$ ]] ||
  fail "--slack-channel must be a notification channel id in ${PROJECT}"

if ((APPLY)); then
  [[ -n "$EMAIL" && -n "$SMS" && -n "$SLACK" ]] ||
    fail "--apply needs all three destinations (urgent = text + Slack + email): --email, --sms, --slack-channel"
  command -v gcloud >/dev/null || fail "gcloud is not installed"
fi
# In a dry run, a missing destination prints as a placeholder.
EMAIL_SHOWN="${EMAIL:-<TW_ALERT_EMAIL>}"
SMS_SHOWN="${SMS:-<TW_ALERT_SMS>}"
SLACK_SHOWN="${SLACK:-projects/${PROJECT}/notificationChannels/<TW_SLACK_CHANNEL>}"
# The phone number is printed masked (it is the owner's).
[[ -n "$SMS" ]] && SMS_MASKED="${SMS:0:2}******${SMS: -2}" || SMS_MASKED="$SMS_SHOWN"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/tw-fly-uptime.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ---- printing and running --------------------------------------------------------------------------------------------
shown() { # one argument, quoted for reading when it needs it
  local a="$1"
  [[ -n "$SMS" ]] && a="${a//$SMS/$SMS_MASKED}"
  if [[ "$a" =~ ^[A-Za-z0-9_@%+=:,./-]+$ ]]; then printf '%s' "$a"; else printf "'%s'" "${a//\'/\'\\\'\'}"; fi
}

show() {
  local first=1 a
  printf '+ '
  for a in "$@"; do
    ((first)) || printf ' '
    first=0
    shown "$a"
  done
  printf '\n'
}

# run CMD...: print it; run it only with --apply.
run() {
  show "$@"
  if ((APPLY)); then "$@"; fi
}

# capture VAR CMD...: print it; with --apply, run it and keep its output in VAR.
capture() {
  local var="$1"
  shift
  show "$@"
  if ((APPLY)); then printf -v "$var" '%s' "$("$@")"; fi
}

# ---- what exists (ours only) -----------------------------------------------------------------------------------------
EXISTING_CHECKS="" EXISTING_CHANNELS="" EXISTING_POLICIES=""
FILTER="displayName:\"${PREFIX}\""
echo "# ${PROJECT}: list what already exists (display names starting \"${PREFIX}\" only)"
capture EXISTING_CHECKS gcloud monitoring uptime list-configs --project="$PROJECT" --filter="$FILTER" \
  --format='value(displayName,name)'
capture EXISTING_CHANNELS gcloud alpha monitoring channels list --project="$PROJECT" --filter="$FILTER" \
  --format='value(displayName,name)'
capture EXISTING_POLICIES gcloud alpha monitoring policies list --project="$PROJECT" --filter="$FILTER" \
  --format='value(displayName,name)'
if ((!APPLY)); then
  echo "# dry run: nothing was listed, so everything below is shown as if absent. With --apply, each create is"
  echo "# skipped when an object with the same display name already exists."
fi

# name_of LISTING DISPLAY_NAME: the resource name for an exact display-name match, or empty.
name_of() { awk -F '\t' -v d="$2" '$1 == d { print $2; exit }' <<<"$1"; }

# ---- notification channels -------------------------------------------------------------------------------------------
# channel DISPLAY TYPE LABEL: sets CHANNEL_NAME to the existing or new channel's resource name.
channel() {
  local display="$1" type="$2" label="$3" existing
  existing="$(name_of "$EXISTING_CHANNELS" "$display")"
  if [[ -n "$existing" ]]; then
    echo "# exists, skipped: $display ($existing)"
    CHANNEL_NAME="$existing"
    return
  fi
  CHANNEL_NAME="projects/${PROJECT}/notificationChannels/<id of $display>"
  capture CHANNEL_NAME gcloud alpha monitoring channels create --project="$PROJECT" --display-name="$display" \
    --type="$type" --channel-labels="$label" --user-labels=owner=trellis-watchtower --format='value(name)'
}

echo
echo "# ---- notification channels"
channel "${PREFIX} owner email" email "email_address=${EMAIL_SHOWN}"
EMAIL_CHANNEL="$CHANNEL_NAME"
channel "${PREFIX} owner SMS" sms "number=${SMS_SHOWN}"
SMS_CHANNEL="$CHANNEL_NAME"
echo "# Slack: an existing channel, referenced by id only: ${SLACK_SHOWN}"
echo "# note: an SMS channel delivers only after it is verified (Monitoring > Alerting > Edit notification channels >"
echo "#       Verify; gcloud has no verify command). Email needs no verification."

# ---- uptime checks and their policies ----------------------------------------------------------------------------------
# check KEY HOST PATH MATCHER_TYPE MATCHER_CONTENT RUNBOOK
check() {
  local key="$1" host="$2" path="$3" mtype="$4" mcontent="$5" runbook="$6"
  local check_display="${PREFIX} ${key}" policy_display="${PREFIX} ${key} down" existing check_id policy_file
  echo
  echo "# ---- ${key}: https://${host}${path}"
  existing="$(name_of "$EXISTING_CHECKS" "$check_display")"
  local args=(gcloud monitoring uptime create "$check_display" --project="$PROJECT"
    --resource-type=uptime-url --resource-labels="host=${host},project_id=${PROJECT}"
    --protocol=https --port=443 --validate-ssl=true --request-method=get --path="$path"
    --status-classes=2xx --matcher-type="$mtype" --matcher-content="$mcontent"
    --period=1 --timeout=10 --regions="$REGIONS"
    --user-labels="owner=trellis-watchtower,stack=fly,service=${key}" --format='value(name)')
  if [[ -n "$existing" ]]; then
    echo "# exists, skipped: $check_display ($existing)"
    check_id="${existing##*/}"
  else
    check_id="<check id of ${check_display}>"
    capture check_id "${args[@]}"
    check_id="${check_id##*/}"
  fi

  if [[ -n "$(name_of "$EXISTING_POLICIES" "$policy_display")" ]]; then
    echo "# exists, skipped: $policy_display"
    return
  fi
  policy_file="${WORK}/${key}-policy.json"
  cat >"$policy_file" <<JSON
{
  "displayName": "${policy_display}",
  "severity": "CRITICAL",
  "combiner": "OR",
  "userLabels": {"owner": "trellis-watchtower", "stack": "fly", "urgency": "urgent"},
  "conditions": [{
    "displayName": "${key} uptime check failing in 2 of 3 regions",
    "conditionThreshold": {
      "filter": "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\" AND metric.label.\"check_id\"=\"${check_id}\"",
      "aggregations": [{
        "alignmentPeriod": "1200s",
        "perSeriesAligner": "ALIGN_NEXT_OLDER",
        "crossSeriesReducer": "REDUCE_COUNT_FALSE",
        "groupByFields": ["resource.label.*"]
      }],
      "comparison": "COMPARISON_GT",
      "thresholdValue": 1,
      "duration": "60s",
      "trigger": {"count": 1}
    }
  }],
  "alertStrategy": {"autoClose": "1800s"},
  "documentation": {"mimeType": "text/markdown", "content": "${runbook}"},
  "notificationChannels": ["${EMAIL_CHANNEL}", "${SMS_CHANNEL}", "${SLACK_SHOWN}"]
}
JSON
  echo "# create policy: ${policy_display}, from ${policy_file##*/}:"
  sed 's/^/#   /' "$policy_file"
  run gcloud alpha monitoring policies create --project="$PROJECT" --policy-from-file="$policy_file" \
    --format='value(name)'
}

check fly-network bodyf1rst-network.fly.dev /api/v1/health matches-regex '"database"\s*:\s*true' \
  "bodyf1rst-network is down, or its health body reports the database down. First check: fly status -a bodyf1rst-network, then fly logs -a bodyf1rst-network, then the bodyf1rst-pgvector app. Fixed by the network session. trellis-watchtower docs/SIGNALS.md."
check fly-portal bodyf1rst-portal.fly.dev / contains-string "Partner Portal" \
  "The partner portal page is not being served (no 2xx, or the page lacks its title). First check: fly status -a bodyf1rst-portal, then whether a deploy just ran. Fixed by the network session (web/). trellis-watchtower docs/SIGNALS.md."

echo
if ((APPLY)); then
  echo "# done. Checks report within about 5 minutes: gcloud monitoring uptime list-configs --project=${PROJECT}"
else
  echo "# dry run complete: nothing was called. Re-run with --apply (owner's OK first) and all three destinations."
fi
