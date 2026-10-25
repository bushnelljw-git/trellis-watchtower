#!/bin/sh
# The image's entrypoint: write the baked dashboards for this environment, then start Grafana.
#
# The image is promoted by digest from one environment to the next, so what differs is settled here, from the
# service's environment (none of it a secret):
#
#   TPA_APP_PROJECT_ID, TPA_CRM_PROJECT_ID, TPA_PHI_PROJECT_ID   required: each query names its datasource's
#   TPA_CC_PROJECT_ID   (may be empty)      project as a placeholder (`__TPA_PHI_PROJECT_ID__` on `cloud-phi`, ...).
#                                           Grafana drops a Cloud Monitoring query with no project name
#                                           (datasource.ts filterQuery). Empty CC (production-full has no call-centre
#                                           project): the no-cc/ variants replace the pages with a call-centre part,
#                                           and the pages that read the call centre alone (CC_ONLY_PAGES) are left out.
#                                           A page in production/ replaces its page in production whatever this is.
#   TPA_ENVIRONMENT     required, `beta` or `production` (tpa-platform's local.env): the uptime tiles' wording, and
#                       the limits each environment's Terraform sets (a service's max_instances and ceiling policy, a
#                       database's max_connections): a line drawn in beta and not in production, or at another value.
#   TPA_PAUSED_JOBS     comma list, may be empty: scheduled jobs paused on purpose (tpa-platform's
#                       var.tpa_jobs_paused, and the administrator-feed importer while beta's feed_ingest_paused).
#   TPA_NOT_DEPLOYED_JOBS  comma list, may be empty: scheduled jobs beta builds only behind a switch that is off (the
#                       importer while feed_ingest_enabled is false). A job is never in both lists.
#   TPA_STOPPED_DATABASES  comma list, may be empty: Cloud SQL instances stopped on purpose (tpa-platform's
#                       local.database_stopped; `auth_db` and `auth-db` both name auth-db).
#                       All three are beta's alone: with TPA_ENVIRONMENT=production any one set is refused, so
#                       production's tiles can never be quieted.
#                       Their tiles, and the tiles of what reads them, read "not deployed", "paused" or "database
#                       stopped" in no colour instead of red (scripts/cloud_dashboards.py, when_quiet), in that order
#                       when several hold.
#
#   render-dashboards.sh [ARGS...]               render /etc/grafana/dashboards into /var/lib/grafana/dashboards,
#                                                then exec /run.sh ARGS (the base image's entrypoint)
#   render-dashboards.sh --render-only SRC DST   render only (tests/cloud/test_render.py)
#
# Every value is checked before it is written into the JSON: a project id must look like one, the environment is one
# of two words, and a not-deployed, paused or stopped name must be one this image knows for its list (anything else
# is refused, so a typo can never quietly turn a red tile neutral).
set -eu

src=/etc/grafana/dashboards
dst=/var/lib/grafana/dashboards
render_only=0
if [ "${1:-}" = "--render-only" ]; then
  render_only=1
  src="${2:?--render-only SRC DST}"
  dst="${3:?--render-only SRC DST}"
fi

# What TPA_PAUSED_JOBS, TPA_NOT_DEPLOYED_JOBS and TPA_STOPPED_DATABASES may name (scripts/cloud_dashboards.py
# PAUSABLE, SWITCHED and DATABASES; the render test holds these to them).
KNOWN_PAUSED_JOBS="erisa-clocks nightly-anomalies stoploss-surveillance accumulator-reconcile workload-audit member-access feed-ingest-everon-sync"
KNOWN_NOT_DEPLOYED_JOBS="feed-ingest-everon-sync"
KNOWN_DATABASES="auth-db tpa-db crm-db cc-db"
# The pages that read the call-centre project alone (scripts/cloud_dashboards.py CC_ONLY): the Call centre page and
# its services' own pages. With no call-centre project they are left out.
CC_ONLY_PAGES="callcentre.json service-svc-voice.json service-svc-ops.json service-svc-twilio-rest.json"

refuse() { echo "render-dashboards: $*" >&2; exit 1; }

project_id() { # NAME REQUIRED(1|0): print the variable's value, refusing anything that is not a project id
  eval "value=\${$1:-}"
  if [ -z "$value" ] && [ "$2" = 0 ]; then
    return 0
  fi
  printf '%s' "$value" | grep -Eq '^[a-z][a-z0-9-]{4,28}[a-z0-9]$' ||
    refuse "$1 must be a Google Cloud project id, got '${value}'"
  printf '%s' "$value"
}

names() { # NAME KNOWN...: print the comma list's names, one per line, refusing a name outside KNOWN
  eval "list=\${$1:-}"
  var="$1"
  shift
  printf '%s\n' "$list" | tr ',' '\n' | while read -r name; do
    name="$(printf '%s' "$name" | tr -d ' ' | tr '_' '-')"
    [ -z "$name" ] && continue
    case " $* " in
      *" $name "*) printf '%s\n' "$name" ;;
      *) refuse "$var names '$name', which is not one of: $*" ;;
    esac
  done
}

app="$(project_id TPA_APP_PROJECT_ID 1)"
crm="$(project_id TPA_CRM_PROJECT_ID 1)"
phi="$(project_id TPA_PHI_PROJECT_ID 1)"
cc="$(project_id TPA_CC_PROJECT_ID 0)"
environment="${TPA_ENVIRONMENT:-}"
# `@@E@@production@@beta@@` inside a string; `"@@N@@production@@beta@@"`, a number (or null) written as a string,
# settles with its quotes, so the JSON holds the number. The generator writes an N token's two values as numbers alone.
case "$environment" in
  beta) settle_environment='s/@@E@@[^@]*@@\([^@]*\)@@/\1/g'
        settle_numbers='s/"@@N@@[^@"]*@@\([^@"]*\)@@"/\1/g' ;;
  production) settle_environment='s/@@E@@\([^@]*\)@@[^@]*@@/\1/g'
              settle_numbers='s/"@@N@@\([^@"]*\)@@[^@"]*@@"/\1/g' ;;
  *) refuse "TPA_ENVIRONMENT must be 'beta' or 'production', got '${environment}'" ;;
esac
# Production pauses, stops and switches off nothing on purpose (and its pages carry no tile of a job it does not
# build), so a quiet tile there would hide a real failure.
if [ "$environment" = production ]; then
  for var in TPA_PAUSED_JOBS TPA_NOT_DEPLOYED_JOBS TPA_STOPPED_DATABASES; do
    eval "value=\${$var:-}"
    [ -z "$value" ] || refuse "$var must be empty with TPA_ENVIRONMENT=production, got '${value}'"
  done
fi
paused="$(names TPA_PAUSED_JOBS $KNOWN_PAUSED_JOBS)"
not_deployed="$(names TPA_NOT_DEPLOYED_JOBS $KNOWN_NOT_DEPLOYED_JOBS)"
stopped="$(names TPA_STOPPED_DATABASES $KNOWN_DATABASES)"
# A job that is not built has no schedule to pause: a name in both lists is a mistake in what set them.
for name in $not_deployed; do
  case " $(echo $paused) " in
    *" $name "*) refuse "TPA_NOT_DEPLOYED_JOBS and TPA_PAUSED_JOBS both name '$name': a job is not deployed or paused, never both" ;;
  esac
done

# One sed program: a quiet name settles each token that lists it (a job not deployed first, then a paused one, so a
# tile both paused and stopped reads "paused"), then every token left settles to its normal text.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
program="$work/program.sed"
{
  for name in $not_deployed; do
    printf 's/@@R[a-z0-9,-]*,%s,[a-z0-9,-]*@@[^@]*@@/not deployed/g\n' "$name"
    printf 's/@@F[a-z0-9,-]*,%s,[a-z0-9,-]*@@\\([^@]*\\)@@[^@]*@@/\\1/g\n' "$name"
  done
  for name in $paused; do
    printf 's/@@R[a-z0-9,-]*,%s,[a-z0-9,-]*@@[^@]*@@/paused/g\n' "$name"
    printf 's/@@F[a-z0-9,-]*,%s,[a-z0-9,-]*@@\\([^@]*\\)@@[^@]*@@/\\1/g\n' "$name"
  done
  for name in $stopped; do
    printf 's/@@R[a-z0-9,-]*,%s,[a-z0-9,-]*@@[^@]*@@/database stopped/g\n' "$name"
    printf 's/@@F[a-z0-9,-]*,%s,[a-z0-9,-]*@@\\([^@]*\\)@@[^@]*@@/\\1/g\n' "$name"
  done
  printf 's/@@R[a-z0-9,-]*@@\\([^@]*\\)@@/\\1/g\n'
  printf 's/@@F[a-z0-9,-]*@@[^@]*@@\\([^@]*\\)@@/\\1/g\n'
  printf '%s\n' "$settle_environment"
  printf '%s\n' "$settle_numbers"
  printf 's/__TPA_APP_PROJECT_ID__/%s/g\n' "$app"
  printf 's/__TPA_CRM_PROJECT_ID__/%s/g\n' "$crm"
  printf 's/__TPA_PHI_PROJECT_ID__/%s/g\n' "$phi"
  printf 's/__TPA_CC_PROJECT_ID__/%s/g\n' "$cc"
} > "$program"

# Rendered into a scratch directory and moved into place only once every check passes, so Grafana never reads a
# half-rendered set.
mkdir -p "$work/out"
found=0
for f in "$src"/*.json; do
  [ -e "$f" ] || continue
  found=1
  name="$(basename "$f")"
  if [ -z "$cc" ]; then
    case " $CC_ONLY_PAGES " in *" $name "*) continue ;; esac
    [ -e "$src/no-cc/$name" ] && f="$src/no-cc/$name"
  fi
  # A page written for this environment (production/: the services production-full runs) wins over both.
  [ -e "$src/$environment/$name" ] && f="$src/$environment/$name"
  sed -f "$program" "$f" > "$work/out/$name"
done
[ "$found" = 1 ] || refuse "no dashboards in $src"
if grep -l -E '__TPA_[A-Z]*_PROJECT_ID__|@@' "$work"/out/*.json >&2; then
  refuse "a placeholder or token above was left unsettled"
fi
mkdir -p "$dst"
rm -f "$dst"/*.json
mv "$work"/out/*.json "$dst"/
echo "render-dashboards: rendered $(ls "$dst"/*.json | wc -l | tr -d ' ') dashboard(s) into $dst" \
  "(environment $environment; not deployed: $(echo $not_deployed | tr ' ' ',' | sed 's/^$/none/');" \
  "paused: $(echo $paused | tr ' ' ',' | sed 's/^$/none/');" \
  "stopped: $(echo $stopped | tr ' ' ',' | sed 's/^$/none/'); call centre: $([ -n "$cc" ] && echo yes || echo no))"

[ "$render_only" = 1 ] && exit 0
# exec replaces this shell, so the EXIT trap never runs: clear the scratch directory first.
rm -rf "$work"
trap - EXIT
exec /run.sh "$@"
