#!/usr/bin/env bash
# probe_check: every blackbox probe as Prometheus last saw it, per the label
# contract (stack/service/probe), plus which stacks are "not running" (no
# successful probe in the last hour) and the postgres exporters' pg_up.
# Exits 1 only when a probe of a RUNNING stack is failing.
#
# Env: PROM_URL (default http://127.0.0.1:4391).

set -euo pipefail
PROM_URL="${PROM_URL:-http://127.0.0.1:4391}"

q() { curl -sfG "$PROM_URL/api/v1/query" --data-urlencode "query=$1" | jq -c '.data.result'; }

success="$(q 'probe_success{job="blackbox"}')"
status="$(q 'probe_http_status_code{job="blackbox"}')"
running="$(q 'max by (stack) (max_over_time(probe_success{job="blackbox"}[1h]))')"
pg="$(q 'pg_up{job="postgres"}')"

jq -rn --argjson s "$success" --argjson h "$status" --argjson r "$running" '
  ($r | map({key: .metric.stack, value: (.value[1] == "1")}) | from_entries) as $run
  | ($h | map({key: (.metric.instance + "|" + .metric.probe), value: .value[1]}) | from_entries) as $code
  | ["STACK", "SERVICE", "PROBE", "SUCCESS", "HTTP", "STATE"],
    ($s | sort_by(.metric.stack, .metric.service, .metric.probe)[]
      | . as $x
      | ($run[$x.metric.stack] // false) as $up
      | [ $x.metric.stack, $x.metric.service, $x.metric.probe, $x.value[1],
          ($code[$x.metric.instance + "|" + $x.metric.probe] // "-"),
          (if $x.value[1] == "1" then "ok"
           elif $up then "DOWN"
           else "not running" end) ])
  | @tsv' | column -t -s $'\t'

echo
not_running="$(jq -rn --argjson r "$running" '[$r[] | select(.value[1] != "1") | .metric.stack] | join(", ")')"
echo "stacks not running: ${not_running:-none}"

if [ "$(jq 'length' <<<"$pg")" -gt 0 ]; then
  echo "postgres: $(jq -r 'sort_by(.metric.db) | map("\(.metric.db) pg_up=\(.value[1])") | join(", ")' <<<"$pg")"
else
  echo "postgres: no pg_up series (profile db not running)"
fi

down="$(jq -rn --argjson s "$success" --argjson r "$running" '
  ($r | map({key: .metric.stack, value: (.value[1] == "1")}) | from_entries) as $run
  | [$s[] | select(.value[1] != "1" and ($run[.metric.stack] // false))] | length')"
if [ "$down" -gt 0 ]; then
  echo "probe-check: $down probe(s) failing on running stacks"
  exit 1
fi
echo "probe-check: every running stack's probes are green"
