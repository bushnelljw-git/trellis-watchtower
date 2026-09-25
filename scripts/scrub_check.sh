#!/usr/bin/env bash
# scrub_check: replay tests/fixtures/logs through the REAL Alloy pipeline and
# prove what reaches Loki is clean (docs/SPEC.md W2).
#
# Each run copies every fixture to .fixtures-run/<service>--<run>.jsonl, which
# Alloy tails as stack="fixture", service=<service>. It then queries Loki for
# lines ingested since the run started and asserts:
#   - ZERO forbidden matches (bodies, query strings, id fields, headers),
#     ZERO DEBUG, ZERO streams for model-gateway / dev-vendor-sink;
#   - the expected sanitised lines DO arrive, with their metadata;
#   - exactly EXPECTED_TOTAL lines arrive (catches over-dropping too).
# Prints counts only, never log lines. Exits non-zero on any failure.
#
# Env: LOKI_URL (default http://127.0.0.1:4392), FIXTURES_RUN_DIR.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOKI_URL="${LOKI_URL:-http://127.0.0.1:4392}"
RUN_DIR="${FIXTURES_RUN_DIR:-$ROOT/.fixtures-run}"
FIXTURES="$ROOT/tests/fixtures/logs"
EXPECTED_TOTAL=21
WAIT_SECONDS="${WAIT_SECONDS:-120}"

command -v jq >/dev/null || { echo "scrub-check: jq is required" >&2; exit 2; }
curl -sf "$LOKI_URL/ready" >/dev/null || { echo "scrub-check: Loki not ready at $LOKI_URL" >&2; exit 2; }

RUN="$(date +%s)"
START="$(( RUN - 2 ))000000000"
mkdir -p "$RUN_DIR"
rm -f "$RUN_DIR"/*.jsonl "$RUN_DIR"/*.part
for f in "$FIXTURES"/*.jsonl; do
  name="$(basename "$f" .jsonl)"
  # Write under a name Alloy ignores, then rename, so no partial file is read.
  cp "$f" "$RUN_DIR/$name--$RUN.part"
  mv "$RUN_DIR/$name--$RUN.part" "$RUN_DIR/$name--$RUN.jsonl"
done

now_ns() { echo "$(( $(date +%s) + 1 ))000000000"; }

# Number of log lines matching a LogQL log query, ingested since START.
count() {
  curl -sfG "$LOKI_URL/loki/api/v1/query_range" \
    --data-urlencode "query=$1" \
    --data-urlencode "start=$START" \
    --data-urlencode "end=$(now_ns)" \
    --data-urlencode "limit=5000" \
    | jq '[.data.result[].values[]] | length'
}

# Number of streams (any stack, last 7 days) matching a selector.
series() {
  curl -sfG "$LOKI_URL/loki/api/v1/series" \
    --data-urlencode "match[]=$1" \
    --data-urlencode "start=$(( $(date +%s) - 7 * 86400 ))000000000" \
    --data-urlencode "end=$(now_ns)" \
    | jq '.data | length'
}

echo "scrub-check: run $RUN, waiting for $EXPECTED_TOTAL lines (up to ${WAIT_SECONDS}s)"
total=0
for _ in $(seq 1 "$(( WAIT_SECONDS / 3 ))"); do
  total="$(count '{stack="fixture"}')"
  [ "$total" -ge "$EXPECTED_TOTAL" ] && break
  sleep 3
done
sleep 3  # anything past the expected total would show up now
total="$(count '{stack="fixture"}')"

fail=0
check() {  # name, got, op, want
  local name="$1" got="$2" op="$3" want="$4" ok=1
  case "$op" in
    eq) [ "$got" -eq "$want" ] || ok=0 ;;
    ge) [ "$got" -ge "$want" ] || ok=0 ;;
  esac
  if [ "$ok" -eq 1 ]; then
    printf '  PASS  %-58s %s\n' "$name" "$got"
  else
    printf '  FAIL  %-58s got %s, want %s %s\n' "$name" "$got" "$op" "$want"
    fail=1
  fi
}

echo "must be zero:"
# The SPEC's pattern (json_data|Request options|\?[A-Za-z_]+=|"tid"|Cookie)
# widened: more id names (as keys, since "error" is also a Caddy level value)
# and every Caddy header/address field.
check 'forbidden (bodies, query strings, ids, headers)' "$(count '{stack="fixture"} |~ `json_data|Request options|\?[A-Za-z_]+=|"(tid|sid|principal_id|tenant_id)"|"(sub|act|act_sub|jti|elevation_id|detail|error)"\s*:|Cookie|Authorization|remote_ip|client_ip|resp_headers|"headers"|User-Agent`')" eq 0
check 'DEBUG (metadata)' "$(count '{stack="fixture"} | level="DEBUG"')" eq 0
check 'DEBUG (raw level field)' "$(count '{stack="fixture"} |~ `(?i)"(level|severity)":"debug"`')" eq 0
check 'auth error message text' "$(count '{stack="fixture", service="auth"} |~ `duplicate key|<email>|invitations_email_key`')" eq 0
check 'httpx / anthropic logger lines' "$(count '{stack="fixture"} |~ `HTTP Request:|anthropic|httpx`')" eq 0
check 'traceback text' "$(count '{stack="fixture"} |~ `Traceback|File "|ValueError`')" eq 0
check 'connectors raw row id' "$(count '{stack="fixture", service="connectors"} |= `01J9ZFXROW`')" eq 0
check 'jobs alert detail ids' "$(count '{stack="fixture", service="tpa-jobs-drains"} |~ `prn-fx|org-fx|tnt-fx`')" eq 0
check 'records id values' "$(count '{stack="fixture", service="records"} |~ `elv-fx|sa-fx|prn-fx|tnt-fx|jti-fx|ses-fx`')" eq 0
check 'auth id values' "$(count '{stack="fixture", service="auth"} |~ `usr-fx|ses-fx|jti-fx|tnt-fx|sa-fx`')" eq 0
check 'streams service=model-gateway (all stacks)' "$(series '{service="model-gateway"}')" eq 0
check 'streams service=dev-vendor-sink (all stacks)' "$(series '{service="dev-vendor-sink"}')" eq 0

echo "must arrive:"
check 'total lines this run' "$total" eq "$EXPECTED_TOTAL"
check 'records ERROR OperationalError/08006/claims.get' "$(count '{stack="fixture", service="records"} | level="ERROR" | exc_class="OperationalError" | sqlstate="08006" | operation="claims.get" | status="503"')" eq 1
check 'records op -> operation (members.get)' "$(count '{stack="fixture", service="records"} | operation="members.get"')" eq 1
check 'records constraint error 23505' "$(count '{stack="fixture", service="records"} | exc_class="UniqueViolation" | sqlstate="23505"')" eq 1
check 'tpa-api ERROR exc_class=ReadTimeout + route' "$(count '{stack="fixture", service="tpa-api"} | exc_class="ReadTimeout" | route="/v1/claims/{claim_id}"')" eq 1
check 'auth error -> exc_class=UniqueViolation only' "$(count '{stack="fixture", service="auth"} | level="ERROR" | exc_class="UniqueViolation" | outcome="unhandled"')" eq 1
check 'auth lockout 423' "$(count '{stack="fixture", service="auth"} | status="423" | level="WARNING"')" eq 1
check 'auth request line (ids stripped, request_id kept)' "$(count '{stack="fixture", service="auth"} |= `req-fx-auth-0001`')" eq 1
check 'publisher count print' "$(count '{stack="fixture", service="auth-publisher"} |= `publisher: 3 items`')" eq 1
check 'jobs run summary + alert (job metadata)' "$(count '{stack="fixture", service="tpa-jobs-drains"} | job="notifications-drain"')" eq 2
check 'jobs failures keep operation/code' "$(count '{stack="fixture", service="tpa-jobs-drains"} |= `"code":"records_unavailable"`')" eq 1
check 'connectors pass line (outcome=pass)' "$(count '{stack="fixture", service="connectors"} | outcome="pass"')" eq 1
check 'connectors lane=sms with row=:id' "$(count '{stack="fixture", service="connectors"} | lane="sms" |= `row=:id`')" eq 1
check 'severity WARN -> level WARNING' "$(count '{stack="fixture", service="connectors"} | level="WARNING"')" eq 1
check 'severity CRITICAL -> level ERROR' "$(count '{stack="fixture", service="connectors"} | level="ERROR" | exc_class="RuntimeError"')" eq 1
check 'Caddy uuid path -> :id, query cut' "$(count '{stack="fixture", service="web-tls"} |= `"path":"/tpa/api/v1/members/:id/claims"`')" eq 1
check 'Caddy numeric + token segments -> :id' "$(count '{stack="fixture", service="web-tls"} |= `"path":"/tpa/api/v1/claims/:id/documents/:id"`')" eq 1
check 'Caddy address segment -> :id' "$(count '{stack="fixture", service="web-tls"} |= `"path":"/tpa/api/v1/lookup/:id"`')" eq 1
check 'Caddy error line (level ERROR, status 502)' "$(count '{stack="fixture", service="web-tls"} | level="ERROR" | status="502"')" eq 1

# Stream labels must be exactly {stack, service}.
labels="$(curl -sfG "$LOKI_URL/loki/api/v1/series" --data-urlencode 'match[]={stack="fixture"}' \
  --data-urlencode "start=$START" --data-urlencode "end=$(now_ns)" | jq -c '[.data[] | keys[]] | unique')"
if [ "$labels" = '["service","stack"]' ]; then
  printf '  PASS  %-58s %s\n' 'stream labels are exactly stack, service' "$labels"
else
  printf '  FAIL  %-58s %s\n' 'stream labels are exactly stack, service' "$labels"; fail=1
fi

# Structured metadata keys must come from the contract's list.
meta="$(curl -sfG "$LOKI_URL/loki/api/v1/query_range" \
  -H 'X-Loki-Response-Encoding-Flags: categorize-labels' \
  --data-urlencode 'query={stack="fixture"}' --data-urlencode "start=$START" \
  --data-urlencode "end=$(now_ns)" --data-urlencode 'limit=5000' \
  | jq -c '[.data.result[].values[][2]?.structuredMetadata // {} | keys[]] | unique')"
extra="$(jq -nc --argjson m "$meta" '$m - ["level","exc_class","sqlstate","operation","route","outcome","status","job","lane"]')"
if [ "$extra" = '[]' ]; then
  printf '  PASS  %-58s %s\n' 'metadata keys within the contract' "$meta"
else
  printf '  FAIL  %-58s extra %s\n' 'metadata keys within the contract' "$extra"; fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "scrub-check: FAILED"
  exit 1
fi
echo "scrub-check: OK"
