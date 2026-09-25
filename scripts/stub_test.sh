#!/usr/bin/env bash
# stub_test: the negative test for the database body-match probes, without
# stopping anybody's database (network-db and forge-db are shared).
#
# Brings up tw-stub (profile `test`), which serves the real health bodies of
# network, enroll and forge in their "database down" and "database up"
# shapes, all with HTTP 200. Asks tw-blackbox to probe each with the module
# the real target uses, and asserts: the down body gives probe_success 0 while
# the status code is still 200, and the up body gives probe_success 1.
# Removes tw-stub afterwards, pass or fail. Needs `make up` first.

set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f compose.yml --profile test)

cleanup() { "${COMPOSE[@]}" rm -sf stub >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker inspect -f '{{.State.Running}}' tw-blackbox 2>/dev/null | grep -q true \
  || { echo "stub-test: tw-blackbox is not running (make up first)" >&2; exit 2; }

"${COMPOSE[@]}" up -d stub >/dev/null 2>&1
for _ in $(seq 1 20); do
  docker exec tw-blackbox wget -qO- http://tw-stub:8080/forge-ok.json >/dev/null 2>&1 && break
  sleep 1
done

fail=0
# module | stub body | expected probe_success
while read -r module body want; do
  out="$(docker exec tw-blackbox wget -qO- "http://localhost:9115/probe?module=${module}&target=http://tw-stub:8080/${body}")"
  got="$(awk '/^probe_success /{print $2}' <<<"$out")"
  code="$(awk '/^probe_http_status_code /{print $2}' <<<"$out")"
  if [ "$got" = "$want" ] && [ "$code" = "200" ]; then
    printf '  PASS  %-24s %-26s probe_success=%s http=%s\n' "$module" "$body" "$got" "$code"
  else
    printf '  FAIL  %-24s %-26s probe_success=%s (want %s) http=%s (want 200)\n' "$module" "$body" "$got" "$want" "$code"
    fail=1
  fi
done <<'CASES'
http_json_db_ok        network-db-down.json      0
http_json_db_ok        network-db-up.json        1
http_json_db_ok        network-tpa-db-down.json  0
http_json_db_ok_enroll enroll-db-down.json       0
http_json_db_ok_enroll enroll-db-up.json         1
http_json_db_ok_forge  forge-degraded.json       0
http_json_db_ok_forge  forge-ok.json             1
CASES

if [ "$fail" -ne 0 ]; then echo "stub-test: FAILED"; exit 1; fi
echo "stub-test: OK"
