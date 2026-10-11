#!/usr/bin/env bash
# Build synthetics/ under a throwaway tag, check it as tpa-platform's shared builder's start check checks a Python
# image (scripts/image_start_check.sh there: the generic path), and remove it. Never pushes anything.
#
#  1. The base is pinned by digest, and the image's configured user is exactly 10001:10001.
#  2. With no network, as its own user: `id -u` and `id -g` say 10001, `python -I -c "import synthetics"` works, and
#     Python's default CA bundle is there (the edge's certificate is Google-managed).
#  3. No shell starts through any shell entrypoint (the strip script's last step).
#  4. The image's own ENTRYPOINT, with no network:
#     - paused: one `skipped`/`paused` line, exit 0;
#     - J3 with the CRM flag off: one `skipped`/`not_configured` line, exit 0;
#     - J1 with no configuration: one `fail`/`config` line, exit 1;
#     - J1 configured but with no network: the metadata call fails, one `fail`/`iap_token` line, exit 1;
#     - no arguments: refused by argparse, exit 2, nothing on stdout.
#     And nothing on stderr on any of the first four.
#
# Usage: scripts/synthetics_image_check.sh      (make synthetics-image-check)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
suffix="$(openssl rand -hex 4)"
tag="trellis-watchtower-synthetics:check-${suffix}"
work="$(mktemp -d)"
cleanup() {
  docker image rm "$tag" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

fail() { echo "synthetics_image_check: FAIL - $*" >&2; exit 1; }

dockerfile="$here/synthetics/Dockerfile"
grep -Eq '^FROM [^ ]+@sha256:[0-9a-f]{64}$' "$dockerfile" || fail "synthetics/Dockerfile's base is not pinned by digest"
[ "$(grep -c '^FROM ' "$dockerfile")" = 1 ] || fail "synthetics/Dockerfile should have exactly one FROM"

echo "== build $tag (context: the repository root)"
docker build --pull -q -t "$tag" -f "$dockerfile" "$here" >"$work/build.log" 2>&1 \
  || { tail -n 30 "$work/build.log" >&2; fail "the image didn't build"; }

echo "== 1. configured user"
user="$(docker image inspect --format '{{.Config.User}}' "$tag")"
[ "$user" = "10001:10001" ] || fail "the image runs as '${user:-root}', not 10001:10001"
echo "   $user"

echo "== 2. id and the package import, offline"
uid="$(docker run --rm --network none --entrypoint id "$tag" -u)"
gid="$(docker run --rm --network none --entrypoint id "$tag" -g)"
[ "$uid" = 10001 ] && [ "$gid" = 10001 ] || fail "the process runs as uid ${uid:-?} gid ${gid:-?}"
docker run --rm --network none --entrypoint python "$tag" -I -c "import synthetics" \
  || fail "python -I -c 'import synthetics' failed as the image's own user, offline"
# The edge's certificate is Google-managed: the system trust store must survive the strip.
docker run --rm --network none --entrypoint python "$tag" -I -c \
  "import os, ssl; p = ssl.get_default_verify_paths(); assert p.cafile and os.path.getsize(p.cafile) > 100000, p" \
  || fail "the image has no CA bundle at Python's default verify path"
echo "   uid 10001, gid 10001; synthetics imports; the CA bundle is there"

echo "== 3. no shell"
for entry in /bin/sh sh /bin/bash bash dash busybox; do
  if docker run --rm --network none --entrypoint "$entry" "$tag" -c 'echo a-shell-ran' >"$work/shell.out" 2>&1; then
    fail "docker run --entrypoint $entry started"
  fi
  ! grep -q a-shell-ran "$work/shell.out" || fail "a shell ran through $entry"
done
echo "   every shell entrypoint is refused"

echo "== 4. the entrypoint, offline"
# expect <exit> <outcome> <code> <docker run arguments...>
expect() {
  local want_exit="$1" outcome="$2" code="$3"
  shift 3
  local got=0
  docker run --rm --network none "$@" >"$work/out" 2>"$work/err" || got=$?
  [ "$got" = "$want_exit" ] || { cat "$work/out" "$work/err" >&2; fail "exit $got, not $want_exit, for: $*"; }
  [ ! -s "$work/err" ] || { cat "$work/err" >&2; fail "stderr was written for: $*"; }
  [ "$(wc -l <"$work/out" | tr -d ' ')" = 1 ] || fail "not exactly one line for: $*"
  python3 - "$work/out" "$outcome" "$code" <<'EOF' || fail "the line is not $outcome/$code"
import json, sys
line = json.loads(open(sys.argv[1]).read())
assert line["message"] == "synthetic_result", line
assert (line["outcome"], line["code"]) == (sys.argv[2], sys.argv[3]), line
EOF
  echo "   $outcome/$code, exit $got: $(cat "$work/out")"
}
expect 0 skipped paused -e SYNTHETICS_PAUSED=1 "$tag" journey staff-sign-in
expect 0 skipped not_configured "$tag" journey crm
expect 1 fail config "$tag" journey staff-sign-in
printf '{"password":"check-only-not-a-secret","totp_secret":"JBSWY3DPEHPK3PXP"}' >"$work/credentials.json"
chmod 0644 "$work/credentials.json"
expect 1 fail iap_token -v "$work/credentials.json:/secrets/credentials.json:ro" \
  -e SYNTHETICS_BASE_URL=https://ops.check.invalid -e SYNTHETICS_PORTAL_BASE_URL=https://portal.check.invalid \
  -e SYNTHETICS_EMAIL=synthetic-staff@check.invalid -e SYNTHETICS_CREDENTIALS_FILE=/secrets/credentials.json \
  -e SYNTHETICS_IAP_AUDIENCE=0-check.apps.googleusercontent.com -e SYNTHETICS_STEP_TIMEOUT_S=3 \
  "$tag" journey staff-sign-in
grep -q check-only-not-a-secret "$work/out" && fail "the password reached stdout"
got=0
docker run --rm --network none "$tag" >"$work/out" 2>"$work/err" || got=$?
[ "$got" = 2 ] && [ ! -s "$work/out" ] || fail "no arguments: exit $got (not 2), or something on stdout"
echo "   no arguments: refused, exit 2"

echo "synthetics_image_check: all checks passed"
