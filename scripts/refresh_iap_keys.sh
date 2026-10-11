#!/usr/bin/env bash
# Re-pin Identity-Aware Proxy's public keys that the cloud image carries (cloud/iap_keys.json).
#
# The website verifies IAP's signed assertion against this pinned copy of Google's published key set (grafana.ini's
# jwk_set_file), so the running service needs no internet path at all. Google rotates those keys: when the pinned
# copy no longer names the key IAP signs with, every sign-in to the website is refused (401) until the image is
# rebuilt with refreshed keys. tpa-platform's tpa-api pins the same set the same way (its tpa_api/iap_keys.json and
# scripts/refresh_iap_keys.py, R187); this file keeps that file's shape: {"pinned_at", "source", "keys"}.
#
#   scripts/refresh_iap_keys.sh                 fetch Google's set, check it, and print what would change; writes
#                                               nothing. Exit 0: the pinned keys are Google's; 1: they differ.
#   scripts/refresh_iap_keys.sh --write         the same, then write cloud/iap_keys.json (pinned_at = today, UTC)
#   scripts/refresh_iap_keys.sh --from FILE     read a saved copy of the set instead of the network
#   scripts/refresh_iap_keys.sh --file PATH     compare with (and --write to) PATH instead of cloud/iap_keys.json
#
# The fetch is https to www.gstatic.com alone, follows no redirect, and is capped at 64 KiB and 10 s. Every key kept
# must be an ES256 P-256 signing key with a kid and a point on the curve; a set with none is refused (exit 2).
# Public keys, never a secret. After --write: review the diff, commit it, rebuild and redeploy the image.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
url="https://www.gstatic.com/iap/verify/public_key-jwk"
target="$here/cloud/iap_keys.json"
write=0
from=""
while [ $# -gt 0 ]; do
  case "$1" in
    --write) write=1 ;;
    --from) from="${2:?--from FILE}"; shift ;;
    --file) target="${2:?--file PATH}"; shift ;;
    *) echo "usage: scripts/refresh_iap_keys.sh [--write] [--from FILE] [--file PATH]" >&2; exit 2 ;;
  esac
  shift
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
if [ -n "$from" ]; then
  cp "$from" "$work/fetched.json"
else
  curl -sS --fail --proto '=https' --max-redirs 0 --max-time 10 --max-filesize 65536 \
    -o "$work/fetched.json" "$url" || { echo "refresh_iap_keys: could not read $url" >&2; exit 2; }
fi

URL="$url" FETCHED="$work/fetched.json" TARGET="$target" WRITE="$write" python3 -I - <<'EOF'
import base64, datetime, json, os, sys

# P-256 (FIPS 186-4 D.1.2.3): y^2 = x^3 - 3x + b mod p.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def coordinate(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != 32:
        raise ValueError("a coordinate is not 32 bytes")
    return int.from_bytes(raw, "big")


def usable(key):
    """An ES256 P-256 signing key with a kid and a point on the curve."""
    try:
        if not (isinstance(key, dict) and key.get("kty") == "EC" and key.get("crv") == "P-256"
                and key.get("alg") == "ES256" and key.get("use", "sig") == "sig"
                and isinstance(key.get("kid"), str) and key["kid"]):
            return False
        x, y = coordinate(key["x"]), coordinate(key["y"])
        return x < P and y < P and (y * y - (x * x * x - 3 * x + B)) % P == 0
    except (KeyError, TypeError, ValueError):
        return False


raw = open(os.environ["FETCHED"], "rb").read()
if len(raw) > 65536:
    print("refresh_iap_keys: the key set is larger than any published one", file=sys.stderr)
    sys.exit(2)
try:
    document = json.loads(raw)
except ValueError:
    print("refresh_iap_keys: the key set is not JSON", file=sys.stderr)
    sys.exit(2)
members = document.get("keys") if isinstance(document, dict) else None
keys = [{name: k[name] for name in ("alg", "crv", "kid", "kty", "use", "x", "y") if name in k}
        for k in (members if isinstance(members, list) else []) if usable(k)]
if not keys:
    print("refresh_iap_keys: the key set has no usable ES256 P-256 key; nothing written", file=sys.stderr)
    sys.exit(2)
keys.sort(key=lambda k: k["kid"])

target = os.environ["TARGET"]
held = []
if os.path.exists(target):
    held = json.load(open(target)).get("keys", [])
held.sort(key=lambda k: k.get("kid", ""))
before, after = {k.get("kid") for k in held}, {k["kid"] for k in keys}
same = held == keys
print(f"refresh_iap_keys: Google publishes {len(keys)} key(s) {sorted(after)}; "
      f"added {sorted(after - before)}, removed {sorted(before - after)}"
      + ("" if same or (after - before) or (before - after) else ", a key's content changed"))
if os.environ["WRITE"] != "1":
    print("refresh_iap_keys: the pinned keys are " + ("Google's; nothing to do" if same else
          "out of date; run with --write, commit, then rebuild and redeploy the image"))
    sys.exit(0 if same else 1)
pinned = {"pinned_at": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
          "source": os.environ["URL"], "keys": keys}
with open(target, "w") as handle:
    handle.write(json.dumps(pinned, indent=2) + "\n")
print(f"refresh_iap_keys: wrote {target}; review the diff, commit it, then rebuild and redeploy the image")
EOF
