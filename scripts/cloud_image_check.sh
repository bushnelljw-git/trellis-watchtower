#!/usr/bin/env bash
# Build cloud/ under a throwaway tag, run it with no network (as cloud/README.md describes), check it, and remove
# the containers and the image. Never pushes anything; nothing leaves this machine.
#
#  0. The image's configured user is exactly 10001:10001 (tpa-platform's shared builder refuses any other); every
#     base is pinned by digest, and the image's stage is the official Grafana's; Grafana's three Go binaries were
#     rebuilt with Go 1.26.10 and every one that carries go-jose v4 has v4.1.6 (read from the binary's own build
#     information); and every installed package of the origins curl, zlib, musl and brotli is the fixed one (curl and
#     libcurl 8.23.0-r0, zlib 1.3.2-r1, musl and musl-utils 1.2.6-r3, brotli-libs 1.2.1-r0).
#  1. As it ships, set up as production-full (no call-centre project): Grafana starts, render-dashboards writes the
#     eight production pages, the four datasources are inserted, /api/search answers 401 without an IAP assertion,
#     Grafana (PID 1) runs as uid 10001 and gid 10001, the config, IAP's pinned keys, provisioning, dashboards and
#     entrypoint are root's and read-only to it, and nothing in the image is writable by it but /tmp and
#     /var/lib/grafana. The image's grafana.ini and iap_keys.json are the committed ones: the key set is read from the
#     file (jwk_set_file), never fetched, and a token under a pinned kid but signed by another key answers 401.
#  2. As beta at rest (every database stopped, the O143 sweeps paused, the importer not built), signed in the way IAP
#     signs people in: the shipped grafana.ini unchanged, with the baked key file (/etc/grafana/iap_keys.json)
#     replaced by a set holding a throwaway ES256 key, and tokens signed here with it. Checks:
#     - a wrong audience, a wrong issuer, an expired token or another key's signature answer 401;
#     - the right token signs a Viewer in, with no Explore permission, and every write answers 403;
#     - the dashboards and datasources are there, rendered for beta at rest;
#     - every dashboard query reaches Cloud Monitoring for its own datasource's project and stops there, at the
#       missing Google credentials (so no query is dropped, crashes the backend, or names another project);
#     - and, as cloud/README.md says, Grafana does not stop a viewer's own query: one naming another project with
#       REDUCE_NONE is sent on as well. Only sa-watchtower's IAM bounds it.
#
# Usage: scripts/cloud_image_check.sh      (make cloud-image-check)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
suffix="$(openssl rand -hex 4)"
tag="trellis-watchtower-cloud:check-${suffix}"
name="tw-cloud-check-${suffix}"
work="$(mktemp -d)"
cleanup() {
  docker rm -f "$name" "$name-viewer" >/dev/null 2>&1 || true
  docker image rm "$tag" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

common=(-e WATCH_HOST=watch.example.invalid -e IAP_AUDIENCE=/projects/0/global/backendServices/0)
production=(-e TPA_ENVIRONMENT=production -e TPA_APP_PROJECT_ID=check-tpa-app -e TPA_CRM_PROJECT_ID=check-crm
            -e TPA_PHI_PROJECT_ID=check-tpa-phi -e TPA_CC_PROJECT_ID=)
beta_at_rest=(-e TPA_ENVIRONMENT=beta -e TPA_APP_PROJECT_ID=check-tpa-app -e TPA_CRM_PROJECT_ID=check-tpa-app
              -e TPA_PHI_PROJECT_ID=check-tpa-phi -e TPA_CC_PROJECT_ID=check-callcentre
              -e TPA_PAUSED_JOBS=nightly-anomalies,accumulator-reconcile
              -e TPA_NOT_DEPLOYED_JOBS=feed-ingest-everon-sync
              -e TPA_STOPPED_DATABASES=auth_db,tpa_db,crm_db,cc_db)

wait_up() {
  for _ in $(seq 1 90); do
    docker exec "$1" wget -q -O /dev/null http://127.0.0.1:8080/api/health 2>/dev/null && return 0
    sleep 1
  done
  docker logs "$1" 2>&1 | tail -20
  echo "cloud_image_check: $1 did not answer /api/health in 90 s" >&2
  return 1
}

fail() { echo "cloud_image_check: $*" >&2; exit 1; }

echo "== build $tag"
docker build -q -t "$tag" "$here/cloud" >/dev/null

echo "== 0. the image's configuration"
user="$(docker image inspect --format '{{.Config.User}}' "$tag")"
[ "$user" = "10001:10001" ] || fail "the image runs as '${user:-root}', not 10001:10001 (the shared builder refuses it)"
echo "   configured user: $user"
# Every FROM is an image pinned by digest, scratch, or an earlier stage; the last is the stage named grafana, which is
# grafana/grafana by digest.
python3 - "$here/cloud/Dockerfile" <<'EOF' || fail "cloud/Dockerfile's stages are not as pinned"
import re, sys
stages, froms = {}, re.findall(r"^FROM (.+)$", open(sys.argv[1]).read(), re.M)
for line in froms:
    m = re.fullmatch(r"(\S+)(?: AS ([a-z][a-z0-9-]*))?", line)
    if not m:
        sys.exit(f"unreadable FROM: {line}")
    base, name = m.groups()
    if not (base == "scratch" or base in stages or re.fullmatch(r"[^ @]+@sha256:[0-9a-f]{64}", base)):
        sys.exit(f"FROM {base} is not pinned by digest")
    if name:
        stages[name] = stages.get(base, base)
if froms[-1] != "grafana" or not stages.get("grafana", "").startswith("grafana/grafana:"):
    sys.exit("the image's stage is not the grafana stage, grafana/grafana by digest")
print(f"   bases pinned by digest; the image is {stages['grafana'][:40]}...")
EOF
docker create --name "$name" "$tag" >/dev/null
mkdir -p "$work/bin"
for b in grafana grafana-server grafana-cli; do
  docker cp "$name:/usr/share/grafana/bin/$b" "$work/bin/$b" >/dev/null
done
docker rm "$name" >/dev/null
# Each binary's Go and modules, from its build information (Go 1.18's format: the magic, then, with flag 2, the
# version and the module list as varint-length strings 32 bytes in, the list between two 16-byte sentinels), so the
# check needs no Go of its own.
python3 - "$work/bin" <<'EOF' || fail "Grafana's binaries are not all go1.26.10 builds, with go-jose v4.1.6"
import os, sys

def string(data, at):
    length, shift = 0, 0
    while True:
        byte = data[at]
        at += 1
        length |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return data[at:at + length], at + length

RAISED = {"github.com/go-jose/go-jose/v4": "v4.1.6"}
for name in ("grafana", "grafana-server", "grafana-cli"):
    data = open(os.path.join(sys.argv[1], name), "rb").read()
    at = data.find(b"\xff Go buildinf:")
    if at < 0 or not data[at + 15] & 2:
        sys.exit(f"{name}: no readable Go build information")
    version, at = string(data, at + 32)
    version = version.decode()
    print(f"   {name}: {version}")
    if version != "go1.26.10":
        sys.exit(f"{name} is built with {version}")
    deps = dict(line.split("\t")[1:3] for line in string(data, at)[0][16:-16].decode().splitlines()
                if line.startswith("dep\t"))
    for path, want in RAISED.items():
        if name == "grafana" and path not in deps:
            sys.exit(f"grafana has no {path}")
        if path in deps:
            if deps[path] != want:
                sys.exit(f"{name}'s {path} is {deps[path]}, not {want}")
            print(f"   {name}: {path} {want}")
EOF
packages="$(docker run --rm --network none --entrypoint awk "$tag" -F: \
  '/^P:/ { p = $2 }; /^V:/ { v = $2 }; /^o:(brotli|curl|musl|zlib)$/ { print p "-" v }' /lib/apk/db/installed \
  | sort | tr '\n' ' ' || true)"
[ "$packages" = "brotli-libs-1.2.1-r0 curl-8.23.0-r0 libcurl-8.23.0-r0 musl-1.2.6-r3 musl-utils-1.2.6-r3 zlib-1.3.2-r1 " ] ||
  fail "the image's curl, zlib, musl and brotli packages are '$packages', not the fixed ones"
echo "   $packages"

# A throwaway ES256 key ("good", whose set replaces the baked one in part 2), another ("other"), and the signer.
mkdir -p "$work/check"
WORK="$work" python3 - <<'EOF'
import base64, json, os, subprocess
work = os.environ["WORK"]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
for key in ("good", "other"):
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{work}/{key}.pem"],
                   check=True)
der = subprocess.run(["openssl", "ec", "-in", f"{work}/good.pem", "-pubout", "-outform", "DER"],
                     capture_output=True, check=True).stdout
point = der[-64:]   # the uncompressed point's x and y
jwks = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "check", "alg": "ES256", "use": "sig",
                  "x": b64(point[:32]), "y": b64(point[32:])}]}
open(f"{work}/check/iap_keys.json", "w").write(json.dumps(jwks))
EOF
chmod 755 "$work/check" && chmod 644 "$work/check"/*
cat > "$work/iap_token.py" <<'EOF'
"""A JWT as IAP writes one, ES256-signed with a key made here. `iap_token.py KEY KID` prints one."""
import base64, json, os, subprocess, sys, time

AUDIENCE, ISSUER = "/projects/0/global/backendServices/0", "https://cloud.google.com/iap"
WORK = os.path.dirname(os.path.abspath(__file__))
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token(key="good", kid="check", **claims):
    now = int(time.time())
    body = {"aud": AUDIENCE, "iss": ISSUER, "email": "viewer@example.invalid", "sub": "accounts.google.com:1",
            "iat": now, "exp": now + 600, **claims}
    signing = f"{b64(json.dumps({'alg': 'ES256', 'kid': kid, 'typ': 'JWT'}).encode())}.{b64(json.dumps(body).encode())}"
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", f"{WORK}/{key}.pem"], input=signing.encode(),
                         capture_output=True, check=True).stdout
    # DER SEQUENCE { INTEGER r, INTEGER s } -> r || s, 32 bytes each.
    i = 2 if der[1] < 0x80 else 3
    r_len = der[i + 1]
    r = der[i + 2:i + 2 + r_len]
    s = der[i + 2 + r_len + 2:]
    return f"{signing}.{b64(r[-32:].rjust(32, b'\0') + s[-32:].rjust(32, b'\0'))}"


if __name__ == "__main__":
    print(token(sys.argv[1], sys.argv[2]))
EOF

echo "== 1. as it ships, production-full, no network"
docker run -d --name "$name" --network none "${common[@]}" "${production[@]}" "$tag" >/dev/null
wait_up "$name"
search="$(docker exec "$name" sh -c 'wget -q -S -O /dev/null http://127.0.0.1:8080/api/search 2>&1 | head -1' || true)"
case "$search" in *" 401 "*) echo "   /api/search without an IAP assertion: 401" ;;
  *) fail "/api/search answered '$search', not 401" ;; esac
logs="$(docker logs "$name" 2>&1)"
grep 'render-dashboards: rendered' <<<"$logs" | sed 's/^/   /'
# Every page but those that read the call centre alone (render-dashboards.sh's CC_ONLY_PAGES).
cc_only="$(sed -n 's/^CC_ONLY_PAGES="\(.*\)"$/\1/p' "$here/cloud/render-dashboards.sh" | wc -w | tr -d ' ')"
production_pages=$(( $(ls "$here"/cloud/dashboards/*.json | wc -l) - cc_only ))
grep -q "rendered ${production_pages} dashboard(s).*environment production.*call centre: no" <<<"$logs" ||
  fail "production-full should render ${production_pages} pages, without the call centre's"
inserted="$(grep -c '"msg":"inserting datasource from configuration"' <<<"$logs" || true)"
echo "   datasources inserted: $inserted"
[ "$inserted" = 4 ] || fail "expected 4 datasources"
if grep -E '"level":"(error|crit)"' <<<"$logs" >&2; then fail "Grafana logged an error at start"; fi
started="$(grep '"msg":"Starting Grafana"' <<<"$logs" || true)"
grep -q '"commit":"3c98af3ba0773ad12a8a54b1faec7dc62d8d6725"' <<<"$started" && grep -q '"version":"12.4.14"' <<<"$started" ||
  fail "the Grafana that started is not 12.4.14 rebuilt from commit 3c98af3b: $started"
echo "   Grafana 12.4.14, rebuilt from commit 3c98af3b, started"
ids="$(docker exec "$name" awk '$1 == "Uid:" || $1 == "Gid:" { print $1, $2 }' /proc/1/status)"
[ "$ids" = $'Uid: 10001\nGid: 10001' ] || fail "Grafana (PID 1) runs as '$ids', not uid 10001 and gid 10001"
pid1="$(docker exec "$name" readlink /proc/1/exe)"
case "$pid1" in */grafana) ;; *) fail "PID 1 is $pid1, not Grafana (render-dashboards must exec it)" ;; esac
echo "   PID 1: $pid1, uid 10001, gid 10001"
docker exec "$name" sh -c '
  for f in /etc/grafana/grafana.ini /etc/grafana/iap_keys.json \
           /etc/grafana/provisioning/datasources/cloud-monitoring.yml \
           /etc/grafana/provisioning/dashboards/dashboards.yml \
           /etc/grafana/dashboards/overview.json /etc/grafana/dashboards/no-cc/overview.json \
           /usr/local/bin/render-dashboards; do
    [ "$(stat -c %u "$f")" = 0 ] || { echo "$f is not root'"'"'s"; exit 1; }
    [ -w "$f" ] && { echo "$f is writable by uid $(id -u)"; exit 1; }
  done
  for d in /etc/grafana /etc/grafana/provisioning /etc/grafana/provisioning/datasources /etc/grafana/dashboards \
           /usr/local/bin /usr/share/grafana /var/log/grafana /usr/share/grafana/.aws /var/tmp; do
    touch "$d/x" 2>/dev/null && { echo "$d is writable by uid $(id -u)"; exit 1; }
  done
  exit 0' || fail "the baked files must be root's and read-only"
echo "   config, IAP's keys, provisioning, dashboards, entrypoint: root's, read-only to uid 10001"
for f in grafana.ini iap_keys.json; do
  docker exec "$name" cat "/etc/grafana/$f" | cmp -s - "$here/cloud/$f" || fail "the image's /etc/grafana/$f is not cloud/$f"
done
grep -qx 'jwk_set_file = /etc/grafana/iap_keys.json' "$here/cloud/grafana.ini" || fail "grafana.ini does not read the pinned keys"
if grep -q '^jwk_set_url' "$here/cloud/grafana.ini"; then fail "grafana.ini fetches IAP's keys (jwk_set_url)"; fi
pinned_kid="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["keys"][0]["kid"])' "$here/cloud/iap_keys.json")"
forged="$(python3 "$work/iap_token.py" other "$pinned_kid")"
status="$(docker exec "$name" curl -s -o /dev/null -w '%{http_code}' -H "X-Goog-Iap-Jwt-Assertion: $forged" \
  http://127.0.0.1:8080/api/user)"
[ "$status" = 401 ] || fail "a token under pinned kid $pinned_kid signed by another key answered $status, not 401"
echo "   IAP's keys: the committed set, from jwk_set_file (no URL); pinned kid $pinned_kid, another key's signature: 401"
# Everything uid 10001 could write: what it owns, what its group owns, and what anyone may write. Only Grafana's data
# folder (its sqlite, the plugins folder, the rendered dashboards) and /tmp (render-dashboards' scratch) may appear.
writable="$(docker exec "$name" find / -xdev ! -type l \( -perm -0002 -o -user 10001 -o -group 10001 \) \
  ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null || true)"
unexpected="$(grep -Ev '^(/tmp|/var/lib/grafana)(/.*)?$' <<<"$writable" || true)"
[ -z "$unexpected" ] || fail "writable by uid 10001 besides /tmp and /var/lib/grafana: $(tr '\n' ' ' <<<"$unexpected")"
grep -qx /var/lib/grafana/grafana.db <<<"$writable" || fail "Grafana's sqlite is not in /var/lib/grafana"
grep -qx /var/lib/grafana/dashboards/overview.json <<<"$writable" || fail "the rendered dashboards are not uid 10001's"
data_mode="$(docker exec "$name" stat -c '%a %u:%g' /var/lib/grafana)"
[ "$data_mode" = "700 10001:10001" ] || fail "/var/lib/grafana is '$data_mode', not '700 10001:10001'"
echo "   writable by uid 10001: /var/lib/grafana (700, its own: sqlite, plugins, rendered dashboards) and /tmp alone"
leftover="$(docker exec "$name" sh -c 'ls -d /tmp/tmp.* 2>/dev/null' || true)"
[ -z "$leftover" ] || fail "render-dashboards left its scratch directory behind: $leftover"
echo "   render-dashboards left nothing in /tmp"
refused="$(docker run --rm --network none "${common[@]}" "${production[@]}" -e TPA_STOPPED_DATABASES=tpa-db \
  "$tag" 2>&1 || true)"
grep -q "TPA_STOPPED_DATABASES must be empty with TPA_ENVIRONMENT=production" <<<"$refused" ||
  fail "production with a stopped database was not refused: $refused"
echo "   production with TPA_STOPPED_DATABASES set: refused before Grafana starts"
docker rm -f "$name" >/dev/null

echo "== 2. beta at rest, a signed-in Viewer (the shipped grafana.ini; the baked key file holds a throwaway key), no network"
docker create --name "$name-viewer" --network none "${common[@]}" "${beta_at_rest[@]}" "$tag" >/dev/null
docker cp "$work/check/iap_keys.json" "$name-viewer:/etc/grafana/iap_keys.json" >/dev/null
docker start "$name-viewer" >/dev/null
wait_up "$name-viewer"
docker logs "$name-viewer" 2>&1 | grep 'render-dashboards: rendered' | sed 's/^/   /'

CONTAINER="$name-viewer" WORK="$work" EXPECTED="$(ls "$here"/cloud/dashboards/*.json | wc -l | tr -d ' ')" \
  python3 - <<'EOF'
import json, os, subprocess, sys, time

container, work, expected = os.environ["CONTAINER"], os.environ["WORK"], int(os.environ["EXPECTED"])
sys.path.insert(0, work)
from iap_token import token  # noqa: E402  (the signer written above; kid "check", the throwaway key's)
projects = {"cloud-app": "check-tpa-app", "cloud-crm": "check-tpa-app", "cloud-phi": "check-tpa-phi",
            "cloud-cc": "check-callcentre"}


def api(path, jwt, method="GET", body=None):
    cmd = ["docker", "exec", "-i", container, "curl", "-s", "-o", "-", "-w", "\n%{http_code}", "-X", method,
           "-H", f"X-Goog-Iap-Jwt-Assertion: {jwt}", "-H", "Content-Type: application/json"]
    if body is not None:
        cmd += ["--data-binary", "@-"]
    out = subprocess.run(cmd + [f"http://127.0.0.1:8080{path}"], input=json.dumps(body) if body is not None else None,
                         capture_output=True, text=True, check=True).stdout
    text, _, status = out.rpartition("\n")
    try:
        return int(status), json.loads(text) if text else None
    except json.JSONDecodeError:
        return int(status), text


problems = []
good = token()
for what, jwt in (("a wrong audience", token(aud="/projects/0/global/backendServices/1")),
                  ("a wrong issuer", token(iss="https://accounts.google.com")),
                  ("an expired token", token(iat=int(time.time()) - 7200, exp=int(time.time()) - 3600)),
                  ("another key's signature", token(key="other"))):
    status, _ = api("/api/user", jwt)
    print(f"   {what}: {status}")
    if status != 401:
        problems.append(f"{what} answered {status}, not 401")

status, orgs = api("/api/user/orgs", good)
role = orgs[0]["role"] if status == 200 and orgs else None
print(f"   the right token: {status}, role {role}")
if role != "Viewer":
    problems.append(f"the signed-in role is {role}, not Viewer")
status, permissions = api("/api/access-control/user/permissions", good)
held = sorted(permissions) if isinstance(permissions, dict) else []
print(f"   permissions: {', '.join(a for a in held if a.startswith(('datasources', 'dashboards', 'folders')))}")
if "datasources:explore" in held:
    problems.append("the viewer holds datasources:explore")
if "datasources:query" not in held:
    problems.append("the viewer cannot query; the dashboards would show nothing")
writes = []
for method, path, body in (("POST", "/api/dashboards/db", {"dashboard": {"title": "check"}, "overwrite": False}),
                           ("DELETE", "/api/dashboards/uid/tw-cloud-overview", None),
                           ("POST", "/api/folders", {"title": "check"}),
                           ("PUT", "/api/datasources/uid/cloud-app", {"name": "x", "type": "stackdriver"}),
                           ("POST", "/api/annotations", {"text": "check", "time": 0})):
    status, _ = api(path, good, method, body)
    writes.append(f"{method} {path.removeprefix('/api/')} {status}")
    if status != 403:
        problems.append(f"{method} {path} answered {status}, not 403")
print(f"   writes: {'; '.join(writes)}")

found = api("/api/search?type=dash-db", good)[1]
home = api("/api/dashboards/home", good)[1]["dashboard"]
settings = api("/api/frontend/settings", good)[1]
sources = {d["uid"]: d.get("jsonData", {}).get("gceDefaultProject") for d in settings["datasources"].values()
           if d.get("type") == "stackdriver"}
print(f"   dashboards: {len(found)}; home: {home.get('uid')}; datasources: {sorted(sources.items())}")
if len(found) != expected:
    problems.append(f"expected {expected} dashboards, found {len(found)}")
if home.get("uid") != "tw-cloud-overview":
    problems.append(f"the home page is {home.get('uid')}")
if sources != projects:
    problems.append(f"the datasources' projects are {sources}")
# The scheduled runs' tiles are in a shut row: its panels are inside it.
resting = {p["title"]: p["fieldConfig"]["defaults"].get("noValue")
           for p in [q for r in home["panels"] for q in (r, *(r.get("panels") or []))]
           if p["title"] in ("nightly-anomalies", "erisa-clocks", "feed-ingest")}
print(f"   at rest: {resting}")
if resting != {"nightly-anomalies": "paused", "erisa-clocks": "database stopped",
               "feed-ingest": "not deployed"}:
    problems.append(f"beta at rest renders {resting}")

counted = {}
for entry in found:
    dashboard = api(f"/api/dashboards/uid/{entry['uid']}", good)[1]["dashboard"]
    # A shut row holds its panels inside it: their queries are sent too.
    for panel in [q for p in dashboard.get("panels", []) for q in (p, *(p.get("panels") or []))]:
        targets = panel.get("targets") or []
        if not targets:
            continue
        body = {"from": "now-1h", "to": "now", "queries": [dict(t, intervalMs=60000, maxDataPoints=100)
                                                            for t in targets]}
        results = (api("/api/ds/query", good, "POST", body)[1] or {}).get("results", {})
        for t in targets:
            uid, ref = t["datasource"]["uid"], t["refId"]
            error = (results.get(ref) or {}).get("error", "")
            want = f"https://monitoring.googleapis.com/v3/projects/{projects[uid]}/timeSeries?"
            if want not in error or "credentials" not in error:
                problems.append(f"{entry['uid']}: {panel['title']} ({ref}): {error or 'no error and no request'}")
            counted[uid] = counted.get(uid, 0) + 1
print(f"   dashboard queries that reached Cloud Monitoring for their own project: {sum(counted.values())} {counted}")

# What README.md says a viewer can do: post their own query. Grafana sends it on; only sa-watchtower's IAM bounds it.
own = {"refId": "A", "datasource": {"type": "stackdriver", "uid": "cloud-app"}, "queryType": "timeSeriesList",
       "timeSeriesList": {"projectName": "somebody-elses-project", "crossSeriesReducer": "REDUCE_NONE",
                          "perSeriesAligner": "ALIGN_NONE", "filters": ["metric.type", "=",
                                                                        "logging.googleapis.com/log_entry_count"],
                          "view": "FULL"}}
results = api("/api/ds/query", good, "POST", {"from": "now-1h", "to": "now", "queries": [own]})[1] or {}
error = (results.get("results", {}).get("A") or {}).get("error", "")
sent = "monitoring.googleapis.com/v3/projects/somebody-elses-project/timeSeries?" in error
print(f"   a viewer's own query (another project, REDUCE_NONE): {'sent on to Cloud Monitoring' if sent else error}")
if not sent:
    problems.append("Grafana now stops a viewer's own query: README.md's \"What a viewer can read\" needs updating")

for p in problems:
    print(f"cloud_image_check: {p}", file=sys.stderr)
sys.exit(1 if problems else 0)
EOF
echo "== removed the containers and $tag"
