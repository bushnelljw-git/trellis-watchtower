#!/usr/bin/env bash
# Build cloud/ under a throwaway tag, run it with no network (as cloud/README.md describes), check it, and remove
# the containers and the image. Never pushes anything; nothing leaves this machine.
#
#  1. As it ships, set up as production-full (no call-centre project): Grafana starts, render-dashboards writes the
#     eight production pages, the four datasources are inserted, /api/search answers 401 without an IAP assertion,
#     and the config, provisioning and dashboards are root's and read-only to Grafana.
#  2. As beta at rest (every database stopped, the O143 sweeps paused), signed in the way IAP signs people in: the
#     shipped grafana.ini with one line changed, the key set read from a file (jwk_set_file) instead of Google's URL,
#     and tokens signed here with a throwaway ES256 key. Checks:
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

echo "== 1. as it ships, production-full, no network"
docker run -d --name "$name" --network none "${common[@]}" "${production[@]}" "$tag" >/dev/null
wait_up "$name"
search="$(docker exec "$name" sh -c 'wget -q -S -O /dev/null http://127.0.0.1:8080/api/search 2>&1 | head -1' || true)"
case "$search" in *" 401 "*) echo "   /api/search without an IAP assertion: 401" ;;
  *) fail "/api/search answered '$search', not 401" ;; esac
logs="$(docker logs "$name" 2>&1)"
grep 'render-dashboards: rendered' <<<"$logs" | sed 's/^/   /'
grep -q 'rendered 8 dashboard(s).*environment production.*call centre: no' <<<"$logs" ||
  fail "production-full should render 8 pages, without the call centre"
inserted="$(grep -c '"msg":"inserting datasource from configuration"' <<<"$logs" || true)"
echo "   datasources inserted: $inserted"
[ "$inserted" = 4 ] || fail "expected 4 datasources"
if grep -E '"level":"(error|crit)"' <<<"$logs" >&2; then fail "Grafana logged an error at start"; fi
docker exec "$name" sh -c '
  for f in /etc/grafana/grafana.ini /etc/grafana/provisioning/datasources/cloud-monitoring.yml \
           /etc/grafana/dashboards/overview.json /etc/grafana/dashboards/no-cc/overview.json \
           /usr/local/bin/render-dashboards; do
    [ "$(stat -c %u "$f")" = 0 ] || { echo "$f is not root'"'"'s"; exit 1; }
    [ -w "$f" ] && { echo "$f is writable by uid $(id -u)"; exit 1; }
  done
  touch /etc/grafana/dashboards/x 2>/dev/null && { echo "/etc/grafana/dashboards is writable"; exit 1; }
  exit 0' || fail "the baked files must be root's and read-only"
echo "   config, provisioning, dashboards, entrypoint: root's, read-only to uid 472"
leftover="$(docker exec "$name" sh -c 'ls -d /tmp/tmp.* 2>/dev/null' || true)"
[ -z "$leftover" ] || fail "render-dashboards left its scratch directory behind: $leftover"
echo "   render-dashboards left nothing in /tmp"
refused="$(docker run --rm --network none "${common[@]}" "${production[@]}" -e TPA_STOPPED_DATABASES=tpa-db \
  "$tag" 2>&1 || true)"
grep -q "TPA_STOPPED_DATABASES must be empty with TPA_ENVIRONMENT=production" <<<"$refused" ||
  fail "production with a stopped database was not refused: $refused"
echo "   production with TPA_STOPPED_DATABASES set: refused before Grafana starts"
docker rm -f "$name" >/dev/null

echo "== 2. beta at rest, a signed-in Viewer (jwk_set_file), no network"
mkdir -p "$work/check"
sed 's|^jwk_set_url = https://www.gstatic.com/iap/verify/public_key-jwk$|jwk_set_file = /etc/grafana-check/jwks.json|' \
  "$here/cloud/grafana.ini" > "$work/check/grafana.ini"
changed="$(diff "$here/cloud/grafana.ini" "$work/check/grafana.ini" | grep -c '^[<>]' || true)"
[ "$changed" = 2 ] || fail "the check's grafana.ini must differ from the shipped one in the key line alone"
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
open(f"{work}/check/jwks.json", "w").write(json.dumps(jwks))
EOF
chmod 755 "$work/check" && chmod 644 "$work/check"/*
docker create --name "$name-viewer" --network none "${common[@]}" "${beta_at_rest[@]}" \
  -e GF_PATHS_CONFIG=/etc/grafana-check/grafana.ini "$tag" >/dev/null
docker cp "$work/check" "$name-viewer:/etc/grafana-check" >/dev/null
docker start "$name-viewer" >/dev/null
wait_up "$name-viewer"
docker logs "$name-viewer" 2>&1 | grep 'render-dashboards: rendered' | sed 's/^/   /'

CONTAINER="$name-viewer" WORK="$work" EXPECTED="$(ls "$here"/cloud/dashboards/*.json | wc -l | tr -d ' ')" \
  python3 - <<'EOF'
import base64, json, os, subprocess, sys, time

container, work, expected = os.environ["CONTAINER"], os.environ["WORK"], int(os.environ["EXPECTED"])
audience, issuer = "/projects/0/global/backendServices/0", "https://cloud.google.com/iap"
projects = {"cloud-app": "check-tpa-app", "cloud-crm": "check-tpa-app", "cloud-phi": "check-tpa-phi",
            "cloud-cc": "check-callcentre"}
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token(key="good", **claims):
    """A JWT as IAP writes one, ES256-signed with a throwaway key."""
    now = int(time.time())
    body = {"aud": audience, "iss": issuer, "email": "viewer@example.invalid", "sub": "accounts.google.com:1",
            "iat": now, "exp": now + 600, **claims}
    signing = f"{b64(json.dumps({'alg': 'ES256', 'kid': 'check', 'typ': 'JWT'}).encode())}.{b64(json.dumps(body).encode())}"
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", f"{work}/{key}.pem"], input=signing.encode(),
                         capture_output=True, check=True).stdout
    # DER SEQUENCE { INTEGER r, INTEGER s } -> r || s, 32 bytes each.
    i = 2 if der[1] < 0x80 else 3
    r_len = der[i + 1]
    r = der[i + 2:i + 2 + r_len]
    s = der[i + 2 + r_len + 2:]
    return f"{signing}.{b64(r[-32:].rjust(32, b'\0') + s[-32:].rjust(32, b'\0'))}"


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
resting = {p["title"]: p["fieldConfig"]["defaults"].get("noValue") for p in home["panels"]
           if p["title"] in ("nightly-anomalies", "erisa-clocks")}
print(f"   at rest: {resting}")
if resting != {"nightly-anomalies": "paused", "erisa-clocks": "database stopped"}:
    problems.append(f"beta at rest renders {resting}")

counted = {}
for entry in found:
    dashboard = api(f"/api/dashboards/uid/{entry['uid']}", good)[1]["dashboard"]
    for panel in dashboard.get("panels", []):
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
