#!/usr/bin/env bash
# Build cloud/ under a throwaway tag, run it with no network (as cloud/README.md describes), check it, and remove
# the containers and the image. Never pushes anything; nothing leaves this machine.
#
#  1. The image as it ships (IAP sign-in only): Grafana starts, render-dashboards writes every dashboard, the four
#     datasources are inserted, and /api/search answers 401 without an IAP assertion.
#  2. The same image with anonymous Admin turned on for this check alone (still no network): Grafana holds the four
#     datasources and every dashboard, the home page is the overview, and every dashboard query reaches Cloud
#     Monitoring's request for its own datasource's project, where it stops at the missing Google credentials.
#     So no query is dropped as empty, crashes the backend, or names another project.
#
# Usage: scripts/cloud_image_check.sh      (make cloud-image-check)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
suffix="$(openssl rand -hex 4)"
tag="trellis-watchtower-cloud:check-${suffix}"
name="tw-cloud-check-${suffix}"
cleanup() {
  docker rm -f "$name" "$name-verify" >/dev/null 2>&1 || true
  docker image rm "$tag" >/dev/null 2>&1 || true
}
trap cleanup EXIT

env=(-e WATCH_HOST=watch.example.invalid -e IAP_AUDIENCE=/projects/0/global/backendServices/0
     -e TPA_APP_PROJECT_ID=check-tpa-app -e TPA_CRM_PROJECT_ID=check-tpa-app
     -e TPA_PHI_PROJECT_ID=check-tpa-phi -e TPA_CC_PROJECT_ID=check-callcentre)

wait_up() {
  for _ in $(seq 1 90); do
    docker exec "$1" wget -q -O /dev/null http://127.0.0.1:8080/api/health 2>/dev/null && return 0
    sleep 1
  done
  docker logs "$1" 2>&1 | tail -20
  echo "cloud_image_check: $1 did not answer /api/health in 90 s" >&2
  return 1
}

echo "== build $tag"
docker build -q -t "$tag" "$here/cloud" >/dev/null

echo "== 1. as it ships, no network"
docker run -d --name "$name" --network none "${env[@]}" "$tag" >/dev/null
wait_up "$name"
search="$(docker exec "$name" sh -c 'wget -q -S -O /dev/null http://127.0.0.1:8080/api/search 2>&1 | head -1' || true)"
case "$search" in *" 401 "*) echo "   /api/search without an IAP assertion: 401" ;;
  *) echo "cloud_image_check: /api/search answered '$search', not 401" >&2; exit 1 ;; esac
logs="$(docker logs "$name" 2>&1)"
grep -q 'render-dashboards: rendered' <<<"$logs" || { echo "cloud_image_check: render-dashboards did not run" >&2; exit 1; }
grep 'render-dashboards: rendered' <<<"$logs" | sed 's/^/   /'
inserted="$(grep -c '"msg":"inserting datasource from configuration"' <<<"$logs" || true)"
echo "   datasources inserted: $inserted"
[ "$inserted" = 4 ] || { echo "cloud_image_check: expected 4 datasources" >&2; exit 1; }
if grep -E '"level":"(error|crit)"' <<<"$logs" >&2; then
  echo "cloud_image_check: Grafana logged an error at start" >&2; exit 1
fi
docker rm -f "$name" >/dev/null

echo "== 2. anonymous Admin for this check alone, no network: provisioning and every query"
docker run -d --name "$name-verify" --network none "${env[@]}" \
  -e GF_AUTH_ANONYMOUS_ENABLED=true -e GF_AUTH_ANONYMOUS_ORG_ROLE=Admin "$tag" >/dev/null
wait_up "$name-verify"
CONTAINER="$name-verify" EXPECTED="$(ls "$here"/cloud/dashboards/*.json | wc -l | tr -d ' ')" python3 - <<'EOF'
import json, os, subprocess, sys

container, expected = os.environ["CONTAINER"], int(os.environ["EXPECTED"])
projects = {"cloud-app": "check-tpa-app", "cloud-crm": "check-tpa-app", "cloud-phi": "check-tpa-phi",
            "cloud-cc": "check-callcentre"}


def api(path, body=None):
    cmd = ["docker", "exec", "-i", container, "curl", "-s", f"http://127.0.0.1:8080{path}"]
    if body is not None:
        cmd[6:6] = ["-H", "Content-Type: application/json", "--data-binary", "@-"]
    out = subprocess.run(cmd, input=json.dumps(body) if body is not None else None, capture_output=True, text=True,
                         check=True).stdout
    return json.loads(out)


found = api("/api/search?type=dash-db")
datasources = api("/api/datasources")
home = api("/api/dashboards/home")["dashboard"]
print(f"   dashboards: {len(found)} in folder(s) {sorted({d.get('folderTitle') for d in found})}; home: {home.get('uid')}")
print(f"   datasources: {sorted((d['uid'], d['jsonData'].get('gceDefaultProject')) for d in datasources)}")
problems = []
if len(found) != expected:
    problems.append(f"expected {expected} dashboards, found {len(found)}")
if home.get("uid") != "tw-cloud-overview":
    problems.append(f"the home page is {home.get('uid')}, not tw-cloud-overview")
if sorted(d["uid"] for d in datasources) != sorted(projects):
    problems.append("the datasources are not exactly the four cloud ones")
for d in datasources:
    if d["jsonData"].get("gceDefaultProject") != projects[d["uid"]]:
        problems.append(f"{d['uid']}: gceDefaultProject is {d['jsonData'].get('gceDefaultProject')}")

counted = {}
for entry in found:
    dashboard = api(f"/api/dashboards/uid/{entry['uid']}")["dashboard"]
    for panel in dashboard.get("panels", []):
        targets = panel.get("targets") or []
        if not targets:
            continue
        body = {"from": "now-1h", "to": "now", "queries": [dict(t, intervalMs=60000, maxDataPoints=100)
                                                            for t in targets]}
        results = api("/api/ds/query", body).get("results", {})
        for t in targets:
            uid, ref = t["datasource"]["uid"], t["refId"]
            error = (results.get(ref) or {}).get("error", "")
            want = f"https://monitoring.googleapis.com/v3/projects/{projects[uid]}/timeSeries?"
            if want not in error or "credentials" not in error:
                problems.append(f"{entry['uid']}: {panel['title']} ({ref}): {error or 'no error and no request'}")
            counted[uid] = counted.get(uid, 0) + 1
print(f"   queries that reached Cloud Monitoring for their own project: {sum(counted.values())} {counted}")
for p in problems:
    print(f"cloud_image_check: {p}", file=sys.stderr)
sys.exit(1 if problems else 0)
EOF
echo "== removed the containers and $tag"
