#!/bin/sh
# The image's entrypoint: write the baked dashboards with this environment's project ids, then start Grafana.
#
# Why: Grafana's Cloud Monitoring datasource drops any query whose project name is empty (datasource.ts filterQuery),
# so every dashboard query must name its project, and the ids differ per environment while the image is promoted by
# digest. Each query in cloud/dashboards names a placeholder for its datasource's project (`__TPA_PHI_PROJECT_ID__`
# on `cloud-phi`, and so on; scripts/dashboard_lint.py holds each query to its own), and this fills them in from the
# same variables the datasources read (provisioning/datasources/cloud-monitoring.yml).
#
#   render-dashboards.sh [ARGS...]                 render /etc/grafana/dashboards into /var/lib/grafana/dashboards,
#                                                  then exec /run.sh ARGS (the base image's entrypoint)
#   render-dashboards.sh --render-only SRC DST     render only (tests/cloud/test_render.py)
#
# A project id must look like one (6 to 30 characters: lower-case letters, digits and hyphens, starting with a letter),
# so nothing else can be written into the JSON. TPA_CC_PROJECT_ID may be empty (production-full has no call-centre
# project): its queries are then left with no project, and Grafana skips them.
set -eu

src=/etc/grafana/dashboards
dst=/var/lib/grafana/dashboards
render_only=0
if [ "${1:-}" = "--render-only" ]; then
  render_only=1
  src="${2:?--render-only SRC DST}"
  dst="${3:?--render-only SRC DST}"
fi

project_id() { # NAME REQUIRED(1|0): print the variable's value, refusing anything that is not a project id
  eval "value=\${$1:-}"
  if [ -z "$value" ] && [ "$2" = 0 ]; then
    return 0
  fi
  if ! printf '%s' "$value" | grep -Eq '^[a-z][a-z0-9-]{4,28}[a-z0-9]$'; then
    echo "render-dashboards: $1 must be a Google Cloud project id, got '${value}'" >&2
    exit 1
  fi
  printf '%s' "$value"
}

app="$(project_id TPA_APP_PROJECT_ID 1)"
crm="$(project_id TPA_CRM_PROJECT_ID 1)"
phi="$(project_id TPA_PHI_PROJECT_ID 1)"
cc="$(project_id TPA_CC_PROJECT_ID 0)"

mkdir -p "$dst"
rm -f "$dst"/*.json
found=0
for f in "$src"/*.json; do
  [ -e "$f" ] || continue
  found=1
  sed -e "s/__TPA_APP_PROJECT_ID__/${app}/g" \
      -e "s/__TPA_CRM_PROJECT_ID__/${crm}/g" \
      -e "s/__TPA_PHI_PROJECT_ID__/${phi}/g" \
      -e "s/__TPA_CC_PROJECT_ID__/${cc}/g" \
      "$f" > "$dst/$(basename "$f")"
done
if [ "$found" = 0 ]; then
  echo "render-dashboards: no dashboards in $src" >&2
  exit 1
fi
if grep -l '__TPA_[A-Z]*_PROJECT_ID__' "$dst"/*.json >&2; then
  echo "render-dashboards: a placeholder above has no variable here" >&2
  exit 1
fi
echo "render-dashboards: rendered $(ls "$dst"/*.json | wc -l | tr -d ' ') dashboard(s) into $dst"

[ "$render_only" = 1 ] && exit 0
exec /run.sh "$@"
