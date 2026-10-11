#!/usr/bin/env bash
# Vendor tpa-platform's metric catalogue (infra/monitoring.yml) into cloud/catalogue/, pinned by commit and blob sha.
# The cloud dashboards are checked against this copy (tests/cloud/test_catalogue.py), so a metric renamed in
# tpa-platform fails this repository's build the moment the new catalogue is vendored.
#
# Usage:
#   scripts/vendor_catalogue.sh TPA_PLATFORM_DIR [REF]          copy REF's catalogue (default HEAD) and its pin
#   scripts/vendor_catalogue.sh --check TPA_PLATFORM_DIR [REF]  exit 1 when the vendored copy differs from REF's
#
# Reads committed objects only (git show REF:path), never the working tree, so a peer's uncommitted edits in that
# checkout are never vendored. Never edit cloud/catalogue/monitoring.yml by hand: the test checks its blob sha.
set -euo pipefail

check=0
if [ "${1:-}" = "--check" ]; then check=1; shift; fi
dir="${1:?usage: $0 [--check] TPA_PLATFORM_DIR [REF]}"
ref="${2:-HEAD}"
path=infra/monitoring.yml

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/cloud/catalogue"

commit="$(git -C "$dir" rev-parse --verify "${ref}^{commit}")"
blob="$(git -C "$dir" rev-parse --verify "${commit}:${path}")"
vendored="$(sed -n 's/^blob=//p' "$out/SOURCE" 2>/dev/null || true)"

if [ "$check" = 1 ]; then
  if [ "$blob" = "$vendored" ]; then
    echo "catalogue: vendored copy matches $ref ($commit)"
    exit 0
  fi
  echo "catalogue: vendored blob $vendored differs from $ref ($commit) blob $blob; re-vendor and run make lint"
  git -C "$dir" diff --stat "$vendored" "$blob" 2>/dev/null || true
  exit 1
fi

mkdir -p "$out"
git -C "$dir" show "${commit}:${path}" > "$out/monitoring.yml"
# The branch name when REF names one (HEAD reads as its branch); a sha stays as given.
branch="$(git -C "$dir" rev-parse --abbrev-ref "$ref" 2>/dev/null || true)"
[ -n "$branch" ] && [ "$branch" != "HEAD" ] || branch="$ref"
cat > "$out/SOURCE" <<EOF
# The metric catalogue the cloud dashboards are checked against (tests/cloud/test_catalogue.py).
# Written by scripts/vendor_catalogue.sh; monitoring.yml beside it is that blob, verbatim.
repository=tpa-platform
ref=$branch
commit=$commit
path=$path
blob=$blob
vendored=$(date -u +%Y-%m-%d)
EOF
echo "catalogue: vendored $path from $branch ($commit), blob $blob"
