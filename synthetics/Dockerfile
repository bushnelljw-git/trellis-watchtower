# trellis-watchtower's synthetic journeys (synthetics/README.md; bodyfirst tasks/reliability/SYNTHETICS-DESIGN.md
# §3): one image, one Cloud Run job per journey, `journey <name>` as the job's args.
#
# Built from the REPOSITORY ROOT, with this Dockerfile, because its last step bind-mounts scripts/image_strip.py:
#     docker build -f synthetics/Dockerfile .
# tpa-platform's shared builder builds it from a trellis-watchtower commit (its row: Dockerfile
# synthetics/Dockerfile, context ".", image trellis-watchtower/watchtower-synthetics) and signs it with this
# repository's own key, image-signing/trellis-watchtower. synthetics/Dockerfile.dockerignore keeps the context to the
# package's modules and the strip script.
#
# The image policy (tpa-platform's cloudbuild/pipeline.py, scripts/image_start_check.sh and the services' own
# Dockerfiles), matched here:
# - The base pinned by digest: python:3.12-slim's multi-platform index, the same digest tpa-platform's Python images
#   use, so the strip script's package list fits it. To move it, resolve the new digest read-only
#   (`docker buildx imagetools inspect python:3.12-slim`) and check scripts/image_strip.py's PURGE against it.
# - One third-party package, cryptography, which the member robot signs its passkey assertion with (synthetics/passkey.py;
#   bodyfirst tasks/signin-robots SECURITY-REVIEW.md SR-13, never hand-written signing), and the two it requires, cffi
#   and pycparser. synthetics/requirements.lock pins the three byte for byte as auth-notary's lock does, every one an
#   exact `==` with its sha256s. The build stage `deps` installs them with --require-hashes --only-binary :all:
#   --no-deps (only those wheels: no sdist, no build backend fetched without a hash, nothing the lock does not name)
#   into a folder of their own, which the image copies into site-packages; `pip check` then holds the three together,
#   before the strip removes pip. The modules are copied straight into site-packages beside them, root's and
#   read-only to the job's user; `python -I -c "import synthetics"` is the start check's import.
# - 10001:10001, a numeric uid:gid with its own passwd row and no home.
# - No shell, package manager, network tool, perl, Python installer or setuid program: scripts/image_strip.py, byte for
#   byte tpa-platform's (tests/synthetics/test_image_policy.py pins its sha256), as the last build step, in exec form.
#   Everything after it is exec form too. `id` (coreutils) stays, which the start check runs.
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f AS deps
COPY synthetics/requirements.lock /tmp/requirements.lock
RUN ["python", "-I", "-m", "pip", "install", "--no-cache-dir", "--disable-pip-version-check", "--no-input", \
     "--require-hashes", "--only-binary", ":all:", "--no-deps", "--target", "/deps", "-r", "/tmp/requirements.lock"]

FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f

# Security upgrades (CVE-2026-85091 and CVE-2026-76844, zlib, HIGH with a fix; DSA-6613-1, trixie-security), the
# same step and pin as records-service's Dockerfile and tpa-platform's services: the scan gate refuses a HIGH finding
# that has a fix, and Debian shipped it before python:3.12-slim carries it (the deploy session's build of 093aff85,
# 2026-11-13, was refused for it). One installed binary package at one exact version; --only-upgrade never adds a
# package the base lacks; the loop fails the build unless dpkg lists each at exactly its version (dpkg's status file
# is what the scanner reads, and the strip keeps it). tests/synthetics/test_image_policy.py holds the list. Remove
# the entry once the pinned base carries the fix.
RUN SECURITY_UPGRADES="zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1" \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --only-upgrade $SECURITY_UPGRADES \
    && for pin in $SECURITY_UPGRADES; do \
         test "$(dpkg-query -W -f='${Version}' "${pin%%=*}")" = "${pin#*=}" \
           || { echo "security upgrade $pin isn't installed at that version" >&2; exit 1; }; \
       done \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /deps/ /usr/local/lib/python3.12/site-packages/
COPY synthetics/__init__.py synthetics/__main__.py synthetics/client.py synthetics/iap.py synthetics/journeys.py \
     synthetics/passkey.py synthetics/result.py synthetics/totp.py /usr/local/lib/python3.12/site-packages/synthetics/

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

RUN ["python", "-I", "-m", "pip", "check"]

RUN --mount=type=bind,source=scripts/image_strip.py,target=/tmp/image_strip.py \
    ["python", "-I", "-B", "/tmp/image_strip.py"]
USER 10001:10001

# -I: no working directory, PYTHONPATH or user site on the path, and no PYTHON* variable read (so none is set here);
# the package is site-packages' alone. The result line is flushed by the runner itself.
# No CMD: the job gives `journey <name>`; with nothing, argparse refuses (exit 2), never a silent pass.
ENTRYPOINT ["python", "-I", "-m", "synthetics"]
