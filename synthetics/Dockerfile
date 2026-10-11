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
# - No third-party package: standard library only, so no pip install and no lock. The modules are copied straight into
#   site-packages, root's and read-only to the job's user; `python -I -c "import synthetics"` is the start check's
#   import.
# - 10001:10001, a numeric uid:gid with its own passwd row and no home.
# - No shell, package manager, network tool, perl, Python installer or setuid program: scripts/image_strip.py, byte for
#   byte tpa-platform's (tests/synthetics/test_image_policy.py pins its sha256), as the last build step, in exec form.
#   Everything after it is exec form too. `id` (coreutils) stays, which the start check runs.
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY synthetics/__init__.py synthetics/__main__.py synthetics/client.py synthetics/iap.py synthetics/journeys.py \
     synthetics/result.py synthetics/totp.py /usr/local/lib/python3.12/site-packages/synthetics/

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

RUN --mount=type=bind,source=scripts/image_strip.py,target=/tmp/image_strip.py \
    ["python", "-I", "-B", "/tmp/image_strip.py"]
USER 10001:10001

# -I: no working directory, PYTHONPATH or user site on the path; the package is site-packages' alone.
# No CMD: the job gives `journey <name>`; with nothing, argparse refuses (exit 2), never a silent pass.
ENTRYPOINT ["python", "-I", "-m", "synthetics"]
