# trellis-watchtower, production form: a stateless Grafana that reads Cloud Monitoring for the TPA app, crm, phi and
# call-centre projects, reached only through IAP on watch.${domain} (the owner ruled yes, 2026-10-11; the cloud half
# is tpa-platform's: see README.md).
#
# Build context is this directory (cloud/). tpa-platform's pipeline builds it from a trellis-watchtower commit pinned
# in releases/<id>.json and promotes it by digest; this repository holds no deploy identity.
#
# No plugins: GF_INSTALL_PLUGINS is never set, the plugin catalogue is off and Grafana 12's plugin preinstall is
# disabled in grafana.ini. Only the core stackdriver (Cloud Monitoring) datasource is used.
#
# Every base is pinned by digest, each a multi-platform index (linux/amd64 among its manifests), and everything
# fetched is pinned by its hash: Grafana's source by its commit, its Go modules by its own go.sum and go.work.sum, and
# the zlib package by its sha256. No build argument and no secret.

# --- Grafana 12.4.12, as Grafana built it ---------------------------------------------------------------------------
#
# The image itself, its frontend, plugins and everything else, except the three Go binaries rebuilt below.
FROM grafana/grafana:12.4.12@sha256:83be3e511ede559bee80e2215bb1987cb1246075461cb961beb515b0341e7aea AS grafana

# --- Grafana's Go binaries, rebuilt with Go 1.26.9 ------------------------------------------------------------------
#
# The official 12.4.12 image's grafana, grafana-server and grafana-cli are built with Go 1.26.6, whose standard
# library Container Scanning reports two CRITICAL and eight fixable HIGH advisories in, each fixed in Go 1.26.9
# (tpa-platform's build 4122c0b2, 2026-10-12). No Grafana release ships a newer Go yet (12.4.12 and 13.2.3, the newest
# on 2026-10-12, are both Go 1.26.6). So the three are rebuilt here from Grafana's own v12.4.12 source with Go 1.26.9,
# the way Grafana's release build makes them (`make build-go`: CGO off, -trimpath, -buildvcs=false, its -X stamps),
# and copied over the official ones; the same Go as tpa-platform's web image builds its Caddy with (I-517).
#
# The source: BuildKit fetches the v12.4.12 tag and refuses it unless it is commit 60d1cb95..., the public release
# commit. That commit, built with Go 1.26.6 and the official build's own stamps, gives the official linux/amd64
# grafana, grafana-server and grafana-cli byte for byte (sha256 886193624f20... for grafana; checked 2026-10-12), so
# Grafana's release build (from its security mirror's release-12.4.12#patched branch) compiled nothing the public
# source lacks.
#
# The modules: GOFLAGS=-mod=readonly, so every module is the version Grafana's go.mod and go.work name, and each
# download is checked against go.sum and go.work.sum at that commit; nothing may add or change one. The RUN then
# requires each rebuilt binary's module list and build settings (`go version -m`, all but its first line, which names
# the file and its Go) to be the official binary's exactly, so the only difference is the Go toolchain. The module and
# build caches (some 3 GB and 5 GB) are emptied in the same RUN, so the stage keeps only the three binaries.
FROM scratch AS grafana-source
ADD --checksum=60d1cb9522f234508f98e9c88295cc920c965d10 https://github.com/grafana/grafana.git#v12.4.12 /

FROM golang:1.26.9-alpine3.24@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS grafana-build
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org
COPY --from=grafana-source / /w/grafana/
COPY --from=grafana /usr/share/grafana/bin/ /w/official/
WORKDIR /w/grafana
RUN set -eu; \
    test "$(go env GOVERSION)" = "go1.26.9"; \
    stamps="-X main.version=12.4.12 -X main.commit=60d1cb9522f234508f98e9c88295cc920c965d10"; \
    stamps="$stamps -X main.buildBranch=v12.4.12 -X main.buildstamp=1790671435"; \
    for cmd in grafana grafana-server grafana-cli; do \
      go build -buildvcs=false -trimpath -ldflags "$stamps" -o "/out/$cmd" "./pkg/cmd/$cmd"; \
      test "$(go version "/out/$cmd")" = "/out/$cmd: go1.26.9"; \
      go version -m "/w/official/$cmd" | sed 1d > "/w/$cmd.official"; \
      go version -m "/out/$cmd" | sed 1d > "/w/$cmd.rebuilt"; \
      grep -qxF "$(printf '\tbuild\tCGO_ENABLED=0')" "/w/$cmd.rebuilt"; \
      cmp "/w/$cmd.official" "/w/$cmd.rebuilt"; \
    done; \
    test "$(/out/grafana -v)" = "grafana version 12.4.12"; \
    go clean -cache -modcache; \
    chmod 0555 /out/grafana /out/grafana-server /out/grafana-cli; \
    echo "grafana, grafana-server, grafana-cli: 12.4.12 (60d1cb95), go1.26.9, the official module list, checked"

# --- zlib 1.3.2-r1 ---------------------------------------------------------------------------------------------------
#
# The base's Alpine 3.24.2 has zlib 1.3.2-r0, and Container Scanning reports CVE-2026-85091 (HIGH) in it, fixed in
# 1.3.2-r1 (in Alpine 3.24's main repository since 2026-10-07; no Alpine or Grafana image carries it yet). The base
# keeps zlib for curl and apk. Both architectures' packages, by sha256, from Alpine's own repository; the RUN below
# installs this machine's with no repository and no network, and apk still checks the package's own signature against
# the base's Alpine keys.
FROM scratch AS zlib
ADD --checksum=sha256:63aeea03c15a2f9018f81805cfc8aa926bdf5cd68921f22149c2fbb5d0ee9f47 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/zlib-1.3.2-r1.apk /x86_64/zlib-1.3.2-r1.apk
ADD --checksum=sha256:1f77a542ac6634761b9fe38d8bdca19b154071dcfa25432e73f2bc8a0740a33f \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/zlib-1.3.2-r1.apk /aarch64/zlib-1.3.2-r1.apk

# --- the image -------------------------------------------------------------------------------------------------------
FROM grafana

# The image runs as 10001:10001, the uid and gid tpa-platform's shared builder requires of every image it builds
# (its canonical step refuses any other configured user), not the base's grafana user (472, in group root). That user
# has no passwd entry and needs none: Grafana reads no name for it, and run.sh sets HOME to GF_PATHS_HOME.
#
# Config, IAP's pinned keys, provisioning, the dashboards as committed and the entrypoint are root's and read-only: Grafana can change
# none of them. It writes exactly two places:
#   /var/lib/grafana   (GF_PATHS_DATA) 10001's own, 0700: the disposable sqlite, the plugins folder (empty: core
#                      plugins only) and the dashboards render-dashboards.sh writes there at start, with each query's
#                      project and this environment's settings;
#   /tmp               the base's 1777, unchanged: render-dashboards.sh's scratch folder (mktemp -d), removed again
#                      before Grafana starts.
# Everything else the base leaves world-writable (its logs folder, unused with console logging; the AWS credentials
# folder, unused; /var/tmp) is root's and closed here, so nothing else in the image is writable by 10001.
USER root
RUN --mount=type=bind,from=zlib,target=/mnt/zlib \
    set -eu; \
    apk --repositories-file=/dev/null add --no-cache "/mnt/zlib/$(apk --print-arch)/zlib-1.3.2-r1.apk"; \
    test "$(apk info -v 2>/dev/null | grep '^zlib-')" = "zlib-1.3.2-r1"
COPY --from=grafana-build /out/grafana /out/grafana-server /out/grafana-cli /usr/share/grafana/bin/
COPY grafana.ini /etc/grafana/grafana.ini
COPY iap_keys.json /etc/grafana/iap_keys.json
COPY provisioning/ /etc/grafana/provisioning/
COPY dashboards/*.json /etc/grafana/dashboards/
COPY dashboards/no-cc/*.json /etc/grafana/dashboards/no-cc/
COPY render-dashboards.sh /usr/local/bin/render-dashboards
RUN chown -R root:root /etc/grafana /usr/local/bin/render-dashboards /var/log/grafana /usr/share/grafana/.aws \
 && chmod -R a-w,a+rX /etc/grafana \
 && chmod 0555 /usr/local/bin/render-dashboards /var/log/grafana /usr/share/grafana/.aws \
 && chmod 0755 /var/tmp \
 && chown -R 10001:10001 /var/lib/grafana \
 && chmod -R u=rwX,go= /var/lib/grafana

ENV GF_PATHS_CONFIG=/etc/grafana/grafana.ini \
    GF_PATHS_DATA=/var/lib/grafana \
    GF_PATHS_PLUGINS=/var/lib/grafana/plugins \
    GF_PATHS_PROVISIONING=/etc/grafana/provisioning \
    GF_INSTALL_PLUGINS=""

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/render-dashboards"]
