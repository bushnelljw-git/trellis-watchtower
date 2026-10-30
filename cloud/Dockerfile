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
# fetched is pinned by its hash: Grafana's source by its commit, its Go modules by its own go.sum and go.work.sum (the
# two raised below by the go.sum lines pinned there), and the Alpine packages by their sha256. No build argument and
# no secret.

# --- Grafana 12.4.14, as Grafana built it ---------------------------------------------------------------------------
#
# The image itself, its frontend, plugins and everything else, except the three Go binaries rebuilt below.
FROM grafana/grafana:12.4.14@sha256:ae509d9ae8c1021ca32ec370a9ca975d40165eda9fccd1e1102d317ff8787cd7 AS grafana

# --- Grafana's Go binaries, rebuilt with Go 1.26.10 and go-jose v4.1.6 ----------------------------------------------
#
# The official 12.4.14 image's grafana, grafana-server and grafana-cli carry github.com/go-jose/go-jose/v4 v4.1.4, which
# Container Scanning reports as HIGH (tpa-platform's build ef0194fb, 2026-10-29, on trellis-watchtower f6f79cb with
# Grafana 12.4.12; fixed in v4.1.6, the floor the deploy skill sets for every image). No Grafana 12.x release has the
# fix (12.4.12, 12.4.13 and 12.4.14 all pin v4.1.4; 13.3.0 and main pin v4.1.6, but are Go 1.27 and a new major). So
# the three are rebuilt here from Grafana's own v12.4.14 source, the way Grafana's release build makes them (`make
# build-go`: CGO off, -trimpath, -buildvcs=false, its -X stamps), with go-jose raised to v4.1.6, and copied over the
# official ones. The Go is 1.26.10, the same as 12.4.14's official binaries (12.4.12's were 1.26.6, and 12.4.13's 1.26.9,
# which is why this rebuild began: Go's standard library findings of 2026-10-12, then kin-openapi v0.147.0 of
# 2026-10-24; 12.4.14 itself has kin-openapi v0.151.0 and jsonschema/v6 v6.0.3, so neither is raised any more).
#
# The source: BuildKit fetches the v12.4.14 tag and refuses it unless it is commit 3c98af3b..., the public release
# commit (git ls-remote: refs/tags/v12.4.14^{}). Grafana's official binaries report the commit of its private mirror's
# release-12.4.14#patched branch (500a5450), so these are stamped with the public commit they were built from, and the
# build stamp is that commit's own time (2026-10-27T11:18:55Z).
#
# The modules: GOFLAGS=-mod=readonly, so every module is the version Grafana's go.mod and go.work name (but go-jose),
# and each download is checked against go.sum and go.work.sum at that commit and the two lines pinned below; nothing
# else may add or change one. The RUN then requires each rebuilt binary's module list and build settings (`go version
# -m`, all but its first line, which names the file and its Go) to be the official binary's exactly, but for go-jose's
# one line, so the only differences are the Go patch level (none today), the stamps and that module. The module and
# build caches (some 3 GB and 5 GB) are emptied in the same RUN, so the stage keeps only the three binaries.
#
# grafana/tempo (two HIGH findings, CVE-2026-21728 and CVE-2026-28377) stays: Grafana pins it at one main-branch
# commit of 2026-04-27, in every release through 13.3.0, and its fixes are already in that commit; see
# security/scan-exceptions.yaml.
FROM scratch AS grafana-source
ADD --checksum=3c98af3ba0773ad12a8a54b1faec7dc62d8d6725 https://github.com/grafana/grafana.git#v12.4.14 /

FROM golang:1.26.10-alpine3.24@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS grafana-build
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org
COPY --from=grafana-source / /w/grafana/
COPY --from=grafana /usr/share/grafana/bin/ /w/official/
WORKDIR /w/grafana
RUN set -eu; \
    test "$(go env GOVERSION)" = "go1.26.10"; \
    go mod edit -require=github.com/go-jose/go-jose/v4@v4.1.6; \
    printf '%s\n' \
      'github.com/go-jose/go-jose/v4 v4.1.6 h1:sNRkftxFJxwsILiQukqp5z83QBSmntVwmgRY7AqBDO4=' \
      'github.com/go-jose/go-jose/v4 v4.1.6/go.mod h1:x4oUasVrzR7071A4TnHLGSPpNOm2a21K9Kf04k1rs08=' \
      >> go.sum; \
    stamps="-X main.version=12.4.14 -X main.commit=3c98af3ba0773ad12a8a54b1faec7dc62d8d6725"; \
    stamps="$stamps -X main.buildBranch=v12.4.14 -X main.buildstamp=1793099935"; \
    for cmd in grafana grafana-server grafana-cli; do \
      go build -buildvcs=false -trimpath -ldflags "$stamps" -o "/out/$cmd" "./pkg/cmd/$cmd"; \
      test "$(go version "/out/$cmd")" = "/out/$cmd: go1.26.10"; \
      go version -m "/w/official/$cmd" | sed 1d | awk -F '\t' -v OFS='\t' ' \
        $3 == "github.com/go-jose/go-jose/v4" && $4 == "v4.1.4" { \
          $4 = "v4.1.6"; $5 = "h1:sNRkftxFJxwsILiQukqp5z83QBSmntVwmgRY7AqBDO4=" }; \
        { print }' > "/w/$cmd.official"; \
      go version -m "/out/$cmd" | sed 1d > "/w/$cmd.rebuilt"; \
      grep -qxF "$(printf '\tbuild\tCGO_ENABLED=0')" "/w/$cmd.rebuilt"; \
      cmp "/w/$cmd.official" "/w/$cmd.rebuilt"; \
    done; \
    test "$(/out/grafana -v)" = "grafana version 12.4.14"; \
    go clean -cache -modcache; \
    chmod 0555 /out/grafana /out/grafana-server /out/grafana-cli; \
    echo "grafana, grafana-server, grafana-cli: 12.4.14 (3c98af3b), go1.26.10, the official module list but" \
      "go-jose v4.1.6, checked"

# --- curl 8.23.0-r0, zlib 1.3.2-r1, musl 1.2.6-r3, brotli 1.2.1-r0 ------------------------------------------------------------------
#
# curl: tpa-platform's build ef0194fb (2026-10-29, trellis-watchtower f6f79cb, Grafana 12.4.12 on Alpine 3.24.2) was
# refused with 24 findings in curl (package curl, which also covers libcurl): 2 CRITICAL, 6 HIGH and 16 with no severity
# yet, all fixed in curl 8.23.0-r0 (Alpine 3.24 main). Grafana 12.4.14's own base is Alpine 3.24.3 and already ships
# curl and libcurl 8.23.0-r0, musl r3, zlib r1 and brotli-libs 1.2.1-r0, so the install below changes nothing in it
# today. It stays as the guard: the RUN requires exactly these versions of the four origins, so a base that regresses
# (or a Grafana release that falls behind Alpine again) fails this build here, not in Cloud Build.
#
# Before 12.4.14: the base's Alpine 3.24.2 had zlib 1.3.2-r0, and Container Scanning reports CVE-2026-85091 (HIGH) in it, fixed in
# 1.3.2-r1 (in Alpine 3.24's main repository since 2026-10-07; no Alpine or Grafana image carries it yet). The base
# keeps zlib for curl and apk. tpa-platform's build b5453d1f (2026-10-24, trellis-watchtower fe9302a) found two more,
# each with no severity yet, which its policy refuses as it refuses a CRITICAL: CVE-2026-107891 in musl 1.2.6-r2
# (packages musl and musl-utils), fixed in 1.2.6-r3 (Alpine 3.24 main, 2026-10-21), and CVE-2026-111497 in brotli
# 1.2.0-r1 (package brotli-libs, which libcurl links), fixed in 1.2.1-r0 (2026-10-22). Container Scanning names each by
# its origin, as /lib/apk/db/installed records it. Both architectures' packages, by sha256, from Alpine's own
# repository; the RUN below installs this machine's with no repository and no network (apk still checks each
# package's own signature against the base's Alpine keys), then requires every installed package of the three origins
# to be exactly the fixed one (curl and libcurl for the origin curl). The stage keeps its name, zlib: tpa-platform's start check
# (scripts/image_start_check.sh) holds this Dockerfile to exactly these five stages, by name.
FROM scratch AS zlib
ADD --checksum=sha256:63aeea03c15a2f9018f81805cfc8aa926bdf5cd68921f22149c2fbb5d0ee9f47 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/zlib-1.3.2-r1.apk /x86_64/zlib-1.3.2-r1.apk
ADD --checksum=sha256:1f77a542ac6634761b9fe38d8bdca19b154071dcfa25432e73f2bc8a0740a33f \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/zlib-1.3.2-r1.apk /aarch64/zlib-1.3.2-r1.apk
ADD --checksum=sha256:e142255d0fa397f14318996bc10378093dcc069dc3dd1b6818c8f28a789c21da \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/musl-1.2.6-r3.apk /x86_64/musl-1.2.6-r3.apk
ADD --checksum=sha256:2e17864102278d9049c3a56f1bceed9e8cf287065617e579325123443daed8a5 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/musl-1.2.6-r3.apk /aarch64/musl-1.2.6-r3.apk
ADD --checksum=sha256:47263d05842c5e12d01e0369e5b5bea51733323501c00ca21968a5102de137ca \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/musl-utils-1.2.6-r3.apk /x86_64/musl-utils-1.2.6-r3.apk
ADD --checksum=sha256:bb460bdc009e88989bd5adca8a7c8298c339cba99da11c6196c818e042fbaf49 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/musl-utils-1.2.6-r3.apk /aarch64/musl-utils-1.2.6-r3.apk
ADD --checksum=sha256:62a7e37e43bbfc1f8525a00ad2125fd5897135dc93b849733884cb78ffd8e26c \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/brotli-libs-1.2.1-r0.apk /x86_64/brotli-libs-1.2.1-r0.apk
ADD --checksum=sha256:f802b9d5a329c216f02e73607cb8f662c434767e41686367ac0afcf6d0d45d64 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/brotli-libs-1.2.1-r0.apk /aarch64/brotli-libs-1.2.1-r0.apk
ADD --checksum=sha256:531ae298451a4c1c44f563fc3b2eedc2c1d7e0a26a33bdfc0efe6faaff6a5942 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/curl-8.23.0-r0.apk /x86_64/curl-8.23.0-r0.apk
ADD --checksum=sha256:3748c544ab475033cb028e415858b8a671ca7d43756e0149732c860588882ced \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/curl-8.23.0-r0.apk /aarch64/curl-8.23.0-r0.apk
ADD --checksum=sha256:1f70ca404818805a6465b615bbfe84ef861488a963d7e630108ebd7fbaa51665 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libcurl-8.23.0-r0.apk /x86_64/libcurl-8.23.0-r0.apk
ADD --checksum=sha256:64ae89f6e5d318ed5209778232191806ce49644ce9e09540b7d7830a5330d127 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libcurl-8.23.0-r0.apk /aarch64/libcurl-8.23.0-r0.apk

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
RUN --mount=type=bind,from=zlib,target=/mnt/apk \
    set -eu; \
    arch="$(apk --print-arch)"; \
    apk --repositories-file=/dev/null add --no-cache "/mnt/apk/$arch/zlib-1.3.2-r1.apk" \
      "/mnt/apk/$arch/musl-1.2.6-r3.apk" "/mnt/apk/$arch/musl-utils-1.2.6-r3.apk" \
      "/mnt/apk/$arch/brotli-libs-1.2.1-r0.apk" "/mnt/apk/$arch/curl-8.23.0-r0.apk" \
      "/mnt/apk/$arch/libcurl-8.23.0-r0.apk"; \
    test "$(awk -F: '/^P:/ { p = $2 }; /^V:/ { v = $2 }; /^o:(brotli|curl|musl|zlib)$/ { print p "-" v }' \
      /lib/apk/db/installed | sort | tr '\n' ' ')" \
      = "brotli-libs-1.2.1-r0 curl-8.23.0-r0 libcurl-8.23.0-r0 musl-1.2.6-r3 musl-utils-1.2.6-r3 zlib-1.3.2-r1 "
COPY --from=grafana-build /out/grafana /out/grafana-server /out/grafana-cli /usr/share/grafana/bin/
COPY grafana.ini /etc/grafana/grafana.ini
COPY iap_keys.json /etc/grafana/iap_keys.json
COPY provisioning/ /etc/grafana/provisioning/
COPY dashboards/*.json /etc/grafana/dashboards/
COPY dashboards/no-cc/*.json /etc/grafana/dashboards/no-cc/
COPY dashboards/production/*.json /etc/grafana/dashboards/production/
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
