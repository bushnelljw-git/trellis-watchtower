# trellis-watchtower: build tasks
The spec is [docs/SPEC.md](../docs/SPEC.md). Owner-gated items are listed at the end of the spec and are not done here.

- [x] W0 Clone watchtower; rename the remote `upstream` and disable pushes to it; stop tracking `.env`; delete the BodyF1rst production and legacy files. gitleaks found 3 false alarms and no real secrets.
- [x] W0 Add the repo to ~/Documents/bodyfirst.code-workspace.
- [x] Phase 0 Left a note for the Member Ask session: trellis `tasks/member-assist/FROM-WATCHTOWER-SESSION-2026-09-24-model-gateway-body-logs.md`.
- [x] W1 Local metrics: compose, blackbox, Prometheus with rules (and rule unit tests), two postgres exporters, a GET-only socket proxy, a Makefile with a disk guard, `.env.example`. `tpa-net` is manual opt-in only.
- [x] W2 Local logs: Loki 3.7 with structured metadata, an Alloy allowlist plus a fail-closed scrub, fixtures, `scrub_check` (36 assertions), `stub_test`.
- [x] W3 11 dashboards (overview is home; errors; staleness for connectors, drains, auth-publisher, auth-sweeper), `dashboard_lint` plus a test, `docs/SIGNALS.md`, README.
- [x] F Dropped: no Fly systems (owner, 2026-10-11). `scripts/fly-uptime-checks.sh` was written and never run; it is removed (see NF below).
- [x] P1 tpa-platform `infra/modules/monitoring` + `infra/monitoring.yml` in both environments, D-65, `docs/infra/monitoring.md`, shape and golden-line tests. Written, not applied.
- [x] P2 `ing-monitoring` is the perimeter's fifth ingress rule in both environments. Written, not applied.
- [x] P3 `cloud/` builds and runs with `--network none` (datasources provisioned; 401 without an IAP assertion). The tpa-platform half is the class 3 request (needs the owner).
- [x] S trellis-security: 10 request files (1 class 3 needing the owner); SECURITY-BAR gets an "Operational monitoring" bullet (provisional until P1 lands); proposed findings go inside the requests; [docs/REQUESTS.md](../docs/REQUESTS.md) covers network, forge and enroll.
- [x] Review: see below.
- [x] PD (2026-10-11, the owner: "i want everything set up very well with it") PagerDuty as code, in [docs/PAGERDUTY.md](../docs/PAGERDUTY.md):
  - `scripts/pagerduty/pd_setup.py` is **applied live**: the team, the schedule, the escalation policy, three "TPA beta ·" services (each with an integration and an orchestration), the business service, and the notification rules. Re-runs show 0 to create and 0 to update.
  - `pd_test_event.py`: four live test events, all as designed (3× Warning → low/warning/P3, 1× Critical → high/critical/P1), each resolved within 11 s.
  - `gcp_channels.py`: written and tested. The dry run is checked (Google answers 403 to the owner's account). **Not applied.**
  - `tests/pagerduty` (local fakes, in `make check`).
- [x] PD review fixes (2026-10-11):
  - The severity rules ignore letter case: `matches regex '(?i)^ *Word *$'`. PagerDuty refuses `\s` in a condition.
    Live re-test: lower-case `warning` → low/warning/P3 and `critical` → high/critical/P1.
  - Grouping moved to `/alert_grouping_settings`.
  - A rule a person removed is no longer put back (`--add-rules` puts it back on request).
  - The script refuses a schedule with more than one layer and a renamed duplicate service, and stops when a parent
    object is refused.
  - `gcp_channels.py`: a refused project prints null and the run continues; an "unknown" key is re-sent only on
    `--rekey`.
  - No redirects; the token is never passed to child processes. 49 tests.
- [x] PD re-review fixes (2026-10-11):
  - The rules are `(?i)^[[:space:]]*Word[[:space:]]*$`. PagerDuty accepted it; live `warning` → low/P3.
  - A plain `--apply` never creates a notification rule (only `--add-rules` does).
  - Step 5's test policy runs in the app and cc projects only, never PHI (D-137). Create and delete are in one
    snippet.
  - The intelligent-grouping fallback keys on "intelligent".
  - A missing service is refused while any service carries our integration under an undesigned name.
  - 52 tests.
- [ ] PD, by people (docs/PAGERDUTY.md):
  - Connect the three services to Slack #tpa-beta-alerts.
  - The owner installs the app and adds a phone, then re-runs `pd_setup.py --apply` and sends a test page.
  - Rafeale accepts his invitation.
  - Once tpa-platform's `beta-alert-gaps` work lands: `alert_pagerduty_enabled = true` and the first apply through
    `tf_with_keys.py`; then the test page (`alert_pagerduty_test_enabled`, app and cc only, never PHI), on for one
    apply and off in the next (docs/PAGERDUTY.md, "The Google Cloud half").
  - After a PagerDuty page reaches the owner's phone, tpa-platform sets `alert_sms_number = null`.
- [x] PD Terraform keys (2026-10-11, the owner: "all changes must be done to terraform … never modify the project
  directly"; Ruling K), branch `pagerduty-tf-keys`:
  - `gcp_channels.py` and its tests removed: it made the channels by API.
  - `scripts/pagerduty/tf_with_keys.py` reads the three integration keys and runs one `terraform plan|apply` with
    `TF_VAR_pagerduty_service_keys` in the child's environment only. It refuses other commands, `-out`, `TF_LOG*` and
    another environment's root, and stops before Terraform if a key is missing. `--env` picks the service names.
  - docs/PAGERDUTY.md's Google Cloud half rewritten for Terraform. Tests: `tests/pagerduty/test_tf_with_keys.py`.
- [x] PD titles (2026-10-13, the owner: "Arent all of these messages supposed to be formatted better?"), branch
  `pd-titles` (docs/PAGERDUTY.md, "Incident titles"):
  - Each service orchestration's `start` set titles the incident with the policy's `documentation.subject` (not
    Monitoring's `[ALERT - …]` default), else "policy · condition", else Monitoring's summary. It copies
    `what_to_check`, `console`, `observed` and `threshold` from the payload into the details, then routes to the
    `severity` set: the three severity rules, unchanged. The dedup key is untouched.
  - The plan lists an orchestration update rule by rule. `pd_test_event.py` checks the title (`--monitoring-subject`
    for the fallback). The fake models nested sets, variables and extractions. 70 tests; 6 mutants killed.
  - `make pagerduty-plan` (live, read only): 3 to update, the orchestrations only.
- [ ] PD titles, by the orchestrator: `pd_setup.py --apply`, then the two live test events (docs/PAGERDUTY.md,
  "Verified live").
- [x] CD (2026-10-11, the owner: hosted dashboard "Yes, everything") the cloud dashboards, branch `cloud-dashboards`:
  - [x] Vendored tpa-platform's `infra/monitoring.yml` (beta-alert-gaps `d88305db`, blob `3e19a7d0`, D-141 included) into
    `cloud/catalogue/`; `scripts/vendor_catalogue.sh` re-vendors from committed objects only and checks drift.
  - [x] Datasources: a fourth, `cloud-cc`; every one also sets `gceDefaultProject`. Without it, Grafana under `gce`
    auth ignores `defaultProject`, and all four would have read the app project. That was a latent bug in the
    three-datasource version.
  - [x] Project ids into the queries: Grafana drops a Cloud Monitoring query with no `projectName`, so the image's
    entrypoint, `cloud/render-dashboards.sh`, fills each query's placeholder from the environment at start.
  - [x] Nine dashboards (overview home, five areas, errors, databases, jobs; 153 panels, 200 queries), generated by
    `scripts/cloud_dashboards.py`. They use the filter form, not PromQL (see the review below).
  - [x] Lint: the cloud rules below (the filter form, labels, operators, one datasource per panel, placeholders, no
    variables, exactly the four uids). 16 bad cases and one good fixture.
  - [x] Tests: `tests/cloud`, 16 tests. They cover every metric (in the catalogue, per project, aligner fits its
    kind), labels per metric and resource, names per project, names agree with the catalogue, every catalogue
    metric charted, PHI on `cloud-phi` alone, and the render script. Each is mutation-checked.
  - [x] Image: `make cloud-image-check`. The image builds and runs with no network. 4 datasources and 9 dashboards
    are provisioned, and it answers 401 without IAP. All 200 queries reach Cloud Monitoring for their own project.
    Screenshots show every panel's query is sent.
  - [x] Docs: cloud/README, SPEC owner decision, SIGNALS cloud rows, README. `make check` green.

- [x] CR (2026-10-11) the coordinator's review of `cloud-dashboards` @ cfbc3a7, in new commits:
  - [x] 1 What a viewer can read: any signed-in viewer can post their own query to `/api/ds/query` (shown by the image
    check on every run). Grafana 12.4.11 has no setting that limits a datasource to its saved panels (checked:
    defaults.ini, the binary's toggles; per-datasource query permissions are Enterprise's). The lint's and README's
    wording now says so, and the README lists what tpa-platform sets to bound it: the IAP host under
    `ing-monitoring`'s access level, a `monitoring.timeSeries.list`-only custom role (a signed-in browser made no
    resource call), on the four projects alone. Explore and query history are off as well.
  - [x] 2 `TPA_PAUSED_JOBS`, `TPA_STOPPED_DATABASES` (and `TPA_ENVIRONMENT`): render-time tokens turn the affected
    tiles neutral "paused" / "database stopped". Unknown names are refused; 16 render tests. Pixels checked.
  - [x] 3 Deadline windows are the deadline plus 3 minutes.
  - [x] 4 CRM errors by service only while its class extractor is unanchored; the test allows the class (and the
    generator adds it) when the vendored catalogue anchors it.
  - [x] 5 Lint: a reducer, primary and secondary, present and not REDUCE_NONE; no bare `__field.labels`. Mutation tests
    on a real page.
  - [x] 6 Cloud Run p95 merged (ALIGN_DELTA + REDUCE_PERCENTILE_95); the Dockerfile's baked files root's and
    read-only; a signed-token Viewer pass in the image check; production-full without the call centre, and the uptime
    wording per environment.
  - [x] The catalogue stays pinned to tpa-platform's `beta-alert-gaps` branch (now `64a144b9`; its two newest moves
    changed comments only). **Re-vendor from tpa-platform master when that branch lands**:
    `scripts/vendor_catalogue.sh --check ../tpa-platform origin/master`, then without `--check`, then `make lint`.

- [x] CR2 (2026-10-11) the re-review of `cloud-dashboards` @ c4abcc6: production refuses `TPA_PAUSED_JOBS` and
  `TPA_STOPPED_DATABASES` (render test, and the image check starts production with one set); the scratch directory is
  removed before `exec /run.sh` (the image check finds nothing in /tmp); the tpa-platform asks are filed in
  docs/REQUESTS.md §4 (the role, its projects, the access level, `ing-watch`, the environment, Query Insights).
  - [ ] For the orchestrating session: carry §4 into trellis-security's hosted-grafana request file, whose status
    still reads "refused (for now)" from D-92.

- [x] IMG (2026-10-11, for the orchestrating session) the cloud image made acceptable to tpa-platform's shared builder
  (D-145; its `watchtower` row is held until this lands), branch `image-10001`:
  - [x] `cloud/Dockerfile` runs as `10001:10001`. It writes `/var/lib/grafana` (10001's own, 700: sqlite, plugins,
    the rendered dashboards) and `/tmp` (the render's scratch) alone; the base's other world-writable folders are
    closed; config, provisioning, dashboards and entrypoint stay root's and read-only; the base stays pinned by digest.
  - [x] The shell question: the builder's no-shell check covers tpa-platform's Python images and `web` only. Its
    `watchtower` start check probes the image with `docker exec … wget`, so the base's busybox stays.
  - [x] `security/scan-exceptions.yaml`: `[]`, in the builder's format (accepted by its own `read_exceptions`).
  - [x] `make cloud-image-check`: the configured user, the digest pin, PID 1 as uid/gid 10001, the read-only files,
    nothing writable but `/var/lib/grafana` and `/tmp`, plus the existing signed-token Viewer pass and the 401s.
  - [x] tpa-platform's own `scripts/image_start_check.sh watchtower`, run on an unpacked `git archive` of the commit.
  - [x] The scan gate (2026-10-11, the coordinator's follow-up, ruled by delegation by bodyfirst-a9): the base moves
    to Grafana 12.4.12 (by digest), which fixes 12.4.11's OpenSSL (CVE-2026-14456) and apache/thrift (CVE-2026-43871)
    findings. A trivy scan of 12.4.12 (amd64 and arm64) finds no CRITICAL and six fixable HIGH pairs: Go stdlib 1.26.6
    (CVE-2026-78667, CVE-2026-78669, CVE-2026-97031), golang.org/x/net (CVE-2026-78669), grafana/tempo
    (CVE-2026-21728, CVE-2026-28377). Each is a dated exception in `security/scan-exceptions.yaml`, expiring
    2026-11-10 (the builder's `read_exceptions` accepts the file, and refuses it on 2026-11-11). Container Scanning's
    own findings and package names are first seen at the first build's policy step.
  - [x] IAP's keys pinned in the image (the tpa-platform reviewer's point): `cloud/iap_keys.json` (Google's set,
    fetched 2026-10-11, the same five kids as tpa-api's pin), `grafana.ini` reads it with `jwk_set_file` (no
    `jwk_set_url`, no `cache_ttl`), so the website needs no internet path. `scripts/refresh_iap_keys.sh` (fetch,
    check, diff; writes only with `--write`), `tests/cloud/test_iap_keys.py` (7 tests, mutation-checked), and the
    image check now uses the shipped `grafana.ini` unchanged, swapping only the baked key file for a throwaway set.
    Trade-off in cloud/README.md, "IAP's keys": a Google rotation breaks sign-in until a rebuild.
  - [x] `provisioning/datasources/cloud-monitoring.yml`'s comment: `tpaMetricsReader`, not `monitoring.viewer`.
  - [ ] For tpa-platform's lane: lift the hold, and drop the `www.gstatic.com` egress (`watch_key_egress_approved`,
    the `watch-run-egress` rule): the image no longer fetches anything.

- [x] IMG2 (2026-10-12, for the orchestrating session bodyfirst-a9) the cloud image through the builder's scan
  policy, branch `image-scan-clean`. tpa-platform's build 4122c0b2 of 3f7fc36 failed its policy step: Container
  Scanning names Go's standard library `go` (two CRITICAL, eight fixable HIGH, five with no severity, all fixed in Go
  1.26.9) and found zlib 1.3.2-r0 (CVE-2026-85091, HIGH); only the two Tempo entries matched.
  - [x] No Grafana release has a newer Go: 12.4.12, 12.4.12-ubuntu, 13.2.3, -ubuntu and -distroless are all Go
    1.26.6 (only `nightly` has 1.27.2). Grafana's release-12.4.13 and release-13.2.4 branches (cut 2026-10-12) are at Go
    1.26.9 and golang.org/x/net 0.60.0: when 12.4.13 is published, moving to it drops the rebuild below.
  - [x] Grafana's three Go binaries rebuilt in `cloud/Dockerfile` from the public v12.4.12 source (BuildKit refuses
    the tag unless it is commit 60d1cb95) with Go 1.26.9 (web's Caddy's `golang` image), as `make build-go` builds
    them; modules by Grafana's own go.sum and go.work.sum (`-mod=readonly`); each binary's module list and build
    settings must equal the official one's (`cmp`), and the caches are emptied in the same RUN.
  - [x] Proof the public source is what Grafana shipped (its release build is from its security mirror's
    `release-12.4.12#patched`): that commit with Go 1.26.6 and the official stamps rebuilds the official amd64
    grafana, grafana-server and grafana-cli byte for byte. With Go 1.26.9, the module lists equal the official
    ones on amd64 and arm64.
  - [x] zlib 1.3.2-r1 (Alpine 3.24 main, 2026-10-07; no image carries it yet) by sha256 per architecture, installed
    with no repository and no network; apk checks its signature, and a tampered copy is refused.
  - [x] `security/scan-exceptions.yaml`: the two Tempo HIGH alone, by Container Scanning's names, dated 2026-11-10;
    both matched by version only (Grafana's Tempo is main at 525d1bab of 2026-04-27, which contains both fix commits,
    650eb198 and bb8ca663, by GitHub's compare). The trivy-named stdlib and golang.org/x/net entries are gone.
  - [x] `make check` (with `tests/cloud/test_image_policy.py`, 8 tests, each pin mutation-checked); the image check
    now also reads each binary's Go (go1.26.9), the zlib version and the started commit; `make cloud-image-check`
    gets `build-guard` (6 GB of memory available and 12 GB of disk free in the Docker VM, or it refuses).
  - [x] Measured on this Mac: the compile is ~950 CPU-seconds (108 s on 12 cores, 295 s at GOMAXPROCS=2 -p 2); its
    peaks are aws-sdk-go-v2's ec2 package (3.0 GB) and the link (1.7 GB, 5.2 GB resident with mapped files). In a
    BuildKit v0.33.1 builder (build.sh's) capped at 2 GB and 4 CPUs, the source by commit, the modules over the
    bridge network and the zlib step all passed and the ec2 compile was killed by the cap, so the full build was
    not run in this Docker VM (7.8 GB, ~2.9 GB available, shared with the live stack). The image's stages were run
    with the same binaries built on the host: `scripts/cloud_image_check.sh` and tpa-platform's
    `image_start_check.sh watchtower` pass, and trivy 0.75.0 (amd64) goes from 27 findings over the policy to 6:
    Tempo's two, golang.org/x/net 0.58.0 (one HIGH, two unknown) and golang.org/x/crypto GO-2026-5932 (unknown, no
    fix), neither of which Container Scanning reported in 4122c0b2.
  - [ ] For tpa-platform's lane: the build step now compiles Grafana. web's Caddy took 380 s on the default machine
    (19 s here), so this step may take 20 to 40 minutes against its 2400 s limit; a larger machine for watchtower
    (e2-highcpu-8) or a longer step. Its start check (`image_start_check.sh`, plain `docker build`) compiles it in
    this Mac's Docker VM too, which has too little memory now.

- [x] NF (2026-10-11, the owner: "There will be NO systems in fly ONLY the gcp project") every Fly piece removed,
  branch `remove-fly`:
  - [x] `prometheus/targets/fly.yml` (the `fly` stack's two laptop probes), the Fly production dashboard, and the
    overview's `fly` row link.
  - [x] The `fly` Prometheus datasource: out of provisioning, and listed under `deleteDatasources` so a Grafana whose
    volume still holds it drops it. `FLY_ORG` and `FLY_PROM_TOKEN` out of `.env.example` and compose.
  - [x] `scripts/fly-uptime-checks.sh` (never run, so nothing in `bodyf1rst-prod` to remove). The lint allows
    `prometheus` and `loki` only.
  - [x] README, SPEC (phase F dropped, owner decision, naming rules), SIGNALS, REQUESTS, PAGERDUTY and the forge and
    errors dashboards' notes.

## Review

### 2026-10-11 (cloud dashboards)
- **The query language was changed after testing in the image.** The first version was PromQL. Posting each query to
  the image's backend showed two defects in Grafana 12.4.11's Cloud Monitoring datasource:
  - a PromQL query without a leftover `timeSeriesList` block is taken as a legacy query: the browser drops it and
    the backend crashes on it (nil pointer, `promql_query.go:23`);
  - a failed PromQL request comes back `200` with an empty frame, where the filter form returns the error and its
    URL. A failing PromQL panel would read "0".
  So every query is the filter form, which surfaces errors and is what the catalogue's threshold policies use.
- **Two latent bugs fixed.**
  - Under `gce` auth Grafana's browser reads `gceDefaultProject`, so the old datasources would all have read the app
    project.
  - Grafana drops a query with an empty `projectName`, which is why the image renders the ids in at start.
- **Pixels.** Headless screenshots of a localhost-only Viewer container showed every panel sends its query (each
  carries the credentials error). They also showed green "0" on failed panels and truncated titles. Both were fixed:
  no-value text is neutral, and the time-override labels are hidden.
- **Left for the tpa-platform lane:** `sa-watchtower` (`monitoring.viewer` on app, PHI, call centre), `ing-watch`
  for the PHI project's Monitoring, the Cloud Run service with the six environment variables, the IAP `watch` host.
  See cloud/README.md, "What tpa-platform's lane provides".
- **The catalogue test earned its keep:** the branch moved twice during the build; the second move (D-141) added
  `log_metric_changes`, and the coverage test failed until it was charted.
- **Re-vendor when beta-alert-gaps lands:** `scripts/vendor_catalogue.sh --check ../tpa-platform origin/master`.

### 2026-09-24 (evening)
- **Incident:** W1's first image pull (about 2 GB) took the nearly full Docker disk to 100% for about 4 minutes (01:42–01:46Z).
  - The :4310 stack saw records `DiskFull` errors and auth `PoolTimeout` errors.
  - `tpa-auth-publisher` exited (restart policy `no`) and is still Exited. Our `docker start` was refused as another session's workload.
  - We left a note for the records session, which owns the approved Docker restart: trellis `tasks/member-assist/FROM-WATCHTOWER-SESSION-2026-09-24-disk-full.md`.
  - Prevention: `make up` and `make check` refuse to run with less than 4 GB free.
- **Verified by the orchestrator:**
  - `make check` is green.
  - `make probe-check`: everything is up except forge (not running) and network `/tpa/health` (`database:false`, a real finding, in docs/REQUESTS.md).
  - `make scrub-check` is OK.
- **Lane C:** the monitoring module contains no IAM, and its labels are all on the allowlist. `terraform validate` and fmt pass on 1.9.8; `make check` passes; 39 new tests pass. Two bugs in other tpa-platform modules (`edge/main.tf:31`, `log-sink/main.tf:46`) would stop a first plan; they are recorded in tpa-platform `tasks/todo.md` P20 for its own session.
- **Final (orchestrator):**
  - `make check`: all green, including the dashboard lint (11 dashboards, 0 problems).
  - `make probe-check`: one red, network `/tpa/health` `database:false`, a real finding. forge is not running.
  - `make scrub-check`: OK.
  - Grafana's home is `tw-overview`; all 11 dashboards are in the `trellis-watchtower` folder.
  - Lane B: 120 of 130 panel queries return data. The other 10: 7 Fly panels (FLY_ORG and token not set), the tpa-net overlay panel (off), and 2 panels with nothing to show (no deliveries, no 5xx).
- **Open for the owner:**
  - rule on the hosted-Grafana class 3 request;
  - decide who may change production alerts (`monitoring.editor`/`admin`) and whether a compliance channel exists;
  - ~~supply FLY_ORG and a read-only Fly token;~~ ~~OK the Fly script run in `bodyf1rst-prod`;~~ dropped: no Fly
    systems (owner, 2026-10-11);
  - OK a GitHub remote and the commits.
