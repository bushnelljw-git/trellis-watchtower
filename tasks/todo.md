# trellis-watchtower: build tasks
The spec is [docs/SPEC.md](../docs/SPEC.md). Owner-gated items are listed at the end of the spec and are not done here.

- [x] W0 Clone watchtower; rename the remote `upstream` and disable pushes to it; stop tracking `.env`; delete the BodyF1rst production and legacy files. gitleaks found 3 false alarms and no real secrets.
- [x] W0 Add the repo to ~/Documents/bodyfirst.code-workspace.
- [x] Phase 0 Left a note for the Member Ask session: trellis `tasks/member-assist/FROM-WATCHTOWER-SESSION-2026-09-24-model-gateway-body-logs.md`.
- [x] W1 Local metrics: compose, blackbox, Prometheus with rules (and rule unit tests), two postgres exporters, a GET-only socket proxy, a Makefile with a disk guard, `.env.example`. `tpa-net` is manual opt-in only.
- [x] W2 Local logs: Loki 3.7 with structured metadata, an Alloy allowlist plus a fail-closed scrub, fixtures, `scrub_check` (36 assertions), `stub_test`.
- [x] W3 11 dashboards (overview is home; errors; staleness for connectors, drains, auth-publisher, auth-sweeper), `dashboard_lint` plus a test, `docs/SIGNALS.md`, README.
- [x] F `scripts/fly-uptime-checks.sh` written. Dry run checked; `--apply` tested against a fake gcloud. **Not run** (needs the owner's OK, a Slack channel id, email and phone).
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
  - The projects' owner runs `gcp_channels.py --apply` during the setup runbook, before the PHI perimeter is enforced,
    and fires one Monitoring test in the app and cc projects only (step 5). tpa-platform takes `alert_pagerduty_channel_ids` once its
    `beta-alert-gaps` work lands.
  - After the test page reaches the owner's phone, tpa-platform sets `alert_sms_number = null`.
- [x] CD (2026-10-11, the owner: hosted dashboard "Yes, everything") the cloud dashboards, branch `cloud-dashboards`:
  - [x] Vendored tpa-platform's `infra/monitoring.yml` (beta-alert-gaps `45665a27`, blob `3e888f44`) into
    `cloud/catalogue/`; `scripts/vendor_catalogue.sh` re-vendors from committed objects only and checks drift.
  - [x] Datasources: a fourth, `cloud-cc`; every one also sets `gceDefaultProject`. Without it, Grafana under `gce`
    auth ignores `defaultProject`, and all four would have read the app project. That was a latent bug in the
    three-datasource version.
  - [x] Project ids into the queries: Grafana drops a Cloud Monitoring query with no `projectName`, so the image's
    entrypoint, `cloud/render-dashboards.sh`, fills each query's placeholder from the environment at start.
  - [x] Nine dashboards (overview home, five areas, errors, databases, jobs; 153 panels, 199 queries), generated by
    `scripts/cloud_dashboards.py`. They use the filter form, not PromQL (see the review below).
  - [x] Lint: the cloud rules below (the filter form, labels, operators, one datasource per panel, placeholders, no
    variables, exactly the four uids). 16 bad cases and one good fixture.
  - [x] Tests: `tests/cloud`, 16 tests. They cover every metric (in the catalogue, per project, aligner fits its
    kind), labels per metric and resource, names per project, names agree with the catalogue, every catalogue
    metric charted, PHI on `cloud-phi` alone, and the render script. Each is mutation-checked.
  - [x] Image: `make cloud-image-check`. The image builds and runs with no network. 4 datasources and 9 dashboards
    are provisioned, and it answers 401 without IAP. All 199 queries reach Cloud Monitoring for their own project.
    Screenshots show every panel's query is sent.
  - [x] Docs: cloud/README, SPEC owner decision, SIGNALS cloud rows, README. `make check` green.

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
  - supply FLY_ORG and a read-only Fly token;
  - OK the Fly script run in `bodyf1rst-prod`;
  - OK a GitHub remote and the commits.
