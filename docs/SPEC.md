# trellis-watchtower: spec

## Context
`watchtower` (~/Documents/code/watchtower) is the BodyF1rst app's monitoring repo.
- **Local:** Grafana, plus Prometheus with exporters, plus Loki/Promtail/Tempo, all on Docker.
- **Production:** one public Grafana on Cloud Run in `bodyf1rst-prod`, reading Google Cloud Monitoring.

The owner wants a copy, **trellis-watchtower**, that monitors every working repo: tpa-platform, auth-notary, records-service, feed-ingest, trellis, bodyf1rst-network, health-forge and bodyf1rst-enroll. The TPA stack isn't in GCP yet: its Terraform is in `tpa-platform/infra/`, no GCP organization exists, and nothing has been applied. trellis-security is reference documentation only.

The research found five constraints that shape the design:
1. **No service exposes metrics.** No `/metrics`, no OpenTelemetry, no tracing anywhere. The signals are health endpoints, JSON log lines, database tables, and Cloud Run, Cloud SQL and load-balancer platform metrics.
2. **The current watchtower's production setup breaks TPA hard rules.** It is public with anonymous viewers, uses the default service account, reads secrets at `latest`, uses tag images and deploys with `gcloud`. The binding gate would fail it.
3. **The PHI project's monitoring and logging APIs sit inside the VPC-SC perimeter.** Metrics scopes can't cross the perimeter. PHI-project alerts and log metrics must live in the PHI project.
4. **tpa-platform is the only place GCP monitoring can be applied from.** Its identity federation can't isolate a second repo. Its release canary reads the log metrics. Its vocab gate bans BodyF1rst and Fly names from its files.
5. **There's a live log-safety problem.** The running `tpa-model-gateway` container writes Anthropic request bodies (possible PHI) into its logs; its image predates fix `12c90f8`. Caddy logs full URLs with query strings. Several health endpoints return 200 while their database is down.

## Owner decisions (2026-09-24)
- **Alerts:** urgent ones (outage, security freeze, audit-chain break) go by **text to the owner's phone plus Slack and email**. Everything else goes to **Slack and email**.
- **Dashboards:** the **platform team** (`grp-platform`) can open the production dashboards.
- **Scope:** trellis-security is docs, not a monitored target.

## Design decisions (stated, not asked)
- **Clone with history** as asked. Rename `origin` to `upstream` with push disabled, and stop tracking `.env`. Put the new GitHub remote under `bushnelljw-git`, with the other TPA repos, created only on the owner's OK after a secret scan of history. The old watchtower is untouched and keeps watching BodyF1rst.
- **One pinned image per process.** This replaces the supervisord bundles, which hide crash loops.
- **Drop:**
  - Tempo (nothing emits traces);
  - node-exporter (on a Mac it measures the Docker VM);
  - the MySQL exporter (no MySQL);
  - cAdvisor (needs privileges and a host `/` mount);
  - the Slack-silence Cloud Function (Cloud Monitoring has snooze).
- **Replace** Promtail (end of life) with **Grafana Alloy**.
- **Upgrade** Grafana 11.4 to **12.x**.
- **Where things live:**
  - trellis-watchtower owns the local stack, all dashboards, the production Grafana image, Fly monitoring and the signal catalogue.
  - tpa-platform/infra owns every GCP resource in the TPA projects.
  - trellis-watchtower holds **no Terraform and no deploy identity**.
- **Production alerts live in Cloud Monitoring alert policies,** not Grafana alerting. They keep running when Grafana scales to zero, and this fixes the current watchtower's lost-silence problem. Grafana is stateless: dashboards only, provisioned from files.
- **Hosted Grafana sits behind IAP on a new `watch.${domain}` host, restricted to `grp-platform`.**
  - `edge.md` §6 excludes IAP because it would add a second identity to the cookie contract. Grafana is not on that contract, so this is a narrow, documented exception.
  - It is also the only way in that adds no fourth `allUsers` service.
- **Slack channel** is created by a person in the console and passed to Terraform by ID, so no Slack token enters Terraform state. **Email and text channels** are declared in Terraform, with the phone number and addresses in untracked tfvars.
- **Error tracking is built from the logs, not GlitchTip or Sentry.**
  - **Why not GlitchTip:** tpa-platform, records and auth-notary deliberately log only the exception's class. Records also logs the SQLSTATE and the constraint name. There is never a message and never a stack trace (`tpa_common/logging.py:222` `exception_facts`, `records/logging.py:292`, records `docs/04` §5.1–5.2: "never … a stack trace containing a row"). A Sentry-style tool is valuable only because it collects stack traces, local variables, request bodies and breadcrumbs, which is exactly what those rules ban. Stripped far enough to be safe, it would hold nothing the logs don't already hold, and it would still cost a new service, database, SDK in every repo, contract revision, and (if hosted) a vendor needing a BAA.
  - **Why not Google Error Reporting:** it needs stack traces for the same reason.
  - **What we build instead:** an **error group** is (service, exception class, operation or route, SQLSTATE). For each group we track a count, first seen and last seen, and the release. There is a **new-group** alert and a **spike** alert.
    - Locally: Loki with LogQL.
    - In the cloud: a log-based counter in each project, with those labels only.
  - **Prometheus alone can't do this.** It only stores numbers the services export, and they export none. Loki locally, and log metrics in the cloud, are what turn error lines into groups.
- **Fly production (network, portal, forge; enroll once it deploys):**
  - Uptime checks and alert policies go in the existing **`bodyf1rst-prod`** project, created by a script in trellis-watchtower. BodyF1rst names can't go in TPA projects, and the old watchtower's Slack wiring already lives there.
  - Local Grafana also reads Fly's hosted Prometheus with a read-only token.
  - forge is private, so it is covered by Fly metrics only.

## Spec: what trellis-watchtower watches

| Repo | Runs where | Local signals | Production signals |
|---|---|---|---|
| tpa-platform (web, tpa-api, tpa-jobs, connectors, model-gateway) | compose `tpa` → :4310; GCP app/phi (planned) | blackbox probes on `/health` and `/ready` (web 8240, tpa-api 8230, drains and connectors 8080 via the opt-in `tpa-net` overlay); scrubbed JSON logs | Cloud Run metrics; LB metrics; uptime checks on `/health` for the web, auth and api hosts; log metrics (request outcome, operation call, run summary, connectors pass counters); job execution status |
| auth-notary | compose `tpa` (auth 8210, outbox, publisher, sweeper) | `/ready` probe; scrubbed logs | Cloud Run and SQL metrics; log metrics for login 401/423, `not_ready` and `unhandled`; audit-verify job failure |
| records-service | compose `tpa` (8220) | `/ready` probe (database, revocations, JWKS); scrubbed logs | PHI project: log metrics for refusals by gate and code, `rate limited`, `audit flush failed`, `database unreachable`, mirror errors; chain-head and export job status |
| feed-ingest | host process, console :8099 | `/healthz` probe | none (it has no cloud deployment by design) |
| trellis | bundle in `web` | `/tpa/release.json` probe (shows the release id) | covered by the web uptime check |
| bodyf1rst-network | host :8100, network-db 5434; Fly | probe `/api/v1/health` with a body match on `"database": true`; postgres_exporter; Fly datasource | Fly uptime checks with body match (bodyf1rst-prod); later GCP `crm` project metrics |
| health-forge | host :8000, forge-db 5433; Fly (private) | body-match probe; postgres_exporter; Fly datasource | Fly metrics only |
| bodyf1rst-enroll | host :8400 (not deployed) | body-match probe (`"db": true`) | added when it deploys |

**Rules the implementation must keep:**
- **No PHI anywhere in monitoring.**
  - Log shipping uses an allowlist of compose services; nothing is shipped by default.
  - Never ship `model-gateway`, `dev-vendor-sink` (it carries sign-in codes), databases, MinIO or gotenberg.
  - Drop DEBUG lines and the `anthropic`, `httpx` and `httpcore` loggers.
  - Cut query strings from Caddy `request.uri`, and drop Caddy headers.
- **Metric and log labels** come from a closed allowlist: `operation`, `gate`, `code`/`outcome`, status class, `job`, `lane`. Never `tid`, `tenant`, `request_id`, row ids or a raw `requestUrl`.
- **No database login for monitoring on tpa-db or auth-db, ever.** postgres_exporter covers network-db and forge-db only, using their existing dev credentials from `.env`.
- **Local stack placement:** every port binds to 127.0.0.1 in the free block **4390–4394**. Grafana 4390, Prometheus 4391, Loki 4392, Alloy UI 4393; 4394 is spare. Compose project `trellis-watchtower`, containers `tw-*`, its own network. It never touches the :4310 stack's containers.
- **Docker access** goes through a socket proxy that allows GET on containers only.
- **Production:** images by `@sha256:`; secrets pinned to a version; no `allUsers`; no default service accounts; no `google_*_iam_member`.

**Alert catalogue (production), sourced from the TPA docs:**
- **Missed run:**
  - Jobs that run every 15 minutes or hourly: an absence condition at 1.5× their cadence.
  - Daily jobs: a PromQL condition.
  - The monthly audit verify: alert on failed execution plus a Cloud Scheduler failure log metric.
- **Job failures:** failed or partial tenants, and a drain tick that raised.
- **connectors:** any dead letter; any destination refused; any unsigned envelope; delivery lag over 5 minutes.
- **auth:** sign-in text (`messages_outbox`) lag over 30 s for 2 minutes; lockout (423) rate; `unhandled`.
- **Release canary:** 5xx over 0.1%; p95 latency; startup failures; Cloud SQL connection errors.
- **Audit chain:** `verify` exit 1, or `BREAK`. **Urgent.**
- **Perimeter:** dry-run violations.
- **Outage:** a failed uptime check on web, auth or api. **Urgent.**
- **Errors:**
  - A **new error group**: seen in the last hour, absent for the 7 days before. Sent to Slack and email.
  - A **spike**: a group's hourly count more than 5× its 7-day hourly average and more than 10. Sent to Slack and email.
  - Any error group from **records** or **auth** marked urgent by the catalogue: `audit flush failed`, `database unreachable`. **Urgent.**

## Plan (phases; execute with Opus subagent lanes, at most 3 at once)

**Phase 0: hand-off (before any log shipper runs).** Write a note for the Member Ask session in `trellis/tasks/member-assist/`: `tpa-model-gateway` runs a pre-`12c90f8` image that logs request bodies, and the rebuild is theirs. Alloy's exclusion is the second layer, not the fix.

**W0: create the repo** (~/Documents/code/trellis-watchtower)
- `git clone` watchtower.
- Rename the remote (`upstream`, push disabled) and `git rm --cached .env`.
- Run gitleaks over all 50 commits.
- Delete the BodyF1rst production and legacy pieces:
  - `Dockerfile`, `cloudbuild.yaml`, `docker-compose.prod.yml`, `functions/`;
  - `grafana/provisioning-prod/`, `grafana/grafana-prod.ini`;
  - `metrics/`, `logs-traces/`, `tempo/`, `promtail/`, `alertmanager/`;
  - the old rules, the Laravel, Next.js, MySQL and coaches dashboards, and `scripts/*.sh` (`setup.sh` reads the BodyF1rst MySQL secret).
- Add `docs/SPEC.md` (the spec above) and `tasks/todo.md` (this plan, with checkboxes).

**W1: local metrics**
- **`compose.yml`:** grafana, prometheus, blackbox, socket-proxy and alloy; loki; profile `db` adds postgres_exporter. Every image pinned by digest.
- **`compose.tpa-net.yml`:** a **manual** opt-in only (`make up TPA_NET=1`). While `tw-blackbox` is attached, a peer's `docker compose down` fails to remove `tpa-net`, and peers chain `make down && …`. By default, connectors and drains are watched from Loki (time since the last pass line or run summary).
- **`blackbox/blackbox.yml`:** `http_json_db_ok` (body match), `http_ready`, and a TLS probe for 4310.
- **`prometheus/prometheus.yml` and `prometheus/rules/*.yml`:**
  - rules: probe down, body mismatch, database down;
  - the `stack` label covers `tpa`, `network`, `forge`, `enroll` and `feed-ingest`, so a stack that isn't running reads as "not running", not as an outage.
- **`Makefile`:** `up`, `down`, `check`, `probe-check`, `scrub-check`.
- **`.env.example`:** database DSNs and `FLY_PROM_TOKEN`.

**W2: local logs**
- **`alloy/config.alloy`:** allowlist by the `com.docker.compose.project`/`service` labels, plus the drops and strips listed under the rules above.
- **Host-process logs** (network, forge, enroll, feed-ingest) stay out until each is shown clean.
- **Tests:**
  - `tests/fixtures/logs/*.jsonl`, including a body-bearing model-gateway line, a Caddy line with `?q=`, and a DEBUG httpx line;
  - `scripts/scrub_check.sh` (a LogQL query for `json_data|Request options|\?[A-Za-z_]+=|"tid"|Cookie` that must return zero);
  - `scripts/dashboard_lint.py` (rejects `requestUrl`, `uri` and id labels in any panel).

**W3: dashboards and signal catalogue**
- **`grafana/dashboards/`:** stack overview (the home page), TPA edge + API, auth, records, jobs + connectors, feed-ingest, CRM (network), forge, enroll, Fly production.
- **Errors dashboard** (over Loki, JSON lines at `level=ERROR`, grouped by `service`, `class`, `operation`/`route` and `sqlstate`):
  - a table of each group with count, first seen, last seen and release;
  - a "new in the last 24 h" panel using LogQL `unless … offset 24h`;
  - a trend per service.
  - network, forge and enroll join once their host logs are shown clean (W2).
- **Fly datasource:** Fly's hosted Prometheus, token from `.env`.
- **`docs/SIGNALS.md`:** each signal, its source, what red means, and who fixes it.
- **README rewrite.**

**F: Fly production paging** (running it needs the owner's OK)
- `scripts/fly-uptime-checks.sh`: idempotent `gcloud` against `bodyf1rst-prod`. It creates body-match uptime checks for `bodyf1rst-network` and `bodyf1rst-portal`, alert policies, and email, text and Slack channels.
- It sits alongside the old watchtower's existing checks and doesn't touch them.

**P1: TPA monitoring as code** (in tpa-platform; written and tested, **not applied**)
- **Lane setup:** the lane loads the `trellis-security:tpa-platform` skill first and works on master in place.
- **`infra/modules/monitoring/`**, one project per call:
  - log-based counter metrics with allowlisted label extractors;
  - alert policies;
  - email and SMS channels, plus the Slack channel by ID;
  - uptime checks;
  - validations that refuse labels outside the allowlist, channel types with sensitive labels, and PHI as a monitored project.
- **`infra/envs/{staging,production}/main.tf`:**
  - add `monitoring_app`, `monitoring_phi` and `monitoring_crm` in both environments (parity);
  - a metrics scope of app ← crm only;
  - uptime checks in the app project, with US regions.
- **Variables and tfvars example:** a deadline per schedule, alert email addresses and the phone number.
- **Docs:**
  - new `docs/infra/monitoring.md` (the metric catalogue);
  - `projects-and-iam.md`, `pipeline.md` §5.1 (canary metric names), `DECISIONS.md`, `tasks/todo.md`.
- **Error metric:** a log-based counter `errors` in app, phi and crm, labelled `service`, `class`, `operation` and `sqlstate` only. The new-group and spike alerts are PromQL conditions (`unless … offset 7d`). Verify during implementation that Cloud Monitoring's PromQL supports `offset` and `unless`. If it doesn't, the new-group alert becomes a spike-from-zero alert.
- **Tests:** `tests/infra/test_monitoring_shape.py`, and golden-line tests for the connectors pass-counter format, so a format change can't silently read as zero.
- **Owner ruling needed before apply:** who holds `monitoring.editor` to apply this. Today the inventory gives people `roles/viewer` only.

**P2: perimeter** (written, not applied)
- One ingress rule, `ing-monitoring`, in both environments:
  - identities: `grp-platform-admin`;
  - source: the break-glass access level;
  - services: Monitoring read and Logging `MetricsServiceV2`.
- Without it, nobody can see PHI metrics or alerts once the perimeter is enforced.
- Update `docs/infra/network-and-perimeter.md` §5.4 and §8.

**P3: hosted Grafana, the production form of trellis-watchtower** (written; **class 3 ruling before apply**)
- **trellis-watchtower `cloud/`:**
  - `Dockerfile`: Grafana 12 pinned, provisioning baked in, no plugins;
  - `grafana.ini`: `[auth.jwt]` on the IAP assertion header, login form off, no initial admin, anonymous off;
  - Cloud Monitoring datasources for app, crm and phi, using the attached identity.
- **Contract and service graph** (the three-repo steps are required by the protocol):
  - a new CONTRACT §1 revision in all three repos, with a CHANGE-NOTICE to the sec-* peers;
  - `schemas/service-graph.schema.json` goes from 7 to 8 services;
  - `infra/service-graph.yml` and `service_graph_lint.py`.
- **tpa-platform/infra:**
  - `sa-watchtower`;
  - `module "watchtower"` in the app project: ingress internal-LB only, `min=0`, `max=1`, image `var.image_digests["watchtower"]`;
  - `modules/edge`: IAP support, the `watch.${domain}` host and `armor-watch`;
  - the `al_tpa_watch` access level plus the `ing-watch` rule (monitoring read only).
- **Inventory and binding gate:**
  - `bindings.json` rows: `monitoring.viewer` on app, crm and phi; IAP agent as invoker; IAP accessor = `grp-platform`;
  - a must-not-exist row: `sa-watchtower` holds no `logging*` role and no invoker;
  - `outputs.tf`, and `binding_gate.py` (`read_plan` learns the IAP IAM resource);
  - fixtures and tests.
- **Images:** built by tpa-platform's pipeline from a trellis-watchtower commit pinned in `releases/<id>.json`. The watchtower repo gets no WIF access.

**S: security docs.** In trellis-security:
- SECURITY-BAR: **layer 13 "Watching" stays "not built".** That layer covers staff-abuse controls (velocity, elevation, canaries, freeze; RS-01, RS-02, AN-05), not operational monitoring. The monitoring status goes in a new "Operational monitoring" bullet under "Outside the layers".
- The design-page rows for P1–P3 are left to the security lead.
- **Proposed findings go inside the request files,** not into FINDINGS.md. trellis-security's CLAUDE.md lets only each service's own session edit its section, and that session assigns the id:
  - model-gateway body logging (stale container);
  - Caddy full-URI logs (plus the unredacted `X-CSRF-Token`);
  - auth workers with no logging setup (their tracebacks go out unredacted);
  - the drains `/health` taking about 56 minutes to fail;
  - the network health endpoints returning 200 when the database is down (in `docs/REQUESTS.md`, since network has no sec-* session).

**Requests to other repos (not built here):**
- Caddy query-string strip at the source (tpa-platform).
- Logging setup in the auth workers (auth-notary).
- A shorter drains health threshold (tpa-platform).
- Health status 503 on database failure (network, forge, enroll).
- A forge check inside network's health (network).
- An alert on the records audit-partition horizon, 2027-12 (records).
- **Where an error happened** (tpa-platform, records, auth-notary): add a safe fourth fact to `exception_facts`, the innermost first-party frame as `module:function:line`. It holds no locals, no message and no values. It gives Sentry-style "where" with no PHI. It changes records `docs/04` §5.2 ("and no fourth"), so it goes through those repos' security review and trellis-security.
- **Browser errors** (trellis + tpa-platform): today the portal reports nothing. Add a same-origin `POST /tpa/api/v1/client-errors` route that accepts only the error name, route template, component and release. It then feeds the same error metric. This means no new vendor, no CSP change, and no URLs or messages collected. It is recommended over Grafana Faro, whose SDK collects URLs (member ids in paths, TR-05) and error messages.
- **Fly production errors** (network, forge, enroll): not covered until network moves to the GCP `crm` project, or until Fly logs are shipped somewhere. Out of scope for this plan.

## Verification
- **Local:**
  - `docker compose config` is clean.
  - `lsof -nP -iTCP -sTCP:LISTEN` shows `tw-*` on 127.0.0.1:4390–4393 only.
  - `curl localhost:4391/api/v1/query?query=probe_success` returns 1 for every running stack.
  - **Negative test:** `make stub-test`. A stub returns HTTP 200 with `"database":false`, and the database probe must read 0. The stub's healthy body must read 1. Never stop `network-db` or `forge-db`, because other sessions use them.
  - Replay the fixtures, then `make scrub-check` returns 0.
  - `{service="model-gateway"}` returns no streams in Loki.
  - **Error tracking:**
    - Replay a fixture ERROR line (`class: "OperationalError"`, `operation: "claims.get"`, `sqlstate: "08006"`). It appears as one group in the Errors dashboard's table and in "new in 24 h".
    - Replay it again. The count becomes 2 and it is still one group.
    - `scrub-check` still returns 0.
  - Open each dashboard in the browser and confirm every panel has data (not NO DATA) with the :4310 stack up.
- **Infra:**
  - `terraform fmt -check`.
  - `terraform validate` for both environments, in a pinned `hashicorp/terraform:1.9` container (the laptop has 1.5.7).
  - `make check` (vocab gate, graph lint) and `make test`.
  - `binding_gate.py` on the updated fixture plan.
  - `contract_check.sh` for P3.
  - Nothing is applied.
- **Fly:** a dry run of `fly-uptime-checks.sh` prints the `gcloud` calls. The real run waits for the owner's OK.

## Owner-gated (not done without the owner's word)
- Applying P1, P2 or P3 to any cloud (class 3; no GCP organization exists yet).
- Who holds `monitoring.editor`.
- The IAP exception and the contract revision.
- Creating the GitHub remote.
- Running the Fly script in `bodyf1rst-prod`.
- Rebuilding `tpa-model-gateway` (the Member Ask session's container).

## Cost (production, once applied)
- Alert policies are billed per condition, a few dollars a month. Uptime checks fit within the free tier.
- Hosted Grafana reuses the existing load balancer and scales to zero, so the cost is small.

## Naming rules shared by the stack and the dashboards
The local stack (W1–W2) and the dashboards (W3) must both use these names exactly.

**Prometheus (blackbox probes, `job="blackbox"`):**
- `stack`: one of `tpa`, `network`, `forge`, `enroll`, `feed-ingest`, `fly`.
- `service`: `web`, `web-tls`, `tpa-api`, `auth`, `records`, `connectors`, `tpa-jobs-drains`, `trellis`, `feed-ingest`, `network-engine`, `network-tpa`, `forge-engine`, `enroll-engine`, `fly-network`, `fly-portal`.
- `probe`: `health`, `ready`, `db` (body match on the database field), `release`, `tls`.
- Series used: `probe_success`, `probe_duration_seconds`, `probe_http_status_code`.

**Prometheus (postgres_exporter, `job="postgres"`):** `db`: `network` or `forge`.

**Loki stream labels (low cardinality only):**
- `stack` (the compose project mapped to a stack name);
- `service` (the compose service name).

**Loki structured metadata, set by Alloy.** It is absent when the source line lacks the field.
- `level`: normalised to `DEBUG`, `INFO`, `WARNING` or `ERROR` from `level` or `severity`. DEBUG is dropped before storage anyway.
- `exc_class`: the exception class from the service's exception facts.
- `sqlstate`: from records' exception facts.
- `operation`, `route` (a route template only), `outcome`, `status` (HTTP status), `job` (tpa-jobs job name), `lane` (connectors lane).

**An error group** is `service` + `exc_class` + (`operation` or `route`) + `sqlstate`, over lines with `level="ERROR"`.
