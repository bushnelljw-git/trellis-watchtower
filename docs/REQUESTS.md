# Requests to other repos

trellis-watchtower watches these repos but changes none of them. What it needs from them is listed here.

- **Non-TPA repos** (bodyf1rst-network, health-forge, bodyf1rst-enroll): the requests are in this file, because those
  repos have no security session.
- **TPA repos** (tpa-platform, auth-notary, records-service, trellis): the requests are files in trellis-security
  `requests/`, listed at the end. The hosted dashboard's cloud half (§4) is written here in full, for the
  orchestrating session to carry into that request file.

Written 2026-09-24 by the watchtower session. Every file:line below was read at the commit named for its repo.

**2026-10-11:** there are no Fly systems (owner: "There will be NO systems in fly ONLY the gcp project"). The
`fly.toml` lines below are kept as the evidence read on 2026-09-24. The asks in §1 and §2 stand wherever the engines
run: a health check that reads only the status code passes a `200` with the database down.

---

## 1. Health answers 503 when its database check fails

**The problem.** All three engines answer `200` while their database is down. They say so only in the body. Fly's
HTTP checks read only the status code, so a machine with a dead pool stays in rotation. Each `fly.toml` comment says
the opposite is intended.

**The ask.** When `db_ok()` is false, return `503` with the same body. Keep the database field in the body for people
to read. Add a unit test that stubs `db_ok()` to `False` and asserts `503`.

**A side effect to accept.** Each app runs a single machine, so a `503` takes that machine out of rotation. Users then
get Fly's `503` instead of the app's `500`s. The outage is the same either way; what changes is that it now shows up
as a signal. That is what each comment says it wants.

**Until then**, trellis-watchtower's probes read the body:
- network: `"database": true`
- enroll: `"db": true`
- forge: `"status":"ok"`, because an anonymous caller sees only `status`

### bodyf1rst-network (at `bd7b1bed`)
- `engine/app/routers/ops.py:15-24`: `GET /api/v1/health` returns `200 {status: "degraded", database: false}`. The
  router is mounted under `/api/v1` at `engine/app/main.py:1231`.
- `engine/app/lattice/main.py:290-298`: `GET /tpa/health` returns `200 {ok: true, database: false}`. The app is mounted
  at `/tpa` at `engine/app/main.py:1364`.
- `fly.toml:302-307` checks `/api/v1/health` by status. The comment at `fly.toml:298-301` says "a machine with a dead
  database is pulled from rotation rather than serving 500s". It is not pulled.

### health-forge (at `1754584`)
- `forge-engine/app/routers/ops.py:156-175`: `GET` and `HEAD /api/v1/health` return `200` with `status: "degraded"`.
  Return `503` for both methods.
- `fly.toml:76-81`: `[[services.http_checks]]` on `/api/v1/health`.

### bodyf1rst-enroll (at `b329df1`)
- `engine/app/routers/health.py:23-32`: `GET /api/v1/health` returns `200 {ok: true, db: false}`. Its docstring says
  "`fly.toml`'s http check reads the status code".
- `fly.toml:137-142`: the check itself. The comment at `fly.toml:133-136` expects a dead pool to take the machine out
  of rotation.

### Proposed finding for network

This finding goes here because network has no security session. It is not in trellis-security's findings register.
The register's CRM section is the place for it if the security lead adds it there.

**The CRM's health answers 200 with its database down.**
- **Severity:** medium.
- **Evidence:** read by the watchtower session at `bd7b1bed`. Both routes answered `200` on :8100 on 2026-09-24.
- **Where:** `engine/app/routers/ops.py:15-24`, `engine/app/lattice/main.py:290-298` and `fly.toml:298-307`.
- **Impact:** a machine with a dead pool stays in rotation, which is the opposite of what its `fly.toml` says.
- **Same pattern elsewhere:** health-forge and bodyf1rst-enroll, above.
- **Live now (2026-09-24, about 21:15 CDT):** on :8100, `/api/v1/health` reports `database: true` but `/tpa/health`
  reports `database: false`, and keeps doing so. So the in-process TPA engine (Lattice) can't reach its database
  while the CRM can. The watchtower probe `network/network-tpa/db` reads 0, and the `DatabaseReportedDown` alert is
  firing. The owning network session should check the Lattice database connection or its settings.

---

## 2. A forge reachability check inside network's health

**Where network reaches forge.** It calls `forge_base_url` (`engine/app/config.py:65`), with a 120 s request timeout
(`:68`). forge is private: it is reachable only over flycast. So network's health is the only production view of
whether network can reach it.

**The ask:**
- Add `forge: true | false` to `GET /api/v1/health`.
- Get the value from a `GET` of forge's `/api/v1/health` with a short timeout (2 s or less).
- Cache the result for 15–30 s, so Fly's 15 s check doesn't call forge on every run.
- Report `forge` in the body only. Don't fail the status on it: a forge outage should not take network out of
  rotation.

trellis-watchtower will body-match `"forge": true` as a separate probe.

---

## 3. Host-process JSON logs to files, so Alloy can ship them later

**Today:**
- **network** writes JSON to stdout only (`configure_logging`, `engine/app/config.py:1063-1068`).
- **enroll** does the same (`engine/app/config.py:347-352`).
- **forge** writes plain text (`logging.basicConfig(... format="%(levelname)s %(name)s: %(message)s")`,
  `forge-engine/app/main.py:19`).

**The ask:**
- Add an opt-in `LOG_FILE` setting. When it is set, add a size-rotated file handler with the same JSON formatter.
  forge adopts the JSON formatter first.
- Put the file outside `~/Documents/code/`, for example `~/Library/Logs/trellis-watchtower/<repo>.jsonl`. Then Alloy
  can mount one directory read-only, and no log file lands in a code tree.

**Why the logs stay unshipped for now.** trellis-watchtower does not ship host-process logs until each is shown clean
(`docs/SPEC.md`, W2). Both JSON formatters today put the full traceback in `exc` and every `extra` field on the line:
- network: `engine/app/config.py:1048-1061`
- enroll: `engine/app/config.py:328-344`

The follow-up ask, once files exist, is class-only exception logging, as tpa_common and records do.

---

## 4. The hosted dashboard's cloud half (tpa-platform)

**Why.** The owner ruled the hosted dashboard yes on 2026-10-11 ("Yes, everything": charts for the app, CRM and call
centre, and health numbers for the member-records area, never member data, through a narrow read-only opening into
the protected area). That reverses tpa-platform D-92. trellis-watchtower has built the image (`cloud/`, branch
`cloud-dashboards`); everything below is tpa-platform's to build, after its `beta-alert-gaps` work lands. It
supersedes the Ask in trellis-security's `2026-09-24-watchtower-to-tpa-platform-hosted-grafana-iap.md` where the two
differ. That file's status still reads "refused (for now)" from D-92; bringing it up to date with the owner's ruling is
for its owners (the orchestrating session or sec-tpa-platform).

**What bounds a viewer.** A signed-in viewer can post their own query to Grafana's `/api/ds/query`, not only the
dashboards' ones. That means any filter, every label, even another project. Grafana 12.4.11 has no setting that
limits a datasource to its saved panels (`cloud/README.md`, "What a viewer can read"; `make cloud-image-check` shows
it on every run). So what a viewer can read is exactly what `sa-watchtower` can read, and the asks below are what
bound it.

**The asks:**

1. **`sa-watchtower` holds a custom role with `monitoring.timeSeries.list` alone**, not `roles/monitoring.viewer`.
   That role also reads alert policies, notification channels, uptime-check configs, dashboards and groups. Viewing
   the pages needs nothing more: a signed-in browser made no datasource resource call, and the backend calls only
   `projects.timeSeries.list`. Add `monitoring.metricDescriptors.list` only if a later Grafana needs it; the query
   editor uses it, and viewers have none.
2. **That role is granted on the four TPA projects alone:** app, PHI, beta's call-centre project, and the CRM's where
   it has a project of its own. Never on a folder or the organisation. No `logging*` role, no invoker, nothing else.
3. **The IAP `watch` host is under the same access level as `ing-monitoring`**, so only the people who may already read
   the PHI project's monitoring reach a page that can. The host is for `grp-platform`, the IAP accessor.
4. **`ing-watch`**: one ingress rule admitting `sa-watchtower`, from the watch service, to `monitoring.googleapis.com`
   in the PHI project, for Monitoring read only.
   - Monitoring takes no method selectors in a perimeter rule, so the read-only part is the role in ask 1.
   - Without the rule, every `cloud-phi` panel shows the perimeter's refusal and nothing else changes.
   - The PHI project's metrics it opens: records, connectors and their jobs (`errors`, `records_*`, `connectors_*`,
     `perimeter_violations`, `monitoring_changes`, `log_metric_changes`, `scheduler_failures`, `run_system_errors`,
     `sql_proxy_errors`), Cloud Run's request, latency, instance and job metrics for them, and tpa-db's `database/up`
     and `disk/utilization`.
5. **The Cloud Run service** (ingress from the internal load balancer only, `min=0`, `max=1`, the image by digest from
   a trellis-watchtower commit pinned in `releases/<id>.json`) **with this environment.** None of it is secret. The
   image checks every value at start and refuses to start on a wrong one.

   | Variable | beta | production-full |
   |---|---|---|
   | `WATCH_HOST` | `watch.<domain>` | `watch.<domain>` |
   | `IAP_AUDIENCE` | `/projects/<number>/global/backendServices/<bes-watch id>` | the same |
   | `TPA_APP_PROJECT_ID` | the app project | the app project |
   | `TPA_CRM_PROJECT_ID` | **the app project** (the CRM shares it, R282) | the CRM project |
   | `TPA_PHI_PROJECT_ID` | the PHI project | the PHI project |
   | `TPA_CC_PROJECT_ID` | the call-centre project | empty (no call-centre project: its page and parts are left out) |
   | `TPA_ENVIRONMENT` | `beta` | `production` (`local.env`) |
   | `TPA_PAUSED_JOBS` | `join(",", var.tpa_jobs_paused)`; since 2026-10-25 also `feed-ingest-everon-sync` while the importer is built and paused (`local.watch_paused_jobs`) | empty: refused otherwise |
   | `TPA_NOT_DEPLOYED_JOBS` (2026-10-25) | `feed-ingest-everon-sync` while `feed_ingest_enabled` is off, else empty (`local.watch_not_deployed_jobs`) | empty: refused otherwise |
   | `TPA_STOPPED_DATABASES` | `join(",", [for db, stopped in local.database_stopped : db if stopped])` | empty: refused otherwise |

   The last three come from the same variables that pause the sweeps, build and pause the administrator-feed importer
   and stop the databases, so the pages follow each apply. In beta at rest the affected tiles read "paused", "not
   deployed" or "database stopped" instead of red.
6. **Query Insights: turn it off on auth-db, crm-db and cc-db, or accept the residual.** With ask 1 a viewer can still
   read every metric in the four projects, and Query Insights' per-query metrics carry normalised query text as a
   label. It is already off on tpa-db (`insights_config`, "a sampled query text is a member id in a Google console").
   Normalised text replaces values with placeholders, so it should hold no member data. Turning it off on the other
   three would close the path; keeping it is the owner's to accept, as a residual written down.

---

## Requests to the TPA repos

They are in trellis-security `requests/`. There are no doorbell messages. The trellis-security SessionStart hook lists
each open request to a service when that service's security session starts. Where a request proposes a finding, the
owning session assigns its id.

| To | File | Class | Asks for |
|---|---|---|---|
| tpa-platform | `2026-09-24-watchtower-to-tpa-platform-caddy-log-query-strings.md` | 1 | Strip query strings and headers from Caddy's access logs. Proposes two findings: the logged URLs and CSRF header, and the stale model-gateway container. |
| tpa-platform | `2026-09-24-watchtower-to-tpa-platform-drains-health-window.md` | 1 | A drains `/health` that fails within minutes, not ~56. Proposes a finding. |
| tpa-platform | `2026-09-24-watchtower-to-tpa-platform-hosted-grafana-iap.md` | 3 | Hosted Grafana behind IAP on `watch.${domain}` (the P3 change list). The file says refused (D-92); the owner ruled yes on 2026-10-11, and §4 above is the current Ask. |
| tpa-platform | `2026-09-24-watchtower-to-tpa-platform-client-errors-route.md` | 2 | `POST /tpa/api/v1/client-errors`: name, route template, component and release only. |
| tpa-platform | `2026-09-24-watchtower-to-tpa-platform-exception-where.md` | 1 | A `where` fact (module:function:line) in `exception_facts`. |
| auth-notary | `2026-09-24-watchtower-to-auth-notary-worker-logging.md` | 1 | Configure logging in the four workers. Proposes a finding. |
| auth-notary | `2026-09-24-watchtower-to-auth-notary-exception-where.md` | 1 | The same `where` fact. |
| records-service | `2026-09-24-watchtower-to-records-service-exception-where.md` | 1 | The same `where` fact. It changes docs/04 §5.2 ("and no fourth"), so it goes through records' own security review. |
| records-service | `2026-09-24-watchtower-to-records-service-audit-partition-horizon.md` | 1 | A daily horizon fact and a runbook. The monthly partitions end at 2027-12. |
| trellis | `2026-09-24-watchtower-to-trellis-client-error-reporting.md` | 2 | Browser error reporting through the client-errors route. |

The model-gateway rebuild is the member Ask session's. A note to that session is at trellis
`tasks/member-assist/FROM-WATCHTOWER-SESSION-2026-09-24-model-gateway-body-logs.md`.

**Seen on the first night's dashboards (2026-09-24). These are signals for the owning sessions, not security requests:**
- **tpa-platform: `tpa-jobs-drains` has logged `a drain tick raised` at ERROR** for `crm_transitions` and
  `outbox_dispatch` for about 14 hours. The research lane also saw 401s in the drains' logs. Most likely it is the
  CRM hop or the drains' token; the errors dashboard groups it.
- **tpa-platform / auth-notary: `tpa-auth-publisher` exited** during the 20:42–20:46 CDT disk-full window and does
  not restart (restart policy `no`). The overview's staleness stat shows it.
- **records-service: no line carries `duration_ms` or `db_ms`,** although both are on the log allowlist. There is no
  records-side latency signal. The dashboards use the edge latency from Caddy for the whole path instead.
- **auth-notary: `auth-outbox-publisher` (the messenger) prints nothing in normal running,** so its silence means
  nothing. It is covered by the worker-logging request above.

## Out of scope

Production errors for network, forge and enroll aren't covered. They will be once each runs in GCP (network in the
`crm` project; `docs/SPEC.md`).
