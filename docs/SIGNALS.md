# Signal catalogue

Every signal trellis-watchtower shows, where it comes from, what red means, the first thing to check, and who fixes
it. Names follow the contract at the end of [SPEC.md](SPEC.md) ("Naming rules shared by the stack and the dashboards").

**Sources**
- **Probe**: a blackbox probe scraped by Prometheus (`job="blackbox"`, labels `stack`, `service`, `probe`). A `db`
  probe matches the health body as well as the status, because these health endpoints answer 200 with their
  database down.
- **Metric**: postgres_exporter (`job="postgres"`, `db`).
- **LogQL**: Loki, over the scrubbed lines Alloy ships from the `tpa` compose project, using the stream labels
  `stack` and `service` and the structured metadata `level`, `exc_class`, `sqlstate`, `operation`, `route`,
  `outcome`, `status`, `job` and `lane`.

**Stack state comes first.** A stack is *not running* when none of its probes passed in the last hour. That is grey,
not red: a repo that isn't started today is not an outage. Every red below assumes the stack is running (the Stack
overview shows it). Log-based signals have no such guard: with the tpa stack stopped, the connectors and drains
staleness stats (and the auth-publisher and auth-sweeper ones) read "none in the last hour".

**The first thing to check is always the scrubbed view.** Open Grafana Explore on Loki with
`{stack="tpa", service="<service>"}` before reading raw `docker logs`. Never read `model-gateway` or `dev-vendor-sink`
output to diagnose anything here: they carry request bodies and sign-in codes.

**Who fixes it** names the repository and so the session that owns it. The sec-* security session of a TPA repository
takes anything that touches its security rules. The :4310 stack is shared: bringing it down needs the owner's word.

## Every stack (Stack overview, `tw-overview`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| Stack state | Probe: `stack:probe_success:max_over_time1h` plus current `probe_success` per stack | **down**: a probe on a running stack gets no answer or a non-2xx. **degraded** (amber): only `db` probes fail, and they answered 2xx (the body reports the database down) | The "Every probe" table: which service and probe, and its HTTP status (0 = nothing answered) | The stack's repository (rows below) |
| `ProbeDown` rule | Probe (Prometheus rule, shown in Grafana's alert list; no Alertmanager locally) | A probe of a running stack failed for 2 min, other than a `db` probe that answered 2xx | Same as above | The stack's repository |
| `DatabaseReportedDown` rule | Probe | A health endpoint answers 2xx but its body says the database is down, for 2 min | `curl` the health URL and read the database field | The stack's repository |
| `PostgresDown` rule | Metric: `pg_up` | The exporter lost a database it could reach in the last hour | `pg_isready -h 127.0.0.1 -p 5434` (network) or `-p 5433` (forge) | network or health-forge |

## TPA: edge and API (`tw-tpa-edge-api`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| trellis `release` | Probe: `https://localhost:4310/tpa/release.json`, body `"release":"<id>"` | The edge does not serve the portal bundle's release file (web-tls down, placeholder bundle, or TLS failure) | `curl -sk https://localhost:4310/tpa/release.json`; does `compose/.env` name a bundle? | tpa-platform (web image); trellis if the bundle lacks the file |
| web-tls `tls` | Probe: TCP+TLS on :4310 | The TLS handshake on :4310 fails | Is the `web-tls` container running in project `tpa`? | tpa-platform |
| TLS certificate days | Probe: `probe_ssl_earliest_cert_expiry` | Under 14 days (amber under 30) | The mkcert certificate (expires 2028-12-22 today) | tpa-platform |
| tpa-api `health`, `ready` | Probe: :8230 | `health`: the process is gone. `ready`: it cannot reach auth or records | The auth and records rows; then tpa-api's lines in Loki | tpa-platform (or auth-notary / records-service when they are the cause) |
| web `ready` | Probe: `web:8240` (TPA_NET overlay only) | The internal web port is not ready | Only present with `make up TPA_NET=1` | tpa-platform |
| Edge responses by status class | LogQL: Caddy lines on `web`, `web-tls`, `status` | A 5xx band appears | Which upstream: the tpa-api panels on the same page | tpa-platform |
| Edge latency p50/p95 | LogQL: Caddy `duration` | p95 climbs well above its usual level | auth latency, then records' busiest operations and refusals in the same window | tpa-platform, then auth-notary or records-service |
| API responses, outcomes, refusals | LogQL: tpa-api `status`, `outcome` | 5xx, or `unavailable`/`misconfigured` outcomes | "5xx by route" and "Operation calls" | tpa-platform |
| 5xx by route | LogQL: tpa-api `route` template | A route template returns 5xx | The ERROR lines for that route on the Errors dashboard | tpa-platform |

## TPA: auth (`tw-auth`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| auth `ready` | Probe: :8210 `/ready` | auth cannot sign anyone in (database, keys or identity certificates) | The `not_ready` stat: its `reason` is on the line | auth-notary |
| 401 and 423 | LogQL: `status` 401/423 | A burst of refused sign-ins (401) or lockouts (423) | "401 and 423 by route" | auth-notary (a lockout wave may be an attack: tell the security lead) |
| `not_ready` | LogQL: `"msg":"not_ready"` | auth refused its readiness check in the range | The line's `reason` in Explore | auth-notary |
| `unhandled` | LogQL: `"msg":"unhandled"` | A request reached the last-resort handler (a 500) | Its `exc_class` on the Errors dashboard | auth-notary |
| auth-publisher: since last line | LogQL: age of the newest `auth-publisher` line (a counts-only print, one per 50 s loop) | Over 150 s (amber over 75 s). The worker has no probe, and Alloy ships running containers only, so a crashed publisher shows up only as silence | `docker ps -a --filter name=tpa-auth-publisher` (Exited?) | auth-notary |
| auth-sweeper: since last line | LogQL: age of the newest `auth-sweeper` line (one per 300 s tick) | Over 900 s (amber over 450 s) | `docker ps -a --filter name=tpa-auth-sweeper` | auth-notary |
| Worker lines | LogQL: line rate of the auth workers | A band stops. auth-outbox-publisher (the messenger) prints nothing in normal running, so its silence means nothing | The staleness stats above | auth-notary |
| Latency | LogQL: auth `duration_ms` | p95 climbs | auth-db health | auth-notary |

## TPA: records (`tw-records`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| records `ready` | Probe: :8220 `/ready` (database, revocations, JWKS) | records cannot serve operations | Which check failed: `curl -s localhost:8220/ready` | records-service |
| `database unreachable` | LogQL: line filter | records lost tpa-db. **Urgent** | Is `tpa-db` (project `records`) running? | records-service |
| `audit flush failed` | LogQL: line filter | An audit record did not reach the chain. **Urgent** | Errors dashboard: its `exc_class` and `sqlstate` | records-service |
| `rate limited` | LogQL: line filter | Callers are hitting their rate class (amber from 1, red from 20) | Which operation: Explore `\|= "rate limited"` | records-service (or the caller's repo if it loops) |
| `mirror puller error` | LogQL: line filter | The revocation mirror cannot pull from auth | auth `ready` | records-service, then auth-notary |
| Refusals by gate and code | LogQL: `gate`, `code` parsed from the line | An unexpected gate or code leads | CONTRACT §7 for the code | records-service, or the caller (tpa-api, tpa-jobs, feed-ingest) |
| Decisions, busiest operations | LogQL: `decision` parsed from the line; lines per `operation` | `deny` appears, or one operation dominates | The refusals table for the gate and code | records-service |
| Errors by class and SQLSTATE | LogQL: `level="ERROR"` | Any row | The SQLSTATE class (08 = connection, 23 = constraint, 40 = rollback, 53 = out of resources, e.g. 53100 disk full) | records-service |

records logs no request duration today: `duration_ms` and `db_ms` are on its log allowlist but no line sets them, so
there is no records latency panel. The edge latency (Caddy) covers the whole request path meanwhile.

## TPA: jobs and connectors (`tw-jobs-connectors`)

The default signal is the logs. The `/health` probes of connectors and tpa-jobs-drains exist only with the manual
TPA_NET overlay (see the README), and the drains `/health` takes about 56 minutes to fail (a request to tpa-platform).

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| connectors: since last pass | LogQL: age of the newest `outcome="pass"` line | Over 120 s (amber over 60 s). A pass runs at least every 20 s | Is `connectors` running? Is Alloy shipping (UI on :4393)? | tpa-platform |
| tpa-jobs-drains: since last run summary | LogQL: age of the newest line with `"tenants_total"` | Over 180 s (amber over 90 s). Drains tick every 30 to 60 s | "Ticks that raised" (a tick that raises writes no summary) | tpa-platform |
| Dead letters, destination refused, unsigned envelopes | LogQL: counters on the pass line (`connectors_dead_total`, …); per process, reset on restart | Any, since connectors started | Explore the delivery lines for that `lane` | tpa-platform (a vendor refusal may be the vendor's; unsigned is records-service's) |
| Delivery lines by lane | LogQL: `lane` | A lane stops while others deliver | The lane's vendor | tpa-platform |
| Run summaries by job | LogQL: `job` | A job stops appearing | "Ticks that raised, by job" | tpa-platform |
| Tenants not ok | LogQL: `tenants_failed`, `tenants_partial`, `tenants_skipped` from the summary | Any failed or skipped tenant | The job's ERROR lines on the Errors dashboard | tpa-platform, or records-service when the operation refused |
| Ticks that raised | LogQL: `a drain tick raised` | A whole tick failed (usually configuration: a scope never granted, an address that answers nothing) | The line's `reason` (the exception class) | tpa-platform |
| Ticks that did not finish clean | LogQL: `outcome="incomplete"` | A tick ended with a tenant not ok (amber); the next tick retries | Tenants not ok | tpa-platform |

## Errors (`tw-errors`)

An **error group** is `service` + `exc_class` + (`operation` or `route`) + `sqlstate`, over lines with
`level="ERROR"`. The lines hold the exception class only, never a message or stack trace (README, "Error tracking").

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| Error groups table | LogQL: count, first seen, last seen per group (release where a service logs one: auth's `revision`) | Any group with a recent last seen | The group's service dashboard at the time of first seen | The group's `service` repository |
| New in the last 24 h | LogQL: `… [24h] unless … [6d] offset 1d` | A group that did not exist in the 6 days before | What changed: a deploy, a migration, a new route | The group's `service` repository |
| Spiking groups | LogQL: last hour over 10 and over 5x the group's 7-day hourly average | A known error suddenly much more frequent | The same group's trend | The group's `service` repository |
| ERROR lines per service | LogQL | A service's band grows | The groups table filtered to that service | That service's repository |

## CRM: bodyf1rst-network (`tw-crm-network`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| network-engine `db` | Probe: :8100 `/api/v1/health`, body `"database": true` | The engine is down (no answer) or reports its database down (degraded) | `curl -s localhost:8100/api/v1/health` | bodyf1rst-network |
| network-tpa `db` | Probe: :8100 `/tpa/health`, body `"database": true` | Lattice reports its database down. **Known finding, 2026-09-24:** it answers 200 with `"database": false` locally, so the network stack reads *degraded* | Lattice `db_ok()` | bodyf1rst-network (docs/REQUESTS.md §1) |
| Postgres: exporter, connections used, size, transactions, cache hit, states, deadlocks | Metric: postgres_exporter `db="network"` (profile `db`) | Exporter disconnected; connections over 90% of `max_connections`; deadlocks | `pg_isready -h 127.0.0.1 -p 5434` | bodyf1rst-network |

## health-forge (`tw-forge`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| forge-engine `db` | Probe: :8000 `/api/v1/health`, body `"status":"ok"` (an anonymous caller sees only `status`) | Down, or `"status":"degraded"` | `curl -s localhost:8000/api/v1/health` | health-forge |
| Postgres | Metric: postgres_exporter `db="forge"` | As for network | `pg_isready -h 127.0.0.1 -p 5433` | health-forge |

## bodyf1rst-enroll (`tw-enroll`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| enroll-engine `db` | Probe: :8400 `/api/v1/health`, body `"db": true` | Down, or its database down | `curl -s localhost:8400/api/v1/health` | bodyf1rst-enroll |

## feed-ingest (`tw-feed-ingest`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| feed-ingest `health` | Probe: console :8099 `/healthz` | The console is not running (it is a host process with no cloud deployment by design) | Is the console process running? | feed-ingest |

## Production TPA signals (cloud: the hosted dashboards)

The TPA projects' production alerts are Cloud Monitoring alert policies in tpa-platform's `infra/modules/monitoring/`
and its catalogue `infra/monitoring.yml` (docs/infra/monitoring.md there). The hosted Grafana in [cloud/](../cloud/)
charts the same metrics: nine dashboards, read-only, over four datasources (`cloud-app`, `cloud-crm`, `cloud-phi`,
`cloud-cc`). The owner ruled it yes on 2026-10-11; it is live once tpa-platform builds the cloud half. **Source** below
is the Cloud Monitoring metric (`logging.googleapis.com/user/<name>` for a log-based one). A red triangle on a panel is
a failed query, not a reading (on `cloud-phi`, most often the perimeter rule missing), and its "no value" text means
nothing. In beta at rest a tile reading "paused" or "database stopped" (no colour) is a sweep paused or a database
stopped on purpose (the service's `TPA_PAUSED_JOBS`, `TPA_STOPPED_DATABASES`), not a fault.

| Signal (dashboard) | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| Uptime checks passing (overview, Portal & API, CRM) | `monitoring.googleapis.com/uptime_check/check_passed` by host | Under 95% in 24 h. Behind IAP a pass is Google's sign-in page: it proves the edge and IAP, never the service | The 5xx and instance panels for the service behind the host | tpa-platform (edge) |
| Scheduled runs (overview, Jobs) | `run.googleapis.com/job/completed_execution_count`, `result="succeeded"`, within each job's deadline plus 3 min (job metrics arrive up to 180 s late) | MISSED: no success within 1.5 cadences (`missed run (<job>)`). "paused" or "database stopped" in beta at rest | Failed executions, then the schedule's failures (Jobs) | the job's repository (tpa-platform, auth-notary, records-service) |
| Requests, 5xx (every area) | `run.googleapis.com/request_count` by service and `response_code_class` | 5xx in the last hour (`canary-5xx` at 0.1% and five; the urgent only-5xx liveness policies) | The service's ERROR lines (Errors), then start-up failures | the service's repository |
| p95 (every area) | `run.googleapis.com/request_latencies` (ALIGN_PERCENTILE_95); tpa-api's own `tpa_api_latency` | Over 2 s (`canary-latency`, `tpa-api-latency`). web's and tpa-api's Cloud Run p95 counts the desk's 40-second streams | records' latency, then auth's | tpa-platform, records-service, auth-notary |
| Error groups (overview, Errors) | `errors` (app, PHI, call centre), `auth_errors`, the CRM's `crm_errors` (beta) or `errors` | A group in 24 h (orange); new groups and spikes page as `new error group` and `error spike` | The group's service or job, class, operation or event, code, SQLSTATE (Errors) | the group's service's repository |
| Database up and disk (overview, Databases) | `cloudsql.googleapis.com/database/up`, `database/disk/utilization` for auth-db, tpa-db, crm-db, cc-db | DOWN (urgent `<instance>-down`), disk over 85% (`<instance>-disk`). No value: stopped on purpose between test sessions, or not built | The instance's operations in the console | tpa-platform |
| Failed jobs and schedules (overview, Jobs, area pages) | `job/completed_execution_count` `result="failed"`; `scheduler_failures` by schedule and status | Any in 24 h (`jobs-failed`, `scheduler-failed`; `audit-chain` for the audit jobs, urgent) | The execution's own lines; PERMISSION_DENIED is an invoker binding | the job's repository |
| Sign-in: refused, lockouts, not ready, unhandled (Sign-in) | `auth_login_failures`, `auth_lockouts`, `auth_not_ready` by check, `auth_errors` `operation="unhandled"` | Lockouts over 20 in 5 min; `not_ready` for `database` (urgent); any unhandled | auth's lines; auth-db | auth-notary |
| Sign-in messages waiting (Sign-in) | `auth_messages_outbox_lag` (p99) and the messenger's instance count | Over 30 s for two minutes, or no instance (`auth-messages-lag`; texts and emails alike) | The vendor, the NAT path, the allowlist | auth-notary |
| Audit and credentials (Sign-in) | `auth_audit_break`, `auth_audit_reconciled`, `auth_audit_reconcile_findings`, `auth_audit_chain_breaks_new`, `auth_credential_tag_invalid` | Any break, finding or tag failure, or the reconcile silent for 90 min (all urgent) | auth-notary runbooks 7.12, 7.17, 04 §5.5 | auth-notary |
| Gateway (Member records, `cloud-phi` only) | `records_refusals` by gate, code, operation; `records_rate_limited`; `records_critical`; `records_mirror_problems`; `errors` SQLSTATE 08 | `audit flush failed` or `database unreachable` (urgent); an unexpected gate or code | tpa-db, then the refusals around the time | records-service |
| Chain head (Member records) | `records-chain-head` executions and schedule; `records_chain_head_exists` | A failure (urgent `audit-chain`); a head already in the vault (normal) | Who ran the job and when | records-service |
| Connectors (Member records) | `connectors_passes`, `connectors_deliveries` by lane, outcome, code; `connectors_dead_letters` | No pass for 5 min; a dead letter; a refused destination; an unsigned envelope | connectors.md §7.3 | tpa-platform (records-service for unsigned) |
| Perimeter and alert changes (Member records) | `perimeter_violations` by reason, service, dry run; `monitoring_changes` and `log_metric_changes` by method | Any violation; any policy, channel, snooze (D-137) or log-counter (D-141) change | network-and-perimeter.md §5.5; the Admin Activity entry | tpa-platform |
| tpa-jobs (Portal & API, Jobs) | `tpa_jobs_runs`, `tpa_jobs_alerts` by job and alert, `tpa_jobs_drain_raised`, `tpa_jobs_accumulator_backlog` | A paging alert (`anomaly_freeze`, `crm_signature_failure`, `member_access_mass_end`); a drain tick that raised; the backlog growing | The run's own summary line | tpa-platform |
| Call centre, CRM (their pages) | Cloud Run request, latency and instance metrics, `errors`, `run_system_errors`, `sql_proxy_errors`, job executions | `voice-down` (urgent), a failed migration, cc-db or crm-db down | The service's system log | call-center; the CRM |

**Paging (2026-10-11).** Every policy in a TPA project notifies that project's `pagerduty` channel. The channel
pages one PagerDuty service: "TPA beta · Portal & API" for the app project, "· Member records" for PHI, and
"· Call centre" for the call-centre project. A CRITICAL policy becomes a high-urgency P1 page (phone, SMS, app, email,
Slack). A WARNING policy becomes a low-urgency P3 (app, email, Slack). A policy with no severity still pages at high
urgency (the rules ignore letter case). The on-call person is on the "TPA primary on-call" schedule. A high-urgency
page goes to level 2 after 15 minutes without an acknowledgement; low urgency never escalates. Slack
messages come from PagerDuty in #tpa-beta-alerts. How it works, how to silence it, and how to test it are in
[PAGERDUTY.md](PAGERDUTY.md).
