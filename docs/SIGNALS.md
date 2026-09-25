# Signal catalogue

Every signal trellis-watchtower shows, where it comes from, what red means, the first thing to check, and who fixes
it. Names follow the contract at the end of [SPEC.md](SPEC.md) ("Naming rules shared by the stack and the dashboards").

**Sources**
- **Probe**: a blackbox probe scraped by Prometheus (`job="blackbox"`, labels `stack`, `service`, `probe`). A `db`
  probe matches the health body as well as the status, because these health endpoints answer 200 with their
  database down.
- **Metric**: postgres_exporter (`job="postgres"`, `db`), or Fly's hosted Prometheus (datasource `fly`).
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

## Fly production (`tw-fly-production`)

| Signal | Source | Red means | First check | Who fixes |
|---|---|---|---|---|
| fly-network `db` (laptop) | Probe: `https://bodyf1rst-network.fly.dev/api/v1/health`, body `"database": true` | Production network is down or reports its database down | `fly status -a bodyf1rst-network`, then the `bodyf1rst-pgvector` app | bodyf1rst-network |
| fly-portal `health` (laptop) | Probe: `https://bodyf1rst-portal.fly.dev/index.html` | The partner portal is not served | `fly status -a bodyf1rst-portal`; did a deploy just run? | bodyf1rst-network (`web/`) |
| Machines up | Metric (fly): `fly_instance_up` by `app` | An app has no machine reporting (every app keeps one running) | `fly status -a <app>` | The app's repository |
| Edge 5xx ratio | Metric (fly): `fly_edge_http_responses_count` | Over 0.1% (the release-canary threshold) | `fly logs -a <app>` | The app's repository |
| App p95, concurrency, CPU, memory | Metric (fly) | p95 or memory climbs toward the machine's limit | The app's own logs | The app's repository |
| **Paging:** `trellis-watchtower: fly-network`, `fly-portal` uptime checks and their `… down` policies | Cloud Monitoring in `bodyf1rst-prod` (`scripts/fly-uptime-checks.sh`; not created until the owner says so) | The check fails from 2 of its 3 US regions. **Urgent**: text, Slack and email | The policy's documentation, then `fly status` | bodyf1rst-network |

The Fly metrics need `FLY_ORG` (the org slug) and `FLY_PROM_TOKEN` (a read-only token from
`fly tokens create readonly`) in `.env`. Until both are set, every Fly-metrics panel shows a datasource error (401):
that is missing configuration, not an outage, and the dashboard says so. The two laptop probes do not depend on it.
forge is private on Fly (flycast only), so Fly metrics are its only production signal. Fly production errors are not
covered (SPEC.md, "Requests to other repos").

## Production TPA signals (planned, not built here)

The TPA projects' production alerts are Cloud Monitoring alert policies in tpa-platform's
`infra/modules/monitoring/` (SPEC.md P1, written but not applied): missed runs, job failures, connectors, auth, the
release canary, the audit chain, the perimeter, outage uptime checks and the error-group alerts. Their catalogue is
the "Alert catalogue (production)" in SPEC.md, and tpa-platform's `docs/infra/monitoring.md` once P1 lands. The
hosted dashboards that read them come from `cloud/` after the owner's class 3 ruling.
