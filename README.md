# trellis-watchtower

Monitoring for every working repository of the TPA platform and the BodyF1rst network, on this laptop today and in
production later. It is a copy of `watchtower` (which keeps watching the BodyF1rst app) rebuilt for these stacks:
one pinned image per process, Grafana 12, Alloy instead of Promtail, and no Tempo, Alertmanager or MySQL.

The design is [docs/SPEC.md](docs/SPEC.md). Every signal, what red means and who fixes it is in
[docs/SIGNALS.md](docs/SIGNALS.md). What this repo needs from the watched repos is in
[docs/REQUESTS.md](docs/REQUESTS.md).

## What it watches

| Stack | What | Signals |
|---|---|---|
| `tpa` | the :4310 compose stack: web and web-tls (Caddy), tpa-api, auth-notary and its workers, records-service, connectors, tpa-jobs-drains, and the trellis portal bundle | probes on `/health`, `/ready`, the TLS handshake and `/tpa/release.json`; scrubbed JSON logs in Loki |
| `network` | bodyf1rst-network on :8100, network-db on 5434 | body-match probes on `/api/v1/health` and `/tpa/health`; postgres_exporter |
| `forge` | health-forge on :8000, forge-db on 5433 | body-match probe; postgres_exporter |
| `enroll` | bodyf1rst-enroll on :8400 | body-match probe |
| `feed-ingest` | the feed-ingest console on :8099 | `/healthz` probe |
| `fly` | bodyf1rst-network, bodyf1rst-portal and bodyf1rst-forge in production on Fly | probes from this laptop; Fly's hosted Prometheus; Cloud Monitoring uptime checks (below) |

trellis-security is documentation, not a monitored target. A stack that is not running today shows as *not running*
(grey), never as an outage.

## Local quick start

```bash
cp .env.example .env         # then fill it in: Grafana admin password, the two postgres DSNs, optionally Fly
make up                      # start the stack
make probe-check             # probe_success per stack, service and probe
open http://127.0.0.1:4390   # Grafana: the Stack overview, as an anonymous Viewer
make down                    # stop this project only; volumes are kept
```

| Port (127.0.0.1 only) | What |
|---|---|
| 4390 | Grafana (anonymous Viewer; the admin password is in `.env`) |
| 4391 | Prometheus |
| 4392 | Loki |
| 4393 | Alloy's UI |
| 4394 | spare |

Everything runs as compose project `trellis-watchtower`, with containers named `tw-*` on its own network. It never
touches the :4310 stack's containers; it reads their logs through a socket proxy that allows `GET` on containers only.

- **Profile `db`.** `make up` adds the two postgres_exporters (network-db and forge-db) when `.env` has both
  `PG_DSN_NETWORK` and `PG_DSN_FORGE`. They use those databases' existing local dev credentials. Monitoring never
  gets a login to tpa-db or auth-db.
- **`make up TPA_NET=1` is a manual opt-in only.** It attaches the probe container to the :4310 stack's `tpa-net` to
  reach three internal-only ports: web's `/ready` (8240) and the `/health` of connectors and tpa-jobs-drains (8080).
  **The caveat:** while it is attached, that stack's own `docker compose down` cannot remove `tpa-net` and exits with
  an error, which breaks the peer sessions that chain `make down && …`. Attach for a short check, then run `make up`
  without it to detach. By default connectors and the drains are watched from their logs instead (the time since
  connectors' last `outcome="pass"` line and since the last drain run summary), and web through the :4310 release
  and TLS probes.
- **Fly metrics are optional.** The Fly production dashboard's metric panels read Fly's hosted Prometheus and need
  `FLY_ORG` (the org slug) and `FLY_PROM_TOKEN` (from `fly tokens create readonly`) in `.env`. Until both are set
  those panels show a datasource error (401): missing configuration, not an outage. The Fly probes run from this
  laptop regardless.
- **Other targets.** `make check` validates every config with the pinned images. `make scrub-check` replays the log
  fixtures through Alloy and proves nothing unsafe is stored. `make stub-test` proves that a health body saying
  `"database": false` reads as down even with a 200. The Makefile header lists them all.
- **Dashboards** are files in [grafana/dashboards/](grafana/dashboards/): a Stack overview (the home page), TPA edge
  and API, auth, records, jobs and connectors, feed-ingest, CRM (network), forge, enroll, Fly production and Errors.
  Each has the uid `tw-<file name>`, the tag `trellis-watchtower` plus a stack tag, and a 30 s refresh.
  `python3 scripts/dashboard_lint.py` must pass before a dashboard change is committed; its test is
  `python3 -m unittest discover -s tests/dashboards`.

## Log safety

No PHI anywhere in monitoring. The rules (docs/SPEC.md) and how they are kept:

- **Nothing is shipped by default.** Alloy ships an allowlist of the `tpa` compose services only. It never ships
  `model-gateway` (it can log request bodies), `dev-vendor-sink` (it carries sign-in codes), databases, MinIO or
  Gotenberg, and it drops those a second time by service name.
- **Host processes stay out** (network, forge, enroll, feed-ingest) until each one's logs are shown clean. Their
  JSON formatters put full tracebacks and every extra field on the line today.
- **Lines are scrubbed before storage.** DEBUG lines and the `anthropic`, `httpx` and `httpcore` loggers are dropped.
  Identifier fields (`tid`, `sid`, `sub`, `principal_id`, `tenant_id`, `jti` and the like) are removed. Caddy lines
  are rebuilt from an allowlist, with the query string cut, the headers dropped and id-shaped path segments replaced
  by `:id`. Any line that still looks unsafe is dropped (fail closed).
- **Labels come from a closed allowlist.** The stream labels are `stack` and `service`. Everything else is structured
  metadata: `level`, `exc_class`, `sqlstate`, `operation`, `route` (a template), `outcome`, `status`, `job`, `lane`.
  Never a tenant, a request id, a row id or a raw URL. `scripts/dashboard_lint.py` fails any dashboard that charts
  `requestUrl`, `uri`, `tid`, `tenant`, `tenant_id`, `request_id`, `principal_id` or `sid`.

## Error tracking, from the logs

An **error group** is (service, exception class, operation or route, SQLSTATE), over lines at `level="ERROR"`. The
Errors dashboard lists each group with its count, first seen and last seen (and the release, where a service logs
one), the groups new in the last 24 hours (`… unless … offset 1d`), the groups spiking now, and a trend per service.
In production the same groups come from a log-based counter in each project, with new-group and spike alerts
(tpa-platform's monitoring module).

**Why not GlitchTip or Sentry.** tpa-platform, records-service and auth-notary deliberately log only an exception's
class (records adds the SQLSTATE and constraint name): never a message and never a stack trace, because a trace can
contain a row. A Sentry-style tool is valuable exactly because it collects stack traces, local variables, request
bodies and breadcrumbs, which those rules ban. Stripped far enough to be safe, it would hold nothing the logs don't,
and it would still cost a new service and database, an SDK in every repo, a contract revision and, if hosted, a
vendor needing a BAA. Google Error Reporting needs stack traces for the same reason. To get Sentry's "where" with no
PHI, docs/REQUESTS.md asks the TPA repos for a fourth exception fact: the innermost first-party frame as
`module:function:line`.

## Production

- **TPA projects.** Alerts are Cloud Monitoring alert policies, not Grafana alerting, so they keep working when
  Grafana scales to zero. They live in tpa-platform's `infra/modules/monitoring/` (log-based metrics, alert policies,
  uptime checks, notification channels), because tpa-platform is the only place GCP resources in the TPA projects are
  applied from. This repo holds no Terraform and no deploy identity. Nothing is applied yet.
- **Hosted Grafana.** [cloud/](cloud/) is the production image: Grafana 12 pinned by digest, signed in only by the
  IAP assertion on `watch.${domain}` for `grp-platform`, reading Cloud Monitoring for the app, crm and phi projects.
  It stays a laptop artifact until the owner rules on the class 3 request
  `trellis-security/requests/2026-09-24-watchtower-to-tpa-platform-hosted-grafana-iap.md`. See
  [cloud/README.md](cloud/README.md).

## Fly paging

The production BodyF1rst apps run on Fly. Their paging is Cloud Monitoring uptime checks in the existing
`bodyf1rst-prod` project, created by [scripts/fly-uptime-checks.sh](scripts/fly-uptime-checks.sh):

- body-match checks on `https://bodyf1rst-network.fly.dev/api/v1/health` (`"database": true`) and
  `https://bodyf1rst-portal.fly.dev/` (the page title), from three US regions every minute;
- one alert policy per check, urgent (text, Slack and email), firing when 2 of the 3 regions fail;
- email and SMS channels from `--email` and `--sms` (or `TW_ALERT_EMAIL` and `TW_ALERT_SMS`). The Slack channel is an
  existing one passed by id (`--slack-channel`); the script never creates one and never handles a token.

The script is a dry run by default and prints every `gcloud` call. `--apply` runs them, skipping anything whose
`trellis-watchtower:` display name already exists, and it never touches the old watchtower's checks. **Running it
with `--apply` needs the owner's OK.** The SMS channel must be verified in the console before it delivers. forge is
private on Fly, so Fly metrics are its only production signal. Fly production errors are not covered yet.
