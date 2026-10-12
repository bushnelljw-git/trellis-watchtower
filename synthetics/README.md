# synthetics: the sign-in journeys

The runner for bodyfirst `tasks/reliability/SYNTHETICS-DESIGN.md` §3 (piece 4): a standard-library Python package
and its image. tpa-platform runs it as one Cloud Run job per journey on Cloud Scheduler (piece 5), and its log
metric `synthetic_results` reads the one line each run writes. There is no phone-call journey: the owner answered
Q4 "No" (design §9).

```
python -I -m synthetics journey <staff-sign-in|ops-desk|crm> [--no-iap]
```

## The journeys

Each is a fixed list of steps that stops at the first failure. One password and one TOTP code per run, never
retried (auth accepts a TOTP step once and charges a refused code to the lockout budget). Past the sign-in everything
is a read.

**Every run that got a session signs out, whatever ends it.** The session counts as signed in the moment auth's
session cookie arrives in the jar (for J3, the moment the CRM's bearer is read), before anything reads the response.
From then on any exception, a failed check or a bug, sends the sign-out before it propagates; the `logout` step runs
once, after the reads succeed, and is never repeated. The sign-out has its own budget, `min(step timeout, 10 s)`,
outside the run's deadline, so a run that spent its deadline on a hung step still ends its session.

**The network warm-up, `egress`, comes first.** Each run is a new Cloud Run task, and its Direct VPC egress goes out
through Cloud NAT, which drops replies for the first 30 to 60 s or more of a task's life. Google says so ("With Cloud
NAT, you might experience cold start delays of 30s or more on instance startup",
https://docs.cloud.google.com/run/docs/configuring/vpc-direct-vpc) and tells an egress check like this one to retry.
On beta (2026-10-12) every run's first HTTPS step timed out at 15 s; with 60 s step timeouts a run passed in full, its
first connection reaching the load balancer 20 s and 28 s after the task started, and one later fresh connection
still took 35.7 s (7.2 s in another task) before every request settled at 70 to 300 ms. So after `config`, and before
`secrets`, `iap_token` or any request, `egress` opens a fresh TCP connection to each host and port the journey will
use (`SYNTHETICS_BASE_URL`'s, and J1's `SYNTHETICS_PORTAL_BASE_URL`'s, once when they are the same; not the metadata
server's, which is not behind NAT) and closes it at once. Not a byte is sent: no TLS, no HTTP, no credential, and no
proxy. Each name is resolved once with getaddrinfo, IPv4 and IPv6 alike, and its addresses are tried in order as the
client tries them (a name that does not resolve is a failed attempt, resolved again the next round). Each attempt has
3 s and the rounds are 1 s apart; a host and port is ready after two fresh connections in a row (a success then a
failure starts it over), and the step ends when every one is. Many short attempts, never one long connect: Linux backs
off a connect's SYN retries (0, 1, 3, 7, 15, 31, 63 s), which can leave one waiting from 31 s to 63 s on a path that
came up in between. The warm-up has its own budget, `SYNTHETICS_EGRESS_WAIT_S` (default 120 s): the run's deadline
starts when it ends, and the step timeouts are unchanged. Its time is `steps_ms.egress` on every run (about 1 s when
the path is already up: two connections, a round apart), so the cold delays can be watched. When the budget runs out
the run is `error` / `egress` at step `egress` (exit 1): the robot could not reach the edge, so it checked nothing,
and that is no verdict on the service. Nothing but the configuration is read before it (the credentials come after).
A paused run writes its `skipped` line at once, before any warm-up (tpa-platform's runbook relies on it); J3
switched off, a bad setting and `SYNTHETICS_EGRESS_WAIT_S=0` do no warm-up either, and none records an `egress`.

| Job | Severity (design §5) | Steps, in order |
|---|---|---|
| `staff-sign-in` (J1) | CRITICAL | `config`, `egress`, `secrets`, `iap_token`; on the ops host: `ops_shell` (`GET /ops/`, 200 with `<base href="/ops/">`), `ops_release` (`GET /ops/release.json`, a JSON object), `login` (`POST /auth/login`, a challenge offering `totp`), `mfa_verify` (`POST /auth/mfa/verify`, which must set `__Host-tpa-session` and `__Host-tpa-csrf`), `me` (`GET /auth/me`), `desk_version` (`GET /tpa/api/v1/desk/cases/version`, counts only, reaches tpa-db), `logout` (`POST /auth/logout` with `X-CSRF-Token`, 204); then on the portal host: `portal_shell` (`GET /tpa/`, 200 with `<base href="/tpa/">`) |
| `ops-desk` (J2) | CRITICAL | `config`, `egress`, `secrets`, `iap_token`, `login`, `mfa_verify`, `live_queue` (`GET /tpa/api/v1/live/queue`, the non-touching snapshot through svc-ops), `desk_version_employers` (`GET /tpa/api/v1/desk/cases/version?scope=employers`), `logout` |
| `crm` (J3) | WARNING | Only with `SYNTHETICS_CRM_ENABLED=true`; otherwise `skipped` / `not_configured` at once, reading nothing and sending nothing. Switched on: `config`, `egress`, `secrets`, `iap_token`, `crm_shell` (`GET /`, `<base href="/">`), `login` (`POST /api/v1/auth/login`, `mfa_required` with method `totp`), `mfa_verify` (`POST /api/v1/auth/mfa/verify`, a bearer token), `me` (`GET /api/v1/auth/me` with that bearer in `Authorization`; a tripwire as well: it must name exactly one business, as `role` `member` with `partner_id` null and no Lattice `roles`, whose `tenant_id` is a UUID, or the robot has been widened and the run fails `shape`), `crm_tenant` (`GET /api/v1/tenants/current` with that id in `X-Tenant-Id`: the portal's boot read, through membership and row security to crm-db, read-only), `logout` (`POST /api/v1/auth/logout`). A `login` that hands back a token with no second factor (the login lost it) is `fail` / `shape`, and that token is signed out too. One session can escape sign-out: a `mfa_verify` whose answer outlasts the step timeout (`timeout`) was minted by the CRM but never read, so J3 holds no bearer to end it; it lives the CRM's thirty days (read-only, no book), and the CRM's `seed-synthetic-rotate` ends every session the login has. The login is the CRM's own (bodyf1rst-network `engine/app/synthetic_login.py`: `synthetic-crm@synthetic.invalid`, a read-only `member` with no book; `seed-crm --args=seed-synthetic` writes `synthetic-crm-credentials`) |

Every request carries `Sec-Fetch-Site: same-origin`; every write carries `Origin`. No redirect is followed. No proxy
from the environment is used.

## The result line

Exactly one line per run on stdout, compact JSON, keys in this order, and nothing on stderr (argparse's usage on a
bad command line is the one exception, with exit 2 and no line). `tests/synthetics/test_result.py` pins these five
lines byte for byte (a pass, a failed check, a broken runner, a warm-up that ran out, a skip), and checks this file
still carries them:

```
{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"staff-sign-in","outcome":"pass","code":"ok","step":"none","status_class":"2xx","elapsed_ms":5222,"steps_ms":{"config":0,"egress":1012,"secrets":0,"iap_token":38,"ops_shell":61,"ops_release":22,"login":180,"mfa_verify":96,"me":41,"desk_version":133,"logout":35,"portal_shell":58}}
{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"ops-desk","outcome":"fail","code":"status","step":"live_queue","status_class":"5xx","elapsed_ms":16031,"steps_ms":{"config":0,"egress":1009,"secrets":0,"iap_token":40,"login":171,"mfa_verify":90,"live_queue":15001}}
{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"staff-sign-in","outcome":"error","code":"runner","step":"login","status_class":"none","elapsed_ms":1223,"steps_ms":{"config":0,"egress":1011,"secrets":0,"iap_token":41,"ops_shell":60,"ops_release":21,"login":88}}
{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"ops-desk","outcome":"error","code":"egress","step":"egress","status_class":"none","elapsed_ms":120004,"steps_ms":{"config":0,"egress":120003}}
{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"crm","outcome":"skipped","code":"not_configured","step":"none","status_class":"none","elapsed_ms":0,"steps_ms":{}}
```

| Field | Values |
|---|---|
| `severity`, `level` | `INFO` for a pass or a skip, `ERROR` for a failure or an error. Both: Cloud Logging lifts `severity` into the entry's severity; `level` is tpa-platform's own line field |
| `message` | always `synthetic_result` (the metric's filter) |
| `job` | `staff-sign-in`, `ops-desk`, `crm` |
| `outcome` | the journey's verdict, `pass`, `fail` or `skipped`; or `error` when the runner itself broke and there is no verdict |
| `code` | a pass is `ok`; a skip is `paused` or `not_configured`; an error is `config` (a missing or bad setting, or a credentials file that is unreadable, not a regular file or malformed), `egress` (the warm-up's budget ran out before two fresh connections in a row reached every host: the job's own network path, Cloud NAT's cold start, not the site), `iap_token` (the metadata server gave no token: the job's own environment, not the site) or `runner` (an unexpected exception: a bug in the runner); a failure is one of `iap` (IAP refused: a response with `X-Goog-IAP-Generated-Response: true`, a redirect to Google's sign-in, or a 401 or 403 on a shell step), `connect`, `tls`, `timeout`, `redirect` (any other 3xx), `status` (an unexpected status), `credentials` (a 401 at `login` or `mfa_verify`), `locked` (423), `rate_limited` (429), `csrf` (logout refused with a 403, or no CSRF cookie to send), `shape` (a 2xx without what the step needs, a body that is not the JSON object expected, or JSON nested too deep) |
| `step` | `none` for a pass or a skip; for a failure the step it failed at, for an error the step it broke in (`none` if before any): `config`, `egress`, `secrets`, `iap_token`, `ops_shell`, `ops_release`, `crm_shell`, `login`, `mfa_verify`, `me`, `crm_tenant`, `desk_version`, `live_queue`, `desk_version_employers`, `logout`, `portal_shell` |
| `status_class` | the failing response's class, or the last response's on a pass: `2xx`, `3xx`, `4xx`, `5xx`, or `none` (no response: a skip, a transport failure, a timeout, a body that outlasted its step) |
| `elapsed_ms` | the whole run, whole milliseconds (it includes the warm-up and a wait of up to 8 s for a fresh TOTP step) |
| `steps_ms` | each step that ran, in order, whole milliseconds |

**For the tpa-platform lane:** the metric's labels are `job`, `outcome`, `code` and `status_class`, all on
docs/infra/monitoring.md §2's closed list. `step` and `steps_ms` are fields only; `step` is not on that list, so
making it a label is a contract change there. Every value above comes from a closed list in `result.py` and the
renderer refuses anything else, so no id, URL, address, token, cookie, code, password, body or exception text can
reach the line.

**Exit status** (the orchestrator's ruling by delegation, 2026-10-11, following design §3):

- **0 whenever the journey ran to a verdict**: `pass`, `fail` or `skipped`. The result line alone drives
  `synthetic-failing`, so a site that fails a check never fails the job too.
- **1 only when the runner itself broke**: an `error` line (`config`, `egress`, `iap_token` or `runner`), or the line
  could not be written at all. So `jobs-failed` keeps meaning "the job is broken", and one failure never pages twice.
- **2** on a bad command line (argparse; no line, as no journey was named).

A wrong credentials *version* (a valid file, the wrong password) is a verdict: `fail` / `credentials` at `login`,
exit 0, which is design §7's proof of `synthetic-failing`. A malformed or missing file is the runner's `error` /
`config`.

## What the job sets

| Environment | J1 | J2 | J3 | Value |
|---|---|---|---|---|
| `SYNTHETICS_BASE_URL` | yes | yes | yes | the ops host's origin (J1, J2), the CRM host's (J3): `https://host`, no path. **J1 and J2: it must equal auth's `AUTH_PUBLIC_ORIGIN`** (beta's `local.browser_origin`, the ops host unless `single_origin = "portal"`): auth's CSRF check refuses a write whose `Origin` is not that origin, so any other host fails every run at `logout` with `csrf` |
| `SYNTHETICS_PORTAL_BASE_URL` | yes | | | the portal host's origin (the same as the ops host's while it is single-origin, until R183) |
| `SYNTHETICS_EMAIL` | yes | yes | yes | `synthetic-staff@<org_domain>`, `synthetic-desk@<org_domain>`, and for J3 exactly `synthetic-crm@synthetic.invalid` (the CRM's own constant, `SYNTHETIC_EMAIL`) |
| `SYNTHETICS_CREDENTIALS_FILE` | yes | yes | yes | the path the credentials secret is mounted at |
| `SYNTHETICS_IAP_AUDIENCE` | yes | yes | yes | `var.iap_oauth_client_id`, R298's External client (no `programmatic_clients` entry, per the design) |
| `SYNTHETICS_PAUSED` | | | | `true` while a needed database is stopped: `skipped` / `paused` at once, before the warm-up, nothing sent. A second guard beside the paused schedule |
| `SYNTHETICS_CRM_ENABLED` | | | yes | `true` once the CRM's beta copy has run `seed-synthetic` and the secret's version is pinned; anything else is `not_configured` |
| `SYNTHETICS_STEP_TIMEOUT_S` | | | | per request, default 15, at most 60 |
| `SYNTHETICS_EGRESS_WAIT_S` | yes | yes | yes | the warm-up's own budget: `120` (the default; at most 180, and `0` skips the warm-up). Spent before the deadline starts |
| `SYNTHETICS_DEADLINE_S` | | | | the rest of the run, from the warm-up's end: default 90, at most 100. The sign-out's own budget (at most 10 s) comes on top, so the job's `task_timeout` (300 s) must hold all three |
| `SYNTHETICS_CA_FILE` | | | | local only: the one CA to trust (the cloud uses the system store) |
| `SYNTHETICS_METADATA_HOST` | | | | tests only: the fake metadata server. Unset in the cloud. With IAP on it may only be `metadata.google.internal` or a loopback host (`error` / `config` otherwise), so the token is never asked of another host |

**The secrets** (design §3): `synthetic-staff-credentials` (J1), `synthetic-desk-credentials` (J2), and the CRM
lane's `synthetic-crm-credentials` (J3), each one version, mounted as a file pinned to
`var.synthetic_credentials_versions` (never `latest`), holding exactly

```
{"password": "...", "totp_secret": "<base32>"}
```

`sa-synthetics` is their one accessor. The file is read once per run; its values live in memory only and are never
printed. It must be a regular file (checked on the open descriptor, opened non-blocking, so a FIFO or a device
never hangs the run). A missing, unreadable, non-regular, oversized or malformed file (JSON nested too deep
included), an empty password or a TOTP secret that is not base32 is `error` / `config` at step `secrets` (exit 1).

**The job:** args `["journey", "<name>"]`; `task_timeout` 300 s, which holds the warm-up's budget, the deadline and
the sign-out's budget together (220 s with the defaults, 290 s at most; the 120 s it had before the warm-up would cut
a slow warm-up off with no result line); `max_retries` 0 (a retry would replay a TOTP step); egress only to the edge
addresses (the metadata server is always reachable).

## IAP, programmatically

- **The token.** `GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=<SYNTHETICS_IAP_AUDIENCE>&format=full`
  with `Metadata-Flavor: Google`: Cloud Run's metadata server, as the job's own service account, never through a
  proxy. It must answer 200 with a JWT; anything else is `error` / `iap_token` (exit 1: the job's environment, not
  the site). One token per run, used for both hosts.
- **The header.** `Proxy-Authorization: Bearer <token>` on every request to the edge, and `Authorization` left empty
  (J1, J2), so auth never reads Google's token as a session bearer (AN-01). Google's programmatic-access page
  ("Authenticating from a service account", `docs.cloud.google.com/iap/docs/authentication-howto`, read
  2026-10-11): "If a valid ID token is found in a `Proxy-Authorization` header, IAP authorizes the request with it.
  After authorizing the request, IAP passes the `Authorization` header to your application without processing the
  content." That is what J3 relies on: IAP's token in `Proxy-Authorization`, the CRM's bearer in `Authorization`.
- **Unverified:**
  - Whether IAP removes a *valid* `Proxy-Authorization` before the backend. The page says it strips the header
    when it finds no valid token there, and is silent on the valid case. If web or the CRM sees it, add it to web's
    strip list (design §3, class 1).
  - The same page tells you to add the OAuth client to the application's programmatic-access allowlist. The design
    reads R298's External client (IAP's own client on these backends) as needing no `programmatic_clients` entry.
    The first beta run settles it: a 401 at `ops_shell` with code `iap` means the entry is needed.
  - `X-Goog-IAP-Generated-Response: true` on IAP's own refusals, which `iap` uses. A 401 or 403 on a shell step is
    read as `iap` either way.

## The image

`synthetics/Dockerfile`, built from the repository root (its last step bind-mounts `scripts/image_strip.py`), with
`synthetics/Dockerfile.dockerignore` keeping the context to the modules and the strip script:

- `python:3.12-slim` pinned by digest (tpa-platform's Python images' digest);
- the modules copied straight into site-packages, root's and read-only (no pip, no lock: standard library only);
- `scripts/image_strip.py`, byte for byte tpa-platform's (`tests/synthetics/test_image_policy.py` pins its sha256),
  as the last build step: no shell, package manager, network tool, perl, Python installer or setuid program;
- `USER 10001:10001`; `ENTRYPOINT ["python", "-I", "-m", "synthetics"]`; no CMD.

No scan exception is needed: tpa-platform's images on the same base pass its gate with none, and
`security/scan-exceptions.yaml`'s entries are Grafana's.

**For tpa-platform's builder** (piece 5, class 2): a `cloudbuild/pipeline.py` row
`"watchtower-synthetics": Service("trellis-watchtower", "synthetics/Dockerfile", ".", "trellis-watchtower/watchtower-synthetics", "trellis-watchtower")`,
and `scripts/image_start_check.sh`'s case
`watchtower-synthetics) source=".sources/trellis-watchtower"; dockerfile="synthetics/Dockerfile"; context="."; sources=""; package="synthetics" ;;`.
Its generic Python path then fits as it is: the configured user is 10001:10001, `id -u` and `id -g` say 10001 with no
network, and `python -I -c "import synthetics"` imports (importing does nothing).

`make synthetics-image-check` is this repository's own proof of the same: it builds the image, checks the user, `id`,
the import, the CA bundle and that no shell starts, then runs the entrypoint offline (paused and J3 off: `skipped`,
exit 0; no network and a 2 s warm-up: `error` / `egress`, exit 1; no metadata server, the warm-up off: `error` /
`iap_token`, exit 1; no configuration: `error` / `config`, exit 1; no arguments: exit 2) and removes the image.

## Locally

The :4310 stack has no IAP, so `--no-iap` runs without a token or `Proxy-Authorization`, and refuses any base URL that
is not a loopback host. With a seeded `ops_agent` (auth-notary's `auth seed`: the shared seed password and
`SEED_TOTP_SECRET`) in a mode-600 credentials file:

```
SYNTHETICS_BASE_URL=https://localhost:4310 SYNTHETICS_PORTAL_BASE_URL=https://localhost:4310 \
SYNTHETICS_EMAIL=ops_agent.second@example.test SYNTHETICS_CREDENTIALS_FILE=<file> \
SYNTHETICS_CA_FILE="$(mkcert -CAROOT)/rootCA.pem" \
python3 -m synthetics journey staff-sign-in --no-iap
```

Wait out the account's last TOTP step first (30 s since its last sign-in), or auth refuses the code as a replay.

## Tests

`make synthetics-test` (part of `make check`): the journeys against a local fake of the metadata server, IAP, auth,
tpa-api and the CRM (`tests/synthetics/synthetic_fakes.py`): a pass, each step failing, IAP's refusals, redirects,
timeouts (a stall, a body trickled a byte every 0.3 s, a spent deadline), dropped connections, TLS, JSON nested too
deep, configuration (a credentials file that is a folder, a FIFO or a device; a metadata host that is not Google's or
loopback), pausing, J3's flag, the warm-up (ready only after two fresh connections in a row to every host and port, a
success then a failure starting over; its budget spent before anything is read or sent, and its bounds; `0` and a
pause doing none; the run's deadline starting after it; a name that does not resolve tried again; not a byte sent),
J3's business read (the id `me` names, sent as `X-Tenant-Id` only when it is a UUID) and a CRM login that answers the
password alone; the sign-out sent after any exception once signed in, with its own budget, and never repeated; the
exit status of a failed check (0), and of a broken configuration, a warm-up that ran out, a metadata server with no
token, a runner crash and an unwritable line (1); RFC 6238's vectors; the golden lines; every code and outcome
against the metric's own extractors (the vendored catalogue's); the result line's labels against tpa-platform's own
allowlist (`tests/synthetics/tpa_metric_labels.txt`, vendored with its commit and blob, and re-read from the sibling
checkout when there is one); the image's policy, read statically; and no secret on stdout or stderr on any path,
in-process and through the real entry point.
