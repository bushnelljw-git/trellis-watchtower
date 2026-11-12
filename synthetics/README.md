# synthetics: the sign-in journeys

The runner for bodyfirst `tasks/reliability/SYNTHETICS-DESIGN.md` §3 (piece 4), and for the two sign-in robots of
bodyfirst `tasks/signin-robots/` (ruling SR-OR-1, phase 1): a Python package on the standard library and one
hash-locked package (`cryptography`, the member robot's passkey signer), and its image. tpa-platform runs it as one
Cloud Run job per journey on Cloud Scheduler (piece 5), and its log metric `synthetic_results` reads the one line each
run writes. There is no phone-call journey: the owner answered Q4 "No" (design §9).

```
python -I -m synthetics journey <staff-sign-in|ops-desk|crm|member-sign-in|broker-sign-in> [--no-iap]
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

**Every connection is dialled, and every request is written once.** The warm-up is not always enough. On beta
(2026-10-12, the runner at `6d652f6`, `task_timeout` 300 s, `SYNTHETICS_EGRESS_WAIT_S=120`) `staff-sign-in` passed
(`egress` 22133 ms, then every step fast), but `ops-desk`'s `egress` took 38070 ms, its `login` reached the load
balancer in 264 ms, and its `mfa_verify` then timed out at 15016 ms on a connection the load balancer never saw. A
fresh connection can still be dropped for a while after the warm-up (the diagnosis saw one take 35.7 s in one task
and 7.2 s in another, quiet about 60 s after the task started), and the client opens a new connection for every
request. So each request's TCP connection is tried with a fresh socket, at most 3 s an attempt and 0.5 s apart, until
one connects or the step's time is spent, as tpa-platform's jobs do since its P121. An attempt resolves the name
(getaddrinfo, which no timeout bounds) and tries its addresses in turn, all inside the attempt's 3 s; the connected
socket's timeout is then what the step has left, for the answer. Then the request is written, once: http.client
writes nothing before the connection is made, and nothing after that is tried again, so `login`, `mfa_verify` and
`logout` are each sent at most once, whatever their answer. A step whose time runs out fails as before, `timeout`
after attempts that timed out and `connect` after refusals; a name that never resolves now spends the step, then
fails `connect`. TLS is not retried: its handshake runs once on the connected socket, so a certificate refusal is
`tls` at once. `mfa_verify` never outlives its code: auth and the CRM accept a code for the rest of its step and one
step more (at least 38 s, as it is minted with 8 s left), and that caps the request's budget, so a connection made
too late fails `timeout` rather than sending a stale code that costs a lockout strike. It can bind only when
`SYNTHETICS_STEP_TIMEOUT_S` is above 38.

| Job | Severity (design §5) | Steps, in order |
|---|---|---|
| `staff-sign-in` (J1) | CRITICAL | `config`, `egress`, `secrets`, `iap_token`; on the ops host: `ops_shell` (`GET /ops/`, 200 with `<base href="/ops/">`), `ops_release` (`GET /ops/release.json`, a JSON object), `login` (`POST /auth/login`, a challenge offering `totp`), `mfa_verify` (`POST /auth/mfa/verify`, which must set `__Host-tpa-session` and `__Host-tpa-csrf`), `me` (`GET /auth/me`), `desk_version` (`GET /tpa/api/v1/desk/cases/version`, counts only, reaches tpa-db), `logout` (`POST /auth/logout` with `X-CSRF-Token`, 204); then on the portal host: `portal_shell` (`GET /tpa/`, 200 with `<base href="/tpa/">`) |
| `ops-desk` (J2) | CRITICAL | `config`, `egress`, `secrets`, `iap_token`, `login`, `mfa_verify`, `live_queue` (`GET /tpa/api/v1/live/queue`, the non-touching snapshot through svc-ops), `desk_version_employers` (`GET /tpa/api/v1/desk/cases/version?scope=employers`), `logout` |
| `member-sign-in` | CRITICAL (SR-OR-1: p1 at two failed runs and no pass in 11 minutes) | No IAP: the public portal, as a member's browser. `config`, `egress`, `secrets` (the member secret, below, its passkey on this run's portal), `portal_shell` (`GET /tpa/`, 200 with `<base href="/tpa/">` and exactly one `<script src="main-….js">`), `portal_release` (`GET /tpa/release.json`, whose `release` every later request sends as `X-Client-Release`), `portal_bundle` (`GET /tpa/main-….js`, 200, JavaScript, not empty; only its first 512 KiB is read), `login` (`POST /auth/login {email, password, audience: "member"}`, a challenge offering `webauthn` whose `webauthn.rpId` is the passkey's), `mfa_verify` (`POST /auth/mfa/verify {challenge_id, assertion}`: the assertion signed with the passkey, below; it must set `__Host-tpa-session` and `__Host-tpa-csrf` and answer `audience` `member`), `me` (`GET /auth/me`, the tripwire below), `logout` (`POST /auth/logout` with `X-CSRF-Token`, 204). Nothing past `/auth/me`: no records read, no member page (phase 1) |
| `broker-sign-in` | CRITICAL (the same) | The same steps, with `audience: "broker"`, a challenge offering `totp`, and `mfa_verify` sending `{challenge_id, code}`: one authenticator code of a fresh step (below) |
| `crm` (J3) | WARNING | Only with `SYNTHETICS_CRM_ENABLED=true`; otherwise `skipped` / `not_configured` at once, reading nothing and sending nothing. Switched on: `config`, `egress`, `secrets`, `iap_token`, `crm_shell` (`GET /`, `<base href="/">`), `login` (`POST /api/v1/auth/login`, `mfa_required` with method `totp`), `mfa_verify` (`POST /api/v1/auth/mfa/verify`, a bearer token), `me` (`GET /api/v1/auth/me` with that bearer in `Authorization`; a tripwire as well: it must name exactly one business, as `role` `member` with `partner_id` null and no Lattice `roles`, whose `tenant_id` is a UUID, or the robot has been widened and the run fails `shape`), `crm_tenant` (`GET /api/v1/tenants/current` with that id in `X-Tenant-Id`: the portal's boot read, through membership and row security to crm-db, read-only), `logout` (`POST /api/v1/auth/logout`). A `login` that hands back a token with no second factor (the login lost it) is `fail` / `shape`, and that token is signed out too. One session can escape sign-out: a `mfa_verify` whose answer outlasts the step timeout (`timeout`) was minted by the CRM but never read, so J3 holds no bearer to end it; it lives the CRM's thirty days (read-only, no book), and the CRM's `seed-synthetic-rotate` ends every session the login has. The login is the CRM's own (bodyf1rst-network `engine/app/synthetic_login.py`: `synthetic-crm@synthetic.invalid`, a read-only `member` with no book; `seed-crm --args=seed-synthetic` writes `synthetic-crm-credentials`) |

Every request carries `Sec-Fetch-Site: same-origin`; every write carries `Origin`. No redirect is followed. No proxy
from the environment is used.

## The sign-in robots

A member robot and a broker robot sign in to the public portal every five minutes exactly as a browser does, check
who they are at `/auth/me`, and sign out (ruling SR-OR-1, phase 1; bodyfirst `tasks/signin-robots/PLAN.md` "Phase
1", `SPEC.md` §2, §4.5 and §6, `SECURITY-REVIEW.md`). Their session reaches `/auth/me` and `/auth/logout` alone, so
they read no data.

- **No IAP, one portal.** The robots never ask the metadata server for a token and never send
  `Proxy-Authorization`, with or without `--no-iap`. Their origin, `SYNTHETICS_PORTAL_ORIGIN`, must be exactly
  production's portal, `https://portal.trellistpa.com` (`journeys.PRODUCTION_PORTAL_ORIGIN`, in the code and never
  taken from the environment); with `--no-iap` (the local mode) it must be a loopback origin instead. Any other
  origin is `error` / `config` before anything is read or sent (SR-11: a run started with other settings cannot
  carry the robots' secrets to another host). A new portal host is a change here and a new image.
- **The address is the secret's alone** (SR-01, blocker B1). The robots read their email from their secret, never
  from `SYNTHETICS_EMAIL`, and a robot job that sets it refuses to run (`config`).
- **The broker's code is never one an earlier run spent** (SR-16). auth accepts each 30-second step once per
  account and refuses any step at or below the last it accepted, as a wrong code charged to the factor lockout. So
  the broker never sends the step that is current when it asks: after `login` it always waits for the next step to
  begin (0.2 s into it; up to 30.2 s, inside the run's deadline) and sends that step's code (`totp.fresh`). A run
  that starts after an earlier run sent its code asks later than that code's step began, so it can never send it,
  whether the earlier run was the schedule's, one started by hand or a retry; the code then has at least 59.8 s of
  accepted life. When the deadline cannot hold the wait, the run fails `timeout` at `mfa_verify` with no wait and
  no code sent. A broker job with more than one task (`CLOUD_RUN_TASK_COUNT` other than 1) refuses to run
  (`config`), since parallel tasks would wait for the same step. Two executions started within one wait can still
  meet: auth refuses the second, which fails `credentials` (one factor failure; SR-16, accepted). The staff
  journeys' rule (`totp.mint`, at least 8 s left) is unchanged.
- **The member's passkey is signed by `cryptography`, never by hand** (SR-13, blocker B7; `passkey.py`, the only
  module that imports it). The key is auth's software passkey, made and registered by auth's attended job
  (auth-notary `auth/domain/synthetic.py`, `_enrol_a_passkey`; `auth/domain/credentials/webauthn.py`,
  `software_registration`). The assertion (WebAuthn L3 §7.2, client side): `authenticatorData` = SHA-256(rpId) ||
  flags `0x1D` (UP, UV, BE, BS: the flags the key was registered with, since auth refuses a BE other than the one it
  stored) || sign count `00000000` (zero for ever: auth admits zero against zero, and a count that did not strictly
  rise would read as a cloned key and revoke it); `clientDataJSON` =
  `{"type":"webauthn.get","challenge":<the login's>,"origin":<the portal origin>,"crossOrigin":false}`; the
  signature ECDSA P-256 with SHA-256 over `authenticatorData` || SHA-256(`clientDataJSON`), DER; the
  `PublicKeyCredential` JSON `{id, rawId, type: "public-key", authenticatorAttachment: "platform", response:
  {clientDataJSON, authenticatorData, signature, userHandle}, clientExtensionResults: {}}`, every bytes field
  base64url without padding. `userHandle` is sent because the login offers no credential list.
- **`/auth/me` is a tripwire, not only a read** (J3's rule). It must name exactly one tenant of kind `tpa`, the
  robot's one role (`member` or `broker`), `audience` its hat, `acr` `aal2` or `aal3`, `current_tid` that tenant,
  `must_replace` not true, and no `staff` object. A second tenant, a role beside or instead of the hat's, a tenant of
  another kind, or `sso` (TPA sign-in for the CRM) is `fail` / `widened`: the run stops there and signs out. Anything
  else off that shape is `shape`. A session wearing a hat shows that hat's role alone, so another role on the login
  itself is held by auth's database (SR-OR-1), not seen here.
- **Switched off is no verdict.** While Sign-in checks is off, auth answers the robot's `login` (or `mfa_verify`,
  if it flips between them) `403 denied` with `decision.reason` `sign_in_checks_off` (`journeys.SIGN_IN_CHECKS_OFF`,
  the one place the runner spells it; a `403` whose `error.code` is that word reads the same). The run is `skipped`
  / `disabled`, exit 0, and pages nothing. Any other `403` at sign-in (`audience_not_held`, `member_access_ended`)
  is `fail` / `denied`.
- **Never retried.** One password and one second factor per run; every request is written once (the dialled
  connection, above, is a TCP connect, never a request sent again); the sign-out is always tried once a session
  cookie is in the jar, whatever ended the run; the job runs with `max_retries` 0.

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

The sign-in robots' four, pinned the same way (a member's pass, a broker switched off, a member whose `/auth/me`
named more than its hat, a passkey the runner could not sign):

```
{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"member-sign-in","outcome":"pass","code":"ok","step":"none","status_class":"2xx","elapsed_ms":2310,"steps_ms":{"config":0,"egress":1008,"secrets":3,"portal_shell":58,"portal_release":21,"portal_bundle":44,"login":402,"mfa_verify":231,"me":38,"logout":30}}
{"severity":"INFO","level":"INFO","message":"synthetic_result","job":"broker-sign-in","outcome":"skipped","code":"disabled","step":"none","status_class":"none","elapsed_ms":1561,"steps_ms":{"config":0,"egress":1007,"secrets":0,"portal_shell":61,"portal_release":20,"portal_bundle":40,"login":398}}
{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"member-sign-in","outcome":"fail","code":"widened","step":"me","status_class":"2xx","elapsed_ms":2287,"steps_ms":{"config":0,"egress":1010,"secrets":3,"portal_shell":57,"portal_release":22,"portal_bundle":43,"login":405,"mfa_verify":229,"me":36}}
{"severity":"ERROR","level":"ERROR","message":"synthetic_result","job":"member-sign-in","outcome":"error","code":"passkey","step":"mfa_verify","status_class":"none","elapsed_ms":1989,"steps_ms":{"config":0,"egress":1009,"secrets":3,"portal_shell":59,"portal_release":21,"portal_bundle":42,"login":401,"mfa_verify":1}}
```

| Field | Values |
|---|---|
| `severity`, `level` | `INFO` for a pass or a skip, `ERROR` for a failure or an error. Both: Cloud Logging lifts `severity` into the entry's severity; `level` is tpa-platform's own line field |
| `message` | always `synthetic_result` (the metric's filter) |
| `job` | `staff-sign-in`, `ops-desk`, `crm`, `member-sign-in`, `broker-sign-in` |
| `outcome` | the journey's verdict, `pass`, `fail` or `skipped`; or `error` when the runner itself broke and there is no verdict |
| `code` | a pass is `ok`; a skip is `paused`, `not_configured` or `disabled` (a sign-in robot refused because Sign-in checks is switched off); an error is `config` (a missing or bad setting, or a credentials file that is unreadable, not a regular file or malformed), `passkey` (the member robot could not sign its assertion: the runner's own fault), `egress` (the warm-up's budget ran out before two fresh connections in a row reached every host: the job's own network path, Cloud NAT's cold start, not the site), `iap_token` (the metadata server gave no token: the job's own environment, not the site) or `runner` (an unexpected exception: a bug in the runner); a failure is one of `iap` (IAP refused: a response with `X-Goog-IAP-Generated-Response: true`, a redirect to Google's sign-in, or a 401 or 403 on a shell step), `connect`, `tls`, `timeout`, `redirect` (any other 3xx), `status` (an unexpected status), `credentials` (a 401 at `login` or `mfa_verify`), `locked` (423), `rate_limited` (429), `csrf` (logout refused with a 403, or no CSRF cookie to send), `shape` (a 2xx without what the step needs, a body that is not the JSON object expected, or JSON nested too deep), `denied` (a sign-in robot's `login` or `mfa_verify` refused with a 403 for any reason but the switch), `widened` (a sign-in robot's `/auth/me` names more than its one hat role: a second tenant, another role, another kind of tenant, or `sso`) |
| `step` | `none` for a pass or a skip; for a failure the step it failed at, for an error the step it broke in (`none` if before any): `config`, `egress`, `secrets`, `iap_token`, `ops_shell`, `ops_release`, `crm_shell`, `login`, `mfa_verify`, `me`, `crm_tenant`, `desk_version`, `live_queue`, `desk_version_employers`, `logout`, `portal_shell`, `portal_release`, `portal_bundle` |
| `status_class` | the failing response's class, or the last response's on a pass: `2xx`, `3xx`, `4xx`, `5xx`, or `none` (no response: a skip, a transport failure, a timeout, a body that outlasted its step) |
| `elapsed_ms` | the whole run, whole milliseconds (it includes the warm-up and the TOTP wait: up to 8 s for a staff journey, up to 30.2 s for the broker robot, which is in no step's time) |
| `steps_ms` | each step that ran, in order, whole milliseconds |

**For the tpa-platform lane:** the metric's labels are `job`, `outcome`, `code` and `status_class`, all on
docs/infra/monitoring.md §2's closed list. `step` and `steps_ms` are fields only; `step` is not on that list, so
making it a label is a contract change there. Every value above comes from a closed list in `result.py` and the
renderer refuses anything else, so no id, URL, address, token, cookie, code, password, body or exception text can
reach the line.

**Exit status** (the orchestrator's ruling by delegation, 2026-10-11, following design §3):

- **0 whenever the journey ran to a verdict**: `pass`, `fail` or `skipped`. The result line alone drives
  `synthetic-failing`, so a site that fails a check never fails the job too.
- **1 only when the runner itself broke**: an `error` line (`config`, `egress`, `iap_token`, `runner` or `passkey`),
  or the line could not be written at all. So `jobs-failed` keeps meaning "the job is broken", and one failure never pages twice.
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
| `SYNTHETICS_EGRESS_WAIT_S` | yes | yes | yes | the warm-up's own budget: `120` (the default; at most 170, and `0` skips the warm-up). Spent before the deadline starts |
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

**The sign-in robots' jobs** (tpa-platform's T2: `synthetics-member-sign-in` at `*/5` and
`synthetics-broker-sign-in` at `2-59/5`, as `sa-signin-robots`, so the metric's `job_name=~"^synthetics-"` holds them):

| Environment | Value |
|---|---|
| `SYNTHETICS_PORTAL_ORIGIN` | exactly `https://portal.trellistpa.com` (any other value refuses to run) |
| `SYNTHETICS_CREDENTIALS_FILE` | the path the robot's secret is mounted at, pinned by version, never `latest` |
| `SYNTHETICS_EGRESS_WAIT_S`, `SYNTHETICS_STEP_TIMEOUT_S`, `SYNTHETICS_DEADLINE_S`, `SYNTHETICS_PAUSED` | as for J1 to J3 (the defaults are 120, 15 and 90 s) |
| `SYNTHETICS_EMAIL` | **never set** (the address is the secret's alone; a robot job that sets it refuses to run) |
| `SYNTHETICS_IAP_AUDIENCE`, `SYNTHETICS_METADATA_HOST`, `SYNTHETICS_BASE_URL`, `SYNTHETICS_PORTAL_BASE_URL` | not read |

Their secrets, `signin-robot-member-credentials` and `signin-robot-broker-credentials`, written by auth's attended job
alone, each a JSON object of **exactly** these keys (any other key, a missing one, or the other robot's shape is
`error` / `config` at `secrets`):

```
broker: {"email": "<address>", "password": "<password>", "totp_secret": "<base32>"}
member: {"email": "<address>", "password": "<password>",
         "passkey": {"credential_id": "<base64url>", "origin": "https://portal.trellistpa.com",
                     "private_jwk": {"crv": "P-256", "d": "<base64url>", "kty": "EC", "x": "<base64url>", "y": "<base64url>"},
                     "rp_id": "portal.trellistpa.com", "user_handle": "<base64url>"}}
```

The member's `passkey` is exactly what auth's `_enrol_a_passkey` writes today (`Values.payload()`, keys sorted,
compact), registered on the public origin's relying party: its `origin` must equal `SYNTHETICS_PORTAL_ORIGIN` and its
`rp_id` that origin's host; the JWK's public point must be the private scalar's. The email is a plain address (one
`@`, no space, at most 254 characters). Values live in memory for the run; nothing is logged, put in an argument or
written anywhere. `tests/synthetics/fixtures/member-credentials.json` is a test key in that shape, made as auth's job
makes one (its `member-registration.json` beside it is the registration auth would store).

The robots' args are `["journey", "member-sign-in"]` and `["journey", "broker-sign-in"]` (no `--no-iap`: that is the
local mode, loopback only); the rest as below (`task_timeout` 300 s, `max_retries` 0, egress only to the portal's
load balancer on 443).

**The job:** args `["journey", "<name>"]`; `task_timeout` 300 s, which holds the warm-up's budget, the deadline and
the sign-out's budget together (220 s with the defaults, 280 s at most, leaving 20 s for what no budget bounds: one
name lookup at the warm-up's end, the task's own start; the 120 s it had before the warm-up would cut a slow warm-up
off with no result line); `max_retries` 0 (a retry would replay a TOTP step); egress only to the edge addresses (the
metadata server is always reachable).

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

- `python:3.12-slim` pinned by digest (tpa-platform's Python images' digest), for both stages;
- **one third-party package**, `cryptography` 50.0.1, and the two it requires (`cffi` 2.1.1, `pycparser` 3.0):
  `synthetics/requirements.lock` holds auth-notary's own lock entries for the three byte for byte (an exact `==` and
  every sha256; `tests/synthetics/test_image_policy.py` holds them to auth's pinned blob, and to its origin/master
  when a sibling checkout is there). The build stage `deps` installs them with `--require-hashes --only-binary :all:
  --no-deps --target /deps`, wheels alone and nothing the lock does not name; the image copies `/deps` into
  site-packages and runs `pip check` before the strip. The runner imports it in `passkey.py` alone. Moving it (a fix
  in the library) is copying auth's three entries again, and a rebuild;
- the modules copied straight into site-packages, root's and read-only;
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

The sign-in robots on :4310, once auth's attended job has made them there (their secrets in mode-600 files):

```
SYNTHETICS_PORTAL_ORIGIN=https://localhost:4310 SYNTHETICS_CREDENTIALS_FILE=<file> \
SYNTHETICS_CA_FILE="$(mkcert -CAROOT)/rootCA.pem" \
python3 -m synthetics journey member-sign-in --no-iap
```

(the member's passkey must be registered on `https://localhost:4310`, rp `localhost`; the broker waits for a fresh
step, up to 30 s). The interpreter needs the lock's packages: `make synthetics-test`'s virtualenv has them.

## Tests

`make synthetics-test` (part of `make check`) runs them with a virtualenv of the lock's three packages, made with the
same `--require-hashes --only-binary :all: --no-deps` and `pip check`, outside every workspace folder
(`~/.cache/trellis-watchtower/synthetics-venv-<the lock's sha256>`, `SYNTHETICS_VENV` to move it), so a moved lock is a
new one. The sign-in robots: each step failing; the portal's shell, release and script; switched off (`disabled`, at
`login` and at `mfa_verify`, in either spelling); every other refusal (`denied`); the tripwire (`widened` and
`shape`); a key auth does not hold, the wrong password and seed (`credentials`); a signature that cannot be made
(`passkey`); the origin pinned (production's alone in the cloud, loopback alone locally); the address only in the
secret; each robot's exact secret; the broker's fresh step (two runs back to back never send one code twice, and the
fake refuses a replayed step as auth does); a deadline that cannot hold the wait; one task only; no IAP, ever; the
passkey signed and verified against the public key auth would store (`test_passkey.py`: the registration fixture's
attestation, read with the fakes' own CBOR reader, and the verifier written apart from the runner; checked once by
hand against auth-notary's own `verify_registration` and `verify_assertion` on py_webauthn 3.0.0). The rest: the
journeys against a local fake of the metadata server, IAP, auth, tpa-api and the CRM
(`tests/synthetics/synthetic_fakes.py`): a pass, each step failing, IAP's refusals, redirects,
timeouts (a stall, a body trickled a byte every 0.3 s, a spent deadline), dropped connections, TLS, JSON nested too
deep, configuration (a credentials file that is a folder, a FIFO or a device; a metadata host that is not Google's or
loopback), pausing, J3's flag, the warm-up (ready only after two fresh connections in a row to every host and port, a
success then a failure starting over; its budget spent before anything is read or sent, and its bounds; `0` and a
pause doing none; the run's deadline starting after it; a name that does not resolve tried again; not a byte sent),
connections dialled again after timeouts and refusals with each request still sent once, no sign-in, code or sign-out
sent twice when its answer hangs or its connection drops, each attempt cut to what the step has left and shared
across the name's addresses, which are tried in turn, a 3.5 s answer inside a 5 s step, a connection made too late
closed, `mfa_verify` never past its code's accepted life (J2 and J3), and a TLS failure never dialled again, J3's
business read (the id `me` names, sent as `X-Tenant-Id` only when it is a UUID) and a CRM login that answers the
password alone; the sign-out sent after any exception once signed in, with its own budget, and never repeated; the
exit status of a failed check (0), and of a broken configuration, a warm-up that ran out, a metadata server with no
token, a runner crash and an unwritable line (1); RFC 6238's vectors; the golden lines; every code and outcome
against the metric's own extractors (the vendored catalogue's); the result line's labels against tpa-platform's own
allowlist (`tests/synthetics/tpa_metric_labels.txt`, vendored with its commit and blob, and re-read from the sibling
checkout when there is one); the image's policy, read statically; and no secret on stdout or stderr on any path,
in-process and through the real entry point.
