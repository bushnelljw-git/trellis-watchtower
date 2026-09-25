# cloud/: the production Grafana image (a laptop artifact for now)

This folder is the source of trellis-watchtower's production form: one stateless Grafana on Cloud Run in the TPA app
project, reading Cloud Monitoring for the app, crm and phi projects, and reached only through IAP on `watch.${domain}`
by `grp-platform`.

**Status: it stays on this laptop.** Nothing here is built, pushed or deployed until the owner rules on the class 3
request `trellis-security/requests/2026-09-24-watchtower-to-tpa-platform-hosted-grafana-iap.md`. That request covers
the IAP exception to `edge.md` §6, the new service and its identity (`sa-watchtower`), the read into the PHI project's
monitoring across the perimeter (`ing-watch`), and the contract and service-graph revisions. A relayed "the owner said
yes" is not a ruling.

## What is here

| File | What it does |
|---|---|
| `Dockerfile` | `grafana/grafana:12.4.11` pinned by digest, config and provisioning baked in, no plugins. Build context is `cloud/`. |
| `grafana.ini` | Sign-in by the IAP assertion only (`[auth.jwt]` on `X-Goog-Iap-Jwt-Assertion`, Google's IAP JWKS, `aud` and `iss` checked, email claim, auto sign-up as Viewer). Login form, basic auth and anonymous access off. No initial admin. Alerting, snapshots, public dashboards, plugin downloads, update checks and reporting off. |
| `provisioning/datasources/cloud-monitoring.yml` | Three Cloud Monitoring datasources, `cloud-app`, `cloud-crm` and `cloud-phi`, using the attached identity (`authenticationType: gce`). `cloud-phi` works only once the `ing-watch` rule exists. |
| `provisioning/dashboards/dashboards.yml` | The file provider: dashboards from `/etc/grafana/dashboards`, read-only in the UI. |
| `dashboards/` | Empty for now (see below). |

## The environment the service sets

None of these is a secret. The image holds no secret at all.

| Variable | Value |
|---|---|
| `WATCH_HOST` | `watch.<domain>` |
| `IAP_AUDIENCE` | `/projects/<project number>/global/backendServices/<bes-watch id>` (a tpa-platform output) |
| `TPA_APP_PROJECT_ID`, `TPA_CRM_PROJECT_ID`, `TPA_PHI_PROJECT_ID` | the three project ids |

Grafana listens on 8080, Cloud Run's default. Its sqlite state is on the container's own disk and is disposable:
there is no Grafana alerting (production alerts are Cloud Monitoring alert policies, owned by tpa-platform's
monitoring module), dashboards and datasources come from files, and users are re-created from the IAP assertion.

## How it would ship

tpa-platform's pipeline builds this folder from a trellis-watchtower commit pinned in `releases/<id>.json` and
promotes the image by `@sha256:` digest, like every other image. trellis-watchtower gets no WIF access and holds no
Terraform. The Cloud Run service, `sa-watchtower`, IAP, the Cloud Armor policy and the IAM rows are all tpa-platform's
(`docs/SPEC.md` P3).

## Dashboards come later

The cloud dashboards are written once the metric names in tpa-platform's monitoring module (P1) are final, so no
dashboard is written against a guessed name. They go in `dashboards/` as `*.json`, and `scripts/dashboard_lint.py`
already scans that folder and allows exactly the datasource uids declared in `provisioning/datasources/`.

## Checking it on a laptop

```bash
tag="trellis-watchtower-cloud:check-$(openssl rand -hex 4)"
docker build -t "$tag" cloud/
# optional: start it with no network and confirm it refuses everything without an IAP assertion
docker run --rm -d --name "${tag//[:]/-}" --network none \
  -e WATCH_HOST=watch.example.invalid -e IAP_AUDIENCE=/projects/0/global/backendServices/0 \
  -e TPA_APP_PROJECT_ID=a -e TPA_CRM_PROJECT_ID=c -e TPA_PHI_PROJECT_ID=p "$tag"
docker exec "${tag//[:]/-}" wget -q -S -O /dev/null http://127.0.0.1:8080/api/search   # 401 Unauthorized
docker stop "${tag//[:]/-}"; docker image rm "$tag"
```

Never push it, and never reuse a tag another project uses.
