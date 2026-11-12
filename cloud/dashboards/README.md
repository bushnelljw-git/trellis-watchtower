# Cloud dashboards

The production dashboards, baked into the image and loaded read-only. **Generated: do not edit the JSON.** Edit
`scripts/cloud_dashboards.py`, run `make cloud-dashboards`, and commit both; `make lint` fails a hand edit.

`no-cc/` holds the pages with a call-centre part written again without it. `render-dashboards.sh` uses them, and leaves
out the pages that read the call centre alone, when the service has no call-centre project. `production/` holds the
overview, the Jobs page, Member records and Sign-in written again for production (the services, scheduled jobs and
counters production-full runs: no administrator-feed importer, no sign-in robots, no texted codes' delivery reads); `render-dashboards.sh` uses them whenever `TPA_ENVIRONMENT` is
production.

Two kinds of mark in the JSON are settled when the container starts (`cloud/render-dashboards.sh`):
- each query's project placeholder (`__TPA_APP_PROJECT_ID__`, ...);
- tokens (`@@R,...@@`, `@@F,...@@`, `@@E@@...`) for the tiles that read neutral while a job is not deployed or paused
  or a database is stopped, and for the uptime wording per environment;
- `"hide": "@@H,...@@"` on a sign-in robot's queries, settled to `true` (never sent) while the robot is not deployed.

What the pages show, how the queries are written and the rules they keep are in
[../README.md](../README.md#the-dashboards).
