# Cloud dashboards

The production dashboards, baked into the image and loaded read-only. **Generated: do not edit the JSON.** Edit
`scripts/cloud_dashboards.py`, run `make cloud-dashboards`, and commit both; `make lint` fails a hand edit.

Each query names its datasource's project as a placeholder (`__TPA_APP_PROJECT_ID__`, ...), which
`cloud/render-dashboards.sh` fills in when the container starts. What the pages show, how the queries are written and
the rules they keep are in [../README.md](../README.md#the-dashboards).
