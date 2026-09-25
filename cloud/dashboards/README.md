# Cloud dashboards (not written yet)

The production dashboards go here as `*.json`, baked into the image and loaded read-only by
`provisioning/dashboards/dashboards.yml`. They come later, once the metric names in tpa-platform's monitoring module
(`infra/modules/monitoring/`, docs/SPEC.md P1) are final, so that no dashboard is written against a guessed name.

Rules they follow, the same as the local ones: uids `tw-<name>`, datasource uids `cloud-app`, `cloud-crm` and
`cloud-phi` only, and `scripts/dashboard_lint.py` (which already scans this folder) must pass.
