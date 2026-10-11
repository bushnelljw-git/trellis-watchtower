# trellis-watchtower, production form: a stateless Grafana that reads Cloud Monitoring for the TPA app, crm, phi and
# call-centre projects, reached only through IAP on watch.${domain} (the owner ruled yes, 2026-10-11; the cloud half
# is tpa-platform's: see README.md).
#
# Build context is this directory (cloud/). tpa-platform's pipeline builds it from a trellis-watchtower commit pinned
# in releases/<id>.json and promotes it by digest; this repository holds no deploy identity.
#
# No plugins: GF_INSTALL_PLUGINS is never set, the plugin catalogue is off and Grafana 12's plugin preinstall is
# disabled in grafana.ini. Only the core stackdriver (Cloud Monitoring) datasource is used.
FROM grafana/grafana:12.4.11@sha256:3ea272e5cab64a4a62240c682e2c62433b25614d956d44c299a10cb6994f6f2e

COPY --chown=472:0 grafana.ini /etc/grafana/grafana.ini
COPY --chown=472:0 provisioning/ /etc/grafana/provisioning/
# The dashboards as committed, with a project placeholder in every query; render-dashboards.sh writes them into
# /var/lib/grafana/dashboards with this environment's project ids before Grafana starts.
COPY --chown=472:0 dashboards/*.json /etc/grafana/dashboards/
COPY --chmod=0555 render-dashboards.sh /usr/local/bin/render-dashboards

ENV GF_PATHS_CONFIG=/etc/grafana/grafana.ini \
    GF_PATHS_PROVISIONING=/etc/grafana/provisioning \
    GF_INSTALL_PLUGINS=""

USER 472
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/render-dashboards"]
