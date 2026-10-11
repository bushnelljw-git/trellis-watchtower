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

# Config, provisioning, the dashboards as committed and the entrypoint are root's and read-only: the Grafana process
# (uid 472) reads them and can change none of them. It writes only /var/lib/grafana: its disposable sqlite and the
# dashboards render-dashboards.sh writes there at start, with each query's project and this environment's settings.
USER root
COPY grafana.ini /etc/grafana/grafana.ini
COPY provisioning/ /etc/grafana/provisioning/
COPY dashboards/*.json /etc/grafana/dashboards/
COPY dashboards/no-cc/*.json /etc/grafana/dashboards/no-cc/
COPY render-dashboards.sh /usr/local/bin/render-dashboards
RUN chown -R root:root /etc/grafana /usr/local/bin/render-dashboards \
 && chmod -R a-w,a+rX /etc/grafana \
 && chmod 0555 /usr/local/bin/render-dashboards

ENV GF_PATHS_CONFIG=/etc/grafana/grafana.ini \
    GF_PATHS_PROVISIONING=/etc/grafana/provisioning \
    GF_INSTALL_PLUGINS=""

USER 472
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/render-dashboards"]
