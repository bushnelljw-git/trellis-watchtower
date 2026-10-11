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

# The image runs as 10001:10001, the uid and gid tpa-platform's shared builder requires of every image it builds
# (its canonical step refuses any other configured user), not the base's grafana user (472, in group root). That user
# has no passwd entry and needs none: Grafana reads no name for it, and run.sh sets HOME to GF_PATHS_HOME.
#
# Config, provisioning, the dashboards as committed and the entrypoint are root's and read-only: Grafana can change
# none of them. It writes exactly two places:
#   /var/lib/grafana   (GF_PATHS_DATA) 10001's own, 0700: the disposable sqlite, the plugins folder (empty: core
#                      plugins only) and the dashboards render-dashboards.sh writes there at start, with each query's
#                      project and this environment's settings;
#   /tmp               the base's 1777, unchanged: render-dashboards.sh's scratch folder (mktemp -d), removed again
#                      before Grafana starts.
# Everything else the base leaves world-writable (its logs folder, unused with console logging; the AWS credentials
# folder, unused; /var/tmp) is root's and closed here, so nothing else in the image is writable by 10001.
USER root
COPY grafana.ini /etc/grafana/grafana.ini
COPY provisioning/ /etc/grafana/provisioning/
COPY dashboards/*.json /etc/grafana/dashboards/
COPY dashboards/no-cc/*.json /etc/grafana/dashboards/no-cc/
COPY render-dashboards.sh /usr/local/bin/render-dashboards
RUN chown -R root:root /etc/grafana /usr/local/bin/render-dashboards /var/log/grafana /usr/share/grafana/.aws \
 && chmod -R a-w,a+rX /etc/grafana \
 && chmod 0555 /usr/local/bin/render-dashboards /var/log/grafana /usr/share/grafana/.aws \
 && chmod 0755 /var/tmp \
 && chown -R 10001:10001 /var/lib/grafana \
 && chmod -R u=rwX,go= /var/lib/grafana

ENV GF_PATHS_CONFIG=/etc/grafana/grafana.ini \
    GF_PATHS_DATA=/var/lib/grafana \
    GF_PATHS_PLUGINS=/var/lib/grafana/plugins \
    GF_PATHS_PROVISIONING=/etc/grafana/provisioning \
    GF_INSTALL_PLUGINS=""

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/render-dashboards"]
