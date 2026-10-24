# trellis-watchtower: the local monitoring stack (docs/SPEC.md W1 + W2).
#
#   make up            start (adds profile db when .env has both DSNs)
#   make up TPA_NET=1  also attach tw-blackbox to tpa-net (MANUAL opt-in; read
#                      the warning in compose.tpa-net.yml; `make up` detaches)
#   make down          stop this project only (volumes kept)
#   make check         validate every config with the pinned images (and lint)
#   make lint          dashboard lint, the cloud dashboards against the vendored
#                      catalogue, the render script, the PagerDuty scripts
#   make cloud-dashboards  regenerate cloud/dashboards/*.json
#   make cloud-catalogue [CATALOGUE_REF=origin/master] re-vendor tpa-platform's catalogue from ../tpa-platform's
#                      committed CATALOGUE_REF (fetch there first), regenerate the dashboards, run make lint
#   make cloud-image-check build cloud/ under a throwaway tag, run it with no
#                      network, check it, send every dashboard query, remove it
#   make probe-check   probe_success per stack/service/probe
#   make scrub-check   replay the log fixtures through Alloy, assert clean
#   make stub-test     negative test of the database body-match probes
#   make pagerduty-test  the PagerDuty scripts against local fakes (also run by check)
#   make pagerduty-plan  pd_setup.py dry run against the live PagerDuty account (reads only)
#   make synthetics-test the synthetic journeys against local fakes (also run by check)
#   make synthetics-image-check build synthetics/'s image under a throwaway tag, check it as
#                      tpa-platform's builder does, run it offline, remove it
#
# Every docker compose call names this project's own file, so nothing here can
# act on another project's containers.

SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE := docker compose
# compose.yml requires GRAFANA_ADMIN_PASSWORD; `check` must not need .env.
CHECK_ENV := GRAFANA_ADMIN_PASSWORD=$${GRAFANA_ADMIN_PASSWORD:-check-only}
FILES := -f compose.yml $(if $(filter 1,$(TPA_NET)),-f compose.tpa-net.yml)
DB_PROFILE := $(shell grep -qE '^PG_DSN_NETWORK=.+' .env 2>/dev/null && grep -qE '^PG_DSN_FORGE=.+' .env 2>/dev/null && echo --profile db)
# The Docker VM disk is shared with the live :4310 stack. The images here are
# about 2 GB; refuse to start below this much free space.
MIN_FREE_MB ?= 4096
# Building cloud/ compiles Grafana's Go binaries (cloud/Dockerfile): one compile
# alone (aws-sdk-go-v2's ec2) peaks near 3 GB and the link near 1.7 GB, with
# others beside them, and the module and build caches take some 8 GB of disk
# while it runs. The VM's memory is shared with the live :4310 stack too; refuse
# below this much available rather than let its OOM killer choose.
MIN_BUILD_MEM_MB ?= 6144
MIN_BUILD_FREE_MB ?= 12288

# The pinned image of a compose service, read from compose.yml (one source).
img = $$($(CHECK_ENV) $(COMPOSE) -f compose.yml --profile db --profile test config --format json | jq -r '.services["$(1)"].image')

.PHONY: help up down check lint probe-check scrub-check stub-test disk-guard build-guard pagerduty-test pagerduty-plan cloud-dashboards cloud-catalogue cloud-image-check synthetics-test synthetics-image-check

help:
	@sed -n '3,23p' Makefile | sed 's/^# \{0,1\}//'

disk-guard:
	@free=$$(docker run --rm $(call img,stub) df -Pm / | awk 'NR==2{print $$4}'); \
	if [ "$$free" -lt "$(MIN_FREE_MB)" ]; then \
	  echo "refusing: the Docker VM has $${free} MB free (< $(MIN_FREE_MB) MB). It is shared with the live :4310 stack; free space first."; exit 1; \
	else echo "docker VM free: $${free} MB"; fi

# cloud-image-check's build: available memory and free disk, both in the Docker VM.
build-guard:
	@avail=$$(docker run --rm $(call img,stub) awk '/MemAvailable/ {print int($$2/1024)}' /proc/meminfo); \
	free=$$(docker run --rm $(call img,stub) df -Pm / | awk 'NR==2{print $$4}'); \
	if [ "$$avail" -lt "$(MIN_BUILD_MEM_MB)" ] || [ "$$free" -lt "$(MIN_BUILD_FREE_MB)" ]; then \
	  echo "refusing: building cloud/ compiles Grafana, which needs $(MIN_BUILD_MEM_MB) MB of memory available and $(MIN_BUILD_FREE_MB) MB of disk free in the Docker VM; it has $${avail} MB and $${free} MB, shared with the live :4310 stack."; exit 1; \
	else echo "docker VM: $${avail} MB of memory available, $${free} MB of disk free"; fi

up: disk-guard
	@test -f .env || { echo "no .env: copy .env.example to .env and fill it in"; exit 1; }
	@mkdir -p .fixtures-run grafana/dashboards
	@$(if $(filter 1,$(TPA_NET)),echo "WARNING: tw-blackbox joins tpa-net; peers' 'docker compose down' cannot remove tpa-net while it is attached. Run 'make up' (no TPA_NET) to detach.")
	$(COMPOSE) $(FILES) $(DB_PROFILE) up -d

down:
	$(COMPOSE) -f compose.yml --profile db --profile test down

check: disk-guard
	@echo "== docker compose config (all files, all profiles)"
	@$(CHECK_ENV) $(COMPOSE) -f compose.yml -f compose.tpa-net.yml --profile db --profile test config -q && echo "   ok"
	@echo "== promtool check config"
	@docker run --rm -v "$(CURDIR)/prometheus:/etc/prometheus:ro" --entrypoint promtool $(call img,prometheus) check config /etc/prometheus/prometheus.yml
	@echo "== promtool check rules"
	@docker run --rm -v "$(CURDIR)/prometheus:/etc/prometheus:ro" --entrypoint sh $(call img,prometheus) -c 'promtool check rules /etc/prometheus/rules/*.yml'
	@echo "== promtool test rules"
	@docker run --rm -v "$(CURDIR):/w:ro" --entrypoint promtool $(call img,prometheus) test rules /w/tests/prometheus/rules_test.yml
	@echo "== blackbox --config.check"
	@docker run --rm -v "$(CURDIR)/blackbox:/etc/blackbox_exporter:ro" $(call img,blackbox) --config.file=/etc/blackbox_exporter/blackbox.yml --config.check 2>&1 | grep -q 'Config file is ok' && echo "   ok"
	@echo "== alloy fmt --test, alloy validate"
	@docker run --rm -v "$(CURDIR)/alloy:/etc/alloy:ro" $(call img,alloy) fmt --test /etc/alloy/config.alloy && echo "   fmt ok"
	@docker run --rm -v "$(CURDIR)/alloy:/etc/alloy:ro" $(call img,alloy) validate /etc/alloy/config.alloy && echo "   validate ok"
	@echo "== loki -verify-config"
	@docker run --rm -v "$(CURDIR)/loki:/etc/loki:ro" $(call img,loki) -config.file=/etc/loki/loki-config.yml -verify-config && echo "   ok"
	@echo "== bash -n scripts, sh -n cloud/render-dashboards.sh"
	@for s in scripts/*.sh; do bash -n "$$s" || exit 1; done && sh -n cloud/render-dashboards.sh && echo "   ok"
	@$(MAKE) --no-print-directory lint

lint:
	@echo "== dashboard lint"
	@python3 scripts/dashboard_lint.py
	@python3 -m unittest discover -s tests/dashboards -q
	@echo "== cloud dashboards: the vendored catalogue, the datasources, the render script"
	@python3 -m unittest discover -s tests/cloud -q
	@$(MAKE) --no-print-directory pagerduty-test
	@$(MAKE) --no-print-directory synthetics-test

cloud-dashboards:
	@python3 scripts/cloud_dashboards.py

# The catalogue the cloud dashboards are checked against, from a tpa-platform checkout's committed CATALOGUE_REF
# (never its working tree): vendor it, write the dashboards it moves (its lines, its names), then every check.
TPA_PLATFORM ?= ../tpa-platform
CATALOGUE_REF ?= origin/master
cloud-catalogue:
	@./scripts/vendor_catalogue.sh "$(TPA_PLATFORM)" "$(CATALOGUE_REF)"
	@python3 scripts/cloud_dashboards.py
	@$(MAKE) --no-print-directory lint

cloud-image-check: disk-guard build-guard
	@./scripts/cloud_image_check.sh

pagerduty-test:
	@echo "== pagerduty scripts (local fakes only)"
	@python3 -m unittest discover -s tests/pagerduty -q

pagerduty-plan:
	@python3 scripts/pagerduty/pd_setup.py

synthetics-test:
	@echo "== synthetics (local fakes only)"
	@python3 -m unittest discover -s tests/synthetics -q

synthetics-image-check: disk-guard
	@./scripts/synthetics_image_check.sh

probe-check:
	@./scripts/probe_check.sh

scrub-check:
	@./scripts/scrub_check.sh

stub-test:
	@./scripts/stub_test.sh
