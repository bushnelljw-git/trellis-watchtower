# trellis-watchtower: the local monitoring stack (docs/SPEC.md W1 + W2).
#
#   make up            start (adds profile db when .env has both DSNs)
#   make up TPA_NET=1  also attach tw-blackbox to tpa-net (MANUAL opt-in; read
#                      the warning in compose.tpa-net.yml; `make up` detaches)
#   make down          stop this project only (volumes kept)
#   make check         validate every config with the pinned images
#   make probe-check   probe_success per stack/service/probe
#   make scrub-check   replay the log fixtures through Alloy, assert clean
#   make stub-test     negative test of the database body-match probes
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

# The pinned image of a compose service, read from compose.yml (one source).
img = $$($(CHECK_ENV) $(COMPOSE) -f compose.yml --profile db --profile test config --format json | jq -r '.services["$(1)"].image')

.PHONY: help up down check lint probe-check scrub-check stub-test disk-guard

help:
	@sed -n '3,11p' Makefile | sed 's/^# \{0,1\}//'

disk-guard:
	@free=$$(docker run --rm $(call img,stub) df -Pm / | awk 'NR==2{print $$4}'); \
	if [ "$$free" -lt "$(MIN_FREE_MB)" ]; then \
	  echo "refusing: the Docker VM has $${free} MB free (< $(MIN_FREE_MB) MB). It is shared with the live :4310 stack; free space first."; exit 1; \
	else echo "docker VM free: $${free} MB"; fi

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
	@echo "== bash -n scripts"
	@for s in scripts/*.sh; do bash -n "$$s" || exit 1; done && echo "   ok"
	@$(MAKE) --no-print-directory lint

lint:
	@echo "== dashboard lint"
	@python3 scripts/dashboard_lint.py
	@python3 -m unittest discover -s tests/dashboards -q

probe-check:
	@./scripts/probe_check.sh

scrub-check:
	@./scripts/scrub_check.sh

stub-test:
	@./scripts/stub_test.sh
