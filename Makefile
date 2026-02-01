GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
CYAN   := \033[36m
RESET  := \033[0m
BOLD   := \033[1m

DOCKER_COMPOSE := docker compose --env-file $(CURDIR)/.env

.DEFAULT_GOAL := help

# ==================== Help ====================

help: ## Show this help message
	@echo ""
	@echo "$(BOLD)🌐 NIDS in a Box (NIB)$(RESET)"
	@echo "$(CYAN)One-command network security monitoring with Suricata IDS and CrowdSec$(RESET)"
	@echo ""
	@echo "$(BOLD)Usage:$(RESET)  make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-24s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ==================== Network ====================

network: ## Create shared Docker network
	@docker network inspect nib-network >/dev/null 2>&1 || \
		(docker network create nib-network && \
		echo "$(GREEN)✓ Created nib-network$(RESET)")

# ==================== Installation ====================

install: network ## Install all stacks (Suricata + CrowdSec + Storage + Grafana)
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)! No .env file found. Creating from .env.example...$(RESET)"; \
		cp .env.example .env; \
	fi
	@# Auto-generate Grafana password if needed
	@if grep -q 'GRAFANA_ADMIN_PASSWORD=CHANGE_ME\|GRAFANA_ADMIN_PASSWORD=$$' .env 2>/dev/null; then \
		NEW_PASS=$$(openssl rand -base64 18 | tr -d '/+=' | head -c 24); \
		if [ "$$(uname)" = "Darwin" ]; then \
			sed -i '' "s|GRAFANA_ADMIN_PASSWORD=.*|GRAFANA_ADMIN_PASSWORD=$$NEW_PASS|" .env; \
		else \
			sed -i "s|GRAFANA_ADMIN_PASSWORD=.*|GRAFANA_ADMIN_PASSWORD=$$NEW_PASS|" .env; \
		fi; \
		echo "$(GREEN)✓ Generated Grafana admin password$(RESET)"; \
		echo "  Password: $$NEW_PASS"; \
		echo "  (saved in .env)"; \
	fi
	@$(MAKE) --no-print-directory install-suricata
	@$(MAKE) --no-print-directory install-storage
	@$(MAKE) --no-print-directory install-crowdsec
	@$(MAKE) --no-print-directory install-grafana
	@echo ""
	@echo "$(GREEN)$(BOLD)✓ NIB installed successfully!$(RESET)"
	@echo ""
	@$(MAKE) --no-print-directory info

install-suricata: network ## Install Suricata IDS
	@echo "$(CYAN)Installing Suricata IDS...$(RESET)"
	@cp suricata/config/suricata.yaml suricata/config/active-suricata.yaml
	@$(MAKE) --no-print-directory update-rules
	@$(DOCKER_COMPOSE) -f suricata/compose.yaml up -d
	@echo "$(GREEN)✓ Suricata installed$(RESET)"

install-crowdsec: network ## Install CrowdSec (local bouncer or sensor mode via BOUNCER_MODE)
	@echo "$(CYAN)Installing CrowdSec...$(RESET)"
	@set -a; . ./.env 2>/dev/null || true; set +a; \
	BMODE=$${BOUNCER_MODE:-local}; \
	if [ "$$BMODE" = "sensor" ]; then \
		echo "$(YELLOW)  Sensor mode: no local bouncer, LAPI exposed for remote bouncers$(RESET)"; \
		$(DOCKER_COMPOSE) -f crowdsec/compose-sensor.yaml up -d; \
		echo "$(YELLOW)  Waiting for CrowdSec to initialize...$(RESET)"; \
		sleep 10; \
		echo "$(CYAN)  Generate a bouncer key for your router:$(RESET)"; \
		echo "    docker exec nib-crowdsec cscli bouncers add my-router -o raw"; \
		echo "  Then configure ROUTER_* variables in .env and run:"; \
		echo "    make router-sync"; \
	else \
		$(DOCKER_COMPOSE) -f crowdsec/compose.yaml up -d nib-crowdsec; \
		echo "$(YELLOW)  Waiting for CrowdSec to initialize...$(RESET)"; \
		sleep 10; \
		if grep -q 'CROWDSEC_BOUNCER_KEY=$$' .env 2>/dev/null; then \
			BOUNCER_KEY=$$(docker exec nib-crowdsec cscli bouncers add nib-firewall-bouncer -o raw 2>/dev/null || echo ""); \
			if [ -n "$$BOUNCER_KEY" ]; then \
				if [ "$$(uname)" = "Darwin" ]; then \
					sed -i '' "s|CROWDSEC_BOUNCER_KEY=.*|CROWDSEC_BOUNCER_KEY=$$BOUNCER_KEY|" .env; \
				else \
					sed -i "s|CROWDSEC_BOUNCER_KEY=.*|CROWDSEC_BOUNCER_KEY=$$BOUNCER_KEY|" .env; \
				fi; \
				echo "$(GREEN)  ✓ Generated bouncer API key$(RESET)"; \
			fi; \
		fi; \
		set -a; . ./.env 2>/dev/null || true; set +a; \
		CROWDSEC_LAPI_URL="http://$${CROWDSEC_API_BIND:-127.0.0.1}:$${CROWDSEC_API_PORT:-8080}"; \
		export CROWDSEC_LAPI_URL CROWDSEC_BOUNCER_KEY; \
		envsubst '$$CROWDSEC_LAPI_URL $$CROWDSEC_BOUNCER_KEY' < crowdsec/config/bouncer.yaml > crowdsec/config/active-bouncer.yaml; \
		$(DOCKER_COMPOSE) -f crowdsec/compose.yaml up -d; \
	fi
	@echo "$(GREEN)✓ CrowdSec installed$(RESET)"

install-storage: network ## Install VictoriaLogs + Vector log shipper
	@echo "$(CYAN)Installing storage stack...$(RESET)"
	@set -a; . ./.env 2>/dev/null || true; set +a; \
	PMODE=$${PRIVACY_MODE:-full}; \
	if [ "$$PMODE" = "alerts-only" ]; then \
		echo "$(YELLOW)  Privacy mode: alerts-only$(RESET)"; \
		echo "  Only IDS alerts + stats shipped to storage (DNS/HTTP/TLS/flow dropped)"; \
		echo "  App-layer fields stripped from alert events"; \
		echo "  $(YELLOW)Dashboards affected: DNS Analysis (empty), TLS & Fingerprints (empty)$(RESET)"; \
		cp storage/vector-privacy.yaml storage/active-vector.yaml; \
	else \
		cp storage/vector.yaml storage/active-vector.yaml; \
	fi
	@$(DOCKER_COMPOSE) -f storage/compose.yaml up -d
	@echo "$(GREEN)✓ Storage installed$(RESET)"

install-grafana: network ## Install Grafana dashboards
	@echo "$(CYAN)Installing Grafana...$(RESET)"
	@$(DOCKER_COMPOSE) -f grafana/compose.yaml up -d
	@echo "$(GREEN)✓ Grafana installed$(RESET)"

# ==================== Start / Stop / Restart ====================

start: ## Start all stacks
	@echo "$(CYAN)Starting NIB...$(RESET)"
	@$(DOCKER_COMPOSE) -f suricata/compose.yaml up -d
	@$(DOCKER_COMPOSE) -f storage/compose.yaml up -d
	@$(MAKE) --no-print-directory start-crowdsec
	@$(DOCKER_COMPOSE) -f grafana/compose.yaml up -d
	@echo "$(GREEN)✓ All stacks started$(RESET)"

stop: ## Stop all stacks
	@echo "$(CYAN)Stopping NIB...$(RESET)"
	@$(DOCKER_COMPOSE) -f grafana/compose.yaml down 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f crowdsec/compose.yaml down 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f crowdsec/compose-sensor.yaml down 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f storage/compose.yaml down 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f suricata/compose.yaml down 2>/dev/null || true
	@echo "$(GREEN)✓ All stacks stopped$(RESET)"

restart: stop start ## Restart all stacks

start-suricata: ## Start Suricata
	@$(DOCKER_COMPOSE) -f suricata/compose.yaml up -d

stop-suricata: ## Stop Suricata
	@$(DOCKER_COMPOSE) -f suricata/compose.yaml down

start-crowdsec: ## Start CrowdSec
	@set -a; . ./.env 2>/dev/null || true; set +a; \
	if [ "$${BOUNCER_MODE:-local}" = "sensor" ]; then \
		$(DOCKER_COMPOSE) -f crowdsec/compose-sensor.yaml up -d; \
	else \
		$(DOCKER_COMPOSE) -f crowdsec/compose.yaml up -d; \
	fi

stop-crowdsec: ## Stop CrowdSec
	@$(DOCKER_COMPOSE) -f crowdsec/compose.yaml down 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f crowdsec/compose-sensor.yaml down 2>/dev/null || true

start-storage: ## Start storage (VictoriaLogs + Vector)
	@$(DOCKER_COMPOSE) -f storage/compose.yaml up -d

stop-storage: ## Stop storage
	@$(DOCKER_COMPOSE) -f storage/compose.yaml down

start-grafana: ## Start Grafana
	@$(DOCKER_COMPOSE) -f grafana/compose.yaml up -d

stop-grafana: ## Stop Grafana
	@$(DOCKER_COMPOSE) -f grafana/compose.yaml down

# ==================== Uninstall ====================

uninstall: ## Uninstall all stacks and remove volumes
	@echo "$(RED)This will remove all NIB containers and data volumes.$(RESET)"
	@read -p "Are you sure? [y/N] " confirm && \
		[ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ] || (echo "Cancelled." && exit 1)
	@$(DOCKER_COMPOSE) -f grafana/compose.yaml down -v 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f crowdsec/compose.yaml down -v 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f crowdsec/compose-sensor.yaml down -v 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f storage/compose.yaml down -v 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f suricata/compose.yaml down -v 2>/dev/null || true
	@docker network rm nib-network 2>/dev/null || true
	@echo "$(GREEN)✓ NIB uninstalled$(RESET)"

# ==================== Status & Health ====================

status: ## Show status of all services
	@echo ""
	@echo "$(BOLD)🌐 NIB Status$(RESET)"
	@echo "$(CYAN)─────────────────────────────────────────$(RESET)"
	@printf "  $(BOLD)%-22s %-12s %s$(RESET)\n" "Service" "Status" "Health"
	@echo "$(CYAN)─────────────────────────────────────────$(RESET)"
	@for svc in nib-suricata nib-crowdsec nib-bouncer-firewall nib-victorialogs nib-vector nib-grafana; do \
		STATUS=$$(docker inspect --format='{{.State.Status}}' $$svc 2>/dev/null || echo "not found"); \
		HEALTH=$$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' $$svc 2>/dev/null || echo "n/a"); \
		if [ "$$STATUS" = "running" ]; then \
			if [ "$$HEALTH" = "healthy" ]; then \
				printf "  %-22s $(GREEN)%-12s$(RESET) $(GREEN)✓ %s$(RESET)\n" "$$svc" "$$STATUS" "$$HEALTH"; \
			elif [ "$$HEALTH" = "unhealthy" ]; then \
				printf "  %-22s $(GREEN)%-12s$(RESET) $(RED)✗ %s$(RESET)\n" "$$svc" "$$STATUS" "$$HEALTH"; \
			else \
				printf "  %-22s $(GREEN)%-12s$(RESET) $(YELLOW)- %s$(RESET)\n" "$$svc" "$$STATUS" "$$HEALTH"; \
			fi; \
		elif [ "$$STATUS" = "not found" ]; then \
			printf "  %-22s $(YELLOW)%-12s$(RESET) -\n" "$$svc" "not installed"; \
		else \
			printf "  %-22s $(RED)%-12s$(RESET) -\n" "$$svc" "$$STATUS"; \
		fi; \
	done
	@echo ""

health: ## Quick health check
	@echo "$(CYAN)Checking health...$(RESET)"
	@docker exec nib-suricata test -f /var/run/suricata/suricata.pid 2>/dev/null && \
		echo "  $(GREEN)✓$(RESET) Suricata running" || echo "  $(RED)✗$(RESET) Suricata not running"
	@docker exec nib-crowdsec cscli version >/dev/null 2>&1 && \
		echo "  $(GREEN)✓$(RESET) CrowdSec running" || echo "  $(RED)✗$(RESET) CrowdSec not running"
	@curl -sf http://localhost:$${VICTORIALOGS_PORT:-9428}/health >/dev/null 2>&1 && \
		echo "  $(GREEN)✓$(RESET) VictoriaLogs healthy" || echo "  $(RED)✗$(RESET) VictoriaLogs not healthy"
	@curl -sf http://localhost:$${GRAFANA_PORT:-3001}/api/health >/dev/null 2>&1 && \
		echo "  $(GREEN)✓$(RESET) Grafana healthy" || echo "  $(RED)✗$(RESET) Grafana not healthy"

info: ## Show endpoints and access info
	@echo ""
	@echo "$(BOLD)🌐 NIB Endpoints$(RESET)"
	@echo "$(CYAN)─────────────────────────────────────────$(RESET)"
	@set -a; . ./.env 2>/dev/null || true; set +a; \
	echo "  Grafana:        http://localhost:$${GRAFANA_PORT:-3001}"; \
	echo "  VictoriaLogs:   http://localhost:$${VICTORIALOGS_PORT:-9428}"; \
	echo "  CrowdSec API:   http://localhost:$${CROWDSEC_API_PORT:-8080}"; \
	echo ""; \
	echo "  Grafana user:   admin"; \
	echo "  Grafana pass:   $${GRAFANA_ADMIN_PASSWORD:-check .env}"; \
	echo ""

# ==================== Logs ====================

logs: ## Tail logs from all services
	@echo "$(CYAN)Tailing all logs (Ctrl+C to stop)...$(RESET)"
	@docker logs -f nib-suricata --tail 20 2>/dev/null &
	@docker logs -f nib-crowdsec --tail 20 2>/dev/null &
	@docker logs -f nib-vector --tail 20 2>/dev/null &
	@docker logs -f nib-grafana --tail 20 2>/dev/null &
	@wait

logs-suricata: ## Tail Suricata logs
	@docker logs -f nib-suricata --tail 50

logs-crowdsec: ## Tail CrowdSec logs
	@docker logs -f nib-crowdsec --tail 50

logs-vector: ## Tail Vector logs
	@docker logs -f nib-vector --tail 50

logs-grafana: ## Tail Grafana logs
	@docker logs -f nib-grafana --tail 50

logs-alerts: ## Tail Suricata alert log (fast.log)
	@docker exec nib-suricata tail -f /var/log/suricata/fast.log

# ==================== Shell Access ====================

shell-suricata: ## Shell into Suricata container
	@docker exec -it nib-suricata /bin/bash

shell-crowdsec: ## Shell into CrowdSec container
	@docker exec -it nib-crowdsec /bin/bash

shell-grafana: ## Shell into Grafana container
	@docker exec -it nib-grafana /bin/bash

# ==================== Suricata Rule Management ====================

update-rules: ## Download/update Suricata ET Open rules
	@echo "$(CYAN)Updating Suricata rules...$(RESET)"
	@curl -sSL https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz | \
		tar xz -C /tmp/
	@cp /tmp/rules/*.rules suricata/rules/suricata.rules 2>/dev/null || \
		cat /tmp/rules/*.rules > suricata/rules/suricata.rules
	@rm -rf /tmp/rules/
	@echo "$(GREEN)✓ Rules updated$(RESET)"
	@wc -l suricata/rules/suricata.rules | awk '{printf "  %s rules loaded\n", $$1}'

reload-rules: ## Reload Suricata rules without restart
	@echo "$(CYAN)Reloading Suricata rules...$(RESET)"
	@docker exec nib-suricata suricatasc -c "reload-rules" /var/run/suricata/suricata-command.socket
	@echo "$(GREEN)✓ Rules reloaded$(RESET)"

test-rules: ## Validate Suricata rule syntax
	@echo "$(CYAN)Testing rule syntax...$(RESET)"
	@docker exec nib-suricata suricata -T -c /etc/suricata/suricata.yaml 2>&1 | tail -5
	@echo "$(GREEN)✓ Rule test complete$(RESET)"

# ==================== CrowdSec Management ====================

decisions: ## List active CrowdSec decisions (bans)
	@docker exec nib-crowdsec cscli decisions list

alerts: ## List CrowdSec alerts
	@docker exec nib-crowdsec cscli alerts list

ban: ## Ban an IP (usage: make ban IP=1.2.3.4)
	@if [ -z "$(IP)" ]; then echo "$(RED)Usage: make ban IP=1.2.3.4$(RESET)"; exit 1; fi
	@docker exec nib-crowdsec cscli decisions add --ip $(IP) --duration 24h --reason "manual ban via NIB"
	@echo "$(GREEN)✓ Banned $(IP) for 24h$(RESET)"

unban: ## Unban an IP (usage: make unban IP=1.2.3.4)
	@if [ -z "$(IP)" ]; then echo "$(RED)Usage: make unban IP=1.2.3.4$(RESET)"; exit 1; fi
	@docker exec nib-crowdsec cscli decisions delete --ip $(IP)
	@echo "$(GREEN)✓ Unbanned $(IP)$(RESET)"

collections: ## List installed CrowdSec collections
	@docker exec nib-crowdsec cscli collections list

bouncer-status: ## Check firewall bouncer status
	@docker exec nib-crowdsec cscli bouncers list

metrics: ## Show CrowdSec metrics
	@docker exec nib-crowdsec cscli metrics

# ==================== Router Sync (Sensor Mode) ====================

router-sync: ## Sync CrowdSec decisions to router (one-shot)
	@./scripts/router-sync.sh

router-sync-dry-run: ## Dry-run router sync (show what would change)
	@./scripts/router-sync.sh --dry-run

router-sync-daemon: ## Sync CrowdSec decisions to router (continuous)
	@./scripts/router-sync.sh --daemon

add-router-bouncer: ## Generate a bouncer API key for your router
	@echo "$(CYAN)Generating bouncer key for router...$(RESET)"
	@KEY=$$(docker exec nib-crowdsec cscli bouncers add nib-router-bouncer -o raw 2>/dev/null); \
	if [ -n "$$KEY" ]; then \
		echo "$(GREEN)✓ Bouncer key: $$KEY$(RESET)"; \
		echo ""; \
		echo "  Add to .env:"; \
		echo "    CROWDSEC_LAPI_KEY=$$KEY"; \
		echo ""; \
		echo "  Or for native router bouncers (pfSense/OPNsense plugin):"; \
		echo "    LAPI URL:  http://<nib-host>:$${CROWDSEC_API_PORT:-8080}"; \
		echo "    API Key:   $$KEY"; \
	else \
		echo "$(RED)Failed to generate key. Is CrowdSec running?$(RESET)"; \
	fi

# ==================== Testing ====================

test-alert: ## Trigger a test IDS alert (requires curl + internet)
	@echo "$(CYAN)Triggering test alert...$(RESET)"
	@echo "  Fetching testmynids.org (should trigger ET rule)..."
	@curl -sf http://testmynids.org/uid/index.html >/dev/null 2>&1 || true
	@echo "  Fetching example malware URL pattern..."
	@curl -sf http://testmynids.org/uid/index.html -H "User-Agent: BlackSun" >/dev/null 2>&1 || true
	@echo "$(GREEN)✓ Test requests sent$(RESET)"
	@echo "  Check 'make logs-alerts' or Grafana in ~30 seconds"

test-dns: ## Generate test DNS queries for dashboard
	@echo "$(CYAN)Generating test DNS queries...$(RESET)"
	@for domain in example.com google.com github.com cloudflare.com wikipedia.org; do \
		nslookup $$domain >/dev/null 2>&1 || true; \
	done
	@echo "$(GREEN)✓ DNS test queries sent$(RESET)"

# ==================== Utilities ====================

open: ## Open Grafana in browser
	@set -a; . ./.env 2>/dev/null || true; set +a; \
	open "http://localhost:$${GRAFANA_PORT:-3001}" 2>/dev/null || \
	xdg-open "http://localhost:$${GRAFANA_PORT:-3001}" 2>/dev/null || \
	echo "Open http://localhost:$${GRAFANA_PORT:-3001} in your browser"

ps: ## Show running NIB containers
	@docker ps --filter "name=nib-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

check-ports: ## Check if required ports are available
	@echo "$(CYAN)Checking port availability...$(RESET)"
	@set -a; . ./.env 2>/dev/null || true; set +a; \
	for port in $${GRAFANA_PORT:-3001} $${VICTORIALOGS_PORT:-9428} $${CROWDSEC_API_PORT:-8080}; do \
		if lsof -i :$$port >/dev/null 2>&1; then \
			echo "  $(RED)✗$(RESET) Port $$port is in use"; \
		else \
			echo "  $(GREEN)✓$(RESET) Port $$port is available"; \
		fi; \
	done

clean: ## Remove stopped containers and unused images
	@docker container prune -f --filter "label=com.docker.compose.project=nib" 2>/dev/null || true
	@docker image prune -f 2>/dev/null || true
	@echo "$(GREEN)✓ Cleaned up$(RESET)"

audit: ## Audit network exposure and security posture (exits non-zero on failure)
	@./scripts/audit.sh

audit-json: ## Audit with JSON output (for CI)
	@./scripts/audit.sh --json

validate: ## Validate configuration files
	@echo "$(CYAN)Validating configuration...$(RESET)"
	@test -f .env && echo "  $(GREEN)✓$(RESET) .env exists" || echo "  $(RED)✗$(RESET) .env missing (run: cp .env.example .env)"
	@test -f suricata/config/suricata.yaml && echo "  $(GREEN)✓$(RESET) suricata.yaml exists" || echo "  $(RED)✗$(RESET) suricata.yaml missing"
	@test -f crowdsec/config/acquis.yaml && echo "  $(GREEN)✓$(RESET) acquis.yaml exists" || echo "  $(RED)✗$(RESET) acquis.yaml missing"
	@test -f storage/vector.yaml && echo "  $(GREEN)✓$(RESET) vector.yaml exists" || echo "  $(RED)✗$(RESET) vector.yaml missing"
	@test -f suricata/rules/custom.rules && echo "  $(GREEN)✓$(RESET) custom.rules exists" || echo "  $(RED)✗$(RESET) custom.rules missing"

.PHONY: help network \
	install install-suricata install-crowdsec install-storage install-grafana \
	start stop restart \
	start-suricata stop-suricata start-crowdsec stop-crowdsec \
	start-storage stop-storage start-grafana stop-grafana \
	uninstall \
	status health info \
	logs logs-suricata logs-crowdsec logs-vector logs-grafana logs-alerts \
	shell-suricata shell-crowdsec shell-grafana \
	update-rules reload-rules test-rules \
	decisions alerts ban unban collections bouncer-status metrics \
	router-sync router-sync-dry-run router-sync-daemon add-router-bouncer \
	test-alert test-dns \
	open ps check-ports clean audit audit-json validate
