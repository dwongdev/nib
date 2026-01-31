#!/usr/bin/env bash
# NIB Security Audit
# Machine-checkable security posture verification.
# Exit code: 0 = all checks pass, 1 = failures found.
# Usage: ./scripts/audit.sh [--json]

set -euo pipefail

# ── Output mode ──────────────────────────────────────────────────────────────

JSON_MODE=false
[ "${1:-}" = "--json" ] && JSON_MODE=true

GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0
JSON_RESULTS="[]"

# ── Helpers ──────────────────────────────────────────────────────────────────

record() {
  local status="$1" section="$2" check="$3" detail="${4:-}"
  case "$status" in
    pass) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    fail) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    warn) WARN_COUNT=$((WARN_COUNT + 1)) ;;
    skip) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
  esac
  if $JSON_MODE; then
    detail_escaped=$(printf '%s' "$detail" | sed 's/"/\\"/g; s/\t/ /g')
    JSON_RESULTS=$(printf '%s' "$JSON_RESULTS" | sed "s/]$/,{\"status\":\"$status\",\"section\":\"$section\",\"check\":\"$check\",\"detail\":\"$detail_escaped\"}]/")
    # fix first entry (leading comma after [)
    JSON_RESULTS=$(printf '%s' "$JSON_RESULTS" | sed 's/\[,/[/')
  else
    case "$status" in
      pass) printf "  ${GREEN}PASS${RESET}  %s: %s\n" "$check" "$detail" ;;
      fail) printf "  ${RED}FAIL${RESET}  %s: %s\n" "$check" "$detail" ;;
      warn) printf "  ${YELLOW}WARN${RESET}  %s: %s\n" "$check" "$detail" ;;
      skip) printf "  ${CYAN}SKIP${RESET}  %s: %s\n" "$check" "$detail" ;;
    esac
  fi
}

section_header() {
  $JSON_MODE || printf "\n${BOLD}── %s ──${RESET}\n" "$1"
}

container_running() {
  docker inspect --format='{{.State.Status}}' "$1" 2>/dev/null | grep -q running
}

# ── Load config ──────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NIB_DIR="$(dirname "$SCRIPT_DIR")"
if [ -f "$NIB_DIR/.env" ]; then
  set -a; . "$NIB_DIR/.env" 2>/dev/null || true; set +a
fi

GRAFANA_PORT="${GRAFANA_PORT:-3001}"
GRAFANA_BIND="${GRAFANA_BIND:-0.0.0.0}"
VICTORIALOGS_PORT="${VICTORIALOGS_PORT:-9428}"
STORAGE_BIND="${STORAGE_BIND:-127.0.0.1}"
CROWDSEC_API_PORT="${CROWDSEC_API_PORT:-8080}"
CROWDSEC_API_BIND="${CROWDSEC_API_BIND:-127.0.0.1}"
BOUNCER_MODE="${BOUNCER_MODE:-local}"
PRIVACY_MODE="${PRIVACY_MODE:-full}"

# Expected security policy per container
# Format: container|need_cap_drop_all|allowed_caps|need_no_new_priv|need_readonly|need_host_net
POLICY="
nib-suricata|yes|NET_ADMIN,NET_RAW,SYS_NICE|yes|no|yes
nib-crowdsec|yes||yes|yes|no
nib-bouncer-firewall|yes|NET_ADMIN,NET_RAW|yes|no|yes
nib-victorialogs|yes||yes|yes|no
nib-vector|yes||yes|yes|no
nib-grafana|yes||yes|yes|no
"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1: Network Exposure
# ═════════════════════════════════════════════════════════════════════════════

section_header "Network Exposure"

check_port_binding() {
  local port="$1" expected_bind="$2" label="$3"
  local listen_line
  listen_line=$(ss -tlnp 2>/dev/null | grep ":${port} " || netstat -tlnp 2>/dev/null | grep ":${port} " || echo "")

  if [ -z "$listen_line" ]; then
    record skip "network" "${label} (:${port})" "not listening"
    return
  fi

  if echo "$listen_line" | grep -q "0\.0\.0\.0:${port} "; then
    if [ "$expected_bind" = "0.0.0.0" ]; then
      record warn "network" "${label} (:${port})" "bound to 0.0.0.0 (matches config — restrict via ${label}_BIND if unintended)"
    else
      record fail "network" "${label} (:${port})" "bound to 0.0.0.0 but config expects ${expected_bind}"
    fi
  elif echo "$listen_line" | grep -q "127\.0\.0\.1:${port} "; then
    if [ "$expected_bind" = "127.0.0.1" ]; then
      record pass "network" "${label} (:${port})" "bound to 127.0.0.1 (localhost only)"
    else
      record pass "network" "${label} (:${port})" "bound to 127.0.0.1"
    fi
  elif echo "$listen_line" | grep -qE '\*:'"${port}"' '; then
    record fail "network" "${label} (:${port})" "bound to all interfaces (*)"
  else
    local actual_bind
    actual_bind=$(echo "$listen_line" | grep -oE '[0-9.]+:'"${port}" | head -1 | sed "s/:${port}//")
    record pass "network" "${label} (:${port})" "bound to ${actual_bind}"
  fi
}

check_port_binding "$GRAFANA_PORT" "$GRAFANA_BIND" "Grafana"
check_port_binding "$VICTORIALOGS_PORT" "$STORAGE_BIND" "VictoriaLogs"
check_port_binding "$CROWDSEC_API_PORT" "$CROWDSEC_API_BIND" "CrowdSec LAPI"

# Sensor mode: LAPI on 0.0.0.0 is expected but needs explicit warning
if [ "$BOUNCER_MODE" = "sensor" ]; then
  if [ "$CROWDSEC_API_BIND" = "0.0.0.0" ]; then
    record warn "network" "Sensor mode LAPI" "LAPI exposed on 0.0.0.0 — ensure port ${CROWDSEC_API_PORT} is firewalled to bouncer IPs only"
  else
    record pass "network" "Sensor mode LAPI" "LAPI bound to ${CROWDSEC_API_BIND}"
  fi
fi

# Check for unexpected listeners on host
unexpected=$(ss -tlnp 2>/dev/null | grep -E '(nib-|suricata|crowdsec|vector|victoria|grafana)' | grep '0\.0\.0\.0:' | grep -vE ":${GRAFANA_PORT} |:${VICTORIALOGS_PORT} |:${CROWDSEC_API_PORT} " || true)
if [ -n "$unexpected" ]; then
  record fail "network" "Unexpected listeners" "found NIB-related processes on unexpected ports bound to 0.0.0.0"
else
  record pass "network" "Unexpected listeners" "none found"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2: Container Security Posture
# ═════════════════════════════════════════════════════════════════════════════

section_header "Container Security Posture"

while IFS='|' read -r cname need_cap_drop allowed_caps need_no_new_priv need_readonly need_host_net; do
  # Skip empty lines
  [ -z "$cname" ] && continue

  if ! container_running "$cname"; then
    record skip "container" "$cname" "not running"
    continue
  fi

  # ── Privileged mode ──
  privileged=$(docker inspect --format='{{.HostConfig.Privileged}}' "$cname" 2>/dev/null || echo "unknown")
  if [ "$privileged" = "true" ]; then
    record fail "container" "${cname}/privileged" "running in privileged mode"
  elif [ "$privileged" = "false" ]; then
    record pass "container" "${cname}/privileged" "not privileged"
  fi

  # ── CapDrop ALL ──
  if [ "$need_cap_drop" = "yes" ]; then
    cap_drop=$(docker inspect --format='{{.HostConfig.CapDrop}}' "$cname" 2>/dev/null || echo "")
    if echo "$cap_drop" | grep -qi 'all'; then
      record pass "container" "${cname}/cap_drop" "ALL capabilities dropped"
    else
      record fail "container" "${cname}/cap_drop" "cap_drop does not include ALL (got: ${cap_drop})"
    fi
  fi

  # ── CapAdd matches policy ──
  cap_add=$(docker inspect --format='{{.HostConfig.CapAdd}}' "$cname" 2>/dev/null || echo "[]")
  # Normalize: remove brackets, spaces
  cap_add_clean=$(echo "$cap_add" | tr -d '[]' | tr ' ' ',')

  if [ -z "$allowed_caps" ]; then
    # No caps should be added
    if [ "$cap_add_clean" = "" ] || [ "$cap_add" = "[]" ]; then
      record pass "container" "${cname}/cap_add" "no capabilities added (none needed)"
    else
      record fail "container" "${cname}/cap_add" "unexpected capabilities: ${cap_add_clean}"
    fi
  else
    # Check each allowed cap is present and no extras exist
    IFS=',' read -ra expected_arr <<< "$allowed_caps"
    extra_caps=""
    for actual in $(echo "$cap_add_clean" | tr ',' ' '); do
      found=false
      for expected in "${expected_arr[@]}"; do
        [ "$actual" = "$expected" ] && found=true && break
      done
      $found || extra_caps="${extra_caps} ${actual}"
    done
    if [ -z "$extra_caps" ]; then
      record pass "container" "${cname}/cap_add" "capabilities match policy (${allowed_caps})"
    else
      record fail "container" "${cname}/cap_add" "unexpected extra capabilities:${extra_caps}"
    fi
  fi

  # ── NoNewPrivileges ──
  if [ "$need_no_new_priv" = "yes" ]; then
    sec_opt=$(docker inspect --format='{{.HostConfig.SecurityOpt}}' "$cname" 2>/dev/null || echo "")
    if echo "$sec_opt" | grep -q 'no-new-privileges'; then
      record pass "container" "${cname}/no_new_priv" "no-new-privileges enabled"
    else
      record fail "container" "${cname}/no_new_priv" "no-new-privileges NOT set"
    fi
  fi

  # ── ReadonlyRootfs ──
  if [ "$need_readonly" = "yes" ]; then
    ro=$(docker inspect --format='{{.HostConfig.ReadonlyRootfs}}' "$cname" 2>/dev/null || echo "unknown")
    if [ "$ro" = "true" ]; then
      record pass "container" "${cname}/readonly" "root filesystem is read-only"
    else
      record fail "container" "${cname}/readonly" "root filesystem is writable (expected read_only: true)"
    fi
  fi

  # ── Network mode ──
  net_mode=$(docker inspect --format='{{.HostConfig.NetworkMode}}' "$cname" 2>/dev/null || echo "unknown")
  if [ "$need_host_net" = "yes" ]; then
    if [ "$net_mode" = "host" ]; then
      record pass "container" "${cname}/network" "host network (required for this component)"
    else
      record warn "container" "${cname}/network" "expected host network but got ${net_mode}"
    fi
  else
    if [ "$net_mode" = "host" ]; then
      record fail "container" "${cname}/network" "using host network unnecessarily"
    else
      record pass "container" "${cname}/network" "isolated network (${net_mode})"
    fi
  fi

  # ── Sensitive env vars not leaking defaults ──
  env_vars=$(docker inspect --format='{{range .Config.Env}}{{.}}{{"\n"}}{{end}}' "$cname" 2>/dev/null || echo "")
  if echo "$env_vars" | grep -qE '(PASSWORD|KEY|SECRET)=CHANGE_ME'; then
    record fail "container" "${cname}/env" "sensitive env var still set to default (CHANGE_ME)"
  elif echo "$env_vars" | grep -qiE '^(GF_SECURITY_ADMIN_PASSWORD|CROWDSEC_BOUNCER_API_KEY)=$'; then
    record warn "container" "${cname}/env" "sensitive env var is empty"
  else
    record pass "container" "${cname}/env" "no default/empty secrets detected"
  fi

done < <(echo "$POLICY" | grep -v '^$')

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3: Runtime Checks
# ═════════════════════════════════════════════════════════════════════════════

section_header "Runtime"

# ── iptables backend detection ──
if command -v iptables >/dev/null 2>&1; then
  ipt_version=$(iptables --version 2>/dev/null || echo "unknown")
  if echo "$ipt_version" | grep -q 'nf_tables'; then
    record warn "runtime" "iptables backend" "nf_tables backend detected — CrowdSec bouncer uses iptables API (usually compatible, but verify)"
  elif echo "$ipt_version" | grep -q 'legacy'; then
    record pass "runtime" "iptables backend" "legacy iptables (fully compatible)"
  else
    record pass "runtime" "iptables backend" "${ipt_version}"
  fi
else
  record skip "runtime" "iptables backend" "iptables command not found"
fi

# ── CrowdSec bouncer active check ──
if container_running nib-bouncer-firewall; then
  if command -v iptables >/dev/null 2>&1; then
    if sudo -n iptables -L crowdsec-blacklists -n >/dev/null 2>&1; then
      record pass "runtime" "bouncer iptables chain" "crowdsec-blacklists chain exists"
    else
      record warn "runtime" "bouncer iptables chain" "crowdsec-blacklists chain not found (may need sudo or bouncer not yet initialized)"
    fi
  else
    record skip "runtime" "bouncer iptables chain" "iptables not available on host"
  fi
elif [ "$BOUNCER_MODE" = "local" ]; then
  record skip "runtime" "bouncer iptables chain" "bouncer not running"
fi

# ── Suricata capture check ──
if container_running nib-suricata; then
  if docker exec nib-suricata test -f /var/run/suricata/suricata.pid 2>/dev/null; then
    record pass "runtime" "suricata process" "running (PID file exists)"
  else
    record fail "runtime" "suricata process" "PID file missing — capture may not be active"
  fi
else
  record skip "runtime" "suricata process" "container not running"
fi

# ── Privacy mode config consistency ──
# Privacy mode is enforced at Vector (log shipping) level, not Suricata.
# Suricata always logs everything (CrowdSec needs the full EVE stream).
# Vector selectively ships events to storage based on PRIVACY_MODE.
if [ -f "$NIB_DIR/storage/active-vector.yaml" ]; then
  if [ "$PRIVACY_MODE" = "alerts-only" ]; then
    if grep -q 'Privacy Mode: alerts-only' "$NIB_DIR/storage/active-vector.yaml"; then
      record pass "runtime" "privacy config" "Vector config matches PRIVACY_MODE=alerts-only"
    else
      record fail "runtime" "privacy config" "PRIVACY_MODE=alerts-only but Vector uses full config — run make install-storage"
    fi
  else
    if grep -q 'Privacy Mode: alerts-only' "$NIB_DIR/storage/active-vector.yaml"; then
      record fail "runtime" "privacy config" "PRIVACY_MODE=full but Vector uses privacy config — run make install-storage"
    else
      record pass "runtime" "privacy config" "Vector config matches PRIVACY_MODE=full"
    fi
  fi
else
  record skip "runtime" "privacy config" "active-vector.yaml not found (run make install-storage)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4: Configuration Hygiene
# ═════════════════════════════════════════════════════════════════════════════

section_header "Configuration"

# ── Grafana password ──
if [ -f "$NIB_DIR/.env" ]; then
  gf_pass=$(grep '^GRAFANA_ADMIN_PASSWORD=' "$NIB_DIR/.env" 2>/dev/null | cut -d= -f2-)
  if [ -z "$gf_pass" ] || [ "$gf_pass" = "CHANGE_ME" ] || [ "$gf_pass" = "admin" ]; then
    record fail "config" "Grafana password" "default or empty password in .env"
  else
    record pass "config" "Grafana password" "custom password set"
  fi
else
  record fail "config" ".env file" "missing — run: cp .env.example .env"
fi

# ── HOME_NET not default ──
home_net="${HOME_NET:-[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]}"
if [ "$home_net" = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]" ]; then
  record warn "config" "HOME_NET" "using RFC1918 defaults — set to your actual network ranges for fewer false positives"
else
  record pass "config" "HOME_NET" "customized (${home_net})"
fi

# ── Retention ──
retention="${VICTORIALOGS_RETENTION:-168h}"
record pass "config" "Log retention" "${retention}"

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════

TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))

if $JSON_MODE; then
  cat <<JSONEOF
{
  "summary": {
    "total": $TOTAL,
    "pass": $PASS_COUNT,
    "fail": $FAIL_COUNT,
    "warn": $WARN_COUNT,
    "skip": $SKIP_COUNT,
    "exit_code": $([ $FAIL_COUNT -eq 0 ] && echo 0 || echo 1)
  },
  "checks": $JSON_RESULTS
}
JSONEOF
else
  printf "\n${BOLD}── Summary ──${RESET}\n"
  printf "  ${GREEN}PASS${RESET}  %d\n" "$PASS_COUNT"
  printf "  ${RED}FAIL${RESET}  %d\n" "$FAIL_COUNT"
  printf "  ${YELLOW}WARN${RESET}  %d\n" "$WARN_COUNT"
  printf "  ${CYAN}SKIP${RESET}  %d\n" "$SKIP_COUNT"
  printf "  Total: %d checks\n\n" "$TOTAL"
  if [ "$FAIL_COUNT" -gt 0 ]; then
    printf "${RED}%d check(s) failed. Fix the issues above.${RESET}\n\n" "$FAIL_COUNT"
  elif [ "$WARN_COUNT" -gt 0 ]; then
    printf "${YELLOW}All checks passed with %d warning(s).${RESET}\n\n" "$WARN_COUNT"
  else
    printf "${GREEN}All checks passed.${RESET}\n\n"
  fi
fi

exit "$([ $FAIL_COUNT -eq 0 ] && echo 0 || echo 1)"
