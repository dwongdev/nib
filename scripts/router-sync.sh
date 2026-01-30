#!/usr/bin/env bash
# =============================================================================
# NIB Router Sync - Push CrowdSec decisions to a remote router/firewall
# =============================================================================
#
# Polls the CrowdSec LAPI for active ban decisions and pushes them to a
# router's API. Supports generic REST APIs, with built-in presets for
# common routers.
#
# Usage:
#   ./scripts/router-sync.sh                     # Run once
#   ./scripts/router-sync.sh --daemon            # Run continuously
#   ./scripts/router-sync.sh --daemon --interval 30  # Custom poll interval
#
# Required environment variables:
#   CROWDSEC_LAPI_URL    - CrowdSec LAPI URL (default: http://127.0.0.1:8080)
#   CROWDSEC_LAPI_KEY    - CrowdSec bouncer API key
#   ROUTER_TYPE          - Router type: generic, mikrotik, openwrt, pfsense, opnsense
#   ROUTER_URL           - Router API URL (e.g., https://192.168.1.1)
#   ROUTER_USER          - Router API username
#   ROUTER_PASS          - Router API password
#
# Optional:
#   ROUTER_LIST_NAME     - Address list name on router (default: nib-blocklist)
#   ROUTER_VERIFY_SSL    - Verify SSL certs (default: false for self-signed router certs)
#   SYNC_INTERVAL        - Seconds between polls in daemon mode (default: 60)
#
# =============================================================================

set -euo pipefail

# Colors
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
CYAN='\033[36m'
RESET='\033[0m'

# Configuration
CROWDSEC_LAPI_URL="${CROWDSEC_LAPI_URL:-http://127.0.0.1:8080}"
CROWDSEC_LAPI_KEY="${CROWDSEC_LAPI_KEY:-}"
ROUTER_TYPE="${ROUTER_TYPE:-generic}"
ROUTER_URL="${ROUTER_URL:-}"
ROUTER_USER="${ROUTER_USER:-}"
ROUTER_PASS="${ROUTER_PASS:-}"
ROUTER_LIST_NAME="${ROUTER_LIST_NAME:-nib-blocklist}"
ROUTER_VERIFY_SSL="${ROUTER_VERIFY_SSL:-false}"
SYNC_INTERVAL="${SYNC_INTERVAL:-60}"

# State
DAEMON_MODE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="/tmp/nib-router-sync-last.json"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon)    DAEMON_MODE=true; shift ;;
        --interval)  SYNC_INTERVAL="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--daemon] [--interval SECONDS]"
            echo ""
            echo "Polls CrowdSec LAPI and pushes ban decisions to a router."
            echo "Set configuration via environment variables or .env file."
            echo ""
            echo "Router types: generic, mikrotik, openwrt, pfsense, opnsense"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Load .env if available
# ---------------------------------------------------------------------------
if [[ -f "${SCRIPT_DIR}/../.env" ]]; then
    set -a
    source "${SCRIPT_DIR}/../.env"
    set +a
fi

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
validate_config() {
    local errors=0

    if [[ -z "$CROWDSEC_LAPI_KEY" ]]; then
        echo -e "${RED}Error: CROWDSEC_LAPI_KEY not set${RESET}"
        echo "  Generate one with: docker exec nib-crowdsec cscli bouncers add nib-router-bouncer -o raw"
        errors=$((errors + 1))
    fi

    if [[ -z "$ROUTER_URL" ]]; then
        echo -e "${RED}Error: ROUTER_URL not set${RESET}"
        echo "  Set to your router's API URL (e.g., https://192.168.1.1)"
        errors=$((errors + 1))
    fi

    if [[ -z "$ROUTER_USER" || -z "$ROUTER_PASS" ]]; then
        echo -e "${RED}Error: ROUTER_USER and ROUTER_PASS must be set${RESET}"
        errors=$((errors + 1))
    fi

    if [[ $errors -gt 0 ]]; then
        echo ""
        echo "See: scripts/router-sync.sh --help"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# CrowdSec LAPI interaction
# ---------------------------------------------------------------------------
get_decisions() {
    local curl_opts=(-sf)
    curl_opts+=(-H "X-Api-Key: ${CROWDSEC_LAPI_KEY}")

    curl "${curl_opts[@]}" "${CROWDSEC_LAPI_URL}/v1/decisions?type=ban" 2>/dev/null || echo "null"
}

extract_ips() {
    local decisions="$1"
    if [[ "$decisions" == "null" || -z "$decisions" ]]; then
        echo ""
        return
    fi
    echo "$decisions" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data:
    for d in data:
        if d.get('value') and d.get('type') == 'ban':
            print(d['value'])
" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Router-specific push functions
# ---------------------------------------------------------------------------
ssl_flag() {
    if [[ "$ROUTER_VERIFY_SSL" == "false" ]]; then
        echo "-k"
    fi
}

# --- MikroTik RouterOS ---
push_mikrotik() {
    local ip="$1"
    local action="$2"  # add or remove

    if [[ "$action" == "add" ]]; then
        curl -sf $(ssl_flag) \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}/rest/ip/firewall/address-list/add" \
            -H "Content-Type: application/json" \
            -d "{\"list\": \"${ROUTER_LIST_NAME}\", \"address\": \"${ip}\", \"comment\": \"NIB-CrowdSec ban\"}" \
            >/dev/null 2>&1
    else
        # Find and remove the entry
        local entry_id
        entry_id=$(curl -sf $(ssl_flag) \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            "${ROUTER_URL}/rest/ip/firewall/address-list?list=${ROUTER_LIST_NAME}&address=${ip}" \
            2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['.id'])" 2>/dev/null || echo "")
        if [[ -n "$entry_id" ]]; then
            curl -sf $(ssl_flag) \
                -u "${ROUTER_USER}:${ROUTER_PASS}" \
                -X POST "${ROUTER_URL}/rest/ip/firewall/address-list/remove" \
                -H "Content-Type: application/json" \
                -d "{\".id\": \"${entry_id}\"}" \
                >/dev/null 2>&1
        fi
    fi
}

# --- OPNsense ---
push_opnsense() {
    local ip="$1"
    local action="$2"

    if [[ "$action" == "add" ]]; then
        # Add to alias via OPNsense API
        curl -sf $(ssl_flag) \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}/api/firewall/alias_util/add/${ROUTER_LIST_NAME}" \
            -H "Content-Type: application/json" \
            -d "{\"address\": \"${ip}\"}" \
            >/dev/null 2>&1
    else
        curl -sf $(ssl_flag) \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}/api/firewall/alias_util/delete/${ROUTER_LIST_NAME}" \
            -H "Content-Type: application/json" \
            -d "{\"address\": \"${ip}\"}" \
            >/dev/null 2>&1
    fi
}

# --- pfSense ---
push_pfsense() {
    local ip="$1"
    local action="$2"

    # pfSense uses the pfBlockerNG or custom API endpoint
    # This uses the fauxapi if installed (https://github.com/ndejong/pfsense_fauxapi)
    if [[ "$action" == "add" ]]; then
        curl -sf $(ssl_flag) \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}/api/v1/firewall/alias/entry" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"${ROUTER_LIST_NAME}\", \"address\": [\"${ip}\"], \"detail\": [\"NIB-CrowdSec ban\"]}" \
            >/dev/null 2>&1
    else
        curl -sf $(ssl_flag) \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X DELETE "${ROUTER_URL}/api/v1/firewall/alias/entry" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"${ROUTER_LIST_NAME}\", \"address\": [\"${ip}\"]}" \
            >/dev/null 2>&1
    fi
}

# --- OpenWrt (luci-rpc / ubus) ---
push_openwrt() {
    local ip="$1"
    local action="$2"

    # Get auth token
    local token
    token=$(curl -sf $(ssl_flag) \
        -X POST "${ROUTER_URL}/cgi-bin/luci/rpc/auth" \
        -H "Content-Type: application/json" \
        -d "{\"id\":1, \"method\":\"login\", \"params\":[\"${ROUTER_USER}\", \"${ROUTER_PASS}\"]}" \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo "")

    if [[ -z "$token" ]]; then
        echo -e "${RED}  Failed to authenticate with OpenWrt${RESET}"
        return 1
    fi

    if [[ "$action" == "add" ]]; then
        # Add iptables rule via ubus/sys exec
        curl -sf $(ssl_flag) \
            -X POST "${ROUTER_URL}/cgi-bin/luci/rpc/sys" \
            -H "Content-Type: application/json" \
            -H "Cookie: sysauth=${token}" \
            -d "{\"id\":1, \"method\":\"exec\", \"params\":[\"ipset add ${ROUTER_LIST_NAME} ${ip} 2>/dev/null || nft add element inet fw4 ${ROUTER_LIST_NAME} { ${ip} } 2>/dev/null\"]}" \
            >/dev/null 2>&1
    else
        curl -sf $(ssl_flag) \
            -X POST "${ROUTER_URL}/cgi-bin/luci/rpc/sys" \
            -H "Content-Type: application/json" \
            -H "Cookie: sysauth=${token}" \
            -d "{\"id\":1, \"method\":\"exec\", \"params\":[\"ipset del ${ROUTER_LIST_NAME} ${ip} 2>/dev/null || nft delete element inet fw4 ${ROUTER_LIST_NAME} { ${ip} } 2>/dev/null\"]}" \
            >/dev/null 2>&1
    fi
}

# --- Generic REST API ---
push_generic() {
    local ip="$1"
    local action="$2"

    if [[ "$action" == "add" ]]; then
        curl -sf $(ssl_flag) \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"action\": \"block\", \"ip\": \"${ip}\", \"list\": \"${ROUTER_LIST_NAME}\", \"source\": \"nib-crowdsec\"}" \
            >/dev/null 2>&1
    else
        curl -sf $(ssl_flag) \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X DELETE "${ROUTER_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"action\": \"unblock\", \"ip\": \"${ip}\", \"list\": \"${ROUTER_LIST_NAME}\", \"source\": \"nib-crowdsec\"}" \
            >/dev/null 2>&1
    fi
}

# ---------------------------------------------------------------------------
# Router dispatch
# ---------------------------------------------------------------------------
push_to_router() {
    local ip="$1"
    local action="$2"

    case "$ROUTER_TYPE" in
        mikrotik)   push_mikrotik "$ip" "$action" ;;
        opnsense)   push_opnsense "$ip" "$action" ;;
        pfsense)    push_pfsense "$ip" "$action" ;;
        openwrt)    push_openwrt "$ip" "$action" ;;
        generic)    push_generic "$ip" "$action" ;;
        *)
            echo -e "${RED}Unknown ROUTER_TYPE: ${ROUTER_TYPE}${RESET}"
            echo "Supported: mikrotik, opnsense, pfsense, openwrt, generic"
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------
sync_decisions() {
    local decisions
    decisions=$(get_decisions)

    local current_ips
    current_ips=$(extract_ips "$decisions")

    # Load previous state
    local previous_ips=""
    if [[ -f "$STATE_FILE" ]]; then
        previous_ips=$(cat "$STATE_FILE" 2>/dev/null || echo "")
    fi

    # Find IPs to add (in current but not in previous)
    local added=0
    local removed=0

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if ! echo "$previous_ips" | grep -qF "$ip"; then
            if push_to_router "$ip" "add"; then
                echo -e "  ${RED}+ Blocked${RESET} ${ip}"
                added=$((added + 1))
            else
                echo -e "  ${YELLOW}! Failed to block${RESET} ${ip}"
            fi
        fi
    done <<< "$current_ips"

    # Find IPs to remove (in previous but not in current)
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if [[ -n "$current_ips" ]] && ! echo "$current_ips" | grep -qF "$ip"; then
            if push_to_router "$ip" "remove"; then
                echo -e "  ${GREEN}- Unblocked${RESET} ${ip}"
                removed=$((removed + 1))
            else
                echo -e "  ${YELLOW}! Failed to unblock${RESET} ${ip}"
            fi
        fi
    done <<< "$previous_ips"

    # Save current state
    echo "$current_ips" > "$STATE_FILE"

    local total
    total=$(echo "$current_ips" | grep -c '[^[:space:]]' 2>/dev/null || echo "0")

    if [[ $added -gt 0 || $removed -gt 0 ]]; then
        echo -e "${CYAN}  Sync: +${added} blocked, -${removed} unblocked, ${total} total active bans${RESET}"
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo -e "${CYAN}NIB Router Sync${RESET}"
    echo -e "  LAPI:   ${CROWDSEC_LAPI_URL}"
    echo -e "  Router: ${ROUTER_TYPE} @ ${ROUTER_URL}"
    echo -e "  List:   ${ROUTER_LIST_NAME}"
    echo ""

    validate_config

    if [[ "$DAEMON_MODE" == "true" ]]; then
        echo -e "${CYAN}Running in daemon mode (interval: ${SYNC_INTERVAL}s)${RESET}"
        echo -e "Press Ctrl+C to stop"
        echo ""
        while true; do
            sync_decisions
            sleep "$SYNC_INTERVAL"
        done
    else
        sync_decisions
        echo -e "${GREEN}✓ Sync complete${RESET}"
    fi
}

main
