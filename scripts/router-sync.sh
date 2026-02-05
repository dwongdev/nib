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
#   ./scripts/router-sync.sh --dry-run           # Show what would be synced
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
#   STATE_DIR            - Directory for state file (default: /var/lib/nib)
#
# =============================================================================

set -euo pipefail

VERSION="1.1.0"

# Colors
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
CYAN='\033[36m'
RESET='\033[0m'

# State
DAEMON_MODE=false
DRY_RUN=false
VERBOSE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# OpenWrt session token (cached)
OPENWRT_TOKEN=""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon)    DAEMON_MODE=true; shift ;;
        --interval)  SYNC_INTERVAL="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=true; shift ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --version)   echo "NIB Router Sync v${VERSION}"; exit 0 ;;
        --help|-h)
            echo "NIB Router Sync v${VERSION}"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --daemon          Run continuously, polling at SYNC_INTERVAL"
            echo "  --interval SECS   Poll interval in daemon mode (default: 60)"
            echo "  --dry-run         Show what would be synced without making changes"
            echo "  --verbose, -v     Show detailed output"
            echo "  --version         Show version"
            echo "  --help, -h        Show this help"
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
# Load .env if available (before variable assignment so .env values take effect)
# ---------------------------------------------------------------------------
if [[ -f "${SCRIPT_DIR}/../.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/../.env"
    set +a
fi

# Configuration (uses environment/`.env` values, with defaults as fallback)
CROWDSEC_LAPI_URL="${CROWDSEC_LAPI_URL:-http://127.0.0.1:8080}"
CROWDSEC_LAPI_KEY="${CROWDSEC_LAPI_KEY:-}"
ROUTER_TYPE="${ROUTER_TYPE:-generic}"
ROUTER_URL="${ROUTER_URL:-}"
ROUTER_USER="${ROUTER_USER:-}"
ROUTER_PASS="${ROUTER_PASS:-}"
ROUTER_LIST_NAME="${ROUTER_LIST_NAME:-nib-blocklist}"
ROUTER_VERIFY_SSL="${ROUTER_VERIFY_SSL:-false}"
SYNC_INTERVAL="${SYNC_INTERVAL:-60}"
STATE_DIR="${STATE_DIR:-/var/lib/nib}"
STATE_FILE="${STATE_DIR}/router-sync-state.txt"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
check_dependencies() {
    local missing=0
    for cmd in curl python3; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}Error: Required command '$cmd' not found${RESET}"
            missing=$((missing + 1))
        fi
    done
    if [[ $missing -gt 0 ]]; then
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# State directory setup
# ---------------------------------------------------------------------------
setup_state_dir() {
    if [[ ! -d "$STATE_DIR" ]]; then
        # Try to create it, fall back to /tmp if no permission
        if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
            STATE_DIR="/tmp"
            STATE_FILE="${STATE_DIR}/nib-router-sync-state.txt"
            [[ "$VERBOSE" == "true" ]] && echo -e "${YELLOW}  Using fallback state dir: ${STATE_DIR}${RESET}"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Signal handling for graceful shutdown
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    echo -e "${CYAN}Shutting down...${RESET}"
    exit 0
}
trap cleanup SIGINT SIGTERM

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
# IP/CIDR validation
# ---------------------------------------------------------------------------
is_valid_ip_or_cidr() {
    local value="$1"
    # Match IPv4, IPv4/CIDR, IPv6 (simplified), IPv6/CIDR
    if [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
        return 0
    elif [[ "$value" =~ ^[0-9a-fA-F:]+(/[0-9]+)?$ ]]; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# CrowdSec LAPI interaction
# ---------------------------------------------------------------------------
get_decisions() {
    local curl_opts=(-s --fail --show-error)
    curl_opts+=(-H "X-Api-Key: ${CROWDSEC_LAPI_KEY}")

    local response http_code
    # Use -w to capture the HTTP status code separately
    response=$(curl "${curl_opts[@]}" "${CROWDSEC_LAPI_URL}/v1/decisions?type=ban" 2>/dev/null)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        echo -e "${RED}  Error: Failed to reach CrowdSec LAPI at ${CROWDSEC_LAPI_URL}${RESET}" >&2
        return 1
    fi

    echo "$response"
}

extract_ips() {
    local decisions="$1"
    if [[ "$decisions" == "null" || -z "$decisions" ]]; then
        echo ""
        return
    fi
    echo "$decisions" | python3 -c "
import sys, json, re
data = json.load(sys.stdin)
ip_re = re.compile(r'^[0-9a-fA-F.:]+(/[0-9]+)?$')
if data:
    for d in data:
        v = d.get('value', '')
        if v and d.get('type') == 'ban' and ip_re.match(v):
            print(v)
" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Router-specific push functions
# ---------------------------------------------------------------------------

# Build curl options array with SSL handling
build_curl_opts() {
    local -n opts=$1
    opts=(-sf)
    if [[ "$ROUTER_VERIFY_SSL" == "false" ]]; then
        opts+=(-k)
    fi
}

# --- MikroTik RouterOS ---
push_mikrotik() {
    local ip="$1"
    local action="$2"  # add or remove
    local -a curl_opts
    build_curl_opts curl_opts

    if [[ "$action" == "add" ]]; then
        curl "${curl_opts[@]}" \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}/rest/ip/firewall/address-list/add" \
            -H "Content-Type: application/json" \
            -d "{\"list\": \"${ROUTER_LIST_NAME}\", \"address\": \"${ip}\", \"comment\": \"NIB-CrowdSec ban\"}" \
            >/dev/null 2>&1
    else
        # Find and remove the entry
        local entry_id
        entry_id=$(curl "${curl_opts[@]}" \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            "${ROUTER_URL}/rest/ip/firewall/address-list?list=${ROUTER_LIST_NAME}&address=${ip}" \
            2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['.id'])" 2>/dev/null || echo "")
        if [[ -n "$entry_id" ]]; then
            curl "${curl_opts[@]}" \
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
    local -a curl_opts
    build_curl_opts curl_opts

    if [[ "$action" == "add" ]]; then
        # Add to alias via OPNsense API
        curl "${curl_opts[@]}" \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}/api/firewall/alias_util/add/${ROUTER_LIST_NAME}" \
            -H "Content-Type: application/json" \
            -d "{\"address\": \"${ip}\"}" \
            >/dev/null 2>&1
    else
        curl "${curl_opts[@]}" \
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
    local -a curl_opts
    build_curl_opts curl_opts

    # pfSense uses the pfBlockerNG or custom API endpoint
    # This uses the fauxapi if installed (https://github.com/ndejong/pfsense_fauxapi)
    if [[ "$action" == "add" ]]; then
        curl "${curl_opts[@]}" \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}/api/v1/firewall/alias/entry" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"${ROUTER_LIST_NAME}\", \"address\": [\"${ip}\"], \"detail\": [\"NIB-CrowdSec ban\"]}" \
            >/dev/null 2>&1
    else
        curl "${curl_opts[@]}" \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X DELETE "${ROUTER_URL}/api/v1/firewall/alias/entry" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"${ROUTER_LIST_NAME}\", \"address\": [\"${ip}\"]}" \
            >/dev/null 2>&1
    fi
}

# --- OpenWrt (luci-rpc / ubus) ---
# Get or refresh OpenWrt auth token (cached for efficiency)
get_openwrt_token() {
    # Return cached token if available
    if [[ -n "$OPENWRT_TOKEN" ]]; then
        echo "$OPENWRT_TOKEN"
        return 0
    fi

    local -a curl_opts
    build_curl_opts curl_opts

    OPENWRT_TOKEN=$(curl "${curl_opts[@]}" \
        -X POST "${ROUTER_URL}/cgi-bin/luci/rpc/auth" \
        -H "Content-Type: application/json" \
        -d "{\"id\":1, \"method\":\"login\", \"params\":[\"${ROUTER_USER}\", \"${ROUTER_PASS}\"]}" \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo "")

    echo "$OPENWRT_TOKEN"
}

push_openwrt() {
    local ip="$1"
    local action="$2"
    local -a curl_opts
    build_curl_opts curl_opts

    # Get auth token (cached)
    local token
    token=$(get_openwrt_token)

    if [[ -z "$token" ]]; then
        echo -e "${RED}  Failed to authenticate with OpenWrt${RESET}"
        return 1
    fi

    if [[ "$action" == "add" ]]; then
        # Add to ipset/nftables via ubus/sys exec
        curl "${curl_opts[@]}" \
            -X POST "${ROUTER_URL}/cgi-bin/luci/rpc/sys" \
            -H "Content-Type: application/json" \
            -H "Cookie: sysauth=${token}" \
            -d "{\"id\":1, \"method\":\"exec\", \"params\":[\"ipset add ${ROUTER_LIST_NAME} ${ip} 2>/dev/null || nft add element inet fw4 ${ROUTER_LIST_NAME} { ${ip} } 2>/dev/null\"]}" \
            >/dev/null 2>&1
    else
        curl "${curl_opts[@]}" \
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
    local -a curl_opts
    build_curl_opts curl_opts

    if [[ "$action" == "add" ]]; then
        curl "${curl_opts[@]}" \
            -u "${ROUTER_USER}:${ROUTER_PASS}" \
            -X POST "${ROUTER_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"action\": \"block\", \"ip\": \"${ip}\", \"list\": \"${ROUTER_LIST_NAME}\", \"source\": \"nib-crowdsec\"}" \
            >/dev/null 2>&1
    else
        curl "${curl_opts[@]}" \
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

    # Validate IP before sending to any router (prevents command/JSON injection)
    if ! is_valid_ip_or_cidr "$ip"; then
        echo -e "${RED}  Rejecting invalid IP/CIDR: ${ip}${RESET}" >&2
        return 1
    fi

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
    if ! decisions=$(get_decisions); then
        echo -e "${YELLOW}  Skipping sync: LAPI unreachable (existing blocklist preserved)${RESET}"
        return 0
    fi

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
        if ! echo "$previous_ips" | grep -qxF "$ip"; then
            if [[ "$DRY_RUN" == "true" ]]; then
                echo -e "  ${RED}+ Would block${RESET} ${ip}"
                added=$((added + 1))
            elif push_to_router "$ip" "add"; then
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
        if [[ -n "$current_ips" ]] && ! echo "$current_ips" | grep -qxF "$ip"; then
            if [[ "$DRY_RUN" == "true" ]]; then
                echo -e "  ${GREEN}- Would unblock${RESET} ${ip}"
                removed=$((removed + 1))
            elif push_to_router "$ip" "remove"; then
                echo -e "  ${GREEN}- Unblocked${RESET} ${ip}"
                removed=$((removed + 1))
            else
                echo -e "  ${YELLOW}! Failed to unblock${RESET} ${ip}"
            fi
        fi
    done <<< "$previous_ips"

    # Save current state (skip in dry-run mode)
    if [[ "$DRY_RUN" != "true" ]]; then
        echo "$current_ips" > "$STATE_FILE"
    fi

    local total
    total=$(echo "$current_ips" | grep -c '[^[:space:]]' 2>/dev/null || echo "0")

    if [[ $added -gt 0 || $removed -gt 0 ]]; then
        local prefix=""
        [[ "$DRY_RUN" == "true" ]] && prefix="(dry-run) "
        echo -e "${CYAN}  ${prefix}Sync: +${added} blocked, -${removed} unblocked, ${total} total active bans${RESET}"
    elif [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}  No changes, ${total} active bans${RESET}"
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    check_dependencies
    setup_state_dir

    echo -e "${CYAN}NIB Router Sync v${VERSION}${RESET}"
    [[ "$DRY_RUN" == "true" ]] && echo -e "${YELLOW}  (dry-run mode)${RESET}"
    echo -e "  LAPI:   ${CROWDSEC_LAPI_URL}"
    echo -e "  Router: ${ROUTER_TYPE} @ ${ROUTER_URL:-<not set>}"
    echo -e "  List:   ${ROUTER_LIST_NAME}"
    [[ "$VERBOSE" == "true" ]] && echo -e "  State:  ${STATE_FILE}"
    echo ""

    validate_config

    if [[ "$DAEMON_MODE" == "true" ]]; then
        echo -e "${CYAN}Running in daemon mode (interval: ${SYNC_INTERVAL}s)${RESET}"
        echo -e "Press Ctrl+C to stop"
        echo ""
        while true; do
            # Reset OpenWrt token each cycle (sessions may expire)
            OPENWRT_TOKEN=""
            sync_decisions
            sleep "$SYNC_INTERVAL"
        done
    else
        sync_decisions
        [[ "$DRY_RUN" == "true" ]] && echo -e "${YELLOW}✓ Dry-run complete (no changes made)${RESET}" || echo -e "${GREEN}✓ Sync complete${RESET}"
    fi
}

main
