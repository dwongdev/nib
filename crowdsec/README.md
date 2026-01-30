# CrowdSec - Collaborative Threat Response

Behavioral detection engine with automated blocking and community-shared threat intelligence.

## Components

| Service | Image | Purpose |
|---------|-------|---------|
| nib-crowdsec | crowdsecurity/crowdsec:v1.6 | Security engine - parses logs, detects attacks |
| nib-bouncer-firewall | crowdsecurity/crowdsec-firewall-bouncer-iptables | Blocks banned IPs via iptables |

## How It Works

```
Suricata EVE logs → CrowdSec Engine → Decisions (ban/captcha) → Firewall Bouncer → iptables DROP
                                    ↕
                          CrowdSec Community API
                     (shared threat intelligence)
```

1. **Acquisition**: CrowdSec reads Suricata's EVE JSON logs in real-time
2. **Parsing**: Logs are parsed using the `crowdsecurity/suricata` collection
3. **Scenarios**: Attack patterns are matched (brute force, scans, exploits)
4. **Decisions**: Offending IPs are banned for a configurable duration
5. **Bouncing**: The firewall bouncer adds iptables rules to DROP traffic from banned IPs
6. **Sharing**: Attack data is shared with the CrowdSec community (opt-in), and you receive community blocklists in return

## Collections

Pre-installed collections:

| Collection | Purpose |
|------------|---------|
| `crowdsecurity/suricata` | Parse Suricata EVE alerts and detect attack patterns |
| `crowdsecurity/iptables` | Parse iptables logs for scan/brute force detection |
| `crowdsecurity/linux` | Parse syslog, auth.log for SSH brute force, etc. |

## Community Threat Intelligence

CrowdSec's community model works like a neighborhood watch:

- **Contribute**: Your detected attacks are shared anonymously
- **Receive**: You get a curated blocklist of IPs flagged by the community (~millions of nodes)
- **Opt-in**: Set `CROWDSEC_ENROLL_KEY` in `.env` to join (get key from [app.crowdsec.net](https://app.crowdsec.net))

## Configuration

### Enrollment (Optional)

Register at [app.crowdsec.net](https://app.crowdsec.net) to get an enrollment key. This enables:
- Community blocklist (pre-ban known bad IPs)
- Dashboard with attack statistics
- Alert notifications

```bash
# Set in .env
CROWDSEC_ENROLL_KEY=your-enrollment-key
```

### Ban Duration

Edit `config/profiles.yaml` to adjust ban durations:
- Default: 4 hours for generic attacks
- Suricata-triggered: 24 hours for IDS-detected attacks

### Bouncer

The firewall bouncer blocks at the iptables level with `DROP` action. Blocked packets are logged with prefix `NIB-BLOCKED:` for audit visibility.

## Bouncer Modes

NIB supports two bouncer modes, configured via `BOUNCER_MODE` in `.env`:

### Local Mode (default)

Blocks attackers on the NIB host using iptables. Best when NIB runs directly on the machine you want to protect (server, gateway).

```
BOUNCER_MODE=local
```

```
CrowdSec Engine → iptables bouncer → DROP on this host
```

### Sensor Mode (remote router/firewall)

No local bouncer. CrowdSec's LAPI is exposed on the network so external bouncers can pull decisions. Use this when NIB is a sensor and blocking should happen on a separate router or firewall.

```
BOUNCER_MODE=sensor
```

```
CrowdSec Engine (LAPI exposed on :8080)
    │
    ├──→ Router pulls decisions (native bouncer plugin)
    ├──→ scripts/router-sync.sh pushes decisions to router API
    └──→ CDN bouncer (Cloudflare, etc.)
```

### Setting Up Sensor Mode

1. Set `BOUNCER_MODE=sensor` in `.env`
2. Install: `make install-crowdsec`
3. Generate a bouncer key: `make add-router-bouncer`
4. Choose your blocking method:

#### Option A: Native Router Plugin (pfSense / OPNsense)

Both pfSense and OPNsense have CrowdSec packages available in their plugin repositories.

**pfSense:**
1. Install the `crowdsec` package from System > Package Manager
2. Configure under Services > CrowdSec:
   - LAPI URL: `http://<nib-host>:8080`
   - Bouncer API Key: (from `make add-router-bouncer`)
3. The pfSense bouncer creates a pf alias and firewall rule automatically

**OPNsense:**
1. Install `os-crowdsec` from System > Firmware > Plugins
2. Configure under Services > CrowdSec > Settings:
   - LAPI URL: `http://<nib-host>:8080`
   - Bouncer API Key: (from `make add-router-bouncer`)
3. Enable the firewall bouncer under CrowdSec > Bouncers

#### Option B: Router Sync Script (MikroTik, OpenWrt, generic)

For routers with REST APIs, use the included sync script that polls LAPI and pushes to the router:

```bash
# Configure in .env
ROUTER_TYPE=mikrotik       # mikrotik, opnsense, pfsense, openwrt, generic
ROUTER_URL=https://192.168.1.1
ROUTER_USER=admin
ROUTER_PASS=your-password
ROUTER_LIST_NAME=nib-blocklist
CROWDSEC_LAPI_KEY=<key from make add-router-bouncer>

# One-shot sync
make router-sync

# Continuous daemon (polls every 60s)
make router-sync-daemon
```

**Supported routers:**

| Router | Type | How It Blocks |
|--------|------|---------------|
| MikroTik (RouterOS 7+) | `mikrotik` | Adds/removes entries in `/ip/firewall/address-list` via REST API |
| OPNsense | `opnsense` | Adds/removes IPs in a firewall alias via API |
| pfSense | `pfsense` | Adds/removes IPs in a firewall alias via API |
| OpenWrt | `openwrt` | Adds/removes IPs in an ipset/nftables set via luci-rpc |
| Any REST API | `generic` | POSTs JSON `{"action":"block","ip":"..."}` to your endpoint |

**MikroTik setup:**
1. Enable the REST API on your MikroTik (available in RouterOS 7.1+): `/ip/service enable api-ssl` or use HTTP
2. Create a firewall rule to drop traffic from the address list:
   ```
   /ip firewall filter add chain=forward src-address-list=nib-blocklist action=drop comment="NIB CrowdSec"
   /ip firewall filter add chain=input src-address-list=nib-blocklist action=drop comment="NIB CrowdSec"
   ```
3. Configure `ROUTER_*` variables in `.env` and run `make router-sync-daemon`

**OpenWrt setup:**
1. Enable `luci-mod-rpc` and `luci-lib-json` packages
2. Create an nftables set or ipset: `nft add set inet fw4 nib-blocklist { type ipv4_addr \; }`
3. Add a firewall rule to drop: `nft add rule inet fw4 input ip saddr @nib-blocklist drop`
4. Configure `ROUTER_*` variables in `.env` and run `make router-sync-daemon`

#### Option C: Cloudflare / CDN Bouncer

CrowdSec provides official bouncers for edge services:

- **Cloudflare**: [crowdsec-cloudflare-bouncer](https://github.com/crowdsecurity/cs-cloudflare-bouncer) — blocks at the CDN edge
- **AWS WAF**: [crowdsec-aws-waf-bouncer](https://github.com/crowdsecurity/cs-aws-waf-bouncer)

Point them at your NIB host's LAPI (`http://<nib-host>:8080`) with the bouncer key from `make add-router-bouncer`.

## Management Commands

```bash
# View active decisions (bans)
make decisions

# View CrowdSec alerts
make alerts

# Manually ban an IP
make ban IP=1.2.3.4

# Manually unban an IP
make unban IP=1.2.3.4

# List installed collections
make collections

# Check bouncer status
make bouncer-status

# View CrowdSec metrics
make metrics
```

## Adding Log Sources

Edit `config/acquis.yaml` to add more log sources:

```yaml
# Example: also monitor auth.log
- filenames:
    - /var/log/auth.log
  labels:
    type: syslog
```

## Troubleshooting

```bash
# Check CrowdSec engine status
make logs-crowdsec

# Verify Suricata log parsing
docker exec nib-crowdsec cscli metrics

# Test a scenario manually
docker exec nib-crowdsec cscli alerts list

# Check bouncer connection
docker exec nib-crowdsec cscli bouncers list

# Inspect iptables rules
sudo iptables -L crowdsec-blacklists -n
```
