# 🌐 NIB - NIDS in a Box

**One-command network security monitoring** with Suricata IDS and CrowdSec collaborative threat response.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Part of the **in-a-Box** family:
- [**SIB**](https://github.com/matijazezelj/sib) - SIEM in a Box (runtime security with Falco)
- [**OIB**](https://github.com/matijazezelj/oib) - Observability in a Box
- **NIB** - NIDS in a Box (this project)

## IDS vs IPS: What NIB Actually Does

**IDS** (Intrusion Detection System) = Passive monitoring, alerts only  
**IPS** (Intrusion Prevention System) = Inline blocking, drops packets in real-time

NIB operates in two modes:

| Mode | How It Works | Blocking | Best For |
|------|--------------|----------|----------|
| **Local** (default) | NIB runs on the host you want to protect | iptables blocks on that host | Servers directly exposed to internet |
| **Sensor** (mirror/SPAN) | NIB receives mirrored traffic from a switch | Pushes bans to router/firewall | Dedicated IDS appliance, full network visibility |

### Sensor Mode (Port Mirror) — What You're Really Getting

When using a **port mirror/SPAN**, NIB is:
- ✅ **IDS**: Suricata detects threats and generates alerts in real-time
- ⚠️ **Delayed IPS**: CrowdSec pushes blocks to your router/firewall, but it's **not instant** — the first packets of an attack get through before the ban kicks in (typically 1-5 seconds)

This is **not** inline IPS. For true real-time packet dropping, traffic would need to flow *through* NIB (which adds latency and creates a single point of failure).

**Sensor mode is ideal when:**
- You want full network visibility without being inline
- Your router/firewall can receive CrowdSec decisions (pfSense, OPNsense, MikroTik, etc.)
- You're okay with blocking attackers *after* initial detection rather than on the first packet

### Local Mode — True IPS for That Host

When NIB runs directly on an internet-facing server (not mirrored traffic), the iptables bouncer **is** a real IPS for that specific host — it drops packets before they reach your applications.

## Features

- **Network IDS**: Suricata deep packet inspection with 40,000+ ET Open signatures
- **Protocol Analysis**: HTTP, DNS, TLS, SMB, SSH, and 20+ protocol parsers
- **TLS Fingerprinting**: JA3/JA4 fingerprints to identify malware and suspicious clients
- **DNS Monitoring**: Full query/response logging, NXDOMAIN tracking for DGA detection
- **Automated Blocking**: CrowdSec firewall bouncer drops traffic from attacking IPs
- **Community Intel**: Shared threat intelligence from millions of CrowdSec nodes
- **Dashboards**: Pre-built Grafana dashboards for alerts, DNS, TLS, and blocking decisions
- **Community ID**: Cross-tool flow correlation using the Community ID standard

## Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │                   Network Traffic                │
                    └────────────────────┬────────────────────────────┘
                                         │
                              ┌──────────▼──────────┐
                              │    Suricata IDS      │
                              │  (Deep Packet Insp.) │
                              └──────────┬──────────┘
                                         │ EVE JSON
                          ┌──────────────┼──────────────┐
                          ▼              ▼              ▼
                  ┌──────────────┐ ┌──────────┐ ┌──────────────┐
                  │   CrowdSec   │ │  Vector   │ │  fast.log    │
                  │  (Behavioral │ │  (Log     │ │  (Quick      │
                  │   Detection) │ │  Shipper) │ │   Review)    │
                  └──────┬───────┘ └─────┬─────┘ └──────────────┘
                         │               │
                  ┌──────▼───────┐ ┌─────▼──────────┐
                  │  Firewall    │ │  VictoriaLogs   │
                  │  Bouncer     │ │  (Log Storage)  │
                  │  (iptables)  │ └─────┬──────────┘
                  └──────────────┘       │
                                   ┌─────▼──────────┐
                                   │    Grafana      │
                                   │  (Dashboards)   │
                                   └────────────────┘
```

## Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Docker | 20.10+ |
| Docker Compose | v2+ |
| Linux | Kernel 4.15+ (for AF_PACKET) |
| RAM | 2 GB |
| Disk | 10 GB |

> **Note**: Suricata requires `network_mode: host` and `NET_ADMIN` + `NET_RAW` capabilities for packet capture. CrowdSec's firewall bouncer requires `NET_ADMIN` for iptables access.

### Hardware Sizing by Link Speed

Suricata performs deep packet inspection on every packet. CPU is the main bottleneck — each worker thread handles ~300-400 Mbps with the full ET Open ruleset.

| Link Speed | CPU | RAM | Storage | Example Hardware |
|------------|-----|-----|---------|------------------|
| **100 Mbps** | 2 cores | 2 GB | 20 GB | Raspberry Pi 4 (4GB), any old PC |
| **500 Mbps** | 4 cores | 4 GB | 50 GB | Intel N100 mini PC, NUC |
| **1 Gbps** | 4-6 cores | 8 GB | 100 GB | Intel N305, i5 NUC, old desktop |
| **2.5 Gbps** | 8 cores | 16 GB | 200 GB | i5/i7 desktop, Ryzen 5 |
| **10 Gbps** | 16+ cores | 32 GB | 500 GB+ | Xeon/EPYC server, high-end workstation |

**NIC recommendations:**
- **1 Gbps**: Any Intel NIC (i210, i350) — avoid Realtek for high packet rates
- **2.5 Gbps**: Intel i225-V, Realtek RTL8125
- **10 Gbps**: Intel X520/X540, Mellanox ConnectX-3/4 (requires kernel drivers)

**Notes:**
- These are for **sustained** throughput. Bursty home traffic uses far less — a 4-core system often handles 1 Gbps fine
- 10 Gbps requires careful tuning (RSS, CPU affinity, ring buffers) — see [docs/10g-tuning.md](docs/10g-tuning.md) if available
- VMs work great — just ensure virtio or SR-IOV passthrough for high speeds
- Check for packet drops: `make shell-suricata` then `suricatasc -c "iface-stat default"`

## Quick Start

```bash
# Clone the repository
git clone https://github.com/matijazezelj/nib.git
cd nib

# Install everything
make install

# Open Grafana dashboard
make open
```

That's it. Suricata is monitoring your network interface, CrowdSec is analyzing alerts and blocking attackers, and Grafana has four pre-built dashboards.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **Network Security Overview** | Alert timeline, top signatures, source/dest IPs, categories |
| **DNS Analysis** | Query volume, top domains, NXDOMAIN tracking, client activity |
| **TLS & Fingerprints** | TLS versions, JA3/JA4 hashes, SNI analysis, certificate issues |
| **CrowdSec Decisions** | Blocked vs allowed traffic, banned IPs, blocked signatures |

## Commands

### Installation & Lifecycle

| Command | Description |
|---------|-------------|
| `make install` | Install all stacks |
| `make start` | Start all services |
| `make stop` | Stop all services |
| `make restart` | Restart all services |
| `make uninstall` | Remove all containers and volumes |
| `make status` | Show service status and health |
| `make health` | Quick health check |

### Suricata IDS

| Command | Description |
|---------|-------------|
| `make update-rules` | Download latest ET Open rules |
| `make reload-rules` | Reload rules without restart |
| `make test-rules` | Validate rule syntax |
| `make logs-suricata` | Tail Suricata logs |
| `make logs-alerts` | Tail IDS alert log |

### CrowdSec Threat Response

| Command | Description |
|---------|-------------|
| `make decisions` | List active bans |
| `make alerts` | List detected attacks |
| `make ban IP=1.2.3.4` | Manually ban an IP for 24h |
| `make unban IP=1.2.3.4` | Remove a ban |
| `make collections` | List installed detection collections |
| `make bouncer-status` | Check bouncer connection |
| `make metrics` | Show CrowdSec statistics |

### Router Sync (Sensor Mode)

| Command | Description |
|---------|-------------|
| `make add-router-bouncer` | Generate a bouncer API key for your router |
| `make router-sync` | Push CrowdSec decisions to router (one-shot) |
| `make router-sync-daemon` | Push CrowdSec decisions to router (continuous) |

### Testing

| Command | Description |
|---------|-------------|
| `make test-alert` | Trigger a test IDS alert |
| `make test-dns` | Generate test DNS queries |

### Utilities

| Command | Description |
|---------|-------------|
| `make open` | Open Grafana in browser |
| `make ps` | Show running containers |
| `make logs` | Tail all service logs |
| `make info` | Show endpoints and credentials |
| `make check-ports` | Verify port availability |
| `make validate` | Check configuration files |

## Configuration

### Network Interface

Set the monitored interface in `.env`:

```bash
SURICATA_INTERFACE=eth0    # Change to your interface (eth0, ens33, etc.)
```

Find your interface: `ip link show` or `ifconfig`

### Port Mirroring (Sensor Mode)

When using NIB as a dedicated sensor, configure your switch to mirror traffic:

| Switch | Setup Guide |
|--------|-------------|
| **UniFi** | Ports tab → Port Mirroring → Select source/destination |
| **TP-Link Omada** | Ports tab → Port Mirroring (IDS only, no bouncer yet) |
| **MikroTik** | Full support with `ROUTER_TYPE=mikrotik` |
| **Cisco** | Monitor session CLI or web UI |
| **Netgear** | Monitoring → Mirroring |

See **[docs/switch-mirroring.md](docs/switch-mirroring.md)** for detailed setup guides.

### Home Network

Define your internal network ranges:

```bash
HOME_NET=[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]
```

### CrowdSec Enrollment

Register at [app.crowdsec.net](https://app.crowdsec.net) for community blocklists:

```bash
CROWDSEC_ENROLL_KEY=your-enrollment-key
```

### Custom Suricata Rules

Add rules to `suricata/rules/custom.rules`:

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"NIB - Outbound to Port 4444"; classtype:trojan-activity; sid:9000001; rev:1;)
```

Then reload: `make reload-rules`

## Project Structure

```
nib/
├── suricata/              Suricata IDS configuration
│   ├── compose.yaml       Docker Compose for Suricata
│   ├── config/
│   │   └── suricata.yaml  Engine configuration
│   └── rules/
│       ├── custom.rules   Your custom rules
│       └── suricata.rules ET Open rules (downloaded)
├── crowdsec/              CrowdSec security engine
│   ├── compose.yaml       Docker Compose for CrowdSec + bouncer
│   └── config/
│       ├── acquis.yaml    Log acquisition sources
│       ├── profiles.yaml  Ban duration profiles
│       └── bouncer.yaml   Firewall bouncer config
├── storage/               Log aggregation
│   ├── compose.yaml       Docker Compose for VictoriaLogs + Vector
│   └── vector.yaml        Log shipping pipeline
├── grafana/               Dashboards
│   ├── compose.yaml       Docker Compose for Grafana
│   ├── provisioning/      Auto-configured datasources
│   └── dashboards/        Pre-built JSON dashboards
├── docs/                  Documentation
├── scripts/               Helper scripts
├── certs/                 TLS certificates
├── examples/              Example configurations
├── Makefile               All management commands
├── .env.example           Configuration template
├── README.md              This file
├── SECURITY.md            Security policy
├── CONTRIBUTING.md        Contribution guidelines
├── ROADMAP.md             Development roadmap
└── LICENSE                Apache 2.0
```

## Comparison

Most network security tools **detect and alert** — they assume someone is watching. NIB **detects, blocks, and shares**: Suricata finds threats, CrowdSec blocks them automatically, and the community network means you benefit from attacks detected by millions of other nodes before they reach you.

| | NIB | Security Onion | SELKS | Malcolm | Zeek |
|---|---|---|---|---|---|
| **Setup** | `make install` | 30-60 min | 15-30 min | 20-30 min | Manual |
| **Auto-blocking** | Yes (CrowdSec) | No | No | No | No |
| **Community intel** | Millions of nodes | No | No | No | No |
| **Router integration** | Built-in | No | No | No | No |
| **RAM** | ~1 GB | 8-16 GB | 4-8 GB | 8-16 GB | ~512 MB |
| **Full PCAP** | No | Yes | Optional | Yes | No |
| **Dashboards** | 4 Grafana | 20+ Kibana | 10+ Scirius | 15+ | None |

For detailed comparisons (when to choose NIB vs when to choose something else), see **[docs/comparison.md](docs/comparison.md)**.

## How It Works

### Data Flow

Suricata runs in Docker with `network_mode: host`, giving it direct access to the host's network interfaces via AF_PACKET (zero-copy kernel capture). It inspects every packet and writes structured JSON events to a shared Docker volume:

```
Network packets on eth0
    │
    ▼
Suricata (AF_PACKET, host network) ──→ /var/log/suricata/eve.json (Docker volume)
                                                │
                                 ┌──────────────┼──────────────┐
                                 ▼              ▼              ▼
                           CrowdSec        Vector          fast.log
                           reads EVE       reads EVE       (plain text
                           for attack      for shipping     alert log)
                           patterns        to storage
                                │              │
                                ▼              ▼
                           Firewall       VictoriaLogs ──→ Grafana
                           Bouncer        (query engine)   (dashboards)
                           (iptables
                            DROP)
```

Both CrowdSec and Vector read from the same Docker volume. CrowdSec detects attack patterns (brute force, scans, exploit attempts) and instructs the firewall bouncer to add iptables DROP rules. The bouncer also runs in `network_mode: host` so it directly manipulates the host's iptables.

### Where to Deploy

The key constraint: **Suricata needs to see the traffic**, and **the bouncer needs iptables on a machine where blocking matters**.

#### 1. Linux Router / Gateway (best coverage)

If you have a Linux box as your network gateway, this is the ideal placement. Suricata sees all traffic entering and leaving your network, and iptables blocks happen before packets reach internal hosts.

```
Internet ──→ [NIB on Linux Router] ──→ Internal Network
              Suricata sees ALL        Blocked IPs never
              inbound + outbound       reach internal hosts
```

Works with: a dedicated Linux box, a repurposed PC running Debian/Ubuntu, or any Linux-based firewall.

#### 2. Port Mirror / SPAN (dedicated sensor)

If your router isn't Linux (or you don't want to modify it), configure a SPAN/mirror port on your managed switch to copy all traffic to a dedicated NIB host. Suricata sees everything, but the iptables bouncer only blocks on the NIB host itself.

```
Switch (SPAN port) ──mirror──→ [NIB Sensor]
                                Suricata sees all traffic
                                Bouncer blocks on sensor only
```

To block on your actual firewall, set `BOUNCER_MODE=sensor` in `.env`. This disables the local iptables bouncer and exposes the CrowdSec LAPI so remote bouncers can pull decisions. Then choose how to push bans to your router:

**Native plugin (easiest):** pfSense and OPNsense have CrowdSec packages in their plugin repos. Point them at `http://<nib-host>:8080` with a key from `make add-router-bouncer`.

**Router sync script:** For MikroTik, OpenWrt, or any router with a REST API:

```bash
# In .env
BOUNCER_MODE=sensor
ROUTER_TYPE=mikrotik          # mikrotik, opnsense, pfsense, openwrt, generic
ROUTER_URL=https://192.168.1.1
ROUTER_USER=admin
ROUTER_PASS=your-password

# Start continuous sync
make router-sync-daemon
```

**CDN/cloud:** CrowdSec has official bouncers for Cloudflare, AWS WAF, nginx, and HAProxy — all can pull from your NIB LAPI.

See [crowdsec/README.md](crowdsec/README.md) for detailed setup instructions per router.

#### 3. Individual Server (protect one host)

Run NIB on any Linux server to monitor and protect that specific machine. Suricata only sees traffic to/from that host, but iptables blocking is fully effective since it's on the same machine.

```
Internet ──→ [Web Server with NIB]
              Suricata monitors this host's traffic
              Bouncer blocks attackers at iptables
```

Good for: web servers, API servers, bastion hosts, any internet-facing Linux box.

#### 4. Alongside SIB (defense in depth)

Run both on the same host for complementary coverage:

```
[Host running SIB + NIB]
  SIB (Falco)  → watches syscalls: file access, process execution, container activity
  NIB (Suricata) → watches network: traffic patterns, DNS, TLS, protocol anomalies
```

They don't share anything — separate Docker networks (`sib-network` vs `nib-network`), separate storage, separate Grafana instances (port 3000 vs 3001). You can also point both at a single Grafana by adding the other's datasource.

### Choosing a Network Interface

Set `SURICATA_INTERFACE` in `.env` to the interface carrying the traffic you want to monitor:

```bash
# Find your interfaces
ip link show

# Common examples:
SURICATA_INTERFACE=eth0       # Physical ethernet
SURICATA_INTERFACE=ens33      # VMware / modern Linux naming
SURICATA_INTERFACE=enp0s3     # VirtualBox
SURICATA_INTERFACE=br0        # Bridge interface (router)
SURICATA_INTERFACE=wlan0      # WiFi (limited - no promiscuous mode on most drivers)
```

For a router/gateway, use the **LAN-facing interface** to see internal traffic, or the **WAN-facing interface** to see external threats, or a **bridge interface** to see both.

## How It Works With SIB

NIB and SIB complement each other:

- **SIB** monitors what happens **inside** your hosts (syscalls, file access, process execution)
- **NIB** monitors what happens **on the network** (traffic, DNS, TLS, attacks)

They can run side by side. Use separate Grafana instances (SIB on port 3000, NIB on port 3001) or combine dashboards into a single Grafana by pointing one at both storage backends.

## Security Notes

- Suricata runs with `network_mode: host` and elevated capabilities for packet capture
- CrowdSec's firewall bouncer needs `NET_ADMIN` to manage iptables rules
- VictoriaLogs is bound to localhost by default (`STORAGE_BIND=127.0.0.1`)
- CrowdSec API is bound to localhost by default
- Grafana has anonymous access disabled, sign-up disabled
- Admin password is auto-generated on first `make install`
- All containers use `no-new-privileges` and `cap_drop: ALL` with only required capabilities added back
- Non-host-network containers run with `read_only: true` filesystems

## Security Hardening

NIB runs with elevated privileges — it's part of your trust boundary. For production deployments:

- **[Threat Model](docs/threat-model.md)** — What NIB detects, what it doesn't, and what happens if NIB itself is compromised
- **[Production Checklist](docs/production-checklist.md)** — Step-by-step hardening checklist (copy-paste friendly)
- **[Known Limitations](docs/known-limitations.md)** — WiFi capture, NIC offloading, false positives, blocking collateral, iptables interaction

Run `make audit` to verify your security posture:

```bash
make audit
```

### Privacy Mode

By default, NIB ships full protocol metadata to storage (DNS queries, HTTP URLs, TLS SNI, flow records). Set `PRIVACY_MODE=alerts-only` in `.env` to restrict what reaches dashboards:

```bash
PRIVACY_MODE=alerts-only
```

**What `alerts-only` does:**
- Only `alert` and `stats` events are shipped to VictoriaLogs (DNS, HTTP, TLS, flow events are dropped at the Vector level)
- Alert events keep: 5-tuple (src/dst IP + port, protocol), timestamp, signature ID/name, severity, action, community ID
- Alert events strip: app-layer fields (`http.*`, `tls.*`, `dns.*`), payload, packet data, alert metadata
- Suricata still logs everything to EVE JSON (CrowdSec needs the full stream for behavioral detection)

**Dashboard impact:**
| Dashboard | Status |
|-----------|--------|
| Network Security Overview | Works (uses alert data) |
| CrowdSec Decisions | Works (uses alert + stats) |
| DNS Analysis | **Empty** (dns events not shipped) |
| TLS & Fingerprints | **Empty** (tls events not shipped) |

## Troubleshooting

### Suricata not capturing traffic

```bash
# Check the interface name
ip link show

# Verify Suricata sees packets
make shell-suricata
suricatasc -c "iface-stat default" /var/run/suricata/suricata-command.socket
```

### No alerts in Grafana

```bash
# Trigger a test alert
make test-alert

# Check Vector is shipping logs
make logs-vector

# Check VictoriaLogs received data
curl -s "http://localhost:9428/select/logsql/query?query=*&limit=5"
```

### CrowdSec bouncer not blocking

```bash
# Check bouncer is connected
make bouncer-status

# Check active decisions
make decisions

# Check iptables rules
sudo iptables -L crowdsec-blacklists -n
```

## License

[Apache 2.0](LICENSE)

## Acknowledgments

- [Suricata](https://suricata.io/) - Open Source IDS/IPS engine
- [CrowdSec](https://crowdsec.net/) - Collaborative security engine
- [VictoriaLogs](https://docs.victoriametrics.com/victorialogs/) - Log storage
- [Vector](https://vector.dev/) - Log shipper
- [Grafana](https://grafana.com/) - Dashboards
- [Emerging Threats](https://rules.emergingthreats.net/) - Open ruleset
