# 🌐 NIB - Network in a Box

**One-command network security monitoring** with Suricata IDS and CrowdSec collaborative threat response.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Part of the **in-a-Box** family:
- [**SIB**](https://github.com/yourusername/sib) - SIEM in a Box (runtime security with Falco)
- [**OIB**](https://github.com/yourusername/oib) - Observability in a Box
- **NIB** - Network in a Box (this project)

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

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/nib.git
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

| Feature | NIB | SecurityOnion | Arkime | Zeek |
|---------|-----|---------------|--------|------|
| Setup time | 2 min | 30+ min | 15+ min | 10+ min |
| Signature IDS | Suricata | Suricata | - | - |
| Auto-blocking | CrowdSec | - | - | - |
| Community Intel | CrowdSec network | - | - | - |
| TLS fingerprints | JA3/JA4 | JA3 | JA3 | JA3 |
| Protocol logging | 20+ protocols | 20+ | Session data | 30+ |
| Dashboards | Grafana | Kibana | Custom | - |
| Resource usage | Low (~1GB) | High (8GB+) | Medium | Low |
| Docker-native | Yes | Partial | Yes | Partial |

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
