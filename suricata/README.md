# Suricata - Network Intrusion Detection

Network-based threat detection engine using deep packet inspection, protocol analysis, and signature matching.

## Components

| Service | Image | Purpose |
|---------|-------|---------|
| nib-suricata | jasonish/suricata:7.0 | Network IDS with ET Open rules |

## What It Detects

- **Malware & C2**: Known malware signatures, command-and-control beacons, exploit kit traffic
- **Network Attacks**: Port scans, brute force, SQL injection, XSS, directory traversal
- **Protocol Anomalies**: Malformed HTTP, DNS tunneling, TLS anomalies, SMB exploits
- **Policy Violations**: Crypto mining, tor usage, unauthorized services
- **Lateral Movement**: Pass-the-hash, DCE/RPC exploitation, SMB lateral movement

## Network Capture

Suricata runs with `network_mode: host` and captures traffic on the interface specified by `SURICATA_INTERFACE` (default: `eth0`). It requires `NET_ADMIN`, `NET_RAW`, and `SYS_NICE` capabilities.

## Logging

All events are written as EVE JSON to `/var/log/suricata/eve.json` inside the container. The log shipper (Vector) reads from the `suricata-logs` volume and forwards to storage.

### EVE JSON Event Types

| Type | Description |
|------|-------------|
| `alert` | Rule match with payload and metadata |
| `dns` | DNS queries and answers |
| `http` | HTTP requests with headers |
| `tls` | TLS handshake with JA3/JA4 fingerprints |
| `flow` | Network flow records |
| `anomaly` | Protocol anomalies |
| `files` | File extraction with hashes |
| `ssh` | SSH protocol metadata |
| `smb` | SMB/CIFS protocol events |
| `stats` | Engine performance statistics |

## Rules

### ET Open Rules

Emerging Threats Open rules are the default ruleset, updated via `make update-rules`. These provide ~40,000 signatures covering:

- Malware signatures and indicators
- Exploit detection (CVEs)
- Command & control communication
- Policy violations
- Scan detection

### Custom Rules

Add custom rules to `rules/custom.rules`. These persist across rule updates.

```
# Example: detect outbound connection to suspicious port
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"NIB - Outbound to Port 4444"; classtype:trojan-activity; sid:9000001; rev:1;)
```

### Rule Management

```bash
# Update ET Open rules
make update-rules

# Test rule syntax
make test-rules

# Reload rules without restart
make reload-rules
```

## Configuration

Edit `config/suricata.yaml` for advanced tuning:

- **HOME_NET**: Your internal network ranges (default: RFC1918)
- **Threading**: Auto-detected, override with `threading.detect-thread-ratio`
- **Memory**: Tune `stream.memcap`, `flow.memcap` for your traffic volume
- **App-layer**: Enable/disable protocol parsers

## TLS/JA3/JA4 Fingerprinting

Suricata extracts TLS fingerprints for every encrypted connection:

- **JA3**: Client TLS fingerprint (identifies malware families)
- **JA3S**: Server TLS fingerprint
- **JA4**: Next-generation TLS fingerprint (more granular)

These appear in the `tls` EVE events and are indexed for dashboard queries.

## Community ID

All EVE events include a [Community ID](https://github.com/corelight/community-id-spec) flow hash, enabling correlation across tools (Suricata, Zeek, Osquery, etc.).

## Troubleshooting

```bash
# Check Suricata status
make status

# View Suricata logs
make logs-suricata

# Check interface capture
make shell-suricata
suricatasc -c "iface-stat default"

# Verify rules loaded
suricatasc -c "ruleset-stats"

# Test with a signature trigger
curl http://testmynids.org/uid/index.html
```
