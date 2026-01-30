# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security details to the maintainers
3. Include steps to reproduce, impact assessment, and suggested fix if possible
4. You will receive a response within 48 hours

## Security Considerations

### Container Capabilities

**Suricata** requires elevated capabilities for packet capture:
- `NET_ADMIN` - Network interface configuration
- `NET_RAW` - Raw socket access for packet capture
- `SYS_NICE` - Process priority for real-time capture
- `network_mode: host` - Direct access to host network interfaces

**CrowdSec Firewall Bouncer** requires:
- `NET_ADMIN` - iptables rule management
- `NET_RAW` - Network socket access
- `network_mode: host` - Direct iptables access

These are required for the tools to function. They are isolated to their respective containers.

### Network Exposure

By default:
- **VictoriaLogs**: Bound to `127.0.0.1` (local only)
- **CrowdSec API**: Bound to `127.0.0.1` (local only)
- **Grafana**: Bound to `0.0.0.0` (accessible externally, password-protected)
- **Suricata**: No exposed ports (host network mode for capture only)

### Data Privacy

- Suricata captures network metadata (IPs, domains, headers, TLS info)
- Full packet payloads are logged for alerts only
- Flow and protocol data is logged without payload content
- All data is stored locally in VictoriaLogs
- CrowdSec community sharing is opt-in and anonymized

### CrowdSec Community Participation

When enrolled in the CrowdSec community:
- Attack signals (attacker IP + scenario) are shared anonymously
- No payload data, internal IPs, or hostnames are shared
- You receive community-curated blocklists in return
- Enrollment is optional (set `CROWDSEC_ENROLL_KEY` in `.env`)

## Security Best Practices

1. **Keep rules updated**: Run `make update-rules` regularly
2. **Review ban decisions**: Check `make decisions` periodically for false positives
3. **Restrict storage access**: Keep `STORAGE_BIND=127.0.0.1` unless needed
4. **Change Grafana password**: Auto-generated on install, rotate periodically
5. **Monitor CrowdSec metrics**: Run `make metrics` to check detection health
6. **Audit custom rules**: Review `suricata/rules/custom.rules` for coverage
7. **Update container images**: Pull latest images periodically
8. **Review iptables**: Check `sudo iptables -L crowdsec-blacklists -n` for active blocks

## Known Limitations

- Suricata cannot inspect encrypted payload content (TLS/HTTPS) without termination
- CrowdSec decisions are IP-based; shared IPs (NAT) may cause collateral blocking
- JA3/JA4 fingerprints can be spoofed by sophisticated attackers
- ET Open rules have a delay compared to ET Pro (commercial)
