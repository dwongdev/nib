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
