# Roadmap

This is a living roadmap. Priorities may shift based on feedback and community contributions.

## 0-3 months

- CI/CD linting for Suricata rules and YAML configs
- Automated rule update schedule (cron/systemd timer)
- GeoIP enrichment for source/destination IPs
- Additional Grafana dashboards (HTTP analysis, flow analysis)
- Integration guide for running alongside SIB

## 3-6 months

- Zeek integration for deeper protocol analysis
- PCAP capture mode for forensic analysis
- Alert correlation between Suricata and CrowdSec
- Notification outputs (Slack, Discord, PagerDuty)
- Fleet deployment for multi-host network monitoring

## 6-12 months

- Network anomaly detection (ML-based baseline)
- Threat hunting query library
- MITRE ATT&CK mapping for network signatures
- Integration with SIB for unified security view
- Custom CrowdSec scenario builder

## How you can help

- Submit Suricata custom rules for common attack patterns
- Build Grafana dashboards for specific use cases
- Test on different Linux distributions and network configurations
- Report false positives from CrowdSec decisions
- Write documentation for deployment scenarios
