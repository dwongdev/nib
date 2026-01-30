# Grafana - Network Security Dashboards

Pre-configured dashboards for Suricata network events and CrowdSec threat response.

## Components

| Service | Image | Purpose |
|---------|-------|---------|
| nib-grafana | grafana/grafana:11.4.0 | Dashboard and visualization |

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **Network Security Overview** | Alert timeline, top signatures, source/dest IPs, alert categories |
| **DNS Analysis** | Query volume, top domains, NXDOMAIN tracking, DNS client activity |
| **TLS & Fingerprints** | TLS versions, JA3/JA4 fingerprints, SNI analysis, certificate issues |
| **CrowdSec Decisions** | Blocked vs allowed, banned IPs, blocked signatures |

## Access

Default URL: `http://localhost:3001`

- Username: `admin`
- Password: Set in `.env` as `GRAFANA_ADMIN_PASSWORD` (auto-generated on install)

## Configuration

Datasources and dashboards are provisioned automatically from the `provisioning/` and `dashboards/` directories.

Port defaults to `3001` to avoid conflicts with SIB's Grafana on `3000`.
