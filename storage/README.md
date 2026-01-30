# Storage - Log Aggregation & Retention

Collects Suricata EVE JSON events via Vector and stores them in VictoriaLogs for querying and dashboards.

## Components

| Service | Image | Purpose |
|---------|-------|---------|
| nib-victorialogs | victoriametrics/victoria-logs:v1.3.1 | Log storage and query engine |
| nib-vector | timberio/vector:0.43.1-alpine | Log shipper (Suricata EVE → VictoriaLogs) |

## Data Flow

```
Suricata EVE JSON → Vector (parse + route) → VictoriaLogs → Grafana Dashboards
                                                           → LogsQL queries
```

## Event Routing

Vector parses Suricata's EVE JSON and routes events by type for optimized storage:

| Event Type | Stream Labels | Description |
|------------|--------------|-------------|
| `alert` | source, event_type, category, action | IDS alert matches |
| `dns` | source, event_type | DNS queries and answers |
| `tls` | source, event_type | TLS handshakes with JA3/JA4 |
| `http` | source, event_type | HTTP transactions |
| `flow` | source, event_type | Network flow records |
| `stats` | source, event_type | Engine statistics |

## Configuration

### Retention

Set in `.env`:
```bash
VICTORIALOGS_RETENTION=168h  # 7 days (default)
```

### Storage Bind

```bash
STORAGE_BIND=127.0.0.1  # Local only (default)
STORAGE_BIND=0.0.0.0    # Accept remote queries
```

## Querying

VictoriaLogs uses [LogsQL](https://docs.victoriametrics.com/victorialogs/logsql/) for queries:

```
# All alerts
_stream:{source="suricata", event_type="alert"}

# High severity alerts
_stream:{source="suricata", event_type="alert"} AND severity:1

# DNS queries for a domain
_stream:{source="suricata", event_type="dns"} AND "example.com"

# TLS connections with specific JA3
_stream:{source="suricata", event_type="tls"} AND ja3.hash:"abc123"

# HTTP requests to a host
_stream:{source="suricata", event_type="http"} AND http.hostname:"suspicious.com"
```

## Troubleshooting

```bash
# Check Vector is shipping logs
make logs-vector

# Check VictoriaLogs is receiving data
curl -s "http://localhost:9428/select/logsql/stats_query?query=*&time=5m"

# Check volume sizes
docker system df -v | grep nib
```
