# network-monitor

Continuously monitors internet-facing IPs, FQDNs, and subnets for changes in network surface. Detects and logs:

- Ports opening or closing
- Service version changes
- Raw service banner changes (SSH, FTP, SMTP, etc.)
- HTTP/S response header changes (`Server`, `X-Powered-By`, `Strict-Transport-Security`, etc.)
- DNS record changes (A, AAAA, CNAME)
- Hosts going up or down

All changes are emitted as structured JSON log records compatible with GCP Cloud Logging. Every scan snapshot is persisted to a database (SQLite for local dev, PostgreSQL/Cloud SQL for production), enabling historical diffs and independent scan/diff processes.

---

## How it works

Each cycle has two phases:

1. **Scan** — runs nmap (port/version detection), grabs raw TCP banners for non-HTTP ports, issues HEAD requests to HTTP/S ports, and resolves DNS for any FQDNs. All results are written to the database.

2. **Diff** — compares the latest scan against the previous one for each host and FQDN. Detected changes are written to the database as `change_events` and emitted as structured log records.

`MONITOR_MODE=all` (default) runs both phases in sequence. `scan` and `diff` can be run as separate processes pointing at the same database.

---

## Quickstart (local)

```bash
pip install -r requirements.txt
# nmap must also be installed: apt install nmap / brew install nmap

MONITOR_TARGETS=192.0.2.1,example.com \
DATABASE_URL=sqlite:///data/monitor.db \
python -m monitor.main
```

---

## Configuration

Settings can be provided as environment variables, a YAML file, or both. Environment variables always override YAML.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `MONITOR_TARGETS` | — | Comma-separated IPs, CIDRs, FQDNs |
| `DATABASE_URL` | `sqlite:///data/monitor.db` | SQLite or PostgreSQL URL |
| `CLIENT_ID` | `default` | Tenant identifier — all DB rows are scoped to this |
| `MONITOR_MODE` | `all` | `scan` / `diff` / `all` |
| `MONITOR_RUN_MODE` | `job` | `job` (single-shot) or `service` (loop) |
| `MONITOR_SCAN_INTERVAL_SECONDS` | `3600` | Loop interval in service mode |
| `MONITOR_NMAP_ARGUMENTS` | `-sV --open -T4` | Arguments passed to nmap |
| `MONITOR_NMAP_PORTS` | `top-1000` | Port scope: `top-1000`, `1-65535`, or explicit list |
| `MONITOR_NMAP_SUDO` | `false` | Enable SYN scan (requires `CAP_NET_RAW`) |
| `MONITOR_ALERT_MIN_SEVERITY` | `info` | Minimum severity to emit: `info` / `warning` / `critical` |
| `MONITOR_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `MONITOR_LOG_CHANGES_ONLY` | `false` | Suppress no-change INFO log lines |
| `CONFIG_FILE` | — | Path to a YAML config file |

See `.env.example` for the full list.

### YAML config (single client)

```yaml
# config.yaml
targets:
  - 203.0.113.0/28
  - api.example.com

database_url: postgresql://user:pass@host/monitor
nmap_ports: top-1000
run_mode: job
```

```bash
CONFIG_FILE=config.yaml python -m monitor.main
```

### YAML config (multiple clients)

Define a `clients:` section to monitor multiple tenants in a single process. Each client gets a separate `client_id` and its data is fully isolated in the database. Global settings are inherited by all clients and can be overridden per-client.

```yaml
# config.yaml

# Global defaults
database_url: postgresql://user:pass@host/monitor
nmap_ports: top-1000
log_level: INFO
run_mode: job

clients:
  acme:
    targets:
      - 203.0.113.0/24
      - api.acme.com

  globex:
    targets:
      - 198.51.100.0/28
      - globex.example.com
    nmap_ports: top-500        # override for this client only
    alert_min_severity: warning
```

```bash
CONFIG_FILE=config.yaml python -m monitor.main
```

If a client is removed from the config and later re-added, the diff picks up from the last scan in the database — any changes during the gap are detected correctly.

---

## Change event severity

| Severity | Change types |
|---|---|
| `critical` | `PORT_OPENED`, `NEW_HOST`, `HOST_DOWN`, `DNS_RECORD_CHANGED` |
| `warning` | `PORT_CLOSED`, `SERVICE_CHANGED`, `DNS_IP_ADDED`, `DNS_IP_REMOVED`, `DNS_CNAME_CHANGED`, `DNS_RESOLUTION_FAILED` |
| `info` | `VERSION_CHANGED`, `BANNER_CHANGED`, `HTTP_HEADER_CHANGED`, `DNS_AAAA_CHANGED`, `DNS_RESOLUTION_RESTORED`, `DNS_NEW_FQDN` |

---

## Docker

```bash
docker build -t network-monitor .

docker run --rm \
  -e MONITOR_TARGETS=203.0.113.0/28,api.example.com \
  -e DATABASE_URL=postgresql://user:pass@host/monitor \
  network-monitor
```

For multi-client config, mount the YAML file:

```bash
docker run --rm \
  -e CONFIG_FILE=/app/config.yaml \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -e DATABASE_URL=postgresql://user:pass@host/monitor \
  network-monitor
```

---

## GCP deployment

### Cloud Run Job + Cloud Scheduler (recommended)

1. Push the image to Artifact Registry
2. Create a Cloud Run Job with the image; set environment variables or mount a config YAML via Secret Manager
3. Create a Cloud Scheduler job to trigger it on your desired interval (e.g. every hour)

Use `MONITOR_RUN_MODE=job` (the default). The job runs one full scan+diff cycle and exits.

### Cloud Run Service (continuous)

Set `MONITOR_RUN_MODE=service` and `MONITOR_SCAN_INTERVAL_SECONDS=3600`. Set `min-instances=1` so the service is never scaled to zero.

### Database

Use Cloud SQL (PostgreSQL) and set `DATABASE_URL` via Secret Manager. The schema is created automatically on first run.

### Alerting

The monitor emits structured JSON to stdout on every change. In GCP, use **log-based alerts** in Cloud Logging to get notified without any additional infrastructure:

1. Cloud Logging → **Log-based alerts**
2. Set a filter, for example:
   ```
   jsonPayload.change_type=~"PORT_OPENED|NEW_HOST|HOST_DOWN"
   ```
   or per-client:
   ```
   jsonPayload.client_id="acme"
   jsonPayload.severity="critical"
   ```
3. Attach a notification channel (email, PagerDuty, Slack webhook, SMS)

For Slack specifically: log-based alert → Pub/Sub topic → Cloud Function that POSTs to a Slack incoming webhook.

---

## Running tests

```bash
pip install pytest
pytest tests/
```
