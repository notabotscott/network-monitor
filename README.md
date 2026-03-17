# network-monitor

Continuously monitors internet-facing IPs, FQDNs, and subnets for changes in network surface. Detects and logs:

- Ports opening or closing
- Service version changes
- Raw service banner changes (SSH, FTP, SMTP, etc.)
- HTTP/S response header changes (`Server`, `X-Powered-By`, `Strict-Transport-Security`, etc.)
- DNS record changes (A, AAAA, CNAME)
- Hosts going up or down

All changes are emitted as structured JSON log records compatible with GCP Cloud Logging. Every scan snapshot is persisted to a database (SQLite for local dev, PostgreSQL/Cloud SQL for production).

---

## How it works

Each cycle runs two phases:

1. **Scan** — runs nmap (port/version detection), grabs raw TCP banners for non-HTTP ports, issues HEAD requests to HTTP/S endpoints, and resolves DNS for any FQDNs. Results are written to the database.

2. **Diff** — compares the latest scan against the previous one for each host and FQDN. Detected changes are written to the database as `change_events` and emitted as structured log records.

`MONITOR_MODE=all` (default) runs both phases in sequence. `scan` and `diff` can be run as separate processes pointing at the same database.

---

## Change event severity

| Severity | Change types |
|---|---|
| `critical` | `PORT_OPENED`, `NEW_HOST`, `HOST_DOWN`, `DNS_RECORD_CHANGED` |
| `warning` | `PORT_CLOSED`, `SERVICE_CHANGED`, `DNS_IP_ADDED`, `DNS_IP_REMOVED`, `DNS_CNAME_CHANGED`, `DNS_RESOLUTION_FAILED` |
| `info` | `VERSION_CHANGED`, `BANNER_CHANGED`, `HTTP_HEADER_CHANGED`, `DNS_AAAA_CHANGED`, `DNS_RESOLUTION_RESTORED`, `DNS_NEW_FQDN` |

---

## Configuration

Settings can be provided as environment variables, a YAML config file, or both. Environment variables always override YAML globals, but never override per-client YAML values.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `MONITOR_TARGETS` | — | Comma-separated IPs, CIDRs, FQDNs |
| `DATABASE_URL` | `sqlite:///data/monitor.db` | SQLite or PostgreSQL connection URL |
| `CLIENT_ID` | `default` | Tenant identifier — all DB rows are scoped to this |
| `MONITOR_MODE` | `all` | `scan` / `diff` / `all` |
| `MONITOR_RUN_MODE` | `job` | `job` (single-shot) or `service` (continuous loop) |
| `MONITOR_SCAN_INTERVAL_SECONDS` | `3600` | Loop interval when `run_mode=service` |
| `MONITOR_NMAP_ARGUMENTS` | `-sV --open -T4` | Arguments passed directly to nmap |
| `MONITOR_NMAP_PORTS` | `top-1000` | Port scope: `top-1000`, `1-65535`, or an explicit list |
| `MONITOR_NMAP_SUDO` | `false` | Enable SYN scan — requires `CAP_NET_RAW` |
| `MONITOR_ALERT_MIN_SEVERITY` | `info` | Minimum severity to emit: `info` / `warning` / `critical` |
| `MONITOR_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `MONITOR_LOG_CHANGES_ONLY` | `false` | Suppress INFO log lines when no changes are detected |
| `CONFIG_FILE` | — | Path to a YAML config file |

### YAML config — single client

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

### YAML config — multiple clients

Define a `clients:` section to monitor multiple tenants in a single process. Each client gets its own `client_id` and is fully isolated in the database. Global settings are inherited by all clients and can be overridden per-client.

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

If a client is removed from the config and later re-added, the diff picks up from the last scan stored in the database — any changes during the gap are detected correctly.

---

## Local development

### Prerequisites

- Python 3.11+
- nmap: `apt install nmap` / `brew install nmap`

```bash
pip install -r requirements.txt

MONITOR_TARGETS=192.0.2.1,example.com \
DATABASE_URL=sqlite:///data/monitor.db \
python -m monitor.main
```

### Docker

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

### Running tests

```bash
pip install pytest
pytest tests/
```

---

## GCP deployment — from scratch

The full GCP stack is managed by Terraform (`infra/`) and deployed automatically via GitHub Actions. A single bootstrap script handles the one-time setup.

### Architecture

| Component | Resource |
|---|---|
| Scanner | Cloud Run Job (`network-monitor`) triggered hourly by Cloud Scheduler |
| Database | Cloud SQL PostgreSQL 16 (`db-g1-small`) |
| Egress IP | Static external IP via Cloud NAT — add this to target allowlists |
| Image registry | Artifact Registry (`network-monitor`) |
| Change events | Structured JSON → Cloud Logging → Pub/Sub topic (`network-monitor-changes`) |
| Slack alerts | Cloud Function (`network-monitor-slack`) subscribed to the Pub/Sub topic |
| Secrets | Secret Manager (`network-monitor-db-url`, `network-monitor-slack-webhook`) |
| CI/CD | GitHub Actions — tests on every push, deploy on push to `master` |
| Auth | Workload Identity Federation (keyless — no long-lived service account keys) |

### Prerequisites

- [gcloud CLI](https://cloud.google.com/sdk/docs/install) installed and authenticated (`gcloud auth login`)
- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.7
- Owner or Editor on the GCP project

### Step 1 — Clone the repo

```bash
git clone git@github.com:notabotscott/network-monitor.git
cd network-monitor
```

### Step 2 — Create a Slack incoming webhook

1. Go to your Slack workspace → **Apps** → search **Incoming Webhooks** → Add to Slack
2. Choose the channel for alerts and click **Add Incoming WebHooks Integration**
3. Copy the webhook URL (`https://hooks.slack.com/services/...`)

### Step 3 — Run bootstrap

```bash
export TF_VAR_slack_webhook_url='https://hooks.slack.com/services/...'
./bootstrap.sh
```

The script runs these steps in order:

1. Creates a GCS bucket for Terraform state (`internal-automation-385014-tf-state`)
2. Runs `terraform init`
3. Enables all required GCP APIs
4. Creates the Artifact Registry repository
5. Builds and pushes the initial Docker image via Cloud Build
6. Runs `terraform apply` to provision the full stack:
   - VPC + subnet + Cloud Router + Cloud NAT + static egress IP
   - Cloud SQL instance, database, and user (password stored in Secret Manager)
   - Cloud Run Job with Cloud SQL proxy and VPC egress routing
   - Cloud Scheduler hourly trigger
   - Pub/Sub topic + Cloud Logging sink
   - Cloud Function Slack notifier
   - Service account and all IAM bindings
   - Workload Identity Federation pool for GitHub Actions

At the end of the script, the static egress IP is printed. **Add this IP to the allowlist on any targets before the first scheduled scan runs.**

If you skip `TF_VAR_slack_webhook_url`, the secret is created but left empty. Populate it manually afterwards:

```bash
printf '%s' 'https://hooks.slack.com/services/...' | \
  gcloud secrets versions add network-monitor-slack-webhook \
    --project=internal-automation-385014 --data-file=-
```

### Step 4 — Add the GitHub Actions secret

Go to **Settings → Secrets and variables → Actions** in the GitHub repository and add:

| Name | Value |
|---|---|
| `SLACK_WEBHOOK_URL` | The Slack webhook URL |

This allows the `infra.yml` workflow to populate the webhook secret automatically whenever `terraform apply` runs in CI.

### Step 5 — Verify

Trigger a manual run and confirm it succeeds:

```bash
gcloud run jobs execute network-monitor \
  --region=us-east1 \
  --project=internal-automation-385014 \
  --wait
```

Check the logs:

```bash
gcloud logging read \
  'resource.type="cloud_run_job" resource.labels.job_name="network-monitor"' \
  --project=internal-automation-385014 \
  --limit=20 \
  --format='table(timestamp,jsonPayload.message)' \
  --order=asc
```

---

## CI/CD

Three GitHub Actions workflows run automatically:

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | Every push and PR | Runs `pytest tests/` |
| `deploy.yml` | Push to `master` | Runs tests, builds amd64 image via Cloud Build, updates Cloud Run Job, redeploys Cloud Function |
| `infra.yml` | Push/PR touching `infra/` | PR: posts `terraform plan` as a comment. Push to `master`: runs `terraform apply` |

All workflows authenticate to GCP via Workload Identity Federation — no long-lived credentials are stored in GitHub.

---

## Ongoing operations

### Changing scan targets

Edit the `monitor_targets` variable in `infra/variables.tf` (or `terraform.tfvars`) and push to `master`. The `infra.yml` workflow will apply the change.

### Rotating the database password

```bash
cd infra
terraform taint random_password.db
terraform apply
```

This generates a new password and atomically updates both the Cloud SQL user and the `network-monitor-db-url` secret.

### Querying change history

All change events are stored in the `change_events` table in Cloud SQL:

```sql
SELECT occurred_at, client_id, change_type, severity, host_ip, target, port, previous, current
FROM change_events
ORDER BY occurred_at DESC
LIMIT 50;
```

### Triggering a manual scan

```bash
gcloud run jobs execute network-monitor \
  --region=us-east1 \
  --project=internal-automation-385014 \
  --wait
```
