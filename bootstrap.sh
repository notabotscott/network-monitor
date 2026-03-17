#!/usr/bin/env bash
# bootstrap.sh — one-time setup to deploy the full stack from a fresh GCP project.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - Terraform >= 1.7 installed
#   - Docker installed (or Cloud Build access)
#   - Project owner or editor on internal-automation-385014
#
# After this script completes:
#   1. Add the SLACK_WEBHOOK_URL secret to GitHub Actions:
#      https://github.com/notabotscott/network-monitor/settings/secrets/actions
#      Name: SLACK_WEBHOOK_URL
#
#   2. Future deploys happen automatically on push to master.
#      Future infra changes apply automatically when infra/ files are pushed.

set -euo pipefail

PROJECT="internal-automation-385014"
REGION="us-east1"
STATE_BUCKET="${PROJECT}-tf-state"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/network-monitor/network-monitor"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "==> Setting active project"
gcloud config set project "${PROJECT}"

# ---------------------------------------------------------------------------
# 1. State bucket
# ---------------------------------------------------------------------------
echo "==> Creating Terraform state bucket (gs://${STATE_BUCKET})"
gcloud storage buckets create "gs://${STATE_BUCKET}" \
  --location="${REGION}" \
  --project="${PROJECT}" 2>/dev/null \
  || echo "    Bucket already exists — skipping"

# ---------------------------------------------------------------------------
# 2. Terraform: enable APIs and create Artifact Registry
# ---------------------------------------------------------------------------
cd "${REPO_ROOT}/infra"

echo "==> terraform init"
terraform init

echo "==> Enabling GCP APIs (this can take a few minutes)"
terraform apply -auto-approve -target=google_project_service.apis

echo "==> Creating Artifact Registry repository"
terraform apply -auto-approve -target=google_artifact_registry_repository.main

# ---------------------------------------------------------------------------
# 3. Build and push the initial Docker image
# ---------------------------------------------------------------------------
echo "==> Building and pushing initial Docker image via Cloud Build"
cd "${REPO_ROOT}"
gcloud builds submit \
  --tag "${IMAGE}:latest" \
  --project="${PROJECT}" \
  --region="${REGION}"

# ---------------------------------------------------------------------------
# 4. Full terraform apply
# ---------------------------------------------------------------------------
cd "${REPO_ROOT}/infra"

echo ""
echo "==> Running full terraform apply"
echo "    If you have a Slack webhook URL, pass it now:"
echo "      export TF_VAR_slack_webhook_url='https://hooks.slack.com/...'"
echo "    Otherwise the secret will be left empty and must be populated manually."
echo ""

terraform apply -auto-approve

# ---------------------------------------------------------------------------
# 5. Post-apply instructions
# ---------------------------------------------------------------------------
EGRESS_IP=$(terraform output -raw egress_ip)
WIF_PROVIDER=$(terraform output -raw workload_identity_provider)

echo ""
echo "===================================================================="
echo " Bootstrap complete!"
echo "===================================================================="
echo ""
echo " Static egress IP: ${EGRESS_IP}"
echo "   Add this IP to allowlists on scanned targets."
echo ""
echo " Workload Identity provider:"
echo "   ${WIF_PROVIDER}"
echo "   (already hardcoded in .github/workflows/*.yml)"
echo ""
echo " Next steps:"
echo "   1. Add SLACK_WEBHOOK_URL to GitHub Actions secrets:"
echo "      https://github.com/notabotscott/network-monitor/settings/secrets/actions"
echo ""
echo "   If you skipped the Slack webhook, populate it manually:"
echo "      printf '%s' 'https://hooks.slack.com/...' | \\"
echo "        gcloud secrets versions add network-monitor-slack-webhook --data-file=-"
echo "===================================================================="
