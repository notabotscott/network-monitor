variable "project" {
  description = "GCP project ID"
  type        = string
  default     = "internal-automation-385014"
}

variable "project_number" {
  description = "GCP project number"
  type        = string
  default     = "123251553865"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-east1"
}

variable "github_org" {
  description = "GitHub org / user that owns the repository"
  type        = string
  default     = "notabotscott"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "network-monitor"
}

variable "monitor_targets" {
  description = "Comma-separated scan targets (IPs, CIDRs, FQDNs)"
  type        = string
  default     = "sinkhole.soteria-offsec.io"
}

variable "client_id" {
  description = "Tenant identifier written to every change event"
  type        = string
  default     = "soteria"
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL — stored in Secret Manager. Set via TF_VAR_slack_webhook_url or leave empty to populate the secret manually after apply."
  type        = string
  sensitive   = true
  default     = ""
}
