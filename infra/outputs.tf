output "egress_ip" {
  description = "Static egress IP — add this to target allowlists"
  value       = google_compute_address.egress.address
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL connection name (project:region:instance)"
  value       = google_sql_database_instance.main.connection_name
}

output "artifact_registry_url" {
  description = "Docker image base URL"
  value       = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.main.repository_id}/network-monitor"
}

output "workload_identity_provider" {
  description = "Full Workload Identity provider resource name — used in GitHub Actions workflows"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "db_password" {
  description = "Generated database password (also stored in Secret Manager as part of DATABASE_URL)"
  value       = random_password.db.result
  sensitive   = true
}
