resource "google_artifact_registry_repository" "main" {
  repository_id = "network-monitor"
  location      = var.region
  format        = "DOCKER"
  description   = "Network monitor container images"
}
