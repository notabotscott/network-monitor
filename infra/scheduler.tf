resource "google_cloud_scheduler_job" "monitor" {
  name        = "network-monitor-hourly"
  description = "Hourly network surface scan"
  schedule    = "0 * * * *"
  time_zone   = "UTC"
  region      = var.region

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project}/jobs/${google_cloud_run_v2_job.monitor.name}:run"
    body        = base64encode("{}")

    oauth_token {
      service_account_email = google_service_account.monitor.email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}
