resource "google_service_account" "monitor" {
  account_id   = "network-monitor"
  display_name = "Network Monitor"
}

locals {
  monitor_sa = "serviceAccount:${google_service_account.monitor.email}"
}

# Project-level roles
resource "google_project_iam_member" "artifact_registry_reader" {
  project = var.project
  role    = "roles/artifactregistry.reader"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "artifact_registry_writer" {
  project = var.project
  role    = "roles/artifactregistry.writer"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "cloudfunctions_developer" {
  project = var.project
  role    = "roles/cloudfunctions.developer"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "cloudsql_client" {
  project = var.project
  role    = "roles/cloudsql.client"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "run_developer" {
  project = var.project
  role    = "roles/run.developer"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "run_invoker" {
  project = var.project
  role    = "roles/run.invoker"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "storage_object_admin" {
  project = var.project
  role    = "roles/storage.objectAdmin"
  member  = local.monitor_sa
}

# Terraform CI needs these to plan/apply infrastructure changes.
# roles/editor covers most GCP service CRUD; the admin roles below fill gaps
# that editor intentionally excludes (IAM, secrets, WIF).
resource "google_project_iam_member" "editor" {
  project = var.project
  role    = "roles/editor"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "serviceusage_admin" {
  project = var.project
  role    = "roles/serviceusage.serviceUsageAdmin"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "project_iam_admin" {
  project = var.project
  role    = "roles/resourcemanager.projectIamAdmin"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "secretmanager_admin" {
  project = var.project
  role    = "roles/secretmanager.admin"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "workload_identity_pool_admin" {
  project = var.project
  role    = "roles/iam.workloadIdentityPoolAdmin"
  member  = local.monitor_sa
}

# roles/editor excludes resource-level IAM policy management
resource "google_project_iam_member" "pubsub_admin" {
  project = var.project
  role    = "roles/pubsub.admin"
  member  = local.monitor_sa
}

resource "google_project_iam_member" "service_account_admin" {
  project = var.project
  role    = "roles/iam.serviceAccountAdmin"
  member  = local.monitor_sa
}

# Secret-level access
resource "google_secret_manager_secret_iam_member" "db_url_accessor" {
  secret_id = google_secret_manager_secret.db_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = local.monitor_sa
}

resource "google_secret_manager_secret_iam_member" "slack_webhook_accessor" {
  secret_id = google_secret_manager_secret.slack_webhook.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = local.monitor_sa
}

# Allow the Pub/Sub log sink's writer identity to publish to the topic
resource "google_pubsub_topic_iam_member" "log_sink_publisher" {
  topic  = google_pubsub_topic.changes.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.changes.writer_identity
}

# Allow the Cloud Build default SA to act as the monitor SA (needed for image builds)
resource "google_service_account_iam_member" "cloudbuild_sa_user" {
  service_account_id = google_service_account.monitor.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${var.project_number}@cloudbuild.gserviceaccount.com"
}
