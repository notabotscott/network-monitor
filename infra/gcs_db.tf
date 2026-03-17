# GCS bucket for SQLite database (lightweight alternative to Cloud SQL).
#
# To use instead of Cloud SQL:
#   1. Set these env vars on the Cloud Run Job:
#        MONITOR_STATE_BACKEND=gcs
#        MONITOR_STATE_GCS_BUCKET=<bucket name from output below>
#      Remove the DATABASE_URL secret reference.
#   2. Grant the service account storage access (already done via
#      google_project_iam_member.storage_object_admin in iam.tf).
#
# The DATABASE_URL secret and Cloud SQL instance can then be removed.

resource "google_storage_bucket" "sqlite_db" {
  name                        = "${var.project}-network-monitor-db"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = false

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 5
    }
    action {
      type = "Delete"
    }
  }
}

output "sqlite_db_bucket" {
  description = "GCS bucket for SQLite database (alternative to Cloud SQL)"
  value       = google_storage_bucket.sqlite_db.name
}
