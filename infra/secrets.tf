resource "google_secret_manager_secret" "db_url" {
  secret_id = "network-monitor-db-url"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

# The DATABASE_URL is constructed from the SQL instance and the generated password.
# Format: postgresql://user:pass@/dbname?host=/cloudsql/project:region:instance
resource "google_secret_manager_secret_version" "db_url" {
  secret = google_secret_manager_secret.db_url.id
  secret_data = "postgresql://monitor:${random_password.db.result}@/monitor?host=/cloudsql/${var.project}:${var.region}:${google_sql_database_instance.main.name}"
}

resource "google_secret_manager_secret" "slack_webhook" {
  secret_id = "network-monitor-slack-webhook"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

# Populate the Slack webhook URL if provided; otherwise set it manually:
#   printf '%s' 'https://hooks.slack.com/...' | \
#     gcloud secrets versions add network-monitor-slack-webhook --data-file=-
resource "google_secret_manager_secret_version" "slack_webhook" {
  count = var.slack_webhook_url != "" ? 1 : 0

  secret      = google_secret_manager_secret.slack_webhook.id
  secret_data = var.slack_webhook_url
}
