resource "google_storage_bucket" "function_source" {
  name                        = "${var.project}-network-monitor-source"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
}

data "archive_file" "slack_notifier" {
  type        = "zip"
  source_dir  = "${path.module}/../slack-notifier"
  output_path = "/tmp/slack-notifier.zip"
}

resource "google_storage_bucket_object" "slack_notifier" {
  # Include the content hash in the object name so Terraform re-uploads on changes.
  name   = "slack-notifier-${data.archive_file.slack_notifier.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.slack_notifier.output_path
}

resource "google_cloudfunctions2_function" "slack_notifier" {
  name     = "network-monitor-slack"
  location = var.region

  build_config {
    runtime     = "python312"
    entry_point = "notify_slack"

    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.slack_notifier.name
      }
    }
  }

  service_config {
    service_account_email = google_service_account.monitor.email
    available_memory      = "256Mi"
    timeout_seconds       = 30
  }

  event_trigger {
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.changes.id
    retry_policy          = "RETRY_POLICY_DO_NOT_RETRY"
    service_account_email = google_service_account.monitor.email
  }

  depends_on = [
    google_secret_manager_secret_iam_member.slack_webhook_accessor,
  ]
}
