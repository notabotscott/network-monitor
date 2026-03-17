# Notification channel: sends Cloud Monitoring alerts to the same Pub/Sub topic
# that the log sink uses, so the existing Cloud Function handles them.
# Creating the channel causes GCP to provision the gcp-sa-monitoring-notification
# service account, which the IAM binding below then grants publisher rights to.
resource "google_monitoring_notification_channel" "pubsub" {
  display_name = "network-monitor-changes"
  type         = "pubsub"
  labels = {
    topic = google_pubsub_topic.changes.id
  }
  depends_on = [google_project_service.apis]
}

# Grant Cloud Monitoring permission to publish incident notifications to the topic.
# depends_on the channel so the service account exists before we try to bind it.
resource "google_pubsub_topic_iam_member" "monitoring_publisher" {
  topic  = google_pubsub_topic.changes.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:service-${var.project_number}@gcp-sa-monitoring-notification.iam.gserviceaccount.com"
  depends_on = [google_monitoring_notification_channel.pubsub]
}

# Alert when a Cloud Run Job execution fails (OOM, timeout, non-zero exit).
# Fires at most once per 5 minutes to avoid Slack spam on repeated failures.
resource "google_monitoring_alert_policy" "job_failures" {
  display_name          = "Network Monitor — Job Execution Failed"
  combiner              = "OR"
  notification_channels = [google_monitoring_notification_channel.pubsub.name]

  conditions {
    display_name = "Cloud Run Job execution failed"
    condition_threshold {
      filter          = "resource.type = \"cloud_run_job\" AND resource.labels.job_name = \"network-monitor\" AND metric.type = \"run.googleapis.com/job/completed_execution_count\" AND metric.labels.result = \"failed\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_COUNT"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
    }
  }
}
