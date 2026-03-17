resource "google_pubsub_topic" "changes" {
  name = "network-monitor-changes"
}

resource "google_logging_project_sink" "changes" {
  name        = "network-monitor-changes"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.changes.id}"

  filter = <<-EOT
    resource.type="cloud_run_job"
    resource.labels.job_name="network-monitor"
    jsonPayload.change_type!=""
  EOT

  # Creates a dedicated writer service account for this sink; the IAM binding
  # in iam.tf grants it pubsub.publisher on the topic.
  unique_writer_identity = true
}
