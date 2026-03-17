resource "google_cloud_run_v2_job" "monitor" {
  name     = "network-monitor"
  location = var.region

  template {
    template {
      service_account       = google_service_account.monitor.email
      timeout               = "600s"
      max_retries           = 0
      execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

      containers {
        # bootstrap.sh pushes the real image before this resource is created.
        # After that, the deploy workflow keeps :latest up to date.
        image = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.main.repository_id}/network-monitor:latest"

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        env {
          name  = "MONITOR_TARGETS"
          value = var.monitor_targets
        }
        env {
          name  = "CLIENT_ID"
          value = var.client_id
        }
        env {
          name  = "MONITOR_MODE"
          value = "all"
        }
        env {
          name  = "MONITOR_RUN_MODE"
          value = "job"
        }
        env {
          name  = "MONITOR_LOG_LEVEL"
          value = "INFO"
        }
        env {
          name  = "MONITOR_NMAP_ARGUMENTS"
          value = "-sV --open -T4 -Pn"
        }
        env {
          name  = "MONITOR_NMAP_PORTS"
          value = "top-1000"
        }
        env {
          name = "DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.db_url.secret_id
              version = "latest"
            }
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.main.connection_name]
        }
      }

      vpc_access {
        network_interfaces {
          network    = google_compute_network.main.name
          subnetwork = google_compute_subnetwork.main.name
        }
        egress = "ALL_TRAFFIC"
      }
    }
  }

  depends_on = [
    google_project_service.apis,
    google_secret_manager_secret_version.db_url,
    google_secret_manager_secret_iam_member.db_url_accessor,
    google_project_iam_member.cloudsql_client,
  ]
}
