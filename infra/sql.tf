resource "random_password" "db" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "main" {
  name             = "network-monitor"
  region           = var.region
  database_version = "POSTGRES_16"

  # Set to true before using in production to prevent accidental deletion.
  deletion_protection = false

  depends_on = [google_project_service.apis]

  settings {
    tier      = "db-g1-small"
    edition   = "ENTERPRISE"
    disk_type = "PD_SSD"
    disk_size = 10

    availability_type = "ZONAL"

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
    }

    backup_configuration {
      enabled = false
    }

    location_preference {
      zone = "${var.region}-d"
    }
  }
}

resource "google_sql_database" "monitor" {
  name     = "monitor"
  instance = google_sql_database_instance.main.name
  charset  = "UTF8"
}

resource "google_sql_user" "monitor" {
  name     = "monitor"
  instance = google_sql_database_instance.main.name
  password = random_password.db.result
}
