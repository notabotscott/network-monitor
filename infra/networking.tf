resource "google_compute_network" "main" {
  name                    = "network-monitor"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "main" {
  name          = "network-monitor"
  network       = google_compute_network.main.id
  region        = var.region
  ip_cidr_range = "10.8.0.0/24"
}

resource "google_compute_address" "egress" {
  name         = "network-monitor-egress"
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
}

resource "google_compute_router" "main" {
  name    = "network-monitor"
  network = google_compute_network.main.id
  region  = var.region
}

resource "google_compute_router_nat" "main" {
  name   = "network-monitor"
  router = google_compute_router.main.name
  region = var.region

  nat_ip_allocate_option = "MANUAL_ONLY"
  nat_ips                = [google_compute_address.egress.self_link]

  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.main.self_link
    source_ip_ranges_to_nat = ["PRIMARY_IP_RANGE"]
  }

  log_config {
    enable = true
    filter = "ALL"
  }
}
