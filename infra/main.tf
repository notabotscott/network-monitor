terraform {
  required_version = ">= 1.7"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # State is stored in GCS. Create the bucket once before the first `terraform init`:
  #   gcloud storage buckets create gs://internal-automation-385014-tf-state \
  #     --location=us-east1 --project=internal-automation-385014
  backend "gcs" {
    bucket = "internal-automation-385014-tf-state"
    prefix = "network-monitor"
  }
}

provider "google" {
  project = var.project
  region  = var.region
}
