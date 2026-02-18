resource "google_cloud_run_v2_service" "dosipas_issuer" {
  name     = "dosipas-issuer"
  location = var.region

  template {
    service_account = google_service_account.dosipas_issuer.email

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      env {
        name  = "GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "KMS_LOCATION"
        value = var.kms_location
      }
      env {
        name  = "KMS_KEYRING"
        value = google_kms_key_ring.dosipas.name
      }
      env {
        name  = "KMS_KEY"
        value = google_kms_crypto_key.level1_signing.name
      }
      env {
        name  = "KMS_KEY_VERSION"
        value = "1"
      }
    }
  }
}
