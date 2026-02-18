resource "google_kms_key_ring" "dosipas" {
  name     = "dosipas-keyring"
  location = var.kms_location
}

resource "google_kms_crypto_key" "level1_signing" {
  name     = "dosipas-level1-signing"
  key_ring = google_kms_key_ring.dosipas.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }

  # Prevent accidental destruction of the signing key
  lifecycle {
    prevent_destroy = true
  }
}
