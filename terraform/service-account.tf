resource "google_service_account" "dosipas_issuer" {
  account_id   = "dosipas-issuer"
  display_name = "DOSIPAS Issuer Cloud Run service account"
}

# Allow the service account to sign with the KMS key
resource "google_kms_crypto_key_iam_member" "issuer_signer" {
  crypto_key_id = google_kms_crypto_key.level1_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.dosipas_issuer.email}"
}

# Allow the service account to read the public key
resource "google_kms_crypto_key_iam_member" "issuer_viewer" {
  crypto_key_id = google_kms_crypto_key.level1_signing.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.dosipas_issuer.email}"
}
