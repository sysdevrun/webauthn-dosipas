output "cloud_run_url" {
  description = "URL of the Cloud Run service"
  value       = google_cloud_run_v2_service.dosipas_issuer.uri
}

output "service_account_email" {
  description = "Email of the Cloud Run service account"
  value       = google_service_account.dosipas_issuer.email
}

output "kms_key_name" {
  description = "Full resource name of the KMS signing key"
  value       = google_kms_crypto_key.level1_signing.id
}

output "artifact_registry_repository" {
  description = "Artifact Registry repository path for Docker images"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.dosipas.repository_id}"
}
