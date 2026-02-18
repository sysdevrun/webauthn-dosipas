variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for Cloud Run and Artifact Registry"
  type        = string
  default     = "europe-west1"
}

variable "kms_location" {
  description = "GCP location for the KMS keyring"
  type        = string
  default     = "europe-west1"
}

variable "image" {
  description = "Container image for the Cloud Run service (e.g. europe-west1-docker.pkg.dev/PROJECT/dosipas/issuer:latest)"
  type        = string
}
