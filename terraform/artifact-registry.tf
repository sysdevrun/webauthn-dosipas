resource "google_artifact_registry_repository" "dosipas" {
  location      = var.region
  repository_id = "dosipas"
  format        = "DOCKER"
  description   = "Docker images for the DOSIPAS issuer function"
}
