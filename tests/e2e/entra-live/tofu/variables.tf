variable "tenant_id" {
  description = "Directory (tenant) ID of the Entra tenant the test resources are created in."
  type        = string
  nullable    = false
}

variable "site_url" {
  description = "Where the disposable CiviCRM stack is reachable from the host browser. Entra only accepts plain http for localhost."
  type        = string
  default     = "http://localhost:8087"
  nullable    = false
}
