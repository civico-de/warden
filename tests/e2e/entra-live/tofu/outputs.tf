output "tenant_id" {
  value = var.tenant_id
}

output "client_id" {
  value = azuread_application.warden.client_id
}

output "client_secret" {
  value     = azuread_application_password.warden.value
  sensitive = true
}

output "user_principal_name" {
  value = azuread_user.staff.user_principal_name
}

output "user_password" {
  value     = random_password.user.result
  sensitive = true
}
