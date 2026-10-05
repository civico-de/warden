terraform {
  required_version = ">= 1.11.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }
}

# Authenticates through the Azure CLI session (az login --tenant …).
provider "azuread" {
  tenant_id = var.tenant_id
}
