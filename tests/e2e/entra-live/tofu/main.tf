# Everything here exists only for tests/e2e/entra-live and is prefixed
# warden-e2e- so it is recognisable in the shared tenant.

data "azuread_client_config" "current" {}

data "azuread_domains" "initial" {
  only_initial = true
}

data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "graph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

locals {
  graph_scopes = ["openid", "profile", "email", "User.Read"]
  domain       = data.azuread_domains.initial.domains[0].domain_name
}

resource "random_uuid" "staff_role" {}

resource "azuread_application" "warden" {
  display_name     = "warden-e2e-live"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]

  web {
    # post_logout_redirect_uri must also be a registered redirect URI.
    redirect_uris = [
      "${var.site_url}/civicrm/warden/return",
      "${var.site_url}/civicrm/login",
    ]
  }

  # login_hint lets Warden send logout_hint, which is what makes Entra end the
  # session without an account picker.
  optional_claims {
    id_token {
      name = "login_hint"
    }
  }

  app_role {
    id                   = random_uuid.staff_role.result
    display_name         = "CiviCRM Staff"
    description          = "Mapped by Warden onto the CiviCRM role warden_entra_staff_e2e."
    value                = "CiviCRM.Staff"
    allowed_member_types = ["User"]
    enabled              = true
  }

  required_resource_access {
    resource_app_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]

    dynamic "resource_access" {
      for_each = local.graph_scopes
      content {
        id   = data.azuread_service_principal.graph.oauth2_permission_scope_ids[resource_access.value]
        type = "Scope"
      }
    }
  }
}

resource "azuread_service_principal" "warden" {
  client_id                    = azuread_application.warden.client_id
  app_role_assignment_required = true
  owners                       = [data.azuread_client_config.current.object_id]
}

# Admin consent for the delegated Graph scopes, so the test user never sees
# a "Permissions requested" interstitial.
resource "azuread_service_principal_delegated_permission_grant" "graph" {
  service_principal_object_id          = azuread_service_principal.warden.object_id
  resource_service_principal_object_id = data.azuread_service_principal.graph.object_id
  claim_values                         = local.graph_scopes
}

resource "azuread_application_password" "warden" {
  application_id = azuread_application.warden.id
  display_name   = "e2e"
}

resource "random_password" "user" {
  length  = 32
  special = false
}

resource "azuread_user" "staff" {
  user_principal_name   = "warden-e2e@${local.domain}"
  display_name          = "Warden E2E"
  mail_nickname         = "warden-e2e"
  password              = random_password.user.result
  force_password_change = false
}

resource "azuread_app_role_assignment" "staff" {
  app_role_id         = random_uuid.staff_role.result
  principal_object_id = azuread_user.staff.object_id
  resource_object_id  = azuread_service_principal.warden.object_id
}
