# Microsoft Entra ID

Create a single-tenant **Web** app registration in Entra ID and add Warden's
callback as an exact redirect URI:

```text
https://YOUR-CIVICRM/civicrm/warden/return
```

Configure the Warden provider as follows:

- Issuer: `https://login.microsoftonline.com/DIRECTORY-TENANT-ID/v2.0`, where
  `DIRECTORY-TENANT-ID` is the tenant GUID. Do not use `common`,
  `organizations`, a tenant domain, the discovery-document URL, or a trailing
  slash. Warden deliberately accepts one exact issuer rather than Microsoft
  multitenant issuer templates.
- Client ID: the Application (client) ID from the app registration.
- Client secret: a current secret value from **Certificates & secrets**.
  Configure `CIVICRM_CRED_KEYS` first so Warden can encrypt it at rest.
- Scopes: `openid profile email`; allowed signing algorithms: `RS256`.
- Linking: keep **Unmatched-subject linking** at `never`. Entra's `email` and
  `preferred_username` values are mutable and Entra does not provide the
  standard `email_verified` assertion Warden requires for account adoption.

For authorization, prefer Entra **App Roles**. Define values such as
`CiviCRM.Staff`, assign users or groups to them in the Enterprise Application,
and map the top-level `roles` claim to CiviCRM role names:

```json
{
  "claim": "roles",
  "map": {
    "CiviCRM.Admin": ["admin"],
    "CiviCRM.Staff": ["staff"]
  }
}
```

Direct `groups` mapping also works with Entra group object IDs, but is not the
recommended profile. Entra omits the claim when membership exceeds its token
limit and points clients to Microsoft Graph instead. Warden does not call Graph
or retain access tokens during login; it refuses that login rather than
interpreting an unavailable claim as an empty authoritative role set.

## Logout

Logging out of CiviCRM redirects through Entra's `end_session_endpoint`. Entra
offers provider-wide sign-out only through OIDC front-channel logout, which
Warden does not support (see [Single logout](single-logout.md)). A logout
started in another Entra-connected application therefore does not end an
existing CiviCRM session.

## System status checks

For a provider whose issuer points at Entra, Warden adds three checks to
CiviCRM's System Status page: the issuer is not tenant-specific (error), email
linking is switched on although Entra cannot assert `email_verified`
(warning), and the role map uses `groups` instead of App Roles (warning).

## Microsoft references

See Microsoft's documentation for the
[tenant-scoped OIDC endpoints](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
[ID-token claim semantics](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference),
and [group claims and overage](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims).
