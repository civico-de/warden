# Configuration

Everything lives under **Administer → Single sign-on (warden)**: identity
providers, linked identities, the login trail and the settings.

## Permissions

| Permission | Grants |
|---|---|
| `administer warden` | Configure providers, identity links and settings. Whoever holds it can give a provider subject access to any account. |
| `view warden log` | Read the login trail without being able to change the configuration. Implied by `administer warden`. |

## Provider fields

| Field | Default | Meaning |
|---|---|---|
| Name | — | Machine name. It is recorded on every login-trail row, so renaming it breaks the link to existing history. |
| Label | — | Text on the login button. |
| Issuer | — | The OIDC issuer URL. Warden appends `/.well-known/openid-configuration`; the `issuer` in the discovered document must match this string exactly. |
| Client ID | — | As registered at the provider. |
| Client secret | empty | Encrypted with `CIVICRM_CRED_KEYS`; Warden refuses to save a secret when no key is configured. Leave it empty for a public client that uses PKCE only. |
| Scopes | `openid profile email` | Space-separated. `openid` is always sent. |
| Mode | `optional` | See [Modes](#modes). |
| Allowed signing algorithms | `RS256` | Space-separated allow-list for the ID token's `alg` header. |
| Enabled | yes | A disabled provider is ignored entirely. |
| Order | 1 | Order of the login buttons. |
| Claim to role map | empty | See [Role mapping](#role-mapping). |
| Role sync | `provision_only` | See [Role mapping](#role-mapping). |
| Provisioning | `never` | See [Who may sign in](#who-may-sign-in). |
| Unmatched-subject linking | `never` | See [Who may sign in](#who-may-sign-in). |
| Roles for provisioned users | empty | Space-separated role names for a newly created user. Empty means the user can sign in and do nothing. |

## Modes

- `disabled` — the provider is configured but nobody can sign in through it.
- `optional` — a button beside the password form.
- `required` — password login and password reset are denied site-wide. The
  password form stays visible but is refused. Read
  [Lockout protection](../README.md#lockout-protection) before switching it on.

## Who may sign in

Warden identifies a person by the provider's issuer and `sub` claim, never by
an email address alone. For each login it decides in this order:

1. **The subject is already linked** to a CiviCRM user: that user is signed
   in. A deactivated user is refused.
2. **Unknown subject, linking set to `verified_email`**: Warden adopts an
   existing user whose username matches the `email` claim, and only when the
   provider asserts `email_verified: true`. This carries an account-takeover
   risk if the provider lets people set unverified addresses; `never` is the
   recommended setting.
3. **Unknown subject, provisioning set to `provision`**: Warden creates a
   user with the roles listed under "Roles for provisioned users". The username
   is a readable prefix taken from `preferred_username` (or the provider name)
   plus a short suffix derived from issuer and subject, so it stays unique and
   stable.
4. **Otherwise** the login is refused and recorded in the login trail.

Existing links are listed under **Linked identities**. Deleting a CiviCRM user
removes their links.

## Role mapping

The claim-to-role map is a JSON object naming one claim and the CiviCRM roles
each of its values grants:

```json
{
  "claim": "realm_access.roles",
  "map": {
    "crm-admin": ["admin"],
    "crm-staff": ["staff"]
  }
}
```

The map is an allow-list: claim values that are not listed grant nothing, and
the right-hand side accepts CiviCRM role names only, never permission strings.

Role sync decides when the map is applied:

| Role sync | Behaviour |
|---|---|
| `off` | Roles are managed in CiviCRM only. |
| `provision_only` | Mapped roles are assigned once, when the user is created. |
| `every_login` | Mapped roles are added and removed on every login to match the claim. Roles outside the map are never touched. |

## Settings

Under **Single sign-on (warden) → Settings**:

| Setting | Default | Meaning |
|---|---|---|
| `warden_enabled` | on | Master switch. Off, Warden refuses its login and callback routes and enforces no mode; password login keeps working. |
| `warden_protect_admin_password_login` | on | In `required` mode, holders of `administer CiviCRM` keep password login and reset. |
| `warden_discovery_ttl` | 900 s | Cache lifetime of the discovery document and JWKS, limited to 300–3600. A failed fetch is cached for 60 seconds only. |
| `warden_clock_leeway` | 60 s | Clock-skew allowance for `exp`, `iat` and `nbf`, limited to 0–300. |
| `warden_state_ttl` | 600 s | How long the browser has to return from the provider, limited to 60–1800. |
| `warden_rate_limit_attempts` | 20 | Failed attempts allowed per source address within the window. 0 disables the limiter. |
| `warden_rate_limit_window` | 300 s | Rate-limit window, limited to 30–3600. |
| `warden_audit_retention_days` | 180 | Age after which login-trail rows are deleted. |
| `warden_session_retention_days` | 30 | Age after which unused session bindings are deleted. Keep it at least as long as the longest PHP session lifetime. |

Defining `CIVICRM_WARDEN_DISABLE` as a truthy constant in
`civicrm.settings.php` overrides `warden_enabled` and cannot be undone from
the UI.
