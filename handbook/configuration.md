---
title: Configuration
order: 10
---

# Configuration

Everything lives under **Administer → Single sign-on (warden)**: identity providers, linked identities, the login trail and the settings. Configuring it needs the permission `administer warden`, see [Permissions](reference.md#permissions).

## Provider fields

| Field | Default | Meaning |
|---|---|---|
| Name | — | Machine name. It is recorded on every login trail row, so renaming it breaks the link to existing history. |
| Label | — | Text on the login button. |
| Issuer | — | The issuer URL. Warden appends `/.well-known/openid-configuration`; the `issuer` in the discovered document must match this string exactly. Each issuer can belong to one provider only. |
| Client ID | — | As registered at the provider. |
| Client secret | empty | Stored encrypted with `CIVICRM_CRED_KEYS`. Leave it empty for a public client that uses PKCE only. |
| Scopes | `openid profile email` | Space-separated. `openid` is always sent. |
| Mode | `optional` | See [Modes](#modes). |
| Allowed signing algorithms | `RS256` | Space-separated allow-list for the ID token's `alg` header. |
| Enabled | yes | A disabled provider is ignored entirely. |
| Order | 1 | Order of the login buttons. |
| Claim to role map | empty | See [Role mapping](#role-mapping). |
| Role sync | `provision_only` | See [Role mapping](#role-mapping). |
| Profile sync | `off` | See [Profile sync](#profile-sync). |
| Provisioning | `never` | See [Who may sign in](#who-may-sign-in). |
| Unmatched-subject linking | `never` | See [Who may sign in](#who-may-sign-in). |
| Roles for provisioned users | empty | Space-separated role names for a newly created user. Empty means the user can sign in and do nothing. |

## Modes

- `disabled`: the provider is configured, but nobody can sign in through it.
- `optional`: a button beside the password form.
- `required`: password login and password reset are refused site-wide. The password form stays visible but does not work. Read [Lockout protection](index.md#lockout-protection) before switching it on.

## Who may sign in

Warden identifies a person by the provider's issuer and `sub` claim, never by an email address alone. For each login it decides in this order:

1. **The subject is already linked** to a CiviCRM user: that user is signed in. A deactivated user is refused.
2. **Unknown subject, another extension knows the person**: an extension listening to the event `civi.warden.resolveUser` may name the user to link, or refuse the login, see [Events](reference.md#events).
3. **Unknown subject, linking set to `verified_email`**: Warden adopts an existing user whose username or login address matches the `email` claim, and only when the provider asserts `email_verified: true`. This carries an account takeover risk if the provider lets people set unverified addresses; `never` is the recommended setting.
4. **Unknown subject, provisioning set to `provision`**: Warden creates a user with the roles listed under "Roles for provisioned users". The username is a readable prefix taken from `preferred_username` (or the provider name) plus a short suffix derived from issuer and subject, so it stays unique and stable.
5. **Otherwise** the login is refused and recorded in the login trail.

Existing links are listed under **Linked identities**. Deleting a CiviCRM user removes their links.

## Role mapping

The claim to role map is a JSON object naming one claim and the CiviCRM roles each of its values grants:

```json
{
  "claim": "realm_access.roles",
  "map": {
    "crm-admin": ["admin"],
    "crm-staff": ["staff"]
  }
}
```

The map is an allow-list: claim values that are not listed grant nothing, and the right-hand side accepts CiviCRM role names only, never permissions.

Role sync decides when the map is applied:

| Role sync | Behaviour |
|---|---|
| `off` | Roles are managed in CiviCRM only. |
| `provision_only` | Mapped roles are assigned once, when the user is created. |
| `every_login` | Mapped roles are added and removed on every login to match the claim. Roles outside the map are never touched. |

## Profile sync

Warden writes the provider's name claims (`given_name`, `family_name`, or `name` as a fallback into the first name) and a verified `email` claim onto the contact when it creates or adopts a user. With profile sync set to `every_login`, it also keeps them current on each later login: the name fields follow the claims, and the address becomes the contact's primary email, promoted if the contact already has it and added otherwise, with the previous primary kept as a secondary address. The email is written only while the provider asserts `email_verified: true`.

Warden does not write the login address itself. Whether a new primary email moves it is CiviCRM's own setting `syncCMSEmail` (on by default); CiviCRM skips an address another user already holds. Password resets go to the login address, so with sync on, the provider's verified address is where a local password can be requested. Switch `syncCMSEmail` off if that address must stay fixed. A failed update refuses the login and is recorded in the trail as `profile_sync_failed`.

At most providers people can edit their own name. Enable profile sync only when the provider is the authority for contact names on this site.

## Microsoft Entra ID

Create a single-tenant **Web** app registration in Entra ID and add Warden's callback as an exact redirect URI:

```text
https://YOUR-CIVICRM/civicrm/warden/return
```

Configure the provider as follows:

- Issuer: `https://login.microsoftonline.com/DIRECTORY-TENANT-ID/v2.0`, where `DIRECTORY-TENANT-ID` is the tenant GUID. Do not use `common`, `organizations`, a tenant domain, the discovery document URL or a trailing slash. Warden accepts one exact issuer, not Microsoft's multi-tenant issuer templates.
- Client ID: the Application (client) ID of the app registration.
- Client secret: a current secret value from **Certificates & secrets**.
- Scopes `openid profile email`, allowed signing algorithm `RS256`.
- Keep **Unmatched-subject linking** at `never`. Entra's `email` and `preferred_username` values can change, and Entra does not send the `email_verified` assertion that linking requires.

For authorization, prefer Entra **App Roles**. Define values such as `CiviCRM.Staff`, assign users or groups to them in the Enterprise Application, and map the top-level `roles` claim:

```json
{
  "claim": "roles",
  "map": {
    "CiviCRM.Admin": ["admin"],
    "CiviCRM.Staff": ["staff"]
  }
}
```

Mapping the `groups` claim with group object IDs also works, but Entra leaves that claim out when someone belongs to too many groups. Warden then refuses the login rather than reading the missing claim as "no roles".

Logging out of CiviCRM ends the Entra session too. A logout started in another Entra-connected application does not end the CiviCRM session, because Entra offers that only through front-channel logout, which Warden does not support, see [Single logout](operations.md#single-logout).
