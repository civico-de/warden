# Warden

Warden provides OpenID Connect single sign-on for CiviCRM Standalone. It uses
provider discovery, authorization-code flow with PKCE, state and nonce checks,
JWKS-backed ID-token validation, stable `iss`/`sub` identity links, optional
first-login provisioning, claim-to-role mapping, rate limiting and an audit
trail.

Warden supports CiviCRM 6.17.2 or newer on PHP 8.4. It is a Standalone-only
extension and requires `standaloneusers`, `authx`, SearchKit and FormBuilder.
The OIDC protocol implementation is provided by
[`digitalcz/openid-connect`](https://github.com/digitalcz/openid-connect);
Warden adds the CiviCRM identity, policy, session and audit integration.

## Installation

Install the extension and its Composer dependencies, then enable it normally:

```sh
composer install --no-dev
cv en warden
```

Open **Administer → System Settings → Warden Settings** to review the global
safety controls. Provider records and their role mappings are managed through
the Warden administration searches.

For each identity provider, configure its HTTPS issuer, client ID and client
secret, redirect URI, operating mode, accepted claims and provisioning policy.
Register this callback URL at the provider:

```text
https://YOUR-CIVICRM/civicrm/warden/return
```

For single logout, prefer an OIDC back-channel logout URL and require the
provider to include its session identifier:

```text
https://YOUR-CIVICRM/civicrm/warden/logout/backchannel
```

Warden deliberately does not advertise OIDC front-channel logout. That flow
runs in a cross-site iframe, where the ordinary CiviCRM session cookie is not
sent with its default SameSite policy and may be blocked as a third-party
cookie even when explicitly relaxed. Back-channel logout is reliable because
its signed token does not depend on the user's browser. Warden records an exact
hashed session revocation and terminates the matching CiviCRM session before
its next CiviCRM route is handled.

Keep the provider in optional mode until a complete login has succeeded. Only
then consider required mode.

Warden is not tied to a vendor. Every provider goes through the same OIDC
Discovery, authorization-code/PKCE and signed-ID-token path. Provider-specific
profiles add configuration diagnostics and E2E coverage; they do not replace
the generic protocol implementation. The suite currently exercises Keycloak
and a Microsoft Entra ID profile.

## Microsoft Entra ID profile

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

Local logout redirects through Entra's discovered `end_session_endpoint`.
Microsoft documents provider-wide single sign-out through OIDC front-channel
logout. Warden does not implement that iframe/cookie-dependent mechanism, so a
logout initiated in another Entra-connected application does not revoke an
existing Warden session. See Microsoft's documentation for the
[tenant-scoped OIDC endpoints](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
[ID-token claim semantics](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference),
and [group claims and overage](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims).

## Lockout protection

Warden has two independent escape hatches:

- The global `warden_enabled` setting disables enforcement while leaving
  password login available.
- Defining `CIVICRM_WARDEN_DISABLE` as a truthy constant in
  `civicrm.settings.php` overrides the database setting when the UI cannot be
  reached.

By default, administrators retaining `administer CiviCRM` may still use
password recovery in required mode. Disabling that protection makes the
identity provider a single point of failure and should only be done with a
tested break-glass procedure.

## Security model

- Authorization requests are short-lived, single-use records containing a
  random state, nonce and PKCE verifier.
- ID tokens are accepted only after issuer, audience, signature and temporal
  claim validation against the provider's discovered JWKS.
- Back-channel logout tokens are signature- and claim-validated, replay
  checked by `jti`, and mapped to hashed local session bindings.
- Users are linked by the stable issuer and subject pair, never by an
  unverified email address alone.
- Callback failures are rate-limited per source address and recorded in the
  audit log without storing tokens or secrets.
- Provider client secrets are stored through CiviCRM's credential mechanisms;
  do not place them in exported managed configuration.

Set finite audit and inactive session-binding retention periods appropriate to
your data-protection policy. The scheduled `warden.prune` job removes both
classes of old records.

## Verified compatibility

The automated suite exercises PHP 8.4 with CiviCRM 6.17.2. Unit, headless,
static-analysis, formatting, dependency, lifecycle, Keycloak browser and Entra
profile browser gates run in CI.

The disposable Keycloak E2E test starts isolated CiviCRM, MariaDB and Keycloak
containers, performs a real browser authorization-code login, requests a
Keycloak user logout, and verifies that the signed back-channel notification
revokes the corresponding CiviCRM browser session:

```sh
tests/e2e/keycloak/run.sh
```

The script deletes its containers and volumes on exit. It requires Docker and
does not depend on a hosted environment.

The Entra profile E2E suite runs a deterministic local authority at Microsoft's
tenant-scoped v2 URLs. It performs confidential-client authentication,
authorization code + PKCE, nonce and ID-token validation, first-login
provisioning, App Role mapping, safe handling of an unverified Entra email, and
RP-initiated logout without requiring production tenant credentials:

```sh
tests/e2e/entra/run.sh
```

This fixture verifies Warden's Entra protocol contract; it does not test a
specific organization's Conditional Access, consent or tenant policy. Keep a
provider optional until a login against the real tenant succeeds.

## License and support

Copyright civico GmbH. The repository is private and the extension is
proprietary. Report operational or security issues through the repository's
private issue tracker.
