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
static-analysis, formatting, dependency, lifecycle and Keycloak browser gates
run in CI.

The disposable Keycloak E2E test starts isolated CiviCRM, MariaDB and Keycloak
containers, performs a real browser authorization-code login, requests a
Keycloak user logout, and verifies that the signed back-channel notification
revokes the corresponding CiviCRM browser session:

```sh
tests/e2e/keycloak/run.sh
```

The script deletes its containers and volumes on exit. It requires Docker and
does not depend on a hosted environment.

## License and support

Copyright civico GmbH. The repository is private and the extension is
proprietary. Report operational or security issues through the repository's
private issue tracker.
