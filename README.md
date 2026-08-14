# Warden

Warden provides OpenID Connect single sign-on for CiviCRM Standalone. It uses
provider discovery, authorization-code flow with PKCE, state and nonce checks,
JWKS-backed ID-token validation, stable `iss`/`sub` identity links, optional
first-login provisioning, claim-to-role mapping, rate limiting and an audit
trail.

Warden supports CiviCRM 6.14 or newer on PHP 8.3 or 8.4. It is a Standalone-only
extension and requires `standaloneusers`, `authx`, SearchKit and FormBuilder.

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
- Users are linked by the stable issuer and subject pair, never by an
  unverified email address alone.
- Callback failures are rate-limited per source address and recorded in the
  audit log without storing tokens or secrets.
- Provider client secrets are stored through CiviCRM's credential mechanisms;
  do not place them in exported managed configuration.

Set a finite audit retention period appropriate to your data-protection policy.
The scheduled `warden.prune` job removes older records.

## Verified compatibility

The automated suite exercises PHP 8.3/8.4 and the declared CiviCRM floor. The
implementation was developed against the 6.14 and 6.15 fleet lines and the
current CiviKitchen CI image. Unit, headless, static-analysis, formatting,
dependency and lifecycle gates run in CI.

## License and support

Copyright civico GmbH. The repository is private and the extension is
proprietary. Report operational or security issues through the repository's
private issue tracker.
