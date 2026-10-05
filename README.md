# Warden

Warden lets people sign in to CiviCRM Standalone through an OpenID Connect
identity provider such as Keycloak or Microsoft Entra ID. It links each CiviCRM
user to the provider's stable `iss`/`sub` pair, can create users on first login,
maps provider claims to CiviCRM roles, and keeps its own login trail.

Warden is not tied to a vendor: every provider goes through the same discovery,
authorization-code flow with PKCE and signed-ID-token validation. The protocol
implementation is
[`digitalcz/openid-connect`](https://github.com/digitalcz/openid-connect);
Warden adds the CiviCRM side — identities, policy, sessions and the audit
trail.

## Requirements

- CiviCRM Standalone, at the release pinned in `info.xml` or newer. Warden
  does not work on Drupal, WordPress or other CMS integrations.
- PHP 8.4.
- The core extensions `standaloneusers`, `authx`, SearchKit and FormBuilder.

## Installation

Release archives bundle their Composer dependencies. Unpack one into the
extensions directory and enable it:

```sh
cv en warden
```

A git checkout needs `composer install --no-dev` first.

## Quick start

1. Configure `CIVICRM_CRED_KEYS`, so the client secret is encrypted at rest.
2. Register a confidential client at your identity provider with this
   callback URL:

   ```text
   https://YOUR-CIVICRM/civicrm/warden/return
   ```

3. In CiviCRM, open **Administer → Single sign-on (warden) → Identity
   providers** and add the provider with its issuer URL, client ID and client
   secret. Leave the mode at `optional`.
4. Sign in through the new button on the login screen. An unknown person is
   refused until you either link their identity or allow provisioning — see
   [Configuration](docs/configuration.md).
5. Check **Administer → Administration Console → System Status** for Warden
   messages, and the login trail for what happened.

Switch a provider to `required` only after a complete login has succeeded,
and read the next section first.

## Lockout protection

A misconfigured provider in `required` mode locks everyone out. There are
three ways back in:

- Switch off the `warden_enabled` setting. Warden then refuses its own login
  and callback routes and no provider mode is enforced, so password login
  works again.
- Define `CIVICRM_WARDEN_DISABLE` as a truthy constant in
  `civicrm.settings.php`. It overrides the setting when the UI cannot be
  reached.
- Disable the extension with `cv ext:disable warden`.

In addition, users holding `administer CiviCRM` keep password login in
`required` mode by default. Turning that protection off makes the identity
provider a single point of failure; do it only with a tested break-glass
procedure.

## Documentation

| Document | Covers |
|---|---|
| [Configuration](docs/configuration.md) | Provider fields, modes, provisioning, linking, role mapping, settings, permissions |
| [Single logout](docs/single-logout.md) | Logout in both directions and the back-channel logout URL |
| [Microsoft Entra ID](docs/entra.md) | App registration, issuer, App Roles, Entra-specific limits |
| [Operations](docs/operations.md) | System status checks, login trail, retention, rate limiting |
| [Security model](docs/security.md) | What Warden validates and what it never stores |
| [Development](docs/development.md) | Test suites and design decisions |

## License and support

Copyright civico GmbH, licensed under [AGPL-3.0](LICENSE.txt) from version
0.4.0 on; earlier releases were proprietary. Report bugs in
the [issue tracker](https://github.com/civico-de/warden/issues). Report
security issues by email to security@civico.de, not in a public issue; see
[SECURITY.md](SECURITY.md).
