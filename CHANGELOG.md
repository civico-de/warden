# Changelog

## [Unreleased]

## [0.6.0] - 2026-10-26

### Changed

- Every status check reports under a stable core status message name, per provider where it
  concerns one (for example `warden_discovery_3`, `warden_jwks_3`), so monitors can follow it and
  administrators can hide it on the System Status page.
- A provider's signing key set that cannot be fetched or holds no keys appears on the System Status
  page, critical for a `required` provider.

### Removed

- The registration hook for a separate monitoring extension; monitors read the core status messages
  instead.

### Fixed

- A status check that fails to run reports an error with the reason instead of staying silent.

## [0.5.0] - 2026-10-07

### Added

- Profile sync: Warden writes the provider's name claims and a verified email onto the contact when
  it creates or adopts a user, and with profile sync set to `every_login` keeps them current on each
  login.
- Login events for other extensions: `civi.warden.resolveUser` can link or refuse an unknown subject,
  `civi.warden.postLogin` runs after a successful login.
- A security policy (`SECURITY.md`) and the documentation under `docs/`.

### Security

- Tokens and secrets passed to the validators and the session binding are marked as sensitive
  parameters, so they stay out of stack traces.

## [0.4.0] - 2026-10-06

### Changed

- Licensed under AGPL-3.0.
- Each issuer can belong to one provider only. The upgrade stops and names the providers when two
  share an issuer; rename or remove one first.
- Users are provisioned atomically, with a username derived from issuer and subject.
- The login trail is append-only through the API.
- Logging out at the provider sends `id_token_hint` and, when available, `logout_hint`.

### Fixed

- The daily prune job failed because it ran without permissions as an APIv3 call.
- The `warden_enabled` switch did not take effect when the setting was stored as `0`.
- A client secret that cannot be decrypted made a provider act as a public client; the provider is
  now treated as unusable.
- A deactivated user could still sign in through a linked identity.
- The login route was not rate-limited like the callback.

### Security

- Error responses from the provider are bound to their state, and the `iss` response parameter is
  checked.

## [0.3.3] - 2026-08-27

### Changed

- Internal maintenance; no change for sites.

## [0.3.2] - 2026-08-27

### Changed

- Internal maintenance; no change for sites.

## [0.3.1] - 2026-08-27

### Changed

- Internal maintenance; no change for sites.

## [0.3.0] - 2026-08-27

### Added

- Microsoft Entra ID support: App Role mapping, three Entra-specific status checks, and a login that
  is refused when Entra omits the group claim for too many memberships instead of reading it as no
  roles.

### Changed

- The project moved to the `civico-de` organisation on GitHub; extension links point there.

## [0.2.0] - 2026-08-15

### Added

- Single logout: logging out of CiviCRM redirects through the provider's end-session endpoint, and
  the back-channel logout URL `civicrm/warden/logout/backchannel` revokes the matching CiviCRM
  session.
- The setting `warden_session_retention_days` for unused session bindings, pruned by the daily job.

### Changed

- The OpenID Connect protocol is handled by the `digitalcz/openid-connect` library, bundled in the
  release archive.
- Requires PHP 8.4 and CiviCRM 6.17.2 or later.

## [0.1.0] - 2026-08-14

### Added

- Sign-in to CiviCRM Standalone through OpenID Connect providers, with PKCE and signed ID token
  validation.
- Identity links by issuer and subject, provisioning of new users, email linking and claim-to-role
  mapping.
- Provider modes `disabled`, `optional` and `required`, with password login kept for administrators
  and a kill switch.
- Administration screens for providers, linked identities, the login trail and the settings.
- The login trail, pruned by a daily scheduled job, rate limiting of failed logins and System Status
  checks.
- Client secrets encrypted with `CIVICRM_CRED_KEYS`.

[Unreleased]: https://github.com/civico-de/warden/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/civico-de/warden/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/civico-de/warden/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/civico-de/warden/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/civico-de/warden/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/civico-de/warden/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/civico-de/warden/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/civico-de/warden/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/civico-de/warden/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/civico-de/warden/releases/tag/v0.1.0
