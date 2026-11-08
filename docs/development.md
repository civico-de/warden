# Development

## Tests

The test suite runs on PHP 8.4 against the CiviCRM release pinned in
`info.xml`: unit and headless PHPUnit tests, static analysis, and two browser
suites that each start their own disposable containers and remove them on
exit. Both need only Docker and Node.

```sh
tests/e2e/keycloak/run.sh
tests/e2e/entra/run.sh
```

- **Keycloak** starts CiviCRM, MariaDB and a real Keycloak, signs in through
  the browser, logs the user out at Keycloak and checks that the back-channel
  notification revokes the CiviCRM session.
- **Entra** runs a local stand-in authority at Microsoft's tenant-scoped v2
  URLs. It covers client authentication, the authorization-code flow,
  first-login provisioning, App Role mapping, an unverified Entra email and
  logout. It checks Warden's side of the protocol, not a tenant's Conditional
  Access, consent or policy settings.

A third suite, [`tests/e2e/entra-live`](../tests/e2e/entra-live/README.md), signs
in against a real Entra tenant. It is run by hand and never in CI.

## Events

The two login events `civi.warden.resolveUser` and `civi.warden.postLogin`
are documented for other extensions in the handbook's
[Events](https://civico-de.github.io/warden/reference/#events).

## Design decisions

| ADR | Decision |
|---|---|
| [0001](adr/0001-no-oauth-client.md) | Why Warden keeps its own OIDC client instead of building on core's `oauth-client` |
| [0002](adr/0002-oidc-single-logout.md) | Why back-channel logout is stored as exact, hashed session revocations |
