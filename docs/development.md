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

Another extension can take part in a login through two Symfony events on
`Civi::dispatcher()`. Each carries an event object from `Civi\Warden\Event` with the
properties listed; `provider` is a `Civi\Warden\Provider` and `claims` a
`Civi\Warden\IdTokenClaims`, both read-only.

| Event | When | Properties |
|---|---|---|
| `civi.warden.resolveUser` (`ResolveUserEvent`) | A verified token names a subject that is not linked to any user, before email linking and provisioning are tried. | `provider`, `claims`, `userId` (set it to an existing user id to link and sign in that user), `refusal` (set it to a short reason to deny the login; it lands in the trail as `refused_by_listener`). |
| `civi.warden.postLogin` (`PostLoginEvent`) | The CiviCRM session exists and the trail has its `login_success` row. | `provider`, `claims`, `userId`, `isNewUser`. |

A subject that is already linked never reaches `resolveUser`, so a listener
cannot override an established link. A user named by a listener is still
refused when the account does not exist, is deactivated, or is already bound
to a different subject at that provider.

The listener is a trust decision: it runs for every provider and before the
provider's linking policy, so it can link an account at a provider whose
`link_policy` is `never`. Check `$e->provider` before matching. Put a reason
code into `refusal`, not personal data — it is stored in the login trail. An
exception thrown by a listener refuses the login with a generic message and
lands in the trail as `listener_failed`; one thrown from `postLogin` is
logged and does not undo the login.

```php
use Civi\Warden\Event\ResolveUserEvent;

Civi::dispatcher()->addListener(ResolveUserEvent::NAME, function (ResolveUserEvent $e) {
  // Only the provider this directory is the authority for.
  if ($e->provider->name !== 'corp_entra') {
    return;
  }
  $userId = MyDirectory::userIdFor($e->claims->claim('employee_id'));
  if ($userId !== NULL) {
    $e->userId = $userId;
  }
});
```

## Design decisions

| ADR | Decision |
|---|---|
| [0001](adr/0001-no-oauth-client.md) | Why Warden keeps its own OIDC client instead of building on core's `oauth-client` |
| [0002](adr/0002-oidc-single-logout.md) | Why back-channel logout is stored as exact, hashed session revocations |
