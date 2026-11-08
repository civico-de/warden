---
title: Reference
order: 30
---

# Reference

## Permissions

| Permission | Grants |
|---|---|
| `administer warden` | Configure providers, identity links and settings. Whoever holds it can give a provider subject access to any account. Implied by `administer CiviCRM`. |
| `view warden log` | Read the login trail without being able to change the configuration. Implied by `administer warden`. |

## Settings

Under **Single sign-on (warden) → Settings**:

| Setting | Default | Meaning |
|---|---|---|
| `warden_enabled` | on | Master switch. Off, Warden refuses its login and callback routes and enforces no mode; password login keeps working. |
| `warden_protect_admin_password_login` | on | In `required` mode, holders of `administer CiviCRM` keep password login and password reset. |
| `warden_discovery_ttl` | 900 s | Cache lifetime of the discovery document and the signing key set, limited to 300–3600. A failed fetch is cached for 60 seconds only. |
| `warden_clock_leeway` | 60 s | Clock skew allowance for `exp`, `iat` and `nbf`, limited to 0–300. |
| `warden_state_ttl` | 600 s | How long the browser has to return from the provider, limited to 60–1800. |
| `warden_rate_limit_attempts` | 20 | Failed attempts allowed per source address within the window. 0 switches the limiter off. |
| `warden_rate_limit_window` | 300 s | Rate limit window, limited to 30–3600. |
| `warden_audit_retention_days` | 180 | Age after which login trail rows are deleted. |
| `warden_session_retention_days` | 30 | Age after which unused session bindings are deleted. Keep it at least as long as the longest PHP session lifetime. |

Defining `CIVICRM_WARDEN_DISABLE` as a truthy constant in `civicrm.settings.php` overrides `warden_enabled` and cannot be undone from the user interface.

## URLs

| Path | Purpose |
|---|---|
| `civicrm/warden/return` | The callback URL to register at the provider. |
| `civicrm/warden/logout/backchannel` | The back-channel logout URL, see [Single logout](operations.md#single-logout). |
| `civicrm/warden/login` | Starts a login; the buttons on the login screen point here. |

## Scheduled job

"Warden: prune the login trail" runs daily and calls the API action `Warden.prune`. It deletes what the two retention settings above allow, see [Retention](operations.md#retention).

## Events

Another extension can take part in a login through two Symfony events on `Civi::dispatcher()`. Each carries an event object from the namespace `Civi\Warden\Event`. `provider` is a `Civi\Warden\Provider` and `claims` a `Civi\Warden\IdTokenClaims`, both read-only.

| Event | When | Properties |
|---|---|---|
| `civi.warden.resolveUser` (`ResolveUserEvent`) | A verified token names a subject that is not linked to any user, before email linking and provisioning are tried. | `provider`, `claims`, `userId` (set it to an existing user ID to link and sign in that user), `refusal` (set it to a short reason to deny the login; it lands in the trail as `refused_by_listener`). |
| `civi.warden.postLogin` (`PostLoginEvent`) | The CiviCRM session exists and the trail has its `login_success` row. | `provider`, `claims`, `userId`, `isNewUser`. |

A subject that is already linked never reaches `resolveUser`, so a listener cannot override an existing link. A user named by a listener is still refused when the account does not exist, is deactivated, or is already linked to a different subject at that provider.

The listener is a trust decision: it runs for every provider and before the provider's linking policy, so it can link an account at a provider whose linking is set to `never`. Check `$e->provider` before matching. Put a reason code into `refusal`, not personal data, because it is stored in the login trail. An exception thrown by a `resolveUser` listener refuses the login with a generic message and lands in the trail as `listener_failed`; one thrown from `postLogin` is logged and does not undo the login.

```php
use Civi\Warden\Event\ResolveUserEvent;

Civi::dispatcher()->addListener(ResolveUserEvent::NAME, function (ResolveUserEvent $e) {
  // Only the provider this directory is the authority for.
  if ($e->provider->name !== 'staff_directory') {
    return;
  }
  $userId = MyDirectory::userIdFor($e->claims->claim('employee_id'));
  if ($userId !== NULL) {
    $e->userId = $userId;
  }
});
```

## Security model

- Authorization requests are short-lived, single-use records holding a random state, nonce and PKCE verifier.
- ID tokens are accepted only after issuer, audience, signature and time claims are validated against the provider's published signing keys.
- Back-channel logout tokens are validated the same way, checked against replay by their `jti`, and matched to hashed local session bindings.
- Users are linked by the stable issuer and subject pair, never by an unverified email address alone.
- The login and callback routes are rate-limited per source address, see [Rate limiting](operations.md#rate-limiting).
- Client secrets are stored encrypted through CiviCRM's credential mechanism. Do not put them into exported managed configuration.
- A user deactivated in CiviCRM is refused even when their identity is linked.
- Role mapping is an allow-list of CiviCRM role names; a provider cannot name a permission.

To report a vulnerability, write to security@civico.de instead of opening a public issue.
