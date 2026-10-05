# Single logout

## Logging out of CiviCRM

When the provider publishes an `end_session_endpoint`, logging out of CiviCRM
redirects through it, so the provider session ends too. Warden sends
`id_token_hint` and, when the provider issued a `login_hint` claim,
`logout_hint`, which lets the provider skip its account picker.

## Logging out at the provider

For the other direction, register Warden's OIDC back-channel logout URL at the
provider and have it include the session identifier (`sid`):

```text
https://YOUR-CIVICRM/civicrm/warden/logout/backchannel
```

The provider then sends Warden a signed logout token. Warden validates its
signature and claims, rejects a token it has seen before, and marks the
matching CiviCRM session as revoked. That session is terminated on its next
request, before the requested page runs — not at the instant the token
arrives, because PHP session storage cannot be reached portably from another
request.

Warden stores only hashes of the local session, the subject and the provider
session. Bindings that have not been seen for `warden_session_retention_days`
are deleted by the daily prune job; a session older than that can no longer be
revoked remotely.

## Front-channel logout

Warden does not support OIDC front-channel logout. That flow runs in a
cross-site iframe, where the CiviCRM session cookie is not sent under its
default SameSite policy and may be blocked as a third-party cookie even when
relaxed. A logout started in another application therefore reaches Warden only
if the provider supports back-channel logout.

The reasoning is recorded in
[ADR 0002](adr/0002-oidc-single-logout.md).
