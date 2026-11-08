---
title: Operations
order: 20
---

# Operations

## Single logout

### Logging out of CiviCRM

When the provider publishes an `end_session_endpoint`, logging out of CiviCRM redirects through it, so the provider session ends too. Warden sends `id_token_hint` and, when the provider issued a `login_hint` claim, `logout_hint`, which lets the provider skip its account picker.

### Logging out at the provider

For the other direction, register Warden's back-channel logout URL at the provider and have it include the session identifier (`sid`):

```text
https://YOUR-CIVICRM/civicrm/warden/logout/backchannel
```

The provider then sends Warden a signed logout token. Warden validates its signature and claims, rejects a token it has seen before, and marks the matching CiviCRM session as revoked. That session ends on its next request, before the requested page runs, not at the moment the token arrives: another request cannot reach PHP's session storage in a portable way.

Warden stores only hashes of the local session, the subject and the provider session. Session bindings that have not been seen for `warden_session_retention_days` are deleted by the daily job; a session older than that can no longer be ended from the provider.

Warden does not support front-channel logout. That flow runs in a cross-site frame, where browsers do not send the CiviCRM session cookie. A logout started in another application reaches Warden only if the provider supports back-channel logout.

## Status checks

Warden reports its findings on CiviCRM's System Status page (**Administer → Administration Console → System Status**). Every finding has a stable name, so a monitor reading the API call `System.check` can follow it and an administrator can hide it. A finding about one provider ends in the provider's ID, for example `warden_discovery_3`.

| Name | Finding | Severity |
|---|---|---|
| `warden_discovery_<id>` | The discovery document cannot be fetched | error; critical for a `required` provider |
| `warden_jwks_<id>` | The signing key set cannot be fetched or holds no keys | error; critical for a `required` provider |
| `warden_no_pkce_<id>` | The provider does not advertise PKCE with `S256`; Warden sends PKCE regardless | notice |
| `warden_no_algorithms_<id>` | The provider allows no signing algorithm | error |
| `warden_alg_mismatch_<id>` | None of the allowed algorithms is one the provider signs with | error |
| `warden_alg_unsupported_<id>` | An allowed algorithm cannot be verified by the bundled OpenID Connect library | error |
| `warden_plaintext_secret_<id>` | The client secret is stored unencrypted | critical |
| `warden_unreadable_secret_<id>` | The client secret cannot be decrypted | critical |
| `warden_unknown_roles_<id>` | The role map names roles that do not exist | warning |
| `warden_cred_key_missing` | No `CIVICRM_CRED_KEYS` configured | warning; critical once a provider holds a secret |
| `warden_insecure_session_cookie` | The session cookie lacks the `Secure` flag, typically behind a proxy that terminates TLS | error |
| `warden_redirect_uri` | The site URL does not yield a usable callback URL | warning |
| `warden_disabled_by_constant` | `CIVICRM_WARDEN_DISABLE` is defined, so Warden is switched off | warning |

For a provider whose issuer points at Microsoft Entra ID, three more checks apply: `warden_entra_tenant_issuer_<id>` (the issuer is not tenant-specific, error), `warden_entra_email_link_<id>` (email linking is switched on although Entra cannot assert a verified email, warning) and `warden_entra_groups_<id>` (the role map uses `groups` instead of App Roles, warning).

A check that fails to run reports an error under its own name with the reason, rather than staying silent. `warden_providers` means the provider list itself could not be read; `warden_provider_<id>` means one provider's checks failed.

## Login trail

CiviCRM Standalone keeps no record of logins, so Warden writes its own, under **Single sign-on (warden) → Login trail**. Each row records the provider, the user when one was resolved, the event, a machine-readable reason such as `bad_signature` or `unknown_subject`, the source IP address and the time.

Recorded events: login succeeded, login failed, login denied by policy, user provisioned, relink refused, rate limited, logout, back-channel logout and revoked session terminated.

The trail never contains tokens, authorization codes, email addresses or display names. The subject is stored as a salted hash, which correlates the rows of one identity without revealing it. Rows cannot be changed or deleted through the API and survive the deletion of their provider or user.

## Retention

Source IP addresses are personal data, so the trail is not kept forever. The daily scheduled job "Warden: prune the login trail" deletes

- login trail rows older than `warden_audit_retention_days` (default 180), and
- session bindings unused for `warden_session_retention_days` (default 30).

Set both to what your data protection policy allows.

## Rate limiting

CiviCRM Standalone has no protection against login floods. Warden counts failed logins, policy denials and refused relinks per source address and blocks its login and callback routes once `warden_rate_limit_attempts` (default 20) is reached within `warden_rate_limit_window` (default 300 seconds). Successful logins are not counted, so a busy office behind one address is not throttled.

When the client address cannot be determined, for example behind a proxy that hides it, the limiter lets the request through.
