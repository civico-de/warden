# Operations

## System status checks

Warden reports its findings on CiviCRM's System Status page. Among them:

| Check | Severity |
|---|---|
| A provider's discovery document cannot be fetched | error; critical for a `required` provider |
| A provider's signing key set cannot be fetched or holds no keys | error; critical for a `required` provider |
| A client secret is stored unencrypted or cannot be decrypted | critical |
| No `CIVICRM_CRED_KEYS` configured | warning; critical once a provider holds a secret |
| The session cookie lacks the `Secure` flag, typically behind a TLS-terminating proxy | error |
| The site URL does not yield a usable redirect URI | warning |
| A provider allows no signing algorithm, or one that it or this CiviCRM does not support | error |
| The role map names roles that do not exist | warning |
| `CIVICRM_WARDEN_DISABLE` is defined, so Warden is switched off | warning |

Entra-specific checks are listed in [Microsoft Entra ID](entra.md).

### Message names

Every finding is a core status message with a stable name, so a monitor that
reads `System.check` can follow it and an operator can hide it on the status
page. A finding about one provider carries the provider ID in its name, for
example `warden_discovery_3` or `warden_jwks_3`.

A check that fails to run reports an error under its own name with the
reason, rather than staying silent. `warden_providers` means the provider list
itself could not be read; `warden_provider_<id>` means one provider's checks
failed.

## Login trail

CiviCRM Standalone keeps no record of logins, so Warden writes its own, visible
under **Single sign-on (warden) → Login trail**. Each row records the provider,
the user when one was resolved, the event, a machine-readable reason such as
`bad_signature` or `unknown_subject`, the source IP address and the time.

Recorded events: login succeeded, login failed, login denied by policy, user
provisioned, relink refused, rate limited, logout, back-channel logout and
revoked session terminated.

The trail never contains tokens, authorization codes, email addresses or
display names. The subject is stored as a salted hash, which correlates rows of
one remote identity without revealing the identifier. Rows are append-only
through the API and survive the deletion of their provider or user.

## Retention

Source IP addresses are personal data, so the trail is not kept forever. The
daily scheduled job "Warden: prune the login trail" deletes

- login-trail rows older than `warden_audit_retention_days` (default 180), and
- session bindings unused for `warden_session_retention_days` (default 30).

Set both to what your data-protection policy allows.

## Rate limiting

CiviCRM Standalone has no login flood control. Warden counts failed logins,
policy denials and refused relinks per source address and blocks the login and
callback routes once `warden_rate_limit_attempts` (default 20) is reached
within `warden_rate_limit_window` (default 300 seconds). Successful logins are
not counted, so a busy office behind one address is not throttled.

When the client address cannot be determined, for example behind a proxy that
hides it, the limiter lets the request through.
