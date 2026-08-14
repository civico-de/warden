# ADR 0002: Persist exact OIDC session revocations

Status: accepted

## Context

An identity provider cannot directly delete an arbitrary PHP session stored by
CiviCRM. OIDC back-channel logout also runs without the user's browser. A
provider notification therefore needs a durable bridge to the later request
made by the affected browser.

Revoking every local session belonging to a subject would be broader than an
OIDC logout carrying a session identifier. Storing raw local session IDs,
subjects or OIDC session IDs would unnecessarily expose authentication
identifiers in the database.

## Decision

Warden stores site-keyed hashes for the local PHP session ID, OIDC issuer,
subject and session ID. A signed back-channel logout token revokes records
matching its `sid`, or its `sub` where the protocol permits that form.

A request subscriber checks the current session's record before CiviCRM route
handling and terminates that session when it has been revoked. RP-initiated
logout clears the binding immediately and redirects to the provider's
end-session endpoint when one is advertised.

## Consequences

- Provider-initiated logout takes effect on the affected browser's next
  CiviCRM request; it does not poll the provider on every page view.
- Back-channel logout is preferred because its signed token is independent of
  browser delivery.
- Front-channel logout is deliberately not exposed: its cross-origin iframe
  cannot rely on the ordinary CiviCRM session cookie under default SameSite
  policy or browser third-party-cookie blocking.
- Session-binding records have their own retention setting and are pruned by
  the scheduled Warden cleanup job.
