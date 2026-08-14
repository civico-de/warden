# ADR 0001: Keep Warden's OIDC client boundary

Status: accepted

## Context

CiviCRM ships the `oauth-client` extension. Its `OAuthState` service already
provides session-bound state with expiry and can store a PKCE verifier. That is
useful prior art and Warden should not claim otherwise.

The authentication requirement is broader than OAuth state handling. In the
CiviCRM 6.17.2 implementation, `CiviGenericProvider::getResourceOwner()`
decodes the `id_token` payload and explicitly relies on the secured token
endpoint instead of verifying the token signature. It does not provide the
complete OIDC authentication policy Warden needs: verified issuer, audience,
signature and temporal claims, nonce binding, stable `iss`/`sub` identity
links, provisioning policy, required-mode enforcement, audit, and local
session binding.

The `oauth_login` extension is valuable prior art for connecting OAuth login
to CiviCRM, but using it as Warden's runtime foundation would still leave these
Warden-specific authentication and policy responsibilities to implement.

## Decision

Warden uses the maintained `digitalcz/openid-connect` package for discovery,
authorization-code/PKCE handling, token exchange and cryptographic OIDC token
validation. Warden owns the CiviCRM-specific identity, authorization, session,
logout and audit layers.

Warden retains its own small one-time state store. This keeps the state, nonce
and library callback data in the same component boundary and avoids making the
optional `oauth-client` extension a transitive runtime dependency.

## Consequences

- Improvements in CiviCRM's OAuth stack should be reviewed and can be adopted
  when they meet the complete authentication contract.
- Warden must keep its OIDC library current and test it against supported
  CiviCRM/PHP combinations.
- Upgrading CiviCRM remains recommended, but does not by itself replace
  Warden's OIDC validation and CiviCRM policy layers.
