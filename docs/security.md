# Security model

- Authorization requests are short-lived, single-use records containing a
  random state, nonce and PKCE verifier.
- ID tokens are accepted only after issuer, audience, signature and temporal
  claim validation against the provider's discovered JWKS.
- Back-channel logout tokens are signature- and claim-validated, replay
  checked by `jti`, and mapped to hashed local session bindings.
- Users are linked by the stable issuer and subject pair, never by an
  unverified email address alone.
- The login and callback routes are rate-limited per source address. Failures
  are recorded in the login trail without storing tokens or secrets.
- Provider client secrets are stored through CiviCRM's credential mechanisms;
  do not place them in exported managed configuration.
- A user who has been deactivated in CiviCRM is refused even when their
  identity is linked.
- Role mapping is an allow-list of CiviCRM role names; a provider cannot name
  a permission and be believed.

Retention of the login trail and of session bindings is described in
[Operations](operations.md#retention). To report a vulnerability, see
[SECURITY.md](../SECURITY.md).
