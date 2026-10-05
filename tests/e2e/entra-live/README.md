# Live Entra ID E2E

Runs Warden's OIDC flow against a real Entra tenant with a Tofu-managed app
registration (`warden-e2e-live`) and test user. Manual only; the signed-in
account must be allowed to create app registrations and users in that tenant:

```sh
export WARDEN_ENTRA_LIVE_TENANT=DIRECTORY-TENANT-ID
az login --tenant "$WARDEN_ENTRA_LIVE_TENANT" --use-device-code
tests/e2e/entra-live/run.sh
```

`run.sh` applies `tofu/`, starts `.docker/docker-compose.entra-live.yml` on
`localhost:8087`, seeds the provider from the Tofu outputs, drives Microsoft's
sign-in page with Playwright on the host and verifies the resulting identity.
`tofu destroy` in `tofu/` removes the app registration and user again.

Tofu state is local by default and holds the client secret and the test
user's password; it is gitignored. To keep it in a remote backend instead, add
a gitignored `tofu/backend_override.tf` with a `terraform { backend … }` block.

Failed runs retain a local Playwright trace below `test-results/`. It is
gitignored and must not be shared because it can contain the test user's
password and authenticated browser state.

Security defaults on the tenant prompt the test user to register MFA; the spec
skips that prompt, which Microsoft allows for 14 days per user. Once Entra
blocks the user, recreate it before the next run:

```sh
(cd tests/e2e/entra-live/tofu && tofu taint azuread_user.staff)
```
