---
title: Warden
---

# Warden

Warden lets people sign in to CiviCRM Standalone through an OpenID Connect identity provider such as Keycloak or Microsoft Entra ID. It links each CiviCRM user to the provider's stable issuer and subject, can create users on their first login, maps provider claims to CiviCRM roles and keeps its own login trail.

Warden is not tied to a vendor: every provider goes through the same discovery, authorization-code flow with PKCE and signed ID token validation. It is meant for organisations that already manage their staff accounts in an identity provider and want CiviCRM to follow it.

## Requirements

- CiviCRM Standalone, at the version listed in the extension's `info.xml` or newer. Warden does not work with Drupal, WordPress or other CMS integrations.
- PHP 8.4.
- The core extensions `standaloneusers`, `authx`, SearchKit and FormBuilder.
- An encryption key in `CIVICRM_CRED_KEYS`, so client secrets are stored encrypted. Warden refuses to save a secret without one.

## Install

Download the release archive from the [releases page](https://github.com/civico-de/warden/releases). It bundles its Composer dependencies. Unpack it into your CiviCRM extensions directory and enable it:

```bash
cv ext:enable warden
```

## Quick start

1. Configure `CIVICRM_CRED_KEYS`.
2. Register a confidential client at your identity provider with this callback URL:

    ```text
    https://YOUR-CIVICRM/civicrm/warden/return
    ```

3. In CiviCRM, open **Administer → Single sign-on (warden) → Identity providers** and add the provider with its issuer URL, client ID and client secret. Leave the mode at `optional`.
4. Sign in through the new button on the login screen. An unknown person is refused until you link their identity or allow provisioning, see [Who may sign in](configuration.md#who-may-sign-in).
5. Check **Administer → Administration Console → System Status** for Warden messages, and the login trail for what happened.

Switch a provider to `required` only after a complete login has succeeded, and read the next section first.

## Lockout protection

A misconfigured provider in `required` mode locks everyone out. There are three ways back in:

- Switch off the setting `warden_enabled`. Warden then refuses its own login and callback routes and enforces no provider mode, so password login works again.
- Define `CIVICRM_WARDEN_DISABLE` as a truthy constant in `civicrm.settings.php`. It overrides the setting when the user interface cannot be reached.
- Disable the extension with `cv ext:disable warden`.

In addition, users holding `administer CiviCRM` keep password login in `required` mode by default. Switching that protection off makes the identity provider a single point of failure; do it only with a tested emergency procedure.

## Further pages

- [Configuration](configuration.md): providers, modes, who may sign in, role mapping, profile sync and Microsoft Entra ID.
- [Operations](operations.md): single logout, status checks, the login trail, retention and rate limiting.
- [Reference](reference.md): permissions, settings, URLs and events for other extensions.
