<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

/**
 * Site-wide settings. Everything PER-PROVIDER (issuer, mode, claim mapping,
 * provisioning) lives on the WardenProvider row instead.
 */
return [
  'warden_enabled' => [
    'name' => 'warden_enabled',
    'settings_pages' => ['warden' => ['weight' => 10]],
    'type' => 'Boolean',
    'default' => TRUE,
    'html_type' => 'toggle',
    'title' => E::ts('warden: single sign-on enabled'),
    'description' => E::ts(
      'Master switch. With it off, the login and callback routes refuse every request and no provider mode is enforced — password login keeps working. The CIVICRM_WARDEN_DISABLE constant in civicrm.settings.php overrides this and cannot be turned back on from the UI.',
    ),
    'is_domain' => 1,
    'is_contact' => 0,
  ],
  'warden_discovery_ttl' => [
    'name' => 'warden_discovery_ttl',
    'settings_pages' => ['warden' => ['weight' => 20]],
    'type' => 'Integer',
    'default' => 900,
    'html_type' => 'text',
    'title' => E::ts('warden: discovery and JWKS cache lifetime (seconds)'),
    'description' => E::ts(
      'How long a fetched discovery document or JWKS stays usable. Clamped to 300-3600. A failed fetch is cached for 60 seconds only, never for this long — a provider that comes back must be usable again within a minute.',
    ),
    'is_domain' => 1,
    'is_contact' => 0,
  ],
  'warden_clock_leeway' => [
    'name' => 'warden_clock_leeway',
    'settings_pages' => ['warden' => ['weight' => 30]],
    'type' => 'Integer',
    'default' => 60,
    'html_type' => 'text',
    'title' => E::ts('warden: clock skew allowance (seconds)'),
    'description' => E::ts(
      'Applied to exp, iat and nbf in both directions. Clamped to 0-300: a larger window is how an expired token becomes a usable one.',
    ),
    'is_domain' => 1,
    'is_contact' => 0,
  ],
  'warden_state_ttl' => [
    'name' => 'warden_state_ttl',
    'settings_pages' => ['warden' => ['weight' => 40]],
    'type' => 'Integer',
    'default' => 600,
    'html_type' => 'text',
    'title' => E::ts('warden: authorization request lifetime (seconds)'),
    'description' => E::ts(
      'How long the browser has to come back from the identity provider before its state, nonce and PKCE verifier expire. Clamped to 60-1800.',
    ),
    'is_domain' => 1,
    'is_contact' => 0,
  ],
  'warden_rate_limit_attempts' => [
    'name' => 'warden_rate_limit_attempts',
    'settings_pages' => ['warden' => ['weight' => 50]],
    'type' => 'Integer',
    'default' => 20,
    'html_type' => 'text',
    'title' => E::ts('warden: callback attempts allowed per IP'),
    'description' => E::ts(
      'Failed callbacks from one source address within the window below. Core Standalone has no login rate limiting at all, so this is the only brake on an automated attack against the callback route. 0 disables the limiter.',
    ),
    'is_domain' => 1,
    'is_contact' => 0,
  ],
  'warden_rate_limit_window' => [
    'name' => 'warden_rate_limit_window',
    'settings_pages' => ['warden' => ['weight' => 60]],
    'type' => 'Integer',
    'default' => 300,
    'html_type' => 'text',
    'title' => E::ts('warden: rate-limit window (seconds)'),
    'is_domain' => 1,
    'is_contact' => 0,
  ],
  'warden_audit_retention_days' => [
    'name' => 'warden_audit_retention_days',
    'settings_pages' => ['warden' => ['weight' => 70]],
    'type' => 'Integer',
    'default' => 180,
    'html_type' => 'text',
    'title' => E::ts('warden: audit retention (days)'),
    'description' => E::ts(
      'Audit rows older than this are purged by the warden.prune scheduled job. The trail records source IP addresses, so keeping it forever is a data-protection decision, not a default.',
    ),
    'is_domain' => 1,
    'is_contact' => 0,
  ],
  'warden_protect_admin_password_login' => [
    'name' => 'warden_protect_admin_password_login',
    'settings_pages' => ['warden' => ['weight' => 80]],
    'type' => 'Boolean',
    'default' => TRUE,
    'html_type' => 'toggle',
    'title' => E::ts('warden: keep password recovery open for administrators'),
    'description' => E::ts(
      'ON by default and deliberately so. In `required` mode warden denies password login and password reset to everyone EXCEPT holders of `administer CiviCRM`, who keep a way back in when the identity provider is unreachable. Turning this off makes the identity provider a single point of failure for the whole site.',
    ),
    'is_domain' => 1,
    'is_contact' => 0,
  ],
];
