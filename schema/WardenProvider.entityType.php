<?php

declare(strict_types = 1);

/**
 * One configured OpenID Connect identity provider. Endpoints are never stored
 * here — they are discovered from `issuer` and cached — so a provider that
 * rotates its endpoints needs no edit.
 */
/**
 * Field groups, so no single closure grows past what a reader can hold in
 * their head. The entity contract is exactly the merge of the three.
 */
$connection = static fn (): array => [
  'id' => [
    'title' => 'ID',
    'sql_type' => 'int unsigned',
    'input_type' => 'Number',
    'required' => TRUE,
    'primary_key' => TRUE,
    'auto_increment' => TRUE,
  ],
  'name' => [
    'title' => 'Name',
    'sql_type' => 'varchar(64)',
    'input_type' => 'Text',
    'required' => TRUE,
    'description' => 'Machine name. Recorded on every audit row; renaming breaks the link to existing history.',
  ],
  'label' => [
    'title' => 'Label',
    'sql_type' => 'varchar(128)',
    'input_type' => 'Text',
    'required' => TRUE,
    'description' => 'Shown on the login button.',
  ],
  'issuer' => [
    'title' => 'Issuer',
    'sql_type' => 'varchar(255)',
    'input_type' => 'Text',
    'required' => TRUE,
    'description' => 'The OIDC issuer URL. Entra ID: https://login.microsoftonline.com/<tenant GUID>/v2.0. Discovery appends /.well-known/openid-configuration; the discovered `issuer` must match this string exactly.',
  ],
  'client_id' => [
    'title' => 'Client ID',
    'sql_type' => 'varchar(255)',
    'input_type' => 'Text',
    'required' => TRUE,
  ],
  'client_secret' => [
    'title' => 'Client secret',
    'sql_type' => 'text',
    'input_type' => 'Text',
    'description' => 'Encrypted at rest with the CRED key. warden refuses to save one when CIVICRM_CRED_KEYS is unset rather than storing it in the clear. Empty for a public client using PKCE only.',
  ],
  'scopes' => [
    'title' => 'Scopes',
    'sql_type' => 'varchar(255)',
    'input_type' => 'Text',
    'required' => TRUE,
    'default' => 'openid profile email',
    'description' => 'Space-separated. `openid` is always sent whether listed or not.',
  ],
];

$security = static fn (): array => [
  'mode' => [
    'title' => 'Mode',
    'sql_type' => 'varchar(16)',
    'input_type' => 'Select',
    'required' => TRUE,
    'default' => 'optional',
    'pseudoconstant' => ['callback' => 'Civi\Warden\Options::modes'],
    'description' => 'disabled | optional | required. `required` also denies password login site-wide — read the lock-out section of the README first.',
  ],
  'allowed_algorithms' => [
    'title' => 'Allowed signing algorithms',
    'sql_type' => 'varchar(255)',
    'input_type' => 'Text',
    'required' => TRUE,
    'default' => 'RS256',
    'description' => 'Space-separated allow-list matched against the ID token `alg` header. Anything outside it is rejected before a key is even looked up.',
  ],
  'is_active' => [
    'title' => 'Enabled',
    'sql_type' => 'boolean',
    'input_type' => 'CheckBox',
    'required' => TRUE,
    'default' => TRUE,
  ],
  'weight' => [
    'title' => 'Order',
    'sql_type' => 'int',
    'input_type' => 'Number',
    'required' => TRUE,
    'default' => 1,
    'description' => 'Order of the login buttons.',
  ],
];

$provisioning = static fn (): array => [
  'claim_role_map' => [
    'title' => 'Claim to role map (JSON)',
    'sql_type' => 'text',
    'input_type' => 'TextArea',
    'description' => 'JSON object. Entra App Roles: {"claim": "roles", "map": {"CiviCRM.Admin": ["admin"]}}. Keycloak: {"claim": "realm_access.roles", "map": {"crm-admin": ["admin"]}}. Values on the right are CiviCRM role NAMES; permission strings are never accepted.',
  ],
  'role_sync_mode' => [
    'title' => 'Role sync',
    'sql_type' => 'varchar(16)',
    'input_type' => 'Select',
    'required' => TRUE,
    'default' => 'provision_only',
    'pseudoconstant' => ['callback' => 'Civi\Warden\Options::roleSyncModes'],
    'description' => 'off | provision_only | every_login. `every_login` also REMOVES mapped roles the claim no longer grants; roles outside the map are never touched.',
  ],
  'profile_sync_mode' => [
    'title' => 'Profile sync',
    'sql_type' => 'varchar(16)',
    'input_type' => 'Select',
    'required' => TRUE,
    'default' => 'off',
    'pseudoconstant' => ['callback' => 'Civi\Warden\Options::profileSyncModes'],
    'description' => 'off | every_login. `every_login` copies the `name` claim onto the contact on each login, and the `email` claim only while email_verified is true.',
  ],
  'provision_policy' => [
    'title' => 'Provisioning',
    'sql_type' => 'varchar(16)',
    'input_type' => 'Select',
    'required' => TRUE,
    'default' => 'never',
    'pseudoconstant' => ['callback' => 'Civi\Warden\Options::provisionPolicies'],
    'description' => 'never | provision. With `never`, an unknown subject is refused instead of creating a user.',
  ],
  'link_policy' => [
    'title' => 'Unmatched-subject linking',
    'sql_type' => 'varchar(24)',
    'input_type' => 'Select',
    'required' => TRUE,
    'default' => 'never',
    'pseudoconstant' => ['callback' => 'Civi\Warden\Options::linkPolicies'],
    'description' => 'never | verified_email. With `verified_email`, an unknown subject may adopt an existing user whose username matches the email claim, and ONLY when email_verified is true. Account takeover risk — see docs/configuration.md.',
  ],
  'default_role_names' => [
    'title' => 'Roles for provisioned users',
    'sql_type' => 'varchar(255)',
    'input_type' => 'Text',
    'description' => 'Space-separated role names given to a newly provisioned user. Empty means no roles: the user can log in and can do nothing.',
  ],
];

return [
  'name' => 'WardenProvider',
  'table' => 'civicrm_warden_provider',
  'class' => 'CRM_Warden_DAO_WardenProvider',
  'getInfo' => fn () => [
    'title' => 'Warden Provider',
    'title_plural' => 'Warden Providers',
    'description' => 'An OpenID Connect identity provider warden will accept logins from.',
    'log' => TRUE,
  ],
  'getFields' => static fn (): array => [...$connection(), ...$security(), ...$provisioning()],
  'getIndices' => fn () => [
    'UI_name' => [
      'fields' => ['name' => TRUE],
      'unique' => TRUE,
    ],
    'UI_issuer' => [
      'fields' => ['issuer' => TRUE],
      'unique' => TRUE,
    ],
    'index_active_weight' => [
      'fields' => ['is_active' => TRUE, 'weight' => TRUE],
    ],
  ],
  'getPaths' => fn () => [],
];
