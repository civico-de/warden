<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

/**
 * Admin navigation: a "Single sign-on" block under Administer. Config pages
 * need `administer warden`, the log is readable with `view warden log`.
 */
$child = static fn (
  string $name,
  string $label,
  string $url,
  string $permission,
  int $weight,
): array => [
  'name' => "Navigation_{$name}",
  'entity' => 'Navigation',
  'cleanup' => 'unused',
  'update' => 'unmodified',
  'params' => [
    'version' => 4,
    'values' => [
      'name' => $name,
      'label' => $label,
      'url' => $url,
      'permission' => $permission,
      'permission_operator' => 'OR',
      'parent_id.name' => 'warden_admin',
      'is_active' => TRUE,
      'weight' => $weight,
      'domain_id' => 'current_domain',
    ],
    'match' => ['name', 'domain_id'],
  ],
];

return [
  [
    'name' => 'Navigation_warden_admin',
    'entity' => 'Navigation',
    'cleanup' => 'unused',
    'update' => 'unmodified',
    'params' => [
      'version' => 4,
      'values' => [
        'name' => 'warden_admin',
        'label' => E::ts('Single sign-on (warden)'),
        'parent_id.name' => 'Administer',
        'icon' => 'crm-i fa-shield',
        'permission' => 'administer warden,view warden log',
        'permission_operator' => 'OR',
        'is_active' => TRUE,
        'domain_id' => 'current_domain',
      ],
      'match' => ['name', 'domain_id'],
    ],
  ],
  $child('warden_providers_nav', E::ts('Identity providers'), 'civicrm/admin/warden/providers', 'administer warden', 10),
  $child('warden_identities_nav', E::ts('Linked identities'), 'civicrm/admin/warden/identities', 'administer warden', 20),
  $child('warden_audit_nav', E::ts('Login trail'), 'civicrm/admin/warden/audit', 'view warden log,administer warden', 30),
  $child('warden_settings_nav', E::ts('Settings'), 'civicrm/admin/setting/warden', 'administer warden', 40),
];
