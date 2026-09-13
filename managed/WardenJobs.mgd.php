<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

/**
 * Audit and stale-session pruning. Enabled by default and daily: the trail
 * records source IP addresses, and logout bindings must not grow forever.
 */
return [
  [
    'name' => 'Job_warden_prune',
    'entity' => 'Job',
    'cleanup' => 'unused',
    'update' => 'unmodified',
    'params' => [
      'version' => 4,
      'values' => [
        'name' => E::ts('Warden: prune the login trail'),
        'description' => E::ts('Delete old audit records and stale OIDC session bindings.'),
        'run_frequency' => 'Daily',
        'api_entity' => 'Warden',
        'api_action' => 'prune',
        // The job runner defaults to APIv3 and runs without a logged-in user.
        'parameters' => "version=4\ncheckPermissions=0",
        'is_active' => TRUE,
        'domain_id' => 'current_domain',
      ],
      'match' => ['name', 'domain_id'],
    ],
  ],
];
