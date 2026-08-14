<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

/**
 * Audit pruning. Enabled by default and daily: the trail records source IP
 * addresses, so a retention job that ships switched off would quietly turn a
 * bounded log into an unbounded one.
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
        'description' => E::ts('Delete warden audit records older than warden_audit_retention_days.'),
        'run_frequency' => 'Daily',
        'api_entity' => 'Warden',
        'api_action' => 'prune',
        'parameters' => '',
        'is_active' => TRUE,
        'domain_id' => 'current_domain',
      ],
      'match' => ['name', 'domain_id'],
    ],
  ],
];
