<?php

declare(strict_types = 1);

/**
 * warden's own login trail. Core Standalone has none — Login.php only leaves a
 * comment inviting extensions to add one — so an SSO deployment would
 * otherwise have no record of who got in, who was refused and why.
 *
 * NO PII. `user_id` and `provider_id` are ids; `subject_hash` is a salted
 * digest, never the subject itself; `detail` carries reason codes and ids.
 * Tokens are never written here, at any log level.
 */
return [
  'name' => 'WardenAudit',
  'table' => 'civicrm_warden_audit',
  'class' => 'CRM_Warden_DAO_WardenAudit',
  'getInfo' => fn () => [
    'title' => 'Warden Audit Record',
    'title_plural' => 'Warden Audit Records',
    'description' => 'Login attempts, provisioning decisions and refusals.',
    'log' => FALSE,
  ],
  'getFields' => fn () => [
    'id' => [
      'title' => 'ID',
      'sql_type' => 'int unsigned',
      'input_type' => 'Number',
      'required' => TRUE,
      'primary_key' => TRUE,
      'auto_increment' => TRUE,
    ],
    'provider_id' => [
      'title' => 'Provider',
      'sql_type' => 'int unsigned',
      'input_type' => 'EntityRef',
      'entity_reference' => [
        'entity' => 'WardenProvider',
        'key' => 'id',
        'on_delete' => 'SET NULL',
      ],
    ],
    'provider_name' => [
      'title' => 'Provider name',
      'sql_type' => 'varchar(64)',
      'input_type' => 'Text',
      'description' => 'Denormalised so the trail survives provider deletion.',
    ],
    'user_id' => [
      'title' => 'User',
      'sql_type' => 'int unsigned',
      'input_type' => 'EntityRef',
      'entity_reference' => [
        'entity' => 'User',
        'key' => 'id',
        // See WardenIdentity.user_id: no physical FK, because `User` belongs
        // to standaloneusers and cannot be resolved when the schema is built
        // in isolation. UserCleanupSubscriber clears these on user deletion.
        'fk' => FALSE,
      ],
      'description' => 'NULL when the attempt never resolved to a user. Deliberately kept when the user is deleted — a trail that vanishes with its subject is not a trail.',
    ],
    'subject_hash' => [
      'title' => 'Subject (hashed)',
      'sql_type' => 'varchar(64)',
      'input_type' => 'Text',
      'description' => 'SHA-256 of siteKey + subject. Correlates rows belonging to one remote identity without storing the identifier.',
    ],
    'event' => [
      'title' => 'Event',
      'sql_type' => 'varchar(32)',
      'input_type' => 'Select',
      'required' => TRUE,
      'pseudoconstant' => ['callback' => 'Civi\Warden\Options::auditEvents'],
      'description' => 'login_success | login_failure | login_denied | provisioned | relink_refused | rate_limited | logout.',
    ],
    'reason' => [
      'title' => 'Reason',
      'sql_type' => 'varchar(64)',
      'input_type' => 'Text',
      'description' => 'Machine-readable reason code, e.g. bad_signature, nonce_mismatch, unknown_subject.',
    ],
    'detail' => [
      'title' => 'Detail',
      'sql_type' => 'varchar(255)',
      'input_type' => 'Text',
      'description' => 'Short operator-facing note. Ids and codes only — never a claim value, never a token.',
    ],
    'source_ip' => [
      'title' => 'Source IP',
      'sql_type' => 'varchar(45)',
      'input_type' => 'Text',
      'description' => 'Personal data under GDPR; retention is bounded by warden_audit_retention_days.',
    ],
    'created_date' => [
      'title' => 'When',
      'sql_type' => 'timestamp',
      'input_type' => 'Date',
      'required' => TRUE,
      'default' => 'CURRENT_TIMESTAMP',
    ],
  ],
  'getIndices' => fn () => [
    'index_created' => [
      'fields' => ['created_date' => TRUE],
    ],
    'index_event_created' => [
      'fields' => ['event' => TRUE, 'created_date' => TRUE],
    ],
    // The rate limiter counts rows by ip within a window.
    'index_ip_created' => [
      'fields' => ['source_ip' => TRUE, 'created_date' => TRUE],
    ],
  ],
  'getPaths' => fn () => [],
];
