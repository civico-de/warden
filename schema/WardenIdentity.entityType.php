<?php

declare(strict_types = 1);

/**
 * The binding between an IdP subject and a CiviCRM user. `subject` is the only
 * identifier warden trusts: it is the one claim an OIDC provider promises is
 * immutable and never reassigned. Email and preferred_username are not stored
 * here on purpose — they are mutable, and they are PII.
 */
return [
  'name' => 'WardenIdentity',
  'table' => 'civicrm_warden_identity',
  'class' => 'CRM_Warden_DAO_WardenIdentity',
  'getInfo' => fn () => [
    'title' => 'Warden Identity',
    'title_plural' => 'Warden Identities',
    'description' => 'Link between an OIDC subject and a CiviCRM user.',
    'log' => TRUE,
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
      'required' => TRUE,
      'entity_reference' => [
        'entity' => 'WardenProvider',
        'key' => 'id',
        'on_delete' => 'CASCADE',
      ],
    ],
    'user_id' => [
      'title' => 'User',
      'sql_type' => 'int unsigned',
      'input_type' => 'EntityRef',
      'required' => TRUE,
      'entity_reference' => [
        'entity' => 'User',
        'key' => 'id',
        'on_delete' => 'CASCADE',
      ],
    ],
    'subject' => [
      'title' => 'Subject',
      'sql_type' => 'varchar(255)',
      'input_type' => 'Text',
      'required' => TRUE,
      'description' => 'The `sub` claim, verbatim. Opaque to warden.',
    ],
    'created_date' => [
      'title' => 'Linked',
      'sql_type' => 'timestamp',
      'input_type' => 'Date',
      'required' => TRUE,
      'default' => 'CURRENT_TIMESTAMP',
    ],
    'last_login_date' => [
      'title' => 'Last login',
      'sql_type' => 'timestamp',
      'input_type' => 'Date',
    ],
    'login_count' => [
      'title' => 'Logins',
      'sql_type' => 'int unsigned',
      'input_type' => 'Number',
      'required' => TRUE,
      'default' => 0,
    ],
  ],
  'getIndices' => fn () => [
    // The security-critical one. Two different CiviCRM users can never end up
    // behind the same remote identity, whatever the application code does.
    'UI_provider_subject' => [
      'fields' => ['provider_id' => TRUE, 'subject' => TRUE],
      'unique' => TRUE,
    ],
    // One remote identity per user per provider: a user cannot silently
    // accumulate links and log in as either of two people.
    'UI_provider_user' => [
      'fields' => ['provider_id' => TRUE, 'user_id' => TRUE],
      'unique' => TRUE,
    ],
  ],
  'getPaths' => fn () => [],
];
