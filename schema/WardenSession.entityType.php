<?php

declare(strict_types = 1);

/**
 * A revocable binding between a local PHP session and the OIDC session that
 * authenticated it. Remote `sub`, `sid`, and the local session id are stored
 * only as site-salted hashes.
 */
return [
  'name' => 'WardenSession',
  'table' => 'civicrm_warden_session',
  'class' => 'CRM_Warden_DAO_WardenSession',
  'getInfo' => fn () => [
    'title' => 'Warden Session',
    'title_plural' => 'Warden Sessions',
    'description' => 'Revocable local sessions established through an OIDC provider.',
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
        'fk' => FALSE,
      ],
    ],
    'local_session_hash' => [
      'title' => 'Local session hash',
      'sql_type' => 'char(64)',
      'input_type' => 'Text',
      'required' => TRUE,
    ],
    'subject_hash' => [
      'title' => 'Subject hash',
      'sql_type' => 'char(64)',
      'input_type' => 'Text',
      'required' => TRUE,
    ],
    'provider_session_hash' => [
      'title' => 'Provider session hash',
      'sql_type' => 'char(64)',
      'input_type' => 'Text',
      'description' => 'Hash of the optional OIDC sid claim.',
    ],
    'created_date' => [
      'title' => 'Created',
      'sql_type' => 'timestamp',
      'input_type' => 'Date',
      'required' => TRUE,
      'default' => 'CURRENT_TIMESTAMP',
    ],
    'last_seen_date' => [
      'title' => 'Last seen',
      'sql_type' => 'timestamp',
      'input_type' => 'Date',
      'required' => TRUE,
      'default' => 'CURRENT_TIMESTAMP',
    ],
    'revoked_date' => [
      'title' => 'Revoked',
      'sql_type' => 'timestamp',
      'input_type' => 'Date',
    ],
  ],
  'getIndices' => fn () => [
    'UI_local_session_hash' => [
      'fields' => ['local_session_hash' => TRUE],
      'unique' => TRUE,
    ],
    'index_provider_subject' => [
      'fields' => ['provider_id' => TRUE, 'subject_hash' => TRUE],
    ],
    'index_provider_session' => [
      'fields' => ['provider_id' => TRUE, 'provider_session_hash' => TRUE],
    ],
    'index_last_seen' => [
      'fields' => ['last_seen_date' => TRUE],
    ],
  ],
  'getPaths' => fn () => [],
];
