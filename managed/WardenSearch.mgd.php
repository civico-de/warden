<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

/**
 * SearchKit admin views: providers, linked identities and the login trail.
 * Exposed as pages via ang/afsearchWarden*.aff.php.
 *
 * The trail display deliberately shows `subject_hash` rather than joining out
 * to anything that would reveal who a row is about beyond the user id.
 */
return [
  [
    'name' => 'SavedSearch_Warden_Providers',
    'entity' => 'SavedSearch',
    'cleanup' => 'unused',
    'update' => 'unmodified',
    'params' => [
      'version' => 4,
      'values' => [
        'name' => 'Warden_Providers',
        'label' => E::ts('Warden - Identity providers'),
        'api_entity' => 'WardenProvider',
        'api_params' => [
          'version' => 4,
          'select' => [
            'id', 'name', 'label', 'issuer', 'mode:label', 'is_active',
            'provision_policy:label', 'link_policy:label', 'role_sync_mode:label',
            'allowed_algorithms', 'weight',
            'COUNT(identity.id) AS linked_count',
          ],
          'join' => [
            ['WardenIdentity AS identity', 'LEFT', ['id', '=', 'identity.provider_id']],
          ],
          'groupBy' => ['id', 'mode', 'is_active'],
          'orderBy' => ['weight' => 'ASC'],
          'where' => [],
        ],
      ],
      'match' => ['name'],
    ],
  ],
  [
    'name' => 'SearchDisplay_Warden_Providers_Table',
    'entity' => 'SearchDisplay',
    'cleanup' => 'unused',
    'update' => 'unmodified',
    'params' => [
      'version' => 4,
      'values' => [
        'name' => 'Warden_Providers_Table',
        'label' => E::ts('Warden - Identity providers'),
        'saved_search_id.name' => 'Warden_Providers',
        'type' => 'table',
        'settings' => [
          'actions' => TRUE,
          'limit' => 50,
          'pager' => ['expose_limit' => TRUE],
          'sort' => [['weight', 'ASC']],
          'placeholder' => 3,
          'noResultsText' => E::ts('No identity provider configured. Nobody can sign in with single sign-on until one exists and is enabled.'),
          'toolbar' => [
            [
              'path' => 'civicrm/admin/warden/provider',
              'text' => E::ts('New provider'),
              'icon' => 'fa-plus',
              'style' => 'primary',
              'target' => 'crm-popup',
            ],
          ],
          'columns' => [
            ['type' => 'field', 'key' => 'label', 'label' => E::ts('Label'), 'sortable' => TRUE,
              'link' => ['path' => 'civicrm/admin/warden/provider#?WardenProvider1=[id]', 'target' => 'crm-popup']],
            ['type' => 'field', 'key' => 'name', 'label' => E::ts('Name'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'issuer', 'label' => E::ts('Issuer'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'mode:label', 'label' => E::ts('Mode'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'allowed_algorithms', 'label' => E::ts('Algorithms'), 'sortable' => FALSE],
            ['type' => 'field', 'key' => 'provision_policy:label', 'label' => E::ts('Provisioning'), 'sortable' => FALSE],
            ['type' => 'field', 'key' => 'link_policy:label', 'label' => E::ts('Email linking'), 'sortable' => FALSE],
            ['type' => 'field', 'key' => 'linked_count', 'label' => E::ts('Linked users'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'is_active', 'label' => E::ts('Enabled'), 'sortable' => TRUE],
          ],
          // `required` is the mode that can lock a site out; it is styled so
          // nobody has to read a column to notice it.
          'cssRules' => [
            ['strong', 'mode', '=', 'required'],
            ['disabled', 'is_active', '=', FALSE],
          ],
        ],
      ],
      'match' => ['name'],
    ],
  ],
  [
    'name' => 'SavedSearch_Warden_Identities',
    'entity' => 'SavedSearch',
    'cleanup' => 'unused',
    'update' => 'unmodified',
    'params' => [
      'version' => 4,
      'values' => [
        'name' => 'Warden_Identities',
        'label' => E::ts('Warden - Linked identities'),
        'api_entity' => 'WardenIdentity',
        'api_params' => [
          'version' => 4,
          'select' => [
            'id', 'provider_id.label', 'user_id', 'user_id.username',
            'subject', 'created_date', 'last_login_date', 'login_count',
          ],
          'orderBy' => ['last_login_date' => 'DESC'],
          'where' => [],
        ],
      ],
      'match' => ['name'],
    ],
  ],
  [
    'name' => 'SearchDisplay_Warden_Identities_Table',
    'entity' => 'SearchDisplay',
    'cleanup' => 'unused',
    'update' => 'unmodified',
    'params' => [
      'version' => 4,
      'values' => [
        'name' => 'Warden_Identities_Table',
        'label' => E::ts('Warden - Linked identities'),
        'saved_search_id.name' => 'Warden_Identities',
        'type' => 'table',
        'settings' => [
          'actions' => TRUE,
          'limit' => 50,
          'pager' => ['expose_limit' => TRUE],
          'sort' => [['last_login_date', 'DESC']],
          'placeholder' => 3,
          'noResultsText' => E::ts('No identity is linked yet. A link is created the first time somebody signs in.'),
          'columns' => [
            ['type' => 'field', 'key' => 'provider_id.label', 'label' => E::ts('Provider'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'user_id.username', 'label' => E::ts('User'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'subject', 'label' => E::ts('Subject'), 'sortable' => FALSE],
            ['type' => 'field', 'key' => 'created_date', 'label' => E::ts('Linked'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'last_login_date', 'label' => E::ts('Last login'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'login_count', 'label' => E::ts('Logins'), 'sortable' => TRUE],
          ],
        ],
      ],
      'match' => ['name'],
    ],
  ],
  [
    'name' => 'SavedSearch_Warden_Audit',
    'entity' => 'SavedSearch',
    'cleanup' => 'unused',
    'update' => 'unmodified',
    'params' => [
      'version' => 4,
      'values' => [
        'name' => 'Warden_Audit',
        'label' => E::ts('Warden - Login trail'),
        'api_entity' => 'WardenAudit',
        'api_params' => [
          'version' => 4,
          'select' => [
            'id', 'created_date', 'event:label', 'provider_name',
            'user_id', 'reason', 'detail', 'source_ip', 'subject_hash',
          ],
          'orderBy' => ['created_date' => 'DESC'],
          'where' => [],
        ],
      ],
      'match' => ['name'],
    ],
  ],
  [
    'name' => 'SearchDisplay_Warden_Audit_Table',
    'entity' => 'SearchDisplay',
    'cleanup' => 'unused',
    'update' => 'unmodified',
    'params' => [
      'version' => 4,
      'values' => [
        'name' => 'Warden_Audit_Table',
        'label' => E::ts('Warden - Login trail'),
        'saved_search_id.name' => 'Warden_Audit',
        'type' => 'table',
        'settings' => [
          'actions' => FALSE,
          'limit' => 100,
          'pager' => ['expose_limit' => TRUE],
          'sort' => [['created_date', 'DESC']],
          'placeholder' => 5,
          'noResultsText' => E::ts('Nothing recorded yet.'),
          'columns' => [
            ['type' => 'field', 'key' => 'created_date', 'label' => E::ts('When'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'event:label', 'label' => E::ts('Event'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'provider_name', 'label' => E::ts('Provider'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'user_id', 'label' => E::ts('User id'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'reason', 'label' => E::ts('Reason'), 'sortable' => TRUE],
            ['type' => 'field', 'key' => 'detail', 'label' => E::ts('Detail'), 'sortable' => FALSE],
            ['type' => 'field', 'key' => 'source_ip', 'label' => E::ts('Source IP'), 'sortable' => TRUE],
          ],
          'cssRules' => [
            ['bg-danger', 'event', 'IN', ['login_denied', 'relink_refused', 'rate_limited']],
            ['bg-warning', 'event', '=', 'login_failure'],
          ],
        ],
      ],
      'match' => ['name'],
    ],
  ],
];
