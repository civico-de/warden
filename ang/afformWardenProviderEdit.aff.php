<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

/**
 * Create/edit form for WardenProvider, launched from the provider list.
 * url-autofill edits an existing row via `#?WardenProvider1=<id>`.
 */
return [
  'type' => 'form',
  'title' => E::ts('Identity provider'),
  'icon' => 'fa-shield',
  'server_route' => 'civicrm/admin/warden/provider',
  'permission' => [
    'administer warden',
  ],
];
