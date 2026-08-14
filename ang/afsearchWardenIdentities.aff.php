<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

return [
  'type' => 'search',
  'title' => E::ts('Warden - Linked identities'),
  'icon' => 'fa-link',
  'server_route' => 'civicrm/admin/warden/identities',
  'permission' => [
    'administer warden',
  ],
];
