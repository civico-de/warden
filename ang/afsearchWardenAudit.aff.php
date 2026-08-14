<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

return [
  'type' => 'search',
  'title' => E::ts('Warden - Login trail'),
  'icon' => 'fa-history',
  'server_route' => 'civicrm/admin/warden/audit',
  'permission' => [
    'view warden log',
  ],
];
