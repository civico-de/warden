<?php

declare(strict_types = 1);

use CRM_Warden_ExtensionUtil as E;

return [
  'type' => 'search',
  'title' => E::ts('Warden - Identity providers'),
  'icon' => 'fa-shield',
  'server_route' => 'civicrm/admin/warden/providers',
  'permission' => [
    'administer warden',
  ],
];
