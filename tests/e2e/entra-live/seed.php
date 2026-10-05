<?php

declare(strict_types = 1);

use Civi\Api4\Role;
use Civi\Api4\WardenProvider;
use Civi\Warden\Entra;

const WARDEN_ENTRA_LIVE_ROLE = 'warden_entra_staff_e2e';

$env = [];
foreach (['WARDEN_ENTRA_LIVE_TENANT', 'WARDEN_ENTRA_LIVE_CLIENT_ID', 'WARDEN_ENTRA_LIVE_CLIENT_SECRET'] as $name) {
  $value = getenv($name);
  if (!is_string($value) || $value === '') {
    throw new RuntimeException("{$name} is required (run.sh passes it from the Tofu outputs).");
  }
  $env[$name] = $value;
}

$role = Role::get(FALSE)
  ->addWhere('name', '=', WARDEN_ENTRA_LIVE_ROLE)
  ->execute()
  ->first();
if (!is_array($role)) {
  Role::create(FALSE)
    ->addValue('name', WARDEN_ENTRA_LIVE_ROLE)
    ->addValue('label', 'Warden Entra E2E staff')
    ->addValue('permissions', [])
    ->addValue('is_active', TRUE)
    ->execute();
}

$existing = WardenProvider::get(FALSE)
  ->addWhere('name', '=', 'entra_live')
  ->execute()
  ->first();

$values = [
  'name' => 'entra_live',
  'label' => 'Microsoft Entra ID (live)',
  'issuer' => Entra::issuer($env['WARDEN_ENTRA_LIVE_TENANT']),
  'client_id' => $env['WARDEN_ENTRA_LIVE_CLIENT_ID'],
  'client_secret' => $env['WARDEN_ENTRA_LIVE_CLIENT_SECRET'],
  'scopes' => 'openid profile email',
  'mode' => 'optional',
  'allowed_algorithms' => 'RS256',
  'claim_role_map' => json_encode([
    'claim' => Entra::ROLE_CLAIM,
    'map' => ['CiviCRM.Staff' => [WARDEN_ENTRA_LIVE_ROLE]],
  ]),
  'role_sync_mode' => 'every_login',
  'provision_policy' => 'provision',
  'link_policy' => 'never',
  'is_active' => TRUE,
  'weight' => 1,
];

if (!is_array($existing)) {
  WardenProvider::create(FALSE)->setValues($values)->execute();
}
if (is_array($existing)) {
  WardenProvider::update(FALSE)
    ->addWhere('id', '=', $existing['id'])
    ->setValues($values)
    ->execute();
}

Civi::settings()->set('warden_enabled', TRUE);
