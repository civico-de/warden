<?php

declare(strict_types = 1);

use Civi\Api4\Role;
use Civi\Api4\WardenProvider;
use Civi\Warden\Entra;

const WARDEN_ENTRA_E2E_TENANT = 'a0b1c2d3-1234-4567-89ab-0123456789cd';

const WARDEN_ENTRA_E2E_ROLE = 'warden_entra_staff_e2e';

$role = Role::get(FALSE)
  ->addWhere('name', '=', WARDEN_ENTRA_E2E_ROLE)
  ->execute()
  ->first();
if (!is_array($role)) {
  Role::create(FALSE)
    ->addValue('name', WARDEN_ENTRA_E2E_ROLE)
    ->addValue('label', 'Warden Entra E2E staff')
    ->addValue('permissions', [])
    ->addValue('is_active', TRUE)
    ->execute();
}

$existing = WardenProvider::get(FALSE)
  ->addWhere('name', '=', 'entra_e2e')
  ->execute()
  ->first();

$values = [
  'name' => 'entra_e2e',
  'label' => 'Microsoft Entra ID',
  'issuer' => Entra::issuer(WARDEN_ENTRA_E2E_TENANT),
  'client_id' => '11112222-bbbb-3333-cccc-4444dddd5555',
  // Fixed credential for this disposable, isolated protocol fixture only.
  // @mago-expect lint:no-literal-password
  'client_secret' => 'entra-e2e-secret',
  'scopes' => 'openid profile email',
  'mode' => 'optional',
  'allowed_algorithms' => 'RS256',
  'claim_role_map' => json_encode([
    'claim' => Entra::ROLE_CLAIM,
    'map' => ['CiviCRM.Staff' => [WARDEN_ENTRA_E2E_ROLE]],
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
