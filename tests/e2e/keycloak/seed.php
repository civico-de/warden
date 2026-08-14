<?php

declare(strict_types = 1);

use Civi\Api4\WardenProvider;

$existing = WardenProvider::get(FALSE)
  ->addWhere('name', '=', 'keycloak_e2e')
  ->execute()
  ->first();

$values = [
  'name' => 'keycloak_e2e',
  'label' => 'Keycloak E2E',
  'issuer' => 'https://keycloak:8443/realms/warden-e2e',
  'client_id' => 'warden-e2e',
  // Fixed credential for the disposable, isolated E2E realm only.
  // @mago-expect lint:no-literal-password
  'client_secret' => 'warden-e2e-secret',
  'scopes' => 'openid profile email',
  'mode' => 'optional',
  'allowed_algorithms' => 'RS256',
  'role_sync_mode' => 'off',
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
