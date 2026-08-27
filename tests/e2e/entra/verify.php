<?php

declare(strict_types = 1);

use Civi\Api4\Email;
use Civi\Api4\User;
use Civi\Api4\WardenAudit;
use Civi\Api4\WardenIdentity;
use Civi\Api4\WardenProvider;
use Civi\Warden\Users;

$provider = WardenProvider::get(FALSE)
  ->addWhere('name', '=', 'entra_e2e')
  ->execute()
  ->single();
$identity = WardenIdentity::get(FALSE)
  ->addWhere('provider_id', '=', $provider['id'])
  ->addWhere('subject', '=', 'entra-e2e-pairwise-subject')
  ->execute()
  ->single();
$user = User::get(FALSE)
  ->addSelect('contact_id')
  ->addWhere('id', '=', $identity['user_id'])
  ->execute()
  ->single();

if (!in_array('warden_entra_staff_e2e', Users::roleNames((int) $identity['user_id']), TRUE)) {
  throw new RuntimeException('Entra App Role was not mapped onto the CiviCRM role.');
}
if (Email::get(FALSE)->addWhere('contact_id', '=', $user['contact_id'])->execute()->count() !== 0) {
  throw new RuntimeException('An Entra email without email_verified was persisted as verified contact data.');
}
if (WardenAudit::get(FALSE)
  ->addWhere('provider_id', '=', $provider['id'])
  ->addWhere('event', '=', 'login_success')
  ->execute()
  ->count() !== 1) {
  throw new RuntimeException('The successful Entra login was not audited exactly once.');
}

echo "Entra identity, App Role mapping, unverified-email handling, and audit verified.\n";
