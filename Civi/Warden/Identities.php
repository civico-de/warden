<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenIdentity;

/**
 * Everything warden does to `civicrm_warden_identity`: the (provider,
 * subject) → user links.
 */
final class Identities {

  /**
   * The existing link for this subject, if any.
   *
   * @return array<string, mixed>|null
   */
  public static function find(Provider $provider, string $subject): ?array {
    /** @var array<string, mixed>|null */
    return WardenIdentity::get(FALSE)
      ->addSelect('id', 'user_id')
      ->addWhere('provider_id', '=', $provider->id)
      ->addWhere('subject', '=', $subject)
      ->execute()
      ->first();
  }

  public static function link(Provider $provider, int $userId, string $subject): void {
    try {
      WardenIdentity::create(FALSE)
        ->addValue('provider_id', $provider->id)
        ->addValue('user_id', $userId)
        ->addValue('subject', $subject)
        ->addValue('last_login_date', 'now')
        ->addValue('login_count', 1)
        ->execute();
    }
    catch (\Throwable $e) {
      // The unique index is the real enforcement against two simultaneous first logins.
      Audit::record(
        Options::EVENT_RELINK_REFUSED,
        $provider,
        $userId,
        'link_conflict',
        'unique index refused the link',
        $subject,
      );

      throw new \CRM_Core_Exception(
        'This identity could not be linked to an account. Ask an administrator to check the warden log.',
        0,
        [],
        $e,
      );
    }
  }

  public static function touch(int $identityId): void {
    try {
      // ckconform-ignore raw-sql -- atomic read-modify-write of a counter
      \CRM_Core_DAO::executeQuery(
        'UPDATE civicrm_warden_identity SET last_login_date = NOW(), login_count = login_count + 1 WHERE id = %1',
        [1 => [$identityId, 'Integer']],
      );
    }
    catch (\Throwable $e) {
      // Error, not warning: a database write is failing.
      \Civi::log()->error('warden: could not update identity {id}: {msg}', [
        'id' => $identityId,
        'msg' => $e->getMessage(),
      ]);
    }
  }

  /**
   * Whether this user is already bound to some subject at this provider.
   */
  public static function isBound(Provider $provider, int $userId): bool {
    return WardenIdentity::get(FALSE)
      ->addSelect('subject')
      ->addWhere('provider_id', '=', $provider->id)
      ->addWhere('user_id', '=', $userId)
      ->execute()
      ->first() !== NULL;
  }

}
