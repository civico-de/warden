<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\Contact;
use Civi\Api4\Email;

/**
 * Keeping a contact's name and primary email in line with the provider.
 *
 * The name claims are copied as they are; the `email` claim only while the
 * provider asserts email_verified. Warden itself never writes the login
 * address (`uf_name`); core's `syncCMSEmail` setting decides whether a new
 * primary email moves it, and skips an address another user already holds.
 */
final class ProfileSync {

  /**
   * @throws \CRM_Core_Exception
   *   With a message safe to show a visitor.
   */
  public static function onLogin(Provider $provider, int $userId, IdTokenClaims $claims): void {
    if ($provider->profileSyncMode !== Options::PROFILE_SYNC_EVERY_LOGIN) {
      return;
    }
    [$email, $emailVerified] = $claims->email();

    try {
      self::apply($userId, $claims->nameFields(), $emailVerified ? $email : NULL);
    }
    catch (\Throwable $e) {
      \Civi::log()->error('warden: profile sync failed for user {id}: {msg}', [
        'id' => $userId,
        'msg' => $e->getMessage(),
      ]);
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        $userId,
        'profile_sync_failed',
        substr($e->getMessage(), 0, 200),
      );

      throw new \CRM_Core_Exception(
        'Your profile could not be updated from the identity provider. Access was refused; ask an administrator to check the warden log.',
        0,
        [],
        $e,
      );
    }
  }

  /**
   * Write what differs; an empty name map or a NULL email leaves that part alone.
   *
   * @param array{first_name?: string, last_name?: string} $name
   *
   * @throws \CRM_Core_Exception
   */
  public static function apply(int $userId, array $name, ?string $email): void {
    $user = Users::find($userId);
    if ($user === NULL) {
      return;
    }
    $contactId = Value::int($user['contact_id'] ?? NULL);

    if ($name !== []) {
      self::setName($contactId, $name);
    }
    if ($email !== NULL && $email !== '') {
      self::setPrimaryEmail($contactId, $email);
    }
  }

  /**
   * @param array{first_name?: string, last_name?: string} $name
   *
   * @throws \CRM_Core_Exception
   */
  private static function setName(int $contactId, array $name): void {
    $current = Contact::get(FALSE)
      ->addSelect('first_name', 'last_name')
      ->addWhere('id', '=', $contactId)
      ->execute()
      ->first();
    if (!is_array($current)) {
      return;
    }
    $changed = array_filter(
      $name,
      static fn (string $value, string $field): bool => ($current[$field] ?? NULL) !== $value,
      ARRAY_FILTER_USE_BOTH,
    );
    if ($changed === []) {
      return;
    }

    Contact::update(FALSE)
      ->addWhere('id', '=', $contactId)
      ->setValues($changed)
      ->execute();
  }

  /**
   * Make this address the contact's primary email: promote the row that
   * already holds it, or add one. The previous primary stays as a secondary
   * address, with its own bounce state.
   *
   * @throws \CRM_Core_Exception
   */
  private static function setPrimaryEmail(int $contactId, string $email): void {
    $existing = Email::get(FALSE)
      ->addSelect('id', 'is_primary')
      ->addWhere('contact_id', '=', $contactId)
      ->addWhere('email', '=', $email)
      ->addOrderBy('is_primary', 'DESC')
      ->execute()
      ->first();

    if (!is_array($existing)) {
      // Core demotes the previous primary when a new primary row is written.
      Email::create(FALSE)
        ->addValue('contact_id', $contactId)
        ->addValue('email', $email)
        ->addValue('is_primary', TRUE)
        ->addValue('location_type_id:name', 'Work')
        ->execute();

      return;
    }
    if (Value::bool($existing['is_primary'] ?? NULL)) {
      return;
    }
    Email::update(FALSE)
      ->addWhere('id', '=', Value::int($existing['id'] ?? NULL))
      ->addValue('is_primary', TRUE)
      ->execute();
  }

}
