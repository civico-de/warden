<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * The lock-out escape hatch.
 *
 * A misconfigured provider plus a strict mode is a locked door with the key
 * inside. Three ways back in: `define('CIVICRM_WARDEN_DISABLE', TRUE)` in
 * civicrm.settings.php (filesystem only, not undoable from the UI), the
 * `warden_enabled` setting, and `cv ext:disable warden`. Additionally
 * `warden_protect_admin_password_login` keeps password login for `administer CiviCRM`.
 */
final class Escape {

  public const CONSTANT = 'CIVICRM_WARDEN_DISABLE';

  /**
   * Is warden switched off entirely?
   */
  public static function disabled(): bool {
    if (self::disabledByConstant()) {
      return TRUE;
    }

    return !Value::bool(\Civi::settings()->get('warden_enabled'), TRUE);
  }

  public static function disabledByConstant(): bool {
    return (bool) \CRM_Utils_Constant::value(self::CONSTANT);
  }

  /**
   * May this user still use a password, whatever a provider's mode says?
   * By user id: the events that need it fire before there is a session.
   */
  public static function passwordLoginProtected(?int $userId): bool {
    if (!Value::bool(\Civi::settings()->get('warden_protect_admin_password_login'), TRUE)) {
      return FALSE;
    }
    if ($userId === NULL) {
      // No user resolved: nothing to protect, and answering TRUE would make
      // `required` mode ineffective against username guessing.
      return FALSE;
    }

    return Users::hasPermission($userId, 'administer CiviCRM');
  }

}
