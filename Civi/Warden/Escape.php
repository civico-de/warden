<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * The lock-out escape hatch.
 *
 * Every mechanism warden has for denying password login is enforced by warden
 * itself, which means a misconfigured provider plus a strict mode is a locked
 * door with the key inside. Three ways back in, in order of how much access
 * they need:
 *
 * 1. `define('CIVICRM_WARDEN_DISABLE', TRUE);` in civicrm.settings.php. Needs
 *    filesystem access, takes effect on the next request, and cannot be undone
 *    from the UI — so an attacker who compromises an admin session cannot turn
 *    it off, and an operator who has lost their admin session can still get in.
 * 2. The `warden_enabled` setting, for an administrator who still has a session.
 * 3. `cv ext:disable warden`, which removes the listeners entirely.
 *
 * On top of those, `warden_protect_admin_password_login` (on by default) keeps
 * password login and password reset working for holders of
 * `administer CiviCRM` even in `required` mode.
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

    return \Civi::settings()->get('warden_enabled') === FALSE;
  }

  public static function disabledByConstant(): bool {
    return (bool) \CRM_Utils_Constant::value(self::CONSTANT);
  }

  /**
   * May this user still use a password, whatever a provider's mode says?
   *
   * Answered for a specific user id because the events that need it fire
   * before there is a session — `pre_credentials_check` knows only which
   * account is being attempted.
   */
  public static function passwordLoginProtected(?int $userId): bool {
    if (\Civi::settings()->get('warden_protect_admin_password_login') === FALSE) {
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
