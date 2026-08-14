<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\Contact;
use Civi\Api4\Role;
use Civi\Api4\User;

// @mago-expect lint:cyclomatic-complexity
// A thin, defensive facade over APIv4 User/Role writes.
/**
 * Everything warden does to `civicrm_uf_match` and `civicrm_user_role`.
 *
 * `checkPermissions(FALSE)` throughout, and not as a shortcut: APIv4's
 * `WriteTrait::validateValues()` requires a logged-in user, and warden is
 * writing these rows for an anonymous visitor who is in the middle of proving
 * who they are. There is no session yet by construction.
 */
final class Users {

  /**
   * Does this user hold this permission?
   *
   * Asked of Standalone's own Security service, which is the authority and
   * caches per user. `CRM_Core_Config::singleton()->userSystem` is NOT used:
   * only the Standalone UF class resolves a permission for an arbitrary user
   * id, and under `CIVICRM_UF=UnitTests` — the headless suite — it silently
   * answers for the current user instead. That difference is the whole
   * administrator escape hatch, so it may not depend on which UF class
   * happens to be loaded.
   *
   * The fallback resolves roles to permissions directly, so the answer stays
   * correct if the service ever moves.
   */
  public static function hasPermission(int $userId, string $permission): bool {
    // `standaloneusers.security` is the 6.15+ service; Security::singleton()
    // is deprecated there and is the only route on 6.14. Try the service
    // first so warden does not call a deprecated method on a modern site.
    try {
      $security = \Civi::container()->has('standaloneusers.security')
        ? \Civi::service('standaloneusers.security')
        : NULL;
      if (is_object($security) && method_exists($security, 'checkPermission')) {
        return (bool) $security->checkPermission($permission, $userId);
      }
    }
    catch (\Throwable $e) {
      \Civi::log()->warning('warden: standaloneusers.security could not answer, falling back: {msg}', [
        'msg' => $e->getMessage(),
      ]);
    }

    try {
      $roleIds = Value::ints(self::find($userId)['roles'] ?? NULL);
      if ($roleIds === []) {
        return FALSE;
      }

      $lists = Role::get(FALSE)
        ->addSelect('permissions')
        ->addWhere('id', 'IN', $roleIds)
        ->addWhere('is_active', '=', TRUE)
        ->execute()
        ->column('permissions');

      foreach ($lists as $list) {
        if (is_array($list) && in_array($permission, $list, TRUE)) {
          return TRUE;
        }
      }
    }
    catch (\Throwable) {
      return FALSE;
    }

    return FALSE;
  }

  /**
   * @return array<string, mixed>|null
   */
  public static function find(int $userId): ?array {
    $user = User::get(FALSE)
      ->addSelect('id', 'contact_id', 'username', 'uf_name', 'is_active', 'roles')
      ->addWhere('id', '=', $userId)
      ->execute()
      ->first();

    return is_array($user) ? Value::row($user) : NULL;
  }

  /**
   * Find a user by the username column, for the email-linking policy.
   *
   * Standalone keeps the login name in `username` and the contact address in
   * `uf_name`; a site provisioned from an IdP usually has the address in both,
   * so both are checked.
   *
   * @return array<string, mixed>|null
   */
  public static function findByEmail(string $email): ?array {
    if ($email === '') {
      return NULL;
    }

    $users = User::get(FALSE)
      ->addSelect('id', 'contact_id', 'username', 'uf_name', 'is_active', 'roles')
      ->addClause('OR', ['username', '=', $email], ['uf_name', '=', $email])
      ->execute();

    // Ambiguous is refused, not guessed: two accounts sharing an address is
    // exactly the situation where picking one silently is a takeover.
    $user = count($users) === 1 ? $users->first() : NULL;

    return is_array($user) ? Value::row($user) : NULL;
  }

  /**
   * Create a CiviCRM user and its contact.
   *
   * The password is random and is never shown to anybody. A provisioned account
   * has to be usable only through the identity provider; leaving the column
   * empty or predictable would make SSO provisioning a way to create
   * password-loginable accounts.
   *
   * @param list<string> $roleNames
   *
   * @return int
   *   The new user id.
   *
   * @throws \CRM_Core_Exception
   */
  public static function provision(string $username, ?string $email, ?string $displayName, array $roleNames): int {
    $contactId = self::createContact($displayName, $email);

    $create = User::create(FALSE)
      ->addValue('contact_id', $contactId)
      ->addValue('username', substr($username, 0, 60))
      ->addValue('password', Random::urlSafe(48))
      ->addValue('is_active', TRUE);

    if ($email !== NULL && $email !== '') {
      $create->addValue('uf_name', $email);
    }

    $roleIds = self::resolveRoleIds($roleNames);
    if ($roleIds !== []) {
      $create->addValue('roles', $roleIds);
    }

    $created = $create->execute()->first();
    $newId = is_array($created) ? Value::nullableInt($created['id'] ?? NULL) : NULL;
    if ($newId === NULL) {
      throw new \CRM_Core_Exception('warden: user creation returned no id');
    }

    return $newId;
  }

  /**
   * Replace a user's roles with exactly this set.
   *
   * @param list<string> $roleNames
   */
  public static function setRoles(int $userId, array $roleNames): void {
    User::update(FALSE)
      ->addWhere('id', '=', $userId)
      ->addValue('roles', self::resolveRoleIds($roleNames))
      ->execute();
  }

  /**
   * Role names a user currently holds.
   *
   * @return list<string>
   */
  public static function roleNames(int $userId): array {
    $user = self::find($userId);
    $roleIds = Value::ints($user['roles'] ?? NULL);
    if ($roleIds === []) {
      return [];
    }

    return Value::strings(
      Role::get(FALSE)
        ->addSelect('name')
        ->addWhere('id', 'IN', $roleIds)
        ->execute()
        ->column('name'),
    );
  }

  /**
   * Role ids for a list of names.
   *
   * Names that match nothing are dropped rather than created. warden mapping a
   * claim onto a role that does not exist is a configuration error an operator
   * has to see in the status check — it is not licence to invent a role, and
   * inventing one would mean the IdP decides what roles a site has.
   *
   * @param list<string> $names
   *
   * @return list<int>
   */
  public static function resolveRoleIds(array $names): array {
    if ($names === []) {
      return [];
    }

    return Value::ints(
      Role::get(FALSE)
        ->addSelect('id')
        ->addWhere('name', 'IN', $names)
        ->addWhere('is_active', '=', TRUE)
        ->execute()
        ->column('id'),
    );
  }

  /**
   * Role names that do not exist on this site.
   *
   * @param list<string> $names
   *
   * @return list<string>
   */
  public static function unknownRoleNames(array $names): array {
    if ($names === []) {
      return [];
    }

    $known = Value::strings(
      Role::get(FALSE)
        ->addSelect('name')
        ->addWhere('name', 'IN', $names)
        ->execute()
        ->column('name'),
    );

    return array_values(array_diff($names, $known));
  }

  /**
   * @throws \CRM_Core_Exception
   */
  private static function createContact(?string $displayName, ?string $email): int {
    $values = ['contact_type' => 'Individual'];
    if ($displayName !== NULL && $displayName !== '') {
      $values['display_name'] = substr($displayName, 0, 128);
      $values['first_name'] = substr($displayName, 0, 64);
    }

    $create = Contact::create(FALSE)->setValues($values);
    if ($email !== NULL && $email !== '') {
      $create->addChain('email', \Civi\Api4\Email::create(FALSE)
        ->addValue('contact_id', '$id')
        ->addValue('email', $email)
        ->addValue('is_primary', TRUE)
        ->addValue('location_type_id:name', 'Work'));
    }

    $contact = $create->execute()->first();
    $contactId = is_array($contact) ? Value::nullableInt($contact['id'] ?? NULL) : NULL;
    if ($contactId === NULL) {
      throw new \CRM_Core_Exception('warden: contact creation returned no id');
    }

    return $contactId;
  }

}
