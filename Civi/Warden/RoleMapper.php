<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Turning claim values into CiviCRM role names.
 *
 * Two rules make this safe, and both are here rather than at the call site:
 *
 * 1. The map is an ALLOW-LIST keyed by claim value. A claim carrying
 *    `administer CiviCRM` grants nothing unless an operator wrote that exact
 *    string on the left-hand side and chose what it means on the right — so
 *    the IdP cannot name a CiviCRM permission and be believed.
 * 2. The right-hand side is a role NAME, never a permission string. Roles are
 *    a CiviCRM-side object an operator curates; permissions are not. Standalone
 *    also silently drops permission strings that no extension registered via
 *    hook_civicrm_permission on role save, so a permission arriving this way
 *    would not even fail loudly — it would just quietly not happen.
 *
 * Pure: no API calls, no database. Resolving names to ids is the caller's job.
 */
final class RoleMapper {

  /**
   * Role names granted by a token, according to a provider's map.
   *
   * @param array<string, mixed> $claims
   *
   * @return list<string>
   */
  public static function rolesFor(Provider $provider, array $claims): array {
    if ($provider->roleClaim === '' || $provider->roleMap === []) {
      return [];
    }

    $granted = [];
    foreach (Claims::stringList($claims, $provider->roleClaim) as $value) {
      foreach ($provider->roleMap[$value] ?? [] as $role) {
        $granted[$role] = TRUE;
      }
    }

    return array_keys($granted);
  }

  /**
   * Every role name the map could ever produce.
   *
   * This is the scope `every_login` sync is allowed to touch. A role outside it
   * — one an administrator granted by hand — is never removed, because the IdP
   * was never given authority over it.
   *
   * @return list<string>
   */
  public static function managedRoles(Provider $provider): array {
    $all = [];
    foreach ($provider->roleMap as $roles) {
      foreach ($roles as $role) {
        $all[$role] = TRUE;
      }
    }

    return array_keys($all);
  }

  /**
   * The roles a user should hold after a sync.
   *
   * @param list<string> $current
   *   Role names the user holds now.
   * @param list<string> $granted
   *   Role names the token grants.
   *
   * @return list<string>
   */
  public static function apply(Provider $provider, array $current, array $granted): array {
    if ($provider->roleSyncMode === Options::ROLE_SYNC_OFF) {
      return array_values(array_unique($current));
    }

    if ($provider->roleSyncMode !== Options::ROLE_SYNC_EVERY_LOGIN) {
      // provision_only: additive, and only at provisioning time. The caller
      // decides whether to call at all; if it does, nothing is taken away.
      return array_values(array_unique([...$current, ...$granted]));
    }

    $managed = self::managedRoles($provider);
    $kept = array_filter($current, static fn (string $r): bool => !in_array($r, $managed, TRUE));

    return array_values(array_unique([...$kept, ...$granted]));
  }

}
