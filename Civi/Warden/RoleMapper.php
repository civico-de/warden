<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Turning claim values into CiviCRM role names.
 *
 * The map is an ALLOW-LIST keyed by claim value, so the IdP cannot name a
 * CiviCRM permission and be believed, and its right-hand side is a role NAME,
 * never a permission string. Pure; resolving names to ids is the caller's job.
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
    if (DistributedClaims::unavailable($claims, $provider->roleClaim)) {
      throw new RoleClaimUnavailableException(sprintf(
        'The configured role claim "%s" is not present in this token because the provider returned an overage marker.',
        $provider->roleClaim,
      ));
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
   * Every role name the map could ever produce: the scope `every_login` sync
   * may touch. A hand-granted role outside it is never removed.
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
