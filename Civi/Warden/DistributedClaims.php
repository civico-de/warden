<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Provider markers for a claim deliberately omitted from the ID token.
 */
final class DistributedClaims {

  /**
   * Entra group overage uses `_claim_names.groups`, while some flows use
   * `hasgroups` without returning `groups`. Warden deliberately does not
   * follow distributed-claim URLs or call provider APIs with a login token.
   *
   * @param array<string, mixed> $claims
   */
  public static function unavailable(array $claims, string $path): bool {
    if ($path === '' || str_contains($path, '.')) {
      return FALSE;
    }
    $distributed = Claims::path($claims, '_claim_names.' . $path);
    if (is_string($distributed) && $distributed !== '') {
      return TRUE;
    }

    return $path === 'groups' && !array_key_exists('groups', $claims) && ($claims['hasgroups'] ?? NULL) === TRUE;
  }

}
