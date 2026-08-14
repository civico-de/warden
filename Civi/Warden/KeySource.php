<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Where the validator gets verification keys from.
 *
 * An interface rather than a concrete JWKS client so the validator has no
 * network dependency and the adversarial tests can hand it crafted keys.
 */
interface KeySource {

  /**
   * @param bool $forceRefresh
   *   TRUE bypasses the cache. The validator sets it exactly once, when a
   *   `kid` is unknown, so a key rollover heals on the first login that needs
   *   the new key — and an attacker cannot turn unknown `kid` values into an
   *   unbounded stream of outbound fetches.
   *
   * @return array<string, \Firebase\JWT\Key>
   *   Keyed by `kid`.
   */
  // @mago-expect lint:no-boolean-flag-parameter
  // Two methods would let a caller refresh without meaning to; one flag keeps
  // the single-retry rule enforceable in the validator.
  public function keys(bool $forceRefresh = FALSE): array;

}
