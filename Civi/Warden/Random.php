<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * One place that produces unguessable strings, so state, nonce and PKCE
 * verifiers cannot drift apart in entropy or encoding.
 */
final class Random {

  /**
   * Base64url without padding — safe in a query string, a JSON body and a
   * database column alike.
   *
   * @param int $bytes
   *   Entropy in bytes, not output length. 32 gives 256 bits and a 43-char
   *   string, which is exactly the PKCE minimum verifier length.
   */
  public static function urlSafe(int $bytes = 32): string {
    return rtrim(strtr(base64_encode(random_bytes(max(16, $bytes))), '+/', '-_'), '=');
  }

}
