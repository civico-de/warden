<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * PKCE (RFC 7636) with S256 only.
 *
 * `plain` is not implemented and is not an option: it protects against nothing
 * an attacker who can read the authorization request cannot already do.
 */
final class Pkce {

  public const METHOD = 'S256';

  /**
   * A code verifier: 43 characters of base64url, the RFC minimum, from 256
   * bits of entropy.
   */
  public static function verifier(): string {
    return Random::urlSafe(32);
  }

  /**
   * The challenge derived from a verifier: base64url(SHA256(verifier)),
   * unpadded, over the ASCII bytes of the verifier.
   */
  public static function challenge(string $verifier): string {
    return rtrim(strtr(base64_encode(hash('sha256', $verifier, TRUE)), '+/', '-_'), '=');
  }

}
