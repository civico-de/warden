<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Support;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Crafted ID tokens for the adversarial validator tests.
 *
 * Real RSA keys, generated once per process, so a "wrong signature" fixture is
 * genuinely signed by the wrong key rather than corrupted bytes — corrupting
 * bytes tests the parser, signing with the wrong key tests the verifier.
 *
 * No network, no fixtures on disk, no CiviCRM.
 */
final class JwtFixture {

  public const ISSUER = 'https://id.example.org/realms/main';
  public const CLIENT_ID = 'civicrm-warden';
  public const KID = 'key-1';
  public const OTHER_KID = 'key-2';

  /** @var array<string, array{private: string, public: string}>|null */
  private static ?array $keys = NULL;

  /**
   * @return array{private: string, public: string}
   */
  public static function keyPair(string $name = 'a'): array {
    self::$keys ??= [];
    if (!isset(self::$keys[$name])) {
      $resource = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
      ]);
      if ($resource === FALSE) {
        throw new \RuntimeException('could not generate an RSA key: ' . (string) openssl_error_string());
      }
      openssl_pkey_export($resource, $private);
      $details = openssl_pkey_get_details($resource);
      if (!is_array($details) || !is_string($details['key'] ?? NULL)) {
        throw new \RuntimeException('could not export the generated public key');
      }
      self::$keys[$name] = ['private' => (string) $private, 'public' => $details['key']];
    }

    return self::$keys[$name];
  }

  /**
   * The key set the validator sees: the correct key under KID, a second,
   * unrelated key under OTHER_KID.
   *
   * @return array<string, Key>
   */
  public static function keySet(): array {
    return [
      self::KID => new Key(self::keyPair('a')['public'], 'RS256'),
      self::OTHER_KID => new Key(self::keyPair('b')['public'], 'RS256'),
    ];
  }

  /**
   * A valid set of claims, which each test then breaks in exactly one way.
   *
   * @return array<string, mixed>
   */
  public static function claims(int $now, string $nonce): array {
    return [
      'iss' => self::ISSUER,
      'sub' => 'subject-0001',
      'aud' => self::CLIENT_ID,
      'exp' => $now + 300,
      'iat' => $now - 5,
      'nonce' => $nonce,
      'email' => 'someone@example.org',
      'email_verified' => TRUE,
      'preferred_username' => 'someone',
      'name' => 'Some One',
      'realm_access' => ['roles' => ['crm-staff', 'unrelated']],
    ];
  }

  /**
   * Sign a token.
   *
   * @param array<string, mixed> $claims
   * @param string $keyName
   *   Which generated key pair signs it — 'a' is the one KID publishes.
   */
  public static function sign(array $claims, string $alg = 'RS256', ?string $kid = self::KID, string $keyName = 'a'): string {
    return JWT::encode($claims, self::keyPair($keyName)['private'], $alg, $kid);
  }

  /**
   * An `alg: none` token, which php-jwt cannot be made to produce — so it is
   * assembled by hand, exactly as an attacker would.
   *
   * @param array<string, mixed> $claims
   */
  public static function unsigned(array $claims): string {
    $header = self::b64(['alg' => 'none', 'typ' => 'JWT', 'kid' => self::KID]);
    $payload = self::b64($claims);

    // A trailing dot with an empty signature is the canonical shape; warden
    // rejects the empty third segment as malformed before it ever reads `alg`,
    // so the fixture carries a junk signature to make sure the `alg` branch is
    // the one under test.
    return $header . '.' . $payload . '.' . rtrim(strtr(base64_encode('not-a-signature'), '+/', '-_'), '=');
  }

  /**
   * A token with an algorithm outside the allow-list but otherwise well formed.
   *
   * @param array<string, mixed> $claims
   */
  public static function hmac(array $claims, string $alg = 'HS256'): string {
    return JWT::encode($claims, 'shared-secret-shared-secret-1234', $alg, self::KID);
  }

  /**
   * @param array<string, mixed> $data
   */
  private static function b64(array $data): string {
    return rtrim(strtr(base64_encode((string) json_encode($data)), '+/', '-_'), '=');
  }

}
