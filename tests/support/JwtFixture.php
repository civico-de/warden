<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Support;

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

  /**
   * @var array<string, array{private: string, public: string}>|null */
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
  public static function sign(
    array $claims,
    string $alg = 'RS256',
    ?string $kid = self::KID,
    string $keyName = 'a',
  ): string {
    if ($alg !== 'RS256') {
      throw new \InvalidArgumentException('The test fixture only signs RS256 tokens.');
    }
    $header = ['alg' => $alg, 'typ' => 'JWT'];
    if ($kid !== NULL) {
      $header['kid'] = $kid;
    }
    $signingInput = self::b64($header) . '.' . self::b64($claims);
    if (!openssl_sign($signingInput, $signature, self::keyPair($keyName)['private'], OPENSSL_ALGO_SHA256)) {
      throw new \RuntimeException('could not sign the JWT fixture');
    }

    return $signingInput . '.' . self::b64String($signature);
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
   * @param array<string, mixed> $data
   */
  private static function b64(array $data): string {
    return self::b64String((string) json_encode($data));
  }

  private static function b64String(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

}
