<?php

declare(strict_types = 1);

namespace Civi\Warden;

use DigitalCz\OpenIDConnect\Discovery\CachingJwksLoader;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Util\JWT;

/**
 * Adds one controlled unknown-kid refresh to digitalcz's cached JWKS loader.
 *
 * Providers normally publish old and new keys during rollover, but Warden must
 * also recover when a new signing key appears before the configured cache TTL.
 * A refresh budget prevents arbitrary public logout tokens from turning every
 * invented kid into an outbound request.
 */
final class RefreshableJwksLoader implements JwksLoader {

  private readonly CachingJwksLoader $cached;

  public function __construct(
    JwksLoader $inner,
    private readonly OidcCache $cache,
    int $ttl,
    #[\SensitiveParameter]
    private readonly string $cacheSecret,
  ) {
    $this->cached = new CachingJwksLoader($inner, $cache, $ttl, $cacheSecret);
  }

  /**
   * @return array<string, mixed>
   */
  public function load(string $jwksUri): array {
    $keys = $this->cached->load($jwksUri);

    return Value::row($keys);
  }

  /**
   * Refresh exactly once when the presented token names a kid absent from the
   * cached set. Returns FALSE for known/missing/non-string kids and while the
   * short per-URI refresh budget is already consumed.
   */
  public function refreshForUnknownKid(string $jwksUri, string $jwt): bool {
    $kid = JWT::header($jwt)['kid'] ?? NULL;
    if (!is_string($kid) || $kid === '') {
      return FALSE;
    }

    $jwks = $this->load($jwksUri);
    $keys = $jwks['keys'] ?? NULL;
    if (!is_array($keys)) {
      return FALSE;
    }
    foreach ($keys as $key) {
      if (is_array($key) && is_string($key['kid'] ?? NULL) && hash_equals($key['kid'], $kid)) {
        return FALSE;
      }
    }

    $budgetKey = 'jwks_refresh_' . hash_hmac('sha256', $jwksUri, $this->cacheSecret);
    if (!Cache::claim($budgetKey, Cache::FAILURE_TTL)) {
      return FALSE;
    }

    $this->cache->delete($this->libraryCacheKey($jwksUri));
    $this->load($jwksUri);

    return TRUE;
  }

  private function libraryCacheKey(string $jwksUri): string {
    return 'oidc_jwks_' . hash_hmac('sha256', $jwksUri, $this->cacheSecret);
  }

}
