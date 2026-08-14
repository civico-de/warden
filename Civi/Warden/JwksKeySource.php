<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;

/**
 * The provider's public keys, fetched from `jwks_uri` and cached.
 *
 * php-jwt ships a `CachedKeySet` that would do this, but it needs a PSR-6
 * `Psr\Cache\CacheItemPoolInterface` and CiviCRM does not install `psr/cache`
 * at all — only `psr/simple-cache` — so it cannot be constructed on a real
 * site. Hence our own, over `Civi\Warden\Cache`.
 */
final class JwksKeySource implements KeySource {

  /**
   * Within one request the key set is fetched at most once per force level, so
   * the validator's single retry cannot become a fetch per token.
   *
   * @var array<string, Key>|null
   */
  private ?array $memo = NULL;

  private bool $refreshedThisRequest = FALSE;

  public function __construct(
    private readonly Provider $provider,
    private readonly DiscoveryDocument $discovery,
  ) {}

  /**
   * @return array<string, Key>
   */
  public function keys(bool $forceRefresh = FALSE): array {
    if ($forceRefresh && !$this->refreshedThisRequest) {
      $this->refreshedThisRequest = TRUE;
      $this->memo = NULL;
      Cache::forget($this->cacheKey());
    }
    if ($this->memo !== NULL) {
      return $this->memo;
    }

    /** @var array<string, mixed> $raw */
    $raw = Cache::remember(
      $this->cacheKey(),
      Cache::ttl(),
      fn (): array => Http::json($this->discovery->jwksUri),
    );

    $this->memo = self::parse($raw);

    return $this->memo;
  }

  /**
   * @param array<string, mixed> $raw
   *
   * @return array<string, Key>
   *
   * @throws \CRM_Core_Exception
   */
  public static function parse(array $raw): array {
    try {
      // JWK::parseKeySet skips keys it cannot handle only when told to; by
      // default one unsupported curve in an otherwise fine key set throws and
      // takes every key down with it. Parse per key instead.
      $keys = [];
      /** @var mixed $jwk */
      foreach ((array) ($raw['keys'] ?? []) as $jwk) {
        if (!is_array($jwk)) {
          continue;
        }
        $kid = $jwk['kid'] ?? NULL;
        if (!is_string($kid) || $kid === '') {
          continue;
        }
        // Signature keys only. An encryption key that happens to share an
        // algorithm must never end up verifying an ID token.
        $use = $jwk['use'] ?? NULL;
        if (is_string($use) && $use !== 'sig') {
          continue;
        }
        try {
          /** @var array<string, Key> $parsed */
          $parsed = JWK::parseKeySet(['keys' => [$jwk]]);
          $keys += $parsed;
        }
        catch (\Throwable) {
          // One key warden's php-jwt cannot represent (P-521, an exotic OKP
          // curve) must not disable the others.
          continue;
        }
      }
    }
    catch (\Throwable $e) {
      throw new \CRM_Core_Exception('warden could not parse the provider key set: ' . $e->getMessage(), 0, $e);
    }

    if ($keys === []) {
      throw new \CRM_Core_Exception('warden: the provider key set contains no usable signing key');
    }

    return $keys;
  }

  public function cacheKey(): string {
    return 'jwks_' . $this->provider->id . '_' . substr(hash('sha256', $this->discovery->jwksUri), 0, 16);
  }

  /**
   * Seconds since the key set was last fetched, or NULL if never.
   */
  public function cacheAge(): ?int {
    $at = Cache::fetchedAt($this->cacheKey());

    return $at === NULL ? NULL : max(0, time() - $at);
  }

}
