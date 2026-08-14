<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Adapts CiviCRM's persistent cache to the cache contract used by the OIDC
 * client. The library owns cache keys and values; Warden owns the deployment
 * appropriate backend and TTL.
 */
final class OidcCache implements CacheInterface {

  /**
   * @param array<string, mixed>|null $metadata
   * @param-out array<string, mixed> $metadata
   */
  public function get(string $key, callable $callback, ?float $beta = NULL, ?array &$metadata = NULL): mixed {
    $ttl = Cache::ttl();
    $metadata = [ItemInterface::METADATA_EXPIRY => time() + $ttl];

    return Cache::remember(
      'oidc_' . hash('sha256', $key),
      $ttl,
      static function () use ($callback, $key): mixed {
        $save = TRUE;

        return $callback(new OidcCacheItem($key), $save);
      },
    );
  }

  public function delete(string $key): bool {
    Cache::forget('oidc_' . hash('sha256', $key));

    return TRUE;
  }

}
