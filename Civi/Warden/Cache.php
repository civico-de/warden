<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * TTL cache for discovery documents and key sets, on top of CiviCRM's own
 * cache service.
 *
 * The asymmetry is the point: a SUCCESSFUL fetch is cached for the configured
 * lifetime, a FAILED one for 60 seconds. Caching a failure for the full
 * lifetime would turn a thirty-second provider outage into fifteen minutes of
 * refused logins, and caching it forever — the mistake this class exists to
 * make impossible — would mean a provider that came back never worked again
 * until someone cleared a cache they did not know about.
 */
final class Cache {

  public const FAILURE_TTL = 60;

  private const GROUP = 'warden';

  /**
   * @template T
   *
   * @param callable(): T $fetch
   *
   * @return T
   *
   * @throws \Throwable
   *   Whatever $fetch threw, after the failure has been recorded.
   */
  public static function remember(string $key, int $ttl, callable $fetch): mixed {
    $cache = \CRM_Utils_Cache::create(['name' => self::GROUP, 'type' => ['*memory*', 'SqlGroup', 'ArrayCache']]);

    /** @var array{ok: bool, value?: mixed, error?: string}|null $entry */
    $entry = $cache->get($key);
    if (is_array($entry) && ($entry['ok'] ?? FALSE) === TRUE && array_key_exists('value', $entry)) {
      /** @var T */
      return $entry['value'];
    }
    if (is_array($entry) && ($entry['ok'] ?? TRUE) === FALSE) {
      throw new \CRM_Core_Exception(sprintf(
        'warden: %s is still failing (cached): %s',
        $key,
        is_string($entry['error'] ?? NULL) ? $entry['error'] : 'unknown error',
      ));
    }

    try {
      $value = $fetch();
    }
    catch (\Throwable $e) {
      $cache->set($key, ['ok' => FALSE, 'error' => $e->getMessage()], self::FAILURE_TTL);
      throw $e;
    }

    $cache->set($key, ['ok' => TRUE, 'value' => $value], max(60, $ttl));
    // Recorded separately from the payload so a health check can report cache
    // age without deserialising or refreshing the entry itself.
    $cache->set($key . ':fetched', time(), max(60, $ttl) * 4);

    return $value;
  }

  /**
   * When was this key last fetched successfully? NULL if never, or long enough
   * ago that even the timestamp expired.
   */
  public static function fetchedAt(string $key): ?int {
    $cache = \CRM_Utils_Cache::create(['name' => self::GROUP, 'type' => ['*memory*', 'SqlGroup', 'ArrayCache']]);
    $value = $cache->get($key . ':fetched');

    return is_int($value) ? $value : NULL;
  }

  public static function forget(string $key): void {
    $cache = \CRM_Utils_Cache::create(['name' => self::GROUP, 'type' => ['*memory*', 'SqlGroup', 'ArrayCache']]);
    $cache->delete($key);
  }

  /**
   * The configured lifetime, clamped. A five-minute floor keeps a busy site
   * from hammering the provider; a one-hour ceiling bounds how long a revoked
   * key stays trusted.
   */
  public static function ttl(): int {
    $configured = \Civi::settings()->get('warden_discovery_ttl');

    return max(300, min(3600, is_numeric($configured) ? (int) $configured : 900));
  }

}
