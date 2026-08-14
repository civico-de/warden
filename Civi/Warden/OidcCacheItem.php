<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Symfony\Contracts\Cache\ItemInterface;

/**
 * Cache-miss item passed to digitalcz so it can declare its desired expiry.
 * Warden intentionally clamps that expiry through Cache::ttl().
 *
 * @internal
 */
final class OidcCacheItem implements ItemInterface {

  private mixed $value = NULL;

  public function __construct(
    private readonly string $key,
  ) {}

  public function getKey(): string {
    return $this->key;
  }

  public function get(): mixed {
    return $this->value;
  }

  public function isHit(): bool {
    return FALSE;
  }

  public function set(mixed $value): static {
    $this->value = $value;

    return $this;
  }

  public function expiresAt(?\DateTimeInterface $expiration): static {
    return $this;
  }

  public function expiresAfter(\DateInterval|int|null $time): static {
    return $this;
  }

  public function tag(string|iterable $tags): static {
    return $this;
  }

  /**
   * @return array<string, mixed>
   */
  public function getMetadata(): array {
    return [];
  }

}
