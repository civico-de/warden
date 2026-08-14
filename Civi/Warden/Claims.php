<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Reading values out of a decoded token payload. Pure, and deliberately
 * unforgiving: a path that does not resolve returns NULL rather than an empty
 * array, so "the claim was absent" and "the claim was an empty list" stay
 * distinguishable at the call site.
 */
final class Claims {

  /**
   * @param array<string, mixed> $claims
   */
  public static function path(array $claims, string $path): mixed {
    if ($path === '') {
      return NULL;
    }

    return self::descend($claims, explode('.', $path));
  }

  /**
   * @param array<string, mixed> $claims
   * @param list<string> $segments
   */
  private static function descend(array $claims, array $segments): mixed {
    $cursor = self::wrap($claims);
    foreach ($segments as $segment) {
      if (!is_array($cursor) || !array_key_exists($segment, $cursor)) {
        return NULL;
      }
      $cursor = self::wrap($cursor[$segment]);
    }

    return $cursor;
  }

  /**
   * Identity, typed as mixed. The descent variable has to start out mixed or
   * its first assignment pins it to array and every later one is a type error.
   */
  private static function wrap(mixed $value): mixed {
    return $value;
  }

  /**
   * A claim read as a list of strings.
   *
   * Providers are inconsistent here: Keycloak sends an array, Entra ID sends
   * an array, some send a single string, and some send a space-separated
   * string. All three shapes mean the same thing to a role mapper.
   *
   * @param array<string, mixed> $claims
   *
   * @return list<string>
   */
  public static function stringList(array $claims, string $path): array {
    /** @var mixed $value */
    $value = self::path($claims, $path);

    if (is_string($value)) {
      $parts = preg_split('/\s+/', trim($value)) ?: [];

      return array_values(array_filter($parts, static fn (string $p): bool => $p !== ''));
    }

    if (!is_array($value)) {
      return [];
    }

    $out = [];
    /** @var mixed $item */
    foreach ($value as $item) {
      if (!is_string($item) || $item === '') {
        continue;
      }
      $out[] = $item;
    }

    return array_values(array_unique($out));
  }

}
