<?php

declare(strict_types = 1);

namespace Civi\Warden;

// @mago-expect lint:cyclomatic-complexity -- type narrowing is branch-heavy by definition
/**
 * Reading untyped values — APIv4 rows, decoded JSON, request parameters —
 * without lying about what came back.
 *
 * A bare cast yields "Array" on an array and "" on NULL, making a missing
 * column and an empty one indistinguishable where warden decides who gets in.
 */
final class Value {

  public static function str(mixed $value, string $default = ''): string {
    if (is_string($value)) {
      return $value;
    }

    return is_int($value) || is_float($value) ? (string) $value : $default;
  }

  /**
   * A string, or NULL when there is nothing usable — so callers can tell
   * "absent" from "empty".
   */
  public static function nullableStr(mixed $value): ?string {
    return is_string($value) && $value !== '' ? $value : NULL;
  }

  public static function int(mixed $value, int $default = 0): int {
    return is_numeric($value) ? (int) $value : $default;
  }

  public static function nullableInt(mixed $value): ?int {
    return is_numeric($value) ? (int) $value : NULL;
  }

  public static function bool(mixed $value, bool $default = FALSE): bool {
    if (is_bool($value)) {
      return $value;
    }
    if (is_numeric($value)) {
      return (bool) (int) $value;
    }
    if (is_string($value)) {
      return in_array(strtolower($value), ['1', 'true', 'yes', 'on'], TRUE);
    }

    return $default;
  }

  /**
   * @return array<string, mixed>
   */
  public static function row(mixed $value): array {
    if (!is_array($value)) {
      return [];
    }

    $out = [];
    /** @var mixed $item */
    foreach ($value as $key => $item) {
      $out[(string) $key] = $item;
    }

    return $out;
  }

  /**
   * @return list<string>
   */
  public static function strings(mixed $value): array {
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

  /**
   * @return list<int>
   */
  public static function ints(mixed $value): array {
    if (!is_array($value)) {
      return [];
    }

    $out = [];
    /** @var mixed $item */
    foreach ($value as $item) {
      if (!is_numeric($item)) {
        continue;
      }
      $out[] = (int) $item;
    }

    return array_values(array_unique($out));
  }

}
