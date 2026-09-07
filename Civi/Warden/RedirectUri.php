<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * The `redirect_uri` registered with the provider.
 *
 * Built from `CIVICRM_UF_BASEURL`, never from `$_SERVER['HTTP_HOST']`: a
 * Host header must not steer it, and the token endpoint compares it byte for byte.
 */
final class RedirectUri {

  public const ROUTE = 'civicrm/warden/return';

  public static function get(): string {
    return \CRM_Utils_System::url(self::ROUTE, '', TRUE, NULL, FALSE, TRUE, TRUE);
  }

  /**
   * Does this site have a base URL that can produce a usable redirect_uri?
   */
  public static function looksResolvable(): bool {
    $uri = self::get();

    return (
      str_starts_with($uri, 'https://')
      && !str_contains($uri, 'localhost')
      && filter_var($uri, FILTER_VALIDATE_URL) !== FALSE
    );
  }

}
