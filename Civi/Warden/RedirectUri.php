<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * The `redirect_uri` registered with the provider.
 *
 * Built from `CRM_Utils_System::url(..., TRUE)`, which resolves against
 * `CIVICRM_UF_BASEURL` — never from `$_SERVER['HTTP_HOST']` or `REQUEST_URI`.
 *
 * Behind the civico edge proxy those request variables carry whatever the
 * proxy passed on, and an attacker who can set a Host header could otherwise
 * make warden send the provider a redirect_uri pointing somewhere else. The
 * provider's own allow-list is the backstop, but the value must be stable
 * anyway: it is compared byte for byte at the token endpoint, so a redirect_uri
 * that varies by request breaks the exchange even when nobody is attacking.
 */
final class RedirectUri {

  public const ROUTE = 'civicrm/warden/return';

  public static function get(): string {
    return \CRM_Utils_System::url(self::ROUTE, '', TRUE, NULL, FALSE, TRUE, TRUE);
  }

  /**
   * Does this site have a base URL that can produce a usable redirect_uri?
   *
   * Reported by StatusCheck, because "the provider says redirect_uri mismatch"
   * is otherwise a very long afternoon.
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
