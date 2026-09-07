<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenAudit;

/**
 * A brake on the callback route.
 *
 * Standalone has no login flood control, and every attempt costs an outbound
 * token-endpoint request. Counts FAILURES per source address, read from the
 * audit table itself, so a busy office is never throttled.
 */
final class RateLimiter {

  /**
   * @return bool
   *   TRUE when the request may proceed.
   */
  public static function allow(?string $ip = NULL): bool {
    $limit = self::limit();
    if ($limit <= 0) {
      return TRUE;
    }

    $ip ??= Audit::clientIp();
    if ($ip === NULL) {
      // Failing open: the alternative locks out a site whose proxy hides client addresses.
      return TRUE;
    }

    $since = (new \DateTimeImmutable('-' . self::window() . ' seconds'))->format('Y-m-d H:i:s');

    try {
      $recent = WardenAudit::get(FALSE)
        ->selectRowCount()
        ->addWhere('source_ip', '=', $ip)
        ->addWhere('created_date', '>=', $since)
        ->addWhere(
          'event',
          'IN',
          [
            Options::EVENT_LOGIN_FAILURE,
            Options::EVENT_LOGIN_DENIED,
            Options::EVENT_RELINK_REFUSED,
          ],
        )
        ->execute()
        ->count();
    }
    catch (\Throwable $e) {
      \Civi::log()->error('warden: rate-limit query failed, allowing the request: {msg}', ['msg' => $e->getMessage()]);

      return TRUE;
    }

    return $recent < $limit;
  }

  public static function limit(): int {
    $configured = \Civi::settings()->get('warden_rate_limit_attempts');

    return max(0, is_numeric($configured) ? (int) $configured : 20);
  }

  public static function window(): int {
    $configured = \Civi::settings()->get('warden_rate_limit_window');

    return max(30, min(3600, is_numeric($configured) ? (int) $configured : 300));
  }

}
