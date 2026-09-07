<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenAudit;

/**
 * warden's login trail.
 *
 * Core Standalone writes no login trail. NEVER written here: tokens, codes,
 * email addresses, display names or a raw `sub`; the subject is a salted digest.
 */
final class Audit {

  // @mago-expect lint:excessive-parameter-list -- six independent facts, no sub-grouping
  public static function record(
    string $event,
    ?Provider $provider = NULL,
    ?int $userId = NULL,
    ?string $reason = NULL,
    ?string $detail = NULL,
    ?string $subject = NULL,
  ): void {
    try {
      WardenAudit::create(FALSE)
        ->addValue('event', $event)
        ->addValue('provider_id', $provider?->id)
        ->addValue('provider_name', $provider?->name)
        ->addValue('user_id', $userId)
        ->addValue('subject_hash', $subject === NULL ? NULL : self::hashSubject($subject))
        ->addValue('reason', $reason === NULL ? NULL : substr($reason, 0, 64))
        ->addValue('detail', $detail === NULL ? NULL : substr($detail, 0, 255))
        ->addValue('source_ip', self::clientIp())
        ->execute();
    }
    catch (\Throwable $e) {
      // Must not become a login failure, must not be silent either.
      \Civi::log()->error('warden: could not write an audit record ({event}): {msg}', [
        'event' => $event,
        'msg' => $e->getMessage(),
      ]);
    }
  }

  /**
   * Salted with the site key: differs per site, and a dump of this table
   * alone cannot be attacked with a precomputed table.
   */
  public static function hashSubject(string $subject): string {
    $salt = Value::str(\CRM_Utils_Constant::value('CIVICRM_SITE_KEY'));

    return hash('sha256', $salt . "\0" . $subject);
  }

  /**
   * The client address as CiviCRM sees it; `ipAddress()` already honours the
   * trusted-proxy handling, `X-Forwarded-For` alone is client-settable.
   */
  public static function clientIp(): ?string {
    $ip = \CRM_Utils_System::ipAddress();

    return is_string($ip) && $ip !== '' ? substr($ip, 0, 45) : NULL;
  }

  /**
   * Delete rows past the retention window. Called by the scheduled job.
   *
   * @return int
   *   Rows deleted.
   */
  public static function prune(?int $days = NULL): int {
    $configured = $days ?? \Civi::settings()->get('warden_audit_retention_days');
    $days = max(1, is_numeric($configured) ? (int) $configured : 180);

    $cutoff = (new \DateTimeImmutable("-{$days} days"))->format('Y-m-d H:i:s');

    $deleted = WardenAudit::delete(FALSE)
      ->addWhere('created_date', '<', $cutoff)
      ->execute();

    return count($deleted);
  }

}
