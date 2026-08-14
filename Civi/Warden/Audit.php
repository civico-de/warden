<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenAudit;

/**
 * warden's login trail.
 *
 * Core Standalone writes none: `Civi\Api4\Action\User\Login` carries a comment
 * inviting extensions to add flood control and auditing, and that is the whole
 * of it. So an SSO deployment with no trail could not answer "who logged in as
 * this account, from where, and when did we start refusing them".
 *
 * What is NEVER written here, at any log level: an ID token, an access token, a
 * refresh token, an authorization code, an email address, a display name, or a
 * raw `sub`. The subject is stored as a salted digest so rows about one remote
 * identity can be correlated without the identifier being recoverable from a
 * database dump.
 */
final class Audit {

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
      // An audit failure must not become a login failure — but it must not be
      // silent either, or the trail's own gaps become invisible.
      \Civi::log()->error('warden: could not write an audit record ({event}): {msg}', [
        'event' => $event,
        'msg' => $e->getMessage(),
      ]);
    }
  }

  /**
   * Salted with the site key so the same subject hashes differently on
   * different sites, and so a dump of this table alone cannot be attacked with
   * a precomputed table of likely identifiers.
   */
  public static function hashSubject(string $subject): string {
    $salt = (string) \CRM_Utils_Constant::value('CIVICRM_SITE_KEY');

    return hash('sha256', $salt . "\0" . $subject);
  }

  /**
   * The client address, as CiviCRM sees it.
   *
   * `CRM_Utils_System::ipAddress()` already honours the trusted-proxy handling
   * core applies elsewhere; re-deriving it from `X-Forwarded-For` here would
   * mean trusting a header any client can set.
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
