<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenSession;

// @mago-expect lint:cyclomatic-complexity
// @mago-expect lint:too-many-methods
// Registration, matching, revocation and termination are one persistence
// boundary; keeping the hashing/query rules together prevents drift.
/**
 * Persistent OIDC-to-local-session bindings used by single logout.
 *
 * PHP's session handler is deployment-specific, so a back-channel request
 * cannot portably delete another browser's session storage. Revocation is
 * therefore persisted here and enforced on that session's next request,
 * before the requested CiviCRM page runs.
 */
final class SessionRegistry {

  private const TOUCH_INTERVAL = 3600;

  private static ?string $sessionIdOverride = NULL;

  /**
   * @var callable|null
   */
  private static mixed $terminatorOverride = NULL;

  /**
   * Test seam for CLI suites, where PHP cannot start a cookie session after
   * PHPUnit has emitted output.
   */
  public static function setTestSessionId(?string $sessionId): void {
    if (!defined('WARDEN_TEST')) {
      throw new \LogicException('session-id override is test-only');
    }
    self::$sessionIdOverride = $sessionId;
  }

  public static function setTestTerminator(?callable $terminator): void {
    if (!defined('WARDEN_TEST')) {
      throw new \LogicException('session terminator override is test-only');
    }
    self::$terminatorOverride = $terminator;
  }

  public static function register(Provider $provider, int $userId, IdTokenClaims $claims): void {
    $localHash = self::currentSessionHash();
    if ($localHash === NULL) {
      throw new \CRM_Core_Exception('warden could not bind the login to a local session.');
    }

    $sid = $claims->claim('sid');
    $now = self::now();

    // A regenerated PHP session id is unique. Delete defensively so a retry
    // cannot turn the unique index into a post-login fatal.
    WardenSession::delete(FALSE)
      ->addWhere('local_session_hash', '=', $localHash)
      ->execute();

    WardenSession::create(FALSE)
      ->addValue('provider_id', $provider->id)
      ->addValue('user_id', $userId)
      ->addValue('local_session_hash', $localHash)
      ->addValue('subject_hash', self::hashRemote('sub', $claims->subject))
      ->addValue('provider_session_hash', is_string($sid) && $sid !== '' ? self::hashRemote('sid', $sid) : NULL)
      ->addValue('created_date', $now)
      ->addValue('last_seen_date', $now)
      ->execute();
  }

  /**
   * Mark the exact session(s) named by a verified logout token.
   *
   * When both sub and sid are supplied they are matched together. A token
   * with contradictory claims therefore revokes nothing rather than widening
   * itself to every session of the subject.
   */
  public static function revoke(Provider $provider, LogoutTokenClaims $claims): int {
    $update = WardenSession::update(FALSE)
      ->addWhere('provider_id', '=', $provider->id)
      ->addWhere('revoked_date', 'IS NULL')
      ->addValue('revoked_date', self::now());

    if ($claims->subject !== NULL) {
      $update->addWhere('subject_hash', '=', self::hashRemote('sub', $claims->subject));
    }
    if ($claims->sessionId !== NULL) {
      $update->addWhere('provider_session_hash', '=', self::hashRemote('sid', $claims->sessionId));
    }

    return count($update->execute());
  }

  public static function currentIsRevoked(): bool {
    $row = self::current();
    if ($row === NULL) {
      return FALSE;
    }

    self::touch($row);

    return is_string($row['revoked_date'] ?? NULL) && $row['revoked_date'] !== '';
  }

  public static function clearCurrent(): void {
    $hash = self::currentSessionHash();
    if ($hash === NULL) {
      return;
    }

    WardenSession::delete(FALSE)
      ->addWhere('local_session_hash', '=', $hash)
      ->execute();
  }

  /**
   * End the current Standalone session without invoking the browser logout
   * page. Used after a signed back-channel revocation.
   */
  public static function terminateCurrent(string $event): void {
    $row = self::current();
    $provider = $row === NULL ? NULL : ProviderRepository::find(Value::int($row['provider_id'] ?? NULL));
    $userId = $row === NULL ? NULL : Value::int($row['user_id'] ?? NULL);

    $testTerminator = is_callable(self::$terminatorOverride) ? self::$terminatorOverride : NULL;
    if ($testTerminator === NULL && !function_exists('_authx_uf')) {
      throw new \CRM_Core_Exception('warden cannot terminate the session because authx is unavailable.');
    }
    if ($testTerminator !== NULL) {
      $testTerminator();
    }
    if ($testTerminator === NULL) {
      _authx_uf()->logoutSession();
    }

    // Keep a revoked row until logoutSession() succeeds. A transient session
    // backend failure must cause the next request to try again, not restore
    // access by making the revocation marker disappear.
    if ($row !== NULL) {
      WardenSession::delete(FALSE)
        ->addWhere('id', '=', Value::int($row['id'] ?? NULL))
        ->execute();
    }
    SessionMark::clear();

    Audit::record($event, $provider, $userId ?: NULL);
  }

  public static function prune(?int $days = NULL): int {
    $configured = $days ?? \Civi::settings()->get('warden_session_retention_days');
    $days = max(1, is_numeric($configured) ? (int) $configured : 30);
    $cutoff = (new \DateTimeImmutable("-{$days} days"))->format('Y-m-d H:i:s');

    return count(
      WardenSession::delete(FALSE)
        ->addWhere('last_seen_date', '<', $cutoff)
        ->execute(),
    );
  }

  /**
   * @return array<string, mixed>|null
   */
  private static function current(): ?array {
    $hash = self::currentSessionHash();
    if ($hash === NULL) {
      return NULL;
    }

    $row = WardenSession::get(FALSE)
      ->setSelect(['id', 'provider_id', 'user_id', 'provider_session_hash', 'last_seen_date', 'revoked_date'])
      ->addWhere('local_session_hash', '=', $hash)
      ->execute()
      ->first();

    return is_array($row) ? Value::row($row) : NULL;
  }

  /**
   * @param array<string, mixed> $row
   */
  private static function touch(array $row): void {
    $lastSeen = strtotime(Value::str($row['last_seen_date'] ?? NULL));
    if ($lastSeen !== FALSE && $lastSeen > (time() - self::TOUCH_INTERVAL)) {
      return;
    }

    WardenSession::update(FALSE)
      ->addWhere('id', '=', Value::int($row['id'] ?? NULL))
      ->addValue('last_seen_date', self::now())
      ->execute();
  }

  private static function currentSessionHash(): ?string {
    $sessionId = self::$sessionIdOverride ?? session_id();

    return $sessionId === '' || $sessionId === FALSE
      ? NULL
      : self::hashRemote('local', $sessionId);
  }

  private static function hashRemote(string $context, string $value): string {
    $key = Value::str(\CRM_Utils_Constant::value('CIVICRM_SITE_KEY'));

    return hash_hmac('sha256', $context . "\0" . $value, $key);
  }

  private static function now(): string {
    return (new \DateTimeImmutable())->format('Y-m-d H:i:s');
  }

}
