<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenIdentity;

// @mago-expect lint:cyclomatic-complexity -- three resolution outcomes, one decision
/**
 * Turning a verified ID token into a CiviCRM user id.
 *
 * Keyed on `sub`, the only claim OIDC promises is immutable and never
 * reassigned; email-keyed provisioning is an account takeover primitive.
 * Outcomes in order: linked subject → log in; unknown + `link_policy` → adopt
 * on a VERIFIED email; unknown + `provision_policy` → create. Else refuse.
 */
final class Provisioner {

  /**
   * @throws \CRM_Core_Exception
   *   With a message safe to show a visitor.
   */
  public static function resolve(Provider $provider, IdTokenClaims $claims): int {
    $subject = $claims->subject;

    $existing = self::linkFor($provider, $subject);
    if ($existing !== NULL) {
      $userId = Value::int($existing['user_id'] ?? NULL);
      // Standalone's authx does not check is_active itself, so a deactivated
      // account would keep signing in through the IdP.
      $user = Users::find($userId);
      if ($user === NULL || !Value::bool($user['is_active'] ?? NULL)) {
        Audit::record(
          Options::EVENT_LOGIN_DENIED,
          $provider,
          $userId,
          'user_inactive',
          'account is disabled',
          $subject,
        );

        throw new \CRM_Core_Exception('Your account on this site is disabled. Ask an administrator to reactivate it.');
      }
      self::touch(Value::int($existing['id'] ?? NULL));
      self::syncRolesOnLogin($provider, $userId, $claims);

      return $userId;
    }

    [$email, $emailVerified] = $claims->email();

    if ($provider->linkPolicy === Options::LINK_VERIFIED_EMAIL && $email !== NULL) {
      $userId = self::adopt($provider, $subject, $email, $emailVerified);
      if ($userId !== NULL) {
        self::syncRolesOnLogin($provider, $userId, $claims);

        return $userId;
      }
    }

    if ($provider->provisionPolicy !== Options::PROVISION_ON) {
      Audit::record(
        Options::EVENT_LOGIN_DENIED,
        $provider,
        NULL,
        'unknown_subject',
        'no linked account and provisioning is off',
        $subject,
      );

      throw new \CRM_Core_Exception(
        'Your identity provider authenticated you, but this site has no account linked to you and does not create accounts automatically. Ask an administrator to link your account.',
      );
    }

    return self::create($provider, $claims, $email, $emailVerified);
  }

  /**
   * The existing link for this subject, if any.
   *
   * @return array<string, mixed>|null
   */
  private static function linkFor(Provider $provider, string $subject): ?array {
    /** @var array<string, mixed>|null */
    return WardenIdentity::get(FALSE)
      ->addSelect('id', 'user_id')
      ->addWhere('provider_id', '=', $provider->id)
      ->addWhere('subject', '=', $subject)
      ->execute()
      ->first();
  }

  /**
   * Adopt an existing account for an unseen subject. Never relinks: an
   * account bound to a DIFFERENT subject is misconfiguration or an attack.
   *
   * @return int|null
   *   NULL means "not adopted, carry on to provisioning".
   *
   * @throws \CRM_Core_Exception
   *   When the account is bound to another subject — a refusal, not a fallthrough.
   */
  // @mago-expect lint:no-boolean-flag-parameter -- `email_verified` qualifies the email beside it
  private static function adopt(Provider $provider, string $subject, string $email, bool $emailVerified): ?int {
    if (!$emailVerified) {
      Audit::record(
        Options::EVENT_LOGIN_DENIED,
        $provider,
        NULL,
        'email_not_verified',
        'linking by email requires email_verified',
        $subject,
      );

      return NULL;
    }

    $user = Users::findByEmail($email);
    if ($user === NULL || !isset($user['id'])) {
      return NULL;
    }
    $userId = Value::int($user['id'] ?? NULL);

    if (($user['is_active'] ?? TRUE) === FALSE) {
      Audit::record(Options::EVENT_LOGIN_DENIED, $provider, $userId, 'user_inactive', 'account is disabled', $subject);

      return NULL;
    }

    // Is this user already bound to a different subject at this provider?
    $bound = WardenIdentity::get(FALSE)
      ->addSelect('subject')
      ->addWhere('provider_id', '=', $provider->id)
      ->addWhere('user_id', '=', $userId)
      ->execute()
      ->first();

    if (is_array($bound)) {
      Audit::record(
        Options::EVENT_RELINK_REFUSED,
        $provider,
        $userId,
        'already_linked',
        'the account is bound to a different subject at this provider',
        $subject,
      );

      throw new \CRM_Core_Exception(
        'This account is already linked to a different identity at your provider. Ask an administrator to unlink it first.',
      );
    }

    self::link($provider, $userId, $subject);
    Audit::record(
      Options::EVENT_PROVISIONED,
      $provider,
      $userId,
      'adopted',
      'linked to an existing account by verified email',
      $subject,
    );

    return $userId;
  }

  /**
   * @throws \CRM_Core_Exception
   */
  // @mago-expect lint:no-boolean-flag-parameter -- the flag qualifies the email beside it
  private static function create(Provider $provider, IdTokenClaims $claims, ?string $email, bool $emailVerified): int {
    $subject = $claims->subject;
    $mappedRoles = self::mappedRoles($provider, $claims, NULL);

    // `preferred_username` is neither stable nor unique: a readable prefix
    // only, the (issuer, sub) digest carries uniqueness.
    $preferred = Value::nullableStr($claims->claim('preferred_username'));
    $prefix = $preferred === NULL ? '' : preg_replace('/[^A-Za-z0-9._-]/', '', $preferred) ?? '';
    $suffix = '-' . substr(Audit::hashSubject($provider->issuerForComparison() . "\0" . $subject), 0, 12);
    $username = substr($prefix === '' ? $provider->name : $prefix, 0, 60 - strlen($suffix)) . $suffix;

    // Contact, user and identity link stand or fall together. Nested
    // (savepoint) so the rollback is immediate inside an outer transaction.
    $transaction = new \CRM_Core_Transaction(TRUE);
    try {
      $userId = Users::provision(
        $username,
        // Only a verified address is written onto the contact. An unverified
        // one would let the IdP put an arbitrary address on a CiviCRM contact.
        $emailVerified ? $email : NULL,
        Value::nullableStr($claims->claim('name')),
        RoleMapper::apply($provider, $provider->defaultRoleNames, $mappedRoles),
      );
      self::link($provider, $userId, $subject);
    }
    catch (\Throwable $e) {
      // Close the frame (rollback() only flags, commit() executes it) before
      // the audit row, or it would roll back too.
      $transaction->rollback()->commit();
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        NULL,
        'provision_rolled_back',
        substr($e->getMessage(), 0, 200),
        $subject,
      );
      throw $e;
    }
    $transaction->commit();
    Audit::record(
      Options::EVENT_PROVISIONED,
      $provider,
      $userId,
      'created',
      'new user provisioned on first login',
      $subject,
    );

    return $userId;
  }

  private static function link(Provider $provider, int $userId, string $subject): void {
    try {
      WardenIdentity::create(FALSE)
        ->addValue('provider_id', $provider->id)
        ->addValue('user_id', $userId)
        ->addValue('subject', $subject)
        ->addValue('last_login_date', 'now')
        ->addValue('login_count', 1)
        ->execute();
    }
    catch (\Throwable $e) {
      // The unique index is the real enforcement against two simultaneous first logins.
      Audit::record(
        Options::EVENT_RELINK_REFUSED,
        $provider,
        $userId,
        'link_conflict',
        'unique index refused the link',
        $subject,
      );

      throw new \CRM_Core_Exception(
        'This identity could not be linked to an account. Ask an administrator to check the warden log.',
        0,
        [],
        $e,
      );
    }
  }

  private static function touch(int $identityId): void {
    try {
      // ckconform-ignore raw-sql -- atomic read-modify-write of a counter
      \CRM_Core_DAO::executeQuery(
        'UPDATE civicrm_warden_identity SET last_login_date = NOW(), login_count = login_count + 1 WHERE id = %1',
        [1 => [$identityId, 'Integer']],
      );
    }
    catch (\Throwable $e) {
      // Error, not warning: a database write is failing.
      \Civi::log()->error('warden: could not update identity {id}: {msg}', [
        'id' => $identityId,
        'msg' => $e->getMessage(),
      ]);
    }
  }

  private static function syncRolesOnLogin(Provider $provider, int $userId, IdTokenClaims $claims): void {
    if ($provider->roleSyncMode !== Options::ROLE_SYNC_EVERY_LOGIN) {
      return;
    }

    try {
      $current = Users::roleNames($userId);
      $target = RoleMapper::apply($provider, $current, self::mappedRoles($provider, $claims, $userId));
      sort($current);
      sort($target);
      if ($current !== $target) {
        Users::setRoles($userId, $target);
      }
    }
    catch (\CRM_Core_Exception $e) {
      throw $e;
    }
    catch (\Throwable $e) {
      // A role sync failure must not silently grant the login the roles it
      // should have lost, so it is loud in the log and in the trail.
      \Civi::log()->error('warden: role sync failed for user {id}: {msg}', [
        'id' => $userId,
        'msg' => $e->getMessage(),
      ]);
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        $userId,
        'role_sync_failed',
        substr($e->getMessage(), 0, 200),
      );

      throw new \CRM_Core_Exception(
        'Your identity provider roles could not be applied. Access was refused; ask an administrator to check the warden log.',
        0,
        [],
        $e,
      );
    }
  }

  /**
   * Resolve the authoritative role input, refusing distributed/overage claims.
   *
   * @return list<string>
   *
   * @throws \CRM_Core_Exception
   */
  private static function mappedRoles(Provider $provider, IdTokenClaims $claims, ?int $userId): array {
    try {
      return RoleMapper::rolesFor($provider, $claims->all);
    }
    catch (RoleClaimUnavailableException $e) {
      Audit::record(
        Options::EVENT_LOGIN_DENIED,
        $provider,
        $userId,
        'role_claim_unavailable',
        substr($e->getMessage(), 0, 200),
        $claims->subject,
      );

      throw new \CRM_Core_Exception(
        'Your identity provider omitted the configured role claim because it was too large for the login token. Access was refused; ask an administrator to use application roles or reduce the emitted groups.',
        0,
        [],
        $e,
      );
    }
  }

}
