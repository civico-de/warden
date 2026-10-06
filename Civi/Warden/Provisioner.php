<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Warden\Event\ResolveUserEvent;

// @mago-expect lint:cyclomatic-complexity -- three resolution outcomes, one decision
/**
 * Turning a verified ID token into a CiviCRM user id.
 *
 * Keyed on `sub`, the only claim OIDC promises is immutable and never
 * reassigned; email-keyed provisioning is an account takeover primitive.
 * Outcomes in order: linked subject → log in; unknown + a resolveUser
 * listener naming a user → adopt; unknown + `link_policy` → adopt on a
 * VERIFIED email; unknown + `provision_policy` → create. Else refuse.
 */
final class Provisioner {

  /**
   * @throws \CRM_Core_Exception
   *   With a message safe to show a visitor.
   */
  public static function resolve(Provider $provider, IdTokenClaims $claims): ResolvedUser {
    $subject = $claims->subject;

    $existing = Identities::find($provider, $subject);
    if ($existing !== NULL) {
      $userId = Value::int($existing['user_id'] ?? NULL);
      self::assertActive($provider, $userId, $subject);
      Identities::touch(Value::int($existing['id'] ?? NULL));
      self::syncRolesOnLogin($provider, $userId, $claims);
      ProfileSync::onLogin($provider, $userId, $claims);

      return new ResolvedUser($userId, FALSE);
    }

    [$email, $emailVerified] = $claims->email();

    $listenerUserId = self::askListeners($provider, $claims);
    if ($listenerUserId !== NULL) {
      self::assertActive($provider, $listenerUserId, $subject);
      self::adopt($provider, $subject, $listenerUserId, 'linked to an existing account by a resolveUser listener');
      self::syncRolesOnLogin($provider, $listenerUserId, $claims);
      ProfileSync::onLogin($provider, $listenerUserId, $claims);

      return new ResolvedUser($listenerUserId, FALSE);
    }

    if ($provider->linkPolicy === Options::LINK_VERIFIED_EMAIL && $email !== NULL) {
      $userId = self::adoptByEmail($provider, $subject, $email, $emailVerified);
      if ($userId !== NULL) {
        self::syncRolesOnLogin($provider, $userId, $claims);
        ProfileSync::onLogin($provider, $userId, $claims);

        return new ResolvedUser($userId, FALSE);
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

    return new ResolvedUser(self::create($provider, $claims, $email, $emailVerified), TRUE);
  }

  /**
   * Let other extensions match an unknown subject. A listener may name an
   * existing user id to link, or set a refusal reason; a linked subject never
   * reaches this point, so a listener cannot override an established link.
   *
   * @throws \CRM_Core_Exception
   */
  private static function askListeners(Provider $provider, IdTokenClaims $claims): ?int {
    $event = new ResolveUserEvent($provider, $claims);
    try {
      \Civi::dispatcher()->dispatch(ResolveUserEvent::NAME, $event);
    }
    catch (\Throwable $e) {
      // A listener's exception is a bug in that listener; its message is not for the visitor.
      \Civi::log()->error('warden: a resolveUser listener failed: {msg}', ['msg' => $e->getMessage()]);
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        NULL,
        'listener_failed',
        substr($e->getMessage(), 0, 200),
        $claims->subject,
      );

      throw new \CRM_Core_Exception(
        'This sign-in could not be completed. Ask an administrator to check the warden log.',
        0,
        [],
        $e,
      );
    }

    $refusal = $event->refusal;
    if ($refusal !== NULL && $refusal !== '') {
      Audit::record(
        Options::EVENT_LOGIN_DENIED,
        $provider,
        NULL,
        'refused_by_listener',
        substr($refusal, 0, 200),
        $claims->subject,
      );

      throw new \CRM_Core_Exception(
        'Your identity provider authenticated you, but this site refused the sign-in. Ask an administrator to check the warden log.',
      );
    }

    return $event->userId !== NULL && $event->userId > 0 ? $event->userId : NULL;
  }

  /**
   * Adopt an existing account by verified email, for an unseen subject.
   *
   * @return int|null
   *   NULL means "not adopted, carry on to provisioning".
   *
   * @throws \CRM_Core_Exception
   *   When the account is bound to another subject — a refusal, not a fallthrough.
   */
  // @mago-expect lint:no-boolean-flag-parameter -- `email_verified` qualifies the email beside it
  private static function adoptByEmail(Provider $provider, string $subject, string $email, bool $emailVerified): ?int {
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

    self::adopt($provider, $subject, $userId, 'linked to an existing account by verified email');

    return $userId;
  }

  /**
   * Link an unseen subject to an existing account. Never relinks: an account
   * bound to a DIFFERENT subject is misconfiguration or an attack.
   *
   * @throws \CRM_Core_Exception
   */
  private static function adopt(Provider $provider, string $subject, int $userId, string $note): void {
    if (Identities::isBound($provider, $userId)) {
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

    Identities::link($provider, $userId, $subject);
    Audit::record(Options::EVENT_PROVISIONED, $provider, $userId, 'adopted', $note, $subject);
  }

  /**
   * Refuse a deactivated account. Standalone's authx does not check
   * is_active itself, so the IdP would otherwise keep signing it in.
   *
   * @throws \CRM_Core_Exception
   */
  private static function assertActive(Provider $provider, int $userId, string $subject): void {
    $user = Users::find($userId);
    if ($user === NULL) {
      Audit::record(
        Options::EVENT_LOGIN_DENIED,
        $provider,
        NULL,
        'user_missing',
        'the linked user id does not exist',
        $subject,
      );

      throw new \CRM_Core_Exception(
        'The account linked to your identity no longer exists. Ask an administrator to relink it.',
      );
    }
    if (Value::bool($user['is_active'] ?? NULL)) {
      return;
    }
    Audit::record(Options::EVENT_LOGIN_DENIED, $provider, $userId, 'user_inactive', 'account is disabled', $subject);

    throw new \CRM_Core_Exception('Your account on this site is disabled. Ask an administrator to reactivate it.');
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
        $claims->nameFields(),
        RoleMapper::apply($provider, $provider->defaultRoleNames, $mappedRoles),
      );
      Identities::link($provider, $userId, $subject);
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
